use std::collections::{BTreeMap, BTreeSet, HashSet};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};

use crate::source::{
    Address, Coverage, MemoryRegion, ModuleInfo, PROTECTION_NAMES, ProcessMemory, TYPE_NAMES,
};
use crate::{Error, Result};

pub const SCAN_SPEC_SCHEMA: u32 = 2;
pub const MAX_PATTERNS: usize = 64;
pub const MAX_PATTERN_BYTES: usize = 4096;
pub const HARD_MAX_MATCHES: usize = 1_000_000;
pub const MAX_SCOPE_SELECTORS: usize = 32;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSpec {
    pub schema: u32,
    pub patterns: Vec<PatternSpec>,
    #[serde(default)]
    pub scope: Option<ScopeSpec>,
    #[serde(default = "default_max_matches")]
    pub max_matches: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternSpec {
    pub tag: String,
    pub value: PatternValue,
    #[serde(default = "default_alignment")]
    pub alignment: u64,
}

/// Deterministic byte representations. Every kind serializes to exact bytes
/// before scanning; nothing is inferred, decoded, or transformed implicitly.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PatternValue {
    Bytes {
        bytes_hex: String,
    },
    Int {
        number: String,
        width: u32,
        signed: bool,
        endian: Endianness,
    },
    Float {
        number: String,
        width: u32,
        endian: Endianness,
    },
    Utf8 {
        text: String,
    },
    Utf16le {
        text: String,
    },
    Masked {
        bytes_hex: String,
        mask_hex: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

/// Bounded scan-scope selectors. Categories compose by intersection; the
/// selectors inside one category compose by union. An omitted category imposes
/// no constraint, and a present category must list at least one selector.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    #[serde(default)]
    pub modules: Option<Vec<String>>,
    #[serde(default)]
    pub regions: Option<Vec<usize>>,
    #[serde(default)]
    pub ranges: Option<Vec<AddressRangeSpec>>,
    #[serde(default)]
    pub protections: Option<Vec<String>>,
    #[serde(default)]
    pub types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressRangeSpec {
    pub start: String,
    pub length: String,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    tag: String,
    /// Full pattern bytes. Masked patterns store zeros outside their mask.
    bytes: Vec<u8>,
    /// `None` for exact patterns.
    mask: Option<Vec<u8>>,
    /// Offset of the literal search anchor inside `bytes`.
    needle_offset: usize,
    needle_len: usize,
    alignment: u64,
}

impl CompiledPattern {
    fn needle(&self) -> &[u8] {
        &self.bytes[self.needle_offset..self.needle_offset + self.needle_len]
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub process_id: String,
    pub pattern_count: usize,
    pub scope: ScanScopeReport,
    pub terminal_reason: &'static str,
    pub scan_complete: bool,
    pub next_address: Option<Address>,
    pub coverage: Coverage,
    pub matches: Vec<ScanMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanScopeReport {
    /// Selector categories that were applied, in deterministic order.
    pub applied: Vec<&'static str>,
    pub interval_count: usize,
    /// Bytes selected by the scope intersection, independent of what the source
    /// captured. `null` when no scope was requested.
    pub selected_bytes: Option<u64>,
    /// Captured readable bytes actually examined inside the scope.
    pub scanned_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanMatch {
    pub address: Address,
    pub length: usize,
    pub tags: Vec<String>,
    pub region: Option<RegionAttribution>,
    pub module: Option<ModuleAttribution>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionAttribution {
    pub id: usize,
    pub base: Address,
    pub offset: Address,
    pub kind: String,
    pub protection: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleAttribution {
    pub name: String,
    pub base: Address,
    pub rva: Address,
}

#[derive(Debug, Clone, Copy)]
struct Interval {
    start: u64,
    end: u64,
}

#[derive(Debug)]
struct ResolvedScope {
    applied: Vec<&'static str>,
    /// `None` selects every captured readable byte.
    intervals: Option<Vec<Interval>>,
    selected_bytes: Option<u64>,
}

struct ScanContext<'a> {
    process: &'a dyn ProcessMemory,
    patterns: &'a [CompiledPattern],
    automaton: &'a AhoCorasick,
    max_pattern_len: u64,
    max_matches: usize,
}

struct ScanState {
    output: Vec<ScanMatch>,
    next_address: Option<u64>,
    scanned_bytes: u64,
    stopped: bool,
}

pub fn scan(process: &dyn ProcessMemory, spec: &ScanSpec) -> Result<ScanReport> {
    let patterns = compile(spec)?;
    let scope = resolve_scope(process, spec.scope.as_ref())?;
    let automaton = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(patterns.iter().map(CompiledPattern::needle))
        .map_err(|error| Error::InvalidSpec(error.to_string()))?;
    let max_pattern_len = patterns
        .iter()
        .map(|pattern| pattern.bytes.len())
        .max()
        .unwrap_or(0) as u64;

    let context = ScanContext {
        process,
        patterns: &patterns,
        automaton: &automaton,
        max_pattern_len,
        max_matches: spec.max_matches,
    };
    let mut state = ScanState {
        output: Vec::with_capacity(spec.max_matches.min(4096)),
        next_address: None,
        scanned_bytes: 0,
        stopped: false,
    };

    process.for_each_scannable_span(&mut |base, span| {
        if state.stopped {
            return Ok(());
        }
        match scope.intervals.as_deref() {
            None => {
                state.scanned_bytes += span.len() as u64;
                scan_slice(&context, &mut state, base, span)
            }
            Some(intervals) => {
                let span_end = base
                    .checked_add(span.len() as u64)
                    .ok_or_else(|| Error::SourceInvariant("scan span address overflow".into()))?;
                let first = intervals.partition_point(|interval| interval.end <= base);
                for interval in &intervals[first..] {
                    if interval.start >= span_end {
                        break;
                    }
                    let start = interval.start.max(base);
                    let end = interval.end.min(span_end);
                    if start >= end {
                        continue;
                    }
                    let offset = (start - base) as usize;
                    let length = (end - start) as usize;
                    state.scanned_bytes += length as u64;
                    scan_slice(&context, &mut state, start, &span[offset..offset + length])?;
                    if state.stopped {
                        break;
                    }
                }
                Ok(())
            }
        }
    })?;

    let scan_complete = state.next_address.is_none();
    Ok(ScanReport {
        process_id: process.process().id.clone(),
        pattern_count: patterns.len(),
        scope: ScanScopeReport {
            applied: scope.applied,
            interval_count: scope.intervals.as_ref().map_or(0, Vec::len),
            selected_bytes: scope.selected_bytes,
            scanned_bytes: state.scanned_bytes,
        },
        terminal_reason: if scan_complete {
            "exhausted_scope"
        } else {
            "match_limit"
        },
        scan_complete,
        next_address: state.next_address.map(Address),
        coverage: process.coverage().clone(),
        matches: state.output,
    })
}

/// Scans one contiguous captured readable slice that lies entirely inside the
/// selected scope. A match is retained only when every one of its bytes is
/// inside this slice, so scope and capture boundaries never fabricate matches.
fn scan_slice(
    context: &ScanContext<'_>,
    state: &mut ScanState,
    base: u64,
    slice: &[u8],
) -> Result<()> {
    let mut pending: BTreeMap<(u64, usize), BTreeSet<String>> = BTreeMap::new();
    for found in context.automaton.find_overlapping_iter(slice) {
        let pattern = &context.patterns[found.pattern().as_usize()];
        let Some(start) = found.start().checked_sub(pattern.needle_offset) else {
            continue;
        };
        let end = start + pattern.bytes.len();
        if end > slice.len() {
            continue;
        }
        if pattern
            .mask
            .as_deref()
            .is_some_and(|mask| !matches_mask(&slice[start..end], &pattern.bytes, mask))
        {
            continue;
        }
        let address = base
            .checked_add(start as u64)
            .ok_or_else(|| Error::SourceInvariant("match address overflow".into()))?;
        if address % pattern.alignment != 0 {
            continue;
        }
        pending
            .entry((address, pattern.bytes.len()))
            .or_default()
            .insert(pattern.tag.clone());

        // Overlapping iteration reports matches by ascending end offset, so no
        // future match can begin earlier than this end minus the longest
        // pattern. Everything below that watermark is final and can be emitted
        // in ascending address order.
        let safe_before = base
            .checked_add(found.end() as u64)
            .and_then(|end| end.checked_sub(context.max_pattern_len))
            .unwrap_or(base);
        flush_before(context, state, &mut pending, safe_before);
        if state.next_address.is_some() {
            state.stopped = true;
            return Ok(());
        }
    }
    flush_before(context, state, &mut pending, u64::MAX);
    state.stopped = state.next_address.is_some();
    Ok(())
}

fn matches_mask(window: &[u8], bytes: &[u8], mask: &[u8]) -> bool {
    window
        .iter()
        .zip(bytes)
        .zip(mask)
        .all(|((found, expected), mask)| found & mask == *expected)
}

fn compile(spec: &ScanSpec) -> Result<Vec<CompiledPattern>> {
    if spec.schema != SCAN_SPEC_SCHEMA {
        return Err(Error::InvalidSpec(format!(
            "unsupported schema {}; expected {SCAN_SPEC_SCHEMA}, where every pattern carries an explicit typed value object",
            spec.schema
        )));
    }
    if spec.patterns.is_empty() {
        return Err(Error::InvalidSpec(
            "at least one pattern is required".into(),
        ));
    }
    if spec.patterns.len() > MAX_PATTERNS {
        return Err(Error::InvalidSpec(format!(
            "pattern count {} exceeds hard limit {MAX_PATTERNS}",
            spec.patterns.len()
        )));
    }
    if spec.max_matches == 0 || spec.max_matches > HARD_MAX_MATCHES {
        return Err(Error::InvalidSpec(format!(
            "max_matches must be between 1 and {HARD_MAX_MATCHES}"
        )));
    }

    let mut tags = HashSet::with_capacity(spec.patterns.len());
    spec.patterns
        .iter()
        .map(|pattern| {
            if pattern.tag.trim().is_empty() {
                return Err(Error::InvalidSpec("pattern tag cannot be empty".into()));
            }
            if !tags.insert(pattern.tag.clone()) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate pattern tag {:?}",
                    pattern.tag
                )));
            }
            if pattern.alignment == 0 {
                return Err(Error::InvalidSpec(format!(
                    "pattern {:?} has zero alignment",
                    pattern.tag
                )));
            }
            let (bytes, mask) = encode(&pattern.tag, &pattern.value)?;
            if bytes.is_empty() {
                return Err(Error::InvalidSpec(format!(
                    "pattern {:?} is empty",
                    pattern.tag
                )));
            }
            if bytes.len() > MAX_PATTERN_BYTES {
                return Err(Error::InvalidSpec(format!(
                    "pattern {:?} is {} bytes; hard limit is {MAX_PATTERN_BYTES}",
                    pattern.tag,
                    bytes.len()
                )));
            }
            let (needle_offset, needle_len) = match mask.as_deref() {
                None => (0, bytes.len()),
                Some(mask) => select_anchor(mask),
            };
            Ok(CompiledPattern {
                tag: pattern.tag.clone(),
                bytes,
                mask,
                needle_offset,
                needle_len,
                alignment: pattern.alignment,
            })
        })
        .collect()
}

fn encode(tag: &str, value: &PatternValue) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    match value {
        PatternValue::Bytes { bytes_hex } => Ok((decode_hex(tag, "bytes_hex", bytes_hex)?, None)),
        PatternValue::Int {
            number,
            width,
            signed,
            endian,
        } => Ok((encode_int(tag, number, *width, *signed, *endian)?, None)),
        PatternValue::Float {
            number,
            width,
            endian,
        } => Ok((encode_float(tag, number, *width, *endian)?, None)),
        PatternValue::Utf8 { text } => {
            require_text(tag, text)?;
            Ok((text.as_bytes().to_vec(), None))
        }
        PatternValue::Utf16le { text } => {
            require_text(tag, text)?;
            let mut bytes = Vec::with_capacity(text.len() * 2);
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            Ok((bytes, None))
        }
        PatternValue::Masked {
            bytes_hex,
            mask_hex,
        } => {
            let bytes = decode_hex(tag, "bytes_hex", bytes_hex)?;
            let mask = decode_hex(tag, "mask_hex", mask_hex)?;
            if bytes.len() != mask.len() {
                return Err(Error::InvalidSpec(format!(
                    "masked pattern {tag:?} has {} value bytes and {} mask bytes",
                    bytes.len(),
                    mask.len()
                )));
            }
            if bytes
                .iter()
                .zip(&mask)
                .any(|(byte, mask)| byte & !mask != 0)
            {
                return Err(Error::InvalidSpec(format!(
                    "masked pattern {tag:?} sets value bits outside its mask; clear masked-out bits to keep the pattern unambiguous"
                )));
            }
            if !mask.contains(&0xff) {
                return Err(Error::InvalidSpec(format!(
                    "masked pattern {tag:?} needs at least one fully known byte (mask ff) to anchor a bounded search"
                )));
            }
            Ok((bytes, Some(mask)))
        }
    }
}

fn require_text(tag: &str, text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(Error::InvalidSpec(format!(
            "string pattern {tag:?} has empty text"
        )));
    }
    Ok(())
}

fn decode_hex(tag: &str, field: &str, raw: &str) -> Result<Vec<u8>> {
    hex::decode(raw).map_err(|error| {
        Error::InvalidSpec(format!("pattern {tag:?} has invalid {field}: {error}"))
    })
}

fn encode_int(
    tag: &str,
    number: &str,
    width: u32,
    signed: bool,
    endian: Endianness,
) -> Result<Vec<u8>> {
    let byte_width = match width {
        8 => 1_usize,
        16 => 2,
        32 => 4,
        64 => 8,
        other => {
            return Err(Error::InvalidSpec(format!(
                "integer pattern {tag:?} has width {other}; expected 8, 16, 32, or 64"
            )));
        }
    };
    let (negative, magnitude) = parse_int_literal(number).ok_or_else(|| {
        Error::InvalidSpec(format!(
            "integer pattern {tag:?} has invalid number {number:?}; use decimal or 0x-prefixed hexadecimal digits"
        ))
    })?;
    let bits = u32::from(byte_width as u8) * 8;
    let span = if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    };
    let value = if signed {
        let limit = 1_u64 << (bits - 1);
        if negative {
            if magnitude > limit {
                return Err(Error::InvalidSpec(format!(
                    "integer pattern {tag:?} value {number} does not fit a signed {width}-bit integer"
                )));
            }
            magnitude.wrapping_neg() & span
        } else {
            if magnitude > limit - 1 {
                return Err(Error::InvalidSpec(format!(
                    "integer pattern {tag:?} value {number} does not fit a signed {width}-bit integer"
                )));
            }
            magnitude
        }
    } else {
        if negative {
            return Err(Error::InvalidSpec(format!(
                "integer pattern {tag:?} is unsigned but value {number} is negative"
            )));
        }
        if magnitude > span {
            return Err(Error::InvalidSpec(format!(
                "integer pattern {tag:?} value {number} does not fit an unsigned {width}-bit integer"
            )));
        }
        magnitude
    };

    Ok(match endian {
        Endianness::Little => value.to_le_bytes()[..byte_width].to_vec(),
        Endianness::Big => value.to_be_bytes()[8 - byte_width..].to_vec(),
    })
}

fn parse_int_literal(raw: &str) -> Option<(bool, u64)> {
    let (negative, digits) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    let magnitude = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hexadecimal) => u64::from_str_radix(hexadecimal, 16).ok()?,
        None => digits.parse::<u64>().ok()?,
    };
    Some((negative, magnitude))
}

fn encode_float(tag: &str, number: &str, width: u32, endian: Endianness) -> Result<Vec<u8>> {
    let bytes = match width {
        32 => {
            let value = number.parse::<f32>().map_err(|error| {
                Error::InvalidSpec(format!(
                    "float pattern {tag:?} has invalid number {number:?}: {error}"
                ))
            })?;
            require_representable(tag, value.is_nan())?;
            value.to_bits().to_le_bytes().to_vec()
        }
        64 => {
            let value = number.parse::<f64>().map_err(|error| {
                Error::InvalidSpec(format!(
                    "float pattern {tag:?} has invalid number {number:?}: {error}"
                ))
            })?;
            require_representable(tag, value.is_nan())?;
            value.to_bits().to_le_bytes().to_vec()
        }
        other => {
            return Err(Error::InvalidSpec(format!(
                "float pattern {tag:?} has width {other}; expected 32 or 64"
            )));
        }
    };
    Ok(match endian {
        Endianness::Little => bytes,
        Endianness::Big => bytes.into_iter().rev().collect(),
    })
}

fn require_representable(tag: &str, is_nan: bool) -> Result<()> {
    if is_nan {
        return Err(Error::InvalidSpec(format!(
            "float pattern {tag:?} is NaN, which has no single exact byte representation; use an explicit bytes or masked pattern"
        )));
    }
    Ok(())
}

/// Chooses the longest run of fully known bytes as the literal search anchor,
/// preferring the earliest run on a tie. Validation guarantees one exists.
fn select_anchor(mask: &[u8]) -> (usize, usize) {
    let mut best = (0_usize, 0_usize);
    let mut index = 0;
    while index < mask.len() {
        if mask[index] != 0xff {
            index += 1;
            continue;
        }
        let start = index;
        while index < mask.len() && mask[index] == 0xff {
            index += 1;
        }
        if index - start > best.1 {
            best = (start, index - start);
        }
    }
    best
}

fn resolve_scope(process: &dyn ProcessMemory, spec: Option<&ScopeSpec>) -> Result<ResolvedScope> {
    let Some(spec) = spec else {
        return Ok(ResolvedScope {
            applied: Vec::new(),
            intervals: None,
            selected_bytes: None,
        });
    };

    let mut applied = Vec::new();
    let mut categories: Vec<Vec<Interval>> = Vec::new();

    if let Some(selectors) = spec.modules.as_deref() {
        require_selectors("modules", selectors.len())?;
        let mut intervals = Vec::with_capacity(selectors.len());
        for selector in selectors {
            intervals.push(resolve_module(process.modules(), selector)?);
        }
        applied.push("modules");
        categories.push(merge(intervals));
    }
    if let Some(selectors) = spec.regions.as_deref() {
        require_selectors("regions", selectors.len())?;
        let mut intervals = Vec::with_capacity(selectors.len());
        for id in selectors {
            intervals.push(resolve_region(process.regions(), *id)?);
        }
        applied.push("regions");
        categories.push(merge(intervals));
    }
    if let Some(selectors) = spec.ranges.as_deref() {
        require_selectors("ranges", selectors.len())?;
        let mut intervals = Vec::with_capacity(selectors.len());
        for range in selectors {
            intervals.push(resolve_range(range)?);
        }
        applied.push("ranges");
        categories.push(merge(intervals));
    }
    if let Some(selectors) = spec.protections.as_deref() {
        require_selectors("protections", selectors.len())?;
        require_metadata(process, "protections")?;
        for selector in selectors {
            require_known(selector, &PROTECTION_NAMES, "protection")?;
        }
        let intervals = regions_matching(process.regions(), |region| {
            protection_tokens(&region.protection)
                .any(|token| selectors.iter().any(|selector| selector == token))
        })?;
        applied.push("protections");
        categories.push(merge(intervals));
    }
    if let Some(selectors) = spec.types.as_deref() {
        require_selectors("types", selectors.len())?;
        require_metadata(process, "types")?;
        for selector in selectors {
            require_known(selector, &TYPE_NAMES, "memory type")?;
        }
        let intervals =
            regions_matching(process.regions(), |region| selectors.contains(&region.kind))?;
        applied.push("types");
        categories.push(merge(intervals));
    }

    if categories.is_empty() {
        return Err(Error::InvalidSpec(
            "scope requires at least one selector category; omit scope to scan every captured readable byte".into(),
        ));
    }

    let mut intervals = categories.remove(0);
    for category in &categories {
        intervals = intersect(&intervals, category);
    }
    let selected_bytes = intervals
        .iter()
        .try_fold(0_u64, |total, interval| {
            total.checked_add(interval.end - interval.start)
        })
        .ok_or_else(|| Error::InvalidSpec("scope byte count overflows u64".into()))?;

    Ok(ResolvedScope {
        applied,
        intervals: Some(intervals),
        selected_bytes: Some(selected_bytes),
    })
}

fn require_selectors(category: &str, count: usize) -> Result<()> {
    if count == 0 {
        return Err(Error::InvalidSpec(format!(
            "scope category {category:?} lists no selectors; omit it instead"
        )));
    }
    if count > MAX_SCOPE_SELECTORS {
        return Err(Error::InvalidSpec(format!(
            "scope category {category:?} lists {count} selectors; hard limit is {MAX_SCOPE_SELECTORS}"
        )));
    }
    Ok(())
}

fn require_metadata(process: &dyn ProcessMemory, category: &str) -> Result<()> {
    if process.coverage().metadata_complete {
        return Ok(());
    }
    Err(Error::ScopeMetadataUnavailable(format!(
        "scope category {category:?} needs region metadata that this source does not provide"
    )))
}

fn require_known(selector: &str, known: &[&str], label: &str) -> Result<()> {
    if known.contains(&selector) {
        return Ok(());
    }
    Err(Error::InvalidSpec(format!(
        "unknown {label} selector {selector:?}; expected one of {}",
        known.join(", ")
    )))
}

fn resolve_module(modules: &[ModuleInfo], selector: &str) -> Result<Interval> {
    if selector.trim().is_empty() {
        return Err(Error::InvalidSpec(
            "module scope selector cannot be empty".into(),
        ));
    }
    let mut matched: Option<&ModuleInfo> = None;
    let mut count = 0_usize;
    for module in modules {
        if module_matches(module, selector) {
            count += 1;
            matched = Some(module);
        }
    }
    match (count, matched) {
        (1, Some(module)) => interval(module.base.0, module.size),
        (0, _) => Err(Error::UnresolvedScope(format!(
            "no captured module matches selector {selector:?}"
        ))),
        (count, _) => Err(Error::UnresolvedScope(format!(
            "module selector {selector:?} matches {count} captured modules; use the full image path"
        ))),
    }
}

fn module_matches(module: &ModuleInfo, selector: &str) -> bool {
    if module.name.eq_ignore_ascii_case(selector) {
        return true;
    }
    module
        .name
        .rsplit(['\\', '/'])
        .next()
        .is_some_and(|file_name| file_name.eq_ignore_ascii_case(selector))
}

fn resolve_region(regions: &[MemoryRegion], id: usize) -> Result<Interval> {
    let region = regions
        .iter()
        .find(|region| region.id == id)
        .ok_or_else(|| Error::UnresolvedScope(format!("no captured region has id {id}")))?;
    interval(region.base.0, region.size)
}

fn resolve_range(range: &AddressRangeSpec) -> Result<Interval> {
    let start = parse_u64_literal(&range.start)
        .ok_or_else(|| Error::InvalidSpec(format!("invalid range start {:?}", range.start)))?;
    let length = parse_u64_literal(&range.length)
        .ok_or_else(|| Error::InvalidSpec(format!("invalid range length {:?}", range.length)))?;
    if length == 0 {
        return Err(Error::InvalidSpec(format!(
            "range starting at {:?} has zero length",
            range.start
        )));
    }
    interval(start, length)
}

fn parse_u64_literal(raw: &str) -> Option<u64> {
    match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hexadecimal) => u64::from_str_radix(hexadecimal, 16).ok(),
        None => raw.parse::<u64>().ok(),
    }
}

fn regions_matching(
    regions: &[MemoryRegion],
    mut predicate: impl FnMut(&MemoryRegion) -> bool,
) -> Result<Vec<Interval>> {
    let mut intervals = Vec::new();
    for region in regions {
        if predicate(region) {
            intervals.push(interval(region.base.0, region.size)?);
        }
    }
    Ok(intervals)
}

fn protection_tokens(protection: &str) -> impl Iterator<Item = &str> {
    protection.split('|').map(str::trim)
}

fn interval(start: u64, size: u64) -> Result<Interval> {
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::InvalidSpec(format!("scope interval at 0x{start:016x} overflows")))?;
    Ok(Interval { start, end })
}

fn merge(mut intervals: Vec<Interval>) -> Vec<Interval> {
    intervals.retain(|interval| interval.start < interval.end);
    intervals.sort_by_key(|interval| (interval.start, interval.end));
    let mut merged: Vec<Interval> = Vec::with_capacity(intervals.len());
    for interval in intervals {
        match merged.last_mut() {
            Some(previous) if interval.start <= previous.end => {
                previous.end = previous.end.max(interval.end);
            }
            _ => merged.push(interval),
        }
    }
    merged
}

/// Intersects two ascending, non-overlapping interval lists.
fn intersect(left: &[Interval], right: &[Interval]) -> Vec<Interval> {
    let mut output = Vec::new();
    let (mut index, mut other) = (0_usize, 0_usize);
    while index < left.len() && other < right.len() {
        let start = left[index].start.max(right[other].start);
        let end = left[index].end.min(right[other].end);
        if start < end {
            output.push(Interval { start, end });
        }
        if left[index].end < right[other].end {
            index += 1;
        } else {
            other += 1;
        }
    }
    output
}

fn flush_before(
    context: &ScanContext<'_>,
    state: &mut ScanState,
    pending: &mut BTreeMap<(u64, usize), BTreeSet<String>>,
    exclusive_address: u64,
) {
    let ready = pending
        .range(..(exclusive_address, 0))
        .map(|(key, _)| *key)
        .collect::<Vec<_>>();
    for key @ (address, length) in ready {
        let tags = pending.remove(&key).expect("key came from pending");
        if state.output.len() == context.max_matches {
            state.next_address = Some(address);
            return;
        }
        state.output.push(attributed_match(
            context.process.regions(),
            context.process.modules(),
            address,
            length,
            tags.into_iter().collect(),
        ));
    }
}

fn attributed_match(
    regions: &[MemoryRegion],
    modules: &[ModuleInfo],
    address: u64,
    length: usize,
    tags: Vec<String>,
) -> ScanMatch {
    let region = regions
        .iter()
        .find(|region| region.contains(address))
        .map(|region| RegionAttribution {
            id: region.id,
            base: region.base,
            offset: Address(address - region.base.0),
            kind: region.kind.clone(),
            protection: region.protection.clone(),
        });
    let module = modules
        .iter()
        .find(|module| module.contains(address))
        .map(|module| ModuleAttribution {
            name: module.name.clone(),
            base: module.base,
            rva: Address(address - module.base.0),
        });
    ScanMatch {
        address: Address(address),
        length,
        tags,
        region,
        module,
    }
}

const fn default_max_matches() -> usize {
    100_000
}

const fn default_alignment() -> u64 {
    1
}
