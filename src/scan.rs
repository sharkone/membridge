use std::collections::{BTreeMap, BTreeSet, HashSet};

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};

use crate::source::{Address, Coverage, MemoryRegion, ModuleInfo, ProcessMemory};
use crate::{Error, Result};

pub const MAX_PATTERNS: usize = 64;
pub const MAX_PATTERN_BYTES: usize = 4096;
pub const HARD_MAX_MATCHES: usize = 1_000_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSpec {
    pub schema: u32,
    pub patterns: Vec<ExactPatternSpec>,
    #[serde(default = "default_max_matches")]
    pub max_matches: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactPatternSpec {
    pub tag: String,
    pub bytes_hex: String,
    #[serde(default = "default_alignment")]
    pub alignment: u64,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    tag: String,
    bytes: Vec<u8>,
    alignment: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub process_id: String,
    pub pattern_count: usize,
    pub terminal_reason: &'static str,
    pub scan_complete: bool,
    pub next_address: Option<Address>,
    pub coverage: Coverage,
    pub matches: Vec<ScanMatch>,
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

pub fn scan(process: &dyn ProcessMemory, spec: &ScanSpec) -> Result<ScanReport> {
    let patterns = compile(spec)?;
    let bytes = patterns
        .iter()
        .map(|pattern| pattern.bytes.as_slice())
        .collect::<Vec<_>>();
    let automaton = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(bytes)
        .map_err(|error| Error::InvalidSpec(error.to_string()))?;
    let max_pattern_len = patterns
        .iter()
        .map(|pattern| pattern.bytes.len())
        .max()
        .unwrap_or(0) as u64;

    let mut output = Vec::with_capacity(spec.max_matches.min(4096));
    let mut next_address = None;
    let mut stopped = false;

    process.for_each_scannable_span(&mut |base, span| {
        if stopped {
            return Ok(());
        }
        let mut pending: BTreeMap<(u64, usize), BTreeSet<String>> = BTreeMap::new();
        for found in automaton.find_overlapping_iter(span) {
            let pattern = &patterns[found.pattern().as_usize()];
            let address = base
                .checked_add(found.start() as u64)
                .ok_or_else(|| Error::SourceInvariant("match address overflow".into()))?;
            if address % pattern.alignment != 0 {
                continue;
            }
            pending
                .entry((address, found.len()))
                .or_default()
                .insert(pattern.tag.clone());

            let safe_before = base
                .checked_add(found.end() as u64)
                .and_then(|end| end.checked_sub(max_pattern_len))
                .unwrap_or(base);
            flush_before(
                process,
                &mut pending,
                safe_before,
                spec.max_matches,
                &mut output,
                &mut next_address,
            );
            if next_address.is_some() {
                stopped = true;
                break;
            }
        }
        if !stopped {
            flush_before(
                process,
                &mut pending,
                u64::MAX,
                spec.max_matches,
                &mut output,
                &mut next_address,
            );
            stopped = next_address.is_some();
        }
        Ok(())
    })?;

    let scan_complete = next_address.is_none();
    Ok(ScanReport {
        process_id: process.process().id.clone(),
        pattern_count: patterns.len(),
        terminal_reason: if scan_complete {
            "exhausted_scope"
        } else {
            "match_limit"
        },
        scan_complete,
        next_address: next_address.map(Address),
        coverage: process.coverage().clone(),
        matches: output,
    })
}

fn compile(spec: &ScanSpec) -> Result<Vec<CompiledPattern>> {
    if spec.schema != 1 {
        return Err(Error::InvalidSpec(format!(
            "unsupported schema {}; expected 1",
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
            let bytes = hex::decode(&pattern.bytes_hex).map_err(|error| {
                Error::InvalidSpec(format!(
                    "pattern {:?} has invalid bytes_hex: {error}",
                    pattern.tag
                ))
            })?;
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
            Ok(CompiledPattern {
                tag: pattern.tag.clone(),
                bytes,
                alignment: pattern.alignment,
            })
        })
        .collect()
}

fn flush_before(
    process: &dyn ProcessMemory,
    pending: &mut BTreeMap<(u64, usize), BTreeSet<String>>,
    exclusive_address: u64,
    max_matches: usize,
    output: &mut Vec<ScanMatch>,
    next_address: &mut Option<u64>,
) {
    let ready = pending
        .range(..(exclusive_address, 0))
        .map(|(key, _)| *key)
        .collect::<Vec<_>>();
    for key @ (address, length) in ready {
        let tags = pending.remove(&key).expect("key came from pending");
        if output.len() == max_matches {
            *next_address = Some(address);
            return;
        }
        output.push(attributed_match(
            process.regions(),
            process.modules(),
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
