//! Read-only live process source.
//!
//! Every host backend supplies the same four primitives - identity, region
//! enumeration, module enumeration, and a best-effort bounded read - and this module
//! turns them into the shared `MemorySource`/`ProcessMemory` contract. Chunking,
//! run merging, gap-aware reads, and coverage accounting live here exactly once, so a
//! new host cannot invent its own semantics.
//!
//! A live source is never immutable. The target keeps running between enumeration and
//! every read, so the answers describe an observation interval rather than a frozen
//! artifact, and a byte that could not be read is reported as unproven rather than as
//! an absent value.

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(windows, path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    path = "unsupported.rs"
)]
mod target;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    Access, Address, AddressRange, Coverage, CoverageLimitation, MAX_COVERAGE_LIMITATIONS,
    MemoryRegion, MemorySource, ModuleInfo, ObservationInterval, ProcessInfo, ProcessMemory,
    ReadSegment, ScanChunk, SourceInfo, now_unix_millis,
};
use crate::{Error, Result};

pub(crate) use target::Target;

/// Bytes read per scan chunk. Large enough that per-call overhead is irrelevant at the
/// measured multi-hundred-MB/s read rates, small enough that the reusable scan buffer
/// stays a fixed, predictable allocation regardless of how large the target is.
pub const SCAN_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Hard caps on live enumeration. A target can map an unbounded number of regions, and
/// every scope operation is at least linear in the region count, so enumeration fails
/// closed with `SOURCE_TOO_LARGE` instead of degrading without bound. These are far
/// above any ordinary process; a browser content process maps a few tens of thousands
/// of regions.
pub const MAX_LIVE_REGIONS: usize = 262_144;
pub const MAX_LIVE_MODULES: usize = 32_768;

const PROCESS_ID_PREFIX: &str = "pid:";

/// Region metadata as reported by a host backend, before membridge assigns ids and
/// normalizes it into the observable `MemoryRegion`.
#[derive(Debug, Clone)]
pub(crate) struct RawRegion {
    pub base: u64,
    pub size: u64,
    pub access: Access,
    /// The platform's own protection rendering, kept verbatim.
    pub native: String,
    /// One of `super::TYPE_NAMES`, or `"unknown"`.
    pub kind: &'static str,
    /// `committed` on every host whose enumeration only reports live mappings; the
    /// Windows address space also exposes `reserved` ranges, which carry no bytes.
    pub state: &'static str,
    pub committed: bool,
}

/// The identity a live source binds to. A PID alone is not an identity: PIDs are
/// reused, so the start time and image path are folded into the fingerprint and a
/// caller comparing two runs can tell a reused PID from the same process.
#[derive(Debug, Clone)]
pub(crate) struct TargetIdentity {
    pub pid: u32,
    pub image_path: String,
    pub start_time_unix_ms: u64,
}

/// One contiguous run of readable address space, merged from adjacent readable
/// regions so a pattern spanning two neighbouring regions is still found.
#[derive(Debug, Clone, Copy)]
struct ReadableRun {
    start: u64,
    end: u64,
}

#[derive(Debug)]
pub struct LiveSource {
    info: SourceInfo,
    processes: Vec<ProcessInfo>,
    process: Arc<LiveProcess>,
}

#[derive(Debug)]
struct LiveProcess {
    target: Target,
    process: ProcessInfo,
    regions: Vec<MemoryRegion>,
    modules: Vec<ModuleInfo>,
    runs: Vec<ReadableRun>,
    expected_readable_bytes: u64,
    /// Readable bytes this command has actually read out of the target.
    read_bytes: AtomicU64,
    /// Bytes the target reported as readable that a read then refused. Their content
    /// is unknown; absence of a value inside them is never proven.
    refused_bytes: AtomicU64,
    started_at_unix_ms: u64,
}

impl LiveSource {
    /// Attaches read-only to `pid` and enumerates its regions and modules.
    pub fn open(pid: u32) -> Result<Self> {
        let started_at_unix_ms = now_unix_millis();
        let target = Target::open(pid)?;
        let identity = target.identity().clone();

        let raw = target.regions()?;
        if raw.len() > MAX_LIVE_REGIONS {
            return Err(Error::SourceTooLarge(format!(
                "memory region count {} exceeds the {MAX_LIVE_REGIONS} limit",
                raw.len()
            )));
        }
        let modules = target.modules()?;
        if modules.len() > MAX_LIVE_MODULES {
            return Err(Error::SourceTooLarge(format!(
                "module count {} exceeds the {MAX_LIVE_MODULES} limit",
                modules.len()
            )));
        }

        let regions: Vec<MemoryRegion> = raw
            .into_iter()
            .enumerate()
            .map(|(id, region)| MemoryRegion {
                id,
                base: Address(region.base),
                size: region.size,
                // A live source captures nothing ahead of time: readability is only
                // ever proven by an actual read, which `Coverage` accounts for.
                captured_bytes: None,
                state: region.state.into(),
                protection: region.access.render(),
                native_protection: region.native,
                kind: region.kind.into(),
                committed: region.committed,
                readable: region.committed && region.access.read,
            })
            .collect();
        validate_regions(&regions)?;

        let expected_readable_bytes = regions
            .iter()
            .filter(|region| region.readable)
            .try_fold(0_u64, |total, region| total.checked_add(region.size))
            .ok_or_else(|| Error::SourceInvariant("readable byte count overflow".into()))?;
        let runs = merge_readable_runs(&regions)?;

        let display_name = std::path::Path::new(&identity.image_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("live-process")
            .to_owned();
        let process = ProcessInfo {
            id: format!("{PROCESS_ID_PREFIX}{}", identity.pid),
            display_name,
        };

        // A live source has no content hash: its bytes change while it is read. The
        // fingerprint therefore identifies the *observed process*, so a caller can
        // tell one target from another and detect a reused PID, and never implies
        // that two commands with the same fingerprint saw the same bytes.
        let mut hasher = blake3::Hasher::new();
        hasher.update(Target::PLATFORM.as_bytes());
        hasher.update(&identity.pid.to_le_bytes());
        hasher.update(&identity.start_time_unix_ms.to_le_bytes());
        hasher.update(identity.image_path.as_bytes());
        let fingerprint = hasher.finalize().to_hex().to_string();

        Ok(Self {
            info: SourceInfo {
                kind: "live",
                fingerprint,
                platform: Target::PLATFORM,
                architecture: ARCHITECTURE,
                immutable: false,
            },
            processes: vec![process.clone()],
            process: Arc::new(LiveProcess {
                target,
                process,
                regions,
                modules,
                runs,
                expected_readable_bytes,
                read_bytes: AtomicU64::new(0),
                refused_bytes: AtomicU64::new(0),
                started_at_unix_ms,
            }),
        })
    }
}

const ARCHITECTURE: &str = if cfg!(target_arch = "x86_64") {
    "x86_64"
} else if cfg!(target_arch = "aarch64") {
    "aarch64"
} else {
    "unknown"
};

impl MemorySource for LiveSource {
    fn info(&self) -> &SourceInfo {
        &self.info
    }

    fn processes(&self) -> &[ProcessInfo] {
        &self.processes
    }

    fn open_process(&self, id: &str) -> Result<Arc<dyn ProcessMemory>> {
        if id != self.process.process.id {
            return Err(Error::InvalidArgument(format!(
                "unknown process id {id:?}; expected {:?}",
                self.process.process.id
            )));
        }
        Ok(self.process.clone())
    }
}

impl ProcessMemory for LiveProcess {
    fn process(&self) -> &ProcessInfo {
        &self.process
    }

    fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    fn modules(&self) -> &[ModuleInfo] {
        &self.modules
    }

    fn coverage(&self) -> Coverage {
        let captured_readable_bytes = self.read_bytes.load(Ordering::Relaxed);
        let refused = self.refused_bytes.load(Ordering::Relaxed);
        // The captured/expected identity is preserved: every readable byte this
        // command did not read is unavailable, whether it was refused or never
        // attempted. `limitations` says which.
        let unavailable_readable_bytes = self
            .expected_readable_bytes
            .saturating_sub(captured_readable_bytes);

        let mut limitations = Vec::with_capacity(MAX_COVERAGE_LIMITATIONS);
        if captured_readable_bytes == 0 && refused == 0 {
            limitations.push(CoverageLimitation::ReadsNotAttempted);
        }
        if unavailable_readable_bytes != 0 {
            limitations.push(CoverageLimitation::ExpectedReadableScopeUnproven);
        }
        if refused != 0 {
            limitations.push(CoverageLimitation::ReadableBytesUnreadable);
        }
        debug_assert!(limitations.len() <= MAX_COVERAGE_LIMITATIONS);

        Coverage {
            expected_readable_bytes: self.expected_readable_bytes,
            captured_readable_bytes,
            unavailable_readable_bytes,
            // Region metadata comes straight from the kernel, so scope selectors that
            // need protection or type metadata are always answerable.
            metadata_complete: true,
            coverage_complete: unavailable_readable_bytes == 0 && refused == 0,
            observation: Some(ObservationInterval {
                started_at_unix_ms: self.started_at_unix_ms,
                completed_at_unix_ms: now_unix_millis(),
            }),
            limitations,
        }
    }

    fn for_each_scannable_span(
        &self,
        selection: Option<&[AddressRange]>,
        overlap: usize,
        visitor: &mut dyn FnMut(ScanChunk<'_>) -> Result<()>,
    ) -> Result<()> {
        let page = self.target.page_size();
        let mut buffer = vec![0_u8; SCAN_CHUNK_BYTES + overlap];

        for run in &self.runs {
            match selection {
                // Reading memory the caller excluded would cost gigabytes of copies
                // and page-ins for a scan that can never report them, so a scoped scan
                // never touches anything outside its scope.
                Some(ranges) => {
                    let first = ranges.partition_point(|range| range.end <= run.start);
                    for range in &ranges[first..] {
                        if range.start >= run.end {
                            break;
                        }
                        let start = range.start.max(run.start);
                        let end = range.end.min(run.end);
                        if start < end {
                            self.sweep(start, end, overlap, page, &mut buffer, visitor)?;
                        }
                    }
                }
                None => self.sweep(run.start, run.end, overlap, page, &mut buffer, visitor)?,
            }
        }
        Ok(())
    }

    fn read(&self, address: u64, length: usize) -> Result<Vec<ReadSegment>> {
        let requested_end = address
            .checked_add(length as u64)
            .ok_or_else(|| Error::InvalidArgument("read range overflows u64".into()))?;
        let page = self.target.page_size();
        let mut output: Vec<ReadSegment> = Vec::new();
        let mut buffer = vec![0_u8; length];

        for region in self.regions.iter().filter(|region| region.readable) {
            let region_end = region.end()?;
            let start = address.max(region.base.0);
            let end = requested_end.min(region_end);
            if start >= end {
                continue;
            }

            let mut cursor = start;
            while cursor < end {
                let offset = (cursor - address) as usize;
                let want = (end - cursor) as usize;
                let filled = self.fill(cursor, &mut buffer[offset..offset + want], page);
                if filled != 0 {
                    let bytes = &buffer[offset..offset + filled];
                    match output.last_mut() {
                        // Adjacent regions produce adjacent bytes; report them as one
                        // segment so the caller sees gaps, not enumeration artifacts.
                        Some(last) if last.address + last.bytes.len() as u64 == cursor => {
                            last.bytes.extend_from_slice(bytes);
                        }
                        _ => output.push(ReadSegment {
                            address: cursor,
                            bytes: bytes.to_vec(),
                        }),
                    }
                }
                if filled == want {
                    break;
                }
                let stopped_at = cursor + filled as u64;
                let skip = (page as u64 - (stopped_at % page as u64)).min(end - stopped_at);
                self.refused_bytes.fetch_add(skip, Ordering::Relaxed);
                cursor = stopped_at + skip;
            }
        }
        Ok(output)
    }
}

impl LiveProcess {
    /// Reads `[start, end)` in chunks and hands each contiguous readable stretch to
    /// `visitor`. The chunk carry is what lets a pattern straddle a chunk boundary; it
    /// restarts at every unreadable page, because a pattern cannot span bytes
    /// membridge never read.
    fn sweep(
        &self,
        start: u64,
        end: u64,
        overlap: usize,
        page: usize,
        buffer: &mut [u8],
        visitor: &mut dyn FnMut(ScanChunk<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut carry = 0_usize;
        let mut cursor = start;
        while cursor < end {
            let want = (end - cursor).min(SCAN_CHUNK_BYTES as u64) as usize;
            let filled = self.fill(cursor, &mut buffer[carry..carry + want], page);
            if filled != 0 {
                let base = cursor
                    .checked_sub(carry as u64)
                    .ok_or_else(|| Error::SourceInvariant("scan carry underflow".into()))?;
                visitor(ScanChunk {
                    base,
                    bytes: &buffer[..carry + filled],
                    carry,
                })?;
            }

            if filled == want {
                let total = carry + filled;
                let next_carry = overlap.min(total);
                buffer.copy_within(total - next_carry..total, 0);
                carry = next_carry;
                cursor += want as u64;
                continue;
            }

            // Enumeration said these bytes were readable and the kernel refused them:
            // the target reprotected or unmapped the page after enumeration, or it
            // raced away entirely. Skip that page, restart the carry, record the gap.
            let stopped_at = cursor + filled as u64;
            let skip = (page as u64 - (stopped_at % page as u64)).min(end - stopped_at);
            self.refused_bytes.fetch_add(skip, Ordering::Relaxed);
            carry = 0;
            cursor = stopped_at + skip;
        }
        Ok(())
    }

    /// Fills `buffer` from `address`, returning how many leading bytes were proven
    /// readable. One bulk call is attempted first; only when the kernel refuses it does
    /// the window retry page by page, so an unreadable page costs its own page and
    /// never the whole chunk. Bytes returned are counted as captured exactly once.
    fn fill(&self, address: u64, buffer: &mut [u8], page: usize) -> usize {
        let mut filled = self.target.read(address, buffer);
        if filled < buffer.len() {
            // Resume at the page boundary after whatever the bulk call delivered.
            loop {
                let at = address + filled as u64;
                let step = (page - (at % page as u64) as usize).min(buffer.len() - filled);
                if step == 0 {
                    break;
                }
                let got = self.target.read(at, &mut buffer[filled..filled + step]);
                filled += got;
                if got != step {
                    break;
                }
            }
        }
        self.read_bytes.fetch_add(filled as u64, Ordering::Relaxed);
        filled
    }
}

/// Rejects overlapping or unordered enumeration, which would make region attribution
/// and scope intersection ambiguous.
fn validate_regions(regions: &[MemoryRegion]) -> Result<()> {
    for pair in regions.windows(2) {
        if pair[0].end()? > pair[1].base.0 {
            return Err(Error::SourceInvariant(
                "overlapping memory regions are unsupported".into(),
            ));
        }
    }
    Ok(())
}

fn merge_readable_runs(regions: &[MemoryRegion]) -> Result<Vec<ReadableRun>> {
    let mut runs: Vec<ReadableRun> = Vec::new();
    for region in regions.iter().filter(|region| region.readable) {
        let end = region.end()?;
        match runs.last_mut() {
            Some(last) if last.end == region.base.0 => last.end = end,
            _ => runs.push(ReadableRun {
                start: region.base.0,
                end,
            }),
        }
    }
    Ok(runs)
}
