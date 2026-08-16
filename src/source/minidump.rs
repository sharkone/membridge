use std::fs::File;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use minidump::format::{MemoryProtection, MemoryState, MemoryType};
use minidump::system_info::{Cpu, Os};
use minidump::{
    Error as MinidumpError, Minidump, MinidumpMemoryInfoList, MinidumpModuleList,
    MinidumpSystemInfo, Module,
};

use super::{
    Address, Coverage, CoverageLimitation, MAX_COVERAGE_LIMITATIONS, MemoryRegion, MemorySource,
    ModuleInfo, PROTECTION_NAMES, ProcessInfo, ProcessMemory, ReadSegment, SourceInfo,
};
use crate::{Error, Result};

const PROCESS_ID: &str = "process:0";

/// Hard caps on minidump-derived structure counts. A crafted dump can pack an
/// attacker-controlled memory range descriptor into as little as 16 bytes with a
/// zero-length payload, and the region/segment interactions below are quadratic in
/// these counts; without a bound, a small hostile file can force minutes of CPU work
/// before any command returns. These limits are far above any real-world capture
/// (large processes rarely exceed a few thousand regions or modules) and, once hit,
/// fail closed with `SOURCE_TOO_LARGE` rather than silently truncating or hanging.
pub const MAX_CAPTURED_SEGMENTS: usize = 32_768;
pub const MAX_MEMORY_REGIONS: usize = 32_768;
pub const MAX_MODULES: usize = 32_768;

#[derive(Clone, Debug)]
struct SharedMmap(Arc<Mmap>);

impl Deref for SharedMmap {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
struct CapturedSegment {
    address: u64,
    length: u64,
    file_offset: usize,
}

#[derive(Debug, Clone)]
struct ScanExtent {
    address: u64,
    length: usize,
    file_offset: usize,
}

#[derive(Debug)]
pub struct MinidumpSource {
    info: SourceInfo,
    processes: Vec<ProcessInfo>,
    process: Arc<MinidumpProcess>,
}

#[derive(Debug)]
struct MinidumpProcess {
    data: SharedMmap,
    process: ProcessInfo,
    regions: Vec<MemoryRegion>,
    modules: Vec<ModuleInfo>,
    coverage: Coverage,
    captured: Vec<CapturedSegment>,
    scannable: Vec<ScanExtent>,
}

impl MinidumpSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        // SAFETY: `Mmap::map` is unsound in general if the backing file is mutated,
        // truncated, or replaced by another process while mapped, which can turn a live
        // `&[u8]` borrow into a reference over changing memory or trigger SIGBUS on a
        // truncated read. Membridge treats an opened dump as a static forensic artifact
        // for the lifetime of this process and relies on the caller not to mutate the
        // file underneath an active analysis; this mapping is opened read-only, no write
        // or protection-changing call is ever made against it, and its `&[u8]` view is
        // retained unchanged for the source's entire lifetime.
        let mmap = unsafe { Mmap::map(&file) }.map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let data = SharedMmap(Arc::new(mmap));
        let fingerprint = blake3::hash(&data).to_hex().to_string();
        let dump = Minidump::read(data.clone())?;

        let system = dump.get_stream::<MinidumpSystemInfo>()?;
        if system.os != Os::Windows || system.cpu != Cpu::X86_64 {
            return Err(Error::UnsupportedTarget(format!(
                "expected Windows x64, found {} {:?}",
                system.os, system.cpu
            )));
        }

        let memory = dump.get_memory().ok_or(Error::MissingMemory)?;
        let data_start = data.as_ptr() as usize;
        let data_end = data_start
            .checked_add(data.len())
            .ok_or_else(|| Error::SourceInvariant("mapped file address overflow".into()))?;

        let mut captured = Vec::new();
        for range in memory.by_addr() {
            let bytes = range.bytes();
            let start = bytes.as_ptr() as usize;
            let end = start
                .checked_add(bytes.len())
                .ok_or_else(|| Error::SourceInvariant("memory range address overflow".into()))?;
            if start < data_start || end > data_end {
                return Err(Error::SourceInvariant(
                    "minidump memory range is outside the mapped file".into(),
                ));
            }
            captured.push(CapturedSegment {
                address: range.base_address(),
                length: bytes.len() as u64,
                file_offset: start - data_start,
            });
            if captured.len() > MAX_CAPTURED_SEGMENTS {
                return Err(Error::SourceTooLarge(format!(
                    "captured memory range count exceeds the {MAX_CAPTURED_SEGMENTS} limit"
                )));
            }
        }
        validate_captured_segments(&captured)?;

        let modules = dump
            .get_stream::<MinidumpModuleList>()
            .map(|list| {
                list.by_addr()
                    .map(|module| ModuleInfo {
                        name: module.code_file().into_owned(),
                        base: Address(module.base_address()),
                        size: module.size(),
                        timestamp: module.raw.time_date_stamp,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if modules.len() > MAX_MODULES {
            return Err(Error::SourceTooLarge(format!(
                "module count {} exceeds the {MAX_MODULES} limit",
                modules.len()
            )));
        }

        let (memory_info, memory_metadata_limitation) =
            match dump.get_stream::<MinidumpMemoryInfoList>() {
                Ok(info) => (Some(info), None),
                Err(MinidumpError::StreamNotFound) => {
                    (None, Some(CoverageLimitation::MemoryMetadataMissing))
                }
                Err(_) => (None, Some(CoverageLimitation::MemoryMetadataUnusable)),
            };
        let metadata_complete = memory_info.is_some();
        let regions: Vec<MemoryRegion> = if let Some(info) = memory_info.as_ref() {
            info.by_addr()
                .enumerate()
                .map(|(id, item)| {
                    let base = item.raw.base_address;
                    let size = item.raw.region_size;
                    let committed = item.state.contains(MemoryState::MEM_COMMIT);
                    let readable = committed && is_readable(item.protection);
                    MemoryRegion {
                        id,
                        base: Address(base),
                        size,
                        captured_bytes: captured_overlap(base, size, &captured),
                        state: state_name(item.state).into(),
                        protection: protection_name(item.protection),
                        kind: kind_name(item.ty).into(),
                        committed,
                        readable,
                    }
                })
                .collect()
        } else {
            captured
                .iter()
                .enumerate()
                .map(|(id, segment)| MemoryRegion {
                    id,
                    base: Address(segment.address),
                    size: segment.length,
                    captured_bytes: segment.length,
                    state: "unknown".into(),
                    protection: "unknown".into(),
                    kind: "unknown".into(),
                    committed: true,
                    readable: true,
                })
                .collect()
        };
        if regions.len() > MAX_MEMORY_REGIONS {
            return Err(Error::SourceTooLarge(format!(
                "memory region count {} exceeds the {MAX_MEMORY_REGIONS} limit",
                regions.len()
            )));
        }

        let expected_readable_bytes = regions
            .iter()
            .filter(|region| region.committed && region.readable)
            .try_fold(0_u64, |total, region| total.checked_add(region.size))
            .ok_or_else(|| Error::SourceInvariant("readable byte count overflow".into()))?;
        let captured_readable_bytes = regions
            .iter()
            .filter(|region| region.committed && region.readable)
            .try_fold(0_u64, |total, region| {
                total.checked_add(region.captured_bytes)
            })
            .ok_or_else(|| Error::SourceInvariant("captured byte count overflow".into()))?;
        let unavailable_readable_bytes = expected_readable_bytes
            .checked_sub(captured_readable_bytes)
            .ok_or_else(|| {
                Error::SourceInvariant("captured bytes exceed expected readable bytes".into())
            })?;
        let mut limitations = Vec::with_capacity(MAX_COVERAGE_LIMITATIONS);
        if let Some(limitation) = memory_metadata_limitation {
            limitations.push(limitation);
            limitations.push(CoverageLimitation::ExpectedReadableScopeUnproven);
        }
        if unavailable_readable_bytes != 0 {
            limitations.push(CoverageLimitation::KnownReadableBytesMissing);
        }
        debug_assert!(limitations.len() <= MAX_COVERAGE_LIMITATIONS);

        let coverage = Coverage {
            expected_readable_bytes,
            captured_readable_bytes,
            unavailable_readable_bytes,
            metadata_complete,
            coverage_complete: metadata_complete && unavailable_readable_bytes == 0,
            limitations,
        };

        let scannable = build_scan_extents(&data, &captured, &regions)?;
        let display_name = modules
            .first()
            .and_then(|module| Path::new(&module.name).file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("minidump-process")
            .to_owned();
        let process = ProcessInfo {
            id: PROCESS_ID.into(),
            display_name,
        };
        let process_impl = Arc::new(MinidumpProcess {
            data,
            process: process.clone(),
            regions,
            modules,
            coverage,
            captured,
            scannable,
        });

        Ok(Self {
            info: SourceInfo {
                kind: "minidump",
                fingerprint,
                platform: "windows",
                architecture: "x86_64",
                immutable: true,
            },
            processes: vec![process],
            process: process_impl,
        })
    }
}

impl MemorySource for MinidumpSource {
    fn info(&self) -> &SourceInfo {
        &self.info
    }

    fn processes(&self) -> &[ProcessInfo] {
        &self.processes
    }

    fn open_process(&self, id: &str) -> Result<Arc<dyn ProcessMemory>> {
        if id != PROCESS_ID {
            return Err(Error::InvalidArgument(format!(
                "unknown process id {id:?}; expected {PROCESS_ID:?}"
            )));
        }
        Ok(self.process.clone())
    }
}

impl ProcessMemory for MinidumpProcess {
    fn process(&self) -> &ProcessInfo {
        &self.process
    }

    fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    fn modules(&self) -> &[ModuleInfo] {
        &self.modules
    }

    fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    fn for_each_scannable_span(
        &self,
        visitor: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        for extent in &self.scannable {
            let end = extent
                .file_offset
                .checked_add(extent.length)
                .ok_or_else(|| Error::SourceInvariant("scan extent overflow".into()))?;
            visitor(extent.address, &self.data[extent.file_offset..end])?;
        }
        Ok(())
    }

    fn read(&self, address: u64, length: usize) -> Result<Vec<ReadSegment>> {
        let requested_end = address
            .checked_add(length as u64)
            .ok_or_else(|| Error::InvalidArgument("read range overflows u64".into()))?;
        let mut output = Vec::new();
        for segment in &self.captured {
            let segment_end = segment
                .address
                .checked_add(segment.length)
                .ok_or_else(|| Error::SourceInvariant("captured address range overflow".into()))?;
            let start = address.max(segment.address);
            let end = requested_end.min(segment_end);
            if start >= end {
                continue;
            }
            let within = (start - segment.address) as usize;
            let file_start = segment.file_offset + within;
            let byte_count = (end - start) as usize;
            output.push(ReadSegment {
                address: start,
                bytes: self.data[file_start..file_start + byte_count].to_vec(),
            });
        }
        Ok(output)
    }
}

fn validate_captured_segments(segments: &[CapturedSegment]) -> Result<()> {
    for pair in segments.windows(2) {
        let end = pair[0]
            .address
            .checked_add(pair[0].length)
            .ok_or_else(|| Error::SourceInvariant("captured address range overflow".into()))?;
        if end > pair[1].address {
            return Err(Error::SourceInvariant(
                "overlapping captured memory ranges are unsupported".into(),
            ));
        }
    }
    Ok(())
}

fn captured_overlap(base: u64, size: u64, captured: &[CapturedSegment]) -> u64 {
    let Some(end) = base.checked_add(size) else {
        return 0;
    };
    captured
        .iter()
        .map(|segment| {
            let segment_end = segment.address.saturating_add(segment.length);
            end.min(segment_end)
                .saturating_sub(base.max(segment.address))
        })
        .sum()
}

fn build_scan_extents(
    data: &[u8],
    captured: &[CapturedSegment],
    regions: &[MemoryRegion],
) -> Result<Vec<ScanExtent>> {
    let mut extents = Vec::new();
    for segment in captured {
        let segment_end = segment
            .address
            .checked_add(segment.length)
            .ok_or_else(|| Error::SourceInvariant("captured address range overflow".into()))?;
        for region in regions
            .iter()
            .filter(|region| region.committed && region.readable)
        {
            let region_end =
                region.base.0.checked_add(region.size).ok_or_else(|| {
                    Error::SourceInvariant("region address range overflow".into())
                })?;
            let start = segment.address.max(region.base.0);
            let end = segment_end.min(region_end);
            if start >= end {
                continue;
            }
            let offset = segment
                .file_offset
                .checked_add((start - segment.address) as usize)
                .ok_or_else(|| Error::SourceInvariant("scan file offset overflow".into()))?;
            let length = (end - start) as usize;
            if offset
                .checked_add(length)
                .is_none_or(|end| end > data.len())
            {
                return Err(Error::SourceInvariant(
                    "scan extent is outside the mapped file".into(),
                ));
            }
            extents.push(ScanExtent {
                address: start,
                length,
                file_offset: offset,
            });
        }
    }
    extents.sort_by_key(|extent| extent.address);

    let mut merged: Vec<ScanExtent> = Vec::with_capacity(extents.len());
    for extent in extents {
        if let Some(previous) = merged.last_mut() {
            let previous_address_end = previous.address + previous.length as u64;
            let previous_file_end = previous.file_offset + previous.length;
            if previous_address_end == extent.address && previous_file_end == extent.file_offset {
                previous.length = previous
                    .length
                    .checked_add(extent.length)
                    .ok_or_else(|| Error::SourceInvariant("merged extent overflow".into()))?;
                continue;
            }
        }
        merged.push(extent);
    }
    Ok(merged)
}

fn is_readable(protection: MemoryProtection) -> bool {
    if protection.contains(MemoryProtection::PAGE_GUARD)
        || protection.contains(MemoryProtection::PAGE_NOACCESS)
    {
        return false;
    }
    protection.intersects(
        MemoryProtection::PAGE_READONLY
            | MemoryProtection::PAGE_READWRITE
            | MemoryProtection::PAGE_WRITECOPY
            | MemoryProtection::PAGE_EXECUTE_READ
            | MemoryProtection::PAGE_EXECUTE_READWRITE
            | MemoryProtection::PAGE_EXECUTE_WRITECOPY,
    )
}

fn state_name(state: MemoryState) -> &'static str {
    if state.contains(MemoryState::MEM_COMMIT) {
        "committed"
    } else if state.contains(MemoryState::MEM_RESERVE) {
        "reserved"
    } else if state.contains(MemoryState::MEM_FREE) {
        "free"
    } else {
        "unknown"
    }
}

/// Index-aligned with `super::PROTECTION_NAMES`.
const PROTECTION_FLAGS: [MemoryProtection; PROTECTION_NAMES.len()] = [
    MemoryProtection::PAGE_NOACCESS,
    MemoryProtection::PAGE_READONLY,
    MemoryProtection::PAGE_READWRITE,
    MemoryProtection::PAGE_WRITECOPY,
    MemoryProtection::PAGE_EXECUTE,
    MemoryProtection::PAGE_EXECUTE_READ,
    MemoryProtection::PAGE_EXECUTE_READWRITE,
    MemoryProtection::PAGE_EXECUTE_WRITECOPY,
    MemoryProtection::PAGE_GUARD,
    MemoryProtection::PAGE_NOCACHE,
    MemoryProtection::PAGE_WRITECOMBINE,
];

/// Renders a region's protection as stable lowercase flag tokens joined by `" | "`,
/// so callers and scope selectors never depend on a derived `Debug` rendering. Bits
/// outside the documented flag set are reported verbatim as hexadecimal rather than
/// dropped.
fn protection_name(protection: MemoryProtection) -> String {
    let mut known = MemoryProtection::empty();
    let mut rendered = String::new();
    for (flag, name) in PROTECTION_FLAGS.into_iter().zip(PROTECTION_NAMES) {
        known |= flag;
        if protection.contains(flag) {
            if !rendered.is_empty() {
                rendered.push_str(" | ");
            }
            rendered.push_str(name);
        }
    }
    let unknown = protection.bits() & !known.bits();
    if unknown != 0 {
        if !rendered.is_empty() {
            rendered.push_str(" | ");
        }
        rendered.push_str(&format!("0x{unknown:x}"));
    }
    if rendered.is_empty() {
        rendered.push_str("none");
    }
    rendered
}

fn kind_name(kind: MemoryType) -> &'static str {
    if kind.contains(MemoryType::MEM_PRIVATE) {
        "private"
    } else if kind.contains(MemoryType::MEM_MAPPED) {
        "mapped"
    } else if kind.contains(MemoryType::MEM_IMAGE) {
        "image"
    } else {
        "unknown"
    }
}
