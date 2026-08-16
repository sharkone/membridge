mod live;
mod minidump;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Serialize, Serializer};

use crate::{Error, Result};

pub use live::{LiveSource, MAX_LIVE_MODULES, MAX_LIVE_REGIONS, SCAN_CHUNK_BYTES};
pub use minidump::{MAX_CAPTURED_SEGMENTS, MAX_MEMORY_REGIONS, MAX_MODULES, MinidumpSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub u64);

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:016x}", self.0))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    pub kind: &'static str,
    pub fingerprint: String,
    pub platform: &'static str,
    pub architecture: &'static str,
    /// `true` when the source bytes cannot change while membridge analyses them, so
    /// an identical command reproduces an identical answer. Live process sources are
    /// never immutable: the target keeps running between enumeration and every read.
    pub immutable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: Address,
    pub size: u64,
    /// Stable source-native module identity, rendered as a lowercase hexadecimal
    /// string: the PE `TimeDateStamp` for Windows minidumps and live Windows
    /// processes, and the Mach-O `LC_UUID` for macOS. `None` when the source cannot
    /// prove an identity without reading the module's file from disk, which is the
    /// normal case on Linux.
    pub identity: Option<String>,
}

impl ModuleInfo {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base.0
            && address
                .checked_sub(self.base.0)
                .is_some_and(|offset| offset < self.size)
    }
}

/// Canonical portable memory-access names. `MemoryRegion::protection` joins the
/// access rights a region carries with `" | "` using exactly these names, and scan
/// scope selectors are validated against the same list. Every source normalizes onto
/// this vocabulary; the untranslated platform rendering stays in
/// `MemoryRegion::native_protection`.
pub const PROTECTION_NAMES: [&str; 3] = ["read", "write", "execute"];

/// Rendered by `MemoryRegion::protection` when a region carries no access rights at
/// all (Windows `PAGE_NOACCESS`, mach `VM_PROT_NONE`, Linux `---p`). Deliberately not
/// selectable: an inaccessible region is never scannable.
pub const PROTECTION_NONE: &str = "none";

/// Rendered when a source provides no protection metadata for a region.
pub const UNKNOWN_NAME: &str = "unknown";

/// Canonical normalized `MemoryRegion::kind` values. A region whose type metadata is
/// absent reports `"unknown"`, which is deliberately not selectable.
pub const TYPE_NAMES: [&str; 3] = ["private", "mapped", "image"];

/// Portable memory access rights, normalized from every source's native protection
/// encoding. Rendering lives in `Access::render`, so the observable protection
/// vocabulary has exactly one definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Access {
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };

    pub fn render(self) -> String {
        let mut rendered = String::new();
        for (present, name) in [
            (self.read, PROTECTION_NAMES[0]),
            (self.write, PROTECTION_NAMES[1]),
            (self.execute, PROTECTION_NAMES[2]),
        ] {
            if present {
                if !rendered.is_empty() {
                    rendered.push_str(" | ");
                }
                rendered.push_str(name);
            }
        }
        if rendered.is_empty() {
            rendered.push_str(PROTECTION_NONE);
        }
        rendered
    }
}

/// Canonical lowercase Windows page-protection flag names. Both Windows sources - the
/// minidump reader and the live process reader - render `native_protection` with
/// exactly these tokens, joined by `" | "`.
pub const WINDOWS_PROTECTION_NAMES: [&str; 11] = [
    "page_noaccess",
    "page_readonly",
    "page_readwrite",
    "page_writecopy",
    "page_execute",
    "page_execute_read",
    "page_execute_readwrite",
    "page_execute_writecopy",
    "page_guard",
    "page_nocache",
    "page_writecombine",
];

/// Index-aligned with `WINDOWS_PROTECTION_NAMES`.
const WINDOWS_PROTECTION_BITS: [u32; WINDOWS_PROTECTION_NAMES.len()] = [
    0x0000_0001,
    0x0000_0002,
    0x0000_0004,
    0x0000_0008,
    0x0000_0010,
    0x0000_0020,
    0x0000_0040,
    0x0000_0080,
    0x0000_0100,
    0x0000_0200,
    0x0000_0400,
];

/// Normalizes Win32 `PAGE_*` protection bits into portable access rights plus the
/// untranslated Windows rendering. Bits outside the documented set are reported
/// verbatim as hexadecimal rather than dropped.
///
/// A guard page is reported as unreadable: the first access to it raises
/// `STATUS_GUARD_PAGE_VIOLATION` in the target rather than returning bytes, so
/// treating it as readable would promise data membridge cannot deliver. Its write and
/// execute rights, and the `page_guard` token itself, are preserved.
pub(crate) fn windows_protection(bits: u32) -> (Access, String) {
    const NOACCESS: u32 = 0x0000_0001;
    const GUARD: u32 = 0x0000_0100;
    const READ_BITS: u32 =
        0x0000_0002 | 0x0000_0004 | 0x0000_0008 | 0x0000_0020 | 0x0000_0040 | 0x0000_0080;
    const WRITE_BITS: u32 = 0x0000_0004 | 0x0000_0008 | 0x0000_0040 | 0x0000_0080;
    const EXECUTE_BITS: u32 = 0x0000_0010 | 0x0000_0020 | 0x0000_0040 | 0x0000_0080;

    let blocked = bits & (NOACCESS | GUARD) != 0;
    let access = Access {
        read: !blocked && bits & READ_BITS != 0,
        write: bits & WRITE_BITS != 0,
        execute: bits & EXECUTE_BITS != 0,
    };

    let mut known = 0_u32;
    let mut native = String::new();
    for (flag, name) in WINDOWS_PROTECTION_BITS
        .into_iter()
        .zip(WINDOWS_PROTECTION_NAMES)
    {
        known |= flag;
        if bits & flag != 0 {
            if !native.is_empty() {
                native.push_str(" | ");
            }
            native.push_str(name);
        }
    }
    let unknown = bits & !known;
    if unknown != 0 {
        if !native.is_empty() {
            native.push_str(" | ");
        }
        native.push_str(&format!("0x{unknown:x}"));
    }
    if native.is_empty() {
        native.push_str(PROTECTION_NONE);
    }
    (access, native)
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRegion {
    pub id: usize,
    pub base: Address,
    pub size: u64,
    /// Bytes of this region present in an immutable captured source. `None` for live
    /// sources, where nothing is captured ahead of time and readability is only
    /// proven by an actual read; see `Coverage` for what a live command observed.
    pub captured_bytes: Option<u64>,
    pub state: String,
    /// Portable access rights, drawn from `PROTECTION_NAMES`.
    pub protection: String,
    /// The source's own protection rendering, kept verbatim for callers that need
    /// platform detail: `page_execute_read`, `r-x`, or `r-xp`.
    pub native_protection: String,
    pub kind: String,
    pub committed: bool,
    pub readable: bool,
}

impl MemoryRegion {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base.0
            && address
                .checked_sub(self.base.0)
                .is_some_and(|offset| offset < self.size)
    }

    pub fn end(&self) -> Result<u64> {
        self.base
            .0
            .checked_add(self.size)
            .ok_or_else(|| Error::SourceInvariant("region address range overflow".into()))
    }
}

pub const MAX_COVERAGE_LIMITATIONS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageLimitation {
    MemoryMetadataMissing,
    MemoryMetadataUnusable,
    ExpectedReadableScopeUnproven,
    KnownReadableBytesMissing,
    /// A live command enumerated regions without reading them, so no readable byte
    /// has been proven present. `inspect` always reports this for a live source.
    ReadsNotAttempted,
    /// A live read of memory the source enumerated as readable failed: the target
    /// unmapped or reprotected it after enumeration, or the kernel refused the read.
    /// Absence of a value in such a range is never proven.
    ReadableBytesUnreadable,
}

/// Wall-clock window a live observation spans. Immutable sources report `None`: their
/// bytes are frozen, so no interval is meaningful.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ObservationInterval {
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub expected_readable_bytes: u64,
    pub captured_readable_bytes: u64,
    pub unavailable_readable_bytes: u64,
    pub metadata_complete: bool,
    pub coverage_complete: bool,
    pub observation: Option<ObservationInterval>,
    pub limitations: Vec<CoverageLimitation>,
}

#[derive(Debug, Clone)]
pub struct ReadSegment {
    pub address: u64,
    pub bytes: Vec<u8>,
}

/// A half-open address interval `[start, end)`. Scan scopes are resolved into these,
/// and a source is handed the resolved selection so it only ever touches memory the
/// caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

/// One contiguous run of readable bytes handed to the scanner.
///
/// A live source cannot materialize a multi-gigabyte region, so it delivers a run in
/// chunks. `carry` is the number of leading bytes that the previous chunk already
/// delivered, present only so a pattern straddling the chunk boundary is still found.
/// The scanner emits a match only when it ends after `base + carry`, which is exactly
/// the set of matches the previous chunk could not have contained. Sources that own
/// whole runs (a mapped minidump) always pass `carry: 0`.
#[derive(Debug)]
pub struct ScanChunk<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
    pub carry: usize,
}

pub trait MemorySource: Send + Sync {
    fn info(&self) -> &SourceInfo;
    fn processes(&self) -> &[ProcessInfo];
    fn open_process(&self, id: &str) -> Result<Arc<dyn ProcessMemory>>;
}

pub trait ProcessMemory: Send + Sync {
    fn process(&self) -> &ProcessInfo;
    fn regions(&self) -> &[MemoryRegion];
    fn modules(&self) -> &[ModuleInfo];

    /// Coverage observed so far. Immutable sources answer from metadata computed once
    /// at open; live sources answer from what the current command actually read, so
    /// this is called after a scan, never cached across commands.
    fn coverage(&self) -> Coverage;

    /// Visits readable bytes in ascending address order.
    ///
    /// `selection` is the resolved scan scope, or `None` for every readable byte. A
    /// source that must copy memory to deliver it - every live source - reads only
    /// what the selection covers, so a narrowly scoped scan never touches the whole
    /// address space. A source that already owns its bytes may ignore it; the scanner
    /// applies the scope again in either case.
    ///
    /// `overlap` is the largest number of trailing bytes the scanner needs repeated at
    /// the head of a following chunk so a pattern spanning a chunk boundary is still
    /// found; a source that never splits a run may ignore it.
    fn for_each_scannable_span(
        &self,
        selection: Option<&[AddressRange]>,
        overlap: usize,
        visitor: &mut dyn FnMut(ScanChunk<'_>) -> Result<()>,
    ) -> Result<()>;

    fn read(&self, address: u64, length: usize) -> Result<Vec<ReadSegment>>;
}

pub(crate) fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}
