mod minidump;

use std::sync::Arc;

use serde::{Serialize, Serializer};

use crate::Result;

pub use minidump::MinidumpSource;

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
    pub timestamp: u32,
}

impl ModuleInfo {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base.0
            && address
                .checked_sub(self.base.0)
                .is_some_and(|offset| offset < self.size)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRegion {
    pub id: usize,
    pub base: Address,
    pub size: u64,
    pub captured_bytes: u64,
    pub state: String,
    pub protection: String,
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
}

pub const MAX_COVERAGE_LIMITATIONS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageLimitation {
    MemoryMetadataMissing,
    MemoryMetadataUnusable,
    ExpectedReadableScopeUnproven,
    KnownReadableBytesMissing,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub expected_readable_bytes: u64,
    pub captured_readable_bytes: u64,
    pub unavailable_readable_bytes: u64,
    pub metadata_complete: bool,
    pub coverage_complete: bool,
    pub limitations: Vec<CoverageLimitation>,
}

#[derive(Debug, Clone)]
pub struct ReadSegment {
    pub address: u64,
    pub bytes: Vec<u8>,
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
    fn coverage(&self) -> &Coverage;

    fn for_each_scannable_span(
        &self,
        visitor: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()>;

    fn read(&self, address: u64, length: usize) -> Result<Vec<ReadSegment>>;
}
