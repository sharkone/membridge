//! Live-source stub for hosts membridge has no read-only acquisition path for.
//!
//! Every entry point fails closed with `UNSUPPORTED_HOST`. Nothing here guesses at a
//! ptrace-like fallback: an unsupported host reports that it is unsupported.

use super::{RawRegion, TargetIdentity};
use crate::source::ModuleInfo;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct Target {
    identity: TargetIdentity,
}

impl Target {
    pub(crate) const PLATFORM: &'static str = "unsupported";

    pub(crate) fn open(_pid: u32) -> Result<Self> {
        Err(Error::UnsupportedHost(
            "live process inspection is available on macOS, Linux, and Windows".into(),
        ))
    }

    pub(crate) fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    pub(crate) fn page_size(&self) -> usize {
        4096
    }

    pub(crate) fn regions(&self) -> Result<Vec<RawRegion>> {
        Ok(Vec::new())
    }

    pub(crate) fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(Vec::new())
    }

    pub(crate) fn read(&self, _address: u64, _buffer: &mut [u8]) -> usize {
        0
    }
}
