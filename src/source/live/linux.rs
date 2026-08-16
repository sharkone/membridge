//! Linux live target backed by procfs and `process_vm_readv`.
//!
//! Neither `/proc/<pid>/maps` nor `process_vm_readv` attaches to, stops, or signals
//! the target: the kernel performs a `ptrace_may_access` permission check and copies
//! bytes out of a still-running process. Membridge never calls `ptrace`, so the target
//! is never suspended and no tracer relationship is established.
//!
//! Access is governed by that check plus Yama `ptrace_scope`: a same-uid dumpable
//! target is readable at scope 0, a descendant of membridge is readable at scope 1,
//! and scope 2 or a foreign uid requires `CAP_SYS_PTRACE`.

use std::fs;
use std::os::raw::{c_int, c_long};
use std::path::PathBuf;

use super::{RawRegion, TargetIdentity};
use crate::source::{Access, Address, ModuleInfo};
use crate::{Error, Result};

const SC_CLK_TCK: c_int = 2;
const SC_PAGESIZE: c_int = 30;
const EPERM: i32 = 1;
const ESRCH: i32 = 3;
const EACCES: i32 = 13;

#[repr(C)]
struct IoVec {
    base: *mut u8,
    len: usize,
}

unsafe extern "C" {
    fn process_vm_readv(
        pid: c_int,
        local_iov: *const IoVec,
        liovcnt: u64,
        remote_iov: *const IoVec,
        riovcnt: u64,
        flags: u64,
    ) -> isize;
    fn sysconf(name: c_int) -> c_long;
    fn __errno_location() -> *mut c_int;
}

fn errno() -> i32 {
    // SAFETY: glibc's per-thread errno slot is always a valid pointer.
    unsafe { *__errno_location() }
}

#[derive(Debug)]
pub(crate) struct Target {
    pid: u32,
    identity: TargetIdentity,
    page: usize,
}

impl Target {
    pub(crate) const PLATFORM: &'static str = "linux";

    pub(crate) fn open(pid: u32) -> Result<Self> {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        if !proc.exists() {
            return Err(Error::ProcessNotFound(pid));
        }
        let image_path = fs::read_link(proc.join("exe"))
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|error| match error.raw_os_error() {
                Some(code) if code == EACCES || code == EPERM => Error::ProcessAccessDenied(
                    format!("process {pid} refused /proc/{pid}/exe: {error}"),
                ),
                _ => Error::ProcessNotFound(pid),
            })?;
        let start_time_unix_ms = start_time_unix_ms(pid)?;

        // SAFETY: `SC_PAGESIZE` is a valid sysconf name; the call has no side effects.
        let page = unsafe { sysconf(SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|page| page.is_power_of_two())
            .ok_or_else(|| Error::ProcessQueryFailed("host reported no usable page size".into()))?;

        let target = Self {
            pid,
            identity: TargetIdentity {
                pid,
                image_path,
                start_time_unix_ms,
            },
            page,
        };
        target.probe_access()?;
        Ok(target)
    }

    /// Proves read permission at open time rather than letting every scanned byte
    /// silently fail later. Reads one byte from the first readable mapping; a target
    /// with no readable mapping needs no proof.
    fn probe_access(&self) -> Result<()> {
        let Some(region) = self
            .regions()?
            .into_iter()
            .find(|region| region.access.read && region.size > 0)
        else {
            return Ok(());
        };
        let mut byte = [0_u8; 1];
        if self.read(region.base, &mut byte) == 1 {
            return Ok(());
        }
        match errno() {
            ESRCH => Err(Error::ProcessNotFound(self.pid)),
            EPERM | EACCES => Err(Error::ProcessAccessDenied(format!(
                "the kernel refused to read process {}: ptrace_may_access denied it. \
                 Membridge must run as the target's user with a dumpable target, as an \
                 ancestor of the target when /proc/sys/kernel/yama/ptrace_scope is 1, or \
                 with CAP_SYS_PTRACE",
                self.pid
            ))),
            code => Err(Error::ProcessQueryFailed(format!(
                "reading process {} failed with errno {code}",
                self.pid
            ))),
        }
    }

    pub(crate) fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    pub(crate) fn page_size(&self) -> usize {
        self.page
    }

    pub(crate) fn regions(&self) -> Result<Vec<RawRegion>> {
        let maps =
            fs::read_to_string(format!("/proc/{}/maps", self.pid)).map_err(|error| match error
                .raw_os_error()
            {
                Some(code) if code == EACCES || code == EPERM => Error::ProcessAccessDenied(
                    format!("process {} refused its mapping list: {error}", self.pid),
                ),
                _ => Error::ProcessNotFound(self.pid),
            })?;

        let mut regions = Vec::new();
        for line in maps.lines() {
            let Some(entry) = parse_maps_line(line) else {
                continue;
            };
            regions.push(entry);
            if regions.len() > super::MAX_LIVE_REGIONS {
                return Err(Error::SourceTooLarge(format!(
                    "memory region count exceeds the {} limit",
                    super::MAX_LIVE_REGIONS
                )));
            }
        }
        Ok(regions)
    }

    /// Derives modules from file-backed executable mappings. The dynamic linker's
    /// `link_map` chain would name the same objects, but it must be walked through the
    /// target's own pointers while it runs; procfs states the mapping facts directly.
    pub(crate) fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))
            .map_err(|error| Error::ProcessQueryFailed(error.to_string()))?;

        let mut modules: Vec<ModuleInfo> = Vec::new();
        let mut spans: Vec<(String, u64, u64)> = Vec::new();
        for line in maps.lines() {
            let Some((path, start, end, executable)) = parse_maps_module(line) else {
                continue;
            };
            match spans.iter_mut().find(|(name, _, _)| name == &path) {
                Some((_, low, high)) => {
                    *low = (*low).min(start);
                    *high = (*high).max(end);
                }
                None if executable => spans.push((path, start, end)),
                None => {}
            }
        }
        for (name, start, end) in spans {
            modules.push(ModuleInfo {
                name,
                base: Address(start),
                size: end - start,
                // An ELF build id would identify the mapping, but reading it means
                // parsing notes out of the running target; procfs alone proves nothing.
                identity: None,
            });
            if modules.len() > super::MAX_LIVE_MODULES {
                return Err(Error::SourceTooLarge(format!(
                    "module count exceeds the {} limit",
                    super::MAX_LIVE_MODULES
                )));
            }
        }
        modules.sort_by_key(|module| module.base);
        Ok(modules)
    }

    /// Reads up to `buffer.len()` bytes. `process_vm_readv` stops at the first
    /// unreadable page and reports the bytes it did transfer, so a short return is a
    /// truthful prefix rather than an error.
    pub(crate) fn read(&self, address: u64, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let local = IoVec {
            base: buffer.as_mut_ptr(),
            len: buffer.len(),
        };
        let remote = IoVec {
            base: address as *mut u8,
            len: buffer.len(),
        };
        // SAFETY: one local iovec describing the live exclusive borrow `buffer`, and
        // one remote iovec that the kernel only interprets as target addresses.
        let read = unsafe { process_vm_readv(self.pid as c_int, &local, 1, &remote, 1, 0) };
        if read <= 0 {
            return 0;
        }
        (read as usize).min(buffer.len())
    }
}

/// Parses one `/proc/<pid>/maps` line: `start-end perms offset dev inode [path]`.
fn parse_maps_line(line: &str) -> Option<RawRegion> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let inode: u64 = fields.next()?.parse().ok()?;
    let path = fields.next().unwrap_or_default();

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    if end <= start {
        return None;
    }
    let mut chars = perms.chars();
    let access = Access {
        read: chars.next() == Some('r'),
        write: chars.next() == Some('w'),
        execute: chars.next() == Some('x'),
    };

    Some(RawRegion {
        base: start,
        size: end - start,
        access,
        native: perms.to_owned(),
        kind: if inode != 0 && access.execute {
            "image"
        } else if inode != 0 || path.starts_with("/memfd:") {
            "mapped"
        } else {
            "private"
        },
        // procfs lists only established mappings; unmapped address space is a gap
        // between lines, never a line of its own.
        state: "committed",
        committed: true,
    })
}

fn parse_maps_module(line: &str) -> Option<(String, u64, u64, bool)> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let inode: u64 = fields.next()?.parse().ok()?;
    let path = fields.next()?;
    if inode == 0 || !path.starts_with('/') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    Some((
        path.to_owned(),
        u64::from_str_radix(start, 16).ok()?,
        u64::from_str_radix(end, 16).ok()?,
        perms.contains('x'),
    ))
}

/// Converts the target's `starttime` (field 22 of `/proc/<pid>/stat`, in clock ticks
/// since boot) into wall-clock milliseconds using `btime` from `/proc/stat`, so a
/// reused PID is distinguishable from the original process.
fn start_time_unix_ms(pid: u32) -> Result<u64> {
    let stat =
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| Error::ProcessNotFound(pid))?;
    // Field 2 is the executable name in parentheses and may itself contain spaces and
    // parentheses, so counting starts after the final ')'. The field right after it is
    // field 3, which puts `starttime` (field 22) at index 19.
    let tail = stat
        .rsplit_once(')')
        .map_or(stat.as_str(), |(_, tail)| tail);
    let ticks: u64 = tail
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::ProcessQueryFailed(format!("/proc/{pid}/stat has no start time")))?;

    // SAFETY: `SC_CLK_TCK` is a valid sysconf name; the call has no side effects.
    let hertz = unsafe { sysconf(SC_CLK_TCK) };
    let hertz = u64::try_from(hertz).unwrap_or(100).max(1);

    let boot_seconds = fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|stat| {
            stat.lines()
                .find_map(|line| line.strip_prefix("btime "))
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
        .unwrap_or(0);

    Ok(boot_seconds
        .saturating_mul(1_000)
        .saturating_add(ticks.saturating_mul(1_000) / hertz))
}
