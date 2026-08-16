//! Windows live target backed by `VirtualQueryEx` and `ReadProcessMemory`.
//!
//! The process handle is opened with `PROCESS_QUERY_LIMITED_INFORMATION |
//! PROCESS_VM_READ` - the least authority that can enumerate and read - and never with
//! `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, or any thread right, so the handle
//! itself cannot mutate the target. The target is never suspended and no debugger is
//! attached; reads observe a running process.

use std::ffi::c_void;

use windows::Win32::Foundation::{CloseHandle, ERROR_PARTIAL_COPY, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_TYPE, VirtualQueryEx,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use super::{RawRegion, TargetIdentity};
use crate::source::{Access, Address, ModuleInfo, windows_protection};
use crate::{Error, Result};

/// Ticks between the Windows epoch (1601-01-01) and the Unix epoch (1970-01-01).
const FILETIME_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const MAX_IMAGE_PATH_CHARS: usize = 32_768;
/// A PE header is a few kilobytes; anything larger is not a header worth trusting.
const PE_HEADER_PROBE_BYTES: usize = 4096;

/// Owns the process handle for the source's lifetime.
#[derive(Debug)]
struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a handle this type opened and never closed elsewhere.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// SAFETY: a Windows process handle is a kernel object reference, valid from any
// thread. Only read-only queries are issued against it, and it is closed exactly once
// by `Drop` when the last owner goes away.
unsafe impl Send for ProcessHandle {}
unsafe impl Sync for ProcessHandle {}

#[derive(Debug)]
pub(crate) struct Target {
    process: ProcessHandle,
    identity: TargetIdentity,
    page: usize,
}

impl Target {
    pub(crate) const PLATFORM: &'static str = "windows";

    pub(crate) fn open(pid: u32) -> Result<Self> {
        // SAFETY: the requested rights are read-only and the PID is validated by the
        // kernel, which fails the call rather than returning an unusable handle.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        }
        .map_err(|error| {
            Error::ProcessAccessDenied(format!(
                "opening process {pid} for read-only inspection failed: {error}. Membridge \
                 must run at an integrity level and privilege at least matching the target; \
                 a protected process cannot be read at all"
            ))
        })?;
        let process = ProcessHandle(handle);

        let mut creation_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();
        // SAFETY: four live out-parameters and a handle carrying QUERY_LIMITED rights.
        unsafe {
            GetProcessTimes(
                process.0,
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            )
        }
        .map_err(|error| {
            Error::ProcessQueryFailed(format!("process {pid} times are unavailable: {error}"))
        })?;
        let start_time_unix_ms = filetime_to_unix_millis(creation_time).ok_or_else(|| {
            Error::ProcessQueryFailed("target process creation time predates the Unix epoch".into())
        })?;

        let mut buffer = vec![0_u16; MAX_IMAGE_PATH_CHARS];
        let mut length = buffer.len() as u32;
        // SAFETY: `buffer` owns `length` UTF-16 units; the call writes at most that
        // many and updates `length` with the count it wrote.
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(|error| {
            Error::ProcessQueryFailed(format!("process {pid} image path is unavailable: {error}"))
        })?;
        let image_path = String::from_utf16_lossy(&buffer[..length as usize]);

        let mut system = SYSTEM_INFO::default();
        // SAFETY: `system` is a live out-parameter of exactly the expected type.
        unsafe { GetSystemInfo(&mut system) };
        let page = system.dwPageSize as usize;
        if !page.is_power_of_two() {
            return Err(Error::ProcessQueryFailed(
                "host reported no usable page size".into(),
            ));
        }

        Ok(Self {
            process,
            identity: TargetIdentity {
                pid,
                image_path,
                start_time_unix_ms,
            },
            page,
        })
    }

    pub(crate) fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    pub(crate) fn page_size(&self) -> usize {
        self.page
    }

    pub(crate) fn regions(&self) -> Result<Vec<RawRegion>> {
        let mut regions = Vec::new();
        let mut address = 0_usize;
        loop {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: `info` is a live out-parameter whose declared size matches the
            // structure the kernel fills.
            let written = unsafe {
                VirtualQueryEx(
                    self.process.0,
                    Some(address as *const c_void),
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                break;
            }
            let size = info.RegionSize as u64;
            if size == 0 {
                break;
            }

            let committed = info.State == MEM_COMMIT;
            // Free address space is not a mapping; only committed and reserved ranges
            // are part of the target's address space.
            if committed || info.State == MEM_RESERVE {
                let (access, native) = windows_protection(info.Protect.0);
                regions.push(RawRegion {
                    base: info.BaseAddress as u64,
                    size,
                    // A reserved range carries no pages, so it can never be read.
                    access: if committed { access } else { Access::NONE },
                    native: if committed {
                        native
                    } else {
                        String::from("none")
                    },
                    kind: kind_name(info.Type),
                    state: if committed { "committed" } else { "reserved" },
                    committed,
                });
                if regions.len() > super::MAX_LIVE_REGIONS {
                    return Err(Error::SourceTooLarge(format!(
                        "memory region count exceeds the {} limit",
                        super::MAX_LIVE_REGIONS
                    )));
                }
            }

            let Some(next) = address.checked_add(info.RegionSize) else {
                break;
            };
            address = next;
        }
        Ok(regions)
    }

    pub(crate) fn modules(&self) -> Result<Vec<ModuleInfo>> {
        // A Toolhelp snapshot needs only the PID, so module enumeration does not force
        // the handle to carry the broader PROCESS_QUERY_INFORMATION right.
        // SAFETY: the call takes plain scalars and returns a handle or an error.
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.identity.pid)
        }
        .map_err(|error| {
            Error::ProcessQueryFailed(format!(
                "module enumeration for process {} failed: {error}",
                self.identity.pid
            ))
        })?;
        let snapshot = ProcessHandle(snapshot);

        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        let mut modules = Vec::new();
        // SAFETY: `entry` declares its own size and is a live out-parameter.
        let mut more = unsafe { Module32FirstW(snapshot.0, &mut entry) }.is_ok();
        while more {
            let name_end = entry
                .szExePath
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExePath.len());
            let base = entry.modBaseAddr as u64;
            modules.push(ModuleInfo {
                name: String::from_utf16_lossy(&entry.szExePath[..name_end]),
                base: Address(base),
                size: u64::from(entry.modBaseSize),
                identity: self.pe_timestamp(base).map(|stamp| format!("{stamp:08x}")),
            });
            if modules.len() > super::MAX_LIVE_MODULES {
                return Err(Error::SourceTooLarge(format!(
                    "module count exceeds the {} limit",
                    super::MAX_LIVE_MODULES
                )));
            }
            // SAFETY: same live out-parameter, still carrying its declared size.
            more = unsafe { Module32NextW(snapshot.0, &mut entry) }.is_ok();
        }
        modules.sort_by_key(|module| module.base);
        Ok(modules)
    }

    /// Reads the PE `TimeDateStamp` out of the mapped image header, matching the
    /// module identity a Windows minidump reports for the same binary.
    fn pe_timestamp(&self, base: u64) -> Option<u32> {
        let mut header = [0_u8; PE_HEADER_PROBE_BYTES];
        if self.read(base, &mut header) != header.len() {
            return None;
        }
        if header[0..2] != *b"MZ" {
            return None;
        }
        let lfanew = u32::from_le_bytes(header[0x3c..0x40].try_into().expect("4 bytes")) as usize;
        let stamp_at = lfanew.checked_add(8)?;
        if header[lfanew..].len() < 12 || header[lfanew..lfanew + 4] != *b"PE\0\0" {
            return None;
        }
        Some(u32::from_le_bytes(
            header[stamp_at..stamp_at + 4].try_into().expect("4 bytes"),
        ))
    }

    /// Reads up to `buffer.len()` bytes. A range crossing into unreadable memory fails
    /// with `ERROR_PARTIAL_COPY` while still reporting the bytes transferred, so a
    /// short return is a truthful prefix.
    pub(crate) fn read(&self, address: u64, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let mut read = 0_usize;
        // SAFETY: the kernel writes at most `buffer.len()` bytes into the live
        // exclusive borrow `buffer` and reports the count through `read`.
        let result = unsafe {
            ReadProcessMemory(
                self.process.0,
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&mut read),
            )
        };
        match result {
            Ok(()) => read.min(buffer.len()),
            Err(error) if error.code() == ERROR_PARTIAL_COPY.to_hresult() => read.min(buffer.len()),
            Err(_) => 0,
        }
    }
}

fn kind_name(kind: PAGE_TYPE) -> &'static str {
    if kind == MEM_PRIVATE {
        "private"
    } else if kind == MEM_MAPPED {
        "mapped"
    } else if kind == MEM_IMAGE {
        "image"
    } else {
        "unknown"
    }
}

fn filetime_to_unix_millis(time: FILETIME) -> Option<u64> {
    let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    ticks
        .checked_sub(FILETIME_TO_UNIX_EPOCH_100NS)
        .map(|unix_100ns| unix_100ns / 10_000)
}
