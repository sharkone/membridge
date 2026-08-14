use std::path::Path;

use serde::Serialize;

#[cfg(not(windows))]
use crate::Error;
use crate::Result;
use crate::source::{Coverage, SourceInfo};

/// The `MiniDumpWriteDump` profile requested for every capture. Any change to this
/// list must update the behavioral tests, README, skill guidance, and this constant
/// together, since it is part of the observable `capture.minidump` response.
pub const CAPTURE_FLAG_NAMES: [&str; 6] = [
    "MiniDumpWithFullMemory",
    "MiniDumpWithFullMemoryInfo",
    "MiniDumpWithThreadInfo",
    "MiniDumpWithProcessThreadData",
    "MiniDumpWithUnloadedModules",
    "MiniDumpIgnoreInaccessibleMemory",
];

/// Stable, bounded capture-time conditions worth surfacing to the caller. This is
/// distinct from `Coverage::limitations`: `warnings` describes what was observed
/// about the *target process* while capturing it; `coverage` (computed by
/// re-importing the resulting file) describes what the *resulting dump* contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureWarning {
    /// The target process had already exited by the time its identity was queried,
    /// immediately before the dump was written.
    ProcessAlreadyExited,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedProcessIdentity {
    pub pid: u32,
    pub image_path: String,
    pub creation_time_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureInterval {
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureReport {
    pub process: CapturedProcessIdentity,
    pub interval: CaptureInterval,
    pub flags: Vec<&'static str>,
    pub warnings: Vec<CaptureWarning>,
    pub output: String,
    pub source: SourceInfo,
    pub coverage: Coverage,
}

/// Capture a full-memory user-mode minidump of `pid` and write it to `output`.
/// Windows only; every other host returns `Error::UnsupportedHost`.
#[cfg(windows)]
pub fn capture_minidump(pid: u32, output: &Path, force: bool) -> Result<CaptureReport> {
    windows_impl::capture_minidump(pid, output, force)
}

#[cfg(not(windows))]
pub fn capture_minidump(_pid: u32, _output: &Path, _force: bool) -> Result<CaptureReport> {
    Err(Error::UnsupportedHost(
        "minidump capture requires a Windows host".into(),
    ))
}

#[cfg(windows)]
mod windows_impl {
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};
    use windows::Win32::System::Diagnostics::Debug::{
        MiniDumpIgnoreInaccessibleMemory, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
        MiniDumpWithProcessThreadData, MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules,
        MiniDumpWriteDump,
    };
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_VM_READ, QueryFullProcessImageNameW,
    };
    use windows::core::{HSTRING, PWSTR};

    use crate::source::{MemorySource, MinidumpSource};
    use crate::{Error, Result};

    use super::{
        CAPTURE_FLAG_NAMES, CaptureInterval, CaptureReport, CaptureWarning, CapturedProcessIdentity,
    };

    /// 100ns ticks between the Windows FILETIME epoch (1601-01-01) and the Unix
    /// epoch (1970-01-01).
    const FILETIME_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    /// The Windows extended-length path limit, in UTF-16 code units including the
    /// terminator; `QueryFullProcessImageNameW` can never need more than this.
    const MAX_IMAGE_PATH_CHARS: usize = 32_768;

    /// Closes the wrapped process handle exactly once, when dropped.
    struct OwnedProcessHandle(HANDLE);

    impl Drop for OwnedProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was returned by a successful `OpenProcess` call
                // held by this guard alone, and is closed at most once, here.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn capture_error(action: &str, error: windows::core::Error) -> Error {
        Error::CaptureFailed(format!("{action}: {error}"))
    }

    fn filetime_to_unix_millis(filetime: FILETIME) -> Option<u64> {
        let ticks = ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64;
        ticks
            .checked_sub(FILETIME_TO_UNIX_EPOCH_100NS)
            .map(|unix_100ns| unix_100ns / 10_000)
    }

    fn now_unix_millis() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .map_err(|_| Error::CaptureFailed("system clock is before the Unix epoch".into()))
    }

    fn path_to_hstring(path: &Path) -> HSTRING {
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        HSTRING::from_wide(&wide)
    }

    pub fn capture_minidump(pid: u32, output: &Path, force: bool) -> Result<CaptureReport> {
        if output.exists() && !force {
            return Err(Error::InvalidArgument(format!(
                "capture output {} already exists; pass --force to replace it",
                output.display()
            )));
        }

        // SAFETY: requests only read-only inspection rights (query info, read
        // memory); no write, suspend, or termination authority is ever requested.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        }
        .map(OwnedProcessHandle)
        .map_err(|error| capture_error("could not open the target process", error))?;

        let mut creation_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();
        // SAFETY: all four out-parameters point at stack-local `FILETIME` values
        // that outlive this call.
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
            capture_error("could not query the target process creation time", error)
        })?;
        let creation_time_unix_ms = filetime_to_unix_millis(creation_time).ok_or_else(|| {
            Error::CaptureFailed("target process creation time predates the Unix epoch".into())
        })?;
        let already_exited = exit_time.dwLowDateTime != 0 || exit_time.dwHighDateTime != 0;

        let mut image_path_buffer = vec![0_u16; MAX_IMAGE_PATH_CHARS];
        let mut image_path_len = image_path_buffer.len() as u32;
        // SAFETY: `image_path_buffer` has `image_path_len` writable `u16` slots;
        // the call reports the number of characters actually written back through
        // `image_path_len`.
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_FORMAT(0),
                PWSTR(image_path_buffer.as_mut_ptr()),
                &mut image_path_len,
            )
        }
        .map_err(|error| capture_error("could not query the target process image path", error))?;
        let image_path = String::from_utf16_lossy(&image_path_buffer[..image_path_len as usize]);

        let started_at_unix_ms = now_unix_millis()?;

        let staging_name = format!(
            ".membridge-capture-{}-{}",
            std::process::id(),
            output
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "capture.dmp".into())
        );
        let staging = output.with_file_name(staging_name);
        let file = File::create(&staging).map_err(|source| Error::Io {
            path: staging.clone(),
            source,
        })?;
        // SAFETY: `file` owns a valid, open, writable file handle for the
        // lifetime of this raw-handle borrow; it is not closed until `file`
        // drops, after `MiniDumpWriteDump` returns.
        let file_handle = HANDLE(file.as_raw_handle());

        let dump_type = MiniDumpWithFullMemory
            | MiniDumpWithFullMemoryInfo
            | MiniDumpWithThreadInfo
            | MiniDumpWithProcessThreadData
            | MiniDumpWithUnloadedModules
            | MiniDumpIgnoreInaccessibleMemory;
        // SAFETY: `process.0` and `file_handle` are both valid, open handles for
        // the duration of this call; no exception, user-stream, or callback data
        // is supplied, so no additional pointer contracts apply.
        let write_result =
            unsafe { MiniDumpWriteDump(process.0, pid, file_handle, dump_type, None, None, None) };
        drop(file);
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&staging);
            return Err(capture_error("could not write the minidump", error));
        }

        let completed_at_unix_ms = now_unix_millis()?;

        let existing = path_to_hstring(&staging);
        let destination = path_to_hstring(output);
        // SAFETY: `existing` and `destination` are both live `HSTRING` values for
        // the duration of this call, which borrows their null-terminated UTF-16
        // buffers through the `Param<PCWSTR>` conversion.
        if let Err(error) =
            unsafe { MoveFileExW(&existing, &destination, MOVEFILE_REPLACE_EXISTING) }
        {
            let _ = std::fs::remove_file(&staging);
            return Err(capture_error(
                "could not publish the captured minidump",
                error,
            ));
        }
        drop(process);

        let source = MinidumpSource::open(output)?;
        let process_info = source.processes()[0].clone();
        let opened = source.open_process(&process_info.id)?;
        let coverage = opened.coverage().clone();

        let mut warnings = Vec::new();
        if already_exited {
            warnings.push(CaptureWarning::ProcessAlreadyExited);
        }

        Ok(CaptureReport {
            process: CapturedProcessIdentity {
                pid,
                image_path,
                creation_time_unix_ms,
            },
            interval: CaptureInterval {
                started_at_unix_ms,
                completed_at_unix_ms,
            },
            flags: CAPTURE_FLAG_NAMES.to_vec(),
            warnings,
            output: output.to_string_lossy().into_owned(),
            source: source.info().clone(),
            coverage,
        })
    }
}
