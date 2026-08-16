//! macOS live target backed by a read-only mach task port.
//!
//! Membridge asks the kernel for `TASK_FLAVOR_READ` (`task_read_for_pid`) and never
//! for a control port. The read port permits exactly the two operations this source
//! needs - `mach_vm_region_recurse` and `mach_vm_read_overwrite` - and the kernel
//! itself rejects writes, allocation, protection changes, and thread control on it, so
//! the read-only boundary is enforced by the port and not merely by convention.
//!
//! Access requires either that the target carries `com.apple.security.get-task-allow`
//! (the usual case for a locally built program under test, and the only way to attach
//! without privilege) or that membridge runs as root. System Integrity Protection
//! refuses Apple platform binaries and hardened-runtime applications regardless.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

use super::{RawRegion, TargetIdentity};
use crate::source::{Access, Address, ModuleInfo};
use crate::{Error, Result};

const KERN_SUCCESS: c_int = 0;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;
const SM_SHARED: u8 = 4;
const SM_TRUESHARED: u8 = 5;
const SM_SHARED_ALIASED: u8 = 7;
const TASK_DYLD_INFO: u32 = 17;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_BSDINFO_SIZE: c_int = 136;
const PROC_BSDINFO_START_TVSEC: usize = 120;
const PROC_BSDINFO_START_TVUSEC: usize = 128;
const SC_PAGESIZE: c_int = 29;
const MAXPATHLEN: usize = 1024;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
/// Guards a hostile or torn remote Mach-O header: a real image header is a few
/// kilobytes of load commands, never megabytes.
const MAX_LOAD_COMMAND_BYTES: usize = 64 * 1024;
const MAX_MODULE_COUNT: usize = super::MAX_LIVE_MODULES;
/// Address-space enumeration guard. Bounded so a pathological or racing target cannot
/// spin the enumerator; the caller-visible limit is `MAX_LIVE_REGIONS`.
const MAX_REGION_STEPS: usize = 4 * super::MAX_LIVE_REGIONS;

unsafe extern "C" {
    fn mach_task_self() -> u32;
    /// Read-only task port trap (macOS 11+). Exported by libSystem but deliberately
    /// absent from the public SDK headers, so it is declared here.
    fn task_read_for_pid(target: u32, pid: c_int, task: *mut u32) -> c_int;
    fn mach_port_deallocate(task: u32, name: u32) -> c_int;
    fn mach_vm_region_recurse(
        target: u32,
        address: *mut u64,
        size: *mut u64,
        depth: *mut u32,
        info: *mut c_void,
        info_count: *mut u32,
    ) -> c_int;
    fn mach_vm_read_overwrite(
        target: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> c_int;
    fn task_info(task: u32, flavor: u32, info: *mut c_void, count: *mut u32) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_char, size: u32) -> c_int;
    fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: *mut c_void, size: c_int)
    -> c_int;
    fn sysconf(name: c_int) -> i64;
}

/// `vm_region_submap_info_64` from `<mach/vm_region.h>`, which is declared under
/// `#pragma pack(4)`. Verified against the macOS SDK: 76 bytes, 19 `natural_t` units.
#[repr(C, packed(4))]
#[derive(Debug, Clone, Copy, Default)]
struct VmRegionSubmapInfo64 {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    offset: u64,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u16,
    external_pager: u8,
    share_mode: u8,
    is_submap: i32,
    behavior: i32,
    object_id: u32,
    user_wired_count: u16,
    pages_reusable: u32,
    object_id_full: u64,
}

const _: () = assert!(size_of::<VmRegionSubmapInfo64>() == 76);
const VM_REGION_SUBMAP_INFO_COUNT_64: u32 = (size_of::<VmRegionSubmapInfo64>() / 4) as u32;

/// `task_dyld_info_data_t` from `<mach/task_info.h>`: 20 bytes, 5 `natural_t` units.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: i32,
}

const TASK_DYLD_INFO_COUNT: u32 = 5;

/// Leading fields of `dyld_all_image_infos` (`<mach-o/dyld_images.h>`). Only the
/// prefix is read: everything after `infoArray` is version-dependent and unused.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct DyldAllImageInfosPrefix {
    version: u32,
    info_array_count: u32,
    info_array: u64,
}

/// `dyld_image_info` for a 64-bit target.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct DyldImageInfo {
    image_load_address: u64,
    image_file_path: u64,
    image_file_mod_date: u64,
}

#[derive(Debug)]
pub(crate) struct Target {
    /// A `TASK_FLAVOR_READ` port. Never a control port.
    task: u32,
    identity: TargetIdentity,
    page: usize,
    modules: Vec<ModuleInfo>,
}

impl Drop for Target {
    fn drop(&mut self) {
        // SAFETY: `task` is a port name this process owns, obtained from
        // `task_read_for_pid` and never handed out or deallocated elsewhere.
        unsafe {
            mach_port_deallocate(mach_task_self(), self.task);
        }
    }
}

impl Target {
    pub(crate) const PLATFORM: &'static str = "macos";

    pub(crate) fn open(pid: u32) -> Result<Self> {
        let image_path = image_path(pid)?;
        let start_time_unix_ms = start_time_unix_ms(pid)?;

        let mut task = 0_u32;
        // SAFETY: a valid port name receiver and PID; the trap only writes `task`.
        let kr = unsafe { task_read_for_pid(mach_task_self(), pid as c_int, &mut task) };
        if kr != KERN_SUCCESS {
            return Err(Error::ProcessAccessDenied(format!(
                "the kernel refused a read-only task port for process {pid} ({image_path}): \
                 mach error {kr}. Sign the target with com.apple.security.get-task-allow \
                 (codesign -f -s - --entitlements <plist> <binary>) or run membridge as root. \
                 System Integrity Protection refuses Apple platform binaries and \
                 hardened-runtime applications either way"
            )));
        }

        // SAFETY: `SC_PAGESIZE` is a valid sysconf name; the call has no side effects.
        let page = unsafe { sysconf(SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|page| page.is_power_of_two())
            .ok_or_else(|| Error::ProcessQueryFailed("host reported no usable page size".into()))?;

        let mut target = Self {
            task,
            identity: TargetIdentity {
                pid,
                image_path,
                start_time_unix_ms,
            },
            page,
            modules: Vec::new(),
        };
        target.modules = target.load_modules()?;
        Ok(target)
    }

    pub(crate) fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    pub(crate) fn page_size(&self) -> usize {
        self.page
    }

    pub(crate) fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(self.modules.clone())
    }

    pub(crate) fn regions(&self) -> Result<Vec<RawRegion>> {
        let mut regions = Vec::new();
        let mut address = 0_u64;
        let mut depth = 0_u32;

        for _ in 0..MAX_REGION_STEPS {
            let mut size = 0_u64;
            let mut info = VmRegionSubmapInfo64::default();
            let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;
            // SAFETY: all four out-parameters are live locals, and `info` is exactly
            // the 19-unit structure `count` declares.
            let kr = unsafe {
                mach_vm_region_recurse(
                    self.task,
                    &mut address,
                    &mut size,
                    &mut depth,
                    (&raw mut info).cast(),
                    &mut count,
                )
            };
            if kr != KERN_SUCCESS {
                // Enumeration ends by reporting no further region above `address`.
                break;
            }
            if info.is_submap != 0 {
                // Descend one level: the kernel re-reports this address as the submap's
                // contents. `depth` is never reset - the kernel lowers it again on its
                // own once the walk leaves the submap - and resetting it here would
                // re-enter the same submap forever.
                depth += 1;
                continue;
            }
            if size == 0 {
                break;
            }

            let protection = info.protection;
            let max_protection = info.max_protection;
            let share_mode = info.share_mode;
            let access = Access {
                read: protection & VM_PROT_READ != 0,
                write: protection & VM_PROT_WRITE != 0,
                execute: protection & VM_PROT_EXECUTE != 0,
            };
            regions.push(RawRegion {
                base: address,
                size,
                access,
                native: format!(
                    "{}/{}",
                    native_protection(protection),
                    native_protection(max_protection)
                ),
                kind: self.region_kind(address, share_mode),
                // Mach only reports mapped entries; an unmapped range is skipped
                // entirely rather than returned as reserved or free.
                state: "committed",
                committed: true,
            });
            if regions.len() > super::MAX_LIVE_REGIONS {
                return Err(Error::SourceTooLarge(format!(
                    "memory region count exceeds the {} limit",
                    super::MAX_LIVE_REGIONS
                )));
            }

            let Some(next) = address.checked_add(size) else {
                break;
            };
            address = next;
        }
        Ok(regions)
    }

    /// Reads up to `buffer.len()` bytes. `mach_vm_read_overwrite` is all-or-nothing
    /// across the requested range - a single unreadable page fails the whole call -
    /// so this returns either the full length or zero, and the caller retries at page
    /// granularity.
    pub(crate) fn read(&self, address: u64, buffer: &mut [u8]) -> usize {
        if buffer.is_empty() {
            return 0;
        }
        let mut out = 0_u64;
        // SAFETY: the kernel writes at most `buffer.len()` bytes into `buffer`, which
        // is a live exclusive borrow, and reports the count in `out`.
        let kr = unsafe {
            mach_vm_read_overwrite(
                self.task,
                address,
                buffer.len() as u64,
                buffer.as_mut_ptr() as u64,
                &mut out,
            )
        };
        if kr != KERN_SUCCESS {
            return 0;
        }
        (out as usize).min(buffer.len())
    }

    /// Classifies a region the way the Windows memory-type vocabulary does: memory
    /// inside a loaded Mach-O image is `image`, shared mappings are `mapped`, and
    /// everything else is `private`.
    fn region_kind(&self, address: u64, share_mode: u8) -> &'static str {
        if self.modules.iter().any(|module| module.contains(address)) {
            "image"
        } else if matches!(share_mode, SM_SHARED | SM_TRUESHARED | SM_SHARED_ALIASED) {
            "mapped"
        } else {
            "private"
        }
    }

    fn load_modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut info = TaskDyldInfo::default();
        let mut count = TASK_DYLD_INFO_COUNT;
        // SAFETY: `TASK_DYLD_INFO` writes exactly `TaskDyldInfo`, whose size matches
        // the five `natural_t` units declared by `count`.
        let kr = unsafe {
            task_info(
                self.task,
                TASK_DYLD_INFO,
                (&raw mut info).cast(),
                &mut count,
            )
        };
        if kr != KERN_SUCCESS || info.all_image_info_addr == 0 {
            // A target caught before dyld published its image list has no modules yet.
            // That is a fact about the target, not a failure of this source.
            return Ok(Vec::new());
        }

        let Some(all_images) =
            self.read_struct::<DyldAllImageInfosPrefix>(info.all_image_info_addr)
        else {
            return Ok(Vec::new());
        };
        let image_count = (all_images.info_array_count as usize).min(MAX_MODULE_COUNT);
        if image_count == 0 || all_images.info_array == 0 {
            return Ok(Vec::new());
        }

        let mut entries = vec![DyldImageInfo::default(); image_count];
        let byte_count = size_of::<DyldImageInfo>() * image_count;
        // SAFETY: `entries` owns `byte_count` initialized bytes of plain-old-data.
        let raw = unsafe {
            std::slice::from_raw_parts_mut(entries.as_mut_ptr().cast::<u8>(), byte_count)
        };
        if self.read(all_images.info_array, raw) != byte_count {
            return Err(Error::ProcessQueryFailed(
                "the target's dyld image list could not be read".into(),
            ));
        }

        let mut modules = Vec::with_capacity(image_count);
        for entry in entries {
            if entry.image_load_address == 0 {
                continue;
            }
            let Some(name) = self.read_c_string(entry.image_file_path) else {
                continue;
            };
            let (size, identity) = self.image_extent(entry.image_load_address);
            modules.push(ModuleInfo {
                name,
                base: Address(entry.image_load_address),
                size,
                identity,
            });
        }
        modules.sort_by_key(|module| module.base);
        Ok(modules)
    }

    /// Derives a loaded image's virtual span and `LC_UUID` from its remote Mach-O
    /// header. A header that cannot be read yields a zero span rather than a guess, so
    /// module attribution stays honest instead of inventing a range.
    fn image_extent(&self, base: u64) -> (u64, Option<String>) {
        let Some(header) = self.read_struct::<MachHeader64>(base) else {
            return (0, None);
        };
        if header.magic != MH_MAGIC_64 {
            return (0, None);
        }
        let commands_len = header.sizeofcmds as usize;
        if commands_len == 0 || commands_len > MAX_LOAD_COMMAND_BYTES {
            return (0, None);
        }
        let mut commands = vec![0_u8; commands_len];
        if self.read(base + size_of::<MachHeader64>() as u64, &mut commands) != commands_len {
            return (0, None);
        }

        let mut segments: Vec<(u64, u64)> = Vec::new();
        let mut text = None;
        let mut uuid = None;
        let mut offset = 0_usize;
        for _ in 0..header.ncmds {
            if offset + 8 > commands.len() {
                break;
            }
            let cmd = u32::from_le_bytes(commands[offset..offset + 4].try_into().expect("4 bytes"));
            let cmd_size = u32::from_le_bytes(
                commands[offset + 4..offset + 8]
                    .try_into()
                    .expect("4 bytes"),
            ) as usize;
            if cmd_size < 8 || offset + cmd_size > commands.len() {
                break;
            }
            match cmd {
                LC_SEGMENT_64 if cmd_size >= 72 => {
                    let name_end = commands[offset + 8..offset + 24]
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(16);
                    let name = &commands[offset + 8..offset + 8 + name_end];
                    let vmaddr = u64::from_le_bytes(
                        commands[offset + 24..offset + 32]
                            .try_into()
                            .expect("8 bytes"),
                    );
                    let vmsize = u64::from_le_bytes(
                        commands[offset + 32..offset + 40]
                            .try_into()
                            .expect("8 bytes"),
                    );
                    // __PAGEZERO is an address-space reservation below the image, not
                    // part of it.
                    if name == b"__PAGEZERO" {
                        offset += cmd_size;
                        continue;
                    }
                    if name == b"__TEXT" {
                        text = Some(vmaddr);
                    }
                    segments.push((vmaddr, vmsize));
                }
                LC_UUID if cmd_size >= 24 => {
                    uuid = Some(hex::encode(&commands[offset + 8..offset + 24]));
                }
                _ => {}
            }
            offset += cmd_size;
        }

        // Load commands carry unslid addresses, and the header sits at __TEXT, so the
        // extent is measured from there. Only segments that stay contiguous with
        // __TEXT are included: a dylib served from the dyld shared cache has its
        // __DATA and __LINKEDIT placed in entirely different cache areas, gigabytes
        // away, and spanning them would claim address space the module does not own
        // and would misattribute every match in between.
        let Some(text) = text else {
            return (0, uuid);
        };
        segments.sort_unstable();
        let mut end = text;
        for (vmaddr, vmsize) in segments {
            if vmaddr > end {
                break;
            }
            end = end.max(vmaddr.saturating_add(vmsize));
        }
        (end.saturating_sub(text), uuid)
    }

    fn read_struct<T: Copy + Default>(&self, address: u64) -> Option<T> {
        let mut value = T::default();
        // SAFETY: `value` owns `size_of::<T>()` initialized bytes of plain-old-data.
        let raw = unsafe {
            std::slice::from_raw_parts_mut((&raw mut value).cast::<u8>(), size_of::<T>())
        };
        (self.read(address, raw) == size_of::<T>()).then_some(value)
    }

    /// Reads a NUL-terminated remote path. Bounded by `MAXPATHLEN` and split at page
    /// boundaries so a string that ends next to an unreadable page still resolves.
    fn read_c_string(&self, address: u64) -> Option<String> {
        if address == 0 {
            return None;
        }
        let mut bytes = Vec::with_capacity(128);
        let mut cursor = address;
        while bytes.len() < MAXPATHLEN {
            let step = (self.page - (cursor as usize & (self.page - 1)))
                .min(MAXPATHLEN - bytes.len())
                .min(256);
            let mut window = [0_u8; 256];
            let window = &mut window[..step];
            if self.read(cursor, window) != step {
                break;
            }
            if let Some(end) = window.iter().position(|byte| *byte == 0) {
                bytes.extend_from_slice(&window[..end]);
                return String::from_utf8(bytes).ok();
            }
            bytes.extend_from_slice(window);
            cursor += step as u64;
        }
        None
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct MachHeader64 {
    magic: u32,
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

fn native_protection(protection: u32) -> String {
    let mut rendered = String::with_capacity(3);
    rendered.push(if protection & VM_PROT_READ != 0 {
        'r'
    } else {
        '-'
    });
    rendered.push(if protection & VM_PROT_WRITE != 0 {
        'w'
    } else {
        '-'
    });
    rendered.push(if protection & VM_PROT_EXECUTE != 0 {
        'x'
    } else {
        '-'
    });
    rendered
}

fn image_path(pid: u32) -> Result<String> {
    let mut buffer = [0_i8; MAXPATHLEN];
    // SAFETY: `buffer` is `MAXPATHLEN` bytes and the call writes at most that many.
    let written = unsafe { proc_pidpath(pid as c_int, buffer.as_mut_ptr(), MAXPATHLEN as u32) };
    if written <= 0 {
        return Err(Error::ProcessNotFound(pid));
    }
    let bytes: Vec<u8> = buffer[..written as usize]
        .iter()
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8(bytes)
        .map_err(|_| Error::ProcessQueryFailed(format!("process {pid} has a non-UTF-8 image path")))
}

/// Reads the target's start time, which turns a reusable PID into a stable identity.
fn start_time_unix_ms(pid: u32) -> Result<u64> {
    let mut buffer = [0_u8; PROC_BSDINFO_SIZE as usize];
    // SAFETY: `PROC_PIDTBSDINFO` writes exactly `PROC_BSDINFO_SIZE` bytes, which is
    // the length of `buffer`.
    let written = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDTBSDINFO,
            0,
            buffer.as_mut_ptr().cast(),
            PROC_BSDINFO_SIZE,
        )
    };
    if written != PROC_BSDINFO_SIZE {
        return Err(Error::ProcessNotFound(pid));
    }
    let seconds = u64::from_ne_bytes(
        buffer[PROC_BSDINFO_START_TVSEC..PROC_BSDINFO_START_TVSEC + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let microseconds = u64::from_ne_bytes(
        buffer[PROC_BSDINFO_START_TVUSEC..PROC_BSDINFO_START_TVUSEC + 8]
            .try_into()
            .expect("8 bytes"),
    );
    Ok(seconds
        .saturating_mul(1_000)
        .saturating_add(microseconds / 1_000))
}
