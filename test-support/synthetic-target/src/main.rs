//! A tiny process with a known memory layout, used by membridge's behavioral tests on
//! every supported host.
//!
//! It reserves two adjacent 64 KiB blocks: the first is readable and holds two
//! canaries - one at the start and one ending exactly at the block boundary - and the
//! second is stripped of all access. Adjacency is guaranteed by allocating one range
//! and reprotecting its upper half, so a test can prove that a read stops precisely at
//! the boundary and that an inaccessible region is never treated as a non-match.
//!
//! It prints one `READY` line with its PID and both addresses, then blocks on stdin
//! until the harness lets it exit. It is never a public command.

use std::io::{self, BufRead, Write};

/// Multiple of every page size membridge runs on (4 KiB, 16 KiB) and of the Windows
/// 64 KiB allocation granularity, so one constant works on every host.
pub const BLOCK_BYTES: usize = 64 * 1024;

/// Planted at the start of the readable block.
pub const READABLE_CANARY: &[u8] = b"MBRIDGE-CAPTURE-READABLE!!";
/// Planted so that its last byte is the last readable byte before the inaccessible
/// block, which is what makes a boundary read observable.
pub const EDGE_CANARY: &[u8] = b"MBRIDGE-EDGE-CANARY!";

fn main() {
    allow_inspection();
    let (readable, noaccess) = reserve();
    println!(
        "READY pid={} readable=0x{readable:012x} noaccess=0x{noaccess:012x}",
        std::process::id()
    );
    io::stdout().flush().expect("flush stdout");

    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
}

/// Opts the target into read-only inspection by a non-ancestor process.
///
/// With Yama `ptrace_scope` set to 1 - the Ubuntu default - only an ancestor may read
/// this process, and membridge runs as a sibling. `PR_SET_PTRACER_ANY` is the
/// documented way for a target to consent, and it is the Linux counterpart of the
/// `com.apple.security.get-task-allow` signature the harness applies on macOS.
#[cfg(target_os = "linux")]
fn allow_inspection() {
    const PR_SET_PTRACER: i32 = 0x5961_6d61;
    const PR_SET_PTRACER_ANY: i64 = -1;

    unsafe extern "C" {
        fn prctl(option: i32, arg2: i64, arg3: i64, arg4: i64, arg5: i64) -> i32;
    }

    // SAFETY: `prctl` only reads the scalar arguments for this option.
    unsafe {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_inspection() {}

/// Returns the base address of the readable block and of the inaccessible block.
#[cfg(unix)]
fn reserve() -> (usize, usize) {
    use std::ffi::c_void;

    const PROT_NONE: i32 = 0;
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const MAP_PRIVATE: i32 = 0x0002;
    #[cfg(target_os = "macos")]
    const MAP_ANON: i32 = 0x1000;
    #[cfg(not(target_os = "macos"))]
    const MAP_ANON: i32 = 0x0020;

    unsafe extern "C" {
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    }

    // SAFETY: requests a fresh anonymous private mapping; the returned pointer is only
    // used within the `2 * BLOCK_BYTES` extent requested here.
    let base = unsafe {
        mmap(
            std::ptr::null_mut(),
            2 * BLOCK_BYTES,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };
    assert!(base as isize > 0, "mmap for the canary blocks failed");

    // SAFETY: `base` is an exclusively owned mapping of at least `2 * BLOCK_BYTES`
    // bytes, written once before anything else can observe it.
    unsafe {
        plant(base.cast::<u8>());
        assert_eq!(
            mprotect(base.byte_add(BLOCK_BYTES), BLOCK_BYTES, PROT_NONE),
            0,
            "mprotect for the inaccessible block failed"
        );
    }
    (base as usize, base as usize + BLOCK_BYTES)
}

#[cfg(windows)]
fn reserve() -> (usize, usize) {
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc, VirtualProtect,
    };

    // SAFETY: requests a fresh, process-private range with no existing mapping at the
    // chosen address; the pointer is used only within the requested extent.
    let base = unsafe {
        VirtualAlloc(
            None,
            2 * BLOCK_BYTES,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!base.is_null(), "VirtualAlloc for the canary blocks failed");

    let mut previous = Default::default();
    // SAFETY: `base` is an exclusively owned range of at least `2 * BLOCK_BYTES`
    // bytes; `previous` is a valid stack-local out-parameter.
    unsafe {
        plant(base.cast::<u8>());
        VirtualProtect(
            base.byte_add(BLOCK_BYTES),
            BLOCK_BYTES,
            PAGE_NOACCESS,
            &mut previous,
        )
        .expect("VirtualProtect for the inaccessible block failed");
    }
    (base as usize, base as usize + BLOCK_BYTES)
}

/// # Safety
///
/// `base` must point to at least `BLOCK_BYTES` writable, exclusively owned bytes.
unsafe fn plant(base: *mut u8) {
    unsafe {
        std::ptr::copy_nonoverlapping(READABLE_CANARY.as_ptr(), base, READABLE_CANARY.len());
        std::ptr::copy_nonoverlapping(
            EDGE_CANARY.as_ptr(),
            base.add(BLOCK_BYTES - EDGE_CANARY.len()),
            EDGE_CANARY.len(),
        );
    }
}
