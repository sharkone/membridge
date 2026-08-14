//! A tiny Windows process with one readable canary page and one `PAGE_NOACCESS`
//! page, used only by the Windows-native `capture minidump` behavioral test. It
//! prints a `READY` line with its own PID once both pages are set up, then blocks
//! on stdin until the test harness lets it exit. A no-op everywhere else so the
//! workspace still builds one binary set per platform.

#[cfg(windows)]
fn main() {
    windows_impl::run();
}

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
mod windows_impl {
    use std::io::{self, BufRead, Write};

    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc, VirtualProtect,
    };

    /// Exercised by the Windows capture behavioral test to confirm a live capture
    /// finds this exact readable canary at the printed address.
    pub const READABLE_CANARY: &[u8] = b"MBRIDGE-CAPTURE-READABLE!!";
    const PAGE_SIZE: usize = 4096;

    pub fn run() {
        // SAFETY: requests a fresh, process-private page from the OS with no
        // existing mapping at the given address; the returned pointer is used
        // only within its documented `PAGE_SIZE` extent below.
        let readable =
            unsafe { VirtualAlloc(None, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(
            !readable.is_null(),
            "VirtualAlloc for the readable page failed"
        );
        // SAFETY: `readable` is a freshly allocated, exclusively owned page at
        // least `READABLE_CANARY.len()` bytes long, written once before any
        // other thread or reader can observe it.
        unsafe {
            std::ptr::copy_nonoverlapping(
                READABLE_CANARY.as_ptr(),
                readable.cast::<u8>(),
                READABLE_CANARY.len(),
            );
        }

        // SAFETY: same allocation contract as above; this second page is never
        // read or written again after protection is dropped below.
        let noaccess =
            unsafe { VirtualAlloc(None, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(
            !noaccess.is_null(),
            "VirtualAlloc for the no-access page failed"
        );
        let mut previous_protection = Default::default();
        // SAFETY: `noaccess` is a freshly allocated, exclusively owned page at
        // least `PAGE_SIZE` bytes long; `previous_protection` is a valid
        // stack-local out-parameter.
        unsafe { VirtualProtect(noaccess, PAGE_SIZE, PAGE_NOACCESS, &mut previous_protection) }
            .expect("VirtualProtect for the no-access page failed");

        println!(
            "READY pid={} readable=0x{:012x}",
            std::process::id(),
            readable as usize
        );
        io::stdout().flush().expect("flush stdout");

        let mut line = String::new();
        let _ = io::stdin().lock().read_line(&mut line);
    }
}
