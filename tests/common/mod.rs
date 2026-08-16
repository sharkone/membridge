use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use minidump::format::MINIDUMP_STREAM_TYPE;
use minidump_synth::{
    DumpString, Memory, MemoryInfo, Module, SimpleStream, SynthMinidump, SystemInfo,
};
use test_assembler::{Endian, Section};

pub const BASE: u64 = 0x0000_0001_4000_0000;
pub const CANARY: &[u8] = b"MBRIDGE!";
pub const FIRST_MATCH: u64 = BASE + 0x100;
pub const BOUNDARY_MATCH: u64 = BASE + 0x0ffc;
pub const NOACCESS_DECOY: u64 = BASE + 0x2100;

/// Typed values planted in otherwise zeroed readable captured memory. Each one is
/// deliberately unique inside the fixture so a typed scan match proves the exact
/// width, signedness, and byte order the scanner encoded.
pub const TYPED_U32: u32 = 0xdead_beef;
pub const TYPED_U32_MATCH: u64 = BASE + 0x200;
pub const TYPED_I64: i64 = -2;
pub const TYPED_I64_MATCH: u64 = BASE + 0x208;
pub const TYPED_F32: f32 = 3.5;
pub const TYPED_F32_MATCH: u64 = BASE + 0x218;
pub const TYPED_F64: f64 = -0.5;
pub const TYPED_F64_MATCH: u64 = BASE + 0x220;
pub const TYPED_U16_BE: u16 = 0x1234;
pub const TYPED_U16_BE_MATCH: u64 = BASE + 0x228;
/// UTF-16LE encoding of `CANARY`, placed at a 2-byte-aligned address.
pub const UTF16_MATCH: u64 = BASE + 0x230;

/// A running `synthetic-target` helper process with a known memory layout: one
/// readable 64 KiB block holding two canaries, immediately followed by an
/// inaccessible block of the same size.
pub struct SyntheticTarget {
    pub child: Child,
    pub pid: u32,
    pub readable: u64,
    pub noaccess: u64,
    /// Owns the private copy of the helper binary this instance runs, so parallel
    /// tests never sign or replace one another's executable.
    _home: tempfile::TempDir,
}

impl SyntheticTarget {
    /// Builds the helper if needed, starts it, and waits for its `READY` line.
    ///
    /// On macOS the helper is signed ad-hoc with `com.apple.security.get-task-allow`
    /// first: without that entitlement the kernel refuses a task port to an
    /// unprivileged caller, so the test would otherwise only pass under `sudo`.
    pub fn start() -> Self {
        let built = build_helper();
        let home = tempfile::tempdir().expect("create helper directory");
        let exe = home
            .path()
            .join(built.file_name().expect("helper file name"));
        fs::copy(&built, &exe).expect("copy the helper binary");
        #[cfg(target_os = "macos")]
        sign_for_debugging(&exe);

        let mut child = spawn_helper(&exe);
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut ready = String::new();
        stdout.read_line(&mut ready).expect("read READY line");
        assert!(
            ready.starts_with("READY"),
            "unexpected target output: {ready}"
        );

        Self {
            pid: child.id(),
            readable: ready_address(&ready, "readable=0x"),
            noaccess: ready_address(&ready, "noaccess=0x"),
            child,
            _home: home,
        }
    }
}

impl Drop for SyntheticTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the private helper copy, retrying while Linux reports `ETXTBSY`.
///
/// `fs::copy` above holds a writable descriptor on this file for a moment. Any other
/// test thread that forks during that moment inherits the descriptor, and the fork
/// keeps it open until its own `execve` clears it, so Linux can briefly refuse to
/// execute this copy. The window is microseconds and cannot be closed from here: it
/// belongs to unrelated `Command::spawn` calls in sibling tests. Every other error is
/// a genuine failure and is raised immediately.
fn spawn_helper(exe: &Path) -> Child {
    for _ in 0..100 {
        match Command::new(exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(child) => return child,
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("start synthetic-target: {error}"),
        }
    }
    panic!(
        "synthetic-target stayed busy for a second: {}",
        exe.display()
    );
}

fn ready_address(line: &str, field: &str) -> u64 {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(field))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or_else(|| panic!("READY line carries a {field} address: {line}"))
}

/// `synthetic-target` is a separate workspace package (test-support/synthetic-target)
/// so `dist` never ships it as a release artifact; a plain `[[bin]]` in this package
/// would still be enumerated and required by dist's build step. It is built
/// explicitly here so the test is self-sufficient regardless of how `cargo test` was
/// invoked, then located next to this test binary's sibling artifacts.
pub fn build_helper() -> PathBuf {
    let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let build = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--manifest-path", manifest_path])
        .args(["--package", "synthetic-target"])
        .status()
        .expect("run cargo build");
    assert!(build.success(), "failed to build synthetic-target");

    // The test binary lives in `<target>/<profile>/deps`, so the helper it just built
    // sits two levels up. `CARGO_BIN_EXE_*` is unavailable here because this module is
    // also included by an example target.
    std::env::current_exe()
        .expect("current test executable path")
        .parent()
        .and_then(Path::parent)
        .expect("test binaries live under <target>/<profile>/deps")
        .join(format!("synthetic-target{}", std::env::consts::EXE_SUFFIX))
}

/// Ad-hoc signs the helper with `com.apple.security.get-task-allow`, the entitlement
/// that lets a same-user process obtain a read-only task port for it. This is the
/// documented way to make a program under test inspectable without root.
#[cfg(target_os = "macos")]
fn sign_for_debugging(exe: &Path) {
    let entitlements = exe.with_extension("entitlements.plist");
    fs::write(
        &entitlements,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
"#,
    )
    .expect("write entitlements");

    let signed = Command::new("codesign")
        .args(["-f", "-s", "-", "--entitlements"])
        .arg(&entitlements)
        .arg(exe)
        .output()
        .expect("run codesign");
    assert!(
        signed.status.success(),
        "codesign failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
}

#[derive(Clone, Copy)]
pub enum MemoryMetadataFixture {
    Complete,
    Missing,
    Partial,
    Unusable,
}

pub fn write_fixture(path: &Path) {
    write_coverage_fixture(path, MemoryMetadataFixture::Partial);
}

pub fn write_coverage_fixture(path: &Path, metadata: MemoryMetadataFixture) {
    write_dump(path, metadata, &[(r"C:\dev\fixture.exe", BASE, 0x2000)])
}

/// Writes a fixture whose two captured modules share one file name, so a
/// file-name module scope selector is genuinely ambiguous.
pub fn write_ambiguous_module_fixture(path: &Path) {
    write_dump(
        path,
        MemoryMetadataFixture::Partial,
        &[
            (r"C:\dev\fixture.exe", BASE, 0x2000),
            (r"C:\other\fixture.exe", BASE + 0x3000, 0x1000),
        ],
    )
}

fn write_dump(path: &Path, metadata: MemoryMetadataFixture, modules: &[(&str, u64, u64)]) {
    let mut memory_bytes = vec![0_u8; 0x3000];
    memory_bytes[0x100..0x108].copy_from_slice(CANARY);
    memory_bytes[0x0ffc..0x1004].copy_from_slice(CANARY);
    memory_bytes[0x2100..0x2108].copy_from_slice(CANARY);
    memory_bytes[0x200..0x204].copy_from_slice(&TYPED_U32.to_le_bytes());
    memory_bytes[0x208..0x210].copy_from_slice(&TYPED_I64.to_le_bytes());
    memory_bytes[0x218..0x21c].copy_from_slice(&TYPED_F32.to_le_bytes());
    memory_bytes[0x220..0x228].copy_from_slice(&TYPED_F64.to_le_bytes());
    memory_bytes[0x228..0x22a].copy_from_slice(&TYPED_U16_BE.to_be_bytes());
    for (index, byte) in CANARY.iter().enumerate() {
        memory_bytes[0x230 + index * 2] = *byte;
    }

    let endian = Endian::Little;
    let module_names = modules
        .iter()
        .map(|(name, _, _)| DumpString::new(name, endian))
        .collect::<Vec<_>>();
    let module_entries = modules
        .iter()
        .zip(&module_names)
        .map(|((_, base, size), name)| {
            Module::new(endian, *base, *size as u32, name, 0x65aa_5511, 0, None)
        })
        .collect::<Vec<_>>();
    let memory = Memory::with_section(
        Section::with_endian(endian).append_bytes(&memory_bytes),
        BASE,
    );
    let system = SystemInfo::new(endian)
        .set_processor_architecture(9) // PROCESSOR_ARCHITECTURE_AMD64
        .set_platform_id(2); // VER_PLATFORM_WIN32_NT

    let mut dump = SynthMinidump::new().add_system_info(system);
    for name in module_names {
        dump = dump.add(name);
    }
    for module in module_entries {
        dump = dump.add_module(module);
    }
    let dump = dump.add_memory64(memory);
    let dump = match metadata {
        MemoryMetadataFixture::Complete => dump
            .add_memory_info(memory_info(endian, BASE, 0x2000, 0x04))
            .add_memory_info(memory_info(endian, BASE + 0x2000, 0x1000, 0x01)),
        MemoryMetadataFixture::Missing => dump,
        MemoryMetadataFixture::Partial => dump
            .add_memory_info(memory_info(endian, BASE, 0x2000, 0x04))
            .add_memory_info(memory_info(endian, BASE + 0x2000, 0x1000, 0x01))
            .add_memory_info(memory_info(endian, BASE + 0x3000, 0x1000, 0x04)),
        MemoryMetadataFixture::Unusable => dump.add_stream(SimpleStream {
            stream_type: MINIDUMP_STREAM_TYPE::MemoryInfoListStream as u32,
            section: Section::with_endian(endian).D32(0),
        }),
    };
    let dump = dump.finish().expect("synthetic minidump labels resolve");

    fs::write(path, dump).expect("write synthetic minidump");
}

fn memory_info(endian: Endian, base: u64, size: u64, protection: u32) -> MemoryInfo {
    MemoryInfo::new(
        endian,
        base,
        base,
        protection,
        size,
        0x1000,
        protection,
        0x0002_0000,
    )
}

/// Writes a synthetic minidump with `segment_count` distinct, tiny, non-overlapping
/// Memory64List descriptors. Used to prove that opening a source with an
/// attacker-inflated captured-segment count fails closed instead of driving the
/// downstream region/scan-extent algorithms into unbounded work.
pub fn write_oversized_capture_fixture(path: &Path, segment_count: usize) {
    let endian = Endian::Little;
    let system = SystemInfo::new(endian)
        .set_processor_architecture(9) // PROCESSOR_ARCHITECTURE_AMD64
        .set_platform_id(2); // VER_PLATFORM_WIN32_NT

    let mut dump = SynthMinidump::new().add_system_info(system);
    for index in 0..segment_count {
        let address = BASE + (index as u64) * 0x10;
        let memory =
            Memory::with_section(Section::with_endian(endian).append_bytes(&[0_u8]), address);
        dump = dump.add_memory64(memory);
    }
    let dump = dump.finish().expect("synthetic minidump labels resolve");
    fs::write(path, dump).expect("write synthetic minidump");
}

/// A `ProcessMemory` that hands the scanner a buffer in fixed-size chunks the way a
/// live source must, so the chunk-overlap contract can be proven without depending on
/// a real process happening to map a multi-megabyte region.
pub struct ChunkedSource {
    base: u64,
    bytes: Vec<u8>,
    chunk: usize,
    process: membridge::source::ProcessInfo,
    regions: Vec<membridge::source::MemoryRegion>,
}

impl ChunkedSource {
    pub fn new(base: u64, bytes: Vec<u8>, chunk: usize) -> Self {
        let regions = vec![membridge::source::MemoryRegion {
            id: 0,
            base: membridge::source::Address(base),
            size: bytes.len() as u64,
            captured_bytes: None,
            state: "committed".into(),
            protection: "read | write".into(),
            native_protection: "rw-".into(),
            kind: "private".into(),
            committed: true,
            readable: true,
        }];
        Self {
            base,
            bytes,
            chunk,
            process: membridge::source::ProcessInfo {
                id: "pid:1".into(),
                display_name: "chunked".into(),
            },
            regions,
        }
    }
}

impl membridge::source::ProcessMemory for ChunkedSource {
    fn process(&self) -> &membridge::source::ProcessInfo {
        &self.process
    }

    fn regions(&self) -> &[membridge::source::MemoryRegion] {
        &self.regions
    }

    fn modules(&self) -> &[membridge::source::ModuleInfo] {
        &[]
    }

    fn coverage(&self) -> membridge::source::Coverage {
        membridge::source::Coverage {
            expected_readable_bytes: self.bytes.len() as u64,
            captured_readable_bytes: self.bytes.len() as u64,
            unavailable_readable_bytes: 0,
            metadata_complete: true,
            coverage_complete: true,
            observation: None,
            limitations: Vec::new(),
        }
    }

    fn for_each_scannable_span(
        &self,
        _selection: Option<&[membridge::source::AddressRange]>,
        overlap: usize,
        visitor: &mut dyn FnMut(membridge::source::ScanChunk<'_>) -> membridge::Result<()>,
    ) -> membridge::Result<()> {
        let mut cursor = 0_usize;
        while cursor < self.bytes.len() {
            let end = (cursor + self.chunk).min(self.bytes.len());
            let carry = cursor.min(overlap);
            visitor(membridge::source::ScanChunk {
                base: self.base + (cursor - carry) as u64,
                bytes: &self.bytes[cursor - carry..end],
                carry,
            })?;
            cursor = end;
        }
        Ok(())
    }

    fn read(
        &self,
        _address: u64,
        _length: usize,
    ) -> membridge::Result<Vec<membridge::source::ReadSegment>> {
        Ok(Vec::new())
    }
}
