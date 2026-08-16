use std::fs;
use std::path::Path;

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
