use std::fs;
use std::path::Path;

use minidump_synth::{DumpString, Memory, MemoryInfo, Module, SynthMinidump, SystemInfo};
use test_assembler::{Endian, Section};

pub const BASE: u64 = 0x0000_0001_4000_0000;
pub const CANARY: &[u8] = b"MBRIDGE!";
pub const FIRST_MATCH: u64 = BASE + 0x100;
pub const BOUNDARY_MATCH: u64 = BASE + 0x0ffc;
pub const NOACCESS_DECOY: u64 = BASE + 0x2100;

pub fn write_fixture(path: &Path) {
    let mut memory_bytes = vec![0_u8; 0x3000];
    memory_bytes[0x100..0x108].copy_from_slice(CANARY);
    memory_bytes[0x0ffc..0x1004].copy_from_slice(CANARY);
    memory_bytes[0x2100..0x2108].copy_from_slice(CANARY);

    let endian = Endian::Little;
    let module_name = DumpString::new(r"C:\dev\fixture.exe", endian);
    let module = Module::new(endian, BASE, 0x2000, &module_name, 0x65aa_5511, 0, None);
    let memory = Memory::with_section(
        Section::with_endian(endian).append_bytes(&memory_bytes),
        BASE,
    );
    let system = SystemInfo::new(endian)
        .set_processor_architecture(9) // PROCESSOR_ARCHITECTURE_AMD64
        .set_platform_id(2); // VER_PLATFORM_WIN32_NT

    let dump = SynthMinidump::new()
        .add(module_name)
        .add_system_info(system)
        .add_module(module)
        .add_memory64(memory)
        .add_memory_info(MemoryInfo::new(
            endian,
            BASE,
            BASE,
            0x04,
            0x2000,
            0x1000,
            0x04,
            0x0002_0000,
        ))
        .add_memory_info(MemoryInfo::new(
            endian,
            BASE + 0x2000,
            BASE + 0x2000,
            0x01,
            0x1000,
            0x1000,
            0x01,
            0x0002_0000,
        ))
        .add_memory_info(MemoryInfo::new(
            endian,
            BASE + 0x3000,
            BASE + 0x3000,
            0x04,
            0x1000,
            0x1000,
            0x04,
            0x0002_0000,
        ))
        .finish()
        .expect("synthetic minidump labels resolve");

    fs::write(path, dump).expect("write synthetic minidump");
}
