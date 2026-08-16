use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{ArgGroup, Args, Parser, Subcommand};
use membridge::capture;
use membridge::protocol::{Failure, Success};
use membridge::scan::{ScanReport, ScanSpec, scan};
use membridge::skill;
use membridge::source::{
    Address, Coverage, LiveSource, MemoryRegion, MemorySource, MinidumpSource, ModuleInfo,
    ProcessInfo, SourceInfo,
};
use membridge::{Error, Result};
use serde::Serialize;

const MAX_READ_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(name = "membridge", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The memory source a command operates on: either an immutable captured file or a
/// live process. Exactly one is required, so a command can never silently default to
/// the wrong kind of source.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["dump", "pid"])))]
struct TargetArgs {
    /// Windows x64 minidump to analyse.
    dump: Option<PathBuf>,
    /// Process id of a running process to inspect read-only.
    #[arg(long)]
    pid: Option<u32>,
}

impl TargetArgs {
    fn open(self) -> Result<Box<dyn MemorySource>> {
        match (self.dump, self.pid) {
            (Some(dump), None) => Ok(Box::new(MinidumpSource::open(dump)?)),
            (None, Some(pid)) => Ok(Box::new(LiveSource::open(pid)?)),
            _ => Err(Error::InvalidArgument(
                "exactly one of a minidump path or --pid is required".into(),
            )),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Describe a memory source and its scan coverage.
    Inspect {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Scan readable memory for a tagged batch of typed patterns.
    Scan {
        #[command(flatten)]
        target: TargetArgs,
        /// JSON scan specification path, or - for stdin.
        #[arg(long)]
        spec: String,
    },
    /// Return bounded readable bytes at one virtual address.
    Read {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, value_parser = parse_address)]
        address: u64,
        #[arg(long, default_value_t = 256)]
        length: usize,
    },
    /// Install the Agent Skill embedded in this binary.
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
    /// Capture a live process into a Windows x64 minidump.
    Capture {
        #[command(subcommand)]
        command: CaptureCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CaptureCommand {
    /// Capture a full-memory user-mode minidump of a running process. Windows only.
    Minidump {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SkillCommand {
    /// Install the version-matched skill under ~/.agents/skills.
    Install {
        #[arg(long)]
        force: bool,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Inspect { .. } => "inspect",
            Self::Scan { .. } => "scan",
            Self::Read { .. } => "read",
            Self::Skill { .. } => "skill.install",
            Self::Capture { .. } => "capture.minidump",
        }
    }
}

#[derive(Debug, Serialize)]
struct InspectData {
    source: SourceInfo,
    process: ProcessInfo,
    coverage: Coverage,
    regions: Vec<MemoryRegion>,
    modules: Vec<ModuleInfo>,
}

#[derive(Debug, Serialize)]
struct ScanData {
    source: SourceInfo,
    report: ScanReport,
}

#[derive(Debug, Serialize)]
struct ReadData {
    source_fingerprint: String,
    process_id: String,
    address: Address,
    requested_bytes: usize,
    returned_bytes: usize,
    complete: bool,
    segments: Vec<ReadSegmentView>,
}

#[derive(Debug, Serialize)]
struct ReadSegmentView {
    address: Address,
    bytes_hex: String,
    ascii: String,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.exit()
        }
        Err(error) => {
            let error = Error::InvalidArgument(error.to_string());
            print_json(&Failure::from_error("cli", &error));
            return ExitCode::from(2);
        }
    };
    let command = cli.command.name();
    match run(cli.command) {
        Ok(value) => {
            print_value(value);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_json(&Failure::from_error(command, &error));
            ExitCode::from(1)
        }
    }
}

fn run(command: Command) -> Result<serde_json::Value> {
    match command {
        Command::Inspect { target } => {
            let source = target.open()?;
            let process_info = source.processes()[0].clone();
            let process = source.open_process(&process_info.id)?;
            let data = InspectData {
                source: source.info().clone(),
                process: process.process().clone(),
                coverage: process.coverage(),
                regions: process.regions().to_vec(),
                modules: process.modules().to_vec(),
            };
            serde_json::to_value(Success::new("inspect", data)).map_err(Error::from)
        }
        Command::Scan { target, spec } => {
            // Every specification problem - malformed JSON, unknown pattern kind,
            // missing field - reports the same stable INVALID_SCAN_SPEC code.
            let spec: ScanSpec = serde_json::from_str(&read_spec(&spec)?)
                .map_err(|error| Error::InvalidSpec(error.to_string()))?;
            let source = target.open()?;
            let process = source.open_process(&source.processes()[0].id)?;
            let report = scan(process.as_ref(), &spec)?;
            let data = ScanData {
                source: source.info().clone(),
                report,
            };
            serde_json::to_value(Success::new("scan", data)).map_err(Error::from)
        }
        Command::Read {
            target,
            address,
            length,
        } => {
            if length == 0 || length > MAX_READ_BYTES {
                return Err(Error::InvalidArgument(format!(
                    "length must be between 1 and {MAX_READ_BYTES}"
                )));
            }
            let source = target.open()?;
            let process = source.open_process(&source.processes()[0].id)?;
            let segments = process.read(address, length)?;
            let returned_bytes = segments.iter().map(|segment| segment.bytes.len()).sum();
            let segments = segments
                .into_iter()
                .map(|segment| ReadSegmentView {
                    address: Address(segment.address),
                    bytes_hex: hex::encode(&segment.bytes),
                    ascii: ascii_view(&segment.bytes),
                })
                .collect();
            let data = ReadData {
                source_fingerprint: source.info().fingerprint.clone(),
                process_id: process.process().id.clone(),
                address: Address(address),
                requested_bytes: length,
                returned_bytes,
                complete: returned_bytes == length,
                segments,
            };
            serde_json::to_value(Success::new("read", data)).map_err(Error::from)
        }
        Command::Skill {
            command: SkillCommand::Install { force },
        } => {
            let report = skill::install(force)?;
            serde_json::to_value(Success::new("skill.install", report)).map_err(Error::from)
        }
        Command::Capture {
            command: CaptureCommand::Minidump { pid, output, force },
        } => {
            let report = capture::capture_minidump(pid, &output, force)?;
            serde_json::to_value(Success::new("capture.minidump", report)).map_err(Error::from)
        }
    }
}

fn read_spec(path: &str) -> Result<String> {
    if path == "-" {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|source| Error::Io {
                path: PathBuf::from("<stdin>"),
                source,
            })?;
        return Ok(input);
    }
    fs::read_to_string(path).map_err(|source| Error::Io {
        path: Path::new(path).to_path_buf(),
        source,
    })
}

fn parse_address(raw: &str) -> std::result::Result<u64, String> {
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        raw.parse()
    };
    parsed.map_err(|error| format!("invalid address {raw:?}: {error}"))
}

fn ascii_view(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

fn print_value(value: serde_json::Value) {
    print_json(&value);
}

fn print_json(value: &impl Serialize) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, value).expect("serializing protocol response cannot fail");
    use std::io::Write;
    writeln!(handle).expect("writing protocol response cannot fail");
}
