# Implementation Plan

## Purpose

This document records the active engineering plan for Membridge. It describes decisions and completion criteria; GitHub issues track executable work. Update this file when architecture, milestone order, or acceptance criteria change.

## Product contract

Membridge is a deterministic, read-only bridge between authorized process-memory sources and bounded human or AI workflows.

The engine owns:

- source and process identity;
- memory regions and modules;
- capture coverage;
- deterministic scanning;
- bounded reads;
- result completeness and provenance.

Skills and callers own:

- deciding what data matters;
- generating explicit representations;
- correlating addresses with code and runtime behavior;
- choosing follow-up experiments;
- explaining remediation.

The default engine must never acquire write, execution, injection, or process-control authority.

## Current implementation

The first vertical slice is complete:

- Rust single binary;
- internal read-only `MemorySource` and `ProcessMemory` interfaces;
- mmap-backed Windows x64 minidump parser;
- normalized regions, modules, and coverage;
- tagged exact-byte batch scanner;
- deterministic match quotas;
- bounded gap-aware reads;
- compact schema-v2 JSON;
- synthetic behavioral fixture;
- stable source-derived coverage limitation codes;
- embedded portable Agent Skill;
- version-matched skill installation through the OMP marketplace or common user-level `.agents/skills` location;
- Windows-only live-process capture producing an importable, atomically published minidump.

Current commands:

```text
membridge inspect
membridge scan
membridge read
membridge skill install
membridge capture minidump
```

## Active milestone: Typed deterministic patterns

Extend scan specifications without introducing a general expression language:

- signed and unsigned integers;
- explicit width and endianness;
- `f32` and `f64` bit patterns;
- UTF-8 and UTF-16LE strings;
- byte/nibble masks;
- tagged batching across all kinds.
- explicit module, region, address-range, and metadata-backed protection/type scan scopes.

No automatic secret classification or implicit transformations.
Scopes compose by deterministic intersection. A scope that depends on unavailable metadata fails explicitly rather than guessing; no general filter expression language is introduced.

## Following milestones

### Stateful daemon and result sets

Introduce the daemon only when persisted results or live targets need it:

- per-user auto-start;
- same-user local IPC;
- no TCP listener;
- asynchronous cancellable jobs;
- source/session/result IDs;
- server-side result set algebra;
- persistent non-sensitive metadata and indexes;
- no persisted literal patterns or memory previews.

The CLI remains the public contract. The daemon is an implementation detail.

### Direct Windows live source

Use documented user-mode APIs:

- `OpenProcess`;
- `VirtualQueryEx`;
- `ReadProcessMemory`.

Live scans are observation intervals, not coherent snapshots. Results must carry target creation time, image identity, start/completion timestamps, read failures, and revalidation state. Do not add a driver or enable `SeDebugPrivilege` automatically.

### Known-value refinement

Support exact initial values followed by:

- equal and unequal;
- changed and unchanged;
- increased and decreased;
- exact delta.

Live baselines remain memory-only and become non-resumable after daemon restart.

### Stable pointer chains

Build bounded reverse-pointer indexes with:

- x64 canonical-address validation;
- explicit alignment, maximum depth, offsets, and fan-out;
- module-relative roots;
- ASLR normalization;
- validation across captures or launches.

A one-snapshot path is intermediate evidence, not a stable chain.

### VMM-backed sources

After the source boundary survives direct Windows access:

1. full system and raw physical dumps;
2. WinPMEM;
3. virtual-machine introspection;
4. explicit remote LeechAgent profiles;
5. PCILeech FPGA/DMA.

Use VMM APIs rather than the mounted MemProcFS filesystem. Do not begin distribution until AGPL/commercial licensing has been resolved deliberately.

### Optional analysis metadata and engines

Add bounded, source-derived metadata that improves offline handoff without turning Membridge into a crash analyzer:

- optional minidump exception code, flags, address, parameters, crashing thread ID, and core x64 instruction/stack/frame pointers;
- module and RVA attribution for the captured fault address;
- module CodeView debug-file and debug-identifier metadata for caller-controlled symbol handoff;
- future optional YARA-X, heap/runtime enrichment, and snapshot modes only after the core acquisition and refinement workflows are stable.

Membridge does not unwind stacks, disassemble instructions, infer root causes, download symbols, or contact symbol servers. Crash metadata is useful for captured dumps but remains optional and lower priority than live reads, refinement, and pointer workflows.

## Engineering decisions

### Source boundary

The internal source API stays narrow and read-only. Minidump, Windows, and VMM adapters normalize into the same process, region, module, coverage, scatter-read, and scan-span semantics.

### Capture

`membridge capture minidump --pid <pid> --output <path> [--force]` is Windows-only and returns `Error::UnsupportedHost` (`UNSUPPORTED_HOST`) everywhere else. It opens only the requested process with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, records PID, image path, process creation time, and the capture interval, then calls `MiniDumpWriteDump` out of process with:

- `MiniDumpWithFullMemory`;
- `MiniDumpWithFullMemoryInfo`;
- `MiniDumpWithThreadInfo`;
- `MiniDumpWithProcessThreadData`;
- `MiniDumpWithUnloadedModules`;
- `MiniDumpIgnoreInaccessibleMemory`.

The dump is written to a same-directory staging path and published with `MoveFileExW`/`MOVEFILE_REPLACE_EXISTING`, so publication is atomic and an existing output is left untouched unless `--force` is passed. After publishing, capture immediately imports the result through the normal minidump source path and returns its `source` (including BLAKE3 fingerprint) and `coverage`, so a caller never has to trust the capture step's own claims about what was captured. Any change to the flag profile must update the behavioral tests, README, skill guidance, and this list together.

### Address representation

Virtual addresses are serialized as fixed-width hexadecimal strings. They must never pass through lossy JSON floating-point numbers.

### Coverage

Missing memory is distinct from a negative match. Every scan exposes both scan completion and source coverage completion. Coverage reports preserve exact known byte counts and a deterministic list of at most four stable limitation codes:

- `MEMORY_METADATA_MISSING`;
- `MEMORY_METADATA_UNUSABLE`;
- `EXPECTED_READABLE_SCOPE_UNPROVEN`;
- `KNOWN_READABLE_BYTES_MISSING`.

The parser emits these codes only from observed source conditions. Missing or unusable metadata means the expected readable scope is unproven; zero known unavailable bytes must not be presented as complete coverage.

### Resource limits

Reads, patterns, matches, jobs, and future result sets are bounded by construction. Reaching a limit produces explicit incomplete output, never silent truncation.

Minidump parsing additionally caps captured memory-range, region, and module counts at 32,768 each (`source::MAX_CAPTURED_SEGMENTS`, `MAX_MEMORY_REGIONS`, `MAX_MODULES`). A crafted dump can otherwise pack a captured-segment descriptor into 16 bytes, and the region-attribution and scan-extent algorithms are quadratic in these counts; exceeding a cap fails closed with `SOURCE_TOO_LARGE` before that work runs, rather than allowing an unbounded-time hang.

### Sensitive persistence

Literal search patterns, byte previews, and live comparison baselines are not persisted by default. Source fingerprints, addresses, metadata, and non-sensitive indexes may persist.

### AI integration

The canonical Agent Skill is stored in `.agents/skills/membridge` and embedded into the binary. Skill text describes shipped capabilities, limits, output semantics, and useful analyses without imposing one mandatory workflow.

The Agent Skills specification standardizes skill contents, not a universal marketplace catalog or user installation path. The canonical integration therefore remains `.agents/skills/membridge`, with `membridge skill install` writing the embedded version-matched copy to the common `~/.agents/skills` convention.

The repository additionally carries a Claude Code-compatible marketplace adapter that OMP loads through its compatibility fallback. Its `membridge` plugin source is the canonical `.agents` directory, which already has the standard plugin-relative `skills/membridge` layout. The adapter is optional and does not make the tool or skill client-specific.

Marketplace catalog and plugin versions use `<binary-version>.skill.<revision>`. The skill revision increments for marketplace-visible package changes that do not require a new native binary, while the binary prefix and skill runtime check preserve exact compatibility.

Marketplace adapters own skill discovery and updates only. The canonical skill package includes explicit checksum-pinned shell and PowerShell bootstrap scripts for first binary installation, but adapters never execute them. An agent may offer the host script only when the version-matched executable is absent, must explain the executable download, and must obtain user approval before running it.

### Distribution

Source and binary releases are licensed under `MIT OR Apache-2.0`. The first release channel is a GitHub prerelease with dist-generated archives, SHA-256 checksums, shell and PowerShell installers, and no package-registry publication. Alpha binaries are unsigned and not notarized.

Installers place the binary under Cargo's binary directory. Portable clients can use `membridge skill install`; OMP and Claude Code may instead use the optional shared marketplace adapter. Ordinary commands perform no background network access, plugin installation never invokes the bootstrap, and bootstrap network access occurs only through a separately approved command.

### Network behavior

No telemetry, symbol downloads, update checks, remote listeners, or outbound requests by default. Future remote acquisition requires an explicit source profile and security review.

## Definition of done for every capability

A capability is complete only when:

- public JSON behavior is versioned and bounded;
- plausible partial-read and malformed-input paths are represented honestly;
- behavioral tests fail on the likely regression;
- the actual CLI path has been exercised;
- README and skill instructions match shipped behavior;
- ROADMAP and linked issues reflect the new state;
- formatting, Clippy, and the complete test suite pass on supported hosts.

## Open decisions

- Signing, notarization, and public package registries after alpha validation.
- Numeric resource defaults after representative large-dump benchmarks.
- Rewriting `captured_overlap`, `build_scan_extents`, and `attributed_match` to use sorted-merge or binary-search lookups instead of nested linear scans, now that counts are capped; deferred because the caps already bound worst-case cost and a full rewrite is unwarranted algorithmic churn without a demonstrated need.
- The exact VMM licensing and packaging model.
- Whether a future UI is justified after the CLI and skill workflows mature.
