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
- compact schema-v1 JSON;
- synthetic behavioral fixture;
- stable source-derived coverage limitation codes;
- embedded portable Agent Skill;
- OMP-native and portable version-matched skill installation.

Current commands:

```text
membridge inspect
membridge scan
membridge read
membridge skill install
```

## Active milestone: Windows capture

The next product capability is an end-to-end Windows capture path.

### Required behavior

Add:

```text
membridge capture minidump --pid <pid> --output <path>
```

The implementation must:

1. Open only the requested process using documented user-mode rights.
2. Record PID, process creation time, image identity, capture start, and capture completion.
3. Call `MiniDumpWriteDump` from outside the target process.
4. Request full memory, memory information, thread information, process/thread data, and unloaded modules.
5. Continue past inaccessible regions while reporting that omission.
6. Write to a temporary path and atomically publish the completed dump.
7. Refuse to overwrite an existing output unless explicitly requested.
8. Import the result and return its BLAKE3 fingerprint and coverage summary.
9. Remain unavailable on non-Windows hosts with a stable `UNSUPPORTED_HOST` error.
10. Add Windows behavioral coverage and update the Agent Skill without inventing live-attach semantics.

### Capture flags

The initial capture profile should use:

- `MiniDumpWithFullMemory`;
- `MiniDumpWithFullMemoryInfo`;
- `MiniDumpWithThreadInfo`;
- `MiniDumpWithProcessThreadData`;
- `MiniDumpWithUnloadedModules`;
- `MiniDumpIgnoreInaccessibleMemory`.

Any change to this profile must update tests, README, skill guidance, and the capture response schema.

## Following milestones

### Typed deterministic patterns

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

### Sensitive persistence

Literal search patterns, byte previews, and live comparison baselines are not persisted by default. Source fingerprints, addresses, metadata, and non-sensitive indexes may persist.

### AI integration

The canonical Agent Skill is stored in `.agents/skills/membridge` and embedded into the binary. Skill text must describe only shipped commands and exact output semantics.

`membridge skill install --omp` delegates active user-profile discovery to `omp config path` and installs under its `skills` directory. This preserves OMP profile and agent-directory semantics without duplicating them. `--target` remains the explicit portable-client path. Exactly one destination mode is required.

Installation output reports matching binary and embedded-skill versions. Updates remain explicit: Membridge performs no background checks and replaces an installed skill only when the caller passes `--force`.

### Distribution

The source repository is public, but no redistribution license is granted. Public binary releases, package registries, signing, and installer channels require an explicit distribution decision; source visibility alone does not authorize them.

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

- Redistribution license and public release/package channels.
- Numeric resource defaults after representative large-dump benchmarks.
- At-rest encryption if sessions become a team feature.
- The exact VMM licensing and packaging model.
- Whether a future UI is justified after the CLI and skill workflows mature.
