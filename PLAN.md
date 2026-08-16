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

The offline vertical slice, project/skill packaging, Windows capture, typed
deterministic patterns, and portable live process sources are complete:

- Rust single binary;
- internal read-only `MemorySource` and `ProcessMemory` interfaces shared by every source;
- mmap-backed Windows x64 minidump parser;
- read-only live process sources on macOS (`task_read_for_pid` mach read port), Linux (`/proc/<pid>/maps` and `process_vm_readv`), and Windows (`OpenProcess` with query-limited and VM-read rights);
- normalized regions, modules, and coverage, with portable `read`/`write`/`execute` access names and the untranslated platform rendering kept alongside as `native_protection`;
- tagged batch scanner over exact bytes, integers, floats, UTF-8, UTF-16LE, and masks;
- bounded module, region, address-range, access-right, and type scan scopes, with the resolved scope handed to the source so a live scan reads only what it selects;
- chunked live scanning with a carried overlap, so a pattern straddling a chunk boundary is matched exactly once;
- deterministic match quotas and scope-ordered continuation;
- bounded gap-aware reads that stop at the first inaccessible page instead of padding;
- compact schema-v4 JSON;
- synthetic behavioral fixture with planted typed values, plus a portable synthetic live target;
- stable source-derived coverage limitation codes, including live `READS_NOT_ATTEMPTED` and `READABLE_BYTES_UNREADABLE`;
- embedded portable Agent Skill;
- version-matched skill installation through the OMP marketplace or common user-level `.agents/skills` location;
- Windows-only live-process capture producing an importable, atomically published minidump.

Current commands:

```text
membridge inspect <dump> | --pid <pid>
membridge scan <dump> | --pid <pid> --spec <path|->
membridge read <dump> | --pid <pid> --address <address> [--length]
membridge skill install
membridge capture minidump --pid <pid> --output <path>
```

### Live source decisions

- **Least authority, enforced by the kernel where possible.** macOS requests only a
  `TASK_FLAVOR_READ` port and never a control port, so writes, allocation, protection
  changes, and thread control are refused by the port itself rather than by our
  discipline. Linux never calls `ptrace`, so the target is never stopped or traced.
  Windows opens `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` only.
- **The target opts in; membridge does not escalate.** Access failures are reported with
  the host's remedy (`get-task-allow` signing or root on macOS, `ptrace_scope`/
  `PR_SET_PTRACER` on Linux, integrity level on Windows). Membridge never enables
  `SeDebugPrivilege`, never asks for a driver, and never disables SIP.
- **Volatility is stated, not hidden.** A live source reports `immutable: false`, an
  observation interval, and coverage computed from what the command actually read.
  Determinism remains "identical bytes produce identical ordered matches"; membridge
  does not claim a live target holds still.
- **Absence is never inferred from a refusal.** A read that fails on memory enumerated
  as readable records `READABLE_BYTES_UNREADABLE` and leaves the range unproven.
- **Bounded by construction.** Live reads are chunked through one reusable 4 MiB buffer,
  the resolved scope is pushed into the source so a narrow scan copies only its scope,
  and region and module counts fail closed at explicit limits.
- **One scanner.** Live sources deliver chunks through the same `ProcessMemory` contract
  the minidump source uses; there is no second scan engine.

## Active milestone: Stateful daemon and result sets

Introduce state only where persisted results or live targets require it:

- per-user local daemon with auto-start and compatible-version negotiation;
- same-user local IPC and no TCP listener;
- asynchronous cancellable jobs;
- opaque source, session, job, and result IDs;
- pagination and server-side filter/union/intersection/difference;
- strong source fingerprints and invalidation;
- persistent non-sensitive metadata and indexes.

The CLI remains the public contract; the daemon stays an implementation detail behind the same commands and JSON schema.

## Following milestones

### Match revalidation for live sources

Live acquisition is done; what remains is proving a match still holds. A live scan
reports where bytes matched during its observation interval, and nothing re-reads a
match afterwards. Add an explicit revalidation step that re-reads each retained match
and reports whether it still matches, was refused, or vanished, so a caller can tell a
stable value from one that only existed mid-sweep. Membridge still never freezes the
target.

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

### Typed patterns

Scan specifications are versioned separately from the response protocol and are now
`schema: 2`. A `schema: 1` specification is rejected with a message naming the
migration; no compatibility path accepts both shapes. Every pattern carries a `tag`,
an optional `alignment`, and exactly one `value` object whose `kind` is `bytes`,
`int`, `float`, `utf8`, `utf16le`, or `masked`. Unknown kinds and unknown fields are
rejected at deserialization, and every specification failure - malformed JSON
included - reports `INVALID_SCAN_SPEC`.

Numeric values are strings so 64-bit magnitudes never pass through JSON floats.
Integers accept decimal or `0x` hexadecimal with an optional sign and must fit the
declared width and signedness. Floats are encoded as the nearest representable
`f32`/`f64` bit pattern; `NaN` is rejected because it has no single representation.

A masked pattern compares `found & mask == value` per byte, so masks are nibble- and
bit-granular. Value bits outside the mask must be zero, and a mask must contain at
least one `0xff` byte: that byte run is the literal Aho-Corasick anchor, which keeps
one automaton pass over source bytes for every kind and avoids an unbounded per-byte
fallback scan. All kinds share the anchor mechanism - an exact pattern is its own
anchor - so mixed batches still scan each captured span once, and a match is retained
only when every one of its bytes lies inside the same captured readable slice.

### Scan scopes

An optional `scope` object narrows a scan to explicit `modules`, `regions`, `ranges`,
`protections`, and `types`. Selectors inside a category form a union, categories
intersect, and an omitted category adds no constraint. A present but empty category,
and an empty `scope` object, are rejected rather than silently interpreted. Each
category accepts at most 32 selectors (`scan::MAX_SCOPE_SELECTORS`).

Resolution never guesses. A module selector matches a full image path or a bare file
name case-insensitively and must resolve to exactly one known module; zero or
several matches, and unknown region ids, report `UNRESOLVED_SCOPE`. `protections` and
`types` require region metadata and report `SCOPE_METADATA_UNAVAILABLE` when the source
has none, instead of scanning an unproven scope. Protection selectors are validated
against `source::PROTECTION_NAMES` and type selectors against `source::TYPE_NAMES`, so
a typo fails instead of quietly matching nothing.

Region protection is therefore serialized twice, for two different readers.
`protection` carries the portable access rights `read`, `write`, and `execute` joined by
`" | "` (or `none`), which is what scope selectors accept, so one specification works
against a Windows dump, a mach task, and a procfs mapping. `native_protection` carries
the platform's own rendering verbatim - `page_readwrite`, `rw-/rwx`, `rw-p`, with
undocumented Windows bits as hexadecimal - so no platform detail is lost. A Windows
guard page is reported as unreadable while keeping its `page_guard` token, because the
first access to it raises an exception in the target instead of returning bytes.
Replacing the previous Windows-only vocabulary is an intentional incompatible change:
`protocol::SCHEMA_VERSION` is now `4`.

Scopes are resolved into a sorted, merged, non-overlapping interval list, so
overlapping selectors neither duplicate nor omit matches, `scanned_bytes` counts each
readable byte once, and match order and `next_address` stay ascending within
the scope regardless of how spans are visited. That same interval list is handed to the
source, so a live source reads only the selected bytes rather than the whole address
space. The report echoes `applied`, `interval_count`, `selected_bytes` (the intersection
size, `null` when unscoped), and `scanned_bytes` (readable bytes actually examined,
counting a chunk overlap once).

### Coverage

Missing memory is distinct from a negative match. Every scan exposes both scan completion and source coverage completion. Coverage reports preserve exact known byte counts and a deterministic list of at most six stable limitation codes:

- `MEMORY_METADATA_MISSING`;
- `MEMORY_METADATA_UNUSABLE`;
- `EXPECTED_READABLE_SCOPE_UNPROVEN`;
- `KNOWN_READABLE_BYTES_MISSING`;
- `READS_NOT_ATTEMPTED`;
- `READABLE_BYTES_UNREADABLE`.

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

## Rejected scope

Deliberately out of scope until an approved plan change says otherwise:

- masked patterns with no fully known byte (an all-nibble mask): rejected because every alternative needs an unbounded per-offset fallback scan; callers can widen one byte of the mask instead;
- regular expressions, fuzzy module matching, Boolean scope expressions, or any general filter language;
- implicit writable/executable scope policy and automatic scope selection;
- implicit value transformations such as Base64, XOR, compression, or project formats: those stay caller workflows;
- automatic type inference or decoding of matched memory.
