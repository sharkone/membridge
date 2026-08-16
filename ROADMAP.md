# Roadmap

Membridge grows by adding trustworthy acquisition and deterministic analysis—not by hiding uncertainty or giving the default process mutation authority.

This document describes milestone order. GitHub issues contain implementation tasks and acceptance criteria. Status changes must update both.

## Status

| Milestone | State | Outcome | Tracking |
|---|---|---|---|
| M0: Offline vertical slice | Complete | Windows x64 minidump inspection, exact scanning, bounded reads, JSON contract | — |
| M1: Project and Agent Skill | Complete | Maintained public repository, embedded skill, CI, examples, explicit coverage limitations, and alpha release packaging | [#10](https://github.com/sharkone/membridge/issues/10), [#15](https://github.com/sharkone/membridge/issues/15), [#18](https://github.com/sharkone/membridge/issues/18), [#22](https://github.com/sharkone/membridge/issues/22) |
| M2: Windows minidump capture | Complete | Authorized PID to full process minidump to cross-platform analysis | [#5](https://github.com/sharkone/membridge/issues/5) |
| M3: Typed deterministic patterns | Complete | Integers, floats, strings, masks, tagged batches, and explicit scan scopes | [#9](https://github.com/sharkone/membridge/issues/9), [#12](https://github.com/sharkone/membridge/issues/12) |
| M4: Stateful daemon and result sets | Active | Jobs, sessions, persistence, bounded set algebra | [#7](https://github.com/sharkone/membridge/issues/7) |
| M5: Direct Windows live source | Planned | Read-only external process scans with honest volatility semantics | [#4](https://github.com/sharkone/membridge/issues/4) |
| M6: Known-value refinement | Planned | Changed/unchanged/increased/decreased candidate narrowing | [#8](https://github.com/sharkone/membridge/issues/8) |
| M7: Stable pointer chains | Planned | Bounded module-rooted paths validated across snapshots | [#6](https://github.com/sharkone/membridge/issues/6) |
| M8: VMM-backed acquisition | Research gate | System dumps, WinPMEM, VM, remote, and DMA sources | [#3](https://github.com/sharkone/membridge/issues/3) |
| M9: Optional analysis metadata and engines | Future | Bounded crash/debug identity handoff, YARA, and runtime enrichment | [#11](https://github.com/sharkone/membridge/issues/11) |
| M10: Explicit mutation mode | Separate security track | Target-scoped process writes outside the default daemon | — |

## M0: Offline vertical slice

Delivered:

- internal read-only source boundary;
- mmap-backed Windows x64 minidumps;
- BLAKE3 identity;
- normalized regions, modules, and coverage;
- tagged exact-byte scans;
- deterministic quotas and continuation addresses;
- bounded gap-aware reads;
- compact schema-v1 JSON;
- deterministic synthetic fixture and behavioral tests.

Exit evidence:

- formatting and Clippy clean;
- behavioral tests pass on the supported development host;
- CLI finds both readable fixture canaries, excludes the no-access decoy, and reports the missing readable region.

## M1: Project and Agent Skill

Delivered:

- public GitHub repository;
- maintained README, plan, roadmap, and AGENTS guidance;
- Agent Skills-compatible capability reference stored in the repository;
- version-matched `membridge skill install` command;
- optional OMP and Claude Code marketplace installation and upgrades sourced directly from the canonical skill tree;
- user-level portable installation through the common cross-client `~/.agents/skills` convention;
- explicit checksum-pinned binary bootstrap resources inside the canonical skill, never run during discovery or activation;
- runnable fixture demo and reusable specifications;
- macOS, Linux, and Windows CI;
- issue and pull-request templates;
- milestone issues with acceptance criteria;
- stable source-derived limitation codes for incomplete metadata and coverage;
- MIT OR Apache-2.0 licensing and dist-generated alpha release artifacts.

Exit evidence:

- a fresh checkout can build, test, run the demo, and install the skill;
- Agent Skills clients discover the repository skill;
- the optional OMP/Claude Code marketplace installs and exposes the canonical skill without a second copy;
- marketplace upgrades preserve the declared plugin version and canonical source;
- portable user-level installation uses the common cross-client location and remains the primary contract;
- an approved host bootstrap installs the pinned release, rejects checksum mismatches, and verifies the resulting binary version;
- repository visibility is public;
- branch CI is running;
- incomplete coverage reports a deterministic reason rather than relying on booleans alone;
- the public alpha publishes checksummed archives and installers for macOS, Linux, and Windows.

## M2: Windows minidump capture

Delivered:

- Windows-only `membridge capture minidump --pid <pid> --output <path> [--force]`;
- read-only process handle (`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`) bound to PID, process creation time, and resolved image path;
- `MiniDumpWriteDump` with `MiniDumpWithFullMemory`, `MiniDumpWithFullMemoryInfo`, `MiniDumpWithThreadInfo`, `MiniDumpWithProcessThreadData`, `MiniDumpWithUnloadedModules`, and `MiniDumpIgnoreInaccessibleMemory`;
- same-directory staging plus `MoveFileExW`/`MOVEFILE_REPLACE_EXISTING` atomic publish, refusing an existing output unless `--force`;
- automatic re-import through the normal minidump source path, returning fingerprint and coverage instead of trusting the capture step's own claims;
- a synthetic Windows target executable with a readable canary page and a `PAGE_NOACCESS` page, exercised only on Windows CI;
- a stable `UNSUPPORTED_HOST` error on every non-Windows host.

Non-goals:

- live scanning;
- process suspension;
- kernel drivers;
- privilege bypass;
- memory writes.

Exit evidence:

- Windows CI spawns the synthetic target, captures it, verifies process identity/interval/flags/warnings/coverage in the response, rejects overwrite without `--force`, publishes with `--force`, then independently `inspect`s and `scan`s the resulting file and finds the readable canary at its reported address;
- macOS and Linux CI confirm the command returns `UNSUPPORTED_HOST` without touching the filesystem;
- formatting, Clippy, and the complete test suite pass on macOS, Linux, and Windows.

## M3: Typed deterministic patterns

Delivered:

- scan specification `schema: 2`, with `schema: 1` rejected in favour of one explicit typed shape;
- per-pattern `value` kinds `bytes`, `int`, `float`, `utf8`, `utf16le`, and `masked`;
- integers with explicit width, signedness, and endianness, validated against the declared range;
- exact `f32`/`f64` bit patterns from string numbers, with `NaN` rejected as unrepresentable;
- byte- and nibble-granular masks anchored on at least one fully known byte;
- one Aho-Corasick pass per captured span across every kind in a mixed batch;
- bounded `modules`, `regions`, `ranges`, `protections`, and `types` scope selectors composing by intersection;
- stable lowercase region protection names, replacing a derived `Debug` rendering (schema v3);
- `UNRESOLVED_SCOPE` and `SCOPE_METADATA_UNAVAILABLE` errors instead of guessed or silently empty scopes;
- a scope report carrying `applied`, `interval_count`, `selected_bytes`, and `scanned_bytes`;
- one stable `INVALID_SCAN_SPEC` code for every specification failure, including malformed JSON.

Non-goals:

- regular expressions, fuzzy module matching, or a Boolean filter language;
- implicit writable/executable policy or automatic scope selection;
- implicit value transformations (Base64, XOR, compression, project formats).

Exit evidence:

- behavioral tests cover typed width/signedness/endianness encoding, mixed-kind batching, masked byte and nibble matching, malformed masks, out-of-range and NaN values, every scope category, category intersection, overlapping ranges, boundary-spanning exclusion, scoped match-limit continuation, ambiguous and unknown module selectors, unknown region ids, and missing protection/type metadata;
- the CLI reports one stable code per specification failure and echoes the resolved scope;
- `./examples/demo.sh` runs both shipped specifications against the synthetic fixture, matching the UTF-8, UTF-16LE, and masked canaries unscoped and the planted typed values under a module-and-protection scope;
- formatting, Clippy, and the complete test suite pass on the supported development host.

## M4: Stateful daemon and result sets

Introduce state after the scan and live-source contracts are proven:

- per-user local daemon;
- auto-start and compatible-version negotiation;
- asynchronous cancellable jobs;
- opaque source, session, job, and result IDs;
- pagination and server-side filter/union/intersection/difference;
- strong source fingerprints and invalidation;
- persistent metadata and indexes without literal sensitive payloads.

No TCP listener and no network behavior by default.

## M5: Direct Windows live source

Add same-host user-mode acquisition using documented APIs. The source must:

- bind PID to process creation time and image identity;
- enumerate regions with `VirtualQueryEx`;
- read using `ReadProcessMemory`;
- partition around inaccessible regions;
- record every scan as an observation interval;
- revalidate matches before presenting current bytes;
- remain read-only.

PSS snapshots may become an optional reproducibility mode later; direct reads remain the external-tool default.

## M6: Known-value refinement

Build Cheat Engine-style deterministic narrowing from a known initial value:

- equal and unequal;
- changed and unchanged;
- increased and decreased;
- exact delta;
- explicit typed semantics;
- bounded candidate storage.

Unknown-initial scans remain deferred until storage and bandwidth behavior is measured.

## M7: Stable pointer chains

Build pointer analysis around evidence rather than path volume:

- reverse pointer indexes;
- module-relative roots;
- bounded depth, offsets, and fan-out;
- canonical x64 address checks;
- ASLR normalization;
- cross-capture and cross-launch validation.

The default report contains stable chains, not every path found in one snapshot.

## M8: VMM-backed acquisition

Integration order:

1. raw physical and supported full system dumps;
2. WinPMEM;
3. VM introspection;
4. authenticated remote LeechAgent profiles;
5. PCILeech FPGA/DMA.

Gates:

- explicit license approval;
- source-specific correctness fixtures;
- latency and partial-read semantics;
- native-library crash and isolation strategy;
- no dependency on the mounted MemProcFS filesystem.

## M9: Optional analysis metadata and engines

Candidates after core acquisition and refinement are stable:

- bounded minidump crash seed: exception metadata, crashing thread ID, core x64 instruction/stack/frame pointers, and module/RVA attribution;
- module CodeView debug identity for caller-controlled symbolizer handoff;
- YARA-X;
- Windows heap allocation attribution;
- language/runtime-specific object helpers;
- PSS stable snapshots;
- local session explorer consuming the same JSON contract.

Crash metadata remains an optional offline aid, not a prerequisite for live reads. Membridge does not unwind stacks, disassemble instructions, infer root causes, download symbols, or contact symbol servers.

These remain optional layers, not requirements for the core CLI.

## M10: Explicit mutation mode

Mutation is not an incremental method on the read-only source trait.

If justified, it requires a separate security design:

- separately launched mode;
- explicit target scope;
- distinct commands and audit records;
- no authority inherited by the default daemon;
- write validation and process-liveness checks;
- dedicated threat model and review.

## Maintenance rules

- Move a milestone to Complete only with executable evidence.
- Link roadmap work to GitHub issues; do not track active implementation only in prose.
- Keep issue acceptance criteria observable and source-specific.
- Update the Agent Skill in the same change as any CLI contract change.
- Do not add dates or delivery promises without an explicit planning decision.
- Record rejected scope in PLAN.md so it is not repeatedly rediscovered.
