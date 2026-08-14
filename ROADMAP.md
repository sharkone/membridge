# Roadmap

Membridge grows by adding trustworthy acquisition and deterministic analysis—not by hiding uncertainty or giving the default process mutation authority.

This document describes milestone order. GitHub issues contain implementation tasks and acceptance criteria. Status changes must update both.

## Status

| Milestone | State | Outcome | Tracking |
|---|---|---|---|
| M0: Offline vertical slice | Complete | Windows x64 minidump inspection, exact scanning, bounded reads, JSON contract | — |
| M1: Project and Agent Skill | Active | Maintained repository, embedded portable skill, CI, examples, issue tracking | — |
| M2: Windows minidump capture | Planned | Authorized PID to full process minidump to cross-platform analysis | [#5](https://github.com/sharkone/membridge/issues/5) |
| M3: Typed deterministic patterns | Planned | Integers, floats, strings, masks, tagged batches | [#9](https://github.com/sharkone/membridge/issues/9) |
| M4: Stateful daemon and result sets | Planned | Jobs, sessions, persistence, bounded set algebra | [#7](https://github.com/sharkone/membridge/issues/7) |
| M5: Direct Windows live source | Planned | Read-only external process scans with honest volatility semantics | [#4](https://github.com/sharkone/membridge/issues/4) |
| M6: Known-value refinement | Planned | Changed/unchanged/increased/decreased candidate narrowing | [#8](https://github.com/sharkone/membridge/issues/8) |
| M7: Stable pointer chains | Planned | Bounded module-rooted paths validated across snapshots | [#6](https://github.com/sharkone/membridge/issues/6) |
| M8: VMM-backed acquisition | Research gate | System dumps, WinPMEM, VM, remote, and DMA sources | [#3](https://github.com/sharkone/membridge/issues/3) |
| M9: Optional analysis engines | Future | YARA, heap/runtime enrichment, snapshot modes | — |
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

Deliverables:

- private GitHub repository;
- maintained README, plan, roadmap, and AGENTS guidance;
- Agent Skills-compatible workflow stored in the repository;
- version-matched `membridge skill install` command;
- runnable fixture demo and reusable specifications;
- macOS, Linux, and Windows CI;
- issue and pull-request templates;
- milestone issues with acceptance criteria.

Exit criteria:

- a fresh checkout can build, test, run the demo, and install the skill;
- OMP discovers the repository skill;
- the installed skill matches the version embedded in the binary;
- repository visibility is private;
- branch CI is running.

## M2: Windows minidump capture

Goal: make the dump-first workflow end to end without requiring an unrelated capture tool.

Deliverables:

- Windows-only `capture minidump` command;
- stable process identity and capture interval;
- documented full-memory capture profile;
- atomic output publication;
- inaccessible-page reporting;
- automatic import, fingerprint, and coverage response;
- synthetic target executable for Windows CI;
- cross-platform analysis of the resulting artifact.

Non-goals:

- live scanning;
- process suspension;
- kernel drivers;
- privilege bypass;
- memory writes.

## M3: Typed deterministic patterns

Add compact mechanisms needed by skills:

- integers with explicit signedness, width, and endianness;
- exact `f32` and `f64` representations;
- explicit UTF-8 and UTF-16LE strings;
- masked bytes;
- one-pass tagged batches across kinds.

Keep transformations caller-controlled. Base64, XOR, compression, and project formats are skill workflows, not implicit engine policy.

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

## M9: Optional analysis engines

Candidates after core acquisition and refinement are stable:

- YARA-X;
- Windows heap allocation attribution;
- language/runtime-specific object helpers;
- PSS stable snapshots;
- dedicated symbolizer handoff;
- local session explorer consuming the same JSON contract.

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
