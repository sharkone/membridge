# AGENTS.md

These instructions apply to the entire Membridge repository.

## Mission

Membridge is a deterministic, bounded, read-only bridge between authorized process-memory sources and human or AI workflows. Correctness and honest uncertainty are more important than feature breadth.

The engine provides mechanics. Callers and Agent Skills provide interpretation.

## Current scope

Shipped capabilities:

- read-only live process inspection on macOS, Linux, and Windows;
- Windows x64 user-mode minidump import;
- memory regions, modules, and explicit coverage;
- tagged batch scanning of typed, string, and masked representations;
- bounded module, region, range, access-right, and type scan scopes;
- deterministic match limits;
- bounded gap-aware reads;
- compact schema-v4 JSON;
- embedded Agent Skill installation.

Before changing behavior, read:

- `README.md` for the public contract;
- `PLAN.md` for active decisions and acceptance criteria;
- `ROADMAP.md` for sequencing;
- `.agents/skills/membridge/SKILL.md` for AI workflow semantics.

Do not implement roadmap capabilities incidentally.

## Non-negotiable invariants

### Read-only default

The default source boundary must not expose memory writes, allocation, protection changes, injection, process suspension, thread control, or execution.

Future mutation belongs in a separately launched and separately reviewed mode.

### Coverage is distinct from scan completion

- `scan_complete` means the scanner exhausted the selected scope it could read.
- `coverage_complete` means every expected readable byte was actually present and read.

Never infer absence from missing pages. Never collapse unavailable reads into non-matches. A live read refused by the kernel is unproven memory, not a non-match.

### Live sources are observations, not snapshots

A live source must report `immutable: false` and an observation interval, and must never
claim reproducibility. Membridge never freezes, suspends, or debugs a target, so memory
may change between enumeration and a read; that outcome is reported as
`READABLE_BYTES_UNREADABLE`, never silently skipped.

Live acquisition must request the least authority that can enumerate and read - a mach
read port, procfs plus `process_vm_readv`, a query-limited and VM-read handle - and must
never escalate privilege, install a driver, or work around a host access policy. An
access refusal is reported with the host's own remedy.

### Bounded output

Patterns, reads, matches, jobs, and future result sets require hard limits. Reaching a limit must produce explicit incomplete output and a continuation or narrowing strategy. Silent truncation is prohibited.

### Stable addresses

Serialize virtual addresses as fixed-width hexadecimal strings. JSON numbers cannot safely represent the full address space.

### Determinism

Identical source bytes and scan specifications must produce identical ordered matches regardless of worker count or host. Preserve overlapping, page-boundary, and chunk-boundary matches; a chunked source must repeat enough overlap that a straddling pattern is found exactly once, never zero or twice.

### Sensitive data

Do not log or persist literal search patterns, memory previews, or future live comparison baselines by default. Tests and examples must use synthetic values only.

### No network by default

Do not add telemetry, symbol downloads, update checks, remote listeners, or outbound requests to ordinary commands.

## Architecture

```text
src/error.rs             stable internal errors and protocol codes
src/protocol.rs          schema-v4 JSON envelopes
src/source/mod.rs        read-only acquisition-neutral traits and models
src/source/minidump.rs   Windows x64 minidump adapter
src/source/live/         read-only live process source: mach, procfs, and Win32 backends
src/capture.rs           Windows-only MiniDumpWriteDump live-process capture
src/scan.rs              deterministic typed, masked, and scoped scanner
src/skill.rs             embedded version-matched skill installer
src/main.rs              public CLI
.agents/skills/          canonical portable Agent Skill
.claude-plugin/          Claude Code-compatible marketplace catalog loaded by OMP
examples/                deterministic fixture and runnable workflows
tests/                   behavioral contracts
test-support/            Cargo workspace members excluded from dist (test-only helper processes)
```

Source adapters normalize into the existing `MemorySource` and `ProcessMemory` contracts. Do not create a second scanner for a new source.

The CLI is the public interface. A future daemon remains an implementation detail behind the same commands and JSON schema.

## Engineering style

- Prefer small concrete types and explicit state over generic frameworks.
- Avoid per-byte and per-match allocations in scan hot paths.
- Reuse caller-owned buffers and batch reads when possible.
- Use checked arithmetic for addresses, sizes, offsets, and file ranges.
- Treat malformed dumps as untrusted input.
- Keep `unsafe` blocks narrow and document their invariant.
- Reject ambiguous input rather than guessing.
- Remove obsolete code during cutovers; do not leave compatibility aliases unless required by a published contract.
- Do not add a general expression language, plugin ABI, or policy engine without an approved plan change.

## CLI and JSON changes

For any observable command change:

1. Keep stdout to one compact JSON object.
2. Keep diagnostics out of stdout.
3. Add or update a stable error code.
4. Add a behavioral integration test.
5. Update `README.md`.
6. Update `.agents/skills/membridge/SKILL.md` and embedded examples.
7. Update `PLAN.md` or `ROADMAP.md` when milestone scope changes.
8. Increment the protocol schema only for intentional incompatible changes.

Do not document commands before they exist.

## Agent Skill maintenance

`.agents/skills/membridge` is the canonical skill source and is embedded with `include_str!` in `src/skill.rs`.

Requirements:

- frontmatter name remains `membridge`;
- description names concrete triggers;
- guidance reflects only shipped behavior;
- examples contain no real secrets;
- installation tests must prove embedded files equal repository files;
- every binary version or observable CLI change must update the canonical skill in the same change;
- bootstrap scripts pin the latest *published* release version, checksum, and download URL, not necessarily `CARGO_PKG_VERSION`; a version bump may briefly precede the matching release, and bootstrap scripts must never reference a version with no published, checksummed archive; and they must authenticate every executable download before execution;
- OMP discovery must be verified when skill layout changes;
- the marketplace plugin source remains `./.agents`, never a copied skill tree;
- catalog and plugin versions must match each other and use `<binary-version>.skill.<revision>`;
- increment the skill revision for marketplace-visible skill changes without a binary version bump; reset it to `1` when the binary version changes;
- local OMP marketplace install, discovery, and upgrade must be exercised when marketplace metadata changes.

Never maintain a second hand-copied skill tree.

## Testing

Required before completion:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
./examples/demo.sh
```

`test-support/synthetic-target` is a separate workspace package holding the portable behavioral-test helper process; it opts itself out of `dist` via `[package.metadata.dist] dist = false` so release archives never contain it. It reserves one readable 64 KiB block with two canaries followed by an inaccessible block, opts into inspection with `PR_SET_PTRACER_ANY` on Linux, and is signed ad-hoc with `com.apple.security.get-task-allow` by the harness on macOS. Behavioral tests build it on demand, run a private copy so parallel tests never race on signing, and locate it next to `membridge`'s own build artifacts; it is never a public command.

Release changes additionally require:

```sh
dist generate --check
dist plan --tag <version-tag>
```

Before declaring a release complete, install a published target artifact, verify its checksum and version, install the embedded skill, and exercise inspect, scan, and read through that binary.

Behavioral tests should defend observable contracts:

- target platform rejection;
- region and module normalization;
- partial coverage;
- readable versus no-access memory;
- overlapping, page-boundary, and chunk-boundary matches;
- typed integer, float, string, and masked encoding, including rejected values;
- scope resolution, intersection, and unresolvable selectors;
- deterministic ordering;
- match-limit incompleteness;
- gap-aware reads;
- live region, module, and coverage reporting, including unproven live coverage and a read that stops at the first inaccessible page;
- source selection requiring exactly one of a dump path or `--pid`;
- JSON address encoding;
- Agent Skill installation and replacement.

Use `minidump-synth` fixtures for captured sources and `test-support/synthetic-target` for live ones. Do not commit real process dumps.

Live and capture behavior must be proven natively on each host it claims to support; cross-compilation alone is not proof. Cross-compiling the Linux and Windows backends catches type errors only, and every such check must be stated as exactly that.

## Documentation and tracking

- `README.md`: current user-facing behavior and examples.
- `CHANGELOG.md`: shipped release notes and explicit alpha limitations.
- `PLAN.md`: active engineering decisions and detailed next milestone.
- `ROADMAP.md`: milestone order and status.
- GitHub issues: executable units with acceptance criteria.

Update status immediately when work lands. Do not let README, skill, roadmap, and implementation disagree.

## Git and GitHub

The repository is public and dual-licensed under MIT OR Apache-2.0. Do not change visibility, transfer ownership, publish to package registries, or change licensing without explicit user approval.

Cutting a GitHub release of an already-versioned change is ordinary maintenance and needs no separate approval, but it must follow the full release procedure: finalize the `CHANGELOG.md` section for that version, tag `v<version>`, let the `dist` release workflow publish the checksummed archives and installers, verify a published artifact end to end, then re-pin the embedded bootstrap scripts and README installer URLs to that release in a follow-up commit.

Keep commits focused and buildable. Pull requests must state:

- observable change;
- coverage/partial-read implications;
- security implications;
- verification performed;
- documentation and skill impact.

Never commit dumps, captured secrets, credentials, local state, build output, or platform signing material.

## Completion standard

A feature is complete only when its end-to-end behavior works through the actual CLI, tests cover plausible regressions, partial outcomes remain explicit, documentation and skill content match, and all required validation commands pass.
