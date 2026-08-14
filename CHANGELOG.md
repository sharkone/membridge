# Changelog

## [Unreleased]

### Added

- `membridge capture minidump --pid <pid> --output <path> [--force]`: a Windows-only, out-of-process `MiniDumpWriteDump` full-memory capture. It opens the target with read-only rights, publishes the dump atomically, refuses to overwrite an existing output without `--force`, and immediately imports the result to return process identity, capture interval, the exact capture flag profile, bounded capture-time warnings, source fingerprint, and coverage. Every other host returns the new `UNSUPPORTED_HOST` error.

### Changed

- `membridge skill install` now installs directly to the common cross-client `~/.agents/skills` location; the `--omp` and `--target` destination modes were removed.
- The embedded Agent Skill now emphasizes shipped capabilities, possible analyses, limits, and result semantics instead of prescribing a mandatory workflow or repeating release installation instructions.
- Added an optional Claude Code-compatible marketplace adapter that OMP also loads; it exposes the canonical skill without making the tool or skill client-specific.
- The canonical skill now packages opt-in, checksum-pinned shell and PowerShell binary bootstrap scripts. Marketplace installation never executes them; agents must obtain explicit approval before a bootstrap downloads executable code.
- Published the current skill-only marketplace revision as `0.1.0-alpha.1.skill.2`, explicitly compatible with the previously published `0.1.0-alpha.1` binary.
- `scan` region `offset` and module `rva` fields are now fixed-width hexadecimal `Address` strings instead of JSON numbers, matching every other address field. This is an incompatible response change: `protocol.SCHEMA_VERSION` is now `2`.

### Security

- Minidump parsing now caps captured memory-range, region, and module counts at 32,768 each and fails closed with a new `SOURCE_TOO_LARGE` error instead of driving unbounded region-attribution work on a crafted dump.

## [0.1.0-alpha.1] - 2026-08-14

First public testing release.

### Shipped

- Windows x64 user-mode minidump import from `Memory64ListStream` and `MemoryListStream` captures.
- Explicit metadata and readable-memory coverage limitations.
- Deterministic tagged exact-byte batch scans with alignment and hard match limits.
- Fixed-width virtual addresses, module/RVA attribution, and region metadata.
- Bounded gap-aware reads.
- Compact schema-v1 JSON command output.
- Version-matched OMP Agent Skill installation through `membridge skill install --omp`.
- Checksummed binaries and shell/PowerShell installers for Apple Silicon macOS, Intel macOS, x64 Linux, and x64 Windows.

### Alpha limitations

- Binaries are unsigned and not notarized.
- Membridge does not capture or attach to live processes.
- No stack unwinding, exception/register crash seed, symbols, disassembly, structure inference, or crash-cause inference.
- No typed, masked, pointer, or YARA scans.
- Installed skills do not update automatically; rerun `membridge skill install --omp --force` after updating the binary.

Only inspect processes and dumps you are authorized to analyze. An incomplete capture cannot prove that a value was absent from process memory.

[0.1.0-alpha.1]: https://github.com/sharkone/membridge/releases/tag/v0.1.0-alpha.1
