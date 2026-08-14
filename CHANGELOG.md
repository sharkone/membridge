# Changelog

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
