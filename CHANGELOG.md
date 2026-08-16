# Changelog

## [Unreleased]

## [0.1.0-alpha.3] - 2026-08-15

### Added

- Typed scan patterns. A scan specification is now `schema: 2` and each pattern carries one explicit `value` object: `bytes`, `int` (8/16/32/64-bit, signed or unsigned, little- or big-endian), `float` (exact `f32`/`f64` bit patterns), `utf8`, `utf16le`, or `masked` (byte- and nibble-granular masks). Numbers are strings, so 64-bit values never pass through lossy JSON floats; out-of-range values, `NaN`, malformed masks, and masks without a fully known byte are rejected explicitly. Mixed-kind batches still make one pass over each captured span.
- Bounded scan scopes. An optional `scope` object narrows a scan to explicit `modules`, `regions`, `ranges`, `protections`, and `types`. Selectors union inside a category and intersect across categories, at most 32 per category, and a match is reported only when every one of its bytes lies inside the selected captured readable scope. The scan report echoes `applied`, `interval_count`, `selected_bytes`, and `scanned_bytes`.
- New stable errors `UNRESOLVED_SCOPE` (a module selector matching no captured module or more than one, or an unknown region id) and `SCOPE_METADATA_UNAVAILABLE` (`protections` or `types` requested from a source without region metadata).
- A second shipped skill example, `examples/scoped-batch.json`, demonstrating typed integers and floats under a module-and-protection scope.

### Changed

- Region `protection` is now stable lowercase Windows flag names joined by `" | "` (for example `page_readwrite`) instead of a derived `Debug` rendering; undocumented bits are reported as hexadecimal. This is an incompatible response change: `protocol.SCHEMA_VERSION` is now `3`.
- Scan specifications with `schema: 1` are rejected with a migration message; the untyped `bytes_hex` pattern shape is gone.
- Every scan-specification failure, including malformed JSON and unknown pattern kinds or fields, now reports the single stable `INVALID_SCAN_SPEC` code.
- The synthetic fixture plants little- and big-endian integers, `f32`/`f64` values, and a UTF-16LE canary, and `./examples/demo.sh` exercises both shipped specifications.

### Alpha limitations

- Binaries are unsigned and not notarized.
- Live capture is Windows-only and requires same-user, unprotected-process access: no elevation, no `SeDebugPrivilege` use, and no cross-platform or protected-process capture.
- No stack unwinding, exception/register crash seed, symbols, disassembly, structure inference, or crash-cause inference.
- No pointer scans, YARA rules, or cross-capture refinement; masked patterns require at least one fully known byte.
- Scan scopes are explicit only; Membridge never selects a scope, and `protections`/`types` need region metadata.
- Installed skills do not update automatically; rerun `membridge skill install --force` after updating the binary.

Only inspect processes and dumps you are authorized to analyze. An incomplete capture cannot prove that a value was absent from process memory.

## [0.1.0-alpha.2] - 2026-08-14

### Added

- `membridge capture minidump --pid <pid> --output <path> [--force]`: a Windows-only, out-of-process `MiniDumpWriteDump` full-memory capture. It opens the target with read-only rights, publishes the dump atomically, refuses to overwrite an existing output without `--force`, and immediately imports the result to return process identity, capture interval, the exact capture flag profile, bounded capture-time warnings, source fingerprint, and coverage. Every other host returns the new `UNSUPPORTED_HOST` error.

### Changed

- `membridge skill install` now installs directly to the common cross-client `~/.agents/skills` location; the `--omp` and `--target` destination modes were removed.
- The embedded Agent Skill now emphasizes shipped capabilities, possible analyses, limits, and result semantics instead of prescribing a mandatory workflow or repeating release installation instructions.
- Added an optional Claude Code-compatible marketplace adapter that OMP also loads; it exposes the canonical skill without making the tool or skill client-specific.
- The canonical skill now packages opt-in, checksum-pinned shell and PowerShell binary bootstrap scripts. Marketplace installation never executes them; agents must obtain explicit approval before a bootstrap downloads executable code.
- Published the current skill-only marketplace revision as `0.1.0-alpha.1.skill.2`, explicitly compatible with the previously published `0.1.0-alpha.1` binary.
- `scan` region `offset` and module `rva` fields are now fixed-width hexadecimal `Address` strings instead of JSON numbers, matching every other address field. This is an incompatible response change: `protocol.SCHEMA_VERSION` is now `2`.
- The Windows-only synthetic capture-test helper process now lives in a separate, `dist`-excluded workspace package (`test-support/synthetic-capture-target`); release archives contain only the `membridge` binary.

### Security

- Minidump parsing now caps captured memory-range, region, and module counts at 32,768 each and fails closed with a new `SOURCE_TOO_LARGE` error instead of driving unbounded region-attribution work on a crafted dump.

### Alpha limitations

- Binaries are unsigned and not notarized.
- Live capture is Windows-only and requires same-user, unprotected-process access: no elevation, no `SeDebugPrivilege` use, and no cross-platform or protected-process capture.
- No stack unwinding, exception/register crash seed, symbols, disassembly, structure inference, or crash-cause inference.
- No typed, masked, pointer, or YARA scans.
- Installed skills do not update automatically; rerun `membridge skill install --force` after updating the binary.

Only inspect processes and dumps you are authorized to analyze. An incomplete capture cannot prove that a value was absent from process memory.

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
[0.1.0-alpha.2]: https://github.com/sharkone/membridge/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.3]: https://github.com/sharkone/membridge/releases/tag/v0.1.0-alpha.3
