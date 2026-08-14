---
name: membridge
description: Inspect and deterministically scan authorized Windows x64 process minidumps with bounded, coverage-aware output. Use for finding known byte representations, checking memory coverage, or reading small windows around matches.
---

# Membridge

Use Membridge as a bounded interface to authorized process-memory captures. The CLI performs deterministic mechanics; you decide what representations matter and how findings relate to source code.

## Current boundary

Membridge currently supports:

- Windows x64 user-mode minidumps containing `Memory64ListStream` or `MemoryListStream`;
- region, module, and capture-coverage inspection;
- tagged batches of exact byte patterns;
- alignment constraints;
- bounded reads of captured virtual memory;
- compact schema-v1 JSON output.

It does not currently capture processes, attach to live processes, decode typed values, resolve symbols, scan pointers, run YARA, or write memory. Do not invent commands for roadmap capabilities.

Only inspect processes and dumps the user is authorized to analyze.

## Installation

Install the `v0.1.0-alpha.1` binary on macOS or Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/sharkone/membridge/releases/download/v0.1.0-alpha.1/membridge-installer.sh |
  sh
```

On Windows PowerShell:

```powershell
irm https://github.com/sharkone/membridge/releases/download/v0.1.0-alpha.1/membridge-installer.ps1 | iex
```

Alpha binaries are checksummed but unsigned and not notarized.

The skill embedded in a Membridge binary is version-matched to that binary. Install it into the active OMP-native user profile with:

```sh
membridge skill install --omp
```

Membridge runs `omp config path` and installs under the reported agent directory's `skills` root. OMP must be on `PATH`. Use `--force` after updating the binary; installed copies do not update automatically. Start a new OMP session after installation.

For another Agent Skills-compatible client, pass its skills root explicitly:

```sh
membridge skill install --target <skills-root>
```

Exactly one of `--omp` or `--target` is required. Successful output reports matching `binary_version` and `skill_version` fields. `OMP_NOT_FOUND` means the OMP executable is unavailable; `OMP_DISCOVERY_FAILED` means its active agent directory could not be safely resolved.

## Required workflow

### 1. Inspect before searching

```sh
membridge inspect <capture.dmp>
```

Read these fields before making claims:

- `data.source.fingerprint`
- `data.coverage.metadata_complete`
- `data.coverage.coverage_complete`
- `data.coverage.unavailable_readable_bytes`
- `data.coverage.limitations`
- `data.regions`
- `data.modules`

A successful command does not imply complete capture coverage.

### 2. Generate deterministic representations

Convert each logical value into explicit bytes. Give every representation a stable descriptive tag. Batch related representations into one scan specification rather than rereading the dump once per pattern.

Use `skill://membridge/examples/canary-batch.json` as a starting point in OMP. In other Agent Skills clients, read `examples/canary-batch.json` relative to this skill.

Never pass a real secret as a command-line argument. Put the scan specification in a protected file or send it through stdin:

```sh
membridge scan <capture.dmp> --spec - < scan.json
```

### 3. Evaluate scan completeness

Inspect:

- `data.report.terminal_reason`
- `data.report.scan_complete`
- `data.report.next_address`
- `data.report.coverage`

`terminal_reason: "match_limit"` means the returned matches are a deterministic prefix, not the complete result. Narrow the pattern or scan scope when scope filters become available; do not report an exhaustive count.

`coverage_complete: false` means absence is unproven even when `scan_complete` is true.

`coverage.limitations` is a deterministically ordered list with at most four stable codes:

- `MEMORY_METADATA_MISSING`: no memory-information stream was captured;
- `MEMORY_METADATA_UNUSABLE`: the stream exists but cannot be parsed;
- `EXPECTED_READABLE_SCOPE_UNPROVEN`: the source cannot establish every expected readable byte;
- `KNOWN_READABLE_BYTES_MISSING`: known readable bytes are absent; use `unavailable_readable_bytes` for the exact known count.

Missing or unusable metadata is accompanied by `EXPECTED_READABLE_SCOPE_UNPROVEN`. Zero unavailable bytes does not prove complete coverage in that state.

### 4. Inspect only promising matches

```sh
membridge read <capture.dmp> --address <virtual-address> --length <bytes>
```

Start with the smallest useful window. The default is 256 bytes and the hard limit is 65,536 bytes. Treat `complete: false` and multiple returned segments as evidence of missing ranges. Never concatenate across a gap as though the bytes were contiguous.

### 5. Report evidence, not intuition

Include:

- source fingerprint;
- exact tagged pattern;
- virtual address;
- module and RVA when present;
- region kind and protection;
- scan terminal reason;
- coverage limitations;
- the smallest bounded byte window needed to support the conclusion.

Distinguish these conclusions:

- **observed:** a pattern matched captured readable memory;
- **not observed in captured scope:** scan exhausted available scope, but capture coverage is incomplete;
- **not observed in complete scope:** scan and coverage are both complete;
- **unknown:** the scan stopped, failed, or omitted relevant memory.

## Scan specification

```json
{
  "schema": 1,
  "patterns": [
    {
      "tag": "canary.utf8",
      "bytes_hex": "4d42524944474521",
      "alignment": 1
    }
  ],
  "max_matches": 10000
}
```

Constraints:

- 1 to 64 patterns;
- unique, non-empty tags;
- non-empty hexadecimal bytes;
- at most 4,096 bytes per pattern;
- positive alignment;
- 1 to 1,000,000 retained matches.

Addresses are JSON strings such as `"0x0000000140000100"`; never coerce them through a lossy floating-point JSON number.

## Failure handling

Every command emits one JSON object. On failure:

```json
{
  "schema": 1,
  "ok": false,
  "command": "scan",
  "error": {
    "code": "INVALID_SCAN_SPEC",
    "message": "...",
    "retryable": false
  }
}
```

Fix the named input or source error. Do not suppress errors, substitute another dump, silently reduce scope, or treat partial output as complete.
