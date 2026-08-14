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
