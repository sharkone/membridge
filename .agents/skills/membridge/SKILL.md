---
name: membridge
description: Inspect and deterministically scan authorized Windows x64 process minidumps with bounded, coverage-aware output. Use for finding known byte representations, checking memory coverage, attributing addresses, or reading small windows around matches.
compatibility: Requires the version-matched membridge executable on PATH.
---

# Membridge

Membridge exposes deterministic mechanics for authorized process-memory captures. It returns compact JSON evidence; callers decide what the bytes mean.

## Binary availability

This skill requires the version-matched `membridge 0.1.0-alpha.1` executable on `PATH`. Check `membridge --version` before using it.

If the executable is missing or has another version, offer to run the bootstrap script for the host platform. Resolve `scripts/` relative to this `SKILL.md`, not the caller's project directory. Explain that it downloads and installs executable code, and run it only after explicit user approval:

```sh
sh scripts/install.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

The scripts pin the release and its SHA-256 digest, enforce download size limits, verify the installed version, and perform no background update checks. Do not replace them with an unverified download pipe. Skill activation itself must remain offline and side-effect free.

## Available operations

### Inspect a dump

```sh
membridge inspect <capture.dmp>
```

`inspect` reports:

- a BLAKE3 source fingerprint;
- target platform and architecture;
- captured processes;
- memory regions, state, protection, type, and capture status;
- modules with image base, size, timestamp, and path;
- expected, captured, and unavailable readable bytes;
- explicit coverage limitations.

### Scan exact byte representations

```sh
membridge scan <capture.dmp> --spec <scan.json|->
```

`scan` accepts a tagged batch of exact byte patterns and reports:

- deterministically ordered, overlapping matches;
- per-pattern alignment constraints;
- module and RVA attribution when a match falls inside a module;
- region attribution when metadata is available;
- a hard match quota and deterministic continuation address;
- scan completion and capture coverage as separate states.

Example specification:

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

Limits:

- 1 to 64 patterns;
- unique, non-empty tags;
- non-empty hexadecimal bytes;
- at most 4,096 bytes per pattern;
- positive alignment;
- 1 to 1,000,000 retained matches.

Use `examples/canary-batch.json` as a reusable starting point. For sensitive values, prefer a protected specification file or stdin rather than a command-line argument:

```sh
membridge scan <capture.dmp> --spec - < scan.json
```

### Read bounded memory

```sh
membridge read <capture.dmp> --address <virtual-address> --length <bytes>
```

`read` returns captured segments beginning at the requested address. The default length is 256 bytes and the hard limit is 65,536 bytes. Separate segments identify gaps; `complete: false` means the requested range was not fully captured.

## Analyses enabled by the current tool

Callers can form explicit bytes and use Membridge to locate:

- UTF-8, UTF-16LE, or other known string encodings;
- integer and floating-point bit representations with chosen width and endianness;
- canaries, sentinels, magic values, identifiers, and serialized headers;
- multiple alternative representations in one tagged scan;
- module-relative locations through returned RVAs;
- small byte windows around promising matches.

These transformations are caller-controlled. Membridge currently scans exact bytes; it does not implicitly encode values or infer types.

## Result semantics

`scan_complete` and `coverage_complete` answer different questions:

- `scan_complete`: the scanner exhausted the selected captured scope;
- `coverage_complete`: the dump contained every expected readable byte.

`terminal_reason: "match_limit"` means matches are a deterministic prefix and `next_address` identifies where omitted results begin.

Coverage limitations are:

- `MEMORY_METADATA_MISSING`;
- `MEMORY_METADATA_UNUSABLE`;
- `EXPECTED_READABLE_SCOPE_UNPROVEN`;
- `KNOWN_READABLE_BYTES_MISSING`.

Missing or unusable metadata is accompanied by `EXPECTED_READABLE_SCOPE_UNPROVEN`. Zero unavailable bytes does not prove complete coverage when expected readable scope is unproven.

Useful evidence language:

- **observed:** matched captured readable memory;
- **not observed in captured scope:** scanning finished, but coverage was incomplete;
- **not observed in complete scope:** scanning and coverage were both complete;
- **unknown:** scanning stopped, failed, or omitted relevant memory.

Addresses, region offsets, and module RVAs are all fixed-width hexadecimal strings such as `"0x0000000140000100"`. Do not coerce them through lossy floating-point JSON numbers. Do not concatenate read segments across a gap.

## Current boundary

Membridge currently supports Windows x64 user-mode minidumps containing `Memory64ListStream` or `MemoryListStream`.

It does not currently:

- capture or attach to processes;
- write, allocate, protect, suspend, or execute memory;
- decode typed values;
- resolve symbols or disassemble instructions;
- scan pointers, masked patterns, or YARA rules;
- infer structures or crash causes;
- contact network services.

Every command emits one compact schema-v2 JSON object. Failures contain a stable error code, message, and retryability flag. Do not suppress failures or treat partial output as complete.

Only inspect processes and dumps the user is authorized to analyze.
