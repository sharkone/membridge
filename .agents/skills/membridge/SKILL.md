---
name: membridge
description: Inspect and deterministically scan the memory of a running process on macOS, Linux, or Windows, or an authorized Windows x64 process minidump, with bounded, coverage-aware output. Use for finding typed integer, float, string, byte, or masked values in memory, scoping a scan to one module, region, address range, access right, or memory type, checking memory coverage, attributing addresses, reading small windows around matches, or capturing a live Windows process into an analyzable minidump.
compatibility: Requires the version-matched membridge executable on PATH.
---

# Membridge

Membridge exposes deterministic mechanics for authorized process memory, live or captured. It returns compact JSON evidence; callers decide what the bytes mean.

## Binary availability

This skill requires a version-matched `membridge` executable on `PATH`: the exact binary that was compiled alongside this skill copy, since `membridge skill install` always installs a skill from the same build as the binary it ships in. Run `membridge --version` first.

If the executable is missing, or a documented command such as `capture` is absent from `membridge --help`, offer to run the bootstrap script for the host platform. Resolve `scripts/` relative to this `SKILL.md`, not the caller's project directory. Explain that it downloads and installs executable code, and run it only after explicit user approval. The bootstrap installs the latest published release, which can briefly lag behind this skill between a version bump and that release actually shipping; if a gap remains after bootstrapping, say so plainly instead of retrying the bootstrap.

```sh
sh scripts/install.sh
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

The scripts pin the release and its SHA-256 digest, enforce download size limits, verify the installed version, and perform no background update checks. Do not replace them with an unverified download pipe. Skill activation itself must remain offline and side-effect free.

## Available operations

### Choose a source

`inspect`, `scan`, and `read` each take exactly one source:

- a minidump path, for an immutable capture;
- `--pid <pid>`, for a process running on this host.

Passing both or neither fails with `INVALID_ARGUMENT`.

A live source is not reproducible: the target keeps running between enumeration and
every read. `source.immutable` states this, `coverage.observation` gives the wall-clock
window the answer covers, and two commands against the same PID may legitimately
disagree. Prefer a capture when a stable artifact matters; prefer live when the
question is about the process as it runs now.

### Inspect a source

```sh
membridge inspect <capture.dmp>
membridge inspect --pid <pid>
```

`inspect` reports:

- a BLAKE3 fingerprint: of the file's bytes for a dump, of process identity for a live source;
- target platform and architecture;
- the process;
- memory regions with state, portable access rights, native protection, type, and capture status;
- modules with image base, size, identity, and path;
- expected, captured, and unavailable readable bytes;
- explicit coverage limitations.

A live `inspect` never reads target memory, so it always reports
`READS_NOT_ATTEMPTED` and `captured_readable_bytes: 0`. That is enumeration, not proof
of content.

### Scan typed representations

```sh
membridge scan <capture.dmp> --spec <scan.json|->
membridge scan --pid <pid> --spec <scan.json|->
```

`scan` accepts one tagged batch of typed patterns, scans the selected readable
bytes once, and reports:

- deterministically ordered, overlapping matches;
- per-pattern alignment constraints;
- module and RVA attribution when a match falls inside a module;
- region attribution when metadata is available;
- the resolved scan scope;
- a hard match quota and deterministic continuation address;
- scan completion and capture coverage as separate states.

Every pattern carries a `tag`, an optional `alignment` (default 1), and one
`value` object naming its kind:

| kind | fields | bytes searched |
|---|---|---|
| `bytes` | `bytes_hex` | those exact bytes |
| `int` | `number`, `width` (8/16/32/64), `signed`, `endian` (`little`/`big`) | two's-complement encoding |
| `float` | `number`, `width` (32/64), `endian` | IEEE-754 bit pattern |
| `utf8` | `text` | UTF-8 encoding |
| `utf16le` | `text` | UTF-16LE encoding |
| `masked` | `bytes_hex`, `mask_hex` | bytes compared under the mask |

`number` is a string, so 64-bit values never pass through lossy JSON floats:
integers accept decimal or `0x` hexadecimal with an optional leading `-`, and
floats accept forms such as `"3.5"`, `"-0.5"`, `"1e-3"`, `"inf"`, and `"-inf"`.
A float value is encoded as the nearest representable `f32`/`f64` and then
matched exactly. `NaN` is rejected because it has no single representation; use
a `bytes` or `masked` pattern for a specific NaN encoding.

A `masked` pattern compares `found & mask_hex == bytes_hex` byte by byte, so
masks work at nibble or bit granularity. Value bits outside the mask must be
zero, and the mask needs at least one fully known (`ff`) byte to anchor the
search.

```json
{
  "schema": 2,
  "patterns": [
    {
      "tag": "canary.utf8",
      "value": { "kind": "utf8", "text": "MBRIDGE!" },
      "alignment": 1
    },
    {
      "tag": "handle.u32",
      "value": {
        "kind": "int",
        "number": "0xdeadbeef",
        "width": 32,
        "signed": false,
        "endian": "little"
      },
      "alignment": 4
    }
  ],
  "max_matches": 10000
}
```

### Narrow a scan to an explicit scope

An optional `scope` object restricts the scan to captured readable bytes inside
the selected address space. Categories intersect; selectors inside one category
form a union. An omitted category adds no constraint.

```json
{
  "schema": 2,
  "patterns": [{ "tag": "canary.utf8", "value": { "kind": "utf8", "text": "MBRIDGE!" } }],
  "scope": {
    "modules": ["fixture.exe"],
    "regions": [0],
    "ranges": [{ "start": "0x140000000", "length": "0x2000" }],
    "protections": ["read", "write"],
    "types": ["private"]
  },
  "max_matches": 10000
}
```

- `modules`: a full image path or a bare file name, compared case-insensitively.
  A selector that matches no known module, or more than one, fails.
- `regions`: region `id` values exactly as `inspect` reports them.
- `ranges`: `start` and `length` as decimal or `0x` strings; length must be
  positive.
- `protections`: portable access rights — `read`, `write`, `execute` — selecting every
  region that carries at least one of them. Each region also reports a
  `native_protection` string (`page_readwrite`, `rw-/rwx`, `rw-p`); that is evidence
  for the caller, not a selector.
- `types`: `private`, `mapped`, or `image`.

A match is reported only when every one of its bytes lies inside the scope, so a
value straddling a scope edge is omitted rather than partially matched. The
report echoes the resolved scope:

```json
{
  "applied": ["modules", "protections"],
  "interval_count": 1,
  "selected_bytes": 8192,
  "scanned_bytes": 8192
}
```

`selected_bytes` is the size of the scope intersection and is `null` when no
scope was requested; `scanned_bytes` counts the readable bytes actually examined.
A large `selected_bytes` with a small `scanned_bytes` means most of the selected
scope was never captured or could not be read.

Scoping a live scan is also how it stays cheap: a live source only reads what the
scope selects. An unscoped live scan copies every readable byte the process maps,
which for an ordinary desktop process includes gigabytes of shared system libraries.
Prefer `protections: ["write"]` with `types: ["private"]`, a module, or an address
range when hunting runtime values.

Limits:

- 1 to 64 patterns;
- unique, non-empty tags;
- at most 4,096 bytes per pattern;
- positive alignment;
- at most 32 selectors per scope category;
- 1 to 1,000,000 retained matches.

Use `examples/canary-batch.json`, `examples/scoped-batch.json`, and
`examples/live-batch.json` as reusable starting points. For sensitive values, prefer a
protected specification file or stdin rather than a command-line argument:

```sh
membridge scan <capture.dmp> --spec - < scan.json
```

### Read bounded memory

```sh
membridge read <capture.dmp> --address <virtual-address> --length <bytes>
membridge read --pid <pid> --address <virtual-address> --length <bytes>
```

`read` returns segments beginning at the requested address. The default length is 256 bytes and the hard limit is 65,536 bytes. Separate segments identify gaps; `complete: false` means the requested range was not fully captured, or that a live target refused part of it. A read that stops at an inaccessible page returns the bytes it proved, never padding.

### Live process access

`--pid` uses the least authority each kernel offers: a `TASK_FLAVOR_READ` mach port on
macOS, `/proc/<pid>/maps` plus `process_vm_readv` on Linux, and
`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` on Windows. Membridge never
attaches a debugger, stops, or modifies the target.

When the kernel refuses, report the refusal; do not retry blindly or present it as an
empty result:

- `PROCESS_NOT_FOUND`: no such process.
- `PROCESS_ACCESS_DENIED`: inspection was refused. On macOS the target must carry
  `com.apple.security.get-task-allow` (`codesign -f -s - --entitlements <plist> <binary>`)
  or membridge must run as root, and SIP refuses Apple platform binaries and
  hardened-runtime applications regardless. On Linux the caller must satisfy
  `ptrace_may_access`: with `ptrace_scope` at 1 the target must be a descendant or must
  have called `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`. On Windows the caller needs a
  matching integrity level; protected processes cannot be read.
- `PROCESS_QUERY_FAILED`: the process is readable but required metadata is missing.
- `UNSUPPORTED_HOST`: this build has no live acquisition path.

### Capture a live process (Windows only)

```sh
membridge capture minidump --pid <pid> --output <capture.dmp> [--force]
```

`capture` opens only the requested process with read-only rights, calls `MiniDumpWriteDump` with a full-memory profile, publishes the result atomically, and immediately imports it. Every host other than Windows returns `UNSUPPORTED_HOST`. An existing `--output` path is refused unless `--force` is passed.

The response includes captured process identity (PID, image path, creation time), the capture interval, the exact `MiniDumpWriteDump` flag profile used, bounded capture-time `warnings` such as `PROCESS_ALREADY_EXITED`, and the same `source`/`coverage` shape `inspect` reports, computed by re-opening the published file. Feed the resulting path straight into `inspect`, `scan`, or `read`.

## Analyses enabled by the current tool

Callers choose the values that matter and use Membridge to locate:

- UTF-8 and UTF-16LE text through explicit string patterns;
- integers and floats with a chosen width, signedness, and byte order;
- partially known values through byte or nibble masks;
- canaries, sentinels, magic values, identifiers, and serialized headers;
- several alternative representations in one tagged batch;
- one module, region, address range, access right, or memory type at a time;
- module-relative locations through returned RVAs;
- small byte windows around promising matches.

Membridge encodes each declared value into exact bytes and matches those bytes.
It never infers a type from memory, decodes values it finds, applies Base64, XOR,
or compression, or chooses a scope on its own.

## Result semantics

`scan_complete` and `coverage_complete` answer different questions:

- `scan_complete`: the scanner exhausted the selected scope it could read;
- `coverage_complete`: every expected readable byte was actually present and read.

`terminal_reason: "match_limit"` means matches are a deterministic prefix and `next_address` identifies where omitted results begin, in the same ascending order inside the selected scope.

Coverage limitations are:

- `MEMORY_METADATA_MISSING`;
- `MEMORY_METADATA_UNUSABLE`;
- `EXPECTED_READABLE_SCOPE_UNPROVEN`;
- `KNOWN_READABLE_BYTES_MISSING`;
- `READS_NOT_ATTEMPTED`;
- `READABLE_BYTES_UNREADABLE`.

Missing or unusable metadata is accompanied by `EXPECTED_READABLE_SCOPE_UNPROVEN`. Zero unavailable bytes does not prove complete coverage when expected readable scope is unproven.

A scoped live scan reports `EXPECTED_READABLE_SCOPE_UNPROVEN` because it deliberately
read only its scope; that is expected, not a defect. `READABLE_BYTES_UNREADABLE` is
different and always worth reporting: memory the kernel listed as readable refused a
read, so the target changed underneath the scan.

Specification and scope failures are distinct and stable:

- `INVALID_SCAN_SPEC`: malformed JSON, unknown kind or field, an out-of-range typed value, NaN, a malformed mask, or a broken limit;
- `UNRESOLVED_SCOPE`: a module selector matching no captured module or more than one, or an unknown region id;
- `SCOPE_METADATA_UNAVAILABLE`: `protections` or `types` requested from a source without region metadata.

Narrow a scope with `regions` or `ranges` when metadata is unavailable; never treat an unresolved scope as an empty result.

Useful evidence language:

- **observed:** matched captured readable memory;
- **not observed in captured scope:** scanning finished, but coverage was incomplete;
- **not observed in complete scope:** scanning and coverage were both complete;
- **unknown:** scanning stopped, failed, or omitted relevant memory.

Addresses, region offsets, and module RVAs are all fixed-width hexadecimal strings such as `"0x0000000140000100"`. Do not coerce them through lossy floating-point JSON numbers. Do not concatenate read segments across a gap.

## Current boundary

Membridge reads live processes on macOS, Linux, and Windows, and Windows x64 user-mode
minidumps containing `Memory64ListStream` or `MemoryListStream` on every host. It can
capture such a dump directly from a running Windows process.

It does not currently:

- write, allocate, protect, suspend, or execute memory in a target;
- attach as a debugger, stop a target, or freeze it for a consistent snapshot;
- decode, infer, or interpret the values it finds;
- resolve symbols or disassemble instructions;
- scan pointers, run YARA rules, or refine results across observations;
- infer structures or crash causes;
- contact network services.

Every command emits one compact schema-v4 JSON object. Failures contain a stable error code, message, and retryability flag. Do not suppress failures or treat partial output as complete.

Only inspect processes and dumps the user is authorized to analyze.
