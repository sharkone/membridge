# Examples

These examples use synthetic data only. Do not add real process dumps or production secrets to the repository.

## Deterministic fixture

`generate_fixture.rs` creates a valid Windows AMD64 user-mode minidump with this layout:

| Virtual range | State | Captured | Contents |
|---|---|---|---|
| `0x140000000..0x140002000` | committed, read/write | yes | two `MBRIDGE!` canaries |
| `0x140002000..0x140003000` | committed, no-access | yes | one identical decoy |
| `0x140003000..0x140004000` | committed, read/write | no | explicit coverage gap |

One readable canary begins at `0x140000ffc`, so the eight-byte match crosses a 4 KiB page boundary.

Generate it with:

```sh
cargo run --example generate_fixture -- target/demo/fixture.dmp
```

## Full demo

```sh
./examples/demo.sh
```

The script:

1. generates the fixture;
2. inspects source coverage;
3. scans the canonical UTF-8 and UTF-16LE batch specification;
4. scans the typed batch under a module-and-access-right scope;
5. reads the first match as bounded context;
6. installs the Agent Skill embedded in the binary;
7. starts `test-support/synthetic-target` and inspects, scans, and reads it live.

Expected facts for the dump section:

- two UTF-8 matches;
- no UTF-16LE matches;
- the no-access decoy is excluded;
- `unavailable_readable_bytes` is `4096`;
- the bounded read returns `MBRIDGE!`;
- installed skill files match `.agents/skills/membridge`.

Expected facts for the live section:

- `source.kind` is `live` and `source.immutable` is `false`;
- `inspect` reports `READS_NOT_ATTEMPTED`, because enumerating an address space proves no byte;
- the scoped scan matches `MBRIDGE-CAPTURE-READABLE!!` at the block base and `MBRIDGE-EDGE-CANARY!` ending at the last readable byte;
- the boundary read requests 64 bytes, returns 32, and reports `complete: false`;
- `coverage.observation` carries the wall-clock window of each command.

On macOS the script signs the target ad-hoc with `com.apple.security.get-task-allow`
first; without that entitlement the kernel refuses a task port to an unprivileged
caller. On Linux the target opts in with `PR_SET_PTRACER_ANY`, so it works under the
default `ptrace_scope` of 1.

## Adapting the workflow

For an authorized dev build, live:

1. Start the build under test. On macOS sign it with `com.apple.security.get-task-allow`; on Linux run it as a descendant of membridge or have it call `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`.
2. Run `membridge inspect --pid <pid>` and record the fingerprint, region layout, and observation window.
3. Choose a scope before scanning: a module, an address range, or `protections: ["write"]` with `types: ["private"]`. An unscoped live scan reads every mapped readable byte, including gigabytes of shared system libraries.
4. Convert only known non-production canaries or test values into exact bytes.
5. Run one tagged batch scan and read the smallest useful window around selected matches.
6. Report `READABLE_BYTES_UNREADABLE` when it appears: the target changed underneath the scan, so those bytes are unproven.

For an authorized dev build, captured:

1. Create a Windows x64 full-memory user-mode minidump using an approved capture tool, or `membridge capture minidump` on Windows.
2. Run `membridge inspect` and record the fingerprint and coverage.
3. Convert only known non-production canaries or test values into exact bytes.
4. Copy `.agents/skills/membridge/examples/canary-batch.json` outside the repository and replace its synthetic values.
5. Keep tags descriptive of representation, not the literal secret.
6. Run one tagged batch scan.
7. Read the smallest useful window around selected matches.
8. Report gaps and match limits with the finding.

Current Membridge does not generate UTF encodings automatically. The Agent Skill or caller must supply every explicit representation.

## Useful experiments

### Erasure check

Observe or capture before and after an authorized dev build clears a canary. Analyse each observation independently. A post-clear match proves a retained copy; no match proves absence only when both scan and coverage are complete — and a live observation is never complete for memory the kernel refused.

### Duplicate-copy inventory

Place a synthetic token into one intended buffer, exercise serialization or IPC code, then inspect every match grouped by region and module. Current output provides attribution per match; server-side grouping is roadmap work.

### Debugger handoff

Use a match's virtual address or module RVA in the debugger already configured for the target build. Membridge intentionally does not install or control a debugger.
