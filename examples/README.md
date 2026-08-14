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
4. reads the first match as bounded context;
5. installs the Agent Skill embedded in the binary.

Expected facts:

- two UTF-8 matches;
- no UTF-16LE matches;
- the no-access decoy is excluded;
- `unavailable_readable_bytes` is `4096`;
- the bounded read returns `MBRIDGE!`;
- installed skill files match `.agents/skills/membridge`.

## Adapting the workflow

For an authorized dev build:

1. Create a Windows x64 full-memory user-mode minidump using an approved capture tool.
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

Capture before and after an authorized dev build clears a canary. Scan each dump independently. A post-clear match proves a retained copy; no match proves absence only when both scan and coverage are complete.

### Duplicate-copy inventory

Place a synthetic token into one intended buffer, exercise serialization or IPC code, then inspect every match grouped by region and module. Current output provides attribution per match; server-side grouping is roadmap work.

### Debugger handoff

Use a match's virtual address or module RVA in the debugger already configured for the target build. Membridge intentionally does not install or control a debugger.
