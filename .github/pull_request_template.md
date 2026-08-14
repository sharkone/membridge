## Observable change

Describe the user-visible or protocol-visible behavior.

## Coverage and incomplete states

Explain effects on missing memory, partial reads, quotas, cancellation, volatility, and determinism. Write “unchanged” when applicable.

## Security and privacy

Explain changes to privileges, persistence, sensitive output, network behavior, or the read-only boundary. Write “unchanged” when applicable.

## Verification

List the exact commands and end-to-end scenario exercised.

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `./examples/demo.sh`

## Contract synchronization

- [ ] Behavioral tests cover the change.
- [ ] README reflects shipped behavior.
- [ ] Agent Skill and embedded examples reflect shipped behavior.
- [ ] PLAN and ROADMAP remain accurate.
- [ ] No real dumps, secrets, credentials, local state, or build output are included.
