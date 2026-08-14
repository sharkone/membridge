#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="$ROOT/target/demo"
DUMP="$WORK/fixture.dmp"
SKILLS="$WORK/skills"
SPEC="$ROOT/.agents/skills/membridge/examples/canary-batch.json"

mkdir -p "$WORK"
cd "$ROOT"

cargo run --quiet --example generate_fixture -- "$DUMP"
cargo run --quiet -- inspect "$DUMP"
cargo run --quiet -- scan "$DUMP" --spec "$SPEC"
cargo run --quiet -- read "$DUMP" --address 0x140000100 --length 8
cargo run --quiet -- skill install --target "$SKILLS" --force
