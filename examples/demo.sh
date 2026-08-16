#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="$ROOT/target/demo"
DUMP="$WORK/fixture.dmp"
DEMO_HOME="$WORK/home"
SPEC="$ROOT/.agents/skills/membridge/examples/canary-batch.json"
SCOPED_SPEC="$ROOT/.agents/skills/membridge/examples/scoped-batch.json"

mkdir -p "$WORK"
cd "$ROOT"

# Immutable source: a synthetic Windows x64 minidump, analysable on every host.
cargo run --quiet --example generate_fixture -- "$DUMP"
cargo run --quiet -- inspect "$DUMP"
cargo run --quiet -- scan "$DUMP" --spec "$SPEC"
cargo run --quiet -- scan "$DUMP" --spec "$SCOPED_SPEC"
cargo run --quiet -- read "$DUMP" --address 0x140000100 --length 8
HOME="$DEMO_HOME" "$ROOT/target/debug/membridge" skill install --force

# Live source: this host's own process memory, read-only.
cargo build --quiet --package synthetic-target
TARGET_BIN="$ROOT/target/debug/synthetic-target"

if [ "$(uname -s)" = "Darwin" ]; then
    # Without this entitlement the kernel refuses a task port to an unprivileged
    # caller, so an ordinary user could only run the live demo under sudo.
    cat > "$WORK/get-task-allow.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
PLIST
    codesign -f -s - --entitlements "$WORK/get-task-allow.plist" "$TARGET_BIN" 2>/dev/null
fi

# The target blocks on stdin until the demo is done with it; a FIFO held open here
# keeps it alive without a sleep race.
rm -f "$WORK/hold" "$WORK/target.out"
mkfifo "$WORK/hold"
"$TARGET_BIN" < "$WORK/hold" > "$WORK/target.out" &
TARGET_PID=$!
exec 3> "$WORK/hold"
trap 'exec 3>&- 2>/dev/null || true; kill "$TARGET_PID" 2>/dev/null || true' EXIT

WAITED=0
while [ ! -s "$WORK/target.out" ] && [ "$WAITED" -lt 50 ]; do
    sleep 0.1
    WAITED=$((WAITED + 1))
done

READABLE=$(sed -n 's/.*readable=\(0x[0-9a-f]*\).*/\1/p' "$WORK/target.out")
NOACCESS=$(sed -n 's/.*noaccess=\(0x[0-9a-f]*\).*/\1/p' "$WORK/target.out")
[ -n "$READABLE" ] || { echo "synthetic-target did not report its layout" >&2; exit 1; }

# Scoped to the target's own readable block, so the live scan reads 64 KiB instead of
# sweeping every mapped byte in the address space.
cat > "$WORK/live-canary.json" <<SPEC
{
  "schema": 2,
  "patterns": [
    { "tag": "live-canary.utf8", "value": { "kind": "utf8", "text": "MBRIDGE-CAPTURE-READABLE!!" } },
    { "tag": "live-canary.edge", "value": { "kind": "utf8", "text": "MBRIDGE-EDGE-CANARY!" } }
  ],
  "scope": { "ranges": [{ "start": "$READABLE", "length": "0x10000" }] },
  "max_matches": 100
}
SPEC

"$ROOT/target/debug/membridge" inspect --pid "$TARGET_PID"
"$ROOT/target/debug/membridge" scan --pid "$TARGET_PID" --spec "$WORK/live-canary.json"
# Ends 32 bytes into the readable block's last page and runs into the inaccessible
# block, so the response is explicitly incomplete instead of silently short.
"$ROOT/target/debug/membridge" read --pid "$TARGET_PID" \
    --address "$(printf '0x%x' $((NOACCESS - 32)))" --length 64
