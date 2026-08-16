#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

VERSION="0.1.0-alpha.4"
INSTALLER_URL="https://github.com/sharkone/membridge/releases/download/v0.1.0-alpha.4/membridge-installer.sh"
INSTALLER_SHA256="8fc8784c0b35ea7fb8de7adf392ef2b3e31b33ea6006a35a1112171eabba9472"
MAX_INSTALLER_BYTES=1048576

fail() {
    printf 'membridge bootstrap: %s\n' "$*" >&2
    exit 1
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        digest=$(sha256sum "$1") || return 1
        printf '%s\n' "${digest%% *}"
    elif command -v shasum >/dev/null 2>&1; then
        digest=$(shasum -a 256 "$1") || return 1
        printf '%s\n' "${digest%% *}"
    elif command -v openssl >/dev/null 2>&1; then
        digest=$(openssl dgst -sha256 "$1") || return 1
        printf '%s\n' "${digest##* }"
    else
        return 1
    fi
}

if [ "${MEMBRIDGE_BOOTSTRAP_FORCE:-0}" != "1" ] && command -v membridge >/dev/null 2>&1; then
    installed_version=$(membridge --version 2>/dev/null || true)
    if [ "$installed_version" = "membridge $VERSION" ]; then
        printf 'membridge %s is already installed\n' "$VERSION"
        exit 0
    fi
fi

umask 077
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/membridge-bootstrap.XXXXXX") || fail "could not create a temporary directory"
installer="$tmp_dir/membridge-installer.sh"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --output "$installer" "$INSTALLER_URL" || fail "could not download the release installer"
elif command -v wget >/dev/null 2>&1; then
    wget --quiet --output-document="$installer" "$INSTALLER_URL" || fail "could not download the release installer"
else
    fail "curl or wget is required"
fi

installer_bytes=$(wc -c < "$installer") || fail "could not measure the release installer"
if [ "$installer_bytes" -eq 0 ] || [ "$installer_bytes" -gt "$MAX_INSTALLER_BYTES" ]; then
    fail "release installer size is outside the allowed range"
fi

actual_sha256=$(sha256_file "$installer") || fail "sha256sum, shasum, or openssl is required"
if [ "$actual_sha256" != "$INSTALLER_SHA256" ]; then
    fail "release installer checksum mismatch"
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    if command -v shasum >/dev/null 2>&1; then
        cat > "$tmp_dir/sha256sum" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-b" ]; then
    shift
fi
exec shasum -a 256 "$@"
EOF
    elif command -v openssl >/dev/null 2>&1; then
        cat > "$tmp_dir/sha256sum" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-b" ]; then
    shift
fi
for file in "$@"; do
    digest=$(openssl dgst -sha256 "$file") || exit 1
    printf '%s  %s\n' "${digest##* }" "$file"
done
EOF
    fi
    chmod 700 "$tmp_dir/sha256sum" || fail "could not prepare archive checksum verification"
    PATH="$tmp_dir:$PATH"
    export PATH
fi

chmod 700 "$installer" || fail "could not make the verified installer executable"
printf 'installing membridge %s from a checksum-verified release installer\n' "$VERSION"
sh "$installer" "$@"
if [ -n "${CARGO_HOME:-}" ]; then
    installed_binary="$CARGO_HOME/bin/membridge"
elif [ -n "${HOME:-}" ]; then
    installed_binary="$HOME/.cargo/bin/membridge"
else
    installed_binary=""
fi

if [ -z "$installed_binary" ] || [ ! -x "$installed_binary" ]; then
    installed_binary=$(command -v membridge 2>/dev/null || true)
fi
if [ -z "$installed_binary" ] || [ ! -x "$installed_binary" ]; then
    fail "installed binary could not be located"
fi

installed_version=$("$installed_binary" --version 2>/dev/null || true)
if [ "$installed_version" != "membridge $VERSION" ]; then
    fail "installed binary did not report membridge $VERSION"
fi
printf 'installed membridge %s at %s\n' "$VERSION" "$installed_binary"
