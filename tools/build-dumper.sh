#!/usr/bin/env bash
#
# build-dumper.sh — (re)build src/dumper.c into prebuilt/dumper for Android.
#
# This is OPTIONAL. The toolkit ships a working prebuilt/dumper binary. You only
# need to rebuild if you modified src/dumper.c or you don't trust the prebuilt.
#
# Requires: Android NDK on $NDK_PATH (or $ANDROID_NDK_HOME / $ANDROID_NDK_ROOT).
#
# Usage:
#   ./build-dumper.sh                 # auto-detect host, pick clang
#   NDK_PATH=/opt/android-ndk-r26d \
#     ./build-dumper.sh
#   API=33 ./build-dumper.sh          # override default Android API level
#
# What it does:
#   - Finds `aarch64-linux-android<API>-clang[.cmd]` in the NDK prebuilt dir
#   - Compiles src/dumper.c with -O2 -static
#   - Writes prebuilt/dumper
#
# Why -static?
#   Device libc versions differ across the 35 different kernels this toolkit
#   targets. Linking statically means the same binary runs everywhere.

set -euo pipefail

# --- resolve paths ----------------------------------------------------------
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TK_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
SRC="$TK_ROOT/src/dumper.c"
OUT="$TK_ROOT/prebuilt/dumper"
mkdir -p -- "$TK_ROOT/prebuilt"

[ -f "$SRC" ] || { echo "[-] missing source: $SRC" >&2; exit 2; }

# --- resolve NDK ------------------------------------------------------------
NDK_PATH="${NDK_PATH:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$NDK_PATH" ]; then
    echo "[-] NDK not found. Set NDK_PATH (or ANDROID_NDK_HOME / ANDROID_NDK_ROOT) to your NDK root." >&2
    echo "    Example: export NDK_PATH=\"$HOME/Android/Sdk/ndk/26.3.11579264\"" >&2
    exit 3
fi
[ -d "$NDK_PATH" ] || { echo "[-] NDK_PATH does not exist: $NDK_PATH" >&2; exit 3; }

# --- detect host triple the NDK prebuilt dir uses ---------------------------
uname_s=$(uname -s 2>/dev/null || echo unknown)
case "$uname_s" in
    Linux*)       host_tag="linux-x86_64" ;;
    Darwin*)      host_tag="darwin-x86_64" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT) host_tag="windows-x86_64" ;;
    *)            host_tag="linux-x86_64" ;;   # best guess
esac

TOOLCHAIN="$NDK_PATH/toolchains/llvm/prebuilt/$host_tag/bin"
[ -d "$TOOLCHAIN" ] || {
    echo "[-] NDK prebuilt dir missing: $TOOLCHAIN" >&2
    echo "    Is your NDK layout unusual? (expected .../toolchains/llvm/prebuilt/$host_tag/bin)" >&2
    exit 3
}

# --- pick an API-level-specific clang wrapper -------------------------------
# Wrappers exist for API 21..<latest>. We prefer 33 (matches FT2.2.0 binaries'
# "for Android 21" minApi but with modern libc) but fall back downwards.
API="${API:-33}"

pick_clang() {
    local a="$1"
    local exe

    # On Windows/MSYS the wrapper is a .cmd, elsewhere it's a plain binary.
    if [ "$host_tag" = "windows-x86_64" ]; then
        exe="$TOOLCHAIN/aarch64-linux-android${a}-clang.cmd"
    else
        exe="$TOOLCHAIN/aarch64-linux-android${a}-clang"
    fi
    [ -f "$exe" ] && echo "$exe"
}

CLANG=""
for a in "$API" 34 33 31 30 29 28 26 24 23 21; do
    c=$(pick_clang "$a" || true)
    if [ -n "$c" ]; then
        CLANG="$c"
        FOUND_API="$a"
        break
    fi
done

[ -n "$CLANG" ] || {
    echo "[-] no aarch64-linux-android<N>-clang wrapper found in $TOOLCHAIN" >&2
    echo "    Tried API levels: $API 34 33 31 30 29 28 26 24 23 21" >&2
    exit 4
}

echo "[*] host tag : $host_tag"
echo "[*] NDK      : $NDK_PATH"
echo "[*] clang    : $CLANG  (api=$FOUND_API)"
echo "[*] source   : $SRC"
echo "[*] output   : $OUT"

# --- compile ----------------------------------------------------------------
# -O2         : mild optimization, keeps dispatch tight
# -static     : avoid libc-version mismatches across device kernels
# -s          : strip; we don't need symbols in the dumper
# -Wall -Wextra: catch bugs if someone edits dumper.c
"$CLANG" \
    -O2 -static -s \
    -Wall -Wextra \
    "$SRC" -o "$OUT"

sz=$(wc -c < "$OUT" | tr -d ' ')
echo "[+] built prebuilt/dumper ($sz bytes)"
