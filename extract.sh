#!/usr/bin/env bash
#
# extract.sh — one-command wrapper. Give it a FT-2.2.0 .sh, get a clean .ko.
#
# What it does, in order:
#   1. Validates host prerequisites (adb, gunzip, tail, od).
#   2. Unpacks the .sh self-extractor into a local .elf file (offline).
#   3. Uses prebuilt/dumper by default, or rebuilds via NDK if requested.
#   4. adb-pushes dumper + .elf + on-device-runner.sh to /data/local/tmp.
#   5. (Unless --no-reboot) reboots the device to clear any previously-loaded
#      bing_rw.ko. The module is rootkit-hidden; reboot is the only way to
#      make the binary take the long path through init_module again.
#   6. Runs the runner on-device as root (needs `su` — Magisk).
#   7. Pulls the captured .ko to output/<stem>.ko.
#   8. Sanity-checks the output and prints a summary.
#
# Usage:
#   ./extract.sh path/to/X.X.sh
#   ./extract.sh --no-reboot path/to/X.X.sh
#   ./extract.sh --rebuild-dumper path/to/X.X.sh       (requires $NDK_PATH)
#   ./extract.sh --use-prebuilt path/to/X.X.sh         (default; explicit)
#   ./extract.sh --timeout 60 path/to/X.X.sh
#
# Env:
#   ADB        : path to adb (default: adb on PATH)
#   ADB_SERIAL : device serial if multiple attached
#
# Host compatibility:
#   - Linux / macOS bash
#   - Windows 10/11 Git Bash (MSYS2) — path conversion of /data/... is disabled

set -euo pipefail

# ---------------------------------------------------------------------------
# locate ourselves and the toolkit tree
# ---------------------------------------------------------------------------
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TK_ROOT="$SCRIPT_DIR"
TOOLS_DIR="$TK_ROOT/tools"
SRC_DIR="$TK_ROOT/src"
PREBUILT_DIR="$TK_ROOT/prebuilt"
OUTPUT_DIR="$TK_ROOT/output"
TMP_DIR="$TK_ROOT/tmp"

mkdir -p -- "$OUTPUT_DIR" "$TMP_DIR"

# ---------------------------------------------------------------------------
# args
# ---------------------------------------------------------------------------
NO_REBOOT=0
USE_PREBUILT=1       # default: use shipped prebuilt
REBUILD=0
TIMEOUT=30
INPUT_SH=""

usage() {
    cat <<EOF
usage: $(basename "$0") [flags] <path/to/X.X.sh>

flags:
  --no-reboot         skip 'adb reboot' (use only if bing_rw is NOT loaded)
  --use-prebuilt      use prebuilt/dumper (default)
  --rebuild-dumper    recompile src/dumper.c with \$NDK_PATH
  --timeout <sec>     wait up to N seconds for the dumper (default 30)
  -h, --help          this help

env:
  ADB           adb binary (default: adb on PATH)
  ADB_SERIAL    device serial if multiple devices attached
  NDK_PATH      only used with --rebuild-dumper
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-reboot)        NO_REBOOT=1; shift ;;
        --use-prebuilt)     USE_PREBUILT=1; REBUILD=0; shift ;;
        --rebuild-dumper)   REBUILD=1; USE_PREBUILT=0; shift ;;
        --timeout)          TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        --)                 shift; INPUT_SH="${1:?}"; shift; break ;;
        -*)                 echo "[-] unknown flag: $1" >&2; usage >&2; exit 1 ;;
        *)                  INPUT_SH="$1"; shift ;;
    esac
done

[ -n "$INPUT_SH" ] || { usage >&2; exit 1; }
[ -f "$INPUT_SH"  ] || { echo "[-] input not found: $INPUT_SH" >&2; exit 1; }

# ---------------------------------------------------------------------------
# host tools
# ---------------------------------------------------------------------------
ADB="${ADB:-adb}"
command -v "$ADB" >/dev/null 2>&1 || { echo "[-] adb not on PATH (or set \$ADB)" >&2; exit 1; }

for t in gunzip tail od wc tr basename dirname; do
    command -v "$t" >/dev/null 2>&1 || { echo "[-] missing host tool: $t" >&2; exit 1; }
done

# Git Bash / MSYS2 auto-converts arguments that look like Unix paths into
# Windows paths when calling non-MSYS programs (like adb.exe). That breaks
# /data/local/tmp/... -> C:\Program Files\Git\data\local\tmp\... on the way to
# the device. Block it globally.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# ...but blocking conversion creates a second problem: the *local* source paths
# we compute ourselves (via `pwd`, which under Git Bash returns `/c/Users/...`)
# are also Unix-style, and adb.exe can't `stat /c/Users/...`. We need to convert
# LOCAL paths to Windows form ourselves, while keeping REMOTE paths literal.
# On Linux / macOS cygpath doesn't exist, so this is a no-op there.
winpath() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w -- "$1" 2>/dev/null || printf '%s\n' "$1"
    else
        printf '%s\n' "$1"
    fi
}

# adb wrapper that inherits ADB_SERIAL and MSYS safety.
adb_() {
    if [ -n "${ADB_SERIAL:-}" ]; then
        MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$ADB" -s "$ADB_SERIAL" "$@"
    else
        MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$ADB" "$@"
    fi
}

# ---------------------------------------------------------------------------
# 1. unpack the .sh
# ---------------------------------------------------------------------------
stem=$(basename -- "$INPUT_SH"); stem="${stem%.sh}"
ELF="$TMP_DIR/$stem.elf"
echo "[*] unpacking $INPUT_SH -> $ELF"
bash "$TOOLS_DIR/unpack-sh.sh" "$INPUT_SH" "$ELF"

# ---------------------------------------------------------------------------
# 2. pick / build dumper
# ---------------------------------------------------------------------------
DUMPER_BIN="$PREBUILT_DIR/dumper"

if [ "$REBUILD" = "1" ]; then
    echo "[*] rebuilding dumper via NDK"
    bash "$TOOLS_DIR/build-dumper.sh"
fi

if [ ! -f "$DUMPER_BIN" ]; then
    echo "[-] no dumper binary at $DUMPER_BIN" >&2
    echo "    run: bash tools/build-dumper.sh     (needs NDK_PATH)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. check a device is actually attached
# ---------------------------------------------------------------------------
echo "[*] checking device"
if ! adb_ get-state >/dev/null 2>&1; then
    echo "[-] no adb device. Plug in, enable USB debug, authorize, and retry." >&2
    echo "    Output of 'adb devices':" >&2
    adb_ devices >&2 || true
    exit 1
fi

# Need su to run the kprobe dumper. Verify early so we fail fast.
if ! adb_ shell 'command -v su >/dev/null && su -c id' 2>/dev/null | grep -q 'uid=0'; then
    echo "[-] device is not rooted (no working 'su -c'). Install Magisk and grant root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. push artifacts
# ---------------------------------------------------------------------------
echo "[*] pushing artifacts to /data/local/tmp"
adb_ push "$(winpath "$DUMPER_BIN")"                     /data/local/tmp/dumper              >/dev/null
adb_ push "$(winpath "$ELF")"                            /data/local/tmp/$stem.elf           >/dev/null
adb_ push "$(winpath "$TOOLS_DIR/on-device-runner.sh")"  /data/local/tmp/on-device-runner.sh >/dev/null

adb_ shell 'chmod 755 /data/local/tmp/dumper /data/local/tmp/on-device-runner.sh' >/dev/null
adb_ shell "chmod 755 /data/local/tmp/$stem.elf" >/dev/null

# ---------------------------------------------------------------------------
# 5. reboot (unless opted out)
# ---------------------------------------------------------------------------
if [ "$NO_REBOOT" = "0" ]; then
    echo "[*] rebooting device to clear any previously-loaded bing_rw"
    echo "    (module is rootkit-hidden; reboot is the only way to unload)"
    adb_ reboot
    # adb will drop the connection; wait for the device to come back.
    echo "[*] waiting for device to come back..."
    adb_ wait-for-device
    # Wait for boot to actually finish — otherwise su may not be available yet.
    # sys.boot_completed becomes "1" at the end of userspace boot.
    echo "[*] waiting for boot_completed..."
    for _ in $(seq 1 60); do
        bc=$(adb_ shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n ')
        [ "$bc" = "1" ] && break
        sleep 2
    done
    # Push again — /data/local/tmp survives reboot, but being paranoid is cheap.
    adb_ shell 'ls /data/local/tmp/dumper /data/local/tmp/on-device-runner.sh' >/dev/null 2>&1 || {
        echo "[*] re-pushing after reboot"
        adb_ push "$(winpath "$DUMPER_BIN")"                     /data/local/tmp/dumper              >/dev/null
        adb_ push "$(winpath "$TOOLS_DIR/on-device-runner.sh")"  /data/local/tmp/on-device-runner.sh >/dev/null
    }
    adb_ shell "ls /data/local/tmp/$stem.elf" >/dev/null 2>&1 || {
        adb_ push "$(winpath "$ELF")" /data/local/tmp/$stem.elf >/dev/null
    }
    adb_ shell 'chmod 755 /data/local/tmp/dumper /data/local/tmp/on-device-runner.sh' >/dev/null
    adb_ shell "chmod 755 /data/local/tmp/$stem.elf" >/dev/null
else
    echo "[*] --no-reboot: skipping reboot (caller asserts bing_rw is not loaded)"
fi

# ---------------------------------------------------------------------------
# 6. run on device
# ---------------------------------------------------------------------------
echo "[*] running on-device-runner as root (timeout=${TIMEOUT}s)"
set +e
adb_ shell "su -c 'sh /data/local/tmp/on-device-runner.sh /data/local/tmp/$stem.elf $TIMEOUT'"
rc=$?
set -e
echo "[*] runner exit code: $rc"

# ---------------------------------------------------------------------------
# 7. pull result
# ---------------------------------------------------------------------------
OUT_KO="$OUTPUT_DIR/$stem.ko"
echo "[*] pulling /data/local/tmp/dumped_bing_rw.ko -> $OUT_KO"
# Pulling may fail if the runner didn't produce a file. Don't abort; print help.
if ! adb_ pull /data/local/tmp/dumped_bing_rw.ko "$(winpath "$OUT_KO")" >/dev/null 2>&1; then
    echo "[-] nothing to pull; no .ko was produced." >&2
    echo "    Common causes:" >&2
    echo "      - /dev/bing_rw was already present (reboot and rerun)" >&2
    echo "      - binary refused to init_module (not root? SELinux?)" >&2
    echo "      - anti-debug fired (no tracers allowed)" >&2
    echo "    See docs/04-TROUBLESHOOTING.md" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# 8. validate
# ---------------------------------------------------------------------------
sz=$(wc -c < "$OUT_KO" | tr -d ' ')
magic=$(head -c 4 -- "$OUT_KO" | od -An -tx1 -N4 | tr -d ' \n')
if [ "$magic" != "7f454c46" ]; then
    echo "[-] $OUT_KO exists but ELF magic is wrong (got $magic)" >&2
    echo "    The dump may be truncated. See docs/04-TROUBLESHOOTING.md" >&2
    exit 3
fi

echo ""
echo "========================================================================"
echo "SUCCESS"
echo "  output : $OUT_KO"
echo "  size   : $sz bytes"
echo "  magic  : 0x$magic (ELF)"
echo ""
echo "  next   : open in IDA as 'Elf64 for ARM (ARM64) [elf64.dll]'"
echo "========================================================================"
