#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# load_driver.sh -- auto-select + insmod the devwh kernel module that
#                   matches the running Android kernel.
#
# This is a clean replacement for the self-extracting Telegram-gated
# "dev/*.sh" loaders that shipped with the original cheat distribution.
# It performs ONLY the steps that are necessary to load the module:
#
#   1. root check
#   2. detect kernel version + vendor flavor via `uname -r`
#   3. pick the matching .ko from $KO_DIR (default: mem_tool_driver/)
#   4. print the file's sha256 and its baked-in modinfo so you can
#      confirm what you are about to load BEFORE it runs
#   5. insmod
#   6. verify a 6-char chardev appeared under /dev, print it
#
# Explicitly NOT done, unlike the originals:
#   - no Telegram "channel verification" gate
#   - no `dmesg -C` (we want to keep the kernel log auditable)
#   - no ELF hidden inside the shell script (the .ko is a real file;
#     you can sha256 it, sign it, etc. before running)
#
# Usage:
#   sh load_driver.sh                 # auto-pick
#   KO=path/to/my.ko sh load_driver.sh
#   KO_DIR=path/to/dir sh load_driver.sh
#   sh load_driver.sh --dry-run       # print the plan, do not insmod
#   sh load_driver.sh --permissive    # setenforce 0 before insmod (if needed)
#   sh load_driver.sh --force-recover # try to rmmod every plausible name + exit
#
# Exit codes:
#   0  loaded ok
#   1  usage / missing file
#   2  not root
#   3  no matching .ko for this kernel
#   4  insmod failed (see kernel log)

set -u

# -------- colors (cheap; disable with NO_COLOR=1) --------------------
if [ "${NO_COLOR:-0}" = "1" ] || [ ! -t 1 ]; then
    C_G=''; C_R=''; C_Y=''; C_C=''; C_0=''
else
    C_G=$(printf '\033[32m'); C_R=$(printf '\033[31m')
    C_Y=$(printf '\033[33m'); C_C=$(printf '\033[36m')
    C_0=$(printf '\033[0m')
fi

log()  { printf "%s[load]%s %s\n"   "$C_C" "$C_0" "$*"; }
ok()   { printf "%s[ ok]%s %s\n"    "$C_G" "$C_0" "$*"; }
warn() { printf "%s[warn]%s %s\n"   "$C_Y" "$C_0" "$*" >&2; }
die()  { printf "%s[fail]%s %s\n"   "$C_R" "$C_0" "$*" >&2; exit "${2:-1}"; }

# -------- args -------------------------------------------------------
DRY_RUN=0
PERMISSIVE=0
RECOVER=0
for a in "$@"; do
    case "$a" in
        --dry-run)        DRY_RUN=1 ;;
        --permissive)     PERMISSIVE=1 ;;
        --force-recover)  RECOVER=1 ;;
        -h|--help)
            sed -n '2,40p' "$0"; exit 0 ;;
        *) die "unknown arg: $a" 1 ;;
    esac
done

# -------- root check -------------------------------------------------
[ "$(id -u)" = "0" ] || die "must run as root (got uid=$(id -u))" 2

# -------- force-recover path (reboot-avoiding unload) ----------------
if [ "$RECOVER" = "1" ]; then
    log "trying rmmod for all plausible names"
    for n in devwh devddyc devcheat; do
        rmmod "$n" 2>/dev/null && ok "rmmod $n"
    done
    exit 0
fi

# -------- detect kernel ---------------------------------------------
UN_R=$(uname -r)
log "uname -r        : ${UN_R}"

# extract just major.minor.patch
KVER=$(printf '%s\n' "$UN_R" | awk -F'[.-]' '{printf "%s.%s.%s", $1, $2, $3}')
KMM=$(printf '%s\n' "$UN_R"  | awk -F'[.-]' '{printf "%s.%s",    $1, $2}')
log "major.minor     : ${KMM}"
log "major.minor.pat : ${KVER}"

# vendor flavor heuristics
FLAVOR=""
case "$UN_R" in
    *qgki*)        FLAVOR="qgki"  ;;   # Qualcomm GKI
    *gki*)         FLAVOR="gki"   ;;   # stock Android GKI
    *android*)     FLAVOR="android";;  # android-mainline
    *mtk*|*gnmtl*) FLAVOR="mtk"   ;;   # MediaTek
esac
[ -n "$FLAVOR" ] && log "vendor flavor   : ${FLAVOR}"

# -------- choose .ko -------------------------------------------------
KO_DIR=${KO_DIR:-"$(cd "$(dirname "$0")" && pwd)/mem_tool_driver"}
PICKED=""

pick() {
    [ -f "$KO_DIR/$1" ] || return 1
    PICKED="$KO_DIR/$1"
    return 0
}

if [ -n "${KO:-}" ]; then
    [ -f "$KO" ] || die "KO=$KO not found" 1
    PICKED="$KO"
else
    case "$KMM" in
    5.4)
        # three 5.4 variants exist: 5.4.ko (qgki 5.4.61), 5.4c.ko
        # (qgki 5.4.191), 5.4b.ko (non-qgki). Pick the closest.
        if [ "$FLAVOR" = "qgki" ]; then
            # compare patch-level numerically
            KPATCH=$(printf '%s\n' "$UN_R" | awk -F'[.-]' '{print $3+0}')
            if [ "${KPATCH:-0}" -le 170 ]; then
                pick 5.4.ko  || pick 5.4c.ko
            else
                pick 5.4c.ko || pick 5.4.ko
            fi
        else
            pick 5.4b.ko || pick 5.4.ko
        fi
        ;;
    5.10)  pick 5.10.ko  ;;
    5.15)  pick 5.15.ko  ;;
    6.1)   pick 6.1.ko   ;;
    6.6)   pick 6.6.ko   ;;
    6.12)  pick 6.12.ko  ;;
    *)
        die "no .ko shipped for kernel ${KMM}.x (have: 5.4/5.10/5.15/6.1/6.6/6.12)" 3
        ;;
    esac
fi

[ -n "$PICKED" ] || die "no matching .ko in $KO_DIR for kernel $KMM" 3
log "picked          : $PICKED"

# -------- integrity: sha256 + modinfo peek ---------------------------
if command -v sha256sum >/dev/null 2>&1; then
    log "sha256          : $(sha256sum "$PICKED" | awk '{print $1}')"
fi

# extract the vermagic= field from the ELF's .modinfo section without
# needing 'modinfo' on device. .modinfo is a concatenation of KEY=VAL
# NUL-terminated strings, so splitting on NULs gives one field per line.
KO_VERMAGIC=$(tr '\000' '\n' < "$PICKED" \
                | grep -a '^vermagic=' \
                | head -n1 \
                | sed 's/^vermagic=//')
log "modinfo vermagic: ${KO_VERMAGIC:-<unreadable>}"

KO_MODNAME=$(tr '\000' '\n' < "$PICKED" \
                | grep -a '^name=' \
                | head -n1 \
                | sed 's/^name=//')
[ -n "$KO_MODNAME" ] && log "modinfo name    : ${KO_MODNAME}"

# soft check: warn if vermagic prefix doesn't match `uname -r`'s prefix
VM_PFX=$(printf '%s' "$KO_VERMAGIC" | awk -F'[-.]' '{print $1"."$2"."$3}')
UR_PFX=$(printf '%s' "$UN_R"        | awk -F'[-.]' '{print $1"."$2"."$3}')
if [ -n "$VM_PFX" ] && [ -n "$UR_PFX" ] && [ "$VM_PFX" != "$UR_PFX" ]; then
    warn ".ko was built for kernel prefix '$VM_PFX' but running kernel is '$UR_PFX'"
    warn "insmod will probably refuse with 'Invalid module format'."
fi

# -------- dry-run exits here -----------------------------------------
if [ "$DRY_RUN" = "1" ]; then
    log "dry-run: would insmod $PICKED"
    exit 0
fi

# -------- optional SELinux permissive --------------------------------
if [ "$PERMISSIVE" = "1" ]; then
    if command -v setenforce >/dev/null 2>&1; then
        prev=$(getenforce 2>/dev/null || echo "?")
        setenforce 0 2>/dev/null && log "SELinux -> permissive (was $prev)"
    fi
fi

# -------- remember what was present before, so we can spot our chardev
BEFORE_DEVS=$(
    find /dev -maxdepth 1 -type c 2>/dev/null \
        | awk -F/ '{print $NF}' \
        | awk 'length($1)==6 && $1 ~ /^[A-Za-z0-9]+$/'
)

# -------- insmod -----------------------------------------------------
log "insmod ${PICKED} ..."
INSMOD_OUT=$(insmod "$PICKED" 2>&1)
INSMOD_RC=$?
if [ $INSMOD_RC -ne 0 ]; then
    printf '%s\n' "$INSMOD_OUT" >&2
    warn "insmod failed (rc=$INSMOD_RC). Last 20 lines of dmesg:"
    dmesg | tail -n 20 >&2 || true
    die "kernel refused the module" 4
fi
ok "insmod succeeded"

# -------- identify the chardev we just created ----------------------
AFTER_DEVS=$(
    find /dev -maxdepth 1 -type c 2>/dev/null \
        | awk -F/ '{print $NF}' \
        | awk 'length($1)==6 && $1 ~ /^[A-Za-z0-9]+$/'
)
NEW_DEV=$(printf '%s\n%s\n' "$BEFORE_DEVS" "$AFTER_DEVS" \
            | sort | uniq -u | head -n1)
if [ -n "$NEW_DEV" ]; then
    ok "chardev         : /dev/$NEW_DEV"
else
    warn "module loaded but no new 6-char chardev appeared in /dev"
    warn "it may have been created under a sysfs-hidden path; the client's"
    warn "auto-probe (kernel_client.h :: driver_path) should still find it."
fi

# -------- module presence (will be hidden if self-hide is on) --------
MNAME="${KO_MODNAME:-devwh}"
if [ -r /proc/modules ] && awk -v m="$MNAME" '$1==m{found=1} END{exit !found}' /proc/modules; then
    ok "module list     : $MNAME"
else
    warn "module '$MNAME' is not visible in /proc/modules (expected: self-hide is on)"
fi

log "done. See CLIENT.md for how your userland talks to this device."
exit 0
