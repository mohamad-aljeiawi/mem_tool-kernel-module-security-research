#!/system/bin/sh
#
# on-device-runner.sh — executed on the Android device as root by extract.sh.
#
# Assumptions (the host-side extract.sh makes them true before invoking us):
#   - /data/local/tmp/dumper       : the aarch64 kprobe dumper (executable)
#   - /data/local/tmp/<target>.elf : the unpacked userland binary
#   - we are running as uid 0 (root)
#
# Flow:
#   1. Sanity checks (root, files present, tracefs writable).
#   2. Clear any stale output and any stale dumper process.
#   3. Start dumper in the background, log to /data/local/tmp/dumper.log.
#   4. Small sleep so the kprobe is definitely armed before the binary runs.
#   5. Run the userland binary (its syscall is what makes the kprobe fire).
#   6. Wait up to TIMEOUT seconds for the dumper to finish.
#   7. If the dumper is still running when the binary already exited, give it a
#      few extra seconds, then SIGTERM; the dumper cleans its own kprobe up.
#   8. Report status and leave the captured .ko in /data/local/tmp/.
#
# Usage:
#   on-device-runner.sh /data/local/tmp/5.10.elf [timeout_seconds]
#
# Exit codes:
#   0   success, /data/local/tmp/dumped_bing_rw.ko exists and starts with ELF
#   10  not running as root
#   11  dumper binary missing / not executable
#   12  target elf missing / not executable
#   13  tracefs not writable (unusual; usually means kernel lockdown or SELinux)
#   20  dumper never produced an output file (binary probably saw /dev/bing_rw
#       already exists and short-circuited — reboot and try again)
#   21  output exists but ELF magic is wrong (partial read or wrong address)

set -u

TARGET="${1:-}"
TIMEOUT="${2:-30}"

DUMPER=/data/local/tmp/dumper
OUT=/data/local/tmp/dumped_bing_rw.ko
LOG=/data/local/tmp/dumper.log
TRACE=/sys/kernel/tracing

log() { echo "[runner] $*"; }

# --- 1. sanity --------------------------------------------------------------
if [ "$(id -u)" != "0" ]; then
    log "not root (uid=$(id -u)); re-invoke me via su -c"
    exit 10
fi

if [ -z "$TARGET" ]; then
    log "usage: $0 /data/local/tmp/<name>.elf [timeout_seconds]"
    exit 10
fi

if [ ! -x "$DUMPER" ]; then
    log "dumper missing or not executable at $DUMPER"
    log "  expected: adb push prebuilt/dumper $DUMPER"
    exit 11
fi

if [ ! -f "$TARGET" ]; then
    log "target not found: $TARGET"
    exit 12
fi

chmod 755 "$TARGET" 2>/dev/null
chmod 755 "$DUMPER" 2>/dev/null

if [ ! -w "$TRACE/kprobe_events" ]; then
    log "tracefs not writable ($TRACE/kprobe_events)"
    log "  kernel lockdown? SELinux? check: ls -la $TRACE/kprobe_events"
    exit 13
fi

# --- 2. clean slate ---------------------------------------------------------
rm -f "$OUT" "$LOG" 2>/dev/null

# There should never be a stale dumper, but if extract.sh was Ctrl-C'd mid-run
# we might have left one behind. Kill any instances of our exact binary.
# (pkill may be absent on toybox; fall back to a manual scan.)
if command -v pkill >/dev/null 2>&1; then
    pkill -f /data/local/tmp/dumper 2>/dev/null
else
    for pid in $(ls /proc 2>/dev/null); do
        [ -d "/proc/$pid" ] || continue
        [ -r "/proc/$pid/cmdline" ] || continue
        if grep -q "/data/local/tmp/dumper" "/proc/$pid/cmdline" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
fi

# Remove any stale kprobe of ours that a previous aborted run may have left.
# We can't truncate kprobe_events (other kprobes may live in there, e.g. MIUI's
# miuibpf). We can only -append a '-:kprobes/<name>' line.
echo '-:kprobes/ft_init_x' >> "$TRACE/kprobe_events" 2>/dev/null

# --- 3. start dumper --------------------------------------------------------
log "starting dumper -> $LOG"
"$DUMPER" >"$LOG" 2>&1 &
DUMPER_PID=$!

# A brief spin so the kprobe is DEFINITELY armed before we run the binary.
# (The dumper prints "kprobe installed" when ready; wait up to 2s for it.)
i=0
while [ $i -lt 20 ]; do
    if grep -q "kprobe installed" "$LOG" 2>/dev/null; then
        break
    fi
    # Dumper might have already died (install failed, e.g. no root on tracefs).
    if ! kill -0 "$DUMPER_PID" 2>/dev/null; then
        log "dumper died during init:"
        cat "$LOG" 2>/dev/null
        exit 13
    fi
    # Toybox sleep accepts fractional seconds.
    sleep 0.1
    i=$((i + 1))
done
log "dumper pid=$DUMPER_PID, kprobe armed"

# --- 4. run the binary ------------------------------------------------------
log "running target: $TARGET"
# We redirect stdout/stderr of the binary into the runner's log so we can see
# things like "刷入成功" / "已刷入驱动" on the host side afterwards.
"$TARGET" >/data/local/tmp/target.stdout 2>/data/local/tmp/target.stderr
TARGET_RC=$?
log "target exit code: $TARGET_RC"

# --- 5. wait for dumper -----------------------------------------------------
# Dumper exits the moment it successfully extracts one .ko. If /dev/bing_rw
# already existed, the binary skipped init_module and the kprobe never fired;
# in that case the dumper will still be sitting in read(trace_pipe) when we
# get here.
log "waiting up to ${TIMEOUT}s for dumper to finish"
w=0
while kill -0 "$DUMPER_PID" 2>/dev/null; do
    # Every 10 iters (≈1s) check if the output file appeared; if so, the
    # dumper already did the work, we can proceed.
    if [ -s "$OUT" ]; then
        break
    fi
    sleep 0.1
    w=$((w + 1))
    if [ $w -ge $((TIMEOUT * 10)) ]; then
        log "timeout; the binary likely short-circuited via /dev/bing_rw"
        log "  => reboot the device and rerun extract.sh"
        kill "$DUMPER_PID" 2>/dev/null
        break
    fi
done

# Give it a small grace period for its write() to finish, then stop it if
# we were the ones who triggered the stop.
sleep 0.2
kill "$DUMPER_PID" 2>/dev/null
wait "$DUMPER_PID" 2>/dev/null

# --- 6. report --------------------------------------------------------------
log "---- dumper log ----"
cat "$LOG" 2>/dev/null
log "---- target stdout ----"
cat /data/local/tmp/target.stdout 2>/dev/null
log "--------------------"

if [ ! -s "$OUT" ]; then
    log "no output produced"
    exit 20
fi

magic=$(head -c 4 "$OUT" 2>/dev/null | od -An -tx1 -N4 | tr -d ' \n')
if [ "$magic" != "7f454c46" ]; then
    log "output exists but ELF magic is wrong (got $magic)"
    exit 21
fi

sz=$(wc -c < "$OUT" | tr -d ' ')
log "SUCCESS: $OUT ($sz bytes, ELF magic OK)"
exit 0
