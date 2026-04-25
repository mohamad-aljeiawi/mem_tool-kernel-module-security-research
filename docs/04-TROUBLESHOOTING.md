# Troubleshooting

Errors we hit during development and how to diagnose / fix them. Organized roughly by phase.

---

## Host-side (Windows / Git Bash)

### `adb push` fails with `secure_mkdirs() failed: No such file or directory`

The remote path `/data/local/tmp/foo` got mangled by Git Bash's MSYS path conversion to `C:/Program Files/Git/data/local/tmp/foo`.

Fix: prefix every adb command with `MSYS_NO_PATHCONV=1`:

```bash
MSYS_NO_PATHCONV=1 adb push ./dumper /data/local/tmp/dumper
```

The toolkit scripts already do this. Use them via `./extract.sh`.

### `mksh` shell math returns wrong values for hex addresses > 32 bits

`$(( 0x72645d3000 / 4096 ))` returns `100` instead of `122,103,357`. Cause: `mksh`'s `$(( ))` is **32-bit signed** — silently truncates anything >2^31.

Fix: do address math in `awk` (uses doubles, fine up to 2^53) or in C. The toolkit does this.

### `Exit code 137` from a Bash tool call

The tool runner / permission system on the host killed the command. Most often happens when a command contains `pkill -9`, `rm -rf /...`, or other destructive-looking flags. Re-approve the prompt or split into smaller per-action commands.

---

## Device-side (Android shell)

### `/proc/modules` is unreadable

```
$ cat /proc/modules
cat: /proc/modules: Permission denied
```

Some Android builds restrict this to root. `su -c 'cat /proc/modules'` works.

### `cp /proc/modules /data/local/tmp/file` returns `Permission denied`

SELinux blocks the specific syscall pattern `read(/proc/modules) → write(/data/...)` from certain contexts. Workaround: route through `cat`:

```sh
cat /proc/modules > /data/local/tmp/file   # works
cp /proc/modules /data/local/tmp/file      # may fail
```

(Different syscall sequence; SELinux policies don't always match both.)

### `awk: calling undefined function strtonum`

Toybox awk on Android **does not have** GNU awk's `strtonum()`. Use a manual hex-to-decimal loop:

```awk
function h2d(h,    n,i,c,v,s) {
    s = 0; sub(/^0[xX]/, "", h); n = length(h);
    for (i = 1; i <= n; i++) {
        c = substr(h, i, 1);
        v = index("0123456789abcdef", tolower(c)) - 1;
        s = s*16 + v;
    }
    return s;
}
```

### `kprobe_events: Device or resource busy`

```
$ echo > /sys/kernel/tracing/kprobe_events
sh: write error: Device or resource busy
```

Truncating the kprobe_events file requires that no kprobes are currently active. On rooted Android devices, Xiaomi's `miuibpf` daemon often has a kprobe like `enter_fd_install_miuibpf_bcc_2845` already installed.

Fix: don't truncate; **append** with `>>`. To remove only your own kprobes:

```sh
echo '-:kprobes/your_probe_name' >> /sys/kernel/tracing/kprobe_events
```

The toolkit's dumper does this correctly.

### kprobe missing: `syscalls/sys_enter_*`

```
[*] enabling syscalls/sys_enter_init_module ... (missing)
```

This kernel was built without `CONFIG_FTRACE_SYSCALLS` for some events. The kprobe-by-symbol approach (`p:my_probe __arm64_sys_init_module ...`) doesn't depend on this and still works. The toolkit uses kprobes, not syscall trace events.

### `module/module_load` event missing

Some hardened kernels disable module-related tracepoints via lockdown. Check:

```
ls /sys/kernel/tracing/events/module/
```

If empty, you can still use the kprobe to catch `__arm64_sys_init_module`. The dumper doesn't require `module_load` — it was useful as a confirmation but not as a trigger.

### `ls /proc/kcore: No such file or directory`

Android kernels are built with `CONFIG_PROC_KCORE=n`. There's no way to get `/proc/kcore` short of building your own kernel. Plan accordingly — kernel-side memory extraction is off the table on stock devices.

### `cat /proc/sys/kernel/kptr_restrict` returns 2

`kallsyms` will return `0000000000000000` for every address even to root. Module-side enumeration relies on alternative paths (`/proc/devices`, kernel tracepoints).

---

## Binary-side (FT2.2.0 binaries)

### `刷入失败: Operation not permitted`

The binary tried `init_module(2)` and got `EPERM`. Causes:

- Not running as root (most common)
- SELinux denied the call from this context
- `/proc/sys/kernel/modules_disabled = 1`
- Something else in the kernel rejected — check `dmesg` for an audit line

### `已刷入驱动无需重复刷入` ("driver already loaded, no need to re-flash")

The binary saw `/dev/bing_rw` already exists (from a previous run) and short-circuited. **`init_module` is not called → kprobe never fires → no dump.**

Fix: reboot the device. The module is rootkit-hidden; you can't `rmmod` it, you can't `rm /dev/bing_rw` and load again (chrdev is still registered). Reboot is the only escape.

### Binary goes into burn loop, never produces output

Symptom: process at 100% CPU with the same `mremap`+`mmap`+`mprotect` triplet every iteration. Cause: anti-debug detected a tracer.

Triggers:
- `strace` (uses ptrace)
- `gdb`/`gdbserver` (uses ptrace)
- `frida-server` in **spawn mode** (briefly ptraces during injection — can be enough to flip the binary into anti-debug)
- Some Magisk modules that ptrace processes

Solution: run **without any tracer**. Use kprobes (kernel-side, no ptrace) for instrumentation.

### Binary stdout shows `telegram @nullnb6` but nothing else

- If running under root with no anti-debug and no `/dev/bing_rw`: this means stage-1 ran, but stage-2 / `init_module` didn't print anything yet. The binary may have crashed silently. Check `dmesg`.
- If running under root with `/dev/bing_rw` already present: expected behavior, plus a second line `已刷入驱动无需重复刷入`.

---

## Frida-specific

### `frida.NotSupportedError: bootstrapper crashed with signal 11`

Frida's bootstrapper SEGV's during injection into the target. This commonly happens with:

- Statically-linked targets (no ld.so to hook)
- Packed targets (executable memory regions are W^X-restricted)
- MTE/HWASan-enabled targets
- Anti-debug targets that mangle their own memory layout

The FT2.2.0 binaries hit all four. Frida is not the right tool here.

Workaround: use the C kprobe dumper (this toolkit). It doesn't inject anything into the target.

### Frida says "device not found" but `adb devices` works

Make sure `frida-server` is running on the device:

```sh
adb shell 'su -c "nohup /data/local/tmp/frida-server > /data/local/tmp/frida.log 2>&1 &"'
```

And the host can talk to it:

```bash
python -c "import frida; print(frida.get_usb_device())"
```

---

## Toolkit-specific

### `extract.sh` fails at `dumper compile failed`

The host's NDK isn't on `$NDK_PATH` or the version is too old. Either:

- Set `NDK_PATH` to your NDK root (e.g. `C:\Users\you\AppData\Local\Android\Sdk\ndk\30.0.14904198`)
- Or use the prebuilt: `./extract.sh --use-prebuilt path/to/X.sh`

### `dumper` fires but produces no `.ko`

Symptoms: dumper logs `[*] kprobe installed; reading trace_pipe...` but never logs `[+] event:`.

Most likely cause: `/dev/bing_rw` was already loaded. The binary took the short path. Reboot and rerun.

If it still doesn't fire after reboot, check that the binary is actually being run as root:

```sh
adb shell 'su -c "ls -la /data/local/tmp/X.X.elf"'
adb shell 'su -c "/data/local/tmp/X.X.elf"'
```

If the second command outputs `刷入失败`, the binary isn't getting root somehow (Magisk denying?). Check Magisk's "Su Settings".

### `dumper` exits with `dumped=0` and `read 0 / 28728 bytes`

The kprobe fired and we got the umod address, but `lseek` + `read` of `/proc/<pid>/mem` returned 0 bytes. Possible causes:

- The MTE tag wasn't stripped (kernel rejected the address as non-canonical). The toolkit's dumper masks `& 0x00FFFFFFFFFFFFFF` — verify no edits broke this.
- The binary already exited before `read()` ran (we lost the race). Try again — speed varies with system load.

### Output `.ko` file exists but is all zeros

Dumper raced and the process was already in the cleanup phase. The buffer was munmap'd. Reboot and rerun.

### `IDA can't find any sections` when opening the `.ko`

Make sure you opened it as **Elf64 for ARM (ARM64) [elf64.dll]** in IDA's loader prompt. The default may try a different loader. Also confirm `e_shnum != 0` (the toolkit's output should have 31 sections).

If `e_shnum == 0`, you got a stripped or memory-image dump rather than a clean on-disk dump — re-extract with this toolkit.

---

## Verification commands

After extracting, sanity-check the output:

```bash
# On host
file output/bing_rw.ko
# expected: ELF 64-bit LSB relocatable, ARM aarch64, ... not stripped

# Quick header check (Python)
python -c "
import struct
d = open('output/bing_rw.ko','rb').read()
e_type    = struct.unpack_from('<H', d, 16)[0]
e_machine = struct.unpack_from('<H', d, 18)[0]
e_shnum   = struct.unpack_from('<H', d, 60)[0]
print(f'e_type=0x{e_type:x} (expect 0x1=ET_REL)')
print(f'e_machine=0x{e_machine:x} (expect 0xb7=AARCH64)')
print(f'e_shnum={e_shnum} (expect >0, not stripped)')
"

# Check vermagic
strings output/bing_rw.ko | grep vermagic=
# expected: vermagic=5.10.<something>-android12-...  modversions  aarch64
```

If all three checks pass, the file is ready for IDA.
