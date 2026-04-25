# The Hunt for `bing_rw.ko` — A Session Story

> *How a strange `.sh` file became a rootkit-hidden kernel module — and how we extracted it.*

This is the analyst's-perspective narrative of every step we took, **including every dead end, mistake, surprise, and recovery**. The technical encyclopedia lives in [`02-HOW-IT-WORKS.md`](02-HOW-IT-WORKS.md). This file is the story.

---

## Act 0 — The artifact

A folder named `FT2.2.0` arrived. 35 shell scripts, each named after a Linux kernel version: `4.14.117.sh`, `4.19.81.sh`, `5.10.sh`, `6.1.sh`, ...

The first line of every script:
```
#Telegram @nullnb6
```

The second line is one giant single-line shell stub. Then from line 3 onward, the file is binary garbage — gzip-shaped.

The naming pattern — one `.sh` per kernel version — is suspicious. That's exactly how memory-research / game-cheat tools are distributed when they ship a **per-kernel `.ko`**. Our hypothesis going in: each `.sh` is a self-extracting wrapper for one kernel module.

The user's goal: extract the executable inside, drop it in IDA Pro.

---

## Act 1 — Unwrapping the stub

The shell stub on line 2 (formatted for reading):

```sh
mkdir -p /data/local/tmp/
random_folder=/data/local/tmp/
wenjmz="driver:$(date +%s | sha256sum | base64 | head -c 32)"
sed -n "$((LINENO+1)),$ p" < "$0" | gzip -cd > "${random_folder}/$wenjmz"
zhixilp="$random_folder/$wenjmz"
chmod 700 "$zhixilp"
(rm -fr "$zhixilp") &
"$zhixilp" ${1+"$@"}
res=$?
exit $res
```

Two things stood out:

- The variable names `wenjmz` and `zhixilp` are pinyin shorthand — `wén jiàn míng zì` (file name) and `zhí xíng lù jìng` (execute path).
- `(rm -fr "$zhixilp") &` runs *concurrently* with the binary. The file is unlinked while it's still executing — the OS keeps the open `fd` valid until exit. **Anti-forensic**: when the script exits, no on-disk trace remains.

To pull the payload offline:

```bash
tail -n +3 5.10.sh | gunzip > 5.10.elf
```

For all 35:
```
ELF 64-bit LSB shared object, ARM aarch64, ... statically linked, no section header
```

`e_type = 3` (ET_DYN, i.e. PIE). `e_machine = 0xB7` (AARCH64). 28-62 KB each.

**Surprise #1: this isn't a kernel module.** Kernel modules are `ET_REL`. This is a userland PIE.

We grepped for the obvious markers — `init_module`, `vermagic`, `.modinfo` — nothing. Searched for embedded `\x7fELF` magic at any non-zero offset — nothing. No gzip / xz / lz4 / zstd blobs inside either.

So... where's the `.ko`?

---

## Act 2 — Static analysis is dead, long live dynamic analysis

The user's device showed up as `2312DRA50G`, kernel `5.10.236-android12-9`, Android 16, MagiskSU available. SELinux Enforcing. `/proc/sys/kernel/modules_disabled` was permission-denied to the shell user but accessible to root — module loading was *not* disabled.

We picked `5.10.sh` because the device runs 5.10.236 and the binary names suggest the generic 5.10 build matches.

First plan: run the binary as the unprivileged `shell` user under `strace`. SELinux + non-root would reject any privileged operation, so the worst case is "the binary fails politely". We get a syscall trace either way.

```bash
adb shell '
  cp /proc/modules /data/local/tmp/mods_before.txt
  cd /data/local/tmp
  timeout 5 strace -f -y -s 96 -o ft_trace.log ./ft_test.elf
  cp /proc/modules /data/local/tmp/mods_after.txt
'
```

Result: **process timed out at 5 s** — it kept running. No stdout. No stderr. The trace had ~7800 syscalls.

But the deciding signals all came back negative:

- `init_module` / `finit_module` / `memfd_create` / `delete_module`: **0 calls**
- `/dev/<driver>` opens, `/proc/kallsyms` reads, kernel-style ioctls: **0**
- `/proc/modules` diff before vs. after: **identical**

We were ready to declare "this binary doesn't load any kernel module".

Then we looked at the *tail* of the strace.

```
mremap(0x7e8092b000, 4096, 4096, MREMAP_MAYMOVE|MREMAP_FIXED, 0x7dba812000)
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
mprotect(0x7dba812000, 4096, PROT_READ)
... repeat for thousands of iterations ...
```

That's an **anti-debug evasion loop**. The binary detected `strace` (almost certainly via `/proc/self/status` reading `TracerPid`) and chose to spin a busy-wait pattern instead of doing its real work. So our "no kernel module" finding only proved "no kernel module *under strace*". Not the same thing.

**Lesson learned the hard way:** an anti-debugged binary's strace is a measurement of the anti-debug branch, not of the program.

---

## Act 3 — The Chinese error message

Without strace, just a plain root-less run:

```bash
adb shell '
  cd /data/local/tmp
  ./ft_test.elf > stdout 2> stderr
'
```

Returns in ~200 ms. Stdout: `telegram @nullnb6`. Stderr:

```
刷入失败: Operation not permitted
```

`刷入失败` is *shuā rù shī bài* — "flash-in failed". In the Chinese rooted-Android scene, **`刷入` is the colloquial verb for `insmod`** — loading a kernel module. The literal translation is "swipe in", as in "swipe data into the kernel". You see it everywhere in Magisk module instructions.

Suddenly the per-kernel `.sh` naming made sense. The error was the binary trying to do **its** thing — which was loading a kernel module — and being told no.

We had been wrong about (B) being ruled out. It was just hidden behind anti-debug. **The hypothesis is back.**

---

## Act 4 — Memory dumping the unpacked stub

The strace anti-debug burn loop wasn't a problem — it was a feature. With the binary stuck in a tight `mremap`/`mmap`/`mprotect` loop, we had an arbitrarily long-lived target whose memory was already unpacked.

We wrote a small dumper in `mksh` that:
1. Reads `/proc/<pid>/maps` of the strace'd binary
2. Finds anonymous executable regions (`r-xp` with empty `pathname` or `[anon:*]` label)
3. For each, dumps the surrounding 16 MiB neighborhood out of `/proc/<pid>/mem`

We hit our first scripting wall: `mksh`'s `$((..))` arithmetic is **32-bit signed**. We were computing things like `0x72645d3000 / 4096`. The arithmetic silently truncated to the lower 32 bits and gave us a "block 100" neighborhood that didn't match anything. After 30 minutes of confused debugging, the fix was to do the math in `awk` (which uses double-precision floats — fine up to 2^53):

```sh
page_skip=$(awk -v h="$start_hex" 'BEGIN{
  s=0; n=length(h);
  for (i=1;i<=n;i++) {
    c = substr(h, i, 1);
    v = index("0123456789abcdef", tolower(c)) - 1;
    s = s*16 + v;
  }
  print int(s / 4096);
}')
```

With that fixed, eight regions came out:

| Offset | Size | Perms | Content |
|---|---|---|---|
| `005_75686d2000` | **53 KiB** | `r-xp` | **Unpacked main code** (the actual program — an aarch64 PIE) |
| `004_75686c5000` | 53 KiB | `rw-p` | `[anon:.bss]` |
| `007_75686e6000` | 160 KiB | `rw-p` | Decrypted data area |
| ... | ... | ... | ... |

Inside region `007` we found two clear strings:

```
/dev/bing_rw
telegram @nullnb6
```

`/dev/bing_rw` is the device node the userland binary expects to talk to. Combined with the per-kernel naming, it looked like: **the FT2.2.0 distribution only ships the userland client. The kernel module that owns `/dev/bing_rw` is installed separately.**

We checked the device:
```
$ ls /dev/bing_rw
ls: /dev/bing_rw: No such file or directory
```

Doesn't exist. So the binary's "刷入失败" was the binary trying to `open("/dev/bing_rw")`, getting `ENOENT`, and giving up.

That seemed to wrap things up neatly. We wrote a final summary saying:

> *"This is `(C)` — userland-only client of an externally-installed kernel driver. The `.ko` is not in this package. The kernel-version naming is for per-kernel struct offsets baked into the userland tool."*

The user pushed back. Hard.

> *"How does the channel owner put it as a lib file inside a shell file to run the live stream? Is it logical to think this is nothing?"*

Reading our own analysis again: every single piece of evidence had been collected with the binary running **under ptrace** — i.e. in its anti-debug branch. We had never observed what happens when it runs normally as root. We were drawing conclusions from a controlled-experiment that explicitly avoided the privileged code path.

We had to actually run it.

---

## Act 5 — The deciding test, with kernel-side eyes

The plan needed to:
- Run as **root** so the privileged path can succeed
- Run **without ptrace** so anti-debug doesn't fire
- Observe with **kernel-side instrumentation** (which the binary can't detect)
- Be ready to undo whatever the binary does, in case the loaded `.ko` doesn't match this exact kernel sub-version and panics

The kernel-side instrumentation is **tracefs `module/module_load`** — a kernel tracepoint that fires whenever any module enters the kernel, regardless of whether it tries to hide itself afterward.

```bash
echo 1 > /sys/kernel/tracing/events/module/module_load/enable
echo 1 > /sys/kernel/tracing/tracing_on

# pre-snapshot
cp /proc/modules ./mods.before
ls -la /dev/   > ./dev.before
dmesg          > ./dmesg.before

# run as root, no tracer
./ft_test.elf > out 2> err

# post-snapshot
cp /proc/modules ./mods.after
ls -la /dev/   > ./dev.after
dmesg | tail   > ./dmesg.delta
cat /sys/kernel/tracing/trace > ./trace.txt
```

Result: binary exited in 1 second. Stdout:

```
telegram @nullnb6
刷入成功
```

`刷入成功` = "load successful". Opposite of what we'd seen before.

But: `/proc/modules` diff showed **only refcount changes** to `qcom_dma_heaps`, `qrtr`, `msm_kgsl` — nothing new added. No `bing_rw` entry. We almost concluded it was using some non-module mechanism.

Then we read `trace.txt`:

```
ft_test.elf-27279   [005] ....   441.774195: module_load: bing_rw O
```

There it was. The kernel's own tracepoint fired and said **`bing_rw` was loaded**. The `O` flag means "out-of-tree module" — the standard mark for a third-party module not in the kernel tree.

And the `dev.diff`:

```diff
+crw------- 1 root root 458, 0 2026-04-25 19:09 bing_rw
```

A new character device node, major **458**, name `bing_rw`. Created during the binary's run.

So the module loads, creates its character device, **and then promptly removes itself from `/proc/modules`**. A working **rootkit hide**: the module is alive in the kernel, its `/dev/bing_rw` interface is functional, but enumerated views show nothing.

We confirmed this by checking `/sys/module/bing_rw/`:
```
$ ls /sys/module/bing_rw/
ls: No such file or directory
```

Not even sysfs has it. `lsmod` doesn't list it. `rmmod bing_rw` returns `No such file or directory`. The module is, for all enumeration purposes, gone — but `/proc/devices` line `458 bing_rw` is right there in plain sight.

This is **method (B)**: the binary carries the `.ko` encrypted internally, decrypts it in memory, and calls `init_module(2)` with a buffer pointer. The hide-from-modules-list trick is performed by the module's own `__init` function, the moment it's running in kernel context.

---

## Act 6 — The hunt for the buffer

Now we knew **what** happens, but we needed the bytes. Kernel-side extraction options were eliminated one by one:

| Approach | Status |
|---|---|
| `/proc/kcore` to read kernel memory by address | Not present — Android kernel built `CONFIG_PROC_KCORE=n` |
| `/proc/kallsyms` to find the loaded `bing_rw` text address | `kptr_restrict=2`, all addresses zeroed even for root |
| `/sys/module/bing_rw/sections/` for kernel-side load addresses | Doesn't exist (rootkit-hidden) |
| `bpftrace` / `drgn` / `crash` | None on the device |

So kernel-side extraction was off the table. We had to catch the **userspace** buffer that gets passed to `init_module`.

A kernel **kprobe** can fire on `__arm64_sys_init_module` and dump the user buffer. Crucially, kprobes are kernel-side — they don't show up in `/proc/<pid>/status`'s `TracerPid`, so the binary's anti-debug doesn't see them.

The kprobe on aarch64 needs to dereference `pt_regs` to reach the syscall args:

```
echo 'p:ft_init_x __arm64_sys_init_module umod=+0(%x0):x64 len=+8(%x0):x64' \
  > /sys/kernel/tracing/kprobe_events
```

`%x0` is `regs` (a `struct pt_regs *`). `+0(%x0)` is `regs->regs[0]` (the first syscall arg = `umod`). `+8(%x0)` is `regs->regs[1]` (= `len`).

First firing was a wake-up call:

```
ft_init_x: umod=0xb4000076ffe73320 len=0x7038 uargs=0x70fc0baeb0
```

Two pieces of immediate intel:

- `len = 0x7038 = 28728 bytes`. So the `.ko` is exactly 28 KB.
- `umod = 0xb40000...`. That `0xb4` is **not** part of the address — it's an **MTE (Memory Tagging Extension) tag** in the top byte. aarch64 with TBI (Top Byte Ignore) lets the CPU treat the high byte as metadata. `0xb4` is the signature of a **scudo allocator** (libc malloc) chunk — meaning the binary called `malloc()` for its decrypted `.ko` buffer.

The actual address is the lower 56 bits: `0x000000076ffe73320`. We need to mask the top byte before feeding it to `/proc/<pid>/mem`.

---

## Act 7 — The race we kept losing

So the plan was clear: have a daemon read `/sys/kernel/tracing/trace_pipe`; when an `ft_init_x` event fires, parse the address, open `/proc/<pid>/mem`, `lseek` to `umod & 0x00FFFFFFFFFFFFFF`, read `len` bytes, write to disk.

The daemon was a `mksh` script. The race was very tight:

| Step | Time |
|---|---|
| Binary calls `init_module(buf, len, args)` | T = 0 |
| Kernel kprobe fires, writes line to `trace_pipe` ring buffer | T + ~µs |
| Shell daemon's `read` returns the line | T + ~10 ms |
| Shell daemon parses with `awk` (multiple forks) | T + ~30 ms |
| Shell daemon `dd`s `/proc/<pid>/mem` | T + ~50 ms |
| **Binary returns from `init_module`, prints success, exits** | T + ~30 ms |

We were dd'ing **after** the process exited. `dd` reported `/proc/<pid>/mem: No such file or directory`. Every. Single. Time.

We tried:

1. **`SIGSTOP` immediately on event.** Signal queues, delivered at next syscall return — by then the `init_module` syscall had already returned and the binary had already moved on, often to its `exit_group` syscall. Race lost.
2. **Pre-launch the binary frozen, only `SIGCONT` after the daemon is reading.** Eliminates the daemon-startup race. Doesn't help the actual reaction race.
3. **Tight-loop poll `/proc/<pid>/syscall`** for syscall number 105. Failed because that file shows `running` while the task is on-CPU and only shows the syscall number while sleeping in syscall — and `init_module` is mostly CPU-bound (no sleeping). We polled 4000 times in 0.5 s and never once observed `105`.
4. **Continuous parallel snapshotter** dumping every readable anon RW region every 50 ms. Caught nothing — even with all filters relaxed, the `.ko` page was either sparse or written between snapshots. The 32-bit `mksh` arithmetic struck again here too, then `awk` overhead ate our budget.
5. **`SIGSTOP`/`SIGCONT` ping-pong** to slow the binary down. Each `SIGCONT` *cancels* a pending `SIGSTOP`, so we were undoing our own work. After fixing that, the binary made progress so slowly that `init_module`'s memory was never resident at the moments we sampled.
6. **Frida** in spawn mode (`device.spawn`, `device.attach`, `device.resume`). The Frida bootstrapper SEGV'd before our hook even loaded — a known issue with statically-linked + packed targets on MTE/HWASAN-enabled kernels.
7. **Frida** in attach mode against a SIGSTOP-frozen binary. Same SEGV.

We had spent serious effort on shell-only solutions and Frida. None of them could close a 30 ms reaction window with a dynamically-allocated `umod` address.

---

## Act 8 — NDK to the rescue

Time to write a real program. The reaction-time budget was incompatible with shell forks. C with the Android NDK was the answer: a single statically-linked binary, one `read()` on `trace_pipe`, one `open()` on `/proc/<pid>/mem`, one `lseek`, one `read`, one `write`. All native syscalls, no fork, no awk.

Approximate cost in C:

| Step | Time |
|---|---|
| `read(/sys/kernel/tracing/trace_pipe)` | ~1 µs |
| `sscanf` of pid, umod, len | ~1 µs |
| `open("/proc/<pid>/mem")` | ~10 µs |
| `lseek(umod & 0x00FF...)` | ~1 µs |
| `read(28728 bytes)` | ~50 µs |
| `write(out_file)` | ~50 µs |

Total: ~120 µs. Versus a 30 ms window. That's **250× more headroom than we need**.

The dumper source is in `src/dumper.c` — about 130 lines. Build is one command:

```bash
$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android33-clang.cmd \
  src/dumper.c -O2 -static -o prebuilt/dumper
```

We pushed it, ran it, ran the binary. The dumper logged:

```
[*] kprobe installed; reading trace_pipe...
[+] event:  ft_test.elf-16694 [007] d..1 92.114483: ft_init_x: umod=0xb4000072a6e51010 len=0x7038
[+] pid=16694 umod=0xb4000072a6e51010 len=28728
[+] read 28728 / 28728 bytes
[+] wrote 28728 bytes -> /data/local/tmp/dumped_bing_rw.ko
[+] ELF MAGIC PRESENT — looks like a .ko!
```

We pulled the file:

```
$ file dumped_bing_rw.ko
dumped_bing_rw.ko: ELF 64-bit LSB relocatable, ARM aarch64, version 1 (SYSV),
                   BuildID[sha1]=e8c8459cd0f917a08e6b04c663871d409f62bd05,
                   not stripped
```

A clean `ET_REL` aarch64 kernel module. 31 sections. Symbols intact. `BuildID` present.

Strings inside:
```
.modinfo
vermagic=5.10.223-android12-9-00008-g4c7b897f395f-dirty SMP preempt mod_unload modversions aarch64
name=bing_rw
```

The `.ko` was built against kernel 5.10.223; our device runs 5.10.236 — same major.minor, different patch. The fact that `init_module` succeeded anyway is because the `.ko` is built with `modversions`, which uses CRCs of exported-symbol prototypes rather than version-string equality.

---

## Act 9 — Why the file doesn't need a header fix

The user's `android-memdump-elf` tool exists for a real and important problem: when you dump a *running* `.so`/`.ko` from `/proc/<pid>/mem`, the loader has already mapped the segments to virtual addresses, the section headers are gone or rewritten, and you have to reconstruct on-disk file offsets.

But our case is different. We caught the buffer **before** `init_module` consumed it. The buffer is the **literal on-disk form** of the `.ko` — exactly the bytes the kernel parses with `load_module()`. Section table intact, `e_type = ET_REL = 1`, file offsets valid, `.modinfo` section right where it should be.

`file` confirms: `relocatable, not stripped`. IDA opens it without complaint.

---

## What we learned

Eight things, in order of generality:

1. **Anti-debug invalidates ptrace-based tracing.** A clean strace of an anti-debugged binary is a measurement of its evasion branch, not the program. If you don't see the syscalls you'd expect, suspect anti-debug before suspecting absence.
2. **Shell-only racing has a hard floor of ~10 ms latency.** `cat`/`awk`/`fork`/`dd` overhead. Anything with sub-100 ms windows needs a compiled native tool.
3. **`mksh`'s `$(( ))` is 32-bit.** Always do address math in `awk` (doubles → 53 bits) or in C. Especially insidious because failure is silent truncation, not an error.
4. **Tracefs kprobes are invisible to ptrace anti-debug.** They're a kernel-side mechanism. `/proc/<pid>/status:TracerPid` doesn't change.
5. **`pt_regs` deref syntax is your friend.** On aarch64 with `__arm64_sys_*` syscall wrappers, `%x0` is `regs`, not the first syscall arg. Use `+0(%x0)`, `+8(%x0)`, `+16(%x0)`.
6. **MTE / TBI tags on Android pointers must be stripped before `lseek`.** Mask with `0x00FFFFFFFFFFFFFF`. The kernel's `untagged_addr()` helper does this internally for some paths, but not all.
7. **Module rootkits hide from `/proc/modules` and `/sys/module/` but not from `/proc/devices` or kernel tracepoints.** `module_load` tracepoint fires before the module's `__init` runs, so the hide hasn't happened yet.
8. **A kernel `init_module` buffer caught at the syscall is the on-disk form.** No header reconstruction needed. Hand it to IDA directly.

---

## Reproducing this with the toolkit

```bash
./extract.sh ../FT2.2.0/5.10.sh
```

That's it. The toolkit script does everything in this story automatically — unpacking, reboot, kprobe install, binary launch, dump, pull. See [`02-HOW-IT-WORKS.md`](02-HOW-IT-WORKS.md) for what each step does, line by line.
