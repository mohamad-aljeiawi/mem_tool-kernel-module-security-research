# How It Works

Deep technical reference for every moving part. If you want the *story*, read [`01-SESSION-STORY.md`](01-SESSION-STORY.md). If you want the *diagrams*, read [`03-DIAGRAMS.md`](03-DIAGRAMS.md). This file is the encyclopedia.

---

## Contents

1. [The `.sh` self-extractor anatomy](#the-sh-self-extractor-anatomy)
2. [What's actually inside](#whats-actually-inside)
3. [The userland binary's behavior](#the-userland-binarys-behavior)
4. [How a kernel module hides itself](#how-a-kernel-module-hides-itself)
5. [Why kernel-side extraction was off the table](#why-kernel-side-extraction-was-off-the-table)
6. [Why kprobe is the right tool](#why-kprobe-is-the-right-tool)
7. [The kprobe definition, byte-by-byte](#the-kprobe-definition-byte-by-byte)
8. [Reading user memory of another process](#reading-user-memory-of-another-process)
9. [MTE / TBI top-byte stripping](#mte--tbi-top-byte-stripping)
10. [Why C and not shell](#why-c-and-not-shell)
11. [Why reboot](#why-reboot)
12. [Why `vermagic` mismatch was OK](#why-vermagic-mismatch-was-ok)
13. [Why no header fix is needed](#why-no-header-fix-is-needed)

---

## The `.sh` self-extractor anatomy

Each `FT2.2.0/X.X.sh` file has the structure:

```
Line 1:    #Telegram @nullnb6
Line 2:    if [ ! -d "/data/local/tmp/" ]; then mkdir -p ...; fi; ...
           (one giant single-line shell script)
Line 3+:   <gzip-compressed binary blob>
```

The line-2 stub does:

```sh
random_folder="/data/local/tmp/"
wenjmz="driver:$(date +%s | sha256sum | base64 | head -c 32)"
sed -n "$((LINENO+1)),$ p" < "$0" | gzip -cd > "${random_folder}/$wenjmz"
chmod 700 "$random_folder/$wenjmz"
(rm -fr "$random_folder/$wenjmz") &
"$random_folder/$wenjmz" ${1+"$@"}
exit $?
```

Important details:

- `wenjmz` is pinyin shorthand for *wén jiàn míng zì* (file name). `zhixilp` = *zhí xíng lù jìng* (execute path).
- The randomized name `driver:<sha256-of-time-base64-trunc32>` makes static IOCs hard.
- `sed -n "$((LINENO+1)),$ p"` prints lines from "this script line + 1" to EOF (`$` in sed line addresses = "last line"). This is how the stub finds the boundary between code and data.
- `(rm -fr "$zhixilp") &` runs *concurrently with* the binary. Linux holds the open file across the `unlink`. By the time the binary exits, the file has already been removed from the directory. **Forensic artifacts are minimized.**
- `${1+"$@"}` passes any args from the `.sh` invocation to the binary.

To unpack offline (what `tools/unpack-sh.sh` does):

```bash
tail -n +3 X.X.sh | gunzip > X.X.elf
```

---

## What's actually inside

For all 35 `.sh` files in FT2.2.0, the payload is the same shape:

```
ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV),
for Android 21, built by NDK r29 (14206865),
BuildID[sha1]=...,
statically linked, no section header
```

Things to notice:

- **`ET_DYN`** (`shared object`) but with a real `e_entry`, no `PT_INTERP`, no dynamic dependencies — it's a **PIE executable**, not a shared library.
- **Statically linked** — no `libc.so` to LD_PRELOAD against.
- **No section headers** — section table stripped. Only program headers remain. IDA can still load it but with reduced auto-analysis.
- **NDK r29 / Android 21** — built recently against modern NDK. `BuildID` differs per script (each is a separately-built binary).

Each binary is also **packed**:

- `mmap(NULL, ..., PROT_READ|PROT_WRITE, MAP_ANONYMOUS)` immediately after `execve`
- `mprotect(..., PROT_READ|PROT_EXEC)` after writing decrypted bytes
- All readable strings except `Fuck_Tencent`, `PROT_EXEC|PROT_WRITE failed.`, and a few NDK build tags are **garbled fragments** at rest — the rest are decrypted at runtime
- A long `readlinkat("/proc/self/fd/<linker-related>")` walk over every `/apex/com.android.*/lib64` directory — the unpacker is trying to dlopen system libraries by exact path

Strings recovered from the unpacked stage-1 in memory (region `r-xp` at `0x75686d2000` in one run):

```
__libc_init  __cxa_atexit  __stack_chk_fail  __errno  malloc
__strlen_chk  perror  __open_2
libc.so  liblog.so  libandroid.so  libEGL.so  libGLESv3.so  libm.so  libdl.so
```

So this is an aarch64 NDK app that uses `libEGL`, `libGLESv3`, `liblog`, `libandroid` — i.e. **a real graphics/overlay app**. Combined with the libraries it `dlopen`s after stage-1 unpacking (`libhwui`, `libgui`, `libvulkan`, `libbinder`, `libsfplugin_ccodec`, `libMiVideoFilter`...), this is a **screen-overlay / aim-helper / ESP** style mobile-game tool.

---

## The userland binary's behavior

Empirically, when run as **root** with `bing_rw` not loaded:

```
1. exec, decrypt stage-1 unpacker            (~10 ms)
2. dlopen system libraries                    (~50 ms)
3. decrypt stage-2 + the embedded .ko bytes   (~50 ms)
4. malloc(28728) — buffer for the .ko         (instant)
5. fill the buffer with decrypted .ko bytes   (~5 ms)
6. init_module(buf, 28728, "")                (kernel: ~50 ms)
7. printf("刷入成功\n")                        (instant)
8. exit                                        (instant)
```

Total wall time ~150-300 ms.

When run as **shell** (no root):
- Steps 1-5 happen
- Step 6 fails with `EPERM`
- The binary prints `刷入失败: Operation not permitted` (write to stderr)
- exits

When run as **root with `/dev/bing_rw` already present**:
- Steps 1-5 happen
- Step 6 is **skipped** — the binary does `stat("/dev/bing_rw")` and if the device exists, prints `已刷入驱动无需重复刷入` ("driver already loaded, no need to re-flash") and exits

This last case is why we **must reboot** before each capture: once `bing_rw` is loaded, the binary takes the fast path that doesn't call `init_module`, and the kprobe never fires.

When run **under any ptracer** (strace, gdb, Frida-spawn, ...):
- After stage-1 unpacks, the binary reads `/proc/self/status` and checks `TracerPid:`. If non-zero, it diverges into an anti-debug burn loop:
  ```c
  for (;;) {
      void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
      mprotect(p, 4096, PROT_READ);
      mremap(p, 4096, 4096, MREMAP_MAYMOVE|MREMAP_FIXED, fixed_addr);
      // never break out
  }
  ```
- This is a *live*, page-table-thrashing busy loop, not a `pause()` or `sleep()`. The process consumes 100% of one core forever. None of the privileged code path runs.

---

## How a kernel module hides itself

When the kernel processes `init_module(buf, len, args)`:

1. `copy_from_user()` — copies the user buffer into a kernel-side `kvmalloc` buffer.
2. `load_module()` — parses the ELF, allocates module memory in vmalloc area, copies sections, resolves symbols, applies relocations, runs `mod->init()`.
3. The module's `__init` function runs in kernel context with full privileges. **Anything is possible here.**

The standard hide-from-`/proc/modules` recipe (which `bing_rw` uses):

```c
// somewhere in __init:
list_del_init(&THIS_MODULE->list);          // unlink from struct module list
kobject_del(&THIS_MODULE->mkobj.kobj);      // remove from sysfs (/sys/module/)
```

After these two lines:

| View | Effect |
|---|---|
| `/proc/modules` (= iterates `modules` linked list) | **Hidden** |
| `lsmod` (reads `/proc/modules`) | **Hidden** |
| `/sys/module/<name>/` directory tree | **Gone** |
| `rmmod <name>` (uses `find_module()` which walks the same list) | Returns `ENOENT` |

What's **NOT** hidden:

- `/proc/devices` — driver registers a chrdev with `register_chrdev(458, "bing_rw", &fops)`. This goes into a *separate* table (`chrdevs[]`) that has no equivalent unhook trick. **`bing_rw` shows up there in plain text.**
- `/dev/bing_rw` — the device node is created by `device_create()`, lives in tmpfs `/dev/`. Visible.
- The module's vmalloc'd code/data is still in the kernel — it has to be, for the chrdev callbacks to keep working.
- Kernel tracepoints `module:module_load` and `module:module_free` fire **before** the module's init runs (during `load_module`'s setup phase). The hide trick only works *after* init. So tracepoints catch the load.

This means even though static enumeration shows nothing, **kernel-side instrumentation (tracefs, kprobes) sees everything**.

---

## Why kernel-side extraction was off the table

Once `bing_rw.ko` is loaded into kernel memory, you'd think you could just dump it from there. We can't, because:

1. **`/proc/kcore`** — the standard interface for reading kernel memory by virtual address — **does not exist** on Android. Kernel built with `CONFIG_PROC_KCORE=n`. (Verified by `ls /proc/kcore: No such file or directory`.)
2. **`/proc/kallsyms`** — would let us look up the load address of `bing_rw`'s `.text` — has `kptr_restrict=2`, so all addresses come back as `0000000000000000` even for root.
3. **`/sys/module/bing_rw/sections/`** — would expose the load address of every section — does not exist (rootkit hidden).
4. **`bpftrace` / `drgn` / `crash`** — kernel-introspection tools that could work around 1-3 — none are present on this device.

Given all four are dead ends, the only remaining attack surface is the **userspace buffer** that's about to be passed to `init_module`. We have to catch it in flight.

---

## Why kprobe is the right tool

A kprobe is a kernel breakpoint installed via the `kprobe_events` interface in `/sys/kernel/tracing/`. When the targeted kernel function is entered, the kprobe handler runs synchronously, can record arbitrary register/memory values into the trace ring buffer, and the function continues normally afterward.

Key properties:

| Property | Detail |
|---|---|
| **Invisible to ptrace anti-debug** | Kprobes are kernel-side. `/proc/<pid>/status:TracerPid` doesn't change. The probed program has no way to detect it (short of measuring its own execution latency). |
| **Synchronous** | The probe fires while the target task is still in the kernel's syscall handler, before any return-to-user. The user buffer pointed to by `umod` is guaranteed to still be mapped at this moment. |
| **Captures register state** | We get `pt_regs->regs[0..2]` which are the syscall args. |
| **Standard Android kernels expose this** | `/sys/kernel/tracing/kprobe_events` is writable for root with `CAP_SYS_ADMIN` on most rooted Androids, including the Magisk-rooted device used here. |

The probe target on aarch64 is `__arm64_sys_init_module` — the syscall wrapper generated by `SYSCALL_DEFINE3(init_module, ...)` in the kernel.

---

## The kprobe definition, byte-by-byte

```
p:ft_init_x __arm64_sys_init_module umod=+0(%x0):x64 len=+8(%x0):x64
```

| Token | Meaning |
|---|---|
| `p:` | Probe type — `p` = entry probe (fires on function entry) |
| `ft_init_x` | Our chosen probe name. Will appear at `/sys/kernel/tracing/events/kprobes/ft_init_x/` |
| `__arm64_sys_init_module` | Target symbol — the aarch64 syscall wrapper for `init_module(2)` |
| `umod=+0(%x0):x64` | Argument extraction: take 64-bit value at offset 0 from the address in register x0, label it `umod`, format as hex |
| `len=+8(%x0):x64` | Same, offset 8, label `len` |

Why `+0(%x0)` instead of just `%x0`?

On older kernels (pre-4.17), syscall handlers had natural arguments: `init_module(void __user *umod, unsigned long len, const char __user *uargs)` — `umod` would be in x0, `len` in x1, `uargs` in x2.

Modern kernels generate **wrappers** via `SYSCALL_DEFINE3` that take a single argument:

```c
asmlinkage long __arm64_sys_init_module(const struct pt_regs *regs);
```

So **x0 is `regs`** (a `pt_regs*`), not the user's `umod`. To get the real syscall args, we have to dereference `regs`:

```c
struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            u64 regs[31];        // <- regs[0]@offset 0, regs[1]@offset 8, regs[2]@offset 16, ...
            u64 sp;
            u64 pc;
            u64 pstate;
        };
    };
};
```

So `+0(%x0)` is `regs->regs[0]` = `umod` (user pointer), `+8(%x0)` is `regs->regs[1]` = `len`, `+16(%x0)` is `regs->regs[2]` = `uargs`.

The `:x64` suffix tells tracefs to format the captured value as 64-bit hex. (Default would be decimal — when we used `:u64` early on, the `len` came out as `28728` instead of `0x7038`, which our shell-based parser didn't recognize. C parser handles either, so it's no longer critical, but using `:x64` consistently makes the trace_pipe lines easier to read.)

---

## Reading user memory of another process

`/proc/<pid>/mem` is a per-process pseudo-file that exposes the target's full virtual address space. Read with `lseek(fd, virt_addr, SEEK_SET)` followed by `read(fd, buf, size)`.

Required permission: either be the same UID as the target, or have `CAP_SYS_PTRACE`. Root has both. (SELinux can additionally restrict; under `magisk:s0` context this works.)

Behavior at unmapped addresses: `read()` returns `0` bytes (treated as EOF). For sparse / lazily-zero-filled anon pages, the same — until the page is *actually written*, the kernel doesn't have backing for it and returns 0 from `mem` reads. This caused some of our shell-based attempts to come back empty even when the maps showed a region was rw-p anonymous.

By the time the binary is **inside `init_module`**:
- The kernel has done `copy_from_user(kbuf, umod, len)` already, which means it touched every page of the buffer
- This is significant: `copy_from_user` is what *forces* the demand-zero pages to be backed (read-fault them in). After it runs, the pages have real backing storage and `/proc/<pid>/mem` reads return the actual contents.

So the time window when we can successfully dump is:

```
[start of copy_from_user inside init_module] ... [end of init_module syscall + binary exit]
```

That's still only ~50-100 ms wide. Hence the C dumper's speed mattering.

---

## MTE / TBI top-byte stripping

Android user pointers on aarch64 with **TBI (Top Byte Ignore)** enabled have arbitrary bytes in bits `[63:56]`. The CPU's MMU ignores those bits when translating addresses — the actual virtual address is the lower 56 bits.

Different allocators use the top byte for different purposes:

| Allocator | Top byte signature | Purpose |
|---|---|---|
| **Scudo** (Android's libc malloc) | `0xb4`, `0xa8`, etc. (per-chunk random) | Use-after-free detection via tag mismatch on free |
| **GWP-ASan** | varies | Statistical heap bug detection |
| **HWASan** (LLVM hardware ASan) | per-byte tag | Heap bug catching |

Our `umod = 0xb4000076ffe73320` has `0xb4` as the scudo MAC tag. The actual address is:

```
umod & 0x00FFFFFFFFFFFFFF = 0x000000076ffe73320 = 0x76ffe73320 dec = 491,314,553,632
```

To pass this address to `lseek` on `/proc/<pid>/mem`, we **must strip the tag**, otherwise `lseek` returns `EINVAL` (the value is a valid 56-bit virtual address but with garbage in the high bits, the kernel sees it as a non-canonical 64-bit address).

Note: in some kernel paths, `untagged_addr()` strips the tag automatically. `/proc/<pid>/mem` is one of the paths that **does not** — the offset given to `lseek` is treated as raw. So we mask explicitly in C:

```c
unsigned long long umod_addr = umod & 0x00FFFFFFFFFFFFFFULL;
lseek(mfd, (off_t)umod_addr, SEEK_SET);
```

---

## Why C and not shell

Reaction-time budget for dumping the umod buffer:

| Phase | Duration |
|---|---|
| Binary's `init_module` syscall (kernel-side) | ~50-100 ms |
| Binary's post-`init_module` user-mode work (printf + exit) | ~5-10 ms |

So we have ~50-110 ms total. Shell-based reaction:

| Step | Cost |
|---|---|
| `cat /sys/kernel/tracing/trace_pipe` flush + line emit | ~10 ms |
| `read` in shell (line-by-line) | ~1 ms |
| `awk` fork + exec + parse | ~10 ms (per call, and we needed 3-4 calls) |
| `dd` fork + exec + open + lseek + read | ~10 ms |
| **Total** | **~50-100 ms** |

Right at the edge of our budget. In practice, we lost the race more often than we won.

C cost:

| Step | Cost |
|---|---|
| `read(trace_pipe_fd, buf, sizeof(buf))` | ~1 µs |
| `sscanf` parse | ~1 µs |
| `open("/proc/<pid>/mem")` | ~10 µs |
| `lseek` + `read(28 KB)` + `write(28 KB)` | ~100 µs |
| **Total** | **~120 µs** |

Three orders of magnitude faster. Plenty of margin.

The dumper is statically linked (no runtime libs to find), uses only POSIX syscalls, ~130 lines of code. See `src/dumper.c`.

---

## Why reboot

The binary takes a different code path depending on whether `/dev/bing_rw` exists at startup:

| `/dev/bing_rw` state | Binary's behavior | Kprobe fires? |
|---|---|---|
| Doesn't exist | Calls `init_module(buf, 28728, "")` — kernel loads the module, creates the device | **Yes** ✓ |
| Exists | Prints `已刷入驱动无需重复刷入` ("driver already loaded") and exits | **No** ✗ |

Once the module is loaded, it's rootkit-hidden: `rmmod` doesn't see it. `rm /dev/bing_rw` removes the node but the chrdev registration is still active in `/proc/devices` (major 458), so a subsequent `init_module` call returns `EEXIST`.

The only practical way to clear the loaded module is **reboot**. The toolkit's `extract.sh` does this automatically (with a `--no-reboot` opt-out for cases where you've just rebooted manually).

---

## Why `vermagic` mismatch was OK

The dumped `.ko` says:

```
vermagic=5.10.223-android12-9-00008-g4c7b897f395f-dirty SMP preempt mod_unload modversions aarch64
```

Our device runs `5.10.236-android12-9-...`. Different patch version. Normally Linux refuses to load a module with mismatched `vermagic`.

The exception is **`modversions`** mode (the `modversions` token in the `vermagic` string above tells you it's enabled). With `modversions`, the kernel ignores the version-string equality and instead checks that the **CRCs of every imported symbol's prototype** match the current kernel's CRCs. Each symbol in `__versions` carries a CRC; if all CRCs match, the load succeeds despite vermagic mismatch.

That's why `init_module` returned `0` (success) on a 5.10.236 kernel for a `.ko` built against 5.10.223 — the imported-symbol ABIs are still compatible.

For the disassembly work in IDA, the `vermagic` is informational. You don't need a matching kernel source tree to read the module — just an aarch64 disassembler.

---

## Why no header fix is needed

The `android-memdump-elf` tool exists for cases where you've dumped a *running* `.so` or `.ko` from `/proc/<pid>/mem` *after* the loader has mapped its segments. In that case:

- File offsets have been replaced with virtual addresses
- Sections may be discontiguous
- The section table may be gone or moved
- Some headers are patched up by the linker

You need to walk program headers, reconstruct the section layout, recompute file offsets, and rebuild a usable on-disk file.

**Our case is fundamentally different**. We caught the buffer that the userland binary was about to hand to `init_module`. That buffer is the *literal on-disk form* of the `.ko` — the same bytes that would be on disk if the binary had written them out before calling `finit_module(open(file), ...)` instead of `init_module(buf, len, ...)`.

Verification:
- `file bing_rw.ko` reports `ELF 64-bit LSB relocatable, ARM aarch64 ... not stripped`
- `e_type = 0x1` (ET_REL — kernel modules are always relocatable)
- `e_shnum = 31` — full section table present
- `e_shstrndx = 29` — section name string table valid
- `.modinfo`, `.symtab`, `.strtab`, `.note.gnu.build-id` all at sane offsets
- The kernel's own `load_module()` parsed and accepted these exact bytes — best possible verification

So: just open in IDA. No fixup tool needed for *this* file.

(The userland `.elf` files unpacked from the `.sh`'s — those *are* runtime-mapped images at rest after the unpacker runs. Memory-dump-ELF would be useful there. But that's a different artifact.)
