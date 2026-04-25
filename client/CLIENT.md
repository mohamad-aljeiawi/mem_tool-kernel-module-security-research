# `kernel_client.h` — userland client API (2026-04, bing_rw driver)

Practical reference for `client/kernel_client.h`, the
C++ header that talks to the loaded **`bing_rw`** kernel module. Every
call is a single `ioctl(2)` against the fixed chardev `/dev/bing_rw`.

The API surface in this header is **exactly the opcodes wired into the
shipped `.ko`**. Re-verified via IDA Pro / Hex-Rays on
`output/5.10.ko` — the dispatcher, auth check, and
file_operations table are all authoritative below.

> Everything below requires the module to already be loaded
> (`insmod` the matching .ko for the running kernel). Without it,
> `open("/dev/bing_rw", ...)` returns -1 / ENOENT and the auto-init in
> the header `exit(0)`s the host process.

## 0. What changed vs the previous header (**read this first**)

The shipped driver has been **wholly replaced**. The prior header was
written for the older `mem_tool` driver (random 6-char dev name, opcodes
0x801–0x806, hide/find_pid features). The new driver is `bing_rw` by
NULL1337 — different name, different device path, different opcodes,
different feature set:

| concept                | prior `mem_tool`                          | current `bing_rw`                      |
|------------------------|-------------------------------------------|----------------------------------------|
| device path            | `/dev/<6 random A-Za-z0-9>` (rand-named)  | `/dev/bing_rw` (fixed)                 |
| auth                   | none                                      | **MUST** `ioctl(0x100, "bingByNULL1337")` first |
| READ opcode            | 0x801                                     | **0x101**                              |
| WRITE opcode           | absent                                    | **0x102** (back, fully wired)          |
| MODULE_BASE opcode     | 0x803                                     | **0x103**                              |
| HIDE / FIND_PID / HWBP | 0x804–0x807                               | **all gone** — no symbols, no imports  |
| device-name discovery  | scan `/dev` for stat-signature            | open `/dev/bing_rw` directly           |
| auth state scope       | n/a                                       | **global** flag, not per-fd            |
| auth state on close    | n/a                                       | reset to 0 — must re-init after close  |
| stealth from /proc     | unregister_chrdev_region + remove_proc_*  | only `list_del` + `kobject_del`        |
| compat_ioctl (32-bit)  | not wired                                 | not wired — 32-bit clients still ENOTTY |

If you have pre-2026 `mem_tool` client code, it will fail to even open
the device (the random-name scan returns NULL). The compile will also
fail because the new header drops `hide_process()`, `hide_pid()`,
`find_pid_by_comm()`, `recover_process()`, and `ClearHwBp()` — those
functions and their opcodes do not exist in the binary.

## 1. Include and boot

```cpp
#include "kernel_client.h"
```

That is the whole integration. Two globals are declared at the bottom of
the header and become live during static init:

| global   | type         | meaning                                                            |
|----------|--------------|--------------------------------------------------------------------|
| `driver` | `c_driver *` | constructed *and authenticated* on first include                   |
| `pid`    | `pid_t`      | set by `getPID()`; consumed by free helpers (`ReadDword`, etc.)    |

The `c_driver` constructor runs at program startup (static init) and:

1. opens `/dev/bing_rw` `O_RDWR`. On failure (ENOENT / EACCES),
   `exit(0)` the host process. Wrap the include behind your own init if
   you need graceful degradation.
2. calls `init_key("bingByNULL1337")`. If that fails (returns false),
   `exit(1)`. **No memory ioctl can succeed before this completes.**

`init_key()` understands the driver's first-call quirk (see §2 below)
and treats `ret==-1, errno==EPERM` as success.

## 2. Authentication — `init_key()` and the EPERM quirk

The dispatcher gates *every* opcode (0x101 / 0x102 / 0x103) behind a
global `is_verified` flag. To set it you must:

```cpp
ioctl(fd, 0x100, buf);   /* buf = 49 bytes; bytes 0..14 = "bingByNULL1337\0" */
```

The kernel `copy_from_user`s **49 bytes** (`0x31`) and runs an XOR check
equivalent to `strncmp(buf, "bingByNULL1337", 15) == 0`. Bytes 15..48
are scratch but must be readable.

### The EPERM quirk

The dispatcher captures `v7 = is_verified` *before* it processes the
verify command, then later does `if (v7) switch(cmd)…`. The switch has
no `case 0x100`, so even when the key matches and the post-verify
update sets `is_verified=1`, the function falls through to
`default: return -1`. Userland sees:

```
ioctl(fd, 0x100, key) == -1, errno == EPERM   // first call: match landed,
                                              //  flag is now 1, but ret -1
ioctl(fd, 0x101, &cm) == 0                    // next call: succeeds
```

`init_key()` masks this: it returns `true` when `errno == EPERM` (success
landed) and `false` only on a *real* failure (EFAULT, EINVAL, copy
fault, or the key didn't match — which manifests as a different errno
or a never-changing global).

### State scope and lifetime

- `is_verified` lives in the module's `.bss` (one global for the whole
  driver), **not** a per-fd `private_data`. If process A has already
  authenticated, process B's first ioctl will succeed without B
  calling `init_key`. Don't rely on that — call `init_key` in every
  client; it's idempotent.
- `dispatch_close` resets `is_verified = 0` on **every** `close(2)`.
  If process A closes its fd, *all* concurrent clients lose auth and
  must `init_key` before their next op. This is a minor footgun if
  you have two short-lived processes hitting the device.

## 3. Target selection — `getPID()`

The bing_rw driver does not expose a kernel-side pidof opcode (the old
mem_tool 0x806 is gone — no `find_pid_by_comm`, no `init_task.tasks`
walker). Pid resolution is back to userland:

```cpp
int tpid = getPID((char *)"com.target.package");
if (tpid <= 0) { fprintf(stderr, "not running\n"); return 1; }
```

Strategy in this header:

1. `popen("pidof <pkg>")` — primary path. Works when the package's
   `cmdline` is its full Java-side name.
2. Fallback: scan `/proc/<n>/comm` for the **last 15 characters** of
   the package name (TASK_COMM_LEN-1 = 15 chars; the zygote truncates
   long package names there).

Both paths are noisy by audit-trail standards (sh process, /proc
walk). If your operational profile cannot tolerate that, do the lookup
out-of-band and feed the pid to `driver->initialize(pid)` directly.

## 4. Methods on `driver`

### 4.1 Cross-process memory READ (0x101)

```cpp
bool driver->read (uintptr_t addr, void *buf, size_t size);
template<class T> T driver->read<T>(uintptr_t addr);   // T{} on fail
```

Kernel-side: `find_get_pid` → `get_pid_task` → `get_task_mm` → manual
PGD/PUD/PMD/PTE walk (no `get_user_pages`). The PTE physical address
is reconstructed via `memstart_addr` / `vabits_actual` / `pfn_valid`,
then the kernel virtual mapping `phys | 0xFFFFFF8000000000` is read
directly into the user buffer with `copy_to_user`. Bypasses ptrace
and SELinux on the target because it never enters via the target
process's mm path from userland.

Free helpers:

| helper                       | width                                   |
|------------------------------|-----------------------------------------|
| `long  ReadValue(long addr)` | auto: 4 if `addr < 0xFFFFFFFF`, else 8  |
| `long  ReadDword(long addr)` | 4                                       |
| `float ReadFloat(long addr)` | 4                                       |

### 4.2 Cross-process memory WRITE (0x102)

```cpp
bool driver->write(uintptr_t addr, const void *buf, size_t size);
template<class T> bool driver->write<T>(uintptr_t addr, const T &value);
```

Same page-walk as read; on the leaf physical page the kernel calls
`copy_from_user` with the user buffer. Free helpers:

| helper                                     | width |
|--------------------------------------------|-------|
| `bool WriteDword(long addr, int   value)`  | 4     |
| `bool WriteFloat(long addr, float value)`  | 4     |

The page must be *resident* — the walk does not fault pages in. If the
target page is swapped/unmapped, the write returns -1; touch the page
on the target side first or read it once to force `copy_to_user` to
fault it in (which is *only* a side-effect of the read path on this
driver — there is no explicit page-pinning ioctl).

### 4.3 Module-base resolution (0x103)

```cpp
uintptr_t driver->get_module_base(const char *name);
long      GetModuleBaseAddr_Maps(char *name);   // /proc/<pid>/maps fallback
```

`get_module_base` walks the target's VMA list kernel-side via
`find_vma()`, takes `d_path(vma->vm_file->f_path)` for each, basename
strips with `strrchr('/')`, then `strcmp`s the basename against the
49-byte name buffer the user supplied. **First match wins.**

Two subtleties verified in IDA:

- The kernel always copies **49 bytes** (`0x31`) from the user pointer
  into a kernel scratch buffer regardless of the actual string length.
  The header zero-fills before `strncpy` so this is safe.
- After a `.so` match, the resolver walks forward via `find_vma()` to
  detect the merged-segment case (some bionic loaders split an .so
  across multiple VMAs). It returns the `vm_start` of the *first* VMA
  whose backing-file basename matches.

`GetModuleBaseAddr_Maps` does the same via `/proc/<pid>/maps` and is
useful when the kernel-side walk returns 0 because the target is using
an unusual VMA layout (anon-mapped JIT, dlmopen()'d module, etc.).

### 4.4 Methods removed since 2026-04

`hide_process()` / `hide_pid()` / `recover_process()` /
`find_pid_by_comm()` / `ClearHwBp()` — none of these symbols exist in
the binary. The .symtab imports list (verified in IDA) contains zero
HWBP, perf_event, kprobe, or pid-hash-mutation helpers. The header no
longer exposes the methods so old callers fail to compile.

## 5. Ioctl reference (for non-C++ clients)

The kernel interface is plain `ioctl(2)`. Open `/dev/bing_rw` `O_RDWR`,
authenticate, then issue the memory ops:

```c
#define BING_OP_VERIFY      0x100
#define BING_OP_READ_MEM    0x101
#define BING_OP_WRITE_MEM   0x102
#define BING_OP_MODULE_BASE 0x103

int fd = open("/dev/bing_rw", O_RDWR);

/* 1. verify -- expect ret=-1, errno=EPERM on success (see §2) */
uint8_t key[0x31] = {0};
memcpy(key, "bingByNULL1337", 14);
ioctl(fd, BING_OP_VERIFY, key);

/* 2. read */
struct { pid_t pid; uintptr_t addr; void *buf; size_t size; } cm;
cm.pid = target_pid; cm.addr = va; cm.buf = dst; cm.size = n;
ioctl(fd, BING_OP_READ_MEM, &cm);   /* 0 on success, -1 on fail */

/* 3. write */
cm.buf = (void*)src;
ioctl(fd, BING_OP_WRITE_MEM, &cm);  /* 0 on success */

/* 4. module-base */
char name[0x31] = {0}; strcpy(name, "libUE4.so");
struct { pid_t pid; char *name; uintptr_t base; } mb;
mb.pid = target_pid; mb.name = name; mb.base = 0;
ioctl(fd, BING_OP_MODULE_BASE, &mb);  /* 0 on success; mb.base filled */
```

Anything other than 0x100/0x101/0x102/0x103 returns -1.

**The `file_operations` table only wires `unlocked_ioctl`, `open`,
`release`. There is no `compat_ioctl`.** A 32-bit aarch32 process
gets `ENOTTY` on every ioctl. Build the client aarch64.

## 6. Kernel-side stealth (what the module does at load)

Verified in `driver_entry` of `output/5.10.ko`:

```text
init
 ├─ alloc_chrdev_region(&dev_t, 0, 1, "bing_rw")    // major in /proc/devices
 ├─ kmem_cache_alloc_trace(...)                     // 0x98 bytes for cdev wrap
 ├─ cdev_init(memdev, &dispatch_functions)
 ├─ cdev_add(...)                                   // major.0 active
 ├─ __class_create(&__this_module, "bing_rw", ...)  // /sys/class/bing_rw/
 ├─ device_create(class, NULL, dev_t, NULL,
 │                "%s", "bing_rw")                  // /dev/bing_rw
 ├─ list_del(&__this_module.list)                   // hidden /proc/modules
 └─ for each holder in __this_module.holders:
       list_del; sysfs_remove_link("bing_rw");
       kfree(holder)                                // hidden /sys/module/bing_rw/holders
```

What the prior `mem_tool` did and **bing_rw does NOT**:

- No `remove_proc_entry("sched_debug", NULL)`
- No `remove_proc_entry("uevents_records", NULL)`
- No `unregister_chrdev_region` at load time (the major stays visible
  in `/proc/devices` as `bing_rw`)
- No random device-name generation

So `bing_rw` is *less* stealthy than the prior driver: a `cat
/proc/devices | grep bing_rw` reveals it, and `/dev/bing_rw` is a
standing breadcrumb. The `kobject_del` + `list_del` calls still hide
it from `/proc/modules` and `/sys/module/`, which is enough to defeat
naive `lsmod` enumeration.

The `dispatch_functions` (file_operations) struct wires only:

- `.owner          = __this_module`
- `.unlocked_ioctl = dispatch_ioctl`   (offset 0x80)
- `.open           = dispatch_open`    (offset 0xb0)
- `.release        = dispatch_close`   (offset 0xc0)

`dispatch_open` is a no-op `return 0`. `dispatch_close` clears
`is_verified` (the global auth flag) and returns 0.

## 7. Integration — Android NDK CLI tool

```cpp
#include "kernel_client.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pkg> <module.so> <hex-offset>\n", argv[0]);
        return 1;
    }

    /* driver is already opened + authenticated by static init */
    if (getPID(argv[1]) <= 0) {
        fprintf(stderr, "not running\n");
        return 1;
    }

    uintptr_t base = driver->get_module_base(argv[2]);
    if (!base) {
        fprintf(stderr, "module %s not in target's VMA list\n", argv[2]);
        return 1;
    }
    uintptr_t off  = strtoull(argv[3], nullptr, 16);
    uintptr_t va   = base + off;

    int v = driver->read<int>(va);
    printf("pid=%d %s+0x%lx = 0x%x\n", (int)pid, argv[2], (long)off, v);

    /* example write-back, demonstrating 0x102 wiring */
    if (driver->write<int>(va, v ^ 0xdeadbeef))
        printf("flipped; readback=0x%x\n", driver->read<int>(va));

    return 0;
}
```

```bash
export NDK=$HOME/Android/Sdk/ndk/26.1.10909125
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++ \
    -O2 -static -std=c++17 -o memtool main.cpp
adb push memtool /data/local/tmp/
adb shell "su 0 /data/local/tmp/memtool com.target.pkg libUE4.so 9F1A34"
```

## 8. Failure modes

| symptom                                  | likely cause                                           | fix                                                  |
|------------------------------------------|--------------------------------------------------------|------------------------------------------------------|
| `open("/dev/bing_rw")` -> ENOENT         | module not loaded, or different driver active         | `insmod` the matching .ko for the running kernel     |
| `open` -> EACCES                         | SELinux denied; or you're not root/uid-0              | run as root; relax SELinux for the test slot         |
| `init_key()` returns false               | wrong key (driver mismatch); or buffer < 49 bytes     | confirm bytes 0..14 = "bingByNULL1337\0"; pad to 49  |
| read/write returns false                 | not authenticated yet                                  | call `init_key()`; check `is_verified` semantics §2  |
| read/write on valid addr returns false   | target page swapped/unmapped, or target died          | verify `/proc/<pid>/maps`; read the page first       |
| `get_module_base` returns 0              | target PID unset, name mismatch (case-sensitive!), VMA not yet mapped | check `/proc/<pid>/maps`; pass exact basename       |
| 32-bit process gets ENOTTY               | driver has no `.compat_ioctl`                          | build the client aarch64                             |
| auth works once then fails after close   | `is_verified` reset by `dispatch_close` (it's global) | call `init_key()` again after any reopen             |
| `ioctl(0x100,...)` returns -1 / EPERM    | this is the **success** case — proceed                 | just continue; `init_key()` already handles it       |
| `ioctl(0x101,...)` returns -1 first call | `is_verified == 0` because verify was never called    | call `init_key()` in this process before any op      |

## 9. Safety notes

- Once loaded, **any process able to `open(/dev/bing_rw)` and pass the
  hard-coded 14-char auth key has ring-0 read AND write** over every
  process on the device. Banking apps, password managers, encryption
  state, kernel-mode buffers reachable from a target's mm — all
  in-scope. The key is a constant string in `.rodata` and trivially
  recoverable from the .ko. **Do not load this on a device you use
  for anything personal.**
- There is no recover/teardown for the side effects (the prior hide
  module had the same property; bing_rw doesn't hide tasks at all so
  this is moot for it). To remove the driver: `rmmod bing_rw` —
  cleanup_module destroys the device, class, and cdev.
- The chardev path is fixed (`/dev/bing_rw`) so its presence is a
  one-`ls` IOC. The major also shows up in `/proc/devices`. Don't
  expect this driver to evade automated module-tracker tooling.

## 10. Provenance

Everything in this document was re-derived from IDA Pro / Hex-Rays
analysis of:

- `output/5.10.ko` — the bing_rw driver
  - .modinfo: `name=bing_rw`, `author=NULL1337`,
    `description=bing memory rw driver tg @nullnb6`,
    `vermagic=5.10.223-android12-9-... aarch64`
  - .rodata: `"bingByNULL1337"` @ 0x357, `"bing_rw"` @ 0x366,
    `".so"` @ 0x350, `"%s"` @ 0x354

Functions inspected: `driver_entry`, `driver_unload`, `dispatch_ioctl`,
`dispatch_open`, `dispatch_close`, `dispatch_functions`
(file_operations), `read_process_memory`, `write_process_memory`,
`get_module_base`. `is_verified` global `.bss @ 0x208`. The XOR check
in `dispatch_ioctl` decodes to literal `"bingByNULL1337\0"`:

- `0x554E7942676E6962` (LE) = `"bingByNU"` (8 bytes)
- `0x373333314C4C55`   (LE) = `"ULL1337\0"` (8 bytes; high byte 0)
- compared as `(buf[0..7] ^ k1) | (buf[7..14] ^ k2) == 0`
