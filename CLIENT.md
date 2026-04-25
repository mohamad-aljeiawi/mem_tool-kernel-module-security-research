# `kernel_client.h` — userland client API

Practical reference for `mem_tool_driver/kernel_client.h`, the C++ header
that talks to the loaded `mem_tool` kernel module. Every call is a single
`ioctl()` against the random-named chardev the module registers under
`/dev`.

The API surface is trimmed to the opcodes that the shipped `.ko` actually
wires into its dispatcher (verified via IDA on 5.4 / 5.10 / 6.12; see
`README.md §3`). Unreachable HWBP add/enable/disable/get_hits and
`init_key` have been removed from the header — calling them was always a
silent no-op against the prebuilt binaries.

> Everything below requires the module to already be loaded (see
> `RUNBOOK.md`). Without the chardev, the auto-constructor will
> `exit(0)` the host process.

## 1. Include and boot

```cpp
#include "kernel_client.h"
```

That's the whole integration. Two globals are declared at the bottom of
the header and are live immediately:

| global    | type         | meaning                                    |
|-----------|--------------|--------------------------------------------|
| `driver`  | `c_driver *` | auto-constructed on first include          |
| `pid`     | `pid_t`      | set by `getPID()`; used by free helpers    |

The `c_driver` constructor runs at program startup (static init) and:

1. calls `driver_path()`, which scans `/dev` for a chardev/blockdev whose
   name is exactly 6 chars `[A-Za-z0-9]`, with
   `atime == ctime`, `size == 0`, `uid == gid == 0`, `ctime > 1980` — the
   signature the module's `get_rand_str()` + `device_create` leaves
   behind;
2. opens it `O_RDWR`;
3. on failure, `exit(0)` the host process. Wrap the include behind your
   own init if you need graceful degradation.

## 2. Target selection — `getPID()`

Before any memory op, bind a target PID:

```cpp
int tpid = getPID((char *)"com.target.package");
if (tpid <= 0) { fprintf(stderr, "not running\n"); return 1; }
```

`getPID()` runs `pidof <pkg>`, fills the global `pid`, and calls
`driver->initialize(pid)` so subsequent reads/writes use it. To switch
target mid-run, call it again.

## 3. Methods on `driver`

### 3.1 Cross-process memory R/W (0x801 / 0x802)

```cpp
bool driver->read (uintptr_t addr, void *buf, size_t size);
bool driver->write(uintptr_t addr, void *buf, size_t size);
template<class T> T    driver->read<T>(uintptr_t addr);       // T{} on fail
template<class T> bool driver->write<T>(uintptr_t addr, T v);
```

Kernel-side pgd → pud → pmd → pte walk against the target PID. Bypasses
ptrace/SELinux restrictions because it never goes through the target
process's mm path from userland.

Free helpers defined lower in the header call through to these:

| helper                                   | width                                    |
|------------------------------------------|------------------------------------------|
| `long  ReadValue(long addr)`             | auto: 4 if `addr < 0xFFFFFFFF`, else 8   |
| `long  ReadDword(long addr)`             | 4                                        |
| `float ReadFloat(long addr)`             | 4                                        |
| `int   WriteDword(long addr, int v)`     | 4                                        |
| `int   WriteFloat(long addr, float v)`   | 4                                        |

### 3.2 Module-base resolution (0x803)

```cpp
uintptr_t driver->get_module_base(char *name);
long      GetModuleBaseAddr_Maps (char *name);   // /proc/<pid>/maps fallback
```

`get_module_base` walks the target's VMA list kernel-side and returns
the `vm_start` of the first VMA whose backing-file basename matches
`name` (case-sensitive). Requires the target PID already bound.

`GetModuleBaseAddr_Maps` does the same via `/proc/<pid>/maps`. Use when
the VMA walk is blocked, or when you want the VMA *containing* a
specific address rather than the first VMA of a given module.

### 3.3 Process hide / recover (0x810 / 0x811)

```cpp
driver->hide_process();
driver->recover_process();
```

**Both ignore their ioctl argument** — the kernel handler reads the
caller's `task_struct->pid` from `SP_EL0 + pid_offset`, so they
hide/unhide **the calling process**, not whatever PID was last bound
with `getPID()`. To hide another process you would need a shim executing
inside that process (common pattern: preload a `.so` into the target).

Kernel-side "hide" unlinks `task->tasks` from `init_task.tasks` under
`tasklist_lock` and overlays tmpfs on the relevant `/proc/<pid>` and
cgroup/kgsl paths. `recover_process()` reverses it. **If the caller
exits while hidden, the overlays survive until reboot.**

### 3.4 Hardware-breakpoint clear (0x807)

```cpp
bool driver->ClearHwBp();   // returns true on success
```

The **only** HW-breakpoint opcode actually routed by the dispatcher in
the shipped binaries. Clears every perf-event HWBP the module holds,
across all PIDs.

The ADD / ENABLE / DISABLE / GET_HITS handlers are present in the `.ko`
but unreachable (no xrefs from `dispatch_ioctl`). The reconstruction in
`devwh-src/` wires them up; if you want working cross-process HWBP,
build and use that instead.

## 4. Free utility functions

| function                                           | purpose                                 |
|----------------------------------------------------|-----------------------------------------|
| `float Kernel_v()`                                 | `uname -r` parsed as `float`            |
| `char *GetVersion(char *pkg)`                      | `dumpsys package … versionName`         |
| `uint64_t GetTime()`                               | monotonic ms timer                      |
| `int   getPID(char *pkg)`                          | `pidof` + sets the target PID           |
| `long  GetModuleBaseAddr_Maps(char *mod)`          | `/proc/<pid>/maps` lookup               |
| `long  ReadValue / ReadDword / ReadFloat`          | sized reads                             |
| `int   WriteDword / WriteFloat`                    | sized writes                            |

## 5. Integration — Android NDK CLI tool

```cpp
#include "kernel_client.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pkg> <hex-offset> <int-value>\n", argv[0]);
        return 1;
    }
    if (getPID(argv[1]) <= 0) { fprintf(stderr, "not running\n"); return 1; }

    uintptr_t base = driver->get_module_base((char *)"libUE4.so");
    uintptr_t off  = strtoull(argv[2], nullptr, 16);
    int       val  = atoi(argv[3]);

    printf("old = %d\n", driver->read<int>(base + off));
    driver->write<int>(base + off, val);
    printf("new = %d\n", driver->read<int>(base + off));
    return 0;
}
```

```bash
export NDK=$HOME/Android/Sdk/ndk/26.1.10909125
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++ \
    -O2 -static -std=c++17 -o memtool main.cpp
adb push memtool /data/local/tmp/
adb shell "su 0 /data/local/tmp/memtool com.target.pkg 9F1A34 999"
```

### 5.1 Non-C++ clients

The kernel interface is a plain `ioctl(2)`. Reproduce `struct
_COPY_MEMORY` / `struct _MODULE_BASE` (authoritative layout in
`devwh-src/uapi/devwh_uapi.h`), open the random 6-char chardev
`O_RDWR`, and call `ioctl(fd, 0x801, &s)` / `0x802` / `0x803` /
`0x807` / `0x810` / `0x811`. That set is the entire contract.

## 6. Failure modes

| symptom                                    | likely cause                                                                 | fix                                          |
|--------------------------------------------|------------------------------------------------------------------------------|----------------------------------------------|
| `driver_path()` returns `NULL`             | module not loaded                                                            | `sh load_driver.sh`                          |
| `open()` fails with `EACCES`               | SELinux blocked you                                                          | root, or `--permissive` in the loader        |
| every ioctl returns `-EFAULT`              | struct layout mismatch with the `.ko`                                         | rebuild userland against this header         |
| `read` returns zeros                       | target PID unset, or addr not mapped                                         | re-call `getPID`; check `/proc/<pid>/maps`   |
| `ClearHwBp()` always returns `false`       | GPL-only HWBP symbols not resolved                                           | irrelevant for prebuilt; source rebuild fixes|
| `hide_process()` succeeds but `ps` shows it| tmpfs overlay on `/proc/<pid>` blocked by sepolicy                           | check `dmesg`; KNOX kernels block this       |

## 7. Safety notes

- Once loaded, any process reachable to the random chardev has ring-0
  R/W over every other process. Banking apps, password managers, E2EE
  keys. **Do not load on a device you use.**
- `hide_process()` without `recover_process()` leaves overlays in place
  until reboot — debugging survivability is zero.
- `ClearHwBp()` wipes every HWBP the module holds, not just yours.
