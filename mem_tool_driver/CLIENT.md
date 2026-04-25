# `kernel_client.h` -- userland client API reference

This is the practical usage document for `mem_tool_driver/kernel_client.h`,
the C++ header that talks to the **devwh** kernel module (the one we
rebuilt in `devwh-src/`). Every function below goes through a single
`ioctl()` against a random-named char device in `/dev`.

> ⚠️  Everything documented here depends on the kernel module already
> being loaded (see `RUNBOOK.md`). Without the module, there is no device
> node to open, and every function returns failure.

## 0. The mental model

```
+-----------------------+        ioctl()          +------------------------+
|  your app / tool      |  ────────────────────▶ |  devwh kernel module   |
|  (uses kernel_client  |                         |  exposes /dev/<rand6>  |
|   .h)                 |  ◀──────────────────── |  unlocked_ioctl switch |
+-----------------------+     copied back         +------------------------+
```

`kernel_client.h` is a thin, inline-only wrapper. There is no `.cpp`, no
library, no build step. `#include "kernel_client.h"` and you are done.

## 1. First-run wiring

At the very top of any process that uses the header:

```cpp
#include "kernel_client.h"     // pulls in <stdio.h>, <sys/ioctl.h>, ...
```

Two globals are declared in the header and are usable immediately:

| Global                    | Type          | Meaning                                |
|---------------------------|---------------|----------------------------------------|
| `driver`                  | `c_driver *`  | auto-constructed on first include      |
| `pid`                     | `pid_t`       | set by `getPID()`; used by helpers     |

The `c_driver` constructor runs **the instant your binary loads**, because
of `static c_driver *driver = new c_driver();` at the bottom of the
header. That constructor:

1. calls `driver_path()` which scans `/dev` for a chardev/blockdev whose
   name is exactly 6 chars, `atime == ctime`, `size == 0`, `uid == gid == 0`,
   and `ctime year > 1980`. That is the signature the kernel module
   leaves when it registers itself.
2. `open()`s that device `O_RDWR`.
3. `exit(0)` immediately on failure (this is intentional, matches the
   original cheat distribution).

**Side-effect**: if you ship this header in a binary and the driver is
not loaded, your binary silently exits. Wrap the include behind your own
init function if you want graceful degradation:

```cpp
// graceful-init replacement -----------------------------------------
#define  CYCLE_SKIP_AUTOINIT
#include "kernel_client.h"

int main() {
    try { driver = new c_driver(); }
    catch (...) { fprintf(stderr, "driver not loaded\n"); return 1; }
    ...
}
```

(and you have to manually comment out the `static c_driver *driver = ...`
line, since the header does not currently honor such a macro -- one small
patch worth making.)

## 2. Per-target wiring: `getPID()`

You must call `getPID("com.target.package")` before any memory op. It:

* runs `pidof <package>` via `popen`,
* fills the global `pid`,
* calls `driver->initialize(pid)` so every subsequent `driver->read`/
  `driver->write` uses that PID.

```cpp
int target = getPID((char *)"com.target.package");
if (target <= 0) { fprintf(stderr, "target not running\n"); return 1; }
```

To switch target mid-run, call `getPID()` again (or `driver->initialize(pid)`).

## 3. Method reference

### 3.1 Memory read / write

```cpp
bool driver->read (uintptr_t addr, void *buffer, size_t size);
bool driver->write(uintptr_t addr, void *buffer, size_t size);
```

Both do a cross-process virtual-address R/W into the currently
initialized target PID. The kernel walks the target's pgd → pud → pmd →
pte by hand, so this **bypasses ptrace/selinux restrictions**.

Templated shortcuts (header inlines):

```cpp
T      driver->read<T>(uintptr_t addr);           // returns T{} on failure
bool   driver->write<T>(uintptr_t addr, T value);
```

Plus free-standing legacy helpers defined further down in the header
that call `driver->read/write` internally:

| Helper                                   | Width |
|------------------------------------------|-------|
| `long  ReadValue(long addr)`             | 4 or 8 (auto on address size) |
| `long  ReadDword(long addr)`             | 4     |
| `float ReadFloat(long addr)`             | 4     |
| `int   WriteDword(long addr, int v)`     | 4     |
| `int   WriteFloat(long addr, float v)`   | 4     |

Example:

```cpp
uintptr_t base = driver->get_module_base((char *)"libUE4.so");
int hp = driver->read<int>(base + 0x9F1A34);
driver->write<int>(base + 0x9F1A34, 999);
```

### 3.2 Module-base resolution

```cpp
uintptr_t driver->get_module_base(char *name);
long      GetModuleBaseAddr_Maps (char *name);   // userland /proc/<pid>/maps fallback
```

`get_module_base` walks the target's VMA list kernel-side and returns the
`vm_start` of the first VMA whose backing file's basename equals `name`
(case-sensitive, suffix after last `/`). Needs the target PID already set.

`GetModuleBaseAddr_Maps` does the same via `/proc/<pid>/maps`. Use it
when the target is not accessible to the kernel walk (uncommon) or when
you want the VMA **containing** an address rather than the first VMA of
a given module. Zero on failure.

### 3.3 Process hide / recover (**rootkit primitives**)

```cpp
driver->hide_process();
driver->recover_process();
```

These issue `OP_CMD_HIDE_PROCESS` / `OP_CMD_RECOVER_PROCESS` with **no
PID argument** -- they hide/recover the **currently-initialized target
PID** (set by the last `driver->initialize(pid)` / `getPID()`).

What "hide" means kernel-side:

* unlink `task->tasks` from `init_task.tasks` under `tasklist_lock`
* tmpfs-overlay `/proc/<pid>` → `ps` / `ls /proc` no longer see it
* tmpfs-overlay `/sys/fs/cgroup/uid_0/pid_<pid>`
* tmpfs-overlay `/sys/devices/virtual/kgsl/kgsl/proc/<pid>` (Adreno GPU)
* set a "hidden" task flag (`0x10000000`) so we don't double-hide

`recover_process()` undoes all four. After recover, the process is
visible to userland again. **If your binary exits mid-hide without
recovering, the overlays survive until reboot.**

### 3.4 Hardware breakpoints (cross-process)

The module uses the kernel's `perf_event` HW-breakpoint API to plant
a breakpoint into **another process's address space**, receives hits
inside the kernel, optionally **rewrites the target's GP registers**,
then resumes the target. This is how "instant trigger" cheats capture a
function's arguments or patch a return value in place.

#### 3.4.1 `AddHwBp` / `UpdateAndEnableHwBp`

```cpp
HW_BP_INFO info = {};
info.pid   = target_pid;
info.addr  = 0x12345000;          // instruction or data address in target
info.type  = HW_BP_TYPE_X;        // _R | _W | _RW | _X
info.len   = 4;

info.is_write_gp_regs = true;     // on every hit, rewrite regs before resume
info.gp_reg_count     = 2;
info.gp_reg_indices[0]= 0;        // X0
info.gp_reg_values [0]= 0xDEADBEEF;
info.gp_reg_indices[1]= 19;       // X19
info.gp_reg_values [1]= 42;

driver->AddHwBp(&info);           // install
// ... or, if already added and you want to change the plan:
driver->UpdateAndEnableHwBp(&info);
```

`len` must be 1/2/4/8 for data breakpoints; 4 for instruction.
`type = HW_BP_TYPE_X` corresponds to `HW_BREAKPOINT_X` (execute).

FP-register rewrite fields (`is_write_fp_regs`, `fp_reg_*`) exist in the
struct but the kernel handler currently **parses and stores them without
injecting**. If you need real FP injection, see `devwh-src/hwbp.c` and
extend `devwh_bp_overwrite_regs`.

#### 3.4.2 `DisableHwBp` / `ClearHwBp`

```cpp
driver->DisableHwBp(target_pid, 0x12345000); // disable a specific one
driver->ClearHwBp();                         // remove ALL, across all pids
```

`Disable` keeps the record; `Clear` unregisters all perf events and frees
them.

#### 3.4.3 `GetHwBpHits` -- drain the hit ring

Each installed breakpoint has a 16-slot ring of `HWBP_HIT_ITEM`. Each hit
records the task id, hit PC, a millisecond timestamp, and the full
`pt_regs` (X0..X30, SP, PC, PSTATE). Drain it periodically:

```cpp
HWBP_HIT_ITEM items[16];
HWBP_HIT_ARGS args = {};
args.pid     = target_pid;
args.addr    = 0x12345000;
args.out_buf = items;
args.out_len = 16;

int n = driver->GetHwBpHits(&args);
for (int i = 0; i < n; i++) {
    printf("[hit] tid=%d pc=%lx X0=%lx\n",
           items[i].task_id, items[i].regs_info.pc, items[i].regs_info.regs[0]);
}
```

`GetHwBpHits` returns the actual count copied (not 16 if the ring has
fewer entries); negative on ioctl failure.

### 3.5 `init_key` -- legacy license gate

```cpp
driver->init_key((char *)"abcdef...");  // 256-byte buffer
```

In the prebuilt binaries this ioctl is present in the enum but the
observed handler is a no-op / absent (OP_INIT_KEY=0x800 was not wired to
any case in the 6.6.ko dispatcher). The reconstructed `devwh-src` returns
`0` unconditionally for this ioctl. You can skip calling it.

### 3.6 Utility free functions

| Function                                             | Purpose                              |
|------------------------------------------------------|--------------------------------------|
| `float Kernel_v()`                                   | `uname -r` parsed as `float`, e.g. `5.10` |
| `char *GetVersion(char *PackageName)`                | `dumpsys package … versionName`      |
| `uint64_t GetTime()`                                 | monotonic ms timer                   |
| `int getPID(char *PackageName)`                      | `pidof` + sets the target            |
| `long GetModuleBaseAddr_Maps(char *module_name)`     | `/proc/<pid>/maps` lookup            |
| `long ReadValue / ReadDword / ReadFloat`             | sized reads                          |
| `int WriteDword / WriteFloat`                        | sized writes                         |

## 4. Integration recipes

### 4.1 Minimal CLI tool (Termux, ARM64 Android)

```cpp
// main.cpp
#include "kernel_client.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pkg> <hex-offset> <int-value>\n", argv[0]);
        return 1;
    }

    int tpid = getPID(argv[1]);
    if (tpid <= 0) { fprintf(stderr, "not running\n"); return 1; }

    uintptr_t base = driver->get_module_base((char *)"libUE4.so");
    uintptr_t off  = strtoull(argv[2], nullptr, 16);
    int       val  = atoi(argv[3]);

    printf("old = %d\n", driver->read<int>(base + off));
    driver->write<int>(base + off, val);
    printf("new = %d\n", driver->read<int>(base + off));
    return 0;
}
```

Build with the NDK against a standalone Android toolchain:

```bash
export NDK=$HOME/Android/Sdk/ndk/26.1.10909125
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++ \
    -O2 -static -std=c++17 -o memtool main.cpp
adb push memtool /data/local/tmp/
adb shell "su 0 /data/local/tmp/memtool com.target.pkg 9F1A34 999"
```

### 4.2 Linked into an Android native library (JNI)

```cpp
// libmytool.cpp
#include <jni.h>
#include "kernel_client.h"

extern "C" JNIEXPORT jint JNICALL
Java_com_example_Mytool_readInt(JNIEnv *env, jclass cls,
                                jstring jpkg, jlong addr) {
    const char *pkg = env->GetStringUTFChars(jpkg, nullptr);
    getPID((char *)pkg);
    jint v = driver->read<int>((uintptr_t)addr);
    env->ReleaseStringUTFChars(jpkg, pkg);
    return v;
}
```

Add a `System.loadLibrary("mytool");` block on the Java side, wrap the
native call, and you can read target memory from normal Java code. This
is the usual way the header is redistributed in cheat APKs.

### 4.3 Using it from a different language

The header is C++-only, but the kernel interface is language-agnostic
`ioctl(2)`. Write your own client in Rust / Go / Python by:

1. Scanning `/dev` for the same 6-char chardev pattern.
2. `open(path, O_RDWR)`.
3. Filling a `struct` laid out identically to `_COPY_MEMORY` and friends
   (see `devwh-src/uapi/devwh_uapi.h` for the authoritative offsets).
4. Calling `ioctl(fd, 0x801, &s)` for read, `0x802` for write, etc.

The raw op numbers are the contract. See the enum in the header.

## 5. Failure modes & how to detect them

| Symptom                                    | Likely cause                                                                     | Fix |
|--------------------------------------------|----------------------------------------------------------------------------------|-----|
| `driver_path()` returns `NULL`             | module not loaded, or loaded but sysfs-hide ran (fine) and chrdev path missing   | run the loader (`load_driver.sh`) |
| `open()` fails with `EACCES`               | SELinux blocked you                                                              | run as root or `setenforce 0` (not recommended) |
| Every ioctl returns `-EFAULT`              | your struct layout does not match the kernel's (`COPY_MEMORY`, etc.)             | rebuild userland against the same `kernel_client.h` the .ko was built with |
| `read` succeeds but returns zeros only     | target PID unset; or address not mapped in target                                | re-call `getPID`; verify with `/proc/<pid>/maps` |
| HWBP `AddHwBp` returns false always        | kernel module could not resolve `register_user_hw_breakpoint` (un-EXPORT + no GPL) | rebuild the module declaring `GPL` license |
| `hide_process()` returns but `ps` still shows it | tmpfs overlay on `/proc/<pid>` failed (selinux on `proc_t` domain transition)  | check `dmesg`; some Samsung/KNOX kernels block this |

## 6. Safety notes

* Once the module is loaded, **any process that can reach the random
  chardev has ring-0 R/W on every other process**. On a phone, that means
  banking apps, password managers, chat session keys. Never load this on
  a device you use for anything real.
* `hide_process()` without `recover_process()` leaves the hidden process
  invisible until reboot, including to the OOM killer's logs and to any
  crash reporter -- debugging survivability is zero.
* `ClearHwBp()` wipes every breakpoint across every PID the module has
  installed for. Not just yours. Use `DisableHwBp` for surgical removal.
