# devwh — source-level audit rebuild of `mem_tool`

Clean-room C reconstruction of the ARM64 Android LKM shipped as
`mem_tool_driver/*.ko` (the rootkit tracked in the repo root `README.md`
as **RT驱动 / RTdrivers / Cycle1337**).

## 1. Scope

Reproduces every primitive observed in the prebuilt binary:

1. cross-process memory **read**                     (`OP_READ_MEM`  0x801)
2. cross-process memory **write**                    (`OP_WRITE_MEM` 0x802)
3. module-base lookup by name in a target PID        (`OP_MODULE_BASE` 0x803)
4. cross-process **hardware breakpoint** add / enable / disable / clear /
   drain-hits                                        (`OP_CMD_HWBP_*`)
5. per-process **hide / recover** (unlink from `init_task.tasks`,
   tmpfs-overlay `/proc/<pid>`, cgroup + Adreno kgsl paths)
                                                     (`OP_CMD_HIDE_PROCESS` /
                                                      `OP_CMD_RECOVER_PROCESS`)

On load:

- resolves `kallsyms_lookup_name` via a one-shot kprobe (un-EXPORTed
  since 5.7);
- registers the chardev under a **6-char random name**;
- tmpfs-overlays `/sys/class/<rand>`, `/sys/devices/virtual/<rand>`, and
  `/data/local/tmp/`;
- **self-hides** from `vmap_area_list`/`vmap_area_root`, the global
  module list, and `/sys/module/`.

### 1.1 Difference vs the prebuilt

The shipped `.ko`s compile in the HWBP add/enable/disable/get_hits
handlers but **never route any ioctl cmd to them** — they sit as dead
code with zero xrefs from `dispatch_ioctl`. This reconstruction wires
them up, so HWBP-driven cheats that don't work against the prebuilt
binary will work against this source build.

`OP_INIT_KEY` (0x800) is accepted and returns `0` unconditionally; the
prebuilt binary has no case for it at all.

### 1.2 What this module does NOT do

Verified by static audit of the `.ko` and preserved in this
reconstruction:

| capability                            | present |
|---------------------------------------|---------|
| network I/O (`sock_create_kern`, `kernel_sendmsg`, …)| no |
| crypto                                | no      |
| file-write side channel               | no      |
| kthread / workqueue / self-running timer | no  |
| syscall-table hook / ftrace trampoline| no      |
| `commit_creds(prepare_kernel_cred(...))` | no  |

So the module itself exfiltrates nothing. The risk is that the
`/dev/<rand>` chardev hands ring-0 R/W to any process that can open it —
which, for any sensible threat model on a phone, is the whole problem.

## 2. Layout

```
devwh-src/
├── Makefile          # top-level wrapper (KDIR=... / matrix target)
├── Kbuild            # obj-m composition for the Linux kbuild
├── README.md         # this file
├── uapi/
│   └── devwh_uapi.h  # ioctl numbers + structs (shared with userland)
├── devwh.h           # in-tree declarations
├── main.c            # module_init / module_exit
├── rand.c            # 6-char random device-name generator
├── kallsyms.c        # kprobe-assisted symbol resolution
├── hide.c            # tmpfs overlay + module self-hide + process hide
├── memrw.c           # cross-process R/W via pgd walk
├── hwbp.c            # cross-process HW-breakpoint + hit ring
└── fops.c            # file_operations + unlocked_ioctl dispatcher
```

## 3. Building

Requires an ARM64 Android kernel source tree cross-compiled with the
**same toolchain the device's kernel was built with** — otherwise
`vermagic` will not match and `insmod` will reject the module.

```bash
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64

make KDIR=$HOME/android/common-android13-5.15 \
     CC=clang LLVM=1 LLVM_IAS=1
```

Matrix build (`devwh-5.4.ko`, `devwh-5.10.ko`, …):

```bash
# under ../kernels/android-5.4 ... ../kernels/android-6.12 put each
# target kernel tree, fully `make defconfig && make modules_prepare`'d.
make matrix
```

## 4. Kernel-version compatibility

| feature                           | 5.4 | 5.10+ | 6.4+ | 6.6+ |
|-----------------------------------|:---:|:-----:|:----:|:----:|
| `kallsyms_lookup_name` (kprobe)   |  Y  |   Y   |  Y   |  Y   |
| `path_mount` (for tmpfs overlay)  | **N**|  Y   |  Y   |  Y   |
| `class_create(name)` (6.4+)       |  compat shim in `devwh.h`       |
| `VMA_ITERATOR` for vma walk       |  N  |   N   |  N   |  Y[*]|
| 4K-page 4-level arm64 pgd walk    |  Y  |   Y   |  Y   |  Y   |

[*] `VMA_ITERATOR` landed in 6.1 — `fops.c` switches at that boundary.

On 5.4 `path_mount` is absent, so the tmpfs-overlay code does not
compile as-is. Either drop the call sites (`devwh_hide_mount_tmpfs` /
`devwh_umount_hidden`) or port them to `ksys_mount` / `do_mount` (the
shipped 5.4.ko uses `ksys_mount`; not reproduced here because those
`ksys_*` helpers are un-EXPORTed).

## 5. Intentional deviations from the prebuilt

- **License.** Declares `MODULE_LICENSE("GPL")` honestly. The original
  binary claims GPL in `.modinfo` but the source was never published —
  GPL-only symbols (`register_user_hw_breakpoint`) otherwise fail to
  link at load time.
- **PAN toggle.** The original open-codes `mrs/msr TTBR0_EL1` around
  every user access; we use `copy_to_user` / `copy_from_user` /
  `kmap + memcpy`. Same effective behavior, less hand-rolled asm.
- **No `dmesg -C`.** That's in the installer, not the module. Not
  reproduced — load this with the log intact.
- **CFI thunks.** The prebuilt is built with LLVM CFI; the
  `*((u32*)fn - 1) != <magic>` checks are build-time artifacts, not
  source, and reappear automatically if you build this against a
  `CONFIG_CFI_CLANG=y` kernel.

## 6. Intentionally preserved

- Raw ioctl numbers from the userland contract (not `_IO*`-encoded).
- Device-name randomization: 6 chars, `A-Za-z0-9`.
- Module-self-hide poison values `0xDEAD000000000100` /
  `0xDEAD000000000122` for `vmap_area_list` walkers.
- Tmpfs-hide set: `/sys/class/<rand>`, `/sys/devices/virtual/<rand>`,
  `/data/local/tmp/` (on init), plus per-process `/proc/<pid>`,
  `/sys/fs/cgroup/uid_0/pid_<pid>`, and
  `/sys/devices/virtual/kgsl/kgsl/proc/<pid>` (Adreno GPU state).
- HWBP ring size: 16 slots (matches `HWBP_HIT_ITEM[16]`).
- `0x10000000` task-flag bit as the "hidden by us" marker.

## 7. Safety

For **auditing**, not running. If you must build and load:

- Throwaway device or emulator/AVD only, never a daily phone.
- Air-gap during testing — once loaded, any userland process can
  scrape arbitrary memory (Wi-Fi keys, Signal state, …).
- Unload with `rmmod devwh` — the module is self-hidden from
  `/proc/modules`, so remember the exact name you built with.

For pure inspection at runtime, prefer tracing
(`bpftrace`/`kfunc`/`kprobe` on public symbols) over `insmod`.
