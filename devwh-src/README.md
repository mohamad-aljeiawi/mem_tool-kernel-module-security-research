# devwh -- audit rebuild of `6.6.ko` (cheating-oriented Android kernel rootkit)

## What this is

This directory is a **source-level reconstruction** of the kernel module
shipped as `dev增强版过检测/6.6.ko` (and its 5.4 / 5.10 / 5.15 / 6.1 /
6.12 siblings, which are the same code rebuilt for a different kernel
ABI / vermagic).

The original binary is an ARM64 Linux LKM that provides, to any
userspace process holding an fd on its device node:

1. arbitrary cross-process memory **read** by PID         (`OP_READ_MEM`)
2. arbitrary cross-process memory **write** by PID        (`OP_WRITE_MEM`)
3. per-process virtual address of a loaded shared object  (`OP_MODULE_BASE`)
4. install / enable / disable / clear / drain hits of
   a **cross-process hardware breakpoint**                (`OP_CMD_HWBP_*`)
5. **hide / unhide a running process** (unlink from
   `init_task.tasks`, tmpfs-overlay `/proc/<pid>`,
   `/sys/fs/cgroup/uid_0/pid_<pid>`, and the Adreno
   `/sys/devices/virtual/kgsl/kgsl/proc/<pid>`)          (`OP_CMD_HIDE_PROCESS`
                                                          / `_RECOVER_PROCESS`)

On load the module also:

* resolves `kallsyms_lookup_name` via a one-shot kprobe (the symbol has
  been un-EXPORTed since 5.7), so it does not need a symbol table;
* registers its character device under a **random 6-char name** so a
  signature-based scanner cannot find the device node by name;
* overlays an empty `tmpfs` on `/sys/class/<rand>` and
  `/sys/devices/virtual/<rand>` to hide its sysfs entries;
* **unlinks itself** from `vmap_area_list` + `vmap_area_root`, from the
  global module list, and from `/sys/module/` (this is the "module
  self-hide" primitive, invisible to `lsmod`, `/proc/modules`,
  `/sys/module/`, and `/proc/vmallocinfo`);
* overlays `tmpfs` on `/data/local/tmp/` so anything userland dropped
  there is invisible until reboot.

**What it is NOT**, verified by both static audit of the binary and by
this reconstruction:

* It has no network I/O capability in-kernel (no `sock_create_kern`,
  `kernel_sendmsg`, `kernel_connect`, `tcp_*`, `udp_*`).
* It has no crypto calls.
* It has no file-write side channel (no `vfs_write`, no `kernel_write`).
* It has no kthread / workqueue / timer that runs on its own.
* It does not hook the syscall table or install ftrace/kprobe trampolines
  on syscalls.
* It does not call `commit_creds(prepare_kernel_cred(...))`.

So on its own, this driver does not exfiltrate anything. **However**,
the presence of arbitrary cross-process kernel-space R/W on a phone
loaded with a banking app / password manager / Signal / Telegram means
that anyone who can reach the device node can scrape those apps' memory.
That is the practical threat model, and it does not require the driver
itself to do anything autonomous.

## Why rebuild it from source?

You asked to rebuild for precautionary / auditability reasons. The
rationale is sound:

* The shipped `.ko` is stripped and packed inside a self-extracting
  shell installer that then runs `dmesg -C` to clear the kernel log.
  That loader is designed to frustrate forensic review.
* The shipped `.ko` is licensed as "GPL" in its modinfo **but the
  source was never published** -- which makes the redistributed binary
  a direct GPL violation by its author. You can't audit what you
  can't read.
* Rebuilding forces you to pin a kernel ABI, a toolchain, and a signing
  policy explicitly. No more "just insmod this random blob."

**This reconstruction is for audit, reverse-engineering practice, and
defensive research.** Do not load it on a phone you actually use.
Running it is indistinguishable from running the original, and anyone
who can reach the device node has ring-0 read/write over the whole
device.

## Layout

```
devwh-src/
├── Makefile          # top-level wrapper (KDIR=... / matrix target)
├── Kbuild            # obj-m composition for the Linux kbuild
├── README.md         # you are here
├── uapi/
│   └── devwh_uapi.h  # ioctl numbers + structs (shared with userland)
├── devwh.h           # in-tree declarations
├── main.c            # module_init / module_exit (driver_entry/unload)
├── rand.c            # 6-char random device-name generator
├── kallsyms.c        # kprobe-assisted symbol resolution
├── hide.c            # tmpfs overlay / module self-hide / process hide
├── memrw.c           # cross-process memory R/W via pgd walk
├── hwbp.c            # cross-process HW-breakpoint install + hit ring
└── fops.c            # file_operations + unlocked_ioctl dispatcher
```

## Building

You need an ARM64 Android kernel source tree, cross-compiled with the
**same toolchain the device's kernel was built with** -- otherwise
`vermagic` will not match and `insmod` will reject the module.

```bash
# example: build against an already-configured MSM Android 13 kernel at
# ~/android/common-android13-5.15

export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64

make KDIR=$HOME/android/common-android13-5.15 \
     CC=clang LLVM=1 LLVM_IAS=1
```

To build for every Android kernel ABI at once (the matrix the
distribution ships one `.ko` per):

```bash
# put each extracted/prepared kernel tree under:
#   ../kernels/android-5.4   ../kernels/android-5.10   ... /android-6.12
# each must be fully `make defconfig && make modules_prepare`'d.

make matrix
```

You get `devwh-5.4.ko`, `devwh-5.10.ko`, ... one per target.

## Kernel-version compatibility notes

| Feature                          | Works on 5.4 | 5.10+ | 6.4+ | 6.6+ |
|----------------------------------|:------------:|:-----:|:----:|:----:|
| `kallsyms_lookup_name` (kprobe)  |      Y       |   Y   |  Y   |  Y   |
| `path_mount` (for tmpfs overlay) |     **N**    |   Y   |  Y   |  Y   |
| `class_create(name)` API (6.4+)  |      compat shim in `devwh.h`         |
| `VMA_ITERATOR` for vma walk      |      N       |  N    |  N   | Y[*] |
| 4K-page 4-level arm64 pgd walk   |      Y       |   Y   |  Y   |  Y   |

[*] `VMA_ITERATOR` landed in 6.1 -- `fops.c` switches at that boundary.

On 5.4 the tmpfs-overlay primitive will not compile because `path_mount`
is absent. Either drop the hide features for 5.4 (remove
`devwh_hide_mount_tmpfs()` / `devwh_umount_hidden()` call sites) or
port them to the older `ksys_mount` / `do_mount` API. The shipped
5.4.ko uses `ksys_mount`; that's not in this reconstruction because
ksys_* are not exported.

## What the reconstruction intentionally changes

* **License**. We declare `MODULE_LICENSE("GPL")` for real. The original
  lies about this, because GPL-only symbols (`register_user_hw_breakpoint`)
  otherwise fail to link at load time.
* **CFI thunks**. The original was built with LLVM CFI and you can see
  the `*((u32*)fn - 1) != <magic>` runtime integrity checks in every
  indirect call. We do not reproduce those -- they are a *build-time*
  feature, not source, and come automatically if you build with the same
  `CONFIG_CFI_CLANG=y` kernel.
* **PAN toggle**. The original open-codes `mrs/msr TTBR0_EL1` sequences
  around every user access. We use `copy_to_user` / `copy_from_user` /
  `kmap+memcpy`; these already handle PAN correctly on every supported
  ARM64 kernel. Identical behavior, less hand-rolled asm.
* **No `dmesg -C`**. That was in the installer shell script, not the
  module. We don't restore it. Load this with the kernel log intact so
  you can actually debug it.

## What the reconstruction intentionally preserves

* The exact raw ioctl numbers from `dev增强版对接.h` (not `_IO*`-encoded).
  The userland client will probe us with those literal numbers.
* The device-name randomization alphabet and length (6 chars, A-Z a-z 0-9).
* The module self-hide poison values (`0xDEAD000000000100`,
  `0xDEAD000000000122`) for `vmap_area_list` walkers.
* The tmpfs-hide set: `/sys/class/<rand>`, `/sys/devices/virtual/<rand>`,
  `/data/local/tmp/` (init), plus per-process `/proc/<pid>`,
  `/sys/fs/cgroup/uid_0/pid_<pid>`, and
  `/sys/devices/virtual/kgsl/kgsl/proc/<pid>` (Adreno GPU state).
* The HWBP ring size of 16 slots (matches `HWBP_HIT_ITEM[16]`).
* The `PF_NO_SETAFFINITY`-overlapping `0x10000000` task-flag bit used
  as "this task is currently hidden by us" marker.

## Safety rails

This source is for *auditing*, not for *running*. If you rebuild and
load it:

* Do it on a throwaway device or an emulator/AVD, never on a daily
  phone.
* Keep the device air-gapped during testing. Even though the module
  itself has no network path, once loaded any user-space process can
  use it to read arbitrary memory (including your Wi-Fi keys, Signal
  session state, etc.).
* Unload with `rmmod` -- but note that because the module is self-hidden
  from `/proc/modules`, you need to remember the exact module name you
  built with (`devwh` by default).

If you just want to *inspect* what it does at runtime, prefer
tracing-oriented approaches (`bpftrace`/`kfunc`/`kprobe` on the module's
public symbols) over `insmod`'ing it.
