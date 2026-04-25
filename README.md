# RTdrivers / `mem_tool` — Android ARM64 Kernel Rootkit Reverse-Engineering & Analysis

Static reverse-engineering notes, IDA Pro walkthrough, ioctl map, loader
dissection, and a from-source audit rebuild of the Android ARM64 kernel module
distributed in the wild under the names **RT驱动**, **RTdrivers** and
**Cycle1337** (internal symbol prefix: `mem_tool_*`).

Analysis target: the eight `.sh` self-extracting installers in `dev/`
(originally named `dev增强版过检测/`) plus the userland C++ client header
`dev增强版对接.h`.

---

## 0. Attribution, disclaimer & purpose

### 0.1 I am not the author of this driver

This repository is an **independent reverse-engineering and static-analysis
bundle**. I did **not** write the original `.ko`, the `.sh` loaders, or the
userland client header. All copyright on those artifacts belongs to their
original author.

- **Original author / distributor:** **`@RTdrivers`** on Telegram —
  <https://t.me/RTdrivers>
- **Names seen in-the-wild:** `RT驱动`, `RTdrivers`, `Cycle1337`,
  internal C symbols `mem_tool_dev_t` / `mem_tool_class` / `memdev`.
- **This repository is maintained by** a third-party researcher
  purely as a reverse-engineering & educational resource.
  **No affiliation** with, and **no endorsement by**, `@RTdrivers`.

If you are the original author and want attribution clarified or an artifact
removed, open an issue — the goal here is public security research, not
redistribution.

### 0.2 Why this repository exists

Published as an open-source **security-research artifact**. It exists so that
other researchers, defenders, and curious engineers can:

1. **Analyse the security posture** of the driver — classify what it does
   (rootkit, info-stealer, cheat engine, backdoor, …) and measure the real
   risk it poses to a device that loads it.
2. **Read the code-level analysis** — the ioctl surface, stealth primitives
   (module self-hide, tmpfs overlay, randomized device name), the ARM64
   **PAN bypass** path, HW-breakpoint machinery, and the runtime
   `kallsyms_lookup_name` resolver.
3. **Understand its operation in depth** — how the self-extracting `.sh`
   loaders embed an ELF after a `#离` marker, how the `.ko` hides itself
   from `lsmod` / `/proc/modules` / `/sys/module`, and how the userland
   client in `kernel_client.h` discovers the randomized `/dev/<rand>` node.
4. **Rebuild parts of the code for manual verification.** `devwh-src/`
   contains a clean-room C reimplementation of the same primitives so the
   behaviour observed in the binary can be recompiled and re-tested by
   hand. It is **not** byte-identical to the upstream `.ko` and is **not**
   intended as a drop-in replacement.

### 0.3 Threat-model warning — do not run this on a real device

The `.ko` files under `mem_tool_driver/` are **rootkit-class kernel
modules**, kept here **for static analysis only**. Do **not** `insmod` any of
them on a device you care about. Once loaded, the driver:

- exposes ring-0 read/write into every other process on the system
  through a randomized character device,
- hides itself from `lsmod` / `/proc/modules` / `/sys/module`,
- hides arbitrary PIDs from the global task list,
- overlays tmpfs on `/data/local/tmp/` to conceal companion files,
- bypasses ARM64 PAN via direct `TTBR0_EL1` writes.

Any process that finds the random device file gets full kernel-level
access to banking apps, password managers, messaging keys, and anything
else on the device — bypassing Android's per-uid sandbox. See §5 *Verdict*
for the detailed threat profile.

### 0.4 License / legal use

The original binaries and the userland header are reproduced here under
a **research / fair-use** claim for the purpose of security analysis,
malware classification, and educational reverse engineering. No warranty.
Using any artifact in this repository to gain unauthorized access to
systems, to distribute cheats, or in violation of any law or terms of
service is **solely the responsibility of the user**. If you are a
platform vendor, AV, or rights-holder and need the set trimmed, open an
issue.

---

## 1. Repository layout

```
kernel-module/
├── README.md                           ← this file (analysis overview)
├── CLIENT.md                           ← userland client API reference
├── RUNBOOK.md                          ← how the loaders work + load checklist
├── load_driver.sh                      ← clean auto-selecting loader
├── extract_all.py                      ← reproducible extractor
│
├── dev增强版对接.h                      ← original userland client header (C++)
├── dev/ (was dev增强版过检测/)          ← original installers, untouched
│   ├── 5.4.sh   5.4b.sh   5.4c.sh
│   ├── 5.10.sh  5.15.sh
│   └── 6.1.sh   6.6.sh    6.12.sh
│
├── mem_tool_driver/                    ← extracted, organized analysis bundle
│   ├── 5.4.ko   5.4b.ko   5.4c.ko     ELF64 / aarch64 / ET_REL
│   ├── 5.10.ko  5.15.ko
│   ├── 6.1.ko   6.6.ko    6.12.ko
│   └── kernel_client.h                 copy of the userland header
│
└── devwh-src/                          ← from-source audit rebuild of the .ko
    ├── Makefile  Kbuild  README.md
    ├── uapi/devwh_uapi.h               ioctl contract (matches kernel_client.h)
    ├── main.c    rand.c   kallsyms.c
    ├── hide.c    memrw.c  hwbp.c   fops.c
```

### Docs quick-reference

| File            | Question it answers                                              |
|-----------------|------------------------------------------------------------------|
| `README.md`     | What is this, what's in the binary, is it malicious              |
| `CLIENT.md`     | How do I use `kernel_client.h` from my own app                   |
| `RUNBOOK.md`    | How do the `.sh` loaders work and how do I load cleanly          |
| `load_driver.sh`| The clean loader itself (run `sh load_driver.sh --help`)         |
| `devwh-src/README.md` | Building the module from source instead of running the blob  |

The folder name `mem_tool_driver` is taken from the binary's own internal
symbols (`mem_tool_dev_t`, `mem_tool_class`, `memdev`) — that is what the author
calls the project inside the code.

---

## 2. The `.sh` files are not shell scripts

Each `*.sh` is a **self-extracting installer**: a small shell preamble followed
by the line `#离` and then the raw ELF kernel module appended after it.

The preamble:

1. Requires root (`id -u` check).
2. Performs a "channel verification" gate by checking for cached Telegram media
   files from the `@RTdrivers` channel under
   `/storage/emulated/0/Android/data/<telegram-package>/cache/...`.
   Failure prompts the user to open `https://t.me/RTdrivers` in their browser.
3. Strips itself with `sed "1,/^#离/d" "$0" > /data/tmpf` to drop the trailing
   ELF onto disk.
4. `chmod u+x /data/tmpf && insmod /data/tmpf`.
5. On success, prints "RT驱动加载成功" 100 times and runs `dmesg -C` to clear the
   kernel log (anti-forensics).
6. On failure, deletes the temp file and threatens a reboot.

The marker between the script and the ELF is the UTF-8 byte sequence
`0x23 0xE7 0xA6 0xBB 0x0A` (`#离\n`). `离` means "depart / separate".

---

## 3. Reproducible extraction

`extract_all.py` walks `dev增强版过检测/`, finds the `#离` marker in each `.sh`,
slices out the trailing ELF, validates the ELF magic, and writes
`mem_tool_driver/<basename>.ko`. It also copies `dev增强版对接.h` into
`mem_tool_driver/kernel_client.h`.

```
python extract_all.py
```

Verified result for all eight files:

| file       | size (bytes) | class  | arch    | e_type            |
|------------|--------------|--------|---------|-------------------|
| 5.4.ko     | 738 464      | ELF64  | aarch64 | ET_REL (0x1)      |
| 5.4b.ko    | 731 936      | ELF64  | aarch64 | ET_REL (0x1)      |
| 5.4c.ko    | 739 176      | ELF64  | aarch64 | ET_REL (0x1)      |
| 5.10.ko    | 904 016      | ELF64  | aarch64 | ET_REL (0x1)      |
| 5.15.ko    | 918 576      | ELF64  | aarch64 | ET_REL (0x1)      |
| 6.1.ko     | 881 568      | ELF64  | aarch64 | ET_REL (0x1)      |
| 6.6.ko     | 746 320      | ELF64  | aarch64 | ET_REL (0x1)      |
| 6.12.ko    | 692 272      | ELF64  | aarch64 | ET_REL (0x1)      |

All eight are functionally the same project, rebuilt against eight different
Android kernel ABI versions (file names match the upstream Linux kernel
release). Differences in size are dominated by `.modinfo` / `__versions`
(per-symbol CRC table consumed by `insmod`) — the actual `.text` is small.

---

## 4. IDA Pro analysis (`6.6.ko` taken as the canonical sample)

- File: `mem_tool_driver/6.6.ko`
- Architecture: ARM64 (`e_machine = 0xB7`)
- Image size: `0xb078`, `.text` is `0xd5c — 0x4818` (~14 KB)
- Functions: 112 total, 89 already named after auto-analysis
- Hashes:
  - MD5  `f401458ba0227d251840d5856bc8c770`
  - SHA-256 `8eb479d6062c5ff8bd036026dbd8ae4083569e4eb7b1e1a410cc9a32dc6d808f`

### 4.1 Entry-point inventory (named by IDA)

| addr     | symbol                          | role                                 |
|----------|---------------------------------|--------------------------------------|
| `0x9008` | `init_module` / `driver_entry`  | module load                          |
| `0x9520` | `cleanup_module` / `driver_unload` | module unload                     |
| `0xfd8`  | `dispatch_ioctl`                | main ioctl router                    |
| `0x1c3c` | `dispatch_open`                 | `file_operations.open`               |
| `0x1c54` | `dispatch_close`                | `file_operations.release`            |
| `0x578`  | `dispatch_functions`            | `struct file_operations`             |
| `0xd60`  | `get_rand_str`                  | random 6-char device-name generator  |
| `0xf30`  | `util_find_kallsyms`            | resolves un-exported `kallsyms_lookup_name` |
| `0xf98`  | `util_kallsyms_lookup_name`     | wrapper                              |
| `0x1c60` | `hide_module`                   | self-hide from `lsmod`/sysfs         |
| `0x1f9c` | `hide_mount_tmpfs`              | overlay tmpfs on a path              |
| `0x16fc` | `manage_process_visibility`     | hide / recover task by PID           |
| `0x224c` | `my_get_task_struct_by_pid`     | task lookup helper                   |
| `0x22b8` | `translate_linear_address`      | manual page walk                     |
| `0x232c` | `my_copy_to_user`               | PAN-bypass copy_to_user              |
| `0x2484` | `read_physical_address`         | phys R via vmap                      |
| `0x2770` | `write_physical_address`        | phys W via vmap                      |
| `0x2a3c` | `read_process_memory`           | cross-process VM read                |
| `0x2f80` | `write_process_memory`          | cross-process VM write               |
| `0x36a8` | `install_hw_bp`                 | add HW breakpoint                    |
| `0x4334` | `clear_all_hw_bps`              | clear all                            |
| `0x4420` | `enable_hw_bp` / `0x46f4 disable_hw_bp` | toggle                       |
| `0x409c` | `get_hw_bp_hits`                | drain hit ring                       |
| `0x3120` | `toggle_bp_registers_directly`  | direct DBGBVR/DBGBCR MSR writes      |
| `0x450`  | `devicename` (data)             | randomized device name slot          |

### 4.2 ioctl command table (matches `kernel_client.h`)

| cmd      | name                  | argument                              | behaviour |
|----------|-----------------------|---------------------------------------|-----------|
| `0x800`  | `OP_INIT_KEY`         | `char[256]` license / auth string     | gates further use |
| `0x801`  | `OP_READ_MEM`         | `COPY_MEMORY{pid,addr,buf,size}`      | cross-process VM read |
| `0x802`  | `OP_WRITE_MEM`        | `COPY_MEMORY{pid,addr,buf,size}`      | cross-process VM write |
| `0x803`  | `OP_MODULE_BASE`      | `MODULE_BASE{pid,name,base,index}`    | walks target VMAs, matches `d_path` basename, returns base |
| `0x804`  | `OP_CMD_HWBP_ADD`     | `HW_BP_INFO`                           | install ARM64 hardware breakpoint |
| `0x805`  | `OP_CMD_HWBP_GET_HITS`| `HWBP_HIT_ARGS`                        | drain ring of hit records (regs+pc+sp+pstate) |
| `0x806`  | `OP_CMD_HWBP_ENABLE`  | `HW_BP_INFO`                           | re-enable + update                  |
| `0x807`  | `OP_CMD_HWBP_CLEAR`   | -                                      | clear all                           |
| `0x809`  | `OP_CMD_HWBP_DISABLE` | `HW_BP_INFO{pid,addr}`                 | disable                             |
| `0x810`  | `OP_CMD_HIDE_PROCESS` | (none — uses caller pid)              | unlink caller from task list        |
| `0x811`  | `OP_CMD_RECOVER_PROCESS` | (none)                              | re-link                             |

The wall of `_ReadStatusReg(SP_EL0)` / `WriteStatusReg(TTBR0_EL1, ...)` you see
in every read/write case is **PAN bypass**: the driver flips `TTBR0_EL1` to
allow privileged reads of user addresses that ARM64 PAN would normally block.

### 4.3 Stealth / anti-detection in `init_module`

1. `util_find_kallsyms()` — locates `kallsyms_lookup_name` (un-exported in
   kernel 5.7+). Required because the driver wants to call non-exported APIs.
2. `get_rand_str()` — generates a random 6-character device name. The userland
   client in `kernel_client.h::driver_path()` discovers this device by scanning
   `/dev` for a 6-char chardev/blockdev with `atime == ctime`, `size == 0`,
   `uid == gid == 0`, post-1980 ctime. The match criteria are deliberately
   tight to evade signature-based scanners.
3. Resolves un-exported symbols at runtime: `kern_path`, `path_mount`,
   `path_umount`, `path_put`, `tasklist_lock`, `init_task`,
   `vmap_area_list`, `vmap_area_root`.
4. Registers the chrdev (`alloc_chrdev_region` + `cdev_init` + `cdev_add`),
   creates the class and device under that random name.
5. `hide_mount_tmpfs("/sys/class/<rand>")` and `("/sys/devices/virtual/<rand>")`
   — overlays an empty tmpfs (`MS_NOATIME|MS_NODEV|MS_NOEXEC`) on each sysfs
   path so userland tools see nothing under those dirs.
6. `hide_module()` — module-level rootkit:
   - walks `vmap_area_list` / `vmap_area_root`, locates the entry covering
     `&__this_module`, unlinks it from the linked list, poisons with
     `0xDEAD000000000100` / `0xDEAD000000000122`, and removes from the rb-tree
     via `rb_erase`. Hides the module's vmap allocation from `/proc/vmallocinfo`.
   - unlinks `__this_module` from the global module list (the `off_9888` /
     `off_9890` `list_head`). Hides from `lsmod` and `/proc/modules`.
   - `kobject_del` on the module kobject. Hides from `/sys/module/`.
   - walks `mod->modinfo_attrs` and `sysfs_remove_link`s the `devwh` attribute
     symlinks, frees the attr structures.
   - prints `[hook] Module hidden successfully.\n` to dmesg (which the loader
     script then clears with `dmesg -C`).
7. `hide_mount_tmpfs("/data/local/tmp/")` — overlays tmpfs on the dropbox
   directory so any companion files dropped before the mount are invisible to
   userland until the next reboot.

### 4.4 What is **not** in the binary

Every category below was checked against the import table and the function
list. None present:

| capability                  | indicators                                          | present |
|-----------------------------|-----------------------------------------------------|---------|
| Network exfil               | `sock_create_kern`, `kernel_sendmsg`, `kernel_connect`, `tcp_*`, `udp_*` | NO |
| Crypto                      | any `crypto_*`, AES, SHA                            | NO |
| File writes                 | `vfs_write`, `kernel_write`, `filp_open` write mode | NO |
| Background threads          | `kthread_run`, `kthread_create`, workqueues          | NO |
| Syscall-table hook          | writes to `sys_call_table`, ftrace trampolines       | NO |
| Privilege-escalation primitive | `commit_creds(prepare_kernel_cred(NULL))`         | NO |
| Persistence                 | filesystem writes to init scripts / properties       | NO |

The only kernel-→-world I/O is `_printk` (dmesg) and `__arch_copy_to_user` to
the calling userland process. `register_kprobe` / `unregister_kprobe` are
imported but used only for the HW-breakpoint hit-handler plumbing, not for
syscall-wide hooking.

The CFI integrity checks you see in the decompilation (`*((DWORD*)fnptr - 1)
!= <magic>` before each indirect call to a resolved kallsyms address) are
LLVM/Clang Control-Flow-Integrity guards, not malicious — they confirm a
hardened Clang build.

---

## 5. Verdict

It is a **Chinese Android game-cheat rootkit** ("RT驱动 / RTdrivers /
Cycle1337" lineage), almost certainly aimed at FPS / MOBA mobile titles.

- It is genuinely a rootkit by every reasonable definition: module self-hide,
  sysfs tmpfs overlays, process hide, randomized device name, dmesg clear in
  the loader script, runtime resolution of un-exported kernel symbols.
- It is **not** a data-stealing payload. There is no covert channel, no
  encrypted transport, no file write, no background worker, no network stack
  use of any kind inside the `.ko`.
- The danger of running it is therefore not exfiltration *by the driver*, but
  the wide-open kernel-level R/W primitive it exposes via the random
  `/dev/<rand>` device. Once that fd is reachable, **any process holding it
  can dump the memory of every other app on the device** — banking sessions,
  password managers, end-to-end-encrypted messenger keys, ART managed heaps,
  whatever. The cheat client is just one such consumer.
- The Telegram-channel "verification" gate in the wrapper script is
  monetization (must be subscribed to `@RTdrivers` to use the driver), not a
  backdoor or remote-control channel.

---

## 6. Rebuild from the binary?

A `.ko` cannot be turned back into byte-identical source. IDA's pseudocode is
useful for understanding but is not a substitute for source. The eight files
in this bundle are the same logical project compiled against eight different
kernel ABIs, but the source for none of them is present here.

A "rewrite from scratch" of the same primitives produces an equally dangerous
rootkit and is not a security improvement — the threat is the *capability*,
not the binary form. The right move if you don't trust the upstream is **not
to load this category of driver at all**, not to load a hand-rolled clone.

---

## 7. Useful follow-ups

- Dump the `.modinfo` section of each `.ko` to confirm `vermagic` / target
  kernel build flags. Diff the eight files to verify the "same project,
  different ABI" hypothesis.
- Compare `.text` byte-for-byte across the eight (after relocation) — almost
  all the size delta will live in `.modinfo` and `__versions`.
- Re-run the IDA analysis on `5.4.ko` and `6.12.ko` (the size extremes) and
  diff the function inventory to confirm the same set of capabilities.

---

*Generated as part of static analysis of the bundle on 2026-04-25. Files are
kept for analysis purposes only.*
