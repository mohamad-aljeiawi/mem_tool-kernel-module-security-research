# `mem_tool` — Android ARM64 Kernel Rootkit — Static RE & Audit

Reverse-engineering notes, verified ioctl contract, a clean loader, a userland
client header, and a source-level audit rebuild of the Android ARM64 LKM
distributed in the wild under the names **RT驱动 / RTdrivers / Cycle1337**
(internal symbol prefix `mem_tool_*`).

---

## 0. Attribution & safety

- **Original author/distributor:** `@RTdrivers` on Telegram — <https://t.me/RTdrivers>.
- **This repo:** third-party static analysis & audit rebuild. Not affiliated
  with, or endorsed by, the original author.
- **Threat class:** rootkit-grade LKM. Exposes arbitrary cross-process ring-0
  R/W, self-hides from `lsmod` / `/proc/modules` / `/sys/module`, overlays
  tmpfs on sysfs paths, bypasses ARM64 PAN via direct `TTBR0_EL1` writes.
- **Do not `insmod` on a device you use.** Any process with an fd on the
  random chardev gets kernel R/W across every app on the phone.
- **License/reuse:** redistributed here under fair-use for security research,
  malware classification, and education. If you are the original author or a
  rights-holder and need artifacts removed, open an issue.

---

## 1. Repository layout

```
.
├── README.md                         ← this file
├── CLIENT.md                         ← how to use kernel_client.h
├── RUNBOOK.md                        ← how to load the .ko cleanly
├── load_driver.sh                    ← clean auto-selecting loader
│
├── mem_tool_driver/                  ← analyzed prebuilt binaries
│   ├── 5.4.ko  5.4b.ko  5.4c.ko     ELF64 / aarch64 / ET_REL
│   ├── 5.10.ko 5.15.ko
│   ├── 6.1.ko  6.6.ko  6.12.ko
│   └── kernel_client.h               userland C++ client header
│
└── devwh-src/                        ← clean-room source rebuild
    ├── Makefile Kbuild README.md
    ├── uapi/devwh_uapi.h             ioctl contract (kernel ⇄ userland)
    ├── main.c  rand.c  kallsyms.c
    ├── hide.c  memrw.c  hwbp.c  fops.c
```

Self-extracting installer scripts (the `dev/*.sh` files shipped by the
original distribution) are **not** included; they are Telegram-gated
monetization wrappers that `dmesg -C` after load. Use `load_driver.sh`
against the `.ko` directly.

---

## 2. Shipped `.ko` inventory

All eight files are the same logical project rebuilt against different
Android kernel ABIs (vermagic-locked).

| file      | size (bytes) |
|-----------|--------------|
| 5.4.ko    | 738,464      |
| 5.4b.ko   | 731,936      |
| 5.4c.ko   | 739,176      |
| 5.10.ko   | 904,016      |
| 5.15.ko   | 918,576      |
| 6.1.ko    | 881,568      |
| 6.6.ko    | 746,320      |
| 6.12.ko   | 692,272      |

All are `ELF64 / aarch64 / ET_REL`. Size delta lives almost entirely in
`.modinfo` + `__versions` (per-symbol CRC table consumed by `insmod`).

---

## 3. Verified ioctl contract (IDA Pro, 5.4 / 5.10 / 6.12)

`dispatch_ioctl` was disassembled and decompiled on `5.4.ko`, `5.10.ko`,
and `6.12.ko`. The dispatch table is identical across all three:

| cmd    | handler                      | status     | arg                                         |
|--------|------------------------------|------------|---------------------------------------------|
| 0x801  | `read_process_memory`        | supported  | `COPY_MEMORY{pid, addr, buf, size}`         |
| 0x802  | `write_process_memory`       | supported  | `COPY_MEMORY{pid, addr, buf, size}`         |
| 0x803  | module-base resolver         | supported  | `MODULE_BASE{pid, name, base, index}`       |
| 0x807  | `clear_all_hw_bps`           | supported  | —                                           |
| 0x810  | `manage_process_visibility`  | supported  | none — hides the **calling** PID (`SP_EL0`) |
| 0x811  | `manage_process_visibility`  | supported  | none — unhides the **calling** PID          |
| else   | returns `-EINVAL`            | unsupported| —                                           |

### 3.1 Dead code in every shipped binary

The following handlers are compiled into the `.ko` but have **zero xrefs**
from the dispatcher — they are unreachable:

- `0x800` `OP_INIT_KEY` — no handler present
- `0x804` `OP_CMD_HWBP_ADD`
- `0x805` `OP_CMD_HWBP_GET_HITS`
- `0x806` `OP_CMD_HWBP_ENABLE`
- `0x809` `OP_CMD_HWBP_DISABLE`

The user-space header in `mem_tool_driver/kernel_client.h` has been
trimmed to the reachable subset. The corresponding structs and macros
(`HW_BP_INFO`, `HWBP_HIT_ARGS`, etc.) exist only in `devwh-src/uapi/`
for the source rebuild, which wires all of them up.

### 3.2 PAN bypass

The repeating `mrs x?, SP_EL0` / `msr TTBR0_EL1, x?` sequence in every
memory handler is the driver flipping `TTBR0_EL1` so the kernel can
privileged-read user pages that ARM64 **PAN** (Privileged Access Never)
would otherwise block.

---

## 4. Runtime behavior (from `init_module`)

`mem_tool` sets up stealth and device registration in this order:

1. **Symbol resolver.** `util_find_kallsyms()` locates `kallsyms_lookup_name`
   (un-exported since 5.7) so the driver can reach non-exported APIs:
   `kern_path`, `path_mount`, `path_umount`, `path_put`, `tasklist_lock`,
   `init_task`, `vmap_area_list`, `vmap_area_root`.
2. **Random chardev name.** `get_rand_str()` generates a 6-char alphanumeric
   name. `alloc_chrdev_region` + `cdev_init`/`cdev_add` + `device_create`
   register it. The client probes `/dev` for a char/block node that matches
   `len == 6 && atime == ctime && size == 0 && uid == gid == 0 && ctime > 1980`.
3. **Sysfs hide.** `hide_mount_tmpfs()` overlays an empty tmpfs
   (`MS_NOATIME|MS_NODEV|MS_NOEXEC`) onto `/sys/class/<rand>` and
   `/sys/devices/virtual/<rand>`.
4. **Module self-hide.**
   - Walks `vmap_area_list`/`vmap_area_root`, locates the entry covering
     `&__this_module`, unlinks it, poisons with `0xDEAD000000000100` /
     `0xDEAD000000000122`, and `rb_erase`s it. Hides from
     `/proc/vmallocinfo`.
   - Unlinks `__this_module` from the global module list (hides from
     `lsmod` / `/proc/modules`).
   - `kobject_del` on the module kobject (hides from `/sys/module/`).
   - Walks `mod->modinfo_attrs` and `sysfs_remove_link`s the symlinks.
5. **/data/local/tmp overlay.** `hide_mount_tmpfs("/data/local/tmp/")`
   hides any companion files dropped there before load.

---

## 5. What the binary does **not** do

Checked against the import table and function list:

| capability                          | present |
|-------------------------------------|---------|
| Network (sock_create_kern, tcp_*…)  | no      |
| Crypto (crypto_*, AES, SHA)         | no      |
| File writes (vfs_write, kernel_write)| no     |
| Background threads (kthread, workqueue)| no   |
| Syscall-table hook / ftrace         | no      |
| `commit_creds(prepare_kernel_cred)` | no      |
| Persistence (fs writes)             | no      |

The only kernel→world I/O is `_printk` (dmesg) and `__arch_copy_to_user`
to the calling process. `register_kprobe` is imported but only for
HW-breakpoint hit-handler plumbing, not for syscall-wide hooking. The
`*((u32*)fn - 1) != <magic>` checks before every indirect call are LLVM
**CFI** guards, not malicious — they confirm a hardened Clang build.

---

## 6. Verdict

Chinese Android game-cheat rootkit (FPS/MOBA mobile). Rootkit by every
reasonable definition (module self-hide, tmpfs sysfs overlays, process
hide, randomized device name, runtime kallsyms resolution), but **not**
a data-stealing payload — no covert channel, no file write, no network.
The danger is the ring-0 R/W primitive it exposes: any process holding
the fd can dump every other app's memory (banking sessions, password
managers, E2EE keys, ART heaps). The Telegram gate in the original
wrapper script is monetization, not a backdoor.

A source-level "rewrite" of the same primitives produces an equally
dangerous rootkit and is not a security improvement; see `devwh-src/`
strictly as an audit artifact.

---

## 7. Further reading

- **`CLIENT.md`** — `kernel_client.h` usage and API.
- **`RUNBOOK.md`** — loader walkthrough and load troubleshooting.
- **`devwh-src/README.md`** — source-level audit rebuild.
