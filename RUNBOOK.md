# RUNBOOK — loading the `mem_tool` kernel module on Android

How the shipped `.ko` loads, what the original self-extracting installer
did (and why we don't reproduce it), and how to load cleanly with
`load_driver.sh`.

## 1. The original installer (context only)

The original distribution shipped one bash file per kernel ABI — each
was not a script but a **self-extracting installer**:

```
[ bash preamble, UTF-8, ~2-3 KB ]
#离                                  ← UTF-8 separator (0x23 0xE7 0xA6 0xBB 0x0A)
[ raw ARM64 ELF (.ko), ~730-920 KB ]
```

Preamble behavior:

| step                                                       | classification            |
|------------------------------------------------------------|---------------------------|
| `[ "$(id -u)" = "0" ]` root check                          | necessary                 |
| Scan Telegram caches for a gated JPEG from `@RTdrivers`    | **monetization gate**     |
| `sed "1,/^#离/d" "$0" > /data/tmpf`                         | strip header, drop ELF    |
| `chmod u+x /data/tmpf && insmod /data/tmpf`                | load                      |
| Spam "success" banner 100×                                 | cosmetic                  |
| `rm /data/tmpf`                                            | **anti-forensic**         |
| `dmesg -C`                                                 | **anti-forensic**         |

We ship neither the installer scripts nor the embedded copies of the
ELFs — the `.ko`s live as plain files under `mem_tool_driver/`, and
`load_driver.sh` does only the strictly-necessary steps (no Telegram
gate, no `dmesg` clear).

## 2. How `insmod` validates the module

On `insmod /path/to/x.ko`:

1. `finit_module(2)` hands the fd to the kernel's module loader.
2. The loader checks the ELF is `ET_REL` for the running `EM_*` and
   that `.modinfo.vermagic=` matches the kernel's compiled-in string.
3. On match: loads `.text/.data/.bss/.rodata` into vmalloc space,
   applies relocations, runs `module_init()`, registers into
   `/proc/modules` and `/sys/module/<name>`.

`vermagic` **must** match — that is why each Android kernel patch-level
gets its own `.ko` build.

### 2.1 Common load errors

| error                                        | meaning                                              |
|----------------------------------------------|------------------------------------------------------|
| `Exec format error`                          | not an ELF, or wrong class/machine                   |
| `Invalid module format`                      | **vermagic mismatch** — wrong `.ko` for this kernel  |
| `Operation not permitted` (EPERM)            | not root, or kernel lockdown (verified boot)         |
| `Unknown symbol in module`                   | imported symbol not in kernel (check `dmesg`)        |
| `Required key not available`                 | `CONFIG_MODULE_SIG_FORCE=y` — unsigned modules refused|

`Required key not available` is fatal on stock Android GKI. The cheat
distribution works only on phones with an unlocked/patched kernel
(KernelSU, custom GKI build, unlocked bootloader).

## 3. `load_driver.sh` vs the original

| feature                     | original | this loader | why                                     |
|-----------------------------|:--------:|:-----------:|-----------------------------------------|
| root check                  |    ✓    |     ✓      | needed                                  |
| Telegram gate               |    ✓    |     ✗      | monetization, not safety                |
| ELF embedded in `.sh`       |    ✓    |     ✗      | `.ko` is a plain file — audit, sign, sha256 before running |
| auto-pick by vermagic       |    ✗    |     ✓      | one-per-version upstream; we do the selection |
| `dmesg -C` after load       |    ✓    |     ✗      | anti-forensic — we keep the log         |
| SELinux permissive switch   |    ✗    |  opt-in    | `--permissive`                          |
| report created chardev      |    ✗    |     ✓      | so the userland client knows what to open|

### 3.1 Selection table

| `uname -r` match                                         | picked `.ko`             |
|----------------------------------------------------------|--------------------------|
| `5.4.*` + `qgki` + patch ≤ 170                           | `mem_tool_driver/5.4.ko` |
| `5.4.*` + `qgki` + patch ≥ 180                           | `mem_tool_driver/5.4c.ko`|
| `5.4.*` + non-qgki                                       | `mem_tool_driver/5.4b.ko`|
| `5.10.*`                                                 | `mem_tool_driver/5.10.ko`|
| `5.15.*`                                                 | `mem_tool_driver/5.15.ko`|
| `6.1.*`                                                  | `mem_tool_driver/6.1.ko` |
| `6.6.*`                                                  | `mem_tool_driver/6.6.ko` |
| `6.12.*`                                                 | `mem_tool_driver/6.12.ko`|

Override: `KO=path/to/any.ko sh load_driver.sh` or
`KO_DIR=path/to/dir sh load_driver.sh`.

## 4. Quick start

```bash
# on-device as root (Termux + tsu, or `adb root`):
cd /sdcard/mem_tool/              # or wherever you pushed the tree
sh ./load_driver.sh
```

Expected on a supported kernel:

```
[load] uname -r        : 6.6.57-4k-gd66e9166bfa1
[load] major.minor     : 6.6
[load] picked          : mem_tool_driver/6.6.ko
[load] sha256          : 1a2b...
[load] modinfo vermagic: 6.6.57-4k-gd66e9166bfa1-dirty SMP preempt mod_unload modversions aarch64
[ ok ] insmod succeeded
[ ok ] chardev         : /dev/xT8q9K
```

After that, any userland tool that `#include`s `kernel_client.h` will
find the chardev via its 6-char scan.

## 5. Unloading

```bash
rmmod mem_tool                        # or whatever .modinfo name= is
sh ./load_driver.sh --force-recover   # tries every plausible name
```

Because the module unlinks itself from the global module list on load,
`rmmod` sometimes works anyway (the kernel also walks the module
rb-tree via `find_module`). If both fail, reboot.

## 6. Android prerequisites

| concern                      | check                                                                                  |
|------------------------------|----------------------------------------------------------------------------------------|
| SELinux                      | `getenforce` — `Enforcing` may need an sepolicy patch; try `--permissive`              |
| Verified boot                | `getprop ro.boot.verifiedbootstate` — `orange` (unlocked) or custom kernel required    |
| GKI + module signing         | `zcat /proc/config.gz \| grep MODULE_SIG` — `_FORCE=y` means no unsigned `insmod`       |
| Root                         | `su -c id` must yield `uid=0`                                                          |
| Chardev creation             | `/sys/class` must be writable (default)                                                |
| SEAndroid init               | very recent kernels may need allow rules for tmpfs overlays under `/sys/class/<rand>`  |

## 7. Ethical note

Loading this module opens ring-0 R/W across every process on the
device. On a daily phone, that means banking apps, password managers,
Signal session state, and every other credential store — not just the
game you're patching. Use a throwaway device or an emulator.
