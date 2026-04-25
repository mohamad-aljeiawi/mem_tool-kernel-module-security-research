# RUNBOOK -- loading the devwh kernel module on Android

This explains exactly how the original `dev/*.sh` self-extracting
loaders work, why they were designed that way, which parts are
legitimate and which are user-hostile, and how to load the module
cleanly instead.

## 1. TL;DR of the original `dev/*.sh` loaders

Each of `dev/5.4.sh` … `dev/6.12.sh` is **not** a shell script. It is:

```
    [ bash loader, UTF-8, ~2-3 KB ]
    #离
    [ raw ARM64 ELF (.ko), ~730-920 KB ]
```

`#离` (Chinese for "leave") is the separator marker. `sed` is used at
run-time to strip everything up to that marker and write the remaining
bytes to a tempfile, which is then `insmod`'d.

### 1.1 Annotated pseudocode of the original loader

```bash
#@RTdrivers                                  # author/channel banner
ESC="\e[";                                   # ANSI color setup
clear
echo -e "RT-dev增强版过检测"                # "RT-dev advanced bypass detection" banner

# --- 1. root check ---
[ "$(id -u)" = "0" ] || { echo "需要 root"; exit 1; }

# --- 2. "channel verification" (MONETIZATION GATE) ---
#     scans every Telegram-family package's cache for a specific JPEG.
#     the JPEG is a file you can only get from @RTdrivers on Telegram,
#     which you can only access after paying.
PACKAGE_NAMES=(org.telegram.messenger ... nekox.messenger ...)
FILE_NAMES=(cache/-6201945136796122720_99.jpg ...)
for pkg in "${PACKAGE_NAMES[@]}"; do
    for f in "${FILE_NAMES[@]}"; do
        [ -f "/storage/emulated/0/Android/data/$pkg/$f" ] && break 2
    done
done
# if not found -> prompt user to open @RTdrivers and exit

# --- 3. strip header + extract embedded ELF ---
Variables=/data/tmpf
rm -f "$Variables"
sed "1,/^#离/d" "$0" > "$Variables"          # everything after "#离" -> /data/tmpf
chmod u+x "$Variables"                        # cosmetic; insmod does not need +x

# --- 4. load ---
if insmod "$Variables"; then
    for i in $(seq 1 100); do                 # spam success banner 100x
        echo "RT驱动加载成功!!!!频道@RTdrivers"
    done
    rm -f "$Variables"
    dmesg -C                                  # ANTI-FORENSICS: wipe kernel log
else
    rm -f "$Variables"
    echo "驱动加载失败!!!!"
    sleep 5
    exit 1
fi
exit 0
#离
<...raw ELF bytes follow, 730-920 KB...>
```

### 1.2 What each step actually does

| Step | Purpose | Classification |
|------|---------|----------------|
| Root check | `insmod` requires CAP_SYS_MODULE | Necessary |
| Telegram cache scan | Gatekeeps to paying customers who joined @RTdrivers | **Monetization, not a safety feature** |
| `sed "1,/^#离/d"` | Strips the bash header; rest is the ELF | Reasonable; but makes audit harder on purpose |
| `insmod /data/tmpf` | Kernel loads the module, calls `init_module`, which registers a random-named chardev | Necessary for the feature |
| 100× success banner | Cosmetic | Harmless |
| `rm /data/tmpf` | Removes the extracted ELF before anyone can grab it | **Anti-forensic** |
| `dmesg -C` | **Clears the kernel ring buffer** right after load, hiding the module's `pr_info()` lines and any complaint from the kernel about the rootkit behavior | **Anti-forensic** |

## 2. How `insmod` loads a kernel module (background)

When root runs `insmod /data/tmpf` on Android:

1. `insmod` calls `finit_module(2)` with the fd of the `.ko`.
2. The kernel's module loader (`kernel/module/main.c`) reads the ELF,
   validates it is `ET_REL` for the current `EM_*`, and checks the
   `vermagic=` field in `.modinfo` against its own compiled-in string.
3. If vermagic matches, it:
   - loads the `.text/.data/.bss/.rodata` into freshly-allocated
     vmalloc space (where the module self-hide later unlinks it from),
   - applies relocations,
   - runs `module_init()` (our `devwh_init`),
   - adds the module to `/sys/module/<name>` and to
     `cat /proc/modules`.

Vermagic **must** match. The reason you ship one `.ko` per kernel version
is that `5.4.61-qgki` and `5.4.191` emit different vermagic strings, and
the kernel rejects the load otherwise.

### 2.1 Possible load failures and what they mean

| Error                                        | Meaning                                                |
|----------------------------------------------|--------------------------------------------------------|
| `insmod: Exec format error`                  | Not an ELF, or wrong ELF class/machine                 |
| `insmod: Invalid module format`              | **Vermagic mismatch** -- wrong .ko for this kernel     |
| `insmod: Operation not permitted` (`EPERM`)  | Not root, or kernel is locked-down (verified boot)     |
| `insmod: No such file or directory`          | A symbol the module imports is not in the kernel       |
| `insmod: Unknown symbol in module`           | Same as above; check `dmesg` for the symbol name       |
| `insmod: Required key not available`         | Kernel requires module signing (common on GKI)         |

"Required key not available" is the fatal one on modern Android GKI
builds -- `CONFIG_MODULE_SIG_FORCE=y` refuses any unsigned module. The
original cheat distribution gets around this because it only works on
phones where the user already installed an unlocked/patched kernel
(KernelSU, custom GKI build, or a bootloader-unlocked device). If your
device has `CONFIG_MODULE_SIG_FORCE=y` and you don't have the signing
key, the module will never load, full stop.

## 3. What we keep, what we throw away

The goal of `load_driver.sh` (next section) is "load the right `.ko` for
this device, loudly". Compared to the originals:

| Feature                     | Original | This loader | Why |
|-----------------------------|:--------:|:-----------:|-----|
| root check                  |    ✅    |     ✅      | needed |
| Telegram gate               |    ✅    |     ❌      | monetization, not safety |
| embed ELF inside .sh        |    ✅    |     ❌      | `.ko` file lives alongside; easier to audit, checksum, sign |
| auto-pick matching vermagic |    ❌    |     ✅      | the originals are one-per-version; we do the selection |
| `dmesg -C` after load       |    ✅    |     ❌      | anti-forensic; we *want* to see `pr_info()` |
| retry on failure            |    ❌    |     ❌      | if it doesn't load, fix it, don't paper over |
| SELinux permissive switch   |    ❌    |  optional   | some kernels need it; opt-in via `--permissive` |
| dump device node on success |    ❌    |     ✅      | so you know what the client will attach to |

## 4. Running it -- quick start

```bash
# on the Android device, as root (Termux + tsu, or adb root):
cd /sdcard/kernel-module/                # wherever you pushed the tree
sh ./load_driver.sh
```

Expected output on a supported kernel:

```
[load] uname -r        : 6.6.57-4k-gd66e9166bfa1
[load] major.minor     : 6.6
[load] vermagic family : 6.6.57-4k
[load] picked          : mem_tool_driver/6.6.ko
[load] sha256          : 1a2b...
[load] modinfo vermagic: 6.6.57-4k-gd66e9166bfa1-dirty SMP preempt mod_unload modversions aarch64
[load] insmod ... ok
[load] chardev         : /dev/xT8q9K
[load] module list     : devwh
```

After that, any userland tool that `#include`s `kernel_client.h` will
find the device via the 6-char scan in its constructor. See `CLIENT.md`.

## 5. Unloading / panic recovery

```bash
# clean unload
rmmod devwh                               # or "devddyc" on 6.12

# if the module self-hid itself (default), rmmod may say "module not found"
# because it is no longer in /proc/modules. In that case:
sh ./load_driver.sh --force-recover       # tries to rmmod every plausible name
# or, as a last resort: reboot the device.
```

Because the module unlinks itself from the module list on init, the only
reliable way to unload it is:

1. Build with `hide_module()` disabled (add a `devwh.hide=0` module
   parameter and gate the call), **or**
2. Remember the name you registered and pass it to `rmmod` before the
   module list re-links on rmmod-time (the kernel handles that on the
   `rmmod` path because it looks up via `find_module`, which also
   searches the module RBTree -- so `rmmod <name>` often works even
   after self-hide, but not always).
3. If (1) and (2) both fail, reboot.

## 6. Android specifics

| Concern                          | What to check                                                               |
|----------------------------------|------------------------------------------------------------------------------|
| SELinux                          | `getenforce` = Permissive (Enforcing needs an sepolicy patch)                |
| Verified boot                    | `adb shell getprop ro.boot.verifiedbootstate` must be `orange` (unlocked) or you need a custom kernel |
| GKI + signed modules             | `zcat /proc/config.gz \| grep -E 'MODULE_SIG(_|\w)='`; if `_FORCE=y` you cannot `insmod`  |
| Root                             | `su -c id` returning `uid=0` is required                                     |
| Chardev creation                 | the module calls `device_create`, so you need `/sys/class` writable (default) |
| SEAndroid init                   | on very recent kernels, `tmpfs` overlay of `/sys/class/<rand>` needs additional allow rules |

## 7. Legal / ethical note

`insmod`'ing this module gives any userland process unrestricted R/W
into every other process on the device. That is equivalent to handing
`root` to anything on the phone, not just to you. Even if you personally
only run it against one game, you have opened a ring-0 hole that any
other app can walk through.

Loading on your daily phone -- the one with your bank app, password
manager, Signal, chat history, Gmail -- is a bad idea regardless of the
author's intent. Use a secondary device or an emulator.

## 8. What the new `load_driver.sh` does

See `load_driver.sh` in this directory. It is ~130 lines of POSIX shell
and its selection table is:

| `uname -r` substring match                               | Picks                              |
|----------------------------------------------------------|------------------------------------|
| `5.4.` + contains `qgki` + kernel ≤ 5.4.170              | `mem_tool_driver/5.4.ko`           |
| `5.4.` + contains `qgki` + kernel ≥ 5.4.180              | `mem_tool_driver/5.4c.ko`          |
| `5.4.` + **no** `qgki`                                   | `mem_tool_driver/5.4b.ko`          |
| `5.10.`                                                  | `mem_tool_driver/5.10.ko`          |
| `5.15.`                                                  | `mem_tool_driver/5.15.ko`          |
| `6.1.`                                                   | `mem_tool_driver/6.1.ko`           |
| `6.6.`                                                   | `mem_tool_driver/6.6.ko`           |
| `6.12.`                                                  | `mem_tool_driver/6.12.ko` (module name becomes `devddyc`, not `devwh`) |

Override with `KO=/path/to/any.ko sh load_driver.sh`. Override the
search dir with `KO_DIR=/somewhere sh load_driver.sh`.
