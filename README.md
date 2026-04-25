# FT-2.2.0 Kernel Module Extraction Toolkit

> One command. One `.sh` from the FT2.2.0 distribution. Get the underlying `X.XX.ko` ready for IDA Pro.

```bash
./extract.sh drivers/X.XX.sh
# -> output/5.10.ko
```

## What this is

A reproducible pipeline for extracting the kernel module that the FT-2.2.0 (`telegram @nullnb6`) Android memory-research userland tool loads at runtime via `init_module(2)`.

The challenge: the userland binary is packed, anti-debugged, statically linked, and the `.ko` it loads exists in user memory only for a few tens of milliseconds — between decryption and `init_module` consuming it. After load, the module **rootkit-hides** itself from `/proc/modules`, `/sys/module/`, and `lsmod`.

This toolkit catches the `.ko` *before* it reaches the kernel by installing a kernel **kprobe** on `__arm64_sys_init_module` and reading `/proc/<pid>/mem` at the captured `umod` address from a small **NDK-compiled C dumper** that reacts in microseconds.

## Quick start

### 0. Requirements

- An adb-connected, **rooted** (Magisk) Android device with the matching kernel sub-version
- `adb` on PATH (`adb devices` shows your device as `device`)
- Optional: Android NDK on `$NDK_PATH` (only needed if you want to rebuild the dumper)
- The toolkit ships a **prebuilt `prebuilt/dumper`** for aarch64 Android API 33+, so NDK is optional

### 1. One-shot extraction

```bash
./extract.sh drivers/X.XX.sh
```

The script will:

1. Unpack the `.sh` self-extractor → `tmp/<name>.elf`
2. Push `dumper` and `<name>.elf` to `/data/local/tmp/`
3. **Reboot the device** (required — see [HOW-IT-WORKS.md](docs/02-HOW-IT-WORKS.md#why-reboot))
4. Start the dumper as root, run the binary
5. Pull the captured `.ko` to `output/<name>.ko`

Tip: pass `--no-reboot` if `bing_rw` definitely isn't loaded (e.g. you just rebooted manually).

### 2. Open in IDA Pro

The output `.ko` is a clean, unmodified, on-disk-form `ET_REL` ELF — no header fixup needed. Just:

```
File → Open → X.XX.ko → "Elf64 for ARM (ARM64) [elf64.dll]" → OK
```

Sections, symbols, `.modinfo`, `vermagic` are all intact.

## Layout

```
.
├── README.md                    # this file
├── extract.sh                   # main entry point
├── docs/
│   ├── 01-SESSION-STORY.md      # how this was figured out (engaging narrative)
│   ├── 02-HOW-IT-WORKS.md       # deep technical walk-through
│   ├── 03-DIAGRAMS.md           # Mermaid diagrams of every moving part
│   └── 04-TROUBLESHOOTING.md    # errors we hit and how to fix them
├── drivers/                     # FT-2.2.0 .sh self-extractors, one per kernel
├── src/
│   └── dumper.c                 # the kprobe + /proc/<pid>/mem dumper
├── tools/
│   ├── unpack-sh.sh             # gunzips a FT-2.2.0 .sh into a .elf
│   ├── build-dumper.sh          # NDK rebuild of dumper (optional)
│   └── on-device-runner.sh      # the script the device runs as root
├── prebuilt/
│   └── dumper                   # statically-linked aarch64 dumper, ready to push
├── client/                      # userland client for the bing_rw .ko
│   ├── CLIENT.md                # API reference (2026-04 contract, re-verified via IDA)
│   └── kernel_client.h          # C++ header to #include from your own tool
├── tmp/                         # scratch (unpacked .elf intermediates)
└── output/                      # extracted .ko files land here
```

> The `client/` folder is not part of the `extract.sh` pipeline — it
> covers the complementary case of *talking to* an already-loaded
> `bing_rw` driver rather than extracting the FT-2.2.0 `.ko`. See
> [`client/CLIENT.md`](client/CLIENT.md) for the opcode contract,
> which changed substantially in the Apr 2026 driver rebuild.

## Reading order

If you just want **the result**: run `./extract.sh`. Done.

If you want to **understand** what just happened, read in order:

1. [`docs/01-SESSION-STORY.md`](docs/01-SESSION-STORY.md) — the analyst's-perspective story of how this was figured out, including every dead end
2. [`docs/02-HOW-IT-WORKS.md`](docs/02-HOW-IT-WORKS.md) — every technical detail: kprobe pt_regs deref, MTE tag stripping, why kcore is gone, how the rootkit hides
3. [`docs/03-DIAGRAMS.md`](docs/03-DIAGRAMS.md) — Mermaid sequence and flow diagrams
4. [`docs/04-TROUBLESHOOTING.md`](docs/04-TROUBLESHOOTING.md) — when things break

## Credits

- The userland tool: `@nullnb6` (Telegram), distributed as the FT-2.2.0 bundle.
- The kernel module being extracted: `X.XX.ko` (vermagic X.XX.223-android12-9-...).
- Memory-dump-ELF rebasing tool: <https://github.com/mohamad-aljeiawi/android-memdump-elf> — useful for the *userland* halves of these scripts (the packed PIE), but **not needed** for the `.ko` this toolkit extracts (the dumped bytes are already in on-disk form).
