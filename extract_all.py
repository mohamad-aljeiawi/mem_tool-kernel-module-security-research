import os, sys, struct, glob

SRC_DIR = r"C:\Users\mohamadaljeiawi\Desktop\kernel-module\dev增强版过检测"
DST_DIR = r"C:\Users\mohamadaljeiawi\Desktop\kernel-module\mem_tool_driver"
HDR_SRC = r"C:\Users\mohamadaljeiawi\Desktop\kernel-module\dev增强版对接.h"

MARKER = b"#\xe7\xa6\xbb\n"

EM_MAP = {0x3e: "x86_64", 0xb7: "aarch64", 0x28: "arm32", 0xf3: "riscv"}

os.makedirs(DST_DIR, exist_ok=True)

ok = 0
for src in sorted(glob.glob(os.path.join(SRC_DIR, "*.sh"))):
    raw = open(src, "rb").read()
    i = raw.find(MARKER)
    if i < 0:
        sys.stdout.buffer.write(("SKIP (no marker): " + os.path.basename(src) + "\n").encode("utf-8"))
        continue
    elf = raw[i + len(MARKER):]
    if elf[:4] != b"\x7fELF":
        sys.stdout.buffer.write(("SKIP (not ELF after marker): " + os.path.basename(src) + "\n").encode("utf-8"))
        continue
    ei_class = elf[4]
    ei_data = elf[5]
    e_machine = struct.unpack_from("<H", elf, 0x12)[0]
    e_type = struct.unpack_from("<H", elf, 0x10)[0]
    base = os.path.basename(src).rsplit(".sh", 1)[0]
    out_name = base + ".ko"
    out = os.path.join(DST_DIR, out_name)
    open(out, "wb").write(elf)
    arch = EM_MAP.get(e_machine, "0x%x" % e_machine)
    sys.stdout.buffer.write(("OK  " + out_name + "  size=" + str(len(elf)) +
                             "  class=ELF" + ("64" if ei_class == 2 else "32") +
                             "  arch=" + arch +
                             "  e_type=0x%x" % e_type + "\n").encode("utf-8"))
    ok += 1

import shutil
shutil.copy2(HDR_SRC, os.path.join(DST_DIR, "kernel_client.h"))
sys.stdout.buffer.write(("\nWrote " + str(ok) + " .ko files + kernel_client.h to " + DST_DIR + "\n").encode("utf-8"))
