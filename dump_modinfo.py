import os, sys, struct, glob, json

DST = r"C:\Users\mohamadaljeiawi\Desktop\kernel-module\mem_tool_driver"

def parse_elf(buf):
    assert buf[:4] == b"\x7fELF" and buf[4] == 2, "not ELF64"
    e_shoff     = struct.unpack_from("<Q", buf, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", buf, 0x3a)[0]
    e_shnum     = struct.unpack_from("<H", buf, 0x3c)[0]
    e_shstrndx  = struct.unpack_from("<H", buf, 0x3e)[0]
    sects = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name   = struct.unpack_from("<I", buf, off + 0x00)[0]
        sh_type   = struct.unpack_from("<I", buf, off + 0x04)[0]
        sh_offset = struct.unpack_from("<Q", buf, off + 0x18)[0]
        sh_size   = struct.unpack_from("<Q", buf, off + 0x20)[0]
        sh_link   = struct.unpack_from("<I", buf, off + 0x28)[0]
        sh_entsize= struct.unpack_from("<Q", buf, off + 0x38)[0]
        sects.append(dict(name_off=sh_name, type=sh_type, offset=sh_offset,
                          size=sh_size, link=sh_link, entsize=sh_entsize))
    shstr = sects[e_shstrndx]
    strtab = buf[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for s in sects:
        end = strtab.find(b"\x00", s["name_off"])
        s["name"] = strtab[s["name_off"]:end].decode("ascii", "replace")
    return sects

def find_section(sects, name):
    for s in sects:
        if s["name"] == name:
            return s
    return None

def dump_modinfo(buf, sects):
    s = find_section(sects, ".modinfo")
    if not s:
        return []
    blob = buf[s["offset"]:s["offset"] + s["size"]]
    items = [b.decode("utf-8", "replace") for b in blob.split(b"\x00") if b]
    return items

def count_versions(buf, sects):
    s = find_section(sects, "__versions")
    if not s:
        return 0
    return s["size"] // 0x40   # struct modversion_info is 8B crc + 56B name

def text_size(sects):
    s = find_section(sects, ".text")
    return s["size"] if s else 0

results = []
for path in sorted(glob.glob(os.path.join(DST, "*.ko"))):
    buf = open(path, "rb").read()
    sects = parse_elf(buf)
    info = dump_modinfo(buf, sects)
    nver = count_versions(buf, sects)
    tsz  = text_size(sects)
    name = os.path.basename(path)
    results.append(dict(file=name, size=len(buf), text=tsz,
                        version_syms=nver, modinfo=info))

with open(os.path.join(DST, "_modinfo_dump.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

for r in results:
    sys.stdout.buffer.write(("\n=== " + r["file"] + " ===\n").encode("utf-8"))
    sys.stdout.buffer.write(("  total=" + str(r["size"]) +
                             "  .text=" + str(r["text"]) +
                             "  __versions count=" + str(r["version_syms"]) + "\n").encode("utf-8"))
    for line in r["modinfo"]:
        sys.stdout.buffer.write(("    " + line + "\n").encode("utf-8"))

sys.stdout.buffer.write(("\nWrote " + os.path.join(DST, "_modinfo_dump.json") + "\n").encode("utf-8"))
