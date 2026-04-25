#!/usr/bin/env bash
#
# unpack-sh.sh — offline unpacker for FT-2.2.0 .sh self-extractors.
#
# Structure of every FT2.2.0/X.X.sh file:
#   Line 1 : "#Telegram @nullnb6"
#   Line 2 : single-line shell stub that gzip-decodes the rest and execs it
#   Line 3+: gzip-compressed aarch64 ELF (the userland binary)
#
# We don't need to execute the stub. We just skip the first two lines and pipe
# the remainder through gunzip. That gives us the exact same bytes the on-device
# stub would have written to /data/local/tmp/driver:<random>.
#
# Usage:
#   ./unpack-sh.sh path/to/X.X.sh [out_elf]
#
# If out_elf is omitted, writes <dir-of-input>/<stem-of-input>.elf next to the
# input file.
#
# Exit codes:
#   0  success, wrote an ELF
#   1  argument error
#   2  input file missing
#   3  gunzip failed (truncated / non-gzip payload)
#   4  output file is not an ELF (shouldn't happen on a real FT sh)

set -euo pipefail

usage() {
    cat >&2 <<EOF
usage: $(basename "$0") <input.sh> [output.elf]

Unpacks a FT-2.2.0 .sh self-extractor into its embedded aarch64 ELF.
No device needed; purely offline.
EOF
    exit 1
}

[ $# -lt 1 ] && usage

IN="$1"
[ -f "$IN" ] || { echo "[-] input not found: $IN" >&2; exit 2; }

if [ $# -ge 2 ]; then
    OUT="$2"
else
    d=$(dirname -- "$IN")
    b=$(basename -- "$IN")
    stem="${b%.sh}"
    OUT="$d/$stem.elf"
fi

# The stub itself lives on line 2, payload starts at line 3. `tail -n +3`
# emits everything from line 3 to EOF. Piping through gunzip is the same
# operation the device-side stub does, just without wrapping it in a shell.
tail -n +3 -- "$IN" | gunzip -c > "$OUT" || {
    echo "[-] gunzip failed; file may be truncated or not a FT-2.2.0 .sh" >&2
    rm -f "$OUT"
    exit 3
}

# Sanity-check: the first four bytes must be the ELF magic.
magic=$(head -c 4 -- "$OUT" | od -An -tx1 -N4 | tr -d ' \n')
if [ "$magic" != "7f454c46" ]; then
    echo "[-] unpacked payload is not an ELF (magic=$magic)" >&2
    exit 4
fi

# Print a small summary so calling scripts can parse it if they want.
size=$(wc -c < "$OUT" | tr -d ' ')
echo "[+] unpacked $(basename -- "$IN") -> $OUT ($size bytes)"
