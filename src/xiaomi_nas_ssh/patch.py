"""Transform an owner's local firmware binary copy; no vendor binary is distributed."""
import hashlib
import struct

from .api import NasError

MENU_SHELL = b"/usr/sbin/mi-shell\0"
POSIX_SHELL = b"/bin/sh\0"


def patch_dropbear(original):
    if len(original) < 64 or original[:7] != b"\x7fELF\x02\x01\x01":
        raise NasError("Expected a 64-bit little-endian ELF binary.")
    if struct.unpack_from("<H", original, 18)[0] != 183:
        raise NasError("Only the reviewed AArch64 binary layout is supported.")
    if original.count(MENU_SHELL) != 1:
        raise NasError("Expected exactly one menu-shell constant; no output was generated.")
    offset = original.index(MENU_SHELL)
    patched = original[:offset] + POSIX_SHELL.ljust(len(MENU_SHELL), b"\0") + original[offset + len(MENU_SHELL):]
    return patched, {"original_sha256": hashlib.sha256(original).hexdigest(),
                     "patched_sha256": hashlib.sha256(patched).hexdigest(),
                     "bytes": len(original), "constant_offset": offset}
