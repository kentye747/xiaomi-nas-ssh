"""Execute generated AArch64 instructions in an emulator; syscalls are intercepted."""

import unittest

from xiaomi_nas_ssh.trigger import build_trigger

try:
    from unicorn import UC_ARCH_ARM64, UC_HOOK_INTR, UC_MODE_ARM, Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X8,
        UC_ARM64_REG_X30,
    )
except ImportError:
    Uc = None


@unittest.skipIf(Uc is None, "Install the test extra for AArch64 emulation")
class TriggerEmulationTests(unittest.TestCase):
    def emulate(self, uid=0, rename=0, clone=0):
        stage = "/etc/.nas-ssh-0123456789ab"
        base, stack, stop = 0x100000, 0x200000, 0x108000
        vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        vm.mem_map(base, 0x10000)
        vm.mem_map(stack, 0x10000)
        vm.mem_write(base, build_trigger(stage))
        vm.reg_write(UC_ARM64_REG_SP, stack + 0x8000)
        vm.reg_write(UC_ARM64_REG_X30, stop)
        calls = []

        def string(address):
            return bytes(vm.mem_read(address, 256)).split(b"\0", 1)[0].decode()

        def syscall(uc, interrupt, _):
            number = uc.reg_read(UC_ARM64_REG_X8)
            args = [
                uc.reg_read(r)
                for r in (
                    UC_ARM64_REG_X0,
                    UC_ARM64_REG_X1,
                    UC_ARM64_REG_X2,
                    UC_ARM64_REG_X3,
                    UC_ARM64_REG_X4,
                )
            ]
            calls.append(number)
            if number == 174:
                result = uid
            elif number == 276:
                self.assertEqual(args[0], (1 << 64) - 100)
                self.assertEqual(args[2], args[0])
                self.assertEqual(string(args[1]), "/etc/ld.so.preload")
                self.assertEqual(string(args[3]), stage + "/preload.claimed")
                self.assertEqual(args[4], 1)
                result = rename
            elif number == 220:
                self.assertEqual(args, [17, 0, 0, 0, 0])
                result = clone
            elif number == 221:
                self.assertEqual(string(args[0]), "/bin/sh")
                vector = bytes(uc.mem_read(args[1], 24))
                pointers = [int.from_bytes(vector[i : i + 8], "little") for i in (0, 8, 16)]
                self.assertEqual([string(x) for x in pointers[:2]], ["/bin/sh", stage + "/run.sh"])
                self.assertEqual(pointers[2], 0)
                self.assertEqual(args[2], 0)
                result = -2  # A simulated failed exec must exit; never run host code.
            elif number == 93:
                self.assertEqual(args[0], 127)
                uc.emu_stop()
                return
            else:
                self.fail("Unexpected syscall: " + str(number))
            uc.reg_write(UC_ARM64_REG_X0, result & ((1 << 64) - 1))

        vm.hook_add(UC_HOOK_INTR, syscall)
        vm.emu_start(base + 4096, stop, timeout=1_000_000, count=200)
        return calls

    def test_nonroot_never_claims_loader_or_forks(self):
        self.assertEqual(self.emulate(uid=1000), [174])

    def test_missing_or_foreign_claim_never_forks(self):
        for result in (-2, -17, -13):
            self.assertEqual(self.emulate(rename=result), [174, 276])

    def test_parent_returns_after_atomic_disarm(self):
        self.assertEqual(self.emulate(clone=123), [174, 276, 220])

    def test_clone_failure_returns_without_exec(self):
        self.assertEqual(self.emulate(clone=-11), [174, 276, 220])

    def test_child_exec_arguments_and_failed_exec_exit(self):
        self.assertEqual(self.emulate(), [174, 276, 220, 221, 93])
