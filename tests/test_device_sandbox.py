"""Exercise root-account and rollback behavior in a completely temporary tree."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_core import synthetic_elf, synthetic_public_key

from xiaomi_nas_ssh import device


class DeviceSandbox:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.home = self.root / "new-home"
        self.unit = self.root / "unit"
        self.passwd = self.root / "passwd"
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.original_root = "root:x:0:0:root:/root:/usr/sbin/mi-shell"
        self.other = "owner:x:1000:1000:Owner:/home/owner:/bin/sh"
        self.passwd.write_text(self.original_root + "\n" + self.other + "\n")
        synthetic_token = "012345" + "6789ab"  # Deliberately fixed, synthetic sandbox input.
        self.config = {"token": synthetic_token, "host": "10.23.45.67", "port": 2222,
                       "uid": "123456789", "public_key": synthetic_public_key()}
        for name, value in (("INSTALL", self.data), ("HOME", self.home), ("UNIT", self.unit), ("PASSWD", self.passwd)):
            patcher = patch.object(device, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        original_keys = self.root / "original-authorized_keys"
        original_keys.write_bytes(b"synthetic-existing-key\n")
        real_path = Path

        def sandbox_paths(value):
            if str(value) == "/root/.ssh/authorized_keys":
                return original_keys
            if str(value).startswith("/root/"):
                raise AssertionError("Unexpected access outside the test sandbox")
            return real_path(value)

        paths = patch.object(device, "Path", side_effect=sandbox_paths)
        paths.start()
        self.addCleanup(paths.stop)
        read = Path.read_bytes

        def private_copy(path):
            if str(path) == "/usr/sbin/dropbearmulti":
                return synthetic_elf()
            return read(path)

        reader = patch.object(Path, "read_bytes", private_copy)
        reader.start()
        self.addCleanup(reader.stop)

    def fake_run(self, argv, check=True):
        if argv[:3] == ["dropbearkey", "-t", "ed25519"]:
            Path(argv[-1]).write_bytes(b"synthetic-key-only")
        output = (synthetic_public_key() + " synthetic-host\n").encode() if argv[:2] == ["dropbearkey", "-y"] else b""
        return subprocess.CompletedProcess(argv, 0, output, b"")


class DeviceSandboxTests(DeviceSandbox, unittest.TestCase):
    def test_install_preserves_other_accounts_and_vendor_input(self):
        with patch.object(device, "run", side_effect=self.fake_run):
            device.install(self.config, self.stage)
        self.assertIn(self.other, self.passwd.read_text())
        self.assertIn(str(self.home), device.root_line())
        self.assertIn("-s -B -j -k -G root", self.unit.read_text())
        self.assertIn("10.23.45.67:2222", self.unit.read_text())
        self.assertEqual((self.home / ".ssh/authorized_keys").stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.stage / "status.json").exists())
        self.assertTrue((self.home / ".ssh/authorized_keys").read_bytes().startswith(b"synthetic-existing-key\n"))

    def test_rollback_restores_root_only_and_preserves_later_user(self):
        with patch.object(device, "run", side_effect=self.fake_run):
            device.install(self.config, self.stage)
            with self.passwd.open("a") as output:
                output.write("later:x:1001:1001:Later:/home/later:/bin/sh\n")
            device.rollback(self.config)
        self.assertEqual(device.root_line(), self.original_root)
        self.assertIn("later:", self.passwd.read_text())
        self.assertFalse(self.unit.exists())
        self.assertTrue((self.data / "rollback-archive/root-home/.ssh/authorized_keys").exists())

    def test_rollback_handles_failure_before_root_home_switch(self):
        self.data.mkdir()
        (self.data / "setup-token").write_text(self.config["token"])
        (self.data / "root.before").write_text(self.original_root)
        self.home.mkdir()
        with patch.object(device, "run", side_effect=self.fake_run):
            device.rollback(self.config)
        self.assertEqual(device.root_line(), self.original_root)
        self.assertIn(self.other, self.passwd.read_text())

    def test_foreign_installation_is_not_rolled_back(self):
        self.data.mkdir()
        (self.data / "setup-token").write_text("different-token")
        with patch.object(device, "run") as runner:
            device.rollback(self.config)
        runner.assert_not_called()
        self.assertIn(self.other, self.passwd.read_text())

    def test_preexisting_installation_is_refused_without_account_change(self):
        self.data.mkdir()
        before = self.passwd.read_bytes()
        with self.assertRaisesRegex(ValueError, "existing_installation"):
            device.install(self.config, self.stage)
        self.assertEqual(before, self.passwd.read_bytes())

    def test_unexpected_root_record_is_refused(self):
        self.passwd.write_text(self.original_root.replace("/root:", "/custom:") + "\n" + self.other + "\n")
        with self.assertRaisesRegex(ValueError, "unexpected_root"):
            device.install(self.config, self.stage)
        self.assertFalse(self.data.exists())

    def test_restrictive_setup_umask_does_not_make_passwd_unreadable(self):
        old_umask = os.umask(0o077)
        try:
            with patch.object(device, "run", side_effect=self.fake_run):
                device.install(self.config, self.stage)
        finally:
            os.umask(old_umask)
        self.assertEqual(self.passwd.stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.home / ".ssh/authorized_keys").stat().st_mode & 0o777, 0o600)

    def test_foreign_loader_file_is_preserved(self):
        loader = self.root / "foreign-loader"
        loader.write_text("/owner-existing/library\n")
        real_path = Path

        def paths(value):
            return loader if str(value) == "/etc/ld.so.preload" else real_path(value)

        with patch.object(device, "Path", side_effect=paths):
            with self.assertRaisesRegex(ValueError, "foreign_loader"):
                device.cleanup(self.config, self.stage)
        self.assertEqual(loader.read_text(), "/owner-existing/library\n")


if __name__ == "__main__":
    unittest.main()
