import base64
import contextlib
import importlib
import io
import json
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from xiaomi_nas_ssh.api import SUPPORTED_VERSION, AdminAPI, NasError, lan_ipv4
from xiaomi_nas_ssh.bootstrap import (
    account_digest,
    arm,
    bootstrap,
    public_key,
    recover,
    write_private,
)
from xiaomi_nas_ssh.cli import main
from xiaomi_nas_ssh.patch import MENU_SHELL, patch_dropbear
from xiaomi_nas_ssh.ssh import SSHConfig, verify_ssh
from xiaomi_nas_ssh.trigger import build_trigger

bootstrap_module = importlib.import_module("xiaomi_nas_ssh.bootstrap")


def synthetic_elf(marker=MENU_SHELL, machine=183):
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 18, machine)
    return bytes(data) + marker + b"synthetic-test-only"


def synthetic_public_key():
    return "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()


class PatchTests(unittest.TestCase):
    def test_only_one_constant_changes_and_input_is_unchanged(self):
        original = synthetic_elf()
        output, manifest = patch_dropbear(original)
        self.assertEqual(len(output), len(original))
        self.assertIn(MENU_SHELL, original)
        self.assertNotIn(MENU_SHELL, output)
        offset = manifest["constant_offset"]
        self.assertEqual(output[:offset], original[:offset])
        self.assertEqual(output[offset + len(MENU_SHELL):], original[offset + len(MENU_SHELL):])
        self.assertNotEqual(manifest["original_sha256"], manifest["patched_sha256"])

    def test_missing_ambiguous_or_already_patched_inputs_are_refused(self):
        for blob in (synthetic_elf(b"none"), synthetic_elf(MENU_SHELL * 2), patch_dropbear(synthetic_elf())[0]):
            with self.subTest(length=len(blob)), self.assertRaises(NasError):
                patch_dropbear(blob)

    def test_wrong_architecture_and_non_elf_refused(self):
        for blob in (b"not ELF", synthetic_elf(machine=62)):
            with self.assertRaises(NasError):
                patch_dropbear(blob)

    def test_device_and_library_patchers_agree(self):
        from xiaomi_nas_ssh.device import patch_binary
        self.assertEqual(patch_binary(synthetic_elf()), patch_dropbear(synthetic_elf())[0])


class SSHTests(unittest.TestCase):
    def test_command_shell_menu_cannot_pass_verification(self):
        fake = Mock(return_value=subprocess.CompletedProcess([], 0, b"MENU> ", b""))
        result = verify_ssh(SSHConfig(alias="owner-nas"), runner=fake)
        self.assertFalse(result["passed"])
        self.assertNotIn("MENU", json.dumps(result))

    def test_expected_channels_exit_and_negative_auth(self):
        returns = [(0, b"0\n", b""), (0, b"SSH_OK\n", b"SSH_ERR_OK\n"),
                   (7, b"OWNER_INPUT\n", b""), (0, b"PTY_OK\r\n", b"closed"),
                   (255, b"", b"Permission denied (publickey).")]
        runner = Mock(side_effect=[subprocess.CompletedProcess([], *x) for x in returns])
        result = verify_ssh(SSHConfig(alias="owner-nas"), runner=runner)
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["checks"]), 5)
        for call in runner.call_args_list:
            argv = call.args[0]
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("BatchMode=yes", argv)
            self.assertFalse(call.kwargs.get("shell", False))

    def test_timeout_does_not_expose_transcript(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired("private-target", 1, b"private-output"))
        result = verify_ssh(SSHConfig(alias="owner-nas"), runner=runner)
        self.assertFalse(result["passed"])
        self.assertNotIn("private", json.dumps(result))

    def test_alias_arguments_cannot_inject_local_options(self):
        for alias in ("-oProxyCommand=bad", "a b", "a;bad", "../name"):
            with self.subTest(alias=alias), self.assertRaises(NasError):
                SSHConfig(alias=alias).arguments()

    def test_address_requires_pin_and_identity(self):
        with self.assertRaises(NasError):
            SSHConfig(host="10.23.45.67").arguments()
        argv, target = SSHConfig(host="10.23.45.67", identity="~/owner-key", known_hosts="~/owner-hosts", port=2222).arguments()
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertEqual(target, "root@10.23.45.67")


class APITests(unittest.TestCase):
    def test_lan_scope(self):
        for address in ("10.23.45.67", "172.20.10.2", "192.168.100.2"):
            self.assertEqual(lan_ipv4(address), address)
        for address in ("198.51.100.10", "example.invalid", "127.0.0.1", "bad;command", "-V"):
            with self.subTest(address=address), self.assertRaises(NasError):
                lan_ipv4(address)

    def test_legacy_crypto_is_rejected_before_key_access(self):
        with patch("xiaomi_nas_ssh.api.ssl.OPENSSL_VERSION", "LibreSSL legacy"):
            with self.assertRaisesRegex(NasError, "modern OpenSSL"):
                AdminAPI("10.23.45.67", "unused", "unused", "unused")

    def test_api_error_body_is_not_echoed(self):
        api = object.__new__(AdminAPI)
        api._request = Mock(return_value=(200, b'{"code":2502,"password":"synthetic-sensitive-value"}'))
        with self.assertRaises(NasError) as context:
            api.call("netshare/get_samba_account")
        self.assertNotIn("synthetic-sensitive-value", str(context.exception))

    def test_non_json_and_unknown_routes_are_refused(self):
        api = object.__new__(AdminAPI)
        api._request = Mock(return_value=(200, b"private error text"))
        for route in ("netshare/get_samba_account", "system/arbitrary_command"):
            with self.assertRaises(NasError):
                api.call(route)


class BootstrapSafetyTests(unittest.TestCase):
    def api(self, version=SUPPORTED_VERSION, rows=None):
        api = Mock(host="10.23.45.67", uid="123456789")
        api.version.return_value = version
        api.accounts.return_value = rows if rows is not None else [
            {"id": "1", "username": "owner", "password": "synthetic-sensitive-value", "share_dir": ["/synthetic/photos"]}]
        return api

    def test_read_only_is_default_and_output_does_not_include_credentials(self):
        api = self.api()
        result = bootstrap(api, "unused", "unused")
        self.assertFalse(result["device_changes"])
        self.assertEqual(result["mode"], "read_only_plan")
        self.assertNotIn("synthetic-sensitive-value", json.dumps(result))
        api.call.assert_not_called()
        api.make_directory.assert_not_called()

    def test_explicit_experimental_ack_is_required(self):
        api = self.api()
        with self.assertRaises(NasError):
            bootstrap(api, "unused", "unused", apply=True)
        api.make_directory.assert_not_called()

    def test_unsupported_firmware_or_account_layout_is_not_mutated(self):
        for api in (self.api(version="different"), self.api(rows=[]), self.api(rows=[{"id": "2", "username": "other"}])):
            with self.assertRaises(NasError):
                bootstrap(api, "unused", "unused", apply=True, experimental=True)
            api.make_directory.assert_not_called()

    def test_existing_listener_is_never_reinstalled(self):
        api = self.api()
        with patch.object(bootstrap_module.socket, "create_connection"):
            with self.assertRaisesRegex(NasError, "already open"):
                bootstrap(api, "unused", "unused", apply=True, experimental=True)
        api.make_directory.assert_not_called()

    def test_port_timeout_is_not_treated_as_an_unused_port(self):
        api = self.api()
        with patch.object(bootstrap_module.socket, "create_connection", side_effect=socket.timeout):
            with self.assertRaisesRegex(NasError, "unknown"):
                bootstrap(api, "unused", "unused", apply=True, experimental=True)
        api.make_directory.assert_not_called()

    def test_original_account_fingerprint_is_canonical(self):
        self.assertEqual(account_digest([{"b": 2, "a": 1}]), account_digest([{"a": 1, "b": 2}]))

    def test_loader_is_exclusively_created_and_not_reopened_after_activation(self):
        share = Mock()
        share.exists.return_value = False
        stage = "/etc/.nas-ssh-0123456789ab"
        arm(share, stage)
        share.write.assert_called_once_with("ld.so.preload", (stage + "/trigger.so\n").encode(), exclusive=True, verify=False)
        share.exists.return_value = True
        with self.assertRaises(NasError):
            arm(share, stage)

    def test_private_state_permissions_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state" / "journal.json"
            write_private(state, {"password": "synthetic-sensitive-value"})
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state.parent.stat().st_mode), 0o700)
            link = state.parent / "link"
            link.symlink_to(state)
            with self.assertRaises(NasError):
                write_private(link, {})

    def test_public_key_comments_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "key"
            Path(str(identity) + ".pub").write_text(synthetic_public_key() + " synthetic-owner-comment")
            self.assertEqual(public_key(identity), synthetic_public_key())

    def test_malformed_recovery_scope_refused_before_network_access(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "journal.json"
            write_private(state, {"host": "10.23.45.67", "uid": "123456789", "token": "synthetic-invalid-token", "stage": "/etc/other", "directory_name": "../other", "port": 22})
            with patch.object(bootstrap_module, "Share") as share:
                with self.assertRaises(NasError):
                    recover(self.api(), state)
                share.assert_not_called()


class TriggerTests(unittest.TestCase):
    def test_elf_header_and_disarm_before_clone(self):
        data = build_trigger("/etc/.nas-ssh-0123456789ab")
        self.assertEqual(data[:7], b"\x7fELF\x02\x01\x01")
        self.assertEqual(struct.unpack_from("<H", data, 18)[0], 183)
        words = struct.unpack_from("<31I", data, 4096)
        self.assertEqual(words[8], 0xD2802288)  # renameat2 syscall 276
        self.assertEqual(words[16], 0xD2801B88) # clone syscall 220
        self.assertEqual(words[30], 0xD65F03C0)
        for index in (2, 10, 18):
            self.assertEqual(index + ((words[index] >> 5) & 0x7FFFF), 30)

    def test_every_adr_targets_the_correct_terminated_string(self):
        stage = "/etc/.nas-ssh-0123456789ab"
        data = build_trigger(stage)
        for index, expected in ((4, "/etc/ld.so.preload"), (6, stage + "/preload.claimed"), (19, "/bin/sh"), (20, stage + "/run.sh")):
            word = struct.unpack_from("<I", data, 4096 + 4 * index)[0]
            delta = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
            at = 4096 + index * 4 + delta
            self.assertEqual(data[at:].split(b"\0", 1)[0].decode(), expected)

    def test_paths_outside_private_scope_are_refused(self):
        for stage in ("/etc", "/tmp/anything", "/etc/.nas-ssh-../bad", "/etc/.nas-ssh-0123456789ab;bad"):
            with self.assertRaises(NasError):
                build_trigger(stage)


class CLITests(unittest.TestCase):
    def test_copy_never_overwrites_source_or_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "copy"
            p.write_bytes(synthetic_elf())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["patch-copy", "--input", str(p), "--output", str(p)]), 2)
            self.assertEqual(p.read_bytes(), synthetic_elf())

    def test_unexpected_exception_is_not_a_public_traceback(self):
        output = io.StringIO()
        with patch("xiaomi_nas_ssh.cli.verify_ssh", side_effect=RuntimeError("synthetic-sensitive-value")):
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(["verify", "--ssh-alias", "owner-nas"]), 2)
        self.assertNotIn("synthetic-sensitive-value", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()
