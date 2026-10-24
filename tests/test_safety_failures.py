"""Faults use synthetic inputs and private temporary trees, never a NAS."""

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_core import synthetic_public_key
from test_device_sandbox import DeviceSandbox

from xiaomi_nas_ssh import device
from xiaomi_nas_ssh.api import NasError
from xiaomi_nas_ssh.bootstrap import (
    Share,
    account_digest,
    require_single_owner,
    require_temporary_account,
    state_lock,
    validate_identity,
    write_private,
)

bootstrap = importlib.import_module("xiaomi_nas_ssh.bootstrap")
SYNTHETIC_SESSION = "012345" + "6789ab"


class LocalSafetyTests(unittest.TestCase):
    def test_atomic_failure_preserves_previous_journal_and_removes_only_own_pending_file(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "state/session.json"
            write_private(p, {"phase": "prepared"})
            original = p.read_bytes()
            with patch.object(os, "replace", side_effect=OSError("synthetic disk failure")):
                with self.assertRaises(OSError):
                    write_private(p, {"phase": "changed"})
            self.assertEqual(p.read_bytes(), original)
            self.assertEqual(list(p.parent.glob("*.pending-*")), [])

    def test_hardlinked_journal_is_not_modified(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "state"
            p.write_text("preserve")
            os.link(p, Path(root) / "other")
            with self.assertRaises(NasError):
                write_private(p, {})
            self.assertEqual(p.read_text(), "preserve")

    def test_parallel_state_operation_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with state_lock(Path(root)):
                with self.assertRaisesRegex(NasError, "Another operation"):
                    with state_lock(Path(root)):
                        self.fail("Concurrent operation entered")
            with state_lock(Path(root)):
                pass

    def test_identity_mismatch_is_rejected_and_encrypted_identity_needs_agent(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "identity"
            key = Ed25519PrivateKey.generate()
            public = (
                key.public_key()
                .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                .decode()
            )
            p.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                )
            )
            p.chmod(0o600)
            validate_identity(p, public)
            with self.assertRaisesRegex(NasError, "does not match"):
                validate_identity(p, synthetic_public_key())
            p.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.BestAvailableEncryption(b"synthetic-passphrase"),
                )
            )
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaisesRegex(NasError, "ssh-agent"):
                    validate_identity(p, public)
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                validate_identity(p, public)

    def test_unexpected_accounts_are_rejected(self):
        before = [{"id": "1", "username": "owner"}]
        state = {"uid": "123456789", "before_accounts_sha256": account_digest(before)}
        temporary = {"id": "2", "username": "u123456789"}
        require_single_owner(before, state["uid"])
        require_temporary_account(before + [temporary], state)
        for rows in (
            before + [temporary, {"id": "3"}],
            [{"id": "1", "username": "changed"}, temporary],
            before + [temporary, temporary],
        ):
            with self.assertRaises(NasError):
                require_temporary_account(rows, state)
        with self.assertRaises(NasError):
            require_single_owner(before + [temporary], state["uid"])

    def test_listener_opened_after_first_preflight_prevents_activation(self):
        with tempfile.TemporaryDirectory() as root:
            api = Mock(host="10.23.45.67", uid="123456789")
            with patch.object(bootstrap.socket, "create_connection"):
                with self.assertRaisesRegex(NasError, "already open"):
                    bootstrap._apply(
                        api, "unused", Path(root), 22, synthetic_public_key(), [], SYNTHETIC_SESSION
                    )
            api.make_directory.assert_not_called()
            api.call.assert_not_called()

    def test_account_drift_after_first_preflight_prevents_activation(self):
        with tempfile.TemporaryDirectory() as root:
            api = Mock(host="10.23.45.67", uid="123456789")
            api.accounts.return_value = [{"id": "1", "username": "changed-owner"}]
            with patch.object(
                bootstrap.socket, "create_connection", side_effect=ConnectionRefusedError
            ):
                with self.assertRaisesRegex(NasError, "Preflight changed"):
                    bootstrap._apply(
                        api,
                        "unused",
                        Path(root),
                        22,
                        synthetic_public_key(),
                        [{"id": "1", "username": "original-owner"}],
                        SYNTHETIC_SESSION,
                    )
            api.make_directory.assert_not_called()
            api.call.assert_not_called()

    def test_pending_session_stops_before_device_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            state = {"host": "10.23.45.67", "uid": "123456789", "password": "synthetic-pending"}
            write_private(Path(root) / "session-pending.json", state)
            api = Mock(host=state["host"], uid=state["uid"])
            with self.assertRaisesRegex(NasError, "unfinished session"):
                bootstrap._apply(
                    api, "unused", Path(root), 22, synthetic_public_key(), [], "0123456789ab"
                )
            api.make_directory.assert_not_called()
            api.call.assert_not_called()

    def test_recovery_does_not_convert_manual_review_into_complete(self):
        with tempfile.TemporaryDirectory() as root:
            api = Mock(host="10.23.45.67", uid="123456789")
            state = {
                "host": api.host,
                "uid": api.uid,
                "token": SYNTHETIC_SESSION,
                "port": 22,
                "directory_name": bootstrap.injection_directory(api.uid),
                "stage": "/etc/.nas-ssh-0123456789ab",
                "before_accounts_sha256": account_digest([]),
                "password": None,
                "phase": "account_cleanup_verified_device_configuration_requires_review",
            }
            p = Path(root) / "journal.json"
            write_private(p, state)
            result = bootstrap.recover(api, p)
            self.assertTrue(result["configuration_review_required"])
            self.assertNotIn("cleanup_complete", result)
            api.accounts.assert_not_called()

    def test_tampered_staging_is_rejected_without_writes(self):
        state = {
            "host": "10.23.45.67",
            "uid": "123456789",
            "token": SYNTHETIC_SESSION,
            "port": 22,
            "directory_name": "synthetic",
            "public_key": synthetic_public_key(),
            "stage": "/etc/.nas-ssh-0123456789ab",
            "helper_sha256": hashlib.sha256(b"expected helper").hexdigest(),
            "trigger_sha256": hashlib.sha256(b"expected trigger").hexdigest(),
        }
        share = Mock()
        share.read.side_effect = [
            json.dumps(bootstrap.stage_config(state)).encode(),
            b"altered helper",
        ]
        with self.assertRaisesRegex(NasError, "program differs"):
            bootstrap.request_cleanup(share, state, undo=True)
        share.write.assert_not_called()

    def test_encrypted_smb_and_exclusive_writes_are_required(self):
        import io
        from contextlib import nullcontext

        import smbclient

        with patch.object(smbclient, "register_session") as register:
            share = Share("10.23.45.67", "123456789", "synthetic-password")
        self.assertTrue(register.call_args.kwargs["encrypt"])
        self.assertEqual(register.call_args.kwargs["auth_protocol"], "ntlm")
        share.client = Mock()
        share.client.open_file.side_effect = [
            nullcontext(io.BytesIO()),
            nullcontext(io.BytesIO(b"synthetic readback")),
        ]
        share.write("stage/file", b"synthetic readback", exclusive=True)
        self.assertEqual(share.client.open_file.call_args_list[0].args[1], "xb")
        share.client.open_file.side_effect = [
            nullcontext(io.BytesIO()),
            nullcontext(io.BytesIO(b"different")),
        ]
        with self.assertRaisesRegex(NasError, "readback failed"):
            share.write("stage/file", b"synthetic readback", exclusive=True)

    def test_share_paths_cannot_escape_or_select_an_alternate_data_stream(self):
        share = object.__new__(Share)
        share.root = "\\\\10.23.45.67\\synthetic\\"
        for name in ("", "../other", "..\\other", "/root", "\\other", "file:stream", "file\0"):
            with self.assertRaises(NasError):
                share.path(name)


class DeviceFailureTests(DeviceSandbox, unittest.TestCase):
    def absent(self, args, check=True):
        if args[:3] == ["uci", "-q", "get"]:
            return subprocess.CompletedProcess(args, 1, b"", b"")
        return self.fake_run(args, check)

    def test_foreign_samba_account_is_not_removed(self):
        calls = []

        def run(args, check=True):
            calls.append(args)
            value = b"foreign-owner" if args[-1].endswith(".name") else b"/etc"
            return subprocess.CompletedProcess(args, 0, value, b"")

        real_path = Path
        with (
            patch.object(
                device,
                "Path",
                side_effect=lambda value: (
                    self.root / "missing"
                    if str(value) == "/etc/ld.so.preload"
                    else real_path(value)
                ),
            ),
            patch.object(device, "run", side_effect=run),
        ):
            with self.assertRaisesRegex(ValueError, "foreign_samba"):
                device.cleanup(self.config, self.stage)
        self.assertFalse(any("delete" in args for args in calls))
        self.assertFalse((self.stage / "cleanup-complete").exists())

    def test_changed_root_fields_are_preserved_during_rollback(self):
        with patch.object(device, "run", side_effect=self.fake_run):
            device.install(self.config, self.stage)
            changed = self.passwd.read_text().replace("root:x:", "root:synthetic-changed:")
            self.passwd.write_text(changed)
            with self.assertRaisesRegex(ValueError, "root_account_changed"):
                device.rollback(self.config)
        self.assertEqual(self.passwd.read_text(), changed)
        self.assertTrue(self.unit.exists())

    def test_failed_rollback_does_not_create_success_marker(self):
        real_path = Path
        with (
            patch.object(
                device,
                "Path",
                side_effect=lambda s: (
                    self.root / "missing"
                    if str(s).startswith(("/etc/", "/home/"))
                    else real_path(s)
                ),
            ),
            patch.object(device, "run", side_effect=self.absent),
            patch.object(device, "rollback", side_effect=ValueError("synthetic refusal")),
        ):
            with self.assertRaisesRegex(ValueError, "rollback_requires_review"):
                device.cleanup(
                    {**self.config, "directory_name": "synthetic-staging"}, self.stage, undo=True
                )
        self.assertFalse((self.stage / "cleanup-complete").exists())

    def test_action_lock_serializes_a_second_process(self):
        ready = self.root / "ready"
        entered = self.root / "entered"
        program = (
            "from pathlib import Path; from xiaomi_nas_ssh.device import action_lock; "
            "import sys; Path(sys.argv[2]).write_text('ready'); "
            "guard=action_lock(Path(sys.argv[1])); guard.__enter__(); "
            "Path(sys.argv[3]).write_text('entered'); guard.__exit__(None,None,None)"
        )
        with device.action_lock(self.stage):
            child = subprocess.Popen(
                [sys.executable, "-c", program, str(self.stage), str(ready), str(entered)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            deadline = time.monotonic() + 5
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            self.assertFalse(entered.exists())
        child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0)
        self.assertEqual(entered.read_text(), "entered")

    def test_automatic_recovery_rechecks_a_late_commit_inside_device_lock(self):
        config = {**self.config, "directory_name": "synthetic-staging"}
        with patch.object(device, "run", side_effect=self.absent):
            device.install(config, self.stage)
            device.commit(config, self.stage)
            real_path = Path
            with patch.object(
                device,
                "Path",
                side_effect=lambda value: (
                    self.root / "missing-user-dir"
                    if str(value).startswith("/home/u")
                    else real_path(value)
                ),
            ):
                with device.action_lock(self.stage):
                    device.dispatch(config, self.stage, "recover")
        self.assertTrue(self.unit.is_file())
        self.assertEqual(device.root_line().split(":")[5], str(self.home))
        self.assertTrue((self.stage / "cleanup-complete").exists())

    def test_commit_refused_after_watchdog_already_rolled_back(self):
        with patch.object(device, "run", side_effect=self.fake_run):
            device.install(self.config, self.stage)
            device.commit(self.config, self.stage)
            device.rollback(self.config)
            with self.assertRaisesRegex(ValueError, "no_longer_active"):
                device.commit(self.config, self.stage)
        self.assertEqual(device.root_line(), self.original_root)

    def test_repeated_rollback_preserves_archive(self):
        with patch.object(device, "run", side_effect=self.fake_run):
            device.install(self.config, self.stage)
            device.rollback(self.config)
            archive = self.data / "rollback-archive/root-home/.ssh/authorized_keys"
            first = archive.read_bytes()
            device.rollback(self.config)
        self.assertEqual(archive.read_bytes(), first)


class FullControllerSandbox(DeviceSandbox, unittest.TestCase):
    """Real controller + real root helper; fake APIs/SMB/OS commands at boundaries."""

    def exercise(self, fault=None):
        original = [{"id": "1", "username": "owner", "password": "synthetic-original"}]
        rows = copy.deepcopy(original)
        api = Mock(host="10.23.45.67", uid="123456789")
        api.version.return_value = bootstrap.SUPPORTED_VERSION
        api.accounts.side_effect = lambda: copy.deepcopy(rows)
        etc = self.root / "etc"
        etc.mkdir()
        user_dir = self.root / "user-staging"
        sentinel = self.root / "existing-backup"
        sentinel.write_bytes(b"synthetic existing backup: preserve exactly")
        before = hashlib.sha256(sentinel.read_bytes()).hexdigest()
        account_fields = {}
        commands = []

        def api_call(route, payload):
            if route.endswith("add_samba_account"):
                rows.append({"id": "2", "username": "u123456789"})
                account_fields.update(
                    {
                        "sambauser.u123456789_2.name": b"u123456789\n",
                        "sambashare.u123456789_2.path": b"/etc\n",
                    }
                )
                if fault == "extra_account":
                    rows.append({"id": "3", "username": "other"})
            return {}

        api.call.side_effect = api_call
        api.make_directory.side_effect = lambda name: (user_dir / name).mkdir(parents=True)

        real_path = Path

        def device_paths(value):
            text = str(value)
            if text == "/root/.ssh/authorized_keys":
                return self.root / "missing-original-key"
            if text == "/etc/ld.so.preload":
                return etc / "ld.so.preload"
            if text.startswith("/home/u"):
                return user_dir
            if text.startswith("/data/xiaomi-nas-ssh-cleanup"):
                return self.root / "cleanup-archive"
            return real_path(value)

        def command(argv, check=True):
            commands.append(argv)
            if argv[:3] == ["uci", "-q", "get"]:
                value = account_fields.get(argv[3])
                return subprocess.CompletedProcess(
                    argv, 1 if value is None else 0, value or b"", b""
                )
            if argv[:3] == ["uci", "-q", "delete"]:
                if fault == "uci_delete":
                    raise subprocess.CalledProcessError(1, argv)
                for key in list(account_fields):
                    if key.startswith(argv[3] + "."):
                        del account_fields[key]
            if argv[:3] == ["/usr/bin/smb_mgr.sh", "user", "delete"]:
                rows[:] = copy.deepcopy(original)
            if fault == "keygen" and argv[:2] == ["dropbearkey", "-t"]:
                raise subprocess.CalledProcessError(1, argv)
            return self.fake_run(argv, check)

        class DiskShare:
            def exists(_self, name):
                return (etc / name).exists()

            def mkdir(_self, name):
                (etc / name).mkdir()

            def read(_self, name):
                return (etc / name).read_bytes()

            def archive_claim(_self, relative):
                p = etc / relative / "preload.claimed"
                if p.exists():
                    p.rename(p.with_name("preload.previous"))

            def write(_self, name, data, *, exclusive=False, verify=True):
                p = etc / name
                with p.open("xb" if exclusive else "wb") as output:
                    output.write(data)
                if name == "ld.so.preload":
                    stage = etc / data.decode().split("/")[2]
                    p.rename(
                        stage / "preload.claimed"
                    )  # Simulated kernel boundary, no host preload.
                    if fault == "timeout":
                        return
                    action = next(
                        a
                        for a in ("install", "rollback", "recover", "cleanup")
                        if ("config.json " + a + " ").encode() in (stage / "run.sh").read_bytes()
                    )
                    config = json.loads((stage / "config.json").read_text())
                    with device.action_lock(stage):
                        try:
                            device.dispatch(config, stage, action)
                        except SystemExit:
                            pass

        share = DiskShare()

        def ssh_run(argv, **kwargs):
            stage = next(etc.glob(".nas-ssh-*"))
            config = json.loads((stage / "config.json").read_text())
            action = argv[-1].rsplit(" ", 1)[-1]
            with device.action_lock(stage):
                if fault == "watchdog_before_commit" and action == "commit":
                    device.dispatch(config, stage, "watchdog")
                try:
                    device.dispatch(config, stage, action)
                    code = 0
                except SystemExit:
                    code = 1
            if fault == "commit_ack_loss" and action == "commit":
                code = 1
            return subprocess.CompletedProcess(argv, code, b"", b"")

        verify_count = 0

        def connect_share(*args):
            if fault == "share_failure":
                raise NasError("Synthetic share failure")
            if fault == "stage_collision":
                journal = json.loads(
                    next((self.root / "private-state").glob("session-*.json")).read_text()
                )
                collision = etc / journal["stage"].removeprefix("/etc/")
                collision.mkdir()
                (collision / "unrelated").write_bytes(b"preserve synthetic collision")
            return share

        def verification(_):
            nonlocal verify_count
            verify_count += 1
            if fault == "interrupt":
                raise KeyboardInterrupt
            valid = fault != "verify" and not (fault == "post_verify" and verify_count > 1)
            return {"passed": valid, "checks": {"synthetic": valid}}

        with (
            patch.object(device, "Path", side_effect=device_paths),
            patch.object(device, "run", side_effect=command),
            patch.object(bootstrap, "Share", side_effect=connect_share),
            patch.object(bootstrap, "validate_identity"),
            patch.object(bootstrap.time, "sleep"),
            patch.object(bootstrap.socket, "create_connection", side_effect=ConnectionRefusedError),
            patch.object(bootstrap, "verify_ssh", side_effect=verification),
            patch.object(subprocess, "run", side_effect=ssh_run),
        ):
            identity = self.root / "identity"
            Path(str(identity) + ".pub").write_text(synthetic_public_key())
            result = None
            try:
                result = bootstrap.bootstrap(
                    api, identity, self.root / "private-state", apply=True, experimental=True
                )
            except NasError:
                pass
        self.assertEqual(hashlib.sha256(sentinel.read_bytes()).hexdigest(), before)
        self.assertIn(self.other, self.passwd.read_text())
        self.assertFalse((etc / "ld.so.preload").exists())
        return result, rows, original, account_fields, commands

    def test_success_runs_real_install_commit_and_cleanup_without_touching_backup(self):
        result, rows, original, account_fields, commands = self.exercise()
        self.assertTrue(result["passed"])
        self.assertEqual(rows, original)
        self.assertEqual(account_fields, {})
        self.assertTrue(self.unit.is_file())
        self.assertEqual(len(list((self.root / "cleanup-archive").glob("*/empty-staging"))), 1)
        self.assertTrue(any(x[:3] == ["systemctl", "is-active", "--quiet"] for x in commands))
        self.assertNotIn(["/usr/bin/smb_mgr.sh", "restart"], commands)

    def test_failure_matrix_preserves_backups_and_original_accounts(self):
        for fault in (
            "keygen",
            "verify",
            "interrupt",
            "watchdog_before_commit",
            "uci_delete",
            "extra_account",
            "share_failure",
            "stage_collision",
            "timeout",
            "commit_ack_loss",
            "post_verify",
        ):
            with self.subTest(fault=fault):
                # Each scenario needs its own entirely fresh tree.
                scenario = FullControllerSandbox()
                scenario.setUp()
                try:
                    result, rows, original, fields, _ = scenario.exercise(fault)
                    self.assertIsNone(result)
                    self.assertEqual(rows[0], original[0])
                    if fault in ("keygen", "verify", "interrupt", "watchdog_before_commit"):
                        self.assertEqual(rows, original)
                        self.assertEqual(device.root_line(), scenario.original_root)
                    if fault in ("uci_delete", "commit_ack_loss", "post_verify"):
                        self.assertTrue(scenario.unit.exists())
                    if fault == "stage_collision":
                        self.assertEqual(len(list((scenario.root / "etc").glob("*/unrelated"))), 1)
                    if fault == "uci_delete":
                        self.assertTrue(scenario.unit.exists())
                        self.assertTrue(fields)
                finally:
                    scenario.doCleanups()


if __name__ == "__main__":
    unittest.main()
