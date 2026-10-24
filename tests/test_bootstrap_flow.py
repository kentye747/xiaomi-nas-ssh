"""Controller transitions with a simulated NAS; this is not a live device test."""
import copy
import importlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_core import synthetic_public_key

from xiaomi_nas_ssh.api import SUPPORTED_VERSION, NasError

module = importlib.import_module("xiaomi_nas_ssh.bootstrap")


class SimulatedShare:
    def __init__(self):
        self.files = {}

    def exists(self, name):
        return name in self.files

    def mkdir(self, name):
        self.files[name] = b""

    def write(self, name, data, **kwargs):
        self.files[name] = data

    def read(self, name):
        return self.files[name]


class ControllerFlowTests(unittest.TestCase):
    def exercise(self, *, ready=True, ssh_passes=True, cleanup_exit=0):
        original = [{"id": "1", "username": "owner", "password": "synthetic-original-secret"}]
        rows = copy.deepcopy(original)
        api = Mock(host="10.23.45.67", uid="123456789")
        api.version.return_value = SUPPORTED_VERSION
        api.accounts.side_effect = lambda: copy.deepcopy(rows)

        def call(route, payload):
            if route == "netshare/add_samba_account":
                rows.append({"id": "2", "username": "u123456789"})
            return {}

        api.call.side_effect = call
        share = SimulatedShare()

        def activate(_share, stage):
            share.files[stage.removeprefix("/etc/") + "/status.json"] = json.dumps({
                "ready": ready, "host_public_key": synthetic_public_key()}).encode()

        def cleanup_run(argv, **kwargs):
            if argv[-1].endswith(" commit"):
                share.files[next(k.rsplit("/", 1)[0] for k in share.files if k.endswith("/config.json")) + "/committed"] = b"verified\n"
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if not cleanup_exit:
                rows[:] = copy.deepcopy(original)
            return subprocess.CompletedProcess(argv, cleanup_exit, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "owner-key"
            Path(str(identity) + ".pub").write_text(synthetic_public_key() + " test-comment")
            state_dir = Path(directory) / "state"
            with patch.object(module, "validate_identity"), \
                    patch.object(module.socket, "create_connection", side_effect=ConnectionRefusedError), \
                    patch.object(module, "Share", return_value=share), \
                    patch.object(module, "arm", side_effect=activate), \
                    patch.object(module, "verify_ssh", return_value={"passed": ssh_passes, "checks": {"synthetic": ssh_passes}}), \
                    patch.object(module, "request_cleanup") as recover, \
                    patch("subprocess.run", side_effect=cleanup_run):
                result = None
                error = None
                try:
                    result = module.bootstrap(api, identity, state_dir, apply=True, experimental=True)
                except NasError as caught:
                    error = str(caught)
                journal = json.loads(next(state_dir.glob("session-*.json")).read_text())
                self.assertNotIn("synthetic-original-secret", json.dumps(journal))
                return result, error, journal, recover.call_args

    def test_success_needs_command_verification_and_account_readback(self):
        result, error, journal, cleanup = self.exercise()
        self.assertIsNone(error)
        self.assertTrue(result["passed"])
        self.assertIsNone(journal["password"])
        self.assertEqual(journal["phase"], "complete")
        self.assertIsNone(cleanup)
        self.assertNotIn("password", json.dumps(result))

    def test_activation_failure_requests_rollback_and_retains_recovery(self):
        result, error, journal, cleanup = self.exercise(ready=False)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertTrue(cleanup.kwargs["undo"])
        self.assertEqual(journal["phase"], "cleanup_required")
        self.assertTrue(journal["password"])

    def test_menu_only_or_failed_ssh_cannot_be_committed(self):
        result, error, journal, cleanup = self.exercise(ssh_passes=False)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertTrue(cleanup.kwargs["undo"])

    def test_cleanup_failure_does_not_undo_a_verified_ssh_installation(self):
        result, error, journal, cleanup = self.exercise(cleanup_exit=1)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertFalse(cleanup.kwargs["undo"])


if __name__ == "__main__":
    unittest.main()
