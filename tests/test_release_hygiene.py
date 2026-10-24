import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("release_audit", Path(__file__).resolve().parents[1] / "tools/audit_release.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class HygieneTests(unittest.TestCase):
    def test_key_material_is_rejected_without_embedding_a_real_key(self):
        marker = "-----" + "BEGIN " + "OPENSSH " + "PRIVATE KEY" + "-----"
        self.assertIn("key/certificate material", audit.problems("synthetic", marker.encode()))

    def test_personal_paths_and_contacts_are_rejected(self):
        path = "/" + "Users" + "/" + "synthetic-user" + "/private"
        contact = "synthetic-person" + "@" + "invalid.test"
        self.assertIn("personal home path", audit.problems("synthetic", path.encode()))
        self.assertIn("non-example contact address", audit.problems("synthetic", contact.encode()))

    def test_example_and_github_service_identities_are_allowed(self):
        for contact in ("opensource@example.invalid", "noreply@github.com", "user@users.noreply.github.com"):
            self.assertEqual(audit.problems("synthetic", contact.encode()), [])

    def test_token_shaped_values_are_rejected(self):
        token = "ghp_" + "A" * 40
        self.assertIn("credential-shaped token", audit.problems("synthetic", token.encode()))


if __name__ == "__main__":
    unittest.main()
