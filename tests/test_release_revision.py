"""Release archives must never include browser session directories."""

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import privacy_gate


class TestReleaseProfiles(unittest.TestCase):
    def test_deployment_master_keys_cannot_enter_release_archives(self):
        with tempfile.TemporaryDirectory(prefix="health-release-check-") as directory:
            archive = Path(directory) / "example.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("example-master.key", b"example-key-placeholder")
                handle.writestr("example-systemd.cred", b"example-credential-placeholder")
            violations = privacy_gate.scan_archive(archive)
            self.assertEqual(len(violations), 2)
            self.assertTrue(all(v.rule == "private-artifact-file" for v in violations))

    def test_session_profiles_are_rejected_even_without_secret_looking_content(self):
        with tempfile.TemporaryDirectory(prefix="health-release-check-") as directory:
            archive = Path(directory) / "example.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("login_browser_example/Default/Preferences", "{}")
                handle.writestr("browser_profile/Local State", "{}")
            violations = privacy_gate.scan_archive(archive)
            self.assertEqual(len(violations), 2)
            self.assertTrue(all(v.rule == "browser-profile-path" for v in violations))


if __name__ == "__main__":
    unittest.main()
