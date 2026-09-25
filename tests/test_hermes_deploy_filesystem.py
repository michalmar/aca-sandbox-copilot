"""Exercise the real private uploader on an empty, disposable Linux mount."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from azure.core.exceptions import HttpResponseError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hermes_common as common


class MountedFilesystemSandbox:
    """SDK-shaped transport; commands and file operations run on real Linux."""

    def __init__(self):
        self.commands = []
        self.staging_paths = []
        self.failure = None
        self._sbx_path = "/test/sandbox"

    def _dp_post(self, path, payload):
        if path != self._sbx_path + "/executeShellCommand" or set(payload) != {"command"}:
            raise AssertionError("Only the pinned SDK exec operation is expected.")
        command = payload["command"]
        self.commands.append(command)
        result = subprocess.run(
            shlex.split(command), capture_output=True, text=True, check=False, timeout=15,
        )
        return {"exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

    def write_file(self, path, content, *, create_dirs, mode):
        if create_dirs or mode != "0600":
            raise AssertionError("The uploader must preserve its private prepared file.")
        self.staging_paths.append(Path(path))
        descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        try:
            middle = len(content) // 2
            os.write(descriptor, content[:middle])
            time.sleep(0.003)
            if self.failure == "transport":
                raise HttpResponseError("synthetic private transport failure")
            os.write(descriptor, content[middle:])
            if self.failure == "permissions":
                os.fchmod(descriptor, 0o644)
            if self.failure == "ownership":
                os.fchown(descriptor, 1001, -1)
        finally:
            os.close(descriptor)

    def delete_file(self, path):
        if Path(path) not in self.staging_paths:
            raise AssertionError("Cleanup must name only this upload's staging file.")
        Path(path).unlink()

    def read_file(self, path):
        return Path(path).read_bytes()


@unittest.skipUnless(
    os.environ.get("HERMES_UPLOAD_IMAGE_TEST") == "1",
    "requires the dedicated network-none Linux verification image and empty /mnt/data mount",
)
class PrivateUploadFilesystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or os.getuid() != 0 or not os.path.ismount("/mnt/data"):
            raise RuntimeError("This fixture requires a root Linux container with its own mounted /mnt/data.")
        cls.root = Path("/mnt/data")
        if list(cls.root.iterdir()):
            raise RuntimeError("Refusing an existing or nonempty data mount.")
        cls.marker = cls.root / ".hermes-upload-test"
        cls.marker.write_text("disposable-private-upload-fixture", encoding="ascii")

    def setUp(self):
        self.sandbox = MountedFilesystemSandbox()
        self.destination = Path(common.GOOGLE_CREDENTIAL_PATH)
        self.content = b'{"refresh_token":"synthetic-credential","revision":1}'
        self.outside = tempfile.TemporaryDirectory(prefix="hermes-upload-outside-")
        self.addCleanup(self.outside.cleanup)

    def tearDown(self):
        self.assertEqual(self.marker.read_text(encoding="ascii"), "disposable-private-upload-fixture")
        for target in (self.root / "hermes", self.root / "secrets"):
            if target.is_symlink():
                target.unlink()
            elif target.exists():
                shutil.rmtree(target)

    def upload(self, content=None):
        common.upload_private_file(
            self.sandbox, destination=str(self.destination),
            content=self.content if content is None else content,
        )

    def assert_private(self):
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        self.assertEqual(self.destination.stat().st_uid, os.geteuid())
        for parent in (self.destination.parent, self.destination.parent.parent):
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
            self.assertEqual(parent.stat().st_uid, os.geteuid())
        self.assertEqual(list(self.destination.parent.glob(".credentials.json.*.tmp")), [])
        self.assertNotIn("synthetic-credential", "\n".join(self.sandbox.commands))
        self.assertTrue(all(shlex.split(command)[0] == common.PYTHON for command in self.sandbox.commands))

    def test_private_modes_and_atomic_replacement_on_mounted_linux(self):
        self.upload()
        previous_inode = self.destination.stat().st_ino
        replacement = b'{"refresh_token":"synthetic-credential","revision":2}'
        self.upload(replacement)
        self.assertEqual(self.destination.read_bytes(), replacement)
        self.assertNotEqual(self.destination.stat().st_ino, previous_inode)
        self.assert_private()

    def test_concurrent_readers_never_observe_partial_credentials(self):
        self.upload()
        stopped = threading.Event()
        failures = []
        reads = []

        def reader():
            while not stopped.is_set():
                try:
                    value = json.loads(self.destination.read_bytes())
                    if set(value) != {"refresh_token", "revision"} or not 1 <= value["revision"] <= 12:
                        failures.append("unexpected complete document")
                    reads.append(1)
                except (OSError, ValueError) as error:
                    failures.append(type(error).__name__)
                stopped.wait(0.001)

        thread = threading.Thread(target=reader)
        thread.start()
        try:
            for revision in range(2, 13):
                self.upload(json.dumps({"refresh_token": "synthetic-credential", "revision": revision}).encode())
        finally:
            stopped.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertGreater(len(reads), 10)
        self.assertEqual(failures, [])
        self.assert_private()

    def test_failed_sdk_write_preserves_existing_document_and_removes_staging(self):
        self.upload()
        self.sandbox.failure = "transport"
        with self.assertRaisesRegex(RuntimeError, "Private SDK upload failed"):
            self.upload(b'{"refresh_token":"different-synthetic-credential"}')
        self.assertEqual(self.destination.read_bytes(), self.content)
        self.assert_private()

    def test_incorrect_staging_mode_is_rejected_before_atomic_commit(self):
        self.upload()
        self.sandbox.failure = "permissions"
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload(b'{"refresh_token":"different-synthetic-credential"}')
        self.assertEqual(self.destination.read_bytes(), self.content)
        self.assert_private()

    def test_sdk_changed_staging_owner_is_rejected_before_atomic_commit(self):
        self.upload()
        self.sandbox.failure = "ownership"
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload(b'{"refresh_token":"different-synthetic-credential"}')
        self.assertEqual(self.destination.read_bytes(), self.content)
        self.assert_private()

    def test_foreign_private_parent_owner_is_not_adopted(self):
        parent = self.root / "secrets"
        parent.mkdir(mode=0o700)
        os.chown(parent, 1001, -1)
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload()
        self.assertEqual(parent.stat().st_uid, 1001)
        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual(self.sandbox.staging_paths, [])

    def test_foreign_private_destination_owner_is_not_overwritten(self):
        self.upload()
        os.chown(self.destination, 1001, -1)
        self.sandbox.staging_paths.clear()
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload(b'{"refresh_token":"different-synthetic-credential"}')
        self.assertEqual(self.destination.stat().st_uid, 1001)
        self.assertEqual(self.destination.read_bytes(), self.content)
        self.assertEqual(self.sandbox.staging_paths, [])

    def test_directory_symlink_cannot_redirect_private_upload(self):
        (self.root / "secrets").symlink_to(self.outside.name, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload()
        self.assertEqual(list(Path(self.outside.name).iterdir()), [])
        self.assertEqual(self.sandbox.staging_paths, [])

    def test_destination_symlink_cannot_replace_or_read_another_file(self):
        outside = Path(self.outside.name) / "unrelated"
        outside.write_bytes(b"untouched")
        self.destination.parent.mkdir(parents=True)
        self.destination.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload()
        self.assertEqual(outside.read_bytes(), b"untouched")
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(self.sandbox.staging_paths, [])

    def test_hardlinked_destination_is_rejected(self):
        self.upload()
        other_name = self.destination.parent / "unrelated"
        os.link(self.destination, other_name)
        self.sandbox.staging_paths.clear()
        with self.assertRaisesRegex(RuntimeError, "Sandbox operation failed"):
            self.upload()
        self.assertEqual(other_name.read_bytes(), self.content)
        self.assertEqual(self.sandbox.staging_paths, [])


if __name__ == "__main__":
    unittest.main()
