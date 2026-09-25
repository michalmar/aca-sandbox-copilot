"""Build-only dependency exception guards, plus an explicit exact-image graph gate."""

from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / "hermes/image"))
import build_dependencies as dependencies


def record(name, version, *hashes, marker=""):
    return f"{name}=={version}{marker} \\\n" + " \\\n".join(f"    --hash={value}" for value in hashes) + "\n"


class DependencyExceptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name, "upstream")
        self.root.mkdir()
        self.support = Path(self.temporary.name, "support")
        self.old_wheel = "sha256:" + "a" * 64
        self.old_source = "sha256:" + "b" * 64
        self.lock_text = ""
        for name, version in (("msal", "1.36.0"), ("qrcode", "7.4.2"),
                              ("pypng", "0.20220715.0"), ("setuptools", "83.0.0")):
            self.lock_text += (
                f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                f'sdist = {{ hash = "{self.old_source}" }}\n'
                f'wheels = [{{ hash = "{self.old_wheel}" }}]\n\n'
            )
        self.project_text = '[project]\nname = "hermes-agent"\nversion = "0.21.5"\n'
        (self.root / "uv.lock").write_text(self.lock_text)
        (self.root / "pyproject.toml").write_text(self.project_text)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (
            ("ROOT", self.root), ("SUPPORT", self.support),
            ("UV_LOCK_SHA256", hashlib.sha256(self.lock_text.encode()).hexdigest()),
            ("PYPROJECT_SHA256", hashlib.sha256(self.project_text.encode()).hexdigest()),
        ):
            self.stack.enter_context(patch.object(dependencies, name, value))
        self.export = (
            record("azure-identity", "1.25.3", "sha256:" + "c" * 64)
            + record("cryptography", "50.0.0", "sha256:" + "d" * 64)
            + record("msal", "1.36.0", self.old_wheel, self.old_source)
        )
        self.generated = (
            record("cryptography", "50.0.0", "sha256:" + "d" * 64)
            + record("msal", "1.37.0", "md5:" + "e" * 32, "sha256:" + "f" * 64,
                     "sha256:" + dependencies.MSAL_WHEEL_SHA256)
        )

    def generate(self, *, effect=None):
        def compiler(command, **kwargs):
            self.assertEqual(command[:4], ["uv", "--no-config", "pip", "compile"])
            self.assertTrue(kwargs["check"])
            self.assertNotIn("--no-deps", command)
            self.assertNotIn("--overrides", command)
            constraints = Path(command[command.index("--constraint") + 1]).read_text()
            self.assertNotIn("msal==", constraints)
            self.assertIn("cryptography==50.0.0", constraints)
            self.assertEqual(Path(command[-1]).read_text(), "msal==1.37.0\n")
            if effect:
                effect()
            Path(command[command.index("--output-file") + 1]).write_text(self.generated)

        with patch.object(dependencies.subprocess, "check_output", side_effect=[self.export, "uv 0.11.1\n"]) as export, \
                patch.object(dependencies.subprocess, "run", side_effect=compiler):
            dependencies.python_lock_exception("https://packages.invalid/simple")
        first = export.call_args_list[0]
        self.assertEqual(first.args[0][:4], ["uv", "--no-config", "export", "--frozen"])
        self.assertIn("--no-annotate", first.args[0])
        self.assertEqual(first.kwargs["cwd"], self.root)

    def test_tool_generated_one_wheel_preserves_every_other_requirement_and_source(self):
        self.generate()
        original = (self.support / "runtime-requirements.upstream.txt").read_text()
        applied = (self.support / "runtime-requirements.txt").read_text()
        before, after = dependencies.requirement_blocks(original), dependencies.requirement_blocks(applied)
        self.assertEqual(set(before), set(after))
        self.assertEqual([name for name in before if before[name] != after[name]], ["msal"])
        self.assertEqual(dependencies.requirement_parts(after["msal"]),
                         ("msal==1.37.0", ["sha256:" + dependencies.MSAL_WHEEL_SHA256]))
        self.assertNotIn("md5:", applied)
        self.assertNotIn("sha256:" + "f" * 64, applied)
        self.assertEqual((self.root / "uv.lock").read_text(), self.lock_text)
        self.assertEqual((self.root / "pyproject.toml").read_text(), self.project_text)
        proof = json.loads((self.support / "python-lock-exception.json").read_text())
        self.assertTrue(proof["all_other_requirement_records_unchanged"])
        self.assertEqual(proof["unchanged_requirement_records"], 5)
        self.assertEqual(proof["generator"], "uv 0.11.1")
        self.assertEqual(proof["resolver_requirements_sha256"],
                         hashlib.sha256(self.generated.encode()).hexdigest())

    def test_original_source_drift_is_rejected_before_any_generator_or_output(self):
        for name in ("uv.lock", "pyproject.toml"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with patch.object(dependencies.subprocess, "check_output") as export, \
                        patch.object(dependencies.subprocess, "run") as compile:
                    with self.assertRaisesRegex(RuntimeError, "fingerprint changed"):
                        dependencies.python_lock_exception("https://packages.invalid/simple")
                    export.assert_not_called()
                    compile.assert_not_called()
                self.assertFalse(self.support.exists())
                path.write_bytes(original)

    def test_source_drift_during_generation_never_writes_a_success_proof(self):
        def mutate():
            (self.root / "uv.lock").write_text(self.lock_text + "\n")
        with self.assertRaisesRegex(RuntimeError, "fingerprint changed"):
            self.generate(effect=mutate)
        self.assertFalse(self.support.exists())

    def test_generator_failure_is_not_suppressed_or_replaced_with_a_pin(self):
        def fail():
            raise subprocess.CalledProcessError(1, ["uv", "pip", "compile"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.generate(effect=fail)
        self.assertFalse(self.support.exists())

    def test_unapproved_generated_version_or_missing_wheel_hash_fails(self):
        original = self.generated
        for generated in (
            original.replace("msal==1.37.0", "msal==1.38.0"),
            original.replace(dependencies.MSAL_WHEEL_SHA256, "0" * 64),
            original.replace("cryptography==50.0.0", "cryptography==48.0.0"),
            record("cryptography", "50.0.0", "sha256:" + "d" * 64),
        ):
            with self.subTest(generated=generated):
                self.generated = generated
                with self.assertRaises(RuntimeError):
                    self.generate()
                self.assertFalse(self.support.exists())

    def test_new_transitive_dependency_is_not_silently_adopted(self):
        self.generated += record("unapproved", "1.0", "sha256:" + "0" * 64)
        with self.assertRaisesRegex(RuntimeError, "new dependency"):
            self.generate()
        self.assertFalse(self.support.exists())

    def test_package_hash_version_marker_addition_and_removal_drift_are_rejected(self):
        self.generate()
        original = (self.support / "runtime-requirements.upstream.txt").read_text()
        applied = (self.support / "runtime-requirements.txt").read_text()
        lock = dependencies.python_source_guard()
        mutations = (
            applied.replace("cryptography==50.0.0", "cryptography==48.0.0"),
            applied.replace("sha256:" + "c" * 64, "sha256:" + "0" * 64),
            applied.replace("azure-identity==1.25.3", "azure-identity==1.25.3 ; sys_platform == 'win32'"),
            applied + record("unapproved", "1.0", "sha256:" + "0" * 64),
            applied.replace(dependencies.requirement_blocks(applied)["azure-identity"], ""),
            applied.replace("msal==1.37.0", "msal==1.36.0"),
            applied.replace(dependencies.MSAL_WHEEL_SHA256, "0" * 64),
            applied.replace("sha256:" + dependencies.MSAL_WHEEL_SHA256,
                            "sha256:" + dependencies.MSAL_WHEEL_SHA256 + " --hash=sha256:" + "0" * 64),
        )
        for changed in mutations:
            with self.subTest(changed=changed[:160]):
                with self.assertRaises(RuntimeError):
                    dependencies.validate_python_exception(original, changed, lock)

    def test_original_msal_export_must_match_both_upstream_artifact_hashes(self):
        self.generate()
        original = (self.support / "runtime-requirements.upstream.txt").read_text()
        applied = (self.support / "runtime-requirements.txt").read_text()
        for changed in (original.replace("msal==1.36.0", "msal==1.35.0"),
                        original.replace(self.old_wheel, "sha256:" + "0" * 64, 1)):
            with self.assertRaisesRegex(RuntimeError, "original MSAL export"):
                dependencies.validate_python_exception(changed, applied, dependencies.python_source_guard())

    def test_duplicate_unhashed_or_unexpected_requirement_directives_fail(self):
        valid = record("msal", "1.37.0", "sha256:" + dependencies.MSAL_WHEEL_SHA256)
        for invalid in (valid + valid, "msal==1.37.0\n", "--index-url https://invalid\n" + valid,
                        valid + "--trusted-host invalid\n", valid + "unbounded>=1\n"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RuntimeError):
                    dependencies.requirement_blocks(invalid)

    def distributions(self):
        return [
            types.SimpleNamespace(metadata={"Name": name}, version=version)
            for name, version in {
                "hermes-agent": "0.21.5", "azure-identity": "1.25.3", "cryptography": "50.0.0",
                "msal": "1.37.0", "qrcode": "7.4.2", "pypng": "0.20220715.0", "setuptools": "83.0.0",
            }.items()
        ]

    def test_exact_installed_set_is_checked_with_standard_uv_and_failure_propagates(self):
        self.generate()
        command = ["uv", "--no-config", "pip", "check", "--python", sys.executable]
        with patch.object(dependencies.importlib.metadata, "distributions", return_value=self.distributions()), \
                patch.object(dependencies.subprocess, "run") as check:
            dependencies.verify_python_dependencies()
            check.assert_called_once_with(command, check=True)
        with patch.object(dependencies.importlib.metadata, "distributions", return_value=self.distributions()), \
                patch.object(dependencies.subprocess, "run",
                             side_effect=subprocess.CalledProcessError(1, command)):
            with self.assertRaises(subprocess.CalledProcessError):
                dependencies.verify_python_dependencies()

    def test_installed_version_addition_and_removal_drift_fail_before_standard_check(self):
        self.generate()
        original = self.distributions()
        changed_version = copy.deepcopy(original)
        changed_version[1].version = "9.9.9"
        mutations = (
            changed_version, original[:-1],
            original + [types.SimpleNamespace(metadata={"Name": "unapproved"}, version="1")],
            original + [original[0]],
        )
        for distributions in mutations:
            with patch.object(dependencies.importlib.metadata, "distributions", return_value=distributions), \
                    patch.object(dependencies.subprocess, "run") as check:
                with self.assertRaisesRegex(RuntimeError, "distribution set or versions"):
                    dependencies.verify_python_dependencies()
                check.assert_not_called()

    def test_exception_provenance_drift_is_rejected(self):
        self.generate()
        path = self.support / "python-lock-exception.json"
        proof = json.loads(path.read_text())
        proof["unchanged_records_sha256"] = "0" * 64
        path.write_text(json.dumps(proof))
        with self.assertRaisesRegex(RuntimeError, "provenance differs"):
            dependencies.verify_python_dependencies()

    def test_resolver_and_patch_bytes_are_verified_before_installed_graph_check(self):
        self.generate()
        for name in ("msal-resolver-requirements.txt", "python-lock-exception.patch"):
            path = self.support / name
            original = path.read_bytes()
            for changed in (original + b"\n", original.replace(b"\n", b"\r\n"), b"stale context file\n"):
                with self.subTest(name=name, changed=changed[:80]):
                    path.write_bytes(changed)
                    with patch.object(dependencies.importlib.metadata, "distributions") as installed, \
                            patch.object(dependencies.subprocess, "run") as check:
                        with self.assertRaisesRegex(RuntimeError, "provenance"):
                            dependencies.verify_python_dependencies()
                        installed.assert_not_called()
                        check.assert_not_called()
                    path.write_bytes(original)

    def test_original_requirement_bytes_cannot_be_normalized_into_a_valid_proof(self):
        self.generate()
        path = self.support / "runtime-requirements.upstream.txt"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        with patch.object(dependencies.importlib.metadata, "distributions") as installed, \
                patch.object(dependencies.subprocess, "run") as check:
            with self.assertRaises(RuntimeError):
                dependencies.verify_python_dependencies()
            installed.assert_not_called()
            check.assert_not_called()

    def test_generated_python_provenance_is_excluded_from_the_copy_context(self):
        root = next(root for root in (SOURCE, Path("/test-repo"))
                    if (root / "hermes/image/.dockerignore").is_file())
        ignored = (root / "hermes/image/.dockerignore").read_text().splitlines()
        generated = {
            "runtime-requirements.upstream.txt", "runtime-requirements.txt",
            "msal-resolver-requirements.txt", "python-lock-exception.patch",
            "python-lock-exception.json", "runtime-distributions.json",
        }
        self.assertFalse(generated - set(ignored), f"generated files may overwrite build output: {generated - set(ignored)}")
        self.assertFalse(any(line.startswith("!") for line in ignored))

    def test_docker_uses_normal_hash_required_resolution_and_both_strict_graph_gates(self):
        root = next(root for root in (SOURCE, Path("/test-repo"))
                    if (root / "hermes/image/Dockerfile").is_file())
        dockerfile = (root / "hermes/image/Dockerfile").read_text()
        self.assertNotIn("--no-deps", dockerfile)
        self.assertNotIn("--overrides", dockerfile)
        self.assertIn("--require-hashes -r /opt/hermes-sandbox/runtime-requirements.txt", dockerfile)
        self.assertIn("--constraint /tmp/runtime-constraints.txt --no-build-isolation -e .", dockerfile)
        self.assertIn("uv --no-config pip check --python .venv/bin/python &&", dockerfile)
        verification = dockerfile.split("FROM runtime AS verification\n", 1)[1]
        self.assertIn("uv --no-config pip check --python /opt/hermes/.venv/bin/python &&", verification)


@unittest.skipUnless(os.environ.get("HERMES_RUNTIME_IMAGE_TESTS") == "1",
                     "requires the exact approved amd64 image and offline test opt-in")
class InstalledDependencyTests(unittest.TestCase):
    def test_actual_approved_requirements_installed_set_and_standard_package_check(self):
        dependencies.verify_python_dependencies()
        self.assertEqual(dependencies.importlib.metadata.version("msal"), "1.37.0")
        self.assertEqual(dependencies.importlib.metadata.version("cryptography"), "50.0.0")
        self.assertEqual(dependencies.importlib.metadata.version("azure-identity"), "1.25.3")


if __name__ == "__main__":
    unittest.main()
