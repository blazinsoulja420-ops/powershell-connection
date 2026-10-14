from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_python_distribution_inventory import (
    inspect_python_distribution, main,
)


def selected_source(temp: str, *, version="0.1.1", entry="upab.cli:main") -> Path:
    folder = Path(temp) / "reviewed"
    folder.mkdir()
    (folder / "pyproject.toml").write_text(
        "[project]\nname = \"universal-powershell-agent-bridge\"\n"
        f"version = \"{version}\"\n"
        "[project.scripts]\n"
        f"upab = \"{entry}\"\n",
        encoding="utf-8",
    )
    return folder


class _Entry:
    def __init__(self, group, name, value):
        self.group, self.name, self.value = group, name, value


class _Distribution:
    def __init__(self, version="0.1.1", entries=None, name="universal-powershell-agent-bridge"):
        self.version = version
        self.metadata = {"Name": name}
        self.entry_points = entries if entries is not None else [
            _Entry("console_scripts", "upab", "upab.cli:main")
        ]


class Stage28DistributionInventoryTests(unittest.TestCase):
    def test_default_ignores_environment_and_denies_all_authority(self):
        with mock.patch(
            "upab.relay.v3_python_distribution_inventory.metadata.distribution",
            side_effect=AssertionError("must not inspect default environment"),
        ):
            report = inspect_python_distribution()
        self.assertFalse(report["environment_scan_requested"])
        self.assertFalse(report["target_distribution_registered_here"])
        self.assertIsNone(report["registered_version"])
        self.assertIsNone(report["registered_version_matches_selected_source"])
        for key in (
            "other_interpreters_inspected",
            "portable_script_checkout_excluded",
            "live_process_watcher_identity_proven",
            "distribution_source_authenticity_proven",
            "installed_runtime_proven",
            "owner_authenticated",
            "migration_authorized",
            "task_execution_authorized",
            "files_or_settings_changed",
        ):
            self.assertFalse(report[key], key)

    def test_missing_package_cannot_prove_portable_absence(self):
        from importlib.metadata import PackageNotFoundError
        with mock.patch(
            "upab.relay.v3_python_distribution_inventory.metadata.distribution",
            side_effect=PackageNotFoundError("missing"),
        ):
            report = inspect_python_distribution(inspect_environment=True)
        self.assertTrue(report["environment_scan_requested"])
        self.assertFalse(report["target_distribution_registered_here"])
        self.assertFalse(report["portable_script_checkout_excluded"])
        self.assertFalse(report["installed_runtime_proven"])

    def test_matching_declared_version_entrypoint_not_authority(self):
        with tempfile.TemporaryDirectory() as td:
            source = selected_source(td)
            before=(source/"pyproject.toml").read_bytes()
            with mock.patch(
                "upab.relay.v3_python_distribution_inventory.metadata.distribution",
                return_value=_Distribution(),
            ):
                result=inspect_python_distribution(
                    inspect_environment=True,checkout=source
                )
            self.assertEqual(result["registered_version"], "0.1.1")
            self.assertEqual(result["expected_source_version"], "0.1.1")
            self.assertTrue(result["expected_source_entrypoint_declared"])
            self.assertTrue(result["registered_entrypoint_matches"])
            self.assertTrue(result["registered_version_matches_selected_source"])
            self.assertFalse(result["distribution_source_authenticity_proven"])
            self.assertFalse(result["task_execution_authorized"])
            self.assertEqual(before,(source/"pyproject.toml").read_bytes())
            self.assertNotIn(str(source),json.dumps(result))

    def test_wrong_versions_and_wrong_entry_points_are_detected(self):
        with tempfile.TemporaryDirectory() as td:
            source=selected_source(td)
            with mock.patch(
                "upab.relay.v3_python_distribution_inventory.metadata.distribution",
                return_value=_Distribution(version="0.2.0", entries=[
                    _Entry("console_scripts", "upab", "evil:run")
                ]),
            ):
                result=inspect_python_distribution(
                    inspect_environment=True,checkout=source
                )
            self.assertFalse(result["registered_version_matches_selected_source"])
            self.assertFalse(result["registered_entrypoint_matches"])
            self.assertFalse(result["migration_authorized"])

    def test_bad_metadata_and_identity_are_blocked(self):
        for dist in (
            _Distribution(version="v"*100),
            _Distribution(name="unrelated"),
            _Distribution(entries=[_Entry("console_scripts","upab","x")]*257),
        ):
            with self.subTest(version=str(dist.version)[:15]):
                with mock.patch(
                    "upab.relay.v3_python_distribution_inventory.metadata.distribution",
                    return_value=dist,
                ):
                    with self.assertRaises(PolicyBlocked):
                        inspect_python_distribution(inspect_environment=True)

    def test_missing_relative_symlinked_and_overlarge_source_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            folder=selected_source(td)
            with self.assertRaises(PolicyBlocked):
                inspect_python_distribution(checkout=folder)
            with self.assertRaises(PolicyBlocked):
                inspect_python_distribution(
                    inspect_environment=True,checkout=Path("relative")
                )
            source=folder/"pyproject.toml"
            with source.open("wb") as f:
                f.truncate(65537)
            with self.assertRaises(PolicyBlocked):
                inspect_python_distribution(
                    inspect_environment=True,checkout=folder
                )
        with tempfile.TemporaryDirectory() as td:
            folder=selected_source(td)
            link=Path(td)/"redirection"
            try:
                link.symlink_to(folder,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest("symlink privileges absent")
            with self.assertRaises(PolicyBlocked):
                inspect_python_distribution(
                    inspect_environment=True,checkout=link
                )

    def test_malformed_source_declaration_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            source=selected_source(td)
            (source/"pyproject.toml").write_text(
                "[project]\nname = \"wrong-package\"\nversion = \"0.1.1\"\n",
                encoding="utf-8"
            )
            with self.assertRaises(PolicyBlocked):
                inspect_python_distribution(
                    inspect_environment=True,checkout=source
                )

    def test_cli_default_does_not_claim_installed(self):
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main([]), 0)
        report=json.loads(stream.getvalue())
        self.assertFalse(report["environment_scan_requested"])
        self.assertFalse(report["installed_runtime_proven"])
        self.assertFalse(report["files_or_settings_changed"])

    def test_no_start_install_enable_process_or_connector_methods(self):
        import upab.relay.v3_python_distribution_inventory as module
        for name in (
            "install", "start", "enable", "migrate", "run_watcher",
            "execute_task", "connect_repo", "authenticate", "merge",
            "stop_process", "restart_service",
        ):
            self.assertFalse(hasattr(module,name))


if __name__ == "__main__":
    unittest.main()
