from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from upab.multiwatch import (
    ProjectRegistry,
    RegistryError,
    _github_repo_from_origin,
    main,
)


def sample():
    return {
        "schema": "upab.multi-project.registry.v1",
        "projects": [
            {
                "id": "poindexter",
                "repository": "blazinsoulja420-ops/UP-UHAIB-001-Poindexter",
                "channel_id": "upab-poindexter",
                "watch_enabled": False,
                "execution_enabled": False,
                "local_root": None,
                "state_directory": None,
            },
            {
                "id": "universal-ai",
                "repository": "blazinsoulja420-ops/Universal-AI-",
                "channel_id": "upab-universal-ai",
                "watch_enabled": False,
                "execution_enabled": False,
                "local_root": None,
                "state_directory": None,
            },
            {
                "id": "uasn",
                "repository": "blazinsoulja420-ops/UASN-AI-Specialist",
                "channel_id": "upab-uasn",
                "watch_enabled": False,
                "execution_enabled": False,
                "local_root": None,
                "state_directory": None,
            },
            {
                "id": "kali-linux",
                "repository": "blazinsoulja420-ops/Kali-Linux-",
                "channel_id": "upab-kali-linux",
                "watch_enabled": False,
                "execution_enabled": False,
                "local_root": None,
                "state_directory": None,
            },
            {
                "id": "researchos",
                "repository": "blazinsoulja420-ops/UP-RES-001-Autonomous-Research-System",
                "channel_id": "upab-researchos",
                "watch_enabled": False,
                "execution_enabled": False,
                "local_root": None,
                "state_directory": None,
            },
        ],
    }


class MultiProjectRegistryTests(unittest.TestCase):
    def test_five_known_profiles_not_armed_or_executable(self):
        registry = ProjectRegistry.from_object(sample())
        self.assertEqual(len(registry.projects), 5)
        self.assertEqual(
            {item["watcher"] for item in registry.preflight()},
            {"NOT_ARMED"},
        )
        self.assertEqual(
            {item["execution"] for item in registry.preflight()},
            {"DISABLED"},
        )

    def test_example_config_matches_five_disabled_profiles(self):
        example = Path(__file__).resolve().parents[1] / "config" / "multi-projects.example.json"
        registry = ProjectRegistry.from_file(example)
        self.assertEqual(
            [p.id for p in registry.projects],
            ["poindexter", "universal-ai", "uasn", "kali-linux", "researchos"],
        )
        self.assertTrue(all(not p.watch_enabled for p in registry.projects))

    def test_unknown_field_or_execution_flag_fails_closed(self):
        raw = sample()
        raw["projects"][0]["arbitrary_shell"] = "rm"
        with self.assertRaisesRegex(RegistryError, "missing or unknown"):
            ProjectRegistry.from_object(raw)
        raw = sample()
        raw["projects"][0]["execution_enabled"] = True
        with self.assertRaisesRegex(RegistryError, "never authorizes task execution"):
            ProjectRegistry.from_object(raw)

    def test_duplicate_names_repos_channels_rejected(self):
        for property_name in ("id", "repository", "channel_id"):
            with self.subTest(property_name=property_name):
                raw = sample()
                raw["projects"][1][property_name] = raw["projects"][0][property_name]
                with self.assertRaisesRegex(RegistryError, "duplicated"):
                    ProjectRegistry.from_object(raw)

    def test_non_boolean_flags_are_rejected(self):
        for field in ("watch_enabled", "execution_enabled"):
            raw = sample()
            raw["projects"][0][field] = "false"
            with self.assertRaisesRegex(RegistryError, "must be booleans"):
                ProjectRegistry.from_object(raw)

    def test_missing_active_paths_denied(self):
        raw = sample()
        raw["projects"][0]["watch_enabled"] = True
        with self.assertRaisesRegex(RegistryError, "requires both bound paths"):
            ProjectRegistry.from_object(raw)

    def test_nested_roots_and_cross_state_overlap_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            nested = root / "nested"
            state = base / "state"
            nested.mkdir(parents=True)
            state.mkdir()
            raw = sample()
            raw["projects"][0]["local_root"] = str(root)
            raw["projects"][0]["state_directory"] = str(state)
            raw["projects"][1]["local_root"] = str(nested)
            with self.assertRaisesRegex(RegistryError, "repository roots overlap"):
                ProjectRegistry.from_object(raw)

            raw["projects"][1]["local_root"] = None
            raw["projects"][1]["state_directory"] = str(root / "relay")
            with self.assertRaisesRegex(RegistryError, "state overlaps repository root"):
                ProjectRegistry.from_object(raw)

            raw["projects"][1]["state_directory"] = str(state / "child")
            with self.assertRaisesRegex(RegistryError, "state directories overlap"):
                ProjectRegistry.from_object(raw)

    def test_read_only_identity_binding_against_actual_git_origin(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, state = base / "repo", base / "state"
            root.mkdir()
            state.mkdir()
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "remote", "add", "origin",
                 "https://github.com/blazinsoulja420-ops/UP-UHAIB-001-Poindexter.git"],
                check=True,
            )
            raw = sample()
            raw["projects"][0]["watch_enabled"] = True
            raw["projects"][0]["local_root"] = str(root)
            raw["projects"][0]["state_directory"] = str(state)
            registry = ProjectRegistry.from_object(raw)
            record = registry.preflight()[0]
            self.assertEqual(record["watcher"], "READY_READ_ONLY_PREFLIGHT")
            self.assertEqual(record["execution"], "DISABLED")
            self.assertNotIn(str(root), json.dumps(record))
            subprocess.run(
                ["git", "-C", str(root), "remote", "set-url", "origin",
                 "https://github.com/elsewhere/wrong-project.git"],
                check=True,
            )
            with self.assertRaisesRegex(RegistryError, "does not match approved binding"):
                registry.preflight()

    def test_disallow_fake_github_origins_and_arbitrary_paths(self):
        allowed = [
            "git@github.com:blazinsoulja420-ops/Universal-AI-.git",
            "https://github.com/blazinsoulja420-ops/Universal-AI-.git",
            "ssh://git@github.com/blazinsoulja420-ops/Universal-AI-",
        ]
        self.assertEqual(
            {_github_repo_from_origin(value) for value in allowed},
            {"blazinsoulja420-ops/Universal-AI-"},
        )
        for value in (
            "https://github.com.evil.test/owner/repo.git",
            "https://github.com@evil.test/owner/repo.git",
            "https://github.com/owner/repo/other",
            "file:///tmp/somewhere",
        ):
            with self.subTest(value=value):
                with self.assertRaises(RegistryError):
                    _github_repo_from_origin(value)

    def test_cli_status_does_not_arm_any_watcher(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "profiles.json"
            config.write_text(json.dumps(sample()), encoding="utf-8")
            self.assertEqual(main(["--config", str(config)]), 0)

    def test_cli_refuses_corrupt_config(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "profiles.json"
            config.write_text("{garbled", encoding="utf-8")
            self.assertEqual(main(["--config", str(config)]), 7)


if __name__ == "__main__":
    unittest.main()
