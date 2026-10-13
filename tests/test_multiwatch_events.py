from __future__ import annotations

import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from upab.multiwatch import ProjectRegistry
from upab.multiwatch_events import EventWatcherError, WindowsProjectEvents


def registry_for(root: Path, state: Path) -> ProjectRegistry:
    return ProjectRegistry.from_object({
        "schema": "upab.multi-project.registry.v1",
        "projects": [{
            "id": "poindexter",
            "repository": "blazinsoulja420-ops/UP-UHAIB-001-Poindexter",
            "channel_id": "upab-poindexter",
            "watch_enabled": True,
            "execution_enabled": False,
            "local_root": str(root),
            "state_directory": str(state),
        }],
    })


@unittest.skipUnless(sys.platform == "win32", "Windows native observer")
class WindowsProjectEventsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.repo = base / "repo"
        self.state = base / "state"
        self.repo.mkdir()
        self.state.mkdir()
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "remote", "add", "origin",
             "https://github.com/blazinsoulja420-ops/UP-UHAIB-001-Poindexter"],
            check=True,
        )
        self.registry = registry_for(self.repo, self.state)

    def test_native_event_detects_file_creation_without_reading_contents(self):
        with WindowsProjectEvents(self.registry) as observer:
            self.assertIsNone(observer.wait_once(timeout_ms=100))
            def write_after_registration():
                time.sleep(0.15)
                (self.repo / "changed.txt").write_text("UNTRUSTED DATA", encoding="utf-8")
            thread = threading.Thread(target=write_after_registration)
            thread.start()
            try:
                self.assertEqual(observer.wait_once(timeout_ms=5000), "poindexter")
            finally:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def test_observer_cannot_start_twice_and_mutex_is_released(self):
        with WindowsProjectEvents(self.registry):
            with self.assertRaisesRegex(EventWatcherError, "another .* observer"):
                with WindowsProjectEvents(self.registry):
                    pass
        with WindowsProjectEvents(self.registry) as observer:
            self.assertIsNone(observer.wait_once(timeout_ms=40))


    def test_five_projects_receive_independent_events(self):
        profiles = [
            ("poindexter", "UP-UHAIB-001-Poindexter"),
            ("universal-ai", "Universal-AI-"),
            ("uasn", "UASN-AI-Specialist"),
            ("kali-linux", "Kali-Linux-"),
            ("researchos", "UP-RES-001-Autonomous-Research-System"),
        ]
        base = Path(self.temp.name)
        raw = {"schema": "upab.multi-project.registry.v1", "projects": []}
        roots = []
        for project_id, repository_name in profiles:
            root = base / ("repo-" + project_id)
            state = base / ("state-" + project_id)
            root.mkdir()
            state.mkdir()
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "remote", "add", "origin",
                 "https://github.com/blazinsoulja420-ops/" + repository_name + ".git"],
                check=True,
            )
            roots.append(root)
            raw["projects"].append({
                "id": project_id,
                "repository": "blazinsoulja420-ops/" + repository_name,
                "channel_id": "upab-" + project_id,
                "watch_enabled": True,
                "execution_enabled": False,
                "local_root": str(root),
                "state_directory": str(state),
            })
        registry = ProjectRegistry.from_object(raw)
        with WindowsProjectEvents(registry) as observer:
            for root in roots:
                (root / "change.txt").write_text("test", encoding="utf-8")
            observed = [observer.wait_once(timeout_ms=5000) for _ in roots]
        self.assertEqual(set(observed), {project_id for project_id, _ in profiles})

    def test_observer_fails_before_subscription_if_origin_changes(self):
        subprocess.run(
            ["git", "-C", str(self.repo), "remote", "set-url", "origin",
             "https://github.com/attacker/wrong-repo"],
            check=True,
        )
        with self.assertRaisesRegex(Exception, "does not match approved binding"):
            WindowsProjectEvents(self.registry)


if __name__ == "__main__":
    unittest.main()
