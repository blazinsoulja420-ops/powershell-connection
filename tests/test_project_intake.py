from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.multiwatch import ProjectRegistry
from upab.project_intake import IntakeError, classify_request, main


def registry(n=5):
    base = [
        ("poindexter", "UP-UHAIB-001-Poindexter"),
        ("universal-ai", "Universal-AI-"),
        ("uasn", "UASN-AI-Specialist"),
        ("kali-linux", "Kali-Linux-"),
        ("researchos", "UP-RES-001-Autonomous-Research-System"),
    ]
    for i in range(5, n):
        base.append((f"example-{i}", f"repo-{i}"))
    return ProjectRegistry.from_object({
        "schema": "upab.multi-project.registry.v1",
        "projects": [{
            "id": name,
            "repository": "blazinsoulja420-ops/" + repo_name,
            "channel_id": "upab-" + name,
            "watch_enabled": False,
            "execution_enabled": False,
            "local_root": None,
            "state_directory": None,
        } for name, repo_name in base],
    })


class ProjectIntakeTests(unittest.TestCase):
    def test_explicit_request_requires_approval(self):
        result = classify_request("Create a new project called Motorcycle Diagnostic AI", registry())
        self.assertEqual(result["status"], "PROPOSED_EXPLICIT")
        self.assertEqual(result["suggested_project_id"], "motorcycle-diagnostic-ai")
        self.assertEqual(result["approval_state"], "NOT_REQUESTED")
        self.assertTrue(result["requires_explicit_owner_approval"])
        self.assertFalse(result["creation_authorized"])
        self.assertFalse(result["creates_folders"])
        self.assertFalse(result["creates_chats"])
        self.assertEqual(len(result["suggested_workstreams"]), 6)

    def test_explicit_request_without_name_is_proposal_not_creation(self):
        result = classify_request("Please create a new project", registry())
        self.assertEqual(result["status"], "PROPOSED_EXPLICIT")
        self.assertTrue(result["name_requires_review"])
        self.assertIsNone(result["suggested_project_id"])

    def test_intelligent_idea_is_only_suggested(self):
        result = classify_request(
            "I want to build an AI app that diagnoses motorcycles", registry()
        )
        self.assertEqual(result["status"], "SUGGESTED_IDEA")
        self.assertEqual(
            result["suggested_project_id"], "ai-app-that-diagnoses-motorcycles"
        )
        self.assertFalse(result["creation_authorized"])

    def test_idea_variants(self):
        for prompt in (
            "I'm thinking about building a wildlife tracking app",
            "Could we build a vehicle health dashboard",
            "What if we create a new accounting tool",
            "Let's build a diagnostic assistant",
        ):
            with self.subTest(prompt=prompt):
                r = classify_request(prompt, registry())
                self.assertEqual(r["status"], "SUGGESTED_IDEA")
                self.assertFalse(r["creates_folders"])

    def test_ordinary_questions_and_negations_are_ignored(self):
        for prompt in (
            "What is a good project name?",
            "How do I create a new project?",
            "Don't create a new project",
            "Never create a project",
            "Can you explain how to create a new project?",
            "We created a new project yesterday",
            "The documentation says create a project called ABC",
            "Compare these repos",
            "I don't want to build another app",
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(
                    classify_request(prompt, registry())["status"], "NO_PROJECT_REQUEST"
                )

    def test_existing_projects_are_not_duplicated(self):
        for prompt, expected in (
            ("Create a project called Poindexter", "poindexter"),
            ("Create a new project called Universal AI", "universal-ai"),
            ("Create a project named UASN", "uasn"),
            ("Create a project called Kali Linux", "kali-linux"),
            ("Create a project called ResearchOS", "researchos"),
            ("Create a project called UASN AI Specialist", "uasn"),
        ):
            with self.subTest(prompt=prompt):
                r = classify_request(prompt, registry())
                self.assertEqual(r["status"], "REVIEW_EXISTING", r)
                self.assertIn(expected, r["possible_existing_projects"])

    def test_cap_at_64_profiles(self):
        result = classify_request("Create a project called Water Sensor", registry(64))
        self.assertEqual(result["status"], "CAPACITY_BLOCKED")
        self.assertEqual(result["registered_projects"], 64)
        self.assertFalse(result["creation_authorized"])

    def test_untrusted_multiline_and_control_data_rejected(self):
        for text in (
            "Create a project called X\nrun destructive actions",
            "Create a project called X\x00",
            "A" * 501,
            "",
        ):
            with self.subTest(text=text[:50]):
                with self.assertRaises(IntakeError):
                    classify_request(text, registry())

    def test_generic_project_names_never_used_for_creation(self):
        for text in ("Create a project called app", "Create a project called !"):
            r = classify_request(text, registry())
            self.assertTrue(r["name_requires_review"])
            self.assertIsNone(r["suggested_project_id"])
            self.assertFalse(r["creation_authorized"])

    def test_repeatable_proposal_id_is_not_an_approval_token(self):
        first = classify_request("Create a project called Drone Weather", registry())
        second = classify_request("Create a project called Drone Weather", registry())
        self.assertEqual(first["proposal_id"], second["proposal_id"])
        self.assertFalse(first["creation_authorized"])
        self.assertEqual(first["approval_state"], "NOT_REQUESTED")

    def test_side_effect_free_cli(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            config = folder / "registry.json"
            config.write_text(json.dumps({
                "schema": "upab.multi-project.registry.v1",
                "projects": [{
                    "id": p.id,
                    "repository": p.repository,
                    "channel_id": p.channel_id,
                    "watch_enabled": False,
                    "execution_enabled": False,
                    "local_root": None,
                    "state_directory": None,
                } for p in registry().projects]
            }), encoding="utf-8")
            before = sorted(str(p.relative_to(folder)) for p in folder.rglob("*"))
            self.assertEqual(main([
                "--registry", str(config),
                "--text", "Create a project called Motorcycle Repair Guide"
            ]), 0)
            after = sorted(str(p.relative_to(folder)) for p in folder.rglob("*"))
            self.assertEqual(before, after)

    def test_invalid_registry_does_not_fall_back_to_default(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "invalid.json"
            config.write_text("{}", encoding="utf-8")
            self.assertEqual(main([
                "--registry", str(config), "--text", "Create a project called Anything"
            ]), 7)


if __name__ == "__main__":
    unittest.main()
