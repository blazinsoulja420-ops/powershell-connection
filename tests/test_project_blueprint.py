from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.multiwatch import ProjectRegistry
from upab.project_blueprint import BlueprintError, preview_blueprint, main
from upab.project_intake import classify_request


def registry() -> ProjectRegistry:
    return ProjectRegistry.from_object({
        "schema": "upab.multi-project.registry.v1",
        "projects": [
            {
                "id": "universal-ai", "repository": "blazinsoulja420-ops/Universal-AI-",
                "channel_id": "upab-universal-ai", "watch_enabled": False,
                "execution_enabled": False, "local_root": None, "state_directory": None,
            }
        ],
    })


class BlueprintPreviewTests(unittest.TestCase):
    def test_preview_six_distinct_workstreams_without_action(self):
        proposal = classify_request("Create a project called Motorcycle Repair Copilot", registry())
        plan = preview_blueprint(proposal)
        self.assertEqual(plan["status"], "PREVIEW_ONLY")
        self.assertIsNone(plan["root_path"])
        self.assertEqual(plan["project_id"], "motorcycle-repair-copilot")
        self.assertEqual(len(plan["proposed_chats"]), 6)
        self.assertEqual(len({
            item["proposed_chat_title"] for item in plan["proposed_chats"]
        }), 6)
        self.assertFalse(plan["folder_created"])
        self.assertFalse(plan["repo_created"])
        self.assertFalse(plan["chat_created"])
        self.assertFalse(plan["creation_authorized"])
        for chat in plan["proposed_chats"]:
            self.assertFalse(chat["chat_created"])
            self.assertIn("requires separate verified authority", chat["starting_prompt"])
            self.assertIn("PROPOSED", chat["starting_prompt"])

    def test_idea_receives_preview_but_not_approval(self):
        proposal = classify_request("I want to build a motorcycle repair tool", registry())
        plan = preview_blueprint(proposal)
        self.assertTrue(plan["review_required"])
        self.assertFalse(plan["creation_authorized"])

    def test_duplicate_and_ambiguous_names_cannot_be_blueprinted(self):
        for text in (
            "Create a project called Universal AI",
            "Create a project called !",
            "Please create a new project",
            "What are we building?",
        ):
            with self.subTest(text=text):
                with self.assertRaises(BlueprintError):
                    preview_blueprint(classify_request(text, registry()))

    def test_forged_proposal_approval_is_not_accepted(self):
        proposal = classify_request("Create a project called Bookkeeping Assistant", registry())
        proposal["creation_authorized"] = True
        with self.assertRaisesRegex(BlueprintError, "forbidden"):
            preview_blueprint(proposal)

    def test_relative_paths_are_fixed_and_non_executable(self):
        proposal = classify_request("Create a project called Bookkeeping Assistant", registry())
        plan = preview_blueprint(proposal)
        for item in plan["relative_files"] + plan["relative_folders"]:
            self.assertNotIn("..", item)
            self.assertFalse(Path(item).is_absolute())
        self.assertNotIn("powershell.exe", json.dumps(plan))
        self.assertNotIn("git push", json.dumps(plan))

    def test_cli_is_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            config = folder / "registry.json"
            config.write_text(json.dumps({
                "schema": "upab.multi-project.registry.v1",
                "projects": [
                    {
                        "id": "universal-ai",
                        "repository": "blazinsoulja420-ops/Universal-AI-",
                        "channel_id": "upab-universal-ai",
                        "watch_enabled": False,
                        "execution_enabled": False,
                        "local_root": None, "state_directory": None,
                    }
                ],
            }), encoding="utf-8")
            before = set(folder.rglob("*"))
            self.assertEqual(
                main([
                    "--registry", str(config),
                    "--text", "Create a project called Bookkeeping Assistant"
                ]),
                0,
            )
            self.assertEqual(before, set(folder.rglob("*")))

    def test_cli_rejects_existing_project_without_writing(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "registry.json"
            config.write_text(json.dumps({
                "schema": "upab.multi-project.registry.v1",
                "projects": [
                    {
                        "id": "universal-ai",
                        "repository": "blazinsoulja420-ops/Universal-AI-",
                        "channel_id": "upab-universal-ai",
                        "watch_enabled": False,
                        "execution_enabled": False,
                        "local_root": None, "state_directory": None,
                    }
                ],
            }), encoding="utf-8")
            self.assertEqual(
                main(["--registry", str(config), "--text", "Create a project called Universal AI"]),
                7,
            )


if __name__ == "__main__":
    unittest.main()
