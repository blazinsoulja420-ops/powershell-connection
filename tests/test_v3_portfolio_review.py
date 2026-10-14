from __future__ import annotations

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_portfolio_review import (
    PROJECTS, POINDEXTER_MODULES, SCHEMA,
    load_portfolio_preview, validate_portfolio_preview, main,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config" / "watcher-v3-owner-selected-portfolio.example.json"


def template():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


class Stage33PortfolioReviewTests(unittest.TestCase):
    def test_exact_selected_nine_projects_and_nineteen_modules_stay_inert(self):
        raw = template()
        before = deepcopy(raw)
        result = validate_portfolio_preview(raw)
        self.assertEqual(result["selected_repository_count"],9)
        self.assertEqual(result["poindexter_module_category_count"],19)
        self.assertEqual(result["additional_repositories_from_modules"],0)
        self.assertEqual(result["project_limit"],64)
        self.assertEqual(result["monitor_limit"],32)
        self.assertEqual(result["monitoring_enabled_count"],0)
        self.assertEqual(result["connections_enabled_count"],0)
        self.assertTrue(result["excluded_online_store"])
        self.assertTrue(result["restricted_projects_retain_boundaries"])
        self.assertEqual(result["status"],"OWNER_SELECTED_ROSTER_VALIDATED_NOT_ACTIVATED")
        for field in (
            "github_repository_permission_granted","chat_creation_authorized",
            "local_folder_creation_authorized","owner_authenticated",
            "monitoring_installed","task_execution_authorized","settings_changed"
        ):
            self.assertIs(result[field],False,field)
        self.assertEqual(raw,before)
        self.assertEqual(len(POINDEXTER_MODULES),19)
        self.assertEqual(len(PROJECTS),9)
        for sensitive in ("blazinsoulja420-ops","Kali-Linux-","NSFW","online-store"):
            self.assertNotIn(sensitive,json.dumps(result))

    def test_exact_source_example_is_unchanged_by_load(self):
        before = EXAMPLE.read_bytes()
        result = load_portfolio_preview(EXAMPLE)
        self.assertEqual(result["selected_repository_count"],9)
        self.assertEqual(EXAMPLE.read_bytes(),before)

    def test_project_roster_must_never_auto_expand(self):
        for name in ("online-store","School.tutor","RAID-AI","sch1",
                     "tasker-autoinput-bridge","Integration-Interoperability"):
            with self.subTest(name=name):
                raw = template()
                raw["projects"][-1]["repository"]=name
                with self.assertRaises(PolicyBlocked):
                    validate_portfolio_preview(raw)

    def test_missing_duplicate_renamed_and_extra_projects_refused(self):
        cases=[]
        raw=template();raw["projects"].pop();cases.append(raw)
        raw=template();raw["projects"][1]["repository"]=raw["projects"][0]["repository"];cases.append(raw)
        raw=template();raw["projects"][0]["repository"]="UP-UHAIB-001-Poindexter-renamed";cases.append(raw)
        raw=template();raw["projects"].append(deepcopy(raw["projects"][0]));cases.append(raw)
        for index,raw in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(PolicyBlocked):
                    validate_portfolio_preview(raw)

    def test_module_identity_must_remain_nested_and_exact(self):
        bad=[]
        raw=template();raw["projects"][0]["modules"].pop();bad.append(raw)
        raw=template();raw["projects"][0]["modules"][4]["id"]="001";bad.append(raw)
        raw=template();raw["projects"][0]["modules"][3]["category"]="Unreviewed";bad.append(raw)
        raw=template();raw["projects"][0]["modules"][3]["id"]="999";bad.append(raw)
        raw=template();raw["projects"][1]["modules"]=[deepcopy(raw["projects"][0]["modules"][0])];bad.append(raw)
        raw=template();raw["projects"][0]["modules"][0]["repository"]="new-module-repo";bad.append(raw)
        raw=template();raw["projects"][0]["modules"][0]["id"]=1;bad.append(raw)
        for index,raw in enumerate(bad):
            with self.subTest(index=index):
                with self.assertRaises(PolicyBlocked):
                    validate_portfolio_preview(raw)

    def test_monitoring_or_connections_may_not_be_enabled(self):
        for edit in (
            lambda d: d.update(auto_activation=True),
            lambda d: d.update(connections=[{"source":"Poindexter","target":"Universal-AI-"}]),
            lambda d: d["projects"][0].update(monitor_enabled=True),
            lambda d: d["projects"][0]["modules"][0].update(monitor_enabled=True),
            lambda d: d.update(auto_activation=0),
            lambda d: d.update(connections=None),
        ):
            raw=template();edit(raw)
            with self.assertRaises(PolicyBlocked):
                validate_portfolio_preview(raw)

    def test_capacities_restrictions_ownership_and_unknown_keys_enforced(self):
        for edit in (
            lambda d: d.update(project_limit=65),
            lambda d: d.update(monitor_limit=33),
            lambda d: d.update(project_limit=True),
            lambda d: d.update(owner="some-other-user"),
            lambda d: d.update(basis="untrusted-discovery"),
            lambda d: d.update(schema="unversioned"),
            lambda d: d["projects"][-1].update(scope="STANDALONE"),
            lambda d: d["projects"][-2].update(scope="STANDALONE"),
            lambda d: d.update(paths=["C:\\private"]),
            lambda d: d["projects"][0].update(command="install"),
        ):
            raw=template();edit(raw)
            with self.assertRaises(PolicyBlocked):
                validate_portfolio_preview(raw)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"sample.json"
            path.write_text('{"schema":"a","schema":"b"}',encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                load_portfolio_preview(path)

    def test_symlink_and_relative_config_are_rejected(self):
        with self.assertRaises(PolicyBlocked):
            load_portfolio_preview("relative.json")
        with tempfile.TemporaryDirectory() as td:
            link=Path(td)/"pointer.json"
            try:
                link.symlink_to(EXAMPLE)
            except (OSError, NotImplementedError):
                self.skipTest("OS disallows symlink creation")
            with self.assertRaises(PolicyBlocked):
                load_portfolio_preview(link)

    def test_file_size_bounded_and_invalid_file_denied(self):
        with tempfile.TemporaryDirectory() as td:
            selected=Path(td)/"big.json"
            selected.write_bytes(b"x"*16385)
            with self.assertRaises(PolicyBlocked):
                load_portfolio_preview(selected)
            with self.assertRaises(PolicyBlocked):
                load_portfolio_preview(Path(td)/"missing.json")

    def test_read_only_cli_receipt_never_exports_repo_names_or_paths(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--config",str(EXAMPLE)]),0)
        result=json.loads(out.getvalue())
        self.assertFalse(result["task_execution_authorized"])
        self.assertEqual(result["poindexter_module_category_count"],19)
        self.assertNotIn(str(EXAMPLE),out.getvalue())
        self.assertNotIn("UP-UHAIB-001-Poindexter",out.getvalue())

    def test_no_execution_or_mutation_service_surface(self):
        import upab.relay.v3_portfolio_review as module
        for name in ("run_watcher","install","enable","monitor","activate",
                     "connect_repository","create_project","create_chat",
                     "migrate","execute","delete_folder","write_state",
                     "owner_approve","add_repository","start_service"):
            self.assertFalse(hasattr(module,name))


if __name__=="__main__":
    unittest.main()
