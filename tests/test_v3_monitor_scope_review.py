from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_monitor_scope_review import (
    SCHEMA, REPORT_SCHEMA, review_monitoring_scope
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "watcher-v3-owner-selected-portfolio.example.json"


def portfolio():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def request(*, names=None, modules=None, preview=True):
    return {
        "schema": SCHEMA,
        "requested_repositories": [] if names is None else names,
        "requested_poindexter_module_ids": [] if modules is None else modules,
        "preview_only": preview,
    }


class Stage35MonitorScopeReviewTests(unittest.TestCase):
    def _report(self, proposal):
        return review_monitoring_scope(portfolio=portfolio(), request=proposal)

    def _all_denied(self, report):
        self.assertEqual(report["schema"], REPORT_SCHEMA)
        self.assertEqual(report["status"],
                         "SCOPE_PREVIEW_NEEDS_INDEPENDENT_OWNER_AND_DEVICE_APPROVAL")
        for key in (
            "owner_selected_repositories_are_connected",
            "requested_paths_present",
            "live_monitoring_enabled",
            "verified_project_health",
            "restricted_repo_access_granted",
            "cross_repository_access_granted",
            "online_store_included",
            "chat_or_folder_creation_authorized",
            "task_execution_authorized",
            "owner_authenticated",
            "settings_changed",
        ):
            self.assertFalse(report[key], key)
        self.assertEqual(report["approved_local_directory_roots"], 0)
        self.assertEqual(report["actual_monitored_root_count"], 0)
        rendered=json.dumps(report)
        for name in ("NSFW", "Kali-Linux-", "online-store",
                     "UP-UHAIB-001-Poindexter", "powershell-connection"):
            self.assertNotIn(name, rendered)

    def test_empty_request_is_inert(self):
        proposal=request()
        before=deepcopy(proposal)
        report=self._report(proposal)
        self.assertEqual(report["requested_repository_scope_reviews"],0)
        self.assertEqual(report["requested_nested_module_reviews"],0)
        self.assertEqual(report["potential_watch_roots_after_separate_approval"],0)
        self._all_denied(report)
        self.assertEqual(before,proposal)

    def test_all_nine_projects_and_nineteen_modules_consume_only_nine_potential_slots(self):
        template=portfolio()
        names=[p["repository"] for p in template["projects"]]
        modules=[m["id"] for m in template["projects"][0]["modules"]]
        proposal=request(names=names,modules=modules)
        initial=deepcopy(proposal)
        report=self._report(proposal)
        self.assertEqual(report["selected_portfolio_projects"],9)
        self.assertEqual(report["selected_poindexter_modules"],19)
        self.assertEqual(report["requested_repository_scope_reviews"],9)
        self.assertEqual(report["requested_nested_module_reviews"],19)
        self.assertEqual(report["additional_watch_roots_for_nested_modules"],0)
        self.assertEqual(report["potential_watch_roots_after_separate_approval"],9)
        self.assertEqual(report["maximum_registered_project_capacity"],64)
        self.assertEqual(report["maximum_concurrent_monitor_capacity"],32)
        self.assertEqual(report["restricted_project_scope_reviews"],2)
        self.assertEqual(report["watcher_self_monitoring_scope_reviews"],1)
        self.assertEqual(report["other_scope_reviews"],6)
        self._all_denied(report)
        self.assertEqual(proposal,initial)

    def test_nested_modules_do_not_create_roots(self):
        report=self._report(request(
            names=["UP-UHAIB-001-Poindexter"],modules=["001","016","019"]))
        self.assertEqual(report["requested_repository_scope_reviews"],1)
        self.assertEqual(report["requested_nested_module_reviews"],3)
        self.assertEqual(report["additional_watch_roots_for_nested_modules"],0)
        self._all_denied(report)

    def test_module_without_parent_project_is_refused(self):
        with self.assertRaises(PolicyBlocked):
            self._report(request(names=["Universal-AI-"],modules=["001"]))
        with self.assertRaises(PolicyBlocked):
            self._report(request(modules=["001"]))

    def test_restricted_projects_never_receive_implicit_access(self):
        report=self._report(request(names=["NSFW","Kali-Linux-"]))
        self.assertEqual(report["restricted_project_scope_reviews"],2)
        self.assertEqual(report["actual_monitored_root_count"],0)
        self._all_denied(report)

    def test_self_reference_is_reported_without_starting_watcher(self):
        report=self._report(request(names=["powershell-connection"]))
        self.assertEqual(report["watcher_self_monitoring_scope_reviews"],1)
        self.assertEqual(report["actual_monitored_root_count"],0)
        self._all_denied(report)

    def test_order_independent_report_without_identity_leaks(self):
        a=self._report(request(names=["Universal-AI-","UP-UHAIB-001-Poindexter"],
                               modules=["002","001"]))
        b=self._report(request(names=["UP-UHAIB-001-Poindexter","Universal-AI-"],
                               modules=["001","002"]))
        self.assertEqual(a,b)

    def test_online_store_and_unselected_repositories_rejected(self):
        for name in ("online-store","School.tutor","RAID-AI",
                     "tasker-autoinput-bridge","Master-Mechanic-AI",
                     "UnknownSource",""):
            with self.subTest(name=name):
                with self.assertRaises(PolicyBlocked):
                    self._report(request(names=[name]))

    def test_duplicate_projects_and_modules_refused(self):
        for proposal in (
            request(names=["Universal-AI-","Universal-AI-"]),
            request(names=["UP-UHAIB-001-Poindexter"],modules=["019","019"]),
        ):
            with self.assertRaises(PolicyBlocked):
                self._report(proposal)

    def test_rogue_modules_or_wrong_identity_rejected(self):
        for mod in ("020","Not a module",1,True,None,""):
            with self.subTest(mod=mod):
                with self.assertRaises(PolicyBlocked):
                    self._report(request(names=["UP-UHAIB-001-Poindexter"],
                                         modules=[mod]))

    def test_activating_claims_commands_paths_and_connections_refused(self):
        for change in (
            lambda v: v.update(preview_only=False),
            lambda v: v.update(preview_only=1),
            lambda v: v.update(watcher_enabled=True),
            lambda v: v.update(folder_path="C:\\private"),
            lambda v: v.update(exec_command="Run now"),
            lambda v: v.update(connections=["all"]),
            lambda v: v.update(owner_authenticated=True),
            lambda v: v.update(schema="forged"),
        ):
            proposal=request(names=["Universal-AI-"])
            change(proposal)
            with self.assertRaises(PolicyBlocked):
                self._report(proposal)

    def test_bad_containers_and_oversized_requests_rejected(self):
        for proposal in (
            [],None,{},True,"all",
            request(names="Universal-AI-"),
            request(modules="001"),
            request(names=[1]),
            request(names=["Universal-AI-"]*10),
            request(names=["UP-UHAIB-001-Poindexter"],modules=["001"]*20),
        ):
            with self.subTest(proposal=str(proposal)[:75]):
                with self.assertRaises(PolicyBlocked):
                    self._report(proposal)

    def test_tampered_portfolio_cannot_reuse_scope_request(self):
        for change in (
            lambda p: p["projects"][0].update(monitor_enabled=True),
            lambda p: p.update(project_limit=65),
            lambda p: p["projects"].append({"repository":"online-store"}),
        ):
            p=portfolio()
            change(p)
            with self.assertRaises(PolicyBlocked):
                review_monitoring_scope(portfolio=p,request=request())

    def test_no_authoritative_execution_or_discovery_api(self):
        import upab.relay.v3_monitor_scope_review as module
        for attr in ("monitor", "start", "install", "approve", "register_project",
                     "watch", "create_chat","create_folder","connect_repository",
                     "scan_folder","read_secret","enable_task","execute_task",
                     "terminate_process","access_restricted_repo"):
            self.assertFalse(hasattr(module,attr))


if __name__ == "__main__":
    unittest.main()
