from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_portfolio_health_rollup import (
    SCHEMA, OBSERVATION_SCHEMA, MAX_OBSERVATIONS, review_health_rollup
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config" / "watcher-v3-owner-selected-portfolio.example.json"
NOW = 1800000000


def portfolio():
    return json.loads(SOURCE.read_text(encoding="utf-8"))


def receipt(repository: str = "Universal-AI-", *, module_id=None,
            condition="OK", time=NOW):
    return {
        "schema": OBSERVATION_SCHEMA,
        "repository": repository,
        "module_id": module_id,
        "condition": condition,
        "observed_at_epoch_s": time,
        "origin": "UNTRUSTED_REVIEW_FIXTURE",
    }


class Stage34PortfolioHealthReviewTests(unittest.TestCase):
    def report(self, items=None, **kwargs):
        return review_health_rollup(
            portfolio=portfolio(),
            observations=[] if items is None else items,
            now_epoch_s=NOW,
            **kwargs,
        )

    def _assert_never_trusted(self, report):
        self.assertEqual(report["status"], "CALLER_REPORTED_DATA_ONLY_NO_VERIFIED_HEALTH")
        for field in (
            "all_project_data_sources_authenticated",
            "watcher_running_verified", "live_monitoring_enabled",
            "cross_project_access_enabled", "online_store_included",
            "owner_authenticated", "installation_authorized",
            "task_execution_authorized", "settings_changed",
        ):
            self.assertIs(report[field], False, field)
        self.assertEqual(report["verified_healthy_projects"], 0)
        self.assertEqual(report["verified_healthy_modules"], 0)
        for term in ("UP-UHAIB-001-Poindexter", "Kali-Linux-",
                     "NSFW", "online-store", "Universal-AI-"):
            self.assertNotIn(term, json.dumps(report))

    def test_no_sources_means_all_projects_and_modules_unknown(self):
        report = self.report()
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["selected_repository_count"], 9)
        self.assertEqual(report["nested_poindexter_module_count"], 19)
        self.assertEqual(report["reported_observations"], 0)
        self.assertEqual(report["missing_project_observations_unknown"], 9)
        self.assertEqual(report["missing_module_observations_unknown"], 19)
        self.assertEqual(report["unknown_total"], 28)
        self._assert_never_trusted(report)

    def test_ok_reported_but_never_verified_healthy(self):
        raw = [receipt("Universal-AI-", condition="OK")]
        original = deepcopy(raw)
        report = self.report(raw)
        self.assertEqual(raw, original)
        self.assertEqual(report["fresh_unverified_ok"], 1)
        self.assertEqual(report["missing_project_observations_unknown"], 8)
        self.assertEqual(report["missing_module_observations_unknown"], 19)
        self.assertEqual(report["unknown_total"], 27)
        self._assert_never_trusted(report)

    def test_alert_degraded_pause_and_unknown_not_collapsed(self):
        items = [
            receipt("Universal-AI-", condition="ALERT"),
            receipt("UASN-AI-Specialist", condition="DEGRADED"),
            receipt("powershell-connection", condition="PAUSED"),
            receipt("UP-RES-001-Autonomous-Research-System", condition="UNKNOWN"),
        ]
        report = self.report(items)
        for condition in ("alert", "degraded", "paused"):
            self.assertEqual(report["fresh_unverified_"+condition],1)
        self.assertEqual(report["explicit_unknown"],1)
        self.assertEqual(report["unknown_total"],25)
        self._assert_never_trusted(report)

    def test_stale_ok_becomes_unknown_not_healthy(self):
        item = receipt(time=NOW-301)
        report = self.report([item], max_age_s=300)
        self.assertEqual(report["stale_unknown"],1)
        self.assertEqual(report["fresh_unverified_ok"],0)
        self.assertEqual(report["unknown_total"],28)
        self._assert_never_trusted(report)

    def test_boundary_freshness_at_limit_is_unverified_not_stale(self):
        report = self.report([receipt(time=NOW-300)])
        self.assertEqual(report["fresh_unverified_ok"],1)
        self.assertEqual(report["stale_unknown"],0)

    def test_module_is_nested_and_does_not_create_new_project(self):
        report = self.report([
            receipt("UP-UHAIB-001-Poindexter",module_id="001"),
            receipt("UP-UHAIB-001-Poindexter",module_id="019",condition="ALERT"),
        ])
        self.assertEqual(report["selected_repository_count"],9)
        self.assertEqual(report["nested_poindexter_module_count"],19)
        self.assertEqual(report["missing_project_observations_unknown"],9)
        self.assertEqual(report["missing_module_observations_unknown"],17)
        self.assertEqual(report["fresh_unverified_ok"],1)
        self.assertEqual(report["fresh_unverified_alert"],1)
        self._assert_never_trusted(report)

    def test_project_and_module_receipts_are_distinct(self):
        report = self.report([
            receipt("UP-UHAIB-001-Poindexter",condition="PAUSED"),
            receipt("UP-UHAIB-001-Poindexter",module_id="001",condition="ALERT"),
        ])
        self.assertEqual(report["reported_observations"],2)
        self.assertEqual(report["missing_project_observations_unknown"],8)
        self.assertEqual(report["missing_module_observations_unknown"],18)

    def test_full_synthetic_inventory_is_bounded_and_untrusted(self):
        template=portfolio()
        items=[]
        for project in template["projects"]:
            items.append(receipt(project["repository"],condition="OK"))
            for mod in project["modules"]:
                items.append(receipt(project["repository"],module_id=mod["id"],condition="OK"))
        self.assertEqual(len(items), MAX_OBSERVATIONS)
        report=self.report(items)
        self.assertEqual(report["reported_observations"],28)
        self.assertEqual(report["fresh_unverified_ok"],28)
        self.assertEqual(report["unknown_total"],0)
        self._assert_never_trusted(report)
        items.append(receipt())
        with self.assertRaises(PolicyBlocked):
            self.report(items)

    def test_online_store_and_unselected_candidates_rejected(self):
        for name in ("online-store","School.tutor","RAID-AI","tasker-autoinput-bridge","sch1"):
            with self.subTest(repo=name):
                with self.assertRaises(PolicyBlocked):
                    self.report([receipt(name)])

    def test_invalid_module_ids_and_cross_project_module_forgery_denied(self):
        for name, mid in (("Universal-AI-","001"),
                          ("UP-UHAIB-001-Poindexter","020"),
                          ("UP-UHAIB-001-Poindexter",1),
                          ("UP-UHAIB-001-Poindexter",True)):
            with self.subTest(repo=name,mid=mid):
                with self.assertRaises(PolicyBlocked):
                    self.report([receipt(name,module_id=mid)])

    def test_duplicate_observations_cannot_override_alert(self):
        items=[receipt(condition="ALERT"),receipt(condition="OK")]
        with self.assertRaises(PolicyBlocked):
            self.report(items)
        items=[receipt("UP-UHAIB-001-Poindexter",module_id="001"),
               receipt("UP-UHAIB-001-Poindexter",module_id="001",condition="ALERT")]
        with self.assertRaises(PolicyBlocked):
            self.report(items)

    def test_untrusted_authority_fields_and_forged_provenance_rejected(self):
        altered=[]
        x=receipt();x["verified"]=True;altered.append(x)
        x=receipt();x["origin"]="WINDOWS_HELLO_AUTHENTICATED";altered.append(x)
        x=receipt();x["source_signature"]="00";altered.append(x)
        x=receipt();x["schema"]="upab.watcher-v3.live-health";altered.append(x)
        x=receipt();x["condition"]="HEALTHY_VERIFIED";altered.append(x)
        x=receipt();x["condition"]=True;altered.append(x)
        for x in altered:
            with self.subTest(x=str(x)[:100]):
                with self.assertRaises(PolicyBlocked):
                    self.report([x])

    def test_future_negative_bool_and_overflow_timestamps_denied(self):
        for when in (NOW+1, -1, True, "1800000000",2**53):
            with self.subTest(timestamp=when):
                with self.assertRaises(PolicyBlocked):
                    self.report([receipt(time=when)])
        for now in (True, -1, 2**53, "not-clock"):
            with self.subTest(now=now):
                with self.assertRaises(PolicyBlocked):
                    review_health_rollup(portfolio=portfolio(),observations=[],
                                         now_epoch_s=now)

    def test_freshness_limit_strictly_bounded(self):
        for limit in (0, 3601, True, 5.5, "300"):
            with self.subTest(limit=limit):
                with self.assertRaises(PolicyBlocked):
                    self.report([],max_age_s=limit)

    def test_invalid_observation_container_or_portfolio_denied(self):
        for observations in (None,{},[None],["anything"],""):
            with self.subTest(observations=observations):
                with self.assertRaises(PolicyBlocked):
                    self.report(observations)
        bad=portfolio()
        bad["projects"][0]["monitor_enabled"]=True
        with self.assertRaises(PolicyBlocked):
            review_health_rollup(portfolio=bad,observations=[],now_epoch_s=NOW)

    def test_no_io_or_execution_or_live_monitor_authority(self):
        import upab.relay.v3_portfolio_health_rollup as mod
        for name in ("scan", "start", "enable", "monitor", "install",
                     "fetch_github", "create_project", "connect_repository",
                     "read_folder", "execute_task", "approve", "activate"):
            self.assertFalse(hasattr(mod,name))


if __name__=="__main__":
    unittest.main()
