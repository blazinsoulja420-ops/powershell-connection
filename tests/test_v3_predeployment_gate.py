from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from upab.relay.v3_features import load_feature_catalog
from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_predeployment_gate import (
    _capture, _CHECKS, _CONTRACTS,
    collect_local_predeployment, evaluate_predeployment, main,
)

FEATURES = (Path(__file__).resolve().parents[1] /
            "config" / "watcher-v3-features.example.json")


def inert(kind: str):
    schema, fields = _CONTRACTS[kind]
    return {"schema": schema, **{flag: False for flag in fields}}


class Stage22ReadOnlyPredeploymentGateTests(unittest.TestCase):
    def setUp(self):
        self.features=load_feature_catalog(FEATURES)

    def test_no_observations_still_disables_activation_and_preserves_limits(self):
        result=evaluate_predeployment(feature_report=self.features)
        self.assertEqual(result["status"],"BLOCKED_NOT_DEPLOYABLE")
        self.assertEqual(result["feature_flags_enabled"],0)
        self.assertEqual(result["registered_project_limit"],64)
        self.assertEqual(result["active_folder_monitor_limit"],32)
        self.assertEqual(result["checks_not_requested"],len(_CHECKS))
        self.assertEqual(result["checks_partially_observed"],0)
        self.assertGreater(len(result["blockers"]),len(_CHECKS))
        for label in (
            "report_is_authenticated_approval","actual_owner_authenticated",
            "legacy_watcher_stopped_proven","backup_protected_and_restored_proven",
            "live_repository_attested", "safe_to_migrate",
            "safe_to_enable_features","safe_to_install",
            "task_execution_authorized","changes_performed",
        ):
            self.assertIs(result[label],False,label)

    def test_even_all_eight_inert_observations_cannot_authorize(self):
        input_reports={name:inert(name) for name in _CHECKS}
        record=evaluate_predeployment(feature_report=self.features,
                                      observations=input_reports)
        self.assertEqual(record["checks_partially_observed"],8)
        self.assertEqual(record["checks_not_requested"],0)
        self.assertEqual(record["status"],"BLOCKED_NOT_DEPLOYABLE")
        self.assertEqual(record["safe_to_migrate"],False)
        self.assertEqual(record["safe_to_install"],False)
        self.assertEqual(record["task_execution_authorized"],False)
        self.assertIn("OWNER_WINDOWS_HELLO_REGISTRATION_NOT_VERIFIED",
                      record["blockers"])
        self.assertNotIn("source_state",record)
        self.assertNotIn("backup_root",record)

    def test_fake_owner_authority_rejected_for_each_source(self):
        for kind in _CHECKS:
            schema, flags = _CONTRACTS[kind]
            record=inert(kind)
            record[flags[0]]=True
            with self.subTest(kind=kind):
                with self.assertRaises(PolicyBlocked):
                    evaluate_predeployment(
                        feature_report=self.features,observations={kind:record}
                    )
                self.assertFalse(
                    evaluate_predeployment(feature_report=self.features)[
                        "task_execution_authorized"]
                )

    def test_incomplete_or_forged_schemas_never_count_as_observed(self):
        for kind in _CHECKS:
            record=inert(kind)
            with self.subTest(kind=kind):
                record["schema"]="forged.other.schema"
                with self.assertRaises(PolicyBlocked):
                    evaluate_predeployment(
                        feature_report=self.features, observations={kind:record}
                    )
                record=inert(kind)
                del record[_CONTRACTS[kind][1][0]]
                with self.assertRaises(PolicyBlocked):
                    evaluate_predeployment(
                        feature_report=self.features, observations={kind:record}
                    )

    def test_disabled_feature_catalog_cannot_be_replaced_with_claimed_enabled(self):
        for name,value in (
            ("activated_upgrades",1),
            ("execution_enabled",True),
            ("project_limit",65),
            ("monitor_limit",33),
            ("registered_upgrades",13),
        ):
            with self.subTest(field=name):
                altered=deepcopy(self.features)
                altered[name]=value
                with self.assertRaises(PolicyBlocked):
                    evaluate_predeployment(feature_report=altered)

    def test_stage_registry_names_and_labels_checked_even_for_inert_receipt(self):
        wrong_names=deepcopy(self.features)
        stages=wrong_names["stages"]
        key=next(iter(stages))
        stages["not-a-registered-upgrade"]=stages.pop(key)
        with self.assertRaises(PolicyBlocked):
            evaluate_predeployment(feature_report=wrong_names)
        wrong_value=deepcopy(self.features)
        key=next(iter(wrong_value["stages"]))
        wrong_value["stages"][key]="activated"
        with self.assertRaises(PolicyBlocked):
            evaluate_predeployment(feature_report=wrong_value)

    def test_unknown_and_bare_positive_observation_states_denied(self):
        for entries in (
            {"unknown-surface":{"state":"BLOCKED"}},
            {"task_scheduler":{"state":"OBSERVED_PARTIAL"}},
            {"task_scheduler":{"state":"SAFE"}},
            {"task_scheduler":{"state":"BLOCKED","secret":"unexpected"}},
            {"task_scheduler":True},
            [("task_scheduler","BLOCKED")],
        ):
            with self.subTest(entries=entries):
                with self.assertRaises(PolicyBlocked):
                    evaluate_predeployment(feature_report=self.features,
                                           observations=entries)
        report=evaluate_predeployment(
            feature_report=self.features,
            observations={"task_scheduler":{"state":"BLOCKED"}}
        )
        self.assertEqual(report["checks_blocked"],1)
        self.assertIn("OBSERVATION_BLOCKED:task_scheduler",report["blockers"])
        self.assertFalse(report["safe_to_install"])

    def test_read_only_feature_only_mode_does_not_touch_system(self):
        result=collect_local_predeployment(feature_config=FEATURES)
        self.assertEqual(result["checks_not_requested"],8)
        self.assertEqual(result["checks_partially_observed"],0)
        self.assertFalse(result["changes_performed"])
        self.assertFalse(result["safe_to_migrate"])
        self.assertEqual(main(["--features",str(FEATURES)]),0)

    def test_no_local_state_scans_without_explicit_opt_in(self):
        for kwargs in (
            {"backup_root":"C:/synthetic"},
            {"source_state":"C:/synthetic"},
            {"collect_windows":"true"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PolicyBlocked):
                    collect_local_predeployment(feature_config=FEATURES,**kwargs)
        if sys.platform!="win32":
            with self.assertRaises(PolicyBlocked):
                collect_local_predeployment(feature_config=FEATURES,
                                            collect_windows=True)

    def test_observation_failure_is_only_sanitized_blocked(self):
        def leaked_exception():
            raise PolicyBlocked("C:\\Sensitive\\do-not-print.txt")
        result=_capture("task_scheduler",leaked_exception)
        self.assertEqual(result,{"state":"BLOCKED"})
        report=evaluate_predeployment(
            feature_report=self.features,observations={"task_scheduler":result}
        )
        self.assertNotIn("Sensitive",str(report))
        self.assertEqual(report["checks_blocked"],1)
        self.assertFalse(report["task_execution_authorized"])

    @unittest.skipUnless(sys.platform=="win32", "Windows opt-in scanning integration")
    def test_explicit_windows_scan_still_cannot_authorize_execution(self):
        # Patch the scans to test orchestration/sanitization without
        # treating the CI runner or its state as user laptop evidence.
        import upab.relay.v3_windows_cutover_preflight as process
        import upab.relay.v3_authoritative_launch_snapshot as launches
        import upab.relay.v3_windows_startup_surfaces as startup
        import upab.relay.v3_owner_enrollment_preflight as hello
        patches=(
            mock.patch.object(process,"snapshot_possible_host_processes",
                              return_value=inert("win32_process_snapshot")),
            mock.patch.object(launches,"observe_scm_services",
                              return_value=inert("service_control_manager")),
            mock.patch.object(launches,"observe_registered_tasks",
                              side_effect=PolicyBlocked("private path")),
            mock.patch.object(startup,"observe_known_startup_surfaces",
                              return_value=inert("registry_startup_surfaces")),
            mock.patch.object(hello,"preflight_owner_enrollment",
                              return_value=inert("windows_hello_preflight")),
        )
        with patches[0],patches[1],patches[2],patches[3],patches[4]:
            report=collect_local_predeployment(
                feature_config=FEATURES,collect_windows=True
            )
        self.assertEqual(report["checks_partially_observed"],4)
        self.assertEqual(report["checks_blocked"],1)
        self.assertEqual(report["checks_not_requested"],3)
        self.assertIn("OBSERVATION_BLOCKED:task_scheduler",report["blockers"])
        self.assertFalse(report["safe_to_install"])
        self.assertFalse(report["actual_owner_authenticated"])

    def test_report_digest_is_deterministic_not_approval_proof(self):
        left=evaluate_predeployment(feature_report=self.features)
        right=evaluate_predeployment(feature_report=self.features)
        self.assertEqual(left["sanitized_untrusted_report_sha256"],
                         right["sanitized_untrusted_report_sha256"])
        self.assertEqual(len(left["sanitized_untrusted_report_sha256"]),64)
        self.assertFalse(left["report_is_authenticated_approval"])

    def test_no_executor_merge_or_repo_connector_api(self):
        import upab.relay.v3_predeployment_gate as m
        for name in ("approve", "execute_task", "install", "deploy",
                     "merge_pull_request", "stop_watcher", "enable_feature",
                     "connect_repository", "authorize_migration",
                     "make_credential", "issue_token"):
            self.assertFalse(hasattr(m,name))


if __name__ == "__main__":
    unittest.main()
