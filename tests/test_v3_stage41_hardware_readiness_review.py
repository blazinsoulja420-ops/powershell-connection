"""Stage 41: untrusted hardware-readiness evidence must never grant authority."""
from __future__ import annotations

import copy
import json
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_stage41_hardware_readiness_review import (
    SCHEMA, FIELDS, CAPABILITY_FIELDS, assess_untrusted_hardware_report,
)

NOW = 1_800_000_000


def fixture():
    return {
        "schema": SCHEMA,
        "source_kind": "SYNTHETIC_FIXTURE",
        "captured_at_epoch_s": NOW,
        "platform": "WINDOWS",
        "tpm_present": True,
        "tpm_ready": True,
        "tpm_enabled": True,
        "tpm_activated": True,
        "webauthn_api_present": True,
    }


class Stage41HardwareReadinessReviewTests(unittest.TestCase):
    def assess(self, obj=None, **args):
        return assess_untrusted_hardware_report(
            fixture() if obj is None else obj, now_epoch_s=NOW, **args)

    def assert_denied(self, report):
        assert_keys = (
            "owner_authorized_device_preflight", "real_device_inspected",
            "tpm_nv_capability_verified", "protected_ledger_available",
            "hardware_monotonic_store_verified", "owner_presence_verified",
            "collector_enrollment_authorized", "credential_created",
            "tpm_provisioning_authorized", "monitoring_enabled",
            "task_execution_authorized", "project_roster_modified",
        )
        for key in assert_keys:
            self.assertIs(report[key], False, key)
        self.assertTrue(report["owner_approval_required_for_next_probe"])
        self.assertEqual(report["evidence_trust"], "UNTRUSTED_SELF_REPORT")

    def test_all_positive_report_never_grants_access(self):
        report = self.assess()
        self.assertEqual(report["status"], "UNTRUSTED_CAPABILITY_CLAIM_ONLY")
        self.assertEqual(report["missing_capability_field_count"], 0)
        self.assert_denied(report)

    def test_each_negative_capability_is_reported_gap(self):
        for field in CAPABILITY_FIELDS:
            obj = fixture()
            obj[field] = False
            with self.subTest(field=field):
                report = self.assess(obj)
                self.assertEqual(report["status"], "REPORTED_CAPABILITY_GAP")
                self.assert_denied(report)

    def test_none_capability_fails_closed_and_counted(self):
        for field in CAPABILITY_FIELDS:
            obj = fixture()
            obj[field] = None
            with self.subTest(field=field):
                report = self.assess(obj)
                self.assertEqual(report["status"],
                                 "INCOMPLETE_OR_UNSUPPORTED_UNTRUSTED_REPORT")
                self.assertEqual(report["missing_capability_field_count"], 1)
                self.assert_denied(report)

    def test_unknown_platform_never_accepted(self):
        for platform in ("UNKNOWN", "OTHER"):
            obj = fixture()
            obj["platform"] = platform
            self.assertEqual(self.assess(obj)["status"],
                             "INCOMPLETE_OR_UNSUPPORTED_UNTRUSTED_REPORT")

    def test_future_or_stale_reports_cannot_be_inferred_fresh(self):
        for observed in (NOW + 1, NOW - 901, 0):
            obj = fixture()
            obj["captured_at_epoch_s"] = observed
            self.assertEqual(self.assess(obj)["status"],
                             "STALE_OR_FUTURE_UNTRUSTED_REPORT")
            self.assert_denied(self.assess(obj))

    def test_age_boundary_is_exact_and_still_untrusted(self):
        obj = fixture()
        obj["captured_at_epoch_s"] = NOW - 900
        self.assertEqual(self.assess(obj)["status"], "UNTRUSTED_CAPABILITY_CLAIM_ONLY")
        self.assert_denied(self.assess(obj))

    def test_approval_and_provisioning_injected_fields_rejected(self):
        for extra in ("owner_authorized", "allow_tpm_nv", "execution_authorized",
                      "owner_presence_verified", "project_list", "private_key"):
            obj = fixture()
            obj[extra] = True
            with self.subTest(extra=extra), self.assertRaises(PolicyBlocked):
                self.assess(obj)

    def test_missing_required_field_rejected_not_assumed(self):
        for key in FIELDS:
            obj = fixture()
            obj.pop(key)
            with self.subTest(key=key), self.assertRaises(PolicyBlocked):
                self.assess(obj)

    def test_wrong_schema_and_source_rejected(self):
        for field, value in (
            ("schema", "upab.watcher-v3.hardware-readiness-report.v2"),
            ("schema", None),
            ("source_kind", "SIGNED_GITHUB_CI"),
            ("source_kind", []),
            ("source_kind", True),
            ("platform", "Linux"),
            ("platform", []),
        ):
            obj = fixture()
            obj[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(PolicyBlocked):
                self.assess(obj)

    def test_strings_numbers_and_objects_cannot_fake_bool(self):
        for value in ("True", 1, 0, [], {}, 1.0):
            obj = fixture()
            obj["tpm_ready"] = value
            with self.subTest(value=value), self.assertRaises(PolicyBlocked):
                self.assess(obj)

    def test_bad_time_types_and_bounds(self):
        for stamp in (True, False, "1800000000", -1, [], 253402300800):
            obj = fixture()
            obj["captured_at_epoch_s"] = stamp
            with self.subTest(stamp=stamp), self.assertRaises(PolicyBlocked):
                self.assess(obj)
        for now in (True, "1800000000", -1, 253402300800):
            with self.subTest(now=now), self.assertRaises(PolicyBlocked):
                assess_untrusted_hardware_report(fixture(), now_epoch_s=now)

    def test_invalid_age_budget_rejected(self):
        for age in (True, None, 0, -1, 86401, "900", 1.2):
            with self.subTest(age=age), self.assertRaises(PolicyBlocked):
                self.assess(max_age_s=age)

    def test_caller_report_has_no_more_trust_than_fixture(self):
        obj = fixture()
        obj["source_kind"] = "CALLER_REPORTED"
        self.assert_denied(self.assess(obj))
        self.assertEqual(self.assess(obj)["status"], "UNTRUSTED_CAPABILITY_CLAIM_ONLY")

    def test_pure_review_does_not_modify_input(self):
        obj = fixture()
        before = copy.deepcopy(obj)
        first = self.assess(obj)
        second = self.assess(obj)
        self.assertEqual(first, second)
        self.assertEqual(obj, before)
        self.assertNotIn("captured_at_epoch_s", first)
        self.assertNotIn("source_kind", first)
        self.assertNotIn("tpm_ready", first)

    def test_no_powershell_webauthn_or_tpm_execution_entrypoints(self):
        import upab.relay.v3_stage41_hardware_readiness_review as module
        for name in ("Get_Tpm", "run_command", "get_tpm",
                     "invoke_webauthn", "make_credential", "take_ownership",
                     "create_nv_index", "clear_tpm", "enable_watcher",
                     "start_monitor", "approve", "execute_task", "connect_repo"):
            self.assertFalse(hasattr(module, name))
        self.assert_denied(self.assess())

    def test_report_is_bounded_and_redacted(self):
        output = json.dumps(self.assess(), sort_keys=True)
        self.assertLess(len(output), 1600)
        self.assertNotIn("SYNTHETIC_FIXTURE", output)
        self.assertNotIn("WINDOWS", output)
        self.assertNotIn("1800000000", output)


if __name__ == "__main__":
    unittest.main()
