"""Stage 42 synthetic transition tests (offline; no operational authority)."""
from copy import deepcopy
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_stage42_monotonic_transition_review import (
    LEDGER_SCHEMA, WITNESS_SCHEMA, PENDING_SCHEMA, BOUNDARIES,
    model_synthetic_crash_boundary, review_synthetic_transition,
)

LID = 'a' * 32
OLD = 'b' * 64
NEW = 'c' * 64
KEY = 'd' * 64
REPLACEMENT = 'e' * 64


def base():
    return ({'schema': LEDGER_SCHEMA, 'ledger_id': LID, 'epoch': 7,
             'committed_digest': OLD, 'phase': 'READY', 'pending': None},
            {'schema': WITNESS_SCHEMA, 'ledger_id': LID, 'epoch': 7,
             'committed_digest': OLD, 'availability': 'PRESENT'})


def proposal(action='HEALTH_ADVANCE'):
    return {'schema': PENDING_SCHEMA, 'action': action, 'repository': 'Universal-AI-',
            'module_id': None, 'expected_epoch': 7, 'next_epoch': 8,
            'previous_digest': OLD, 'next_digest': NEW,
            'previous_sequence': 22 if action == 'HEALTH_ADVANCE' else None,
            'next_sequence': 23 if action == 'HEALTH_ADVANCE' else None,
            'previous_key_id': KEY,
            'next_key_id': KEY if action == 'HEALTH_ADVANCE' else (
                REPLACEMENT if action == 'COLLECTOR_ROTATE' else None)}


class Stage42TransitionTests(unittest.TestCase):
    def model(self, action='HEALTH_ADVANCE', point='AFTER_FINALIZE', p=None):
        db, witness = base()
        return model_synthetic_crash_boundary(
            ledger=db, witness=witness, proposal=proposal(action) if p is None else p,
            boundary=point)

    def check(self, db, witness, expected):
        r = review_synthetic_transition(ledger=db, witness=witness)
        self.assertEqual(r['status'], expected)
        self.assertEqual(r['evidence_trust'], 'UNTRUSTED_SYNTHETIC_PAIR')
        for key in ('source_authenticated', 'collector_enrolled', 'owner_authenticated',
                    'real_witness_contacted', 'tpm_nv_capability_verified',
                    'protected_monotonicity_verified', 'real_crash_recovery_verified',
                    'rollback_resistance_verified', 'recovery_execution_allowed',
                    'new_enrollment_authorized', 'real_monitoring_enabled',
                    'task_execution_authorized', 'project_roster_modified'):
            self.assertIs(r[key], False)
        self.assertNotIn(LID, str(r))
        return r

    def test_four_crash_boundaries(self):
        expected = {'BEFORE_PREPARE': 'SYNTHETIC_READY_CONSISTENT_NO_TRUST',
                    'AFTER_PREPARE': 'QUARANTINED_PREPARED_NOT_ANCHORED',
                    'AFTER_WITNESS_ADVANCE': 'SYNTHETIC_RECOVERY_REVIEW_REQUIRED',
                    'AFTER_FINALIZE': 'SYNTHETIC_READY_CONSISTENT_NO_TRUST'}
        for action in ('HEALTH_ADVANCE', 'COLLECTOR_REVOKE', 'COLLECTOR_ROTATE'):
            for point in BOUNDARIES:
                with self.subTest(action=action, point=point):
                    db, witness = self.model(action=action, point=point)
                    self.check(db, witness, expected[point])
                    if point in ('AFTER_WITNESS_ADVANCE', 'AFTER_FINALIZE'):
                        self.assertEqual(witness['epoch'], 8)

    def test_no_mutation_of_caller_values(self):
        db, witness = base()
        first = deepcopy((db, witness))
        p = proposal()
        original_proposal = deepcopy(p)
        model_synthetic_crash_boundary(ledger=db, witness=witness, proposal=p,
                                       boundary='AFTER_WITNESS_ADVANCE')
        self.assertEqual((db, witness), first)
        self.assertEqual(p, original_proposal)

    def test_revocation_cannot_reseal_same_epoch_or_retain_key(self):
        for change in ({'next_epoch': 7}, {'next_key_id': KEY},
                       {'previous_sequence': 22}, {'next_sequence': 23}):
            p = proposal('COLLECTOR_REVOKE')
            p.update(change)
            with self.subTest(change=change), self.assertRaises(PolicyBlocked):
                self.model(p=p)

    def test_rotation_requires_different_key_and_epoch(self):
        for change in ({'next_epoch': 7}, {'next_key_id': KEY},
                       {'next_key_id': None}, {'next_sequence': 23}):
            p = proposal('COLLECTOR_ROTATE')
            p.update(change)
            with self.subTest(change=change), self.assertRaises(PolicyBlocked):
                self.model(p=p)

    def test_sequence_gap_regression_and_type_denied(self):
        for value in (22, 24, 0, True, '23', None, -1):
            p = proposal()
            p['next_sequence'] = value
            with self.subTest(value=value), self.assertRaises(PolicyBlocked):
                self.model(p=p)

    def test_excluded_repos_and_wrong_module_denied(self):
        for repo, module in (('online-store', None), ('Universal-AI-', '001'),
                             ('UP-UHAIB-001-Poindexter', '020'),
                             ('UP-UHAIB-001-Poindexter', 1), ([], None)):
            p = proposal()
            p['repository'], p['module_id'] = repo, module
            with self.subTest(repo=repo, module=module), self.assertRaises(PolicyBlocked):
                self.model(p=p)

    def test_poindexter_nested_module_retained(self):
        p = proposal()
        p.update(repository='UP-UHAIB-001-Poindexter', module_id='019')
        db, witness = self.model(p=p)
        self.check(db, witness, 'SYNTHETIC_READY_CONSISTENT_NO_TRUST')

    def test_pair_rollback_is_untrusted_even_if_consistent(self):
        old_db, old_witness = base()
        new_db, new_witness = self.model()
        self.check(old_db, old_witness, 'SYNTHETIC_READY_CONSISTENT_NO_TRUST')
        self.check(new_db, new_witness, 'SYNTHETIC_READY_CONSISTENT_NO_TRUST')

    def test_witness_ledger_epoch_and_hash_disagreement_denied(self):
        cases = [({'epoch': 8}, {}, 'QUARANTINED_LEDGER_AHEAD'),
                 ({}, {'epoch': 8}, 'QUARANTINED_WITNESS_AHEAD'),
                 ({}, {'ledger_id': 'f'*32}, 'QUARANTINED_IDENTITY_MISMATCH'),
                 ({}, {'committed_digest': 'f'*64}, 'QUARANTINED_DIGEST_MISMATCH'),
                 ({}, {'availability': 'MISSING'}, 'BLOCKED_WITNESS_UNAVAILABLE'),
                 ({'phase': 'QUARANTINED'}, {}, 'QUARANTINED_PREEXISTING')]
        for lc, wc, expected in cases:
            db, witness = base()
            db.update(lc)
            witness.update(wc)
            with self.subTest(expected=expected):
                self.check(db, witness, expected)

    def test_ambiguous_prepared_recovery_denied(self):
        db, witness = self.model(point='AFTER_WITNESS_ADVANCE')
        witness['committed_digest'] = 'f'*64
        self.check(db, witness, 'QUARANTINED_AMBIGUOUS_TRANSITION')
        witness['epoch'] = 9
        self.check(db, witness, 'QUARANTINED_AMBIGUOUS_TRANSITION')

    def test_pending_state_binding_required(self):
        for field, value in (('previous_digest', 'f'*64), ('expected_epoch', 8)):
            db, witness = self.model(point='AFTER_PREPARE')
            db['pending'][field] = value
            with self.subTest(field=field), self.assertRaises(PolicyBlocked):
                review_synthetic_transition(ledger=db, witness=witness)

    def test_surplus_approval_and_missing_fields_rejected(self):
        for item in ('ledger', 'witness', 'pending'):
            db, witness = self.model(point='AFTER_PREPARE')
            target = db if item == 'ledger' else witness if item == 'witness' else db['pending']
            target['owner_approved'] = True
            with self.subTest(item=item), self.assertRaises(PolicyBlocked):
                review_synthetic_transition(ledger=db, witness=witness)
        for key in proposal():
            p = proposal()
            p.pop(key)
            with self.subTest(missing=key), self.assertRaises(PolicyBlocked):
                self.model(p=p)

    def test_schema_boolean_and_unknown_action_denied(self):
        for key, value in (('action', 'OWNER_ENROLL'), ('action', []),
                           ('schema', 'wrong'), ('next_epoch', True),
                           ('previous_key_id', 'x'), ('next_digest', OLD)):
            p = proposal()
            p[key] = value
            with self.subTest(key=key), self.assertRaises(PolicyBlocked):
                self.model(p=p)
        db, witness = base()
        db['epoch'] = True
        with self.assertRaises(PolicyBlocked):
            review_synthetic_transition(ledger=db, witness=witness)

    def test_invalid_crash_boundary_denied(self):
        for name in ('AFTER_EXECUTION', '', True, None):
            with self.subTest(value=name), self.assertRaises(PolicyBlocked):
                self.model(point=name)

    def test_model_denies_untrusted_inconsistent_baseline(self):
        db, witness = base()
        witness['epoch'] += 1
        with self.assertRaises(PolicyBlocked):
            model_synthetic_crash_boundary(ledger=db, witness=witness,
                                           proposal=proposal(), boundary='AFTER_FINALIZE')

    def test_no_operational_entrypoints(self):
        import upab.relay.v3_stage42_monotonic_transition_review as m
        for name in ('advance', 'increment_nv', 'enroll', 'revoke_collector',
                     'execute_task', 'get_tpm', 'make_credential', 'connect_repo',
                     'recover_real_watcher', 'start_monitor'):
            self.assertFalse(hasattr(m, name))
        db, witness = base()
        self.check(db, witness, 'SYNTHETIC_READY_CONSISTENT_NO_TRUST')
