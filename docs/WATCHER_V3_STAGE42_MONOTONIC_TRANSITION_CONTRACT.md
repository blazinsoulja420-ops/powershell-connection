# Watcher v3 — Stage 42 monotonic transition and crash-recovery contract

**Status:** SYNTHETIC REVIEW ONLY / NOT A TPM OR PROTECTED COUNTER / NOT PRODUCTION READY.  
**Repository:** blazinsoulja420-ops/powershell-connection, Draft PR #4 (unmerged).  
**Predecessors:** Stage 39 whole-state digest; Stage 40 paired rollback and revocation-resurrection counterexamples; Stage 41 hardware-evidence consent gate.

## Deliverable and limitation

The pure Python module \`src/upab/relay/v3_stage42_monotonic_transition_review.py\` accepts two **caller-controlled hypothetical dictionaries** (SQLite ledger view and monotonic witness view). It checks narrowly specified state-machine invariants and returns only sanitized **non-authoritative** statuses. \`model_synthetic_crash_boundary\` constructs theoretical before/after views without writing to SQLite, a computer, TPM, GitHub, or any collector.

No output proves that the witness is independent or persisted, that a collector is enrolled, that a GitHub CI claim originated from GitHub, or that owner presence occurred. Even an apparently consistent pair can be the product of **paired rollback**, as shown by Stage 40. A production adapter must not use this review as an authorization grant.

## Contract

- \`ledger\`: \`schema\`, 32-hex \`ledger_id\`, nonnegative bounded integer \`epoch\`, 64-hex \`committed_digest\`, \`phase\` (READY/PREPARED/QUARANTINED), and nullable \`pending\`.
- \`witness\`: \`schema\`, matching identity, epoch, committed digest and \`availability\` (PRESENT/MISSING). All fields supplied by caller and **UNTRUSTED**.
- \`pending\`: exact schema, action, repository/module scope, expected/new epoch, old/new whole-state digest, previous/next sequence and old/new signer fingerprints. \`next_epoch == expected_epoch + 1\` is mandatory, with distinct state digests.
- \`HEALTH_ADVANCE\`: next sequence must equal previous +1 and signer fingerprint unchanged.
- \`COLLECTOR_REVOKE\`: next signer must be null, sequence fields null, epoch increments.
- \`COLLECTOR_ROTATE\`: new signer differs from old, sequence fields null, epoch increments.
- Repositories come from the fixed existing nine-project roster. Poindexter's 19 module identifiers are nested scope entries only. \`online-store\` is excluded.
- Unknown methods, fields, schemas, booleans as counters, missing witnesses, invalid scopes, sequence gaps, same-epoch revocation or rotation and forged owner flags are denied.

## Crash outcome truth table

| Hypothetical crash boundary | Ledger | Witness | Review disposition |
|---|---|---|---|
| BEFORE_PREPARE | old READY | old | SYNTHETIC_READY_CONSISTENT_NO_TRUST |
| AFTER_PREPARE | PREPARED with pending | old | QUARANTINED_PREPARED_NOT_ANCHORED |
| AFTER_WITNESS_ADVANCE | PREPARED with pending | next matching epoch/digest | SYNTHETIC_RECOVERY_REVIEW_REQUIRED |
| AFTER_FINALIZE | next READY, no pending | next | SYNTHETIC_READY_CONSISTENT_NO_TRUST |
| Missing witness | any | MISSING | BLOCKED_WITNESS_UNAVAILABLE |
| Either side mismatched / stale / tampered | inconsistency | inconsistency | QUARANTINED_* or PolicyBlocked |
| Both old resources restored together | old READY | old | Can appear SYNTHETIC_READY_CONSISTENT_NO_TRUST: **KNOWN VULNERABILITY IN HYPOTHETICAL PAIR** |

**Recovery review is not recovery authorization.** No function finalizes a real pending transaction or changes actual keys. No CRASH test establishes actual power loss safety or SQLite/TPM atomicity. Cryptographic binding, independent source identity, revocation history and protected hardware custody remain required.

## Security gates before real implementation

1. Device-specific supported TPM NV mechanism or independently controlled external monotonic witness; verify counter behavior, capacity, ACL, privilege, endurance and reset behavior. Stage 41 explicit owner approval must be obtained before any live Windows probe.
2. Broker-owned durable single-writer transaction state and verified native IPC peer identity, with exact state hash and authentic enrollment/revocation history.
3. Explicit owner-approved enrollment and rotation ceremony with independently authenticated trust anchors; **no same-epoch reseal** for real revocation.
4. Genuine GitHub CI provenance and local collector executable identity rather than caller-supplied \`GITHUB_CI\` text.
5. Authenticated owner-reviewed recovery when a prepared transition or witness state differs; fail closed on unknown hardware state, disk rollback or torn writes.
6. Full Windows on-device power-failure and restart tests with approved hardware scope, independent review, precise evidence and rollback/disable procedures.

## Validation and governance

Code is inert, deterministic and test-only. Focused test coverage exercises all four theoretical crash boundaries for each action and negative cases for replay, key reuse, spoofed approval, scope violations, inconsistent snapshots and paired rollback. Run full existing Windows CI on Python 3.11 and 3.12 at exact commit SHA before calling Stage 42 complete.

**Unchanged:** nine selected project identities, 19 nested Poindexter modules, 64 registered project capacity, 32 concurrent monitor limit, all 12 Watcher v3 upgrades disabled, Online Store excluded. PR #4 remains draft and unmerged. Zero real monitoring, TPM provisioning, Windows changes, execution, release or credential enrollment.
