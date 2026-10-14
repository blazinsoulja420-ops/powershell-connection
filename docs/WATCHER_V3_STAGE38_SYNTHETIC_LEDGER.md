# Watcher v3 — Stage 38 synthetic replay ledger

**Status:** DRAFT / TEST FIXTURE ONLY. No owner enrollment, production anti-replay, monitoring, GitHub connector, installation, autonomous execution or approval. This candidate must NOT be merged as a production-readiness claim.

## Boundaries

Stage 37 compared signed health claims against a caller-controlled sequence snapshot. Stage 38 adds an isolated, disposable SQLite laboratory with a strictly in-memory fake monotonic witness and a test-created synthetic enrollment fixture. Signature validation reuses Stage 36. The fake witness is mutable by the process, does not persist across a real machine reboot, does not coordinate independent processes, and is not hardware-backed. Its success in detecting an older database is NOT real rollback protection.

Data is only permitted under a pre-existing upab-v3-lab-* directory directly within the system temp directory. No production root or monitor is opened. SQLite WAL and FULL synchronous mode are checked before use. Path/reparse checks here are not race-free and do not establish Windows ownership or secure ACLs. SQLite transactions and Python data paths are not equivalent to protected custody.

A deliberately explicit seed_fixture step creates a prior record and scope-bound synthetic signer. No signed observation can self-enroll or bootstrap an unknown prior. accept_fixture verifies Stage 36 Ed25519 envelope and exact roster; rejects mismatched/revoked/expired keys, backward sequences/clocks, missing prior, and unsupported source; sequence gaps quarantine instead of silently reporting health. Every receipt states trusted_collector_authenticated=false, hardware_monotonic_store_verified=false, rollback_resistance_verified=false, real_monitoring_enabled=false, task_execution_authorized=false.

## Two-resource failure model

1. A single SQLite writer transaction persists PENDING with prior/new digest and target epoch.
2. Fake witness advances outside that SQLite transaction.
3. A second transaction validates original row, pending record and fake witness epoch before finalization.
4. A crash before preparation leaves the prior state intact. A crash after preparation but before witness advancement quarantines. A crash after witness advancement but before finalization can recover only from the exact matching persistent PREPARED record; otherwise fail closed. A crash after finalization leaves the new sequence recorded and exact replay denied.
5. A reintroduced old SQLite snapshot detected against the still-running fake witness quarantines. If the witness is lost, replaced, reset, forged or desynchronized, the experiment offers no reliable security guarantee.

## Tests

See tests/test_v3_synthetic_health_ledger.py: 17 scoped tests for replay, time regression, untrusted fresh key, excluded repo, missing history, crash boundaries, witness failures, prepared-record tampering, duplicate concurrency and restored SQLite snapshots. These tests are synthetic, not Windows power-failure or TPM acceptance. The test suite requires optional cryptography, already installed by the existing Windows CI workflow.

## Missing gates for real operation

- Independently authenticated, least-privilege scoped collector enrollment with protected owner approval, expiry, revocation and rotation.
- A durable, provisioned, hardware/external monotonic anchor with tested two-resource commit/recovery protocol and write/endurance limits.
- Strict Windows file HANDLE identity, DACL/owner checks, storage locking and verified restart/power-loss tests.
- Authenticated GitHub CI origin and Windows device provenance rather than trusting a signed source_kind claim.
- Secure release, review, rollback, acceptance and consent. Every one of the 12 v3 feature flags remains disabled.

Preserve nine chosen projects, 19 nested Poindexter modules, 64 project capacity, 32 monitor cap, and excluded Online Store. Existing draft PR #4 remains the only candidate branch; keep it unmerged.
