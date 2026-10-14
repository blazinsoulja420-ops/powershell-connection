# Watcher v3 — Stage 39 whole-state commitment and adversarial review

**Status:** DEVELOPMENT CANDIDATE ONLY. Exact candidate PR #4 remains DRAFT and UNMERGED. No production state, new monitoring, collector enrollment, releases, device settings, scheduled tasks, external repository connections, or owner approvals were changed.

## Finding from Stage 38

The Stage 38 in-memory fake monotonic witness stored only (ledger ID, epoch), while the SQLite per-row checksum covered only (scope, sequence, timestamp, epoch). A local editor able to change a collector registration or a historical sequence and recompute its unkeyed row checksum could preserve the epoch and pass a narrow continuity comparison. Likewise, updating a QUARANTINED phase back to READY could otherwise evade an epoch-only check.

## Stage 39 candidate changes

- A canonical deterministic SHA-256 **whole-state commitment** covers ledger ID, epoch, all ordered collector registrations, all ordered sequence rows and SQLite schema. It is compared to the fake witness digest inside each READY admission check and READY recovery. SHA-256 is an integrity consistency primitive here, not an authenticator.
- For a PENDING transition, the code computes the commitment of the proposed final READY state, then advances a fake witness with (next epoch, proposed state digest), then validates and completes the SQLite transaction against that digest.
- Fixture seeding and revocation explicitly **re-seal fake witness state within the same epoch**. That is a TEST-ONLY convenience and a dangerous bypass if repurposed for production. It requires neither protected authority nor a durable monotonic transition.
- The fake witness now includes a nonpersistent in-process quarantine latch. A detected sequence gap or uncertain recovery sets the latch before writing a QUARANTINED state. Rewriting the SQLite phase to READY cannot clear the still-running fake latch. Recreating or manipulating the fake witness can still defeat this laboratory barrier.
- Additional checks reject SQLite foreign-key violations, constrain the snapshot to the expected roster bound, and close SQLite connections on early initialization failure.

## Focused negative coverage

File: tests/test_v3_health_state_commitment.py. Seventeen tests include:
- Normal acceptance and digest/epoch advance
- Signed history rewrite with a recomputed per-row checksum
- Collector fingerprint, enrollment ID, source, and expiry mutations
- Prior history deletion and forged registration insertion
- Unauthorized SQLite trigger creation
- Test-only revocation and same-epoch pre-revocation snapshot restoration
- Tampered reactivation after gap or interrupted-commit quarantine
- Prepared transaction + collector mutation before crash recovery
- Fake witness loss, user-controlled fake witness modification and fail-closed denial

The existing Stage 38 suite remains intact. Windows Actions run on Python 3.11 and 3.12 with the maintained cryptography signing backend.

## Security limitations — DO NOT overstate

**No production rollback resistance.** The fake witness lives in-process, is caller-manipulable, can be lost on restart, cannot securely coordinate across independent processes, and is not provisioned TPM NV or an external authenticated monotonic service. SHA-256 hashes alone do NOT authenticate current collectors or sources. A hostile actor who controls both the database and the witness can align their values.

**No authentic collector enrollment.** The lab seeds keys supplied by test callers. GitHub CI and LOCAL_WATCHER are untrusted source labels, not authenticated origins. Real collector permissions, enrollment/rotation/revocation, cryptographic identity, trusted owner UI, access control, signed release custody, and runtime device attestation are not established.

**No production durability guarantee.** SQLite WAL/FULL, scripted interruptions, replay tests and synthetic checks do not prove Windows power-cut safety, protected ACLs, lock correctness, cross-process isolation, tamper-evident recovery, or security under compromised OS accounts. Per-row and whole-state hash validation occur within the same untrusted Python process.

**No real quarantine guarantees.** The latch is in-memory, and synthetic fixture re-sealing is mutable. Actual unquarantine would require independently authenticated operator action and a protected monotonic transition, not a database flag.

## Required next gate

Stage 40 should be an **independent architecture/security review** of the staged producer → verifier → trusted identity → protected ledger → output chain, followed by an explicitly authorized and bounded Windows hardware capability preflight. Do not enroll credentials or allocate TPM NV without separate deliberate owner approval. Specify crash atomicity, offline restore, power-failure tests, rollback/revocation behavior, and independent trust anchors before any real acceptance tests.

Preserved: exactly nine selected repositories, nineteen nested Poindexter modules, 64-project capacity, 32-monitor limit, Online Store excluded, all twelve features OFF. Production monitoring and execution authority remain FALSE.
