# Watcher v3 — Stage 40 independent trust-chain/security review

**Status: DEVELOPMENT CANDIDATE / NOT PRODUCTION READY.** Watcher PR #4 remains DRAFT and UNMERGED. No real monitoring, owner enrollment, hardware acceptance, device configuration, repo connection or task execution occurs.

## Verdict

DENY production monitoring and ALL task execution. Stage 39 added a useful whole-SQLite-state SHA-256 consistency check against a process-local fake witness. This is NOT protection against an actor who can roll back or forge both resources. Stage 40 deliberately demonstrates paired rollback, revoked-key resurrection and source-kind forgery, using fake OS-temp fixtures. Passing these tests demonstrates the presence of a **documented insecurity in the fake lab**, not production acceptance or readiness.

## Boundary-by-boundary security audit

| Boundary | Existing synthetic evidence | Real trust gap |
|---|---|---|
| Producer (GitHub or Windows) | Caller-supplied GITHUB_CI / LOCAL_WATCHER text | Independently authenticated GitHub run/workflow/commit or Windows executable identity |
| Collector signer | Test-generated Ed25519 key; domain-separated signature | Owner-approved key enrollment, protected custody, scope, expiry and revocation |
| Verifier | Cryptographic consistency with supplied key | Protected allowlisted key identity; independent source provenance; zero inherited authority |
| Durable ledger | Disposable SQLite WAL/FULL, row and whole-state checks | Protected file ownership/ACL, cross-process locks, independent crash/power tests |
| Monotonic witness | Mutable FakeMonotonicWitness in Python memory | Independent provisioned TPM NV or demonstrably trusted external monotonic service; authenticated compare-and-swap |
| Owner/UI | Count-only non-sensitive synthetic receipts | Protected owner identity, scoped review, age/staleness and offline/unknown handling |
| Executor | No operational v3 authorization | Windows Hello user verification, exact task digest and source SHA, one-use approval, replay denial, rollback, legacy lockout |

A signed observation is not permission to read a repo; genuine health cannot itself authorize command execution. Never promote a caller-supplied boolean into a trusted control-plane decision.

## Explicit adversarial findings

**S40-A: Database-only rollback.** Restoring an old SQLite snapshot against the *unchanged current* fake witness quarantines. This is a test of local consistency only.

**S40-B: Paired database/witness rollback.** Restore a pre-commit SQLite snapshot AND the fake process-local identity, epoch, commitment and quarantine latch. The identical previously accepted, signed health claim can be accepted again. This is why Stage 39 cannot claim real anti-replay or protected monotonicity.

**S40-C: Paired revocation rollback.** Stage 39 test-only revoke reseals the fake commitment **without advancing its epoch**. Restoring both pre-revocation resources can reuse the apparently revoked fixture key. This is expressly forbidden as a real revocation technique.

**S40-D: Source-kind impersonation.** A test caller can create an ephemeral key, seed a fake GITHUB_CI collector, sign fictitious OK health and pass cryptographic consistency, without any actual GitHub API call or verified workflow identity. Source labels are not independent proof.

**S40-E: Restart and witness loss.** A new empty witness cannot recover the prior ledger. A counterfeit prior witness can be replayed. Both make operational state UNKNOWN or BLOCKED, not VERIFIED healthy.

New independent adversarial test file: tests/test_v3_stage40_trust_boundary_adversary.py. Disposable directories must be prefixed upab-v3-lab- and reside directly in the OS temp directory. Fixture private keys must be ephemeral and never persisted to the target Windows host. All synthetic receipts explicitly report owner authentication, protected rollback, monitoring, project mutation, and task execution FALSE.

## Architecture and security work required BEFORE any hardware probe

1. Separate producer, collector enrollment authority, verifier, protected state-owner broker and owner UI. Enumerate compromised collector, untrusted CI source, malicious source repo, compromised local unprivileged user, privileged OS compromise, stolen key, clock failure, disk restore and network partitions. State residual risks explicitly.
2. Build a protected monotonic transition contract that binds source, key identity, revocation history, sequence, epoch and state digest. Define crash-consistent states and atomic compare-and-swap. Never permit a same-epoch mutable reseal after enrollment or revocation.
3. Define two-resource crash and recovery outcomes for pre-prepare, post-prepare, post-anchor and post-finalize failures. Ambiguous recovery must QUARANTINE until independent authenticated owner review. Backups may not roll protected epochs backward.
4. Independently verify the origin of real GitHub CI and Windows telemetry. Exact repo, commit SHA, workflow run and credentials must be checked by an authenticated, narrowly scoped adapter. A public signature whose public key is caller-supplied does not establish provenance.
5. Evaluate TPM NV only after owner authorization of device-specific provisioning, counter/wear budget, permissions, firmware reset/recovery, lock policy, rate limiting, protected key custody and independent test cases. An unprotected local JSON, DPAPI blob, timestamp or hash chain alone is insufficient anti-rollback protection.
6. Owner-presence and release ceremonies must be separate: Windows Hello actual user verification, independently approved RP/origin and challenge issuer, single-use scoped approval, safe legacy watcher cutover, protected backup restore, and documented failure modes. Never reuse Poindexter approvals automatically.
7. Require separate review/authorization for Windows capability probes, any key enrollment, TPM NV allocation, system service/task changes, production CI credentials and execution. Isolated GitHub synthetic CI does not confer device acceptance.

## Owner-selected project invariants

Nine repositories are the *proposed* selection; Kali-Linux- included for offline defensive training and NSFW restricted and isolated. online-store is explicitly excluded. Nineteen Poindexter features remain internal modules, not nineteen separate watch roots. The four previously suggested add-on repos remain unapproved. Registered capacity 64; concurrently monitored folder maximum 32; all 12 feature flags OFF; zero authorized cross-repo links. Do not alter roster, create chats, enable watchers or activate any project.

**Next Stage 41:** hardware-readiness evidence contract and exact owner approval checklist. Do not perform TPM/Windows Hello preflight automatically. Ask for deliberate consent and exact scope before any live-device probe.
