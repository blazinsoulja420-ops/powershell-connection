# Watcher v3 — Stage 44 protected witness interface contract

**Status:** DESIGN AND SYNTHETIC REVIEW ONLY / NO TRUSTED PROVIDER / NO DEVICE ACCESS.  
**Development branch:** \`candidate/upab-watcher-v3-control-plane\` (Draft PR #4, not merged).  
**Predecessors:** Stage 40 paired-rollback counterexamples, Stage 41 hardware/owner approval gate, Stage 42 crash-state contract, Stage 43 protected-witness architecture review.

## Goal

Define an exact bounded request/response shape for a *future* independent Watcher witness and test that incorrect assumptions fail closed. The module \`src/upab/relay/v3_stage44_witness_protocol_review.py\` simulates a writer request against caller-owned dictionary snapshots. **It has no TPM, network, disk, Windows API, secure key or operating service dependency.** Successful simulation is **not proof of protected monotonicity, authentic CAS, source identity, owner approval or recovery authorization**.

A single process (or two hostile callers) can rewind all the simulated records. Existing Stage 40 proof of paired database/witness rollback still applies. Stage 44 deliberately contains a test in which **two independent copies of the same prior witness snapshot both accept the same request**. That is not real compare-and-swap: a future broker must serialize and authenticate the transition in protected storage.

## Candidate request format

\`upab.watcher-v3.synthetic-witness-request.v1\`, exact keys only:
- \`operation\`: \`READ_SNAPSHOT\` or \`COMPARE_ADVANCE\`.
- \`witness_id\`: lowercase, 32-hex synthetic identity.
- \`request_id\`: lowercase, 32-hex synthetic nonce.
- \`expected_epoch\`: integer 0 .. MAX_EPOCH.
- \`expected_commitment\`: lowercase, 64-hex prior-state digest.
- \`next_epoch\`, \`next_commitment\`, \`transition_kind\`: NULL for \`READ_SNAPSHOT\`. For \`COMPARE_ADVANCE\`: next epoch exactly prior+1, distinct new digest, kind in HEALTH / ENROLL / ROTATE / REVOKE / RECOVER.

No caller-supplied \`owner_approved\`, \`execute\`, \`trusted\`, \`privilege\`, \`skip_review\` or other authority field is accepted. This is *not* a complete production wire protocol: it intentionally has no cryptographically authenticated signer, secure session, signed CAS witness statement, scope-bound authorization proof, provenance chain or protected recovery ceremony.

## Hypothetical witness snapshot

\`upab.watcher-v3.synthetic-witness-state.v1\` requires exact keys:
\`schema\`, \`witness_id\`, \`epoch\`, \`commitment\`, \`available\` (boolean), \`remaining_write_budget\` (bounded integer), \`seen_request_ids\` (bounded list of unique 32-hex IDs, maximum 256).

A \`READ_SNAPSHOT\` produces an unchanged copy. A matching, available \`COMPARE_ADVANCE\` may only return a mutated *copy*: new epoch/digest, decremented hypothetical write budget and appended request ID. It never executes a real atomic write. A changed epoch or digest rejects; an already seen nonce rejects; a full nonce history or exhausted capacity rejects without dropping history. Unknown input types and extra approval fields raise \`PolicyBlocked\`.

**No production strategy should cap replay protection at 256 entries and then silently forget old nonces**. A secure provider requires durable, authenticated, workload-appropriate retention and an explicit protected epoch/idempotency migration protocol. This bounded list is only a way to test fail-closed behavior under pressure.

## Security invariants

1. Protected provider identity **independent** from a local SQLite DB and **independent** from Poindexter authority/Windows Hello relying party. Watcher cannot re-use Poindexter's secrets, TPM NV counters or approval tokens.
2. Authenticated sole writer/broker validates request origin, exact enrolled actor, project/module scope, revocation and expiration *before* atomically advancing a protected epoch and exact state commitment. An untrusted \`request_id\` is not cryptographic proof of freshness.
3. Witness CAS comparison, new commitment, idempotency records and signature/attestation must be backed by a demonstrably protected independent trust domain; no caller-controlled two-copy simulation qualifies.
4. Real \`REVOKE\`, \`ROTATE\`, \`RECOVER\` and \`ENROLL\` require separate owner-controlled ceremonies, protected audit evidence and epoch increase; never permit same-epoch silent resealing or local AI approvals.
5. The two-resource SQLite and witness transaction remains **PREPARE → ANCHOR → FINALIZE**. Failures, stale state, missing witness, ambiguous resumption, unexpected trust change and replay return QUARANTINE/UNKNOWN, never HEALTHY.
6. If witness outage or budget exhaustion occurs, deny new observations; do not silently fall back to timestamps, DPAPI, JSON, hash chains or local-only counters. Do not auto-wipe/repair witness history.
7. An authenticated GitHub API adapter must independently prove repository, commit SHA, workflow and run identity. A signed \`GITHUB_CI\` string alone does not certify external provenance.
8. Privacy and read scopes: minimal result fields, sanitized errors and bounded objects, no owner identifiers, key bytes, private paths or secret material in a response.

## Fault tests and known limitations

\`tests/test_v3_stage44_witness_protocol_review.py\` validates read-only behavior, candidate compare-and-advance, nonce replay, two independent duplicate-acceptance counterexample, wrong expected state, unknown identity, outage, full nonce history, exhausted write budget, same-epoch revocation, identical digest reuse, forged approval keys, type/schema rejection, deterministic sanitized output and no operational entrypoints.

**Counterexample is intentional:** Two independently obtained copies of the old state both produce \`SYNTHETIC_ADVANCE_APPLIED_NO_TRUST\`; therefore they prove the absence of a protected serialized CAS, not real replay safety.

The reviewer returns \`real_state_modified=false\`, \`real_provider_contacted=false\`, \`request_authenticated=false\`, \`hardware_monotonicity_verified=false\`, \`replay_resistance_verified=false\`, \`monitoring_enabled=false\`, and \`task_execution_authorized=false\` in EVERY result. \`synthetic_copy_changed\` only describes an isolated Python dictionary.

## Device-specific readiness and explicit consent

No Get-Tpm query, Windows Hello credential operation, TPM NV index allocation, counter increment, external witness enrollment, network account or paid provider has occurred. Stage 41's separate explicit owner-approved physical-device preflight is still needed. Before selecting TPM NV or external provider, verify **supported Windows API, TPM capabilities and authorization, monotonic semantics, write endurance and frequency, physical reset and recovery, provenance, single-writer isolation, external witness cost, and degraded/offline policy**.

Windows TPM Base Services schedule application TPM access, but this is not evidence that a deployable authenticated NV counter API is available in this project's execution context. Windows TPM key-storage APIs are not automatically equivalent to an anti-rollback witness. SQLite WAL+FULL offers useful DB durability but no atomic TPM+SQLite update and no protection when both records can be restored.

## Exit gates and future stage

Stage 44 closes only after exact-head Windows Python 3.11 and 3.12 full tests pass and the new review-only spec is committed. Stage 45 should define a **separately protected authenticated provider interface** and adversarial provider-conformance fixtures, not automatically connect to a physical TPM or create Windows services.

**Preserved:** Nine selected project identities, 19 nested Poindexter modules, maximum 64 projects and 32 monitors, Online Store excluded, all 12 upgrades OFF, no cross-repo integrations, no command execution, no laptop configuration changes, PR #4 DRAFT/UNMERGED.

## Platform references

- Microsoft TPM Base Services: https://learn.microsoft.com/windows/win32/tbs/tpm-base-services-portal
- SQLite synchronous pragma: https://www.sqlite.org/pragma.html#pragma_synchronous
- SQLite WAL documentation: https://www.sqlite.org/wal.html
