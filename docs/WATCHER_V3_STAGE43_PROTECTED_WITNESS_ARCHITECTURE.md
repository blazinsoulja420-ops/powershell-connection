# Watcher v3 — Stage 43 protected-witness architecture audit

**Status:** CANDIDATE SPECIFICATION + PURE VALIDATION ONLY. **No live Windows TPM use or permission.**  
**Repository:** \`blazinsoulja420-ops/powershell-connection\` — Draft PR #4, unmerged.  
**Based on:** Stage 40 attacker-controlled paired rollback finding; Stage 41 owner-consent/evidence gate; Stage 42 synthetic crash/revocation transition contract.

## Architecture decision

**Do not choose or provision a production witness yet.** The current in-memory \`FakeMonotonicWitness\` and caller-supplied snapshot pairs are useful adversarial laboratories, but do not provide independent authenticated or persistent anti-rollback protection.

Stage 43 adds a deterministic, pure candidate-architecture reviewer (\`src/upab/relay/v3_stage43_witness_architecture_review.py\`) and focused negative tests (\`tests/test_v3_stage43_witness_architecture_review.py\`). It reviews an **untrusted** proposal, not a live device. The input explicitly identifies a candidate provider (TPM NV, external authenticated witness, undecided), security boundaries and hypothetical daily witness writes. The reviewer never elevates caller claims to measured platform evidence.

## Mandatory separation

1. **Project boundary:** Independent Watcher authority; never borrow Poindexter secrets, Windows Hello relying party, enrollment records, broker tokens, TPM NV allocation, recovery authority, or protected counters. Any cross-project contract needs explicit separate approval and review.
2. **Owner trust:** Independently configured and verified owner-approval ceremony. Chat, local AI, source files, prompt injection, unknown process identity and unsigned fixture data are not owner approval.
3. **Collector identity:** Bind public key fingerprint to a protected enrollment with exact source kind, project, optional nested Poindexter module, expiry, revocation and independent evidence of external producer provenance. A valid self-signed \`GITHUB_CI\` label is not attestation.
4. **Writer isolation:** Least-privilege, single-writer broker; authenticate local process/token/session and deny anonymous, low-integrity and remote clients; use protected persisted custody. A Python dict and SQLite path cannot alone establish this.
5. **Authenticated state:** Each protected transition must bind ledger ID, epoch, whole-state commitment, registered collector identity/scope, revocation history and exact previous state. SHA-256 alone is not a trust root.
6. **Monotonic transitions:** Every revocation, key rotation or accepted state advancement needs an independently protected epoch transition. Reject same-epoch re-sealing outside isolated lab fixtures. A native TPM counter alone may be insufficient to bind arbitrary digest without protected adjunct storage.
7. **Crash protocol:** Durable PREPARE → independent anchored update → verified FINALIZE with fail-closed restart behavior. SQLite and TPM are not one atomic transaction; ambiguous boundary requires quarantine and independently authenticated owner recovery.
8. **Availability:** If local hardware or external witness cannot be authenticated or contacted, no accepting unanchored observations, no replay downgrade, no automatic roll-back of protected state, no task execution.
9. **Owner presence:** A status check or Windows WebAuthn API availability does not equal actual Windows Hello user verification or permission for enrollment/monitoring.

## Candidate-provider tradeoffs

| Option | Potential benefit | Mandatory unresolved evidence |
|---|---|---|
| TPM NV-backed local witness | Device-bound persisted epoch if independently provisioned and verified | Precise TPM 2.0 NV semantics/Windows API access, permissions, policy, hardware restrictions, counter/endorsement resets, endurance/write rates, protected coupling of epoch to authenticated state digest, backup/reinstall/recovery |
| External authenticated monotonic service | Independent witness outside local disk rollback domain; potentially easier durable CAS/digest | Service/key authority, strictly scoped auth, CAS atomicity, cost, network partitions, privacy, availability, encrypted storage, audit, break-glass recovery; zero-paid preference |
| Undecided | Avoids assuming unsupported hardware | Cannot assert readiness or authorize any live migration |

**Important:** Do not assume the Windows Platform Crypto Provider or \`Get-Tpm\` offers a working general TPM NV counter service. A ready TPM and existing cryptographic APIs are prerequisites at best, not proof of Watcher support for protected monotonic writes.

## Reported write budget

The candidate reviewer accepts a *hypothetical* positive bounded write estimate and optional *claimed* daily capacity. Missing capacity, or expected writes exceeding the claim, is an explicit architecture gap. A caller-provided capacity does not establish hardware endurance. Before choosing per-observation NV increments, measure/bound expected changes: collector observations, renewals, revocations, enrollment events, restart repairs and any batch checkpointing strategy. Test edge cases, counter exhaustion, Windows sleep/restart behavior, firmware/TPM replacement and unauthorized reset; choose a warranted batching policy without treating non-anchored intervals as tamper proof.

## Trust and review model

The proposal contract requires exact known fields, enumerated values, strictly typed counts and rejects unsupported methods or forged approval flags. It disallows known-unsafe architectures (e.g., caller mutable roots, Poindexter authority reuse, epoch-only state, same-epoch key revocation, SQLite-only transaction, automatic old-state restore). Complete-looking designs receive **UNVERIFIED_ARCHITECTURE_REQUIRES_EVIDENCE**, never production approval. Returned fields \`real_windows_device_inspected\`, \`tpm_nv_index_provisioned\`, \`independent_witness_authenticated\`, \`collector_identity_authenticated\`, \`protected_monotonicity_verified\`, \`rollback_resistance_verified\`, \`recovery_execution_authorized\`, \`monitoring_enabled\` and \`task_execution_authorized\` are always **FALSE**.

A design that passes the syntax/policy contract is only a design candidate. Its status cannot bypass real hardware witness testing, independent review, or owner consent.

## Exit gates / next work

- Exact-head Windows Python 3.11 and 3.12 tests including Stage 43 negative suite pass, with captured run ID, counts and reviewer disposition.
- Independently establish which protected witness platform is actually supported; device read-only preflight needs distinct owner approval and approved command scope. No TPM NV allocation, Windows Hello prompt, service or key enrollment under Stage 43.
- Write a concrete interface and threat model for independent broker, protected digest, replay-resistant credential custody and source/provenance checks. Review hardware write and reset budgets before selecting provider.
- Plan authenticated owner recovery after disk restore/witness failure, without using Poindexter’s authority or enabling dangerous task execution.
- Obtain independent security review before a real implementation candidate and owner-supervised acceptance.

## Preserved invariants

Nine owner-selected projects, nineteen internal Poindexter modules, project capacity 64, concurrent monitor limit 32, Online Store excluded, all twelve Watcher v3 feature flags OFF, no active monitoring, no laptop settings touched, no external repository integration or execution. Draft PR #4 must remain **unmerged**.
