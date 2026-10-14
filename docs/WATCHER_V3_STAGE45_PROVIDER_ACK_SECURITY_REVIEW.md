# Watcher v3 — Stage 45 synthetic signed-provider acknowledgment adversarial review

**Status:** DRAFT / SYNTHETIC REVIEW ONLY / NO AUTHENTICATED PROVIDER.  
**Repository:** blazinsoulja420-ops/powershell-connection, Draft PR #4, unmerged.

## Purpose

Stage 44 defined a hypothetical witness request/state interface, but deliberately demonstrated two independent snapshots can both accept the same operation. Stage 45 adds a *pure cryptographic consistency review* for an equally hypothetical **provider acknowledgement**. It does not connect to TPM, any external service, authenticated broker, Windows, real collectors, GitHub workflow source or owner's credentials. Signature verification is real Ed25519 when the maintained \`cryptography\` library is installed; trusted key enrollment is **not**.

**Crucial security distinction:** An attacker can generate an Ed25519 key, issue a synthetic acknowledgement claiming \`TPM_NV_CANDIDATE\`, and supply that public key's digest as the “trusted” pin. A successful signature therefore proves only possession of the corresponding *caller-selected private key*, **not** that any TPM, trusted witness or authentic provider participated.

## Inputs and checks

\`src/upab/relay/v3_stage45_provider_ack_review.py\` takes:
- One strict Stage 44 request for \`READ_SNAPSHOT\` or \`COMPARE_ADVANCE\`.
- One versioned provider envelope containing a bounded, canonicalized claim, raw 32-byte public key as lowercase hex, and Ed25519 signature over a versioned, domain-separated signing payload.
- One **caller-selected** SHA-256 digest of the alleged provider key, not separately enrolled or protected.
- One **caller-selected** bounded list of previous signed-claim SHA-256 digests (0–128), not persisted or independently authenticated.
- A bounded, caller-supplied current timestamp.

The claim binds version, provider *label*, witness ID, request ID, canonical request SHA-256, operation, transition kind, alleged resulting epoch, alleged resulting commitment, status, issue time and expiration. Wrong pin, bad signature, malformed fields, unsupported/extra fields or bad timestamp types raise \`PolicyBlocked\`. Expired/future claims, replayed acknowledgement hashes, wrong request or witness identity, changed request digest/operation, wrong resulting epoch/digest, contradictory statuses, and out-of-scope recovery indications produce bounded BLOCKED or QUARANTINED synthetic receipts.

No response returns a private key, public key, signature, nonce, witness ID, project path or source credential. All receipts state FALSE for independent key enrollment, provider authentication, actual CAS, persistent replay resistance, Windows/TPM verification, collector identity, owner approval, monitoring and task execution.

## Adversarial acceptance criteria

The test file \`tests/test_v3_stage45_provider_ack_review.py\` deliberately includes:

1. Correct signed acknowledgement with attacker-controlled pin is still untrusted.
2. An unknown signing key **with different caller pin** is rejected.
3. A signed claim changed without resigning, a corrupted signature, or wrong domain separator is rejected.
4. Expired/future acknowledgements are blocked; unreasonable lifetime is invalid.
5. A caller-provided prior acknowledgement hash is detected as replay; **empty reset history can be bypassed**, demonstrating missing protected durable history.
6. Request ID, witness ID, operation or request digest substitution is quarantined.
7. Wrong resulting epoch, commitment and APPLIED/SNAPSHOT mismatch is quarantined.
8. Provider denial does not automatically authorize retry.
9. RECOVER must be explicitly scoped and always requires owner review; a claimed APPLIED recovery cannot finalize protected state.
10. Unknown/missing/extra approval fields and noncanonical types fail closed.
11. Strict no-network/no-hardware/no-execution test surface.

**Passing these tests is not proof of production security:** replay history is untrusted, pinning is untrusted, provider labels are unauthenticated, no physical source of trusted time exists, signatures are not bound to an independently authenticated enrollment ceremony, no monotonic trusted hardware operation was executed, and no protected write or crash atomicity was tested. A powerful attacker able to forge both the key pin and replay ledger can still satisfy the validator. Those limitations are intentional and must not be “fixed” by quietly treating the caller's proposed identity as enrolled.

## Required later milestones

**Stage 46:** Independently reviewed authentic provider enrollment, transport identity, durable revocation and nonce-history custody specification using *synthetic* certification fixtures first, with attack scenarios for compromised signer, paired rollback, out-of-order acknowledgements, duplicate concurrent CAS, network partition, protected-state restoration, and failover. Use explicit lifetime and capacity bounds. No real observer automatically starts as a result of a conformant contract.

**Separate owner authorization before hardware:** Stage 41 device-specific, bounded, consented Windows read-only capability preflight; dedicated security assessment of Windows TPM NV API and OS privileges; hardware wear/write budget; never provision keys, NV indices, services, Windows Hello credentials or production approvals from a generic “Continue”. Independently verify any external provider service, credential scope, price and uptime if considered.

## Frozen invariants

Nine selected projects, Poindexter's nineteen nested modules only, capacity 64 projects/32 concurrent monitors, Online Store excluded, twelve v3 upgrade switches OFF. No installation, real monitoring, device modification, cross-project authority, paid provider, merging or autonomous execution. Draft PR #4 remains **unmerged**.
