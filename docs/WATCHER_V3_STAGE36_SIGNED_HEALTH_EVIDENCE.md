# Watcher v3 Stage 36 — Signed health-evidence review contract (candidate)

**Source of truth:** powershell-connection candidate branch / unmerged PR #4.
**No deployment.** Zero installed Watcher v3 monitors; no owner key enrollment,
no approved repo connections, no project-folder or chat creation.

## Why this stage exists

Stage 33 fixes the approved proposal at 9 repository identities, with 19
Poindexter modules nested under ONE repository. Stage 34 takes untrusted
health claims and refuses to mark the projects verified/healthy. Stage 35
previews possible monitor scopes without opening a single directory.

Stage 36 adds actual signature *consistency* checking to those reports.
A caller supplies an Ed25519 public key, key fingerprint, health claim, and
signature. The maintained optional Python cryptography backend validates
the signature over a fixed domain and exactly canonical bounded fields.

**Security distinction:** The key, fingerprint, report and even the claimed
source class all originate with the caller. A malicious source can create a
new key and sign any fictional health condition, including OK. Therefore a
passing signature establishes only consistency with an untrusted signer.
It is NOT evidence that GitHub, Windows, a specific model, a folder, a
watcher or the account owner emitted the report.

## Strict candidate envelope

Schema: upab.watcher-v3.health-signature-envelope.v1
Fields: schema, claim, public_key_hex, public_key_sha256, signature_hex.
Claim schema: upab.watcher-v3.health-claim.v1
Fields: schema, repository, module_id, condition, observed_at_epoch_s,
sequence, source_kind.

- Repository must match exactly one of the nine owner-selected GitHub names,
  never online-store or unapproved School Tutor, RAID AI, Tasker, etc.
- Module ID must match one of Poindexter's 19 canonical IDs. Other projects
  must have module_id null. Module claims use source_kind LOCAL_WATCHER,
  never GITHUB_CI.
- Source classes LOCAL_WATCHER and GITHUB_CI are only untrusted labels.
  A future authenticated GitHub adapter must independently verify response
  origin, repository identity, commit SHA, workflow run and permissions.
- Observed time must be an integer, nonnegative and not future. Unknown and
  stale conditions remain UNKNOWN; fresh reported OK is UNVERIFIED, never
  automatically HEALTHY.
- Sequence is bounded but NOT stored. Duplicate repo/module IDs within a
  batch fail; cross-batch replay is NOT prevented and this must not be used
  to accept real telemetry until protected state exists.
- Only 28 reports per batch (9 projects plus 19 nested modules), strict
  exact schemas, capped canonical payload and no optional free text. No
  commands, paths, arbitrary source URL, secrets, extra approval fields
  or token-bearing content may be accepted.
- Signature verification fails closed if optional cryptography backend is
  unavailable. No unsigned downgrade/fallback.

## Trust and deployment prerequisites

1. Independent out-of-band enrollment of the exact allowed observation
   signer key for the approved collector, with scoped key purpose, ownership,
   rotation, expiry and revocation. A caller-supplied key digest is insufficient.
2. Protected monotonically increasing sequence ledger per signer AND
   project/module scope, with single-use replay rejection across restarts.
3. Windows Hello owner confirmation of the approved local roots and the
   independent origin/credential requirements for the chosen GitHub adapter.
4. No connectivity or data sharing with Poindexter or other projects before
   a separately approved typed/versioned integration edge; default C0.
5. Bounded real-device CI/telemetry/backup/failure acceptance including
   UNKNOWN on outage, stale data and authenticated source compromise.
6. Independently verified installation and old watcher quiescence, rollback,
   resource impact, signed release, protected approval and owner consent.

The module does not read source code, run PowerShell, reach a GitHub API,
install software, create a service, write files, monitor a directory,
issue a command or turn on any of the 12 disabled features.

**Current reviewer verdict:** Candidate cryptographic-consistency test
only. Signature-valid/untrusted provenance ≠ authenticated monitoring.
Use standalone synthetic receipts and Windows CI to test regressions.
