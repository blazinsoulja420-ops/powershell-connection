# Watcher v3 Stage 37 — Health sequence-continuity review

**Status:** Candidate review only. No production anti-replay ledger,
publisher enrollment, monitoring activation, Windows service, or new
project registration.

## Purpose

Stage 36 verifies Ed25519 signature consistency over a caller-supplied
health claim and public key. But signing an OK observation does not
prove the origin, health, or that the event has not been replayed.

Stage 37 adds a bounded **synthetic previous-sequence comparison**.
It can reject older or equal sequence values and backwards observation
timestamps for exactly one supplied `(signer fingerprint, repository,
Poindexter module)` identity; missing history and skipped sequence
numbers are separately reported. This is a code-review model, not
a persistent authorization or monitoring engine.

## Strict input and read-only output

- `src/upab/relay/v3_health_sequence_continuity_review.py` calls the
  existing Stage 36 cryptographic signature/batch review, which
  validates the selected nine repositories, exactly nineteen nested
  Poindexter modules, stale/future reports, and duplicate identities.
- A caller may supply a synthetic snapshot with schema
  `upab.watcher-v3.untrusted-health-sequence-snapshot.v1`, containing
  only `schema` and `entries`. Each entry has exactly
  `signer_key_sha256`, `repository`, `module_id`, `last_sequence`,
  and `last_observed_at_epoch_s`. Maximum 112 sorted, unique entries.
- Signed observations with an exact matching prior entry must strictly
  increase sequence and must never decrease observation time. Positive
  gaps are counted for review. Missing prior entries are explicitly
  counted as missing, not treated as authenticated first events.
- Invalid signatures, unrecognized project IDs (including excluded
  `online-store`), out-of-scope modules, malformed snapshots,
  replayed sequences and forged fields fail closed.
- All outputs are **sanitized counts/booleans**; no public keys,
  signatures, fingerprints, file paths, source text or task commands.
  Reported fresh OK remains UNVERIFIED; stale OK remains UNKNOWN.

## Unmet protection requirements

**The entire previous snapshot is caller-controlled.** Anyone who
can swap or delete it can bypass a purely synthetic continuity review.
An attacker could also create a new key, sign fictitious status and
present no prior history. This code DOES NOT store or authenticate
sequences and cannot block replay after restart or rollback.

Production readiness requires independently enrolled, scoped signer
identities, authenticated GitHub/Windows source provenance, atomic
protected per-signer/per-repo/per-module sequence storage, crash-safe
recovery and genuine rollback resistance. Owner approval and real
Windows Hello/device acceptance are separate prerequisites.

**No state changed:** all twelve v3 features stay OFF, project cap 64,
monitor cap 32, exactly nine currently selected project identities;
nineteen Poindexter features are internal modules and need zero
additional repository monitor slots. No repo connections, monitoring
startup, paid API use, credential enrollment, new project folders or
ChatGPT chats.

## Security acceptance

`tests/test_v3_health_sequence_continuity_review.py` exercises empty
inputs, untrusted matching history, replay and clock rollback, gaps,
unknown signer/missing history, Poindexter subscopes, excluded repos,
duplicate malformed snapshots, stale health, invalid signature,
missing cryptography backend and forbidden persistent/execution APIs.

Run only in isolated CI with synthetic signing keys. The outcome
remains REVIEW ONLY until separate trusted storage and owner
enrollment are implemented and accepted.
