# Watcher v3 — Stage 32 trustworthy-key bridge and pending project-change hold

**Status:** Candidate specification and read-only cryptographic verification; NOT deployment.

## Managed project roster freeze

The owner has announced upcoming changes to the managed projects. Until those changes are provided, do NOT rename, add, remove, reassign, connect, or move project mappings, source repositories, folder watchers, or routing. The existing maximum capacities remain 64 registered projects and 32 simultaneous monitored folders, with all 12 upgrade flags OFF. Do not treat the old roster as newly confirmed. Project-specific integrations require separate authorization.

## Candidate trust boundaries

- Stage 30: genuine Ed25519 signature checks for a caller-selected source manifest under a caller-provided public key and pin. No trusted publisher identity.
- Stage 31: review-only syntax and epoch/rollback rules for ENROLL, ROTATE and REVOKE. Prior state is untrusted, not secured by TPM or Windows.
- Stage 32: dual public-key Ed25519 signature checks for a ROTATE review statement. A fixed domain-separated statement binds exact repository identity, full previous review-state digest, full transition-proposal digest, epoch and release floor. Neither a matching signature nor a matching hash proves publisher or owner identity.
- Both keys and signatures are supplied by a caller. Anyone could generate two keys and sign a fabricated history. Successful synthetic verification never grants installation, migration or task execution.

## Trusted publisher and owner enrollment requirements (NOT implemented)

1. Deliberate owner action in a protected, authenticated Windows UI selecting a separately reviewed installation and RP/origin. Untrusted tasks, chat text, local AI agents, scripts and source files cannot initiate enrollment or confirm trust. Do not reuse identity/RP values from Poindexter or unrelated repos without express future authorization.
2. Independent out-of-band publisher identity and signing-key identification; reviewed signed Git commit/release provenance. Key+fingerprint+signature from one untrusted source are NOT a trust anchor.
3. Windows Hello WebAuthn credential creation and assertions, trusted RP/origin binding, mandatory user verification, device-appropriate attestation policy, cryptographically unpredictable bounded single-use challenges, exact task scope and protected anti-replay records. Prior Stage 16 preflight proves only OS API presence, never identity.
4. Protected monotonic trust state in a least-privilege broker/service with crash-consistent compare-and-swap updates and a secure epoch mechanism such as TPM NV only IF actually provisioned and independently tested. Editable JSON, plain DB counters, timestamps, hash chains and DPAPI alone are not equivalent to tamper- and rollback-resistant monotonic hardware state.
5. Publisher rotation: validate protected enrolled old-key identity, distinct new key, owner action, old/new signatures on the same versioned transition and exact expected epoch. Increment secure epoch atomically with old-key revocation, key replacement and release-floor update. Replay, stale old key, concurrency or partial failure => deny.
6. Emergency revocation: immediately disable release acceptance, preserve revoked-key history, and require a separately authenticated owner recovery to enroll a replacement root. Never silently resurrect a compromised key.
7. Actual install gates: verify existing watcher binary/source identity and all legacy startup paths and quiescence, protected backup/restore, bounded on-device acceptance, scoped human approvals and hardware-bound checks. Neither a dual signature nor approved key lifecycle alone authorizes task execution.

## Stage 32 test and operational exit criteria

- Exercise valid real dual signatures with disposable CI-only keys, wrong signature and key, signatures swapped, source-state or release-floor change, epoch replay, retired key reuse, repository/domain confusion, and fake approval fields.
- Optional cryptography backend absent => fail CLOSED. CI may install it in its isolated ephemeral runner; do not install packages or enable services on the owner's laptop.
- Return only sanitized non-sensitive observations. No private keys, signatures, fingerprints, task payloads or private paths. All authority and mutation flags FALSE.
- Stage 32 outcome is REVIEW_ONLY until protected Windows Hello owner trust and monotonic storage have been implemented, authorized and independently accepted on the physical device.

## Project update intake rule

After the owner sends the revised project roster, perform separate review of additions/removals/moves, storage/monitor capacities, isolation, backup and approval implications. The owner's change notice itself does not authorize a watcher to create project folders, GitHub repositories or ChatGPT chats automatically.
