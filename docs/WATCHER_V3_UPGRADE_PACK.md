# Watcher v3 — twelve-upgrade candidate and release gate

**Status:** REVIEW CANDIDATE ONLY. Unmerged, never installed or activated.
**Repository:** blazinsoulja420-ops/powershell-connection.
**Stack:** based on unmerged Watcher v2 PR #2. This is NOT an Ollama
connection, Universal AI integration, ResearchOS integration or UASN gateway.

## Unchanged limits

- Maximum registered projects: **64**.
- Maximum active project-folder monitors: **32** in the separate manager candidate.
- Existing v1 exact-relay watcher, CLI, launch scripts, governor and repository
  execution authority are unchanged. No new task executor has been activated.
- No command, ChatGPT conversation, GitHub write, service installation,
  model download or billable provider call is performed by the v3 modules.

The proposed feature registry is in config/watcher-v3-features.example.json.
All 12 entries MUST have enabled=false; src/upab/relay/v3_features.py checks
that schema fail-closed and prohibits silently increasing project limits.

## Twelve requested upgrades: real implementation boundaries

| # | Requested upgrade | Candidate delivered | Remaining gate |
| - | - | - | - |
| 1 | Secure Execution Controller | Existing v2 atomic ledger + single-flight primitives only; v3 execution DISABLED | Authenticated approval, v1/v2 lockout, protected executor integration |
| 2 | Intelligent Task Scheduler | v3_policy ReviewScheduler: bounded 1–32 metadata items, priority/aging | Durable integration and performance validation |
| 3 | Crash Recovery Engine | v3_checkpoint: interrupted-review quarantine; v2 review queue recovery | Real crash injection and executor-state reconciliation |
| 4 | Local Task Inbox | v3_policy: strict untrusted metadata preview schema; NO listener/server | Owner identity, CSRF/origin, authentication, anti-replay |
| 5 | Automatic Health Monitor | v3_policy HeartbeatWatchdog observes stale heartbeats | Trusted Windows runtime sampling, notifications, health service |
| 6 | Resource-Aware Scheduling | v3_policy ResourceSample and fail-closed admission recommendation | Real measurement collection + device benchmarks |
| 7 | Task Dependency Engine | v3_policy ReviewScheduler checks known prior review dependencies | Persistent DAG, failure propagation and approval semantics |
| 8 | Smart Retry System | v3_policy bounded delays only for named read-only failures | Trusted classifier and integration, never auto-retry writes |
| 9 | Task Checkpointing | v3_checkpoint: SQLite immutable digest + review transitions | Approved execution checkpoint protocol |
| 10 | Performance Analytics | v3_policy allowlisted counters, no free-form user content | Timers, histograms, baseline Windows benchmark |
| 11 | Automatic Log Management | v3_diagnostics: bounded allowlisted JSONL rotation | Protected ACL, multi-process safety/rotation audit |
| 12 | Update & Rollback Manager | v3_release_guard: read-only SHA-256 manifest comparison and rollback checklist | Signed artifacts, protected backup, transactional migration and rollback |

Each module is either a testable non-executing preview, review/metadata module
or policy. They do not compose into a complete working executor yet.
Do not call any of them production-ready.

## Safe preview commands

From a clone of this candidate branch, Python >=3.11 in Windows PowerShell:

    $env:PYTHONPATH = ".\src"
    python -m upab.relay.v3_features --config .\config\watcher-v3-features.example.json

This validates all twelve disabled feature declarations and fixed limits.

For a pre-existing **user-selected** state folder:

    python -m upab.relay.v3_status --state "C:\path\to\existing\state"

The status command does not create state files, approve tasks or start a
worker. It reports UNKNOWN for process liveness; it cannot infer that a watcher
is running from checkpoint files. If the checkpoint database has not been
initialized, it reports NOT_INITIALIZED.

The v2 passive clipboard observer is independently available as a read-only
candidate. It does not submit into the v3 policy or checkpoint modules.

## Legacy v1 marker lockout (candidate)

The legacy relay ledger now checks for a marker named
`relay/v2_active.marker` before initialization and before each nonce lookup,
replay lookup or task consumption. This is a **fail-closed safeguard**, not
an activation procedure. Nothing in this PR creates the marker in a user's
real state directory.

This guard can stop new v1 operations once a separately authorized migration
creates the marker. It does not retroactively block an operation already
running or another unsupported v1 binary. Migration must still stop and
verify all old processes, lock out old launch paths, take a protected backup,
rotate nonce state, test rollback and independently verify authorization.
Do not manually create the marker as a substitute for those steps.

## Stage 5 — scoped proof verification and migration inventory (candidate)

New non-executing module: src/upab/relay/v3_approval_preview.py.
It checks exact-schema, time-limited HMAC proof metadata including task digest,
repository, channel, pinned Git HEAD, read-only scope and one-time nonce.
An atomic SQLite transaction denies reuse of the proof nonce or task ID.
Output always has authenticated_owner=false and execution_authorized=false.
An HMAC alone does NOT establish the human owner's identity. Protected
secret custody, independent owner verification and trusted live bindings
are requirements for a future approval broker, NOT implemented here.

New read-only tool: src/upab/relay/v3_migration_inventory.py.
It inventories existing legacy nonce, ledger records and migration markers.
It NEVER creates files, stops processes, activates the watcher, or grants
migration permission. State files cannot prove the legacy process is stopped.

No integration with the existing task executor, GitHub, Universal AI, UASN,
ResearchOS or Ollama was added. Production migration and security review
remain blocked.

## Stage 6 — isolated readiness and resource integration laboratory

- src/upab/relay/v3_execution_readiness.py reports outstanding protected
  owner authentication, approval issuance, repository attestation, legacy
  process exclusion, executor isolation and Windows acceptance. It always
  returns execution_allowed=false, even when presented with a verified
  review-only proof. Forged authorization fields are rejected.
- src/upab/relay/v3_windows_resources.py reads real Windows GetSystemTimes
  and GlobalMemoryStatusEx counters, returning available physical RAM and
  CPU utilization for an admission suggestion. It never runs a task.
  Read-only report command in Windows PowerShell:

      python -m upab.relay.v3_windows_resources

- src/upab/relay/v3_synthetic_lab.py joins the existing v2 single-flight
  guard, metadata-only review queue and SQLite checkpoint records using only
  one hardcoded fictional fixture inside a disposable upab-v3-lab-* folder.
  It tests duplicate refusal, review lifecycle and crash quarantine, but
  does not connect the task executor or issue an approval.

These modules are test candidates. Approval-proof verification does NOT
prove owner authentication or create a protected Windows service. Synthetic
review completion is not authorization to execute a user task. The existing
v1 watcher and actual execution logic remain unchanged.

## Stage 7 — Windows identity evidence and fixed-workload run-once worker

- src/upab/relay/v3_windows_identity.py reads the current Windows process
  token's user SID and process session ID through Win32 APIs. It expressly
  reports owner_authenticated=false, human_present=false and
  execution_allowed=false. A process SID is NOT human consent, Windows Hello
  proof or an authenticated approval ceremony. Do not emit the SID in logs.
- src/upab/relay/v3_synthetic_worker.py runs one fixed public SHA-256 fixture
  exclusively inside an explicitly named disposable upab-v3-lab-* folder.
  It durably journals PENDING->RUNNING->DONE for that fixture and denies
  duplicate runs, restart replays and unsafe automatic re-execution after
  simulated interruption. It has no user task parser, external process
  command, repository access or approval issuance.
- Tests include native Windows SID/session observation, fixture contention
  and crash injection, and blocking redirected fixture state directories.
  Path checks are defense in depth: they are NOT proof of Windows DACL
  correctness or race-free open-by-handle containment.

Remaining blockers: a protected owner-authenticating Windows approval
service, independent binding to live trusted task scope, robust secure
storage and task execution authority, an approved migration with v1 stopped,
and laptop acceptance with a real governed task. This stage changes no
production runtime behavior and installs nothing.

## Stage 8 — single-use approval protocol laboratory (NOT a live approval broker)

- `src/upab/relay/v3_approval_lab.py` provides a **test-only** 90-second
  nonce challenge journal, simulated approval decision, and spend-once
  claim before the fixed public hash workload. It verifies expected
  synthetic task ID/digest/scope; stale/unknown or reused challenges are
  denied. Expired entries become terminal so queue capacity can recover.
- `tests/test_v3_approval_lab.py` covers expiry, forgery, backdating,
  concurrent claim, crash quarantine and replay denial.
- Both lab modules require a disposable `upab-v3-lab-*` folder directly
  beneath the canonical OS temporary directory, not a project checkout.
- There is **no Windows Hello broker**, no proof of user verification, no
  protected credential vault, no authenticated IPC, no secure signing
  service, no subprocess command runner, and NO production approval.
  The lab's `test_simulation=True` is deliberately not a credential.
  A user may not approve real work by feeding a simulation to the watcher.
- State directory symlink checks are defense-in-depth; secure Windows
  file handles, final-component reparse safety and DACL validation remain
  release requirements.

Stage 8 establishes an inspectable baseline for later separate-process
owner-authentication design without weakening the real approval boundary.

## Stage 9 — Windows user-scoped data protection + disarmed broker protocol

- `v3_windows_dpapi.py` exposes current-user Win32 CryptProtectData and
  CryptUnprotectData in memory. It requests UI-free DPAPI; it does NOT
  use machine-wide decryptability, create a credential file, or prove
  interactive user approval. Native Windows CI tests verify roundtrips
  and malformed/tampered ciphertext rejection.
- `v3_dpapi_fixture_store.py` stores one internally random **synthetic**
  32-byte test seed in an existing disposable OS-temp test directory.
  Uses O_EXCL to refuse overwrite and DPAPI ciphertext at rest, and
  refuses export of decrypted seed. These are NOT approved signing keys.
  Production custody still requires protected Windows ACLs, key rotation,
  account/session isolation, secure handle-based path checks and a formal
  secret-lifecycle design.
- `v3_broker_contract.py` defines a compact versioned request frame and
  a future named-pipe endpoint contract; unknown fields, duplicate JSON
  keys, oversized messages, fake approval claims and all execute/approve
  methods are rejected. Accepted frames only return public denial/preview
  metadata with owner_authenticated=false and execution_authorized=false.
  **It does not create a pipe listener or authenticate a client.**
- `v3_pipe_acl_preview.py` asks Win32 to parse a protected proposed
  security descriptor with only the current process token SID and
  LocalSystem principals. This validates syntax and non-null DACL
  existence; it does NOT create a pipe, bind handles, authenticate peers,
  apply DACLs, or prove origin/session isolation.
- The future real Windows broker must create a local-only, authenticated
  pipe with a fixed single-user security descriptor, check peer token SID
  and session by impersonation per request, require actual user verification
  (Windows Hello/WebAuthn or separately approved equivalent), and issue a
  one-time exact-scope proof from a protected isolated process. This must
  be independently tested on the actual Windows device before enabling
  ANY task execution.

Do not interpret successful DPAPI decryption, presence of a Windows SID,
a synthetically approved challenge or valid JSON as human authorization.

## Stage 10 — authenticated local IPC **peer** only (not user presence)

New `src/upab/relay/v3_pipe_server_preview.py` creates a one-connection,
non-persistent, current-user Windows named pipe for native acceptance tests.
It uses FILE_FLAG_FIRST_PIPE_INSTANCE (fail if a matching instance exists),
PIPE_REJECT_REMOTE_CLIENTS, a protected DACL for the current account only,
bounded overlapped connection/read/write waits, and a 4 KiB message bound.
After receiving a message, the server impersonates the actual pipe client,
verifies the token user SID matches the server, checks the kernel-reported
client session and minimum medium integrity level, then always RevertToSelf.
No untrusted token, SID, PID or raw task content is put in responses/logs.

Valid requests remain `status` and `review_preview` only. All replies
state owner_authenticated=false, presence_verified=false,
execution_authorized=false, approval_issued=false. The transport may
report transport_peer_verified=true, which is only OS account/session
evidence, NOT a fresh verification of a human owner.

Native Windows integration tests cover a same-user status request,
denial-only review preview, rejected arbitrary execute request, oversize
frame denial and an unconnected server timeout. The listener is launched
only by explicitly invoking the test object's serve_once method; there is
no startup hook, CLI service, installer, background daemon, or production
execution adapter. Its ephemeral creation during CI does NOT deploy it
to the user's laptop.

**Release blockers:** independent Windows Hello/WebAuthn user verification
with proof-bound challenge, persistent broker lifecycle/stop semantics,
complete named-pipe security review including overlapped cancellation,
broker credential custody and ACL/handle hardening, rate limits and
denial-of-service handling, authenticated task/repository source identity,
legacy watcher lockout/migration, approved executor integration, rollback
and same-device Windows acceptance. CI cannot establish owner consent.

## Stage 11 — native Windows WebAuthn readiness, NOT completed authentication

- \`src/upab/relay/v3_webauthn_preflight.py\` calls only
  \`WebAuthNGetApiVersionNumber\` and
  \`WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable\`. No Windows Hello
  popup, credential creation, authenticator assertion, network request,
  registration or approval is requested. Native Win32 capabilities may be
  present in CI even when the actual owner's device is unsupported or has
  no enrolled credential. \`credential_enrolled=UNKNOWN\` in all cases.
- \`src/upab/relay/v3_presence_challenge.py\` issues a *preview* challenge
  with 32 random bytes, exact project ID/task ID/task SHA-256/review-only
  scope, a 90-second expiry and a deterministic context fingerprint. It
  rejects changed identities, scopes, nonces, times and forged approval flags.
  The context fingerprint is **not signed or keyed**: it offers only a
  development-time consistency check. This is NOT an authenticator challenge
  accepted as authorization, and it is not persisted in a replay ledger.
  Every response has \`owner_verified=false\`, no verified credential
  assertion and \`execution_authorized=false\`.
- To build a real verifier, a separate authenticated owner enrollment
  ceremony must bind an approved origin/relying-party ID, an enrolled
  credential public key, a verified signed assertion with the user
  verification flag, exact challenge/project/task digest, expected RP ID
  hash and origin, expiry, monotonic or equivalent replay defenses and
  secure registration storage. The broker must verify all of those before
  issuing a separate one-time, scoped authorization to a governed executor.
  No bare process SID, clipboard string or model output can approve tasks.
- Windows CI validates detection and fail-closed construction/parsing, not
  personal owner presence on the laptop or approved real execution.

## Stage 12 — native cryptographic ES256 assertion checking (candidate)

- \`src/upab/relay/v3_assertion_crypto.py\` verifies a WebAuthn assertion
  signature against supplied P-256 public key X/Y coordinates using the
  Windows CNG BCrypt ECCPUBLICBLOB and BCryptVerifySignature APIs, without
  installing an additional Python crypto package.
- A strict compact parser verifies signed clientDataJSON type
  \`webauthn.get\`, exact HTTPS origin, base64url-encoded 32-byte challenge,
  explicit crossOrigin=false, exact SHA-256 RP ID hash, UP and UV flags,
  no attested credentials or extensions in the assertion, and a strictly
  increasing, positive authenticator signCount. Noncanonical DER ES256
  signatures, duplicate JSON properties and incorrect signature hashes
  fail closed. The supported minimal format excludes extension-bearing
  authenticators and signCount=0 authenticators until a separately reviewed
  counter/replay policy is established.
- \`tests/test_v3_assertion_crypto.py\` uses one **PUBLIC synthetic test
  vector**: public EC P-256 key coordinates and a valid precomputed signature
  for a fictional RP/origin, then negative paths for wrong key, signature,
  challenge, origin, RP ID hash, missing user verification, bad counter and
  forged client data. The test private key is NOT stored in the repository.
- Even after a valid cryptographic signature, the result always declares
  \`trusted_credential_enrollment_proven=false\`,
  \`challenge_replay_protection_connected=false\`,
  \`owner_authenticated=false\`, \`approval_issued=false\`, and
  \`execution_authorized=false\`. Anyone can supply a public key and
  produce a valid signature with their own private key; therefore
  **cryptographic signature matching alone is not owner authentication**.

**Not yet implemented:** real WebAuthn credential registration with verified
attestation/authenticator output and protected credential-record storage;
human consent to enroll; trustworthy RP ID and origin with approved
application setup; a protected server-side challenge/replay ledger bound to
an actual client ceremony; an approved credential-ID lookup and monotonic
counter transaction; a Windows Hello assertion request; complete
registration and assertion integration on the owner's laptop; issuance of
one-time review/execution approval from an isolated protected broker.
No assertion in this candidate can grant authority to run a user task.
Preserve all twelve upgrade flags disabled and all repositories disconnected.

## Stage 13 — durable synthetic WebAuthn challenge and credential journal

New \`src/upab/relay/v3_synthetic_assertion_journal.py\` implements an
isolated SQLite **LAB ONLY** ledger for WebAuthn replay/recovery experiments:

- State can be created only inside an existing, disposable
  \`upab-v3-lab-*\` folder directly beneath the OS temporary directory.
  Existing reparse/symlink and unexpected file types are rejected.
  No live state directory or external project path is opened.
- A fixed **public test** P-256 credential record contains X/Y coordinates,
  fixture relying party, origin, a persisted counter and
  \`trusted=0\` enforced by a SQL CHECK. No private key or real user enrollment
  is available. Arbitrary caller-supplied public-key enrollment is disallowed.
- Issuance generates a fresh 32-byte random nonce by default, binding it
  in SQLite to project ID, task ID, SHA-256 digest, scope and a 90-second
  expiry. Only nonce hashes are retained. For deterministic CI, one
  explicitly named synthetic mode can issue the static PUBLIC fixture nonce
  corresponding to the previously verified public test signature.
- The verifier claims a nonce in an immediate SQLite transaction *before*
  cryptography. A second requester cannot reuse it. Successful synthetic
  ES256 validation atomically advances the stored counter and sets
  \`CRYPTO_VERIFIED_ONLY\`; invalid crypto moves the claim to \`REJECTED\`.
  An interrupted \`CLAIMED\` record is never retried automatically: an
  exclusive recovery pass marks it \`INTERRUPTED\`.
- A bounded queue (8 active pending/claimed entries), state restart,
  expiry, malformed inputs, forged task context and concurrent claims have
  regression tests in \`tests/test_v3_synthetic_assertion_journal.py\`.
- All responses state \`trusted_enrollment=false\`,
  \`owner_authenticated=false\`, \`execution_authorized=false\` and no real
  task execution. The public test key is **not** your owner's credential.

Still required before any real approval: secure owner-controlled credential
registration and proof of user consent, trusted RP/origin configuration,
protection of the stored credential ID and public key from tampering,
a crash-safe trusted counter policy including zero-counter authenticators,
Windows Hello interactive assertion, authenticated peer context and binding
to the exact allowed real task, single-use protected authorization issuance,
safe legacy-watcher migration and same-laptop acceptance. This prototype
does NOT authenticate a human or activate task execution.

## Stage 14 — disposable Windows credential enrollment rehearsal

New `src/upab/relay/v3_enrollment_lab.py` provides an explicitly
**synthetic and non-authorizing** enrollment challenge state machine:

- A bounded four-slot SQLite journal stores hashes of 32-byte random
  challenges, issuance and 90-second expiry timestamps, and terminal phases.
- Only an explicitly invoked `synthetic_test_only=True` method can advance
  a challenge. It seals a pre-existing **public development P-256 credential**
  using Windows current-user DPAPI and stores ciphertext with `trusted=0`
  enforced by SQLite. No arbitrary public key, private key, attestation,
  WebAuthn registration API or live user identity is accepted.
- A challenge is marked CLAIMED before encryption. A simulated interruption
  leaves it quarantined; exclusive recovery changes CLAIMED to INTERRUPTED
  rather than restarting. Expired/duplicate claims and concurrent attempts
  are rejected. Corrupt ciphertext cannot be loaded as a valid test fixture.
- Test data may be persisted **only** inside disposable `upab-v3-lab-*`
  directories directly under the OS temporary directory. This module has
  no launch hook and cannot access external project repositories.
- Responses always report credential_enrolled=false,
  owner_authenticated=false, attestation_verified=false,
  approval_issued=false, execution_authorized=false.

Limitations: DPAPI current-user ciphertext is NOT a trust anchor against
a compromised process running as that user, and the SQLite file has NOT
been hardened with Windows protected service identity/DACL/open-by-handle.
The synthetic record is never eligible for authorization. No actual
Windows Hello `WebAuthNAuthenticatorMakeCredential` ceremony was run.

Before real owner enrollment: select a genuine approved RP ID and HTTPS
origin, build a verifiable WebAuthn registration/attestation ceremony,
bind the user-presence challenge to that enrollment, verify the RP ID hash
and P-256 credential public key, establish protected credential record
integrity and lifecycle, test account/session/IPC isolation, then perform
an owner-approved local Windows Hello test. Only after that can a separate
authorization design be reviewed for actual tasks; no live task execution
is permitted by this stage.

## Stage 15 — strict WebAuthn registration inspection (non-authorizing)

- `src/upab/relay/v3_registration_inspection.py` is a dependency-free,
  read-only parser for bounded `attestationObject` CBOR and clientDataJSON.
  It supports `fmt=none` and an empty attestation statement only. This
  provides **no attestation trust**, even when it parses successfully.
- Checks the exact caller-supplied 32-byte challenge, `webauthn.create`,
  HTTPS relying-party origin, RP ID SHA-256 in authenticatorData, and
  authenticator UP/UV/AT bits; rejects unsupported extensions and RFU bits.
- Extracts an extension-free attested credential ID, sign counter, AAGUID
  and COSE EC2/ES256/P-256 public key. It strictly checks lengths, known
  fields, no duplicate CBOR map keys, no trailing bytes or noncanonical
  integer encodings. It outputs only hashes of candidate credential ID
  and public key, never raw private key or approval token.
- A successful response ALWAYS says `attestation_trust_verified=false`,
  `trusted_relying_party_configured=false`,
  `challenge_was_issued_by_trusted_broker=false`,
  `credential_record_stored=false`, `owner_authenticated=false` and
  `execution_authorized=false`. Supplied RP ID/challenge/origin are
  untrusted unless independently anchored by a protected approval broker.
- The strict parser does not prove the candidate EC point lies on P-256,
  establish authenticator manufacturer provenance, verify a trust chain,
  enroll an owner's Windows Hello credential, or implement production
  credential storage. Some legitimate WebAuthn formats/extensions are
  intentionally unsupported, and such registration responses fail closed.
- `tests/test_v3_registration_inspection.py` verifies a synthetic CBOR
  `fmt=none` registration and rejected malformed CBOR, duplicate keys,
  wrong origin/challenge/RP ID, missing flags, wrong algorithms, and
  oversized/truncated registration inputs.

Windows' `WebAuthNAuthenticatorMakeCredential` is a separate modal user-
presence operation that must be initiated only on the owner's machine
with explicit consent; it is NOT called by this component. Genuine
enrollment also requires selecting an RP/origin, trusted challenge
issuance and a protected identity and credential store, followed by
independent owner-presence verification and real Windows acceptance.

## Stage 16 — guarded Windows Hello owner-enrollment preflight

- `src/upab/relay/v3_owner_enrollment_preflight.py` checks Win32
  WebAuthn API availability, platform-authenticator reporting and exported
  MakeCredential/attestation-free/cancel functions. It only OBSERVES Windows
  readiness; it never calls MakeCredential, displays Hello, registers a
  credential or authorizes the watcher.
- An optional RP-ID and HTTPS-origin pair is checked for exact HTTPS
  canonical shape, DNS label validity and exclusion of test/reserved
  hostnames. Syntactic acceptance is **not** proof of domain ownership,
  owner consent, identity, or availability of the application.
- The preflight returns a fail-closed checklist of missing trust gates:
  approved RP/domain, secure challenge issuer, real owner-initiated UI,
  verified registration and P-256 point, protected credential storage,
  one-time scope-bound task approval, migration and laptop acceptance.
  All enrollment/execution/approval status fields remain false.
- Safe, read-only Windows PowerShell command from a local checked-out
  candidate (not the installed watcher):

      $env:PYTHONPATH = '.\src'
      python -m upab.relay.v3_owner_enrollment_preflight

  No real RP domain has been selected or verified. Do not use
  `upab.example.test` or any reserved illustrative domain for genuine
  credential creation.
- Stage 15 registration inspection now also validates P-256 COSE public
  coordinates using the curve equation and rejects off-curve points.
  Neither key shape nor attestation format `none` creates owner trust.

Actual native credential creation is a modal Windows UI operation that
requires a verified relying party, authenticated challenge handling and
the owner's interactive consent. None are available in the candidate.
Prior to calling Windows Hello for real, review a bounded, cancellable,
single-session user interface and a protected credential/nonce broker on
the owner's laptop. Never start a credential enrollment from a watcher
poll, repository update, AI output, clipboard event, or startup hook.

## Stage 17 — strict read-only legacy migration risk audit

- `src/upab/relay/v3_migration_risk_audit.py` checks existing v1 nonce,
  strict canonical v1 JSONL task history and optional v2 SQLite ledger
  without creating or mutating files, markers, locks or repositories.
- The auditor enforces fixed byte/record bounds, canonical task IDs and
  SHA-256 hashes, timezone-aware timestamps and duplicate-task rejection.
  It compares historical task IDs against v2 consumed records using
  an explicit read-only SQLite connection and reports any missing imports.
- A v2 activation marker is not proof that a legacy process has stopped.
  The auditor always reports `migration_allowed=false`,
  `v1_quiescence_proven=false` and `task_execution_allowed=false`,
  even if both ledgers appear internally consistent.
- Focused tests demonstrate no file changes, replay-history mismatch
  detection, damaged SQLite rejection, oversize/corrupt JSONL rejection,
  symlink/reparse guard and marker-without-database refusal.
- In a Windows PowerShell checkout of this *candidate branch*, a user may
  explicitly select their **existing** state root for a READ-ONLY audit:

      $env:PYTHONPATH = '.\src'
      python -m upab.relay.v3_migration_risk_audit --state 'C:\PATH\TO\EXISTING\STATE'

  Do not replace the placeholder with a project repository directory.
  No automatic state discovery, process termination, migration or
  activation is performed.

**Blocking issue:** legacy v1 does not respect the v2 single-flight lock.
Even if the v2_active.marker appears, an old v1 process may already be
inside a task consumption or execution path. True cutover requires
independently attested old-process termination and disabled old launch
paths, a protected backup, separately authorized migration, nonce
rotation, rollback drills and Windows laptop acceptance.

## Stage 18 — isolated v1-to-v2 migration / rollback rehearsal (TEST ONLY)

- `src/upab/relay/v3_migration_rehearsal.py` uses only a brand-new, EMPTY,
  direct OS-temporary `upab-v3-lab-*` fixture root. It rejects an existing
  project checkout, real state directory, symlink, or nonempty lab folder.
- Creates two fixed, fictional v1 task-consumption records in `source/`.
  Takes a byte-for-byte hash-checked copy in `backup/`, creates a
  *separate* `candidate/` copy and uses the existing candidate v2 ledger
  to import consumed task IDs, rotate the candidate nonce, and confirm
  already-consumed tasks are refused. Any `v2_active.marker` is created
  **only in the disposable candidate directory**.
- Demonstrates that a marked copied candidate blocks legacy v1 startup,
  then restores the untouched source snapshot into a *fourth* disposable
  `restored/` directory and checks byte-for-byte integrity and v1 replay
  history. Never overwrites the original fixture in place.
- Explicit fault-injection checkpoints stop after backup, v2 import, or
  candidate marker. They do not resume, replay, or automatically repair
  unknown work; partial fixture state remains local to the disposable
  test folder, and a second run rejects the nonempty root.
- `tests/test_v3_migration_rehearsal.py` covers success, each interruption,
  unchanged source/backup integrity, replay rejection and no real-state
  access. The rehearsal calls no GitHub connector, task executor, service
  launcher, production marker writer or owner approval issuer.
- These tests demonstrate **protocol feasibility only**, NOT a correct
  live cutover. No real v1 process was stopped; no backed-up user data,
  production migration, approved rollback or Windows laptop acceptance
  was performed. An old noncooperating v1 process may continue executing
  despite the separate v2 lock or a newly written marker.

Mandatory deployment gates remain unchanged: separately authenticated owner
authorization, operating-system verification that v1 and all old launcher
paths are quiescent, protected/verified backups, a bounded transactional
cutover with nonce rotation, independent rollback drills, real device
security review and explicit owner approval before enabling any task.

## Stage 19 — Windows cutover preflight and backup consistency (READ ONLY)

- `src/upab/relay/v3_windows_cutover_preflight.py` enumerates Windows
  process executable names using the Win32 Toolhelp32 APIs. It counts
  potential Python/PowerShell/UPAB hosts without emitting PIDs, process
  command lines, environment variables, process tokens or private paths.
  The absence of a recognizable host does NOT prove v1 has exited, because
  other launchers, renamed executables, suspended processes or work in
  flight can exist. Every result says `old_watcher_not_running_proven=false`,
  `old_launcher_paths_disabled_verified=false` and
  `migration_authorized=false`.
- An optional explicit `--compare-backup` mode compares the two bounded
  historical v1 state files (`relay/nonce.txt`, `relay/seen_tasks.jsonl`)
  under independent, existing source and backup directories. It validates
  regular-file type, basic symlink/reparse indicators, non-nested roots,
  size bounds and matching SHA-256 hashes without emitting nonce or task
  contents. This is a sampling-time consistency check only, NOT a
  complete backup inventory, Windows ACL verification, tamper-proof
  snapshot, owner authorization, or proof the source is idle. Hash
  checking by pathname is not race-free handle-based integrity assurance.
- `src/upab/relay/v3_windows_startup_surfaces.py` observes bounded classic
  HKCU/HKLM Run/RunOnce registry entries and standard current/all-user
  Startup folder filenames. It returns counts of possible UPAB/ExactRelay
  references but never exports registry commands, linked targets or file
  contents, and never modifies a startup entry. This is NOT exhaustive:
  Task Scheduler, Windows services, other accounts, WMI events, logon
  scripts, arbitrary scheduled commands and already-running processes
  remain unchecked. It ALWAYS returns
  `all_legacy_launch_paths_disabled_proven=false`.
- Windows CI tests exercise native process scanning, redirection guards,
  known-host classification, exact backup matching and mismatch detection,
  unrelated project path refusal, missing/oversized files and negative
  no-authorization behavior. All tests use disposable state fixtures.

Read-only commands from a separately authorized Windows checkout:

    $env:PYTHONPATH = '.\src'
    python -m upab.relay.v3_windows_cutover_preflight --processes
    python -m upab.relay.v3_windows_cutover_preflight --compare-backup --source-state 'C:\EXISTING\STATE' --backup-state 'C:\EXISTING\BACKUP'

**No live cutover authority**: these tools do not prove v1 quiescence,
launcher deactivation, backup protection, restoration success, or personal
owner authorization. Real migration still requires process and launcher
shutdown proofs, trusted Windows approval, protected backups, independent
rollback testing and explicit owner permission on the actual laptop.

## Stage 20 — read-only Windows service/task registration and backup ACL inspection

- `src/upab/relay/v3_service_task_registry_preview.py` inspects bounded
  HKLM Services registration subkeys plus ImagePath/DisplayName strings,
  and Task Scheduler TaskCache Tree key *names*. It returns aggregate
  counts of possible watcher references, never service commands, task
  actions, user SIDs, full paths or PIDs. This is REGISTRY inspection,
  not authoritative Service Control Manager enumeration or complete
  Task Scheduler COM enumeration. If an entry is unreadable or the scan
  is bounded, it stays incomplete. A zero hit count does NOT prove
  startup launchers are disabled.
- `src/upab/relay/v3_windows_backup_acl.py` observes a security descriptor
  and DACL through native GetNamedSecurityInfoW, GetSecurityDescriptorDacl
  and GetAce on one caller-selected existing file. It reports whether
  a DACL exists, whether DACL inheritance is protected, limited ACE counts
  and conservative broad-principal write ALLOW evidence. Raw SID, ACL
  text, task payload, nonce, or file path are not returned.
- A NULL or missing DACL is explicitly treated as a risky write-access
  condition; unrecognized ACE types are counted rather than presumed safe.
  Even an apparently restrictive DACL does not establish protective
  custody, full directory permissions, inheritance correctness, race-free
  open-by-handle checks, backup immutability or authenticated provenance.
- Native CI tests exercise Win32 service/task registration observation,
  real-file ACL reading, missing/redirected/oversized paths, limited
  startup visibility and no modifications to systems or backup contents.

**The actual laptop was NOT inspected** when these candidate tests ran.
Do not promote this module to a live launcher-disable or migration gate
without a protected, independently reviewed SCM + Task Scheduler API
implementation, user/session-specific process exclusion, secure
handle-based state checks, DACL/owner/access tests on every backup object,
trusted owner approval, and real Windows laptop acceptance.

## Stage 21 — OS service/task snapshots and bounded backup tree ACLs (REVIEW ONLY)

- `src/upab/relay/v3_authoritative_launch_snapshot.py` uses native
  Windows Service Control Manager EnumServicesStatusExW to enumerate
  registered Win32 service names, display names and instantaneous state
  inside a bounded buffer. Only aggregate possible-watcher hit counts
  are returned; no service PIDs or names leave the process. SCM
  enumeration is closer to the source of truth than registry keys, but
  a snapshot still cannot prove old watcher processes or tasks stopped,
  prevent an immediate subsequent launch or exhaust every launch path.
- The same module invokes ONLY the Win32-resolved `schtasks.exe` binary
  using a fixed `/Query /FO CSV /NH` argument vector, no shell and a
  bounded timeout, and counts possible UPAB task *names* in memory.
  Neither task actions nor credentials are returned. Scheduler access
  failures, oversized/malformed data and missing API availability
  block the evidence rather than granting clearance. This query is
  an operating-system scheduled-task inventory, but the caller's access
  and task-action coverage are still insufficient for live migration.
- `src/upab/relay/v3_windows_backup_acl.py` now reuses its Win32 DACL
  reader for existing directories as well as explicitly selected files,
  with no ACL modifications.
- `src/upab/relay/v3_backup_tree_acl_preview.py` examines only an
  explicit narrow relay backup folder with expected v1 state files and
  known optional v2 files. It refuses unknown or missing required files,
  reparse points and unexpectedly large files. It samples DACLs for both
  directories and each allowlisted file; returns only aggregate risky
  broad-write, NULL DACL, inherited/unprotected and uninterpreted ACE
  counts, not paths, SIDs, file contents or backup credentials.
- Nothing in this stage proves effective ACL rights, immutable backup
  provenance, race-free handle-based access, restoration correctness,
  full launcher shutdown, trusted owner approval or real-task authority.
  The tests use Windows runners and disposable public file fixtures;
  the owner's Windows laptop was NOT enrolled, inspected or modified.

All reported approvals, migration permission, production execution and
system mutations remain **false**, irrespective of apparently clean
service/task results or narrow DACLs. Release requires device-specific
full access-controlled inventory, owner-authorized v1 process shutdown,
protected backups + rollback, real Windows Hello verification and an
independently reviewed locked-down executor.

## Stage 22 — consolidated read-only predeployment blockers

- `src/upab/relay/v3_predeployment_gate.py` consolidates eight optional
  security observation categories: process snapshot, SCM service scan,
  Task Scheduler survey, registry startup entries, backup tree DACLs,
  source/backup SHA-256 comparison, legacy replay history and the
  Windows Hello capability preflight. It never establishes owner trust.
- `evaluate_predeployment` accepts only known sanitized schema receipts
  with explicitly denied authentication, shutdown, migration, system
  mutation and execution flags. An observation which asserts any of
  those authorities is rejected. Bare status placeholders can report
  `BLOCKED`, never claim that a source is observed or approved.
- Missing observations become `NOT_REQUESTED`, failed observations
  become `BLOCKED`, and successfully read sources become
  `OBSERVED_PARTIAL`. Even when all eight appear observed, the resulting
  `status` is permanently `BLOCKED_NOT_DEPLOYABLE` and the tool returns
  `safe_to_migrate=false`, `safe_to_install=false`,
  `task_execution_authorized=false` and `changes_performed=false`.
- The feature catalog must preserve all twelve disabled upgrade entries,
  64 registered projects and 32 simultaneous folder monitors.
- Optional Win32 collection must be explicitly requested with
  `--collect-windows`; state and backup locations must be selected
  explicitly and are never auto-discovered. Errors are sanitized to
  a blocked status without exposing local paths or task material.
  Windows Hello registration is never invoked by this tool.
- A deterministic SHA-256 fingerprint identifies only the **UNTRUSTED**
  sanitized report, not a signature, credential or approval proof.
- Windows CI tests exercise omitted checks, eight synthetic inert
  receipts, counterfeit authority claims, malformed receipts,
  bounded feature invariants and blocked OS sampling.

Windows PowerShell preview from this reviewed branch (no Windows scans):

    $env:PYTHONPATH = '.\src'
    python -m upab.relay.v3_predeployment_gate --features .\config\watcher-v3-features.example.json

Explicit read-only Windows observation (not an owner approval):

    python -m upab.relay.v3_predeployment_gate --features .\config\watcher-v3-features.example.json --collect-windows

A zero command exit status means the **blocker report** was generated,
NOT that deployment was approved. Device-specific enrollment, protected
approval brokerage, old watcher exclusion, backup recovery and explicit
owner authorization remain unresolved. No feature is activated.

## Stage 23 — externally pinned backup consistency and supervised acceptance (DISARMED)

- `src/upab/relay/v3_backup_manifest_evidence.py` strictly parses a compact
  declared manifest for an **existing**, explicitly chosen, narrow
  `relay/` backup tree. Only expected v1/v2 state file names are accepted.
  For each declared file, it rehashes bytes under fixed size limits,
  rejects added/missing files, mismatched sizes, bad hashes, renamed
  unexpected data, symlinks and obvious reparse paths.
- The caller must separately supply the lowercase SHA-256 of the canonical
  manifest bytes. The pin is a **comparison input**, not a verified
  signature, protected custody, a known good trusted baseline, owner
  approval, or complete source-of-origin evidence. Both manifest and
  pin can be provided by an untrusted caller. A matching pair is NEVER
  considered authentic, immutable, restorable or approved.
- Checks are read-only by filename with basic before/after size/time
  observations; they are **not** atomic NTFS handle-based snapshots, and
  cannot protect against live concurrent changes. The output exposes
  aggregate counts only, never the nonce, task contents, raw file hashes,
  chosen path or user identity. On a mismatch, the preview refuses
  success rather than modifying backups or repairing history.
- `src/upab/relay/v3_supervised_acceptance.py` supplies 14 fixed device
  acceptance checkpoints: exact baseline; v1 quiescence and launcher
  exclusion; protected backup, isolated restore and rollback; verified
  relying party and user-interactive Windows Hello; secure task broker;
  executor isolation; single-flight and fault recovery; performance;
  independent security review and explicit owner deployment approval.
- Checkpoint outcomes are **untrusted self-reports**. Values may be
  `NOT_TESTED`, `FAILED` or `REPORTED_PASS_UNVERIFIED`. Even if all
  checkpoints claim PASS, `real_device_acceptance_passed=false`,
  `safe_to_install=false` and `live_task_execution_authorized=false`.
  No component starts a service, touches Windows Hello or executes tasks.
- New negative CI tests exercise swapped/altered/missing backups, external
  fingerprint mismatch, forged approval fields, symlink and extra-file
  refusal, and claimed-all-PASS not being treated as permission.

These are **audit tools**, not proof of authenticated owner consent.
Before a real cutover, genuine owner-interactive Windows acceptance,
trusted RP/credential enrollment, complete protected backups, v1
process/launcher shutdown, approved rollback and independently verified
execution isolation remain mandatory and cannot be replaced with a
CI-generated SHA-256 value or a checked checklist.

## Stage 24 — Windows process/session evidence (READ ONLY)

- `src/upab/relay/v3_process_session_evidence.py` uses a bounded
  Toolhelp32 process snapshot plus read-only `OpenProcess` handles,
  `GetProcessTimes` probes and `ProcessIdToSessionId` to observe the
  Windows session distribution of exact, common host executable names
  (Python, PowerShell and UPAB). It also compares the current inspection
  session with `WTSGetActiveConsoleSessionId`. No PID, path, command
  line, process creation timestamp, SID, credential or token is returned.
- Inaccessible, exited or ambiguous candidate processes are counted
  as unresolved, NOT proof of absence. Session equality or console
  session presence is NOT physical human consent, Windows Hello
  verification, or proof a watcher is quiescent. Renamed executables,
  arbitrary generic host commands and new processes after the snapshot
  remain outside the evidence boundary.
- This module has NO process stop, service control, credential creation,
  approval, repo connection, migration or task execution method. Its
  result always reports `old_watcher_process_absence_proven=false`,
  `owner_interactive_presence_proven=false`,
  `owner_windows_hello_verified=false`,
  `deployment_authorized=false` and `task_execution_authorized=false`.
- Read-only Windows PowerShell preview from a reviewed candidate checkout:

      $env:PYTHONPATH = '.\src'
      python -m upab.relay.v3_process_session_evidence

- Stage 24 includes Windows CI tests for native session observations,
  invalid and oversized synthetic inputs, console/session mismatch,
  zero-candidate non-proof, redaction and a one-shot CLI.
- An isolated, native PowerShell process/session *observation* was
  conducted on the connected owner laptop while online, without
  changing the watcher or the device. It found ten generic candidate
  Python/PowerShell/cmd/UPAB hosts in the inspector's session at that
  moment; **no executable-level evidence uniquely identified v1**.
  This does not establish complete session enumeration, legacy process
  termination, old launch-path exclusion or owner authentication.

Before release, independently inspect the exact installed v1 command
identity and launcher ownership without exporting secrets, obtain
interactive owner verification and verified old-runtime quiescence,
then perform approved migration and rollback acceptance. Generic process
counts must NEVER be used as permission to promote a release.

## Stage 25 — bounded Windows watcher-launch attribution (READ ONLY)

- `src/upab/relay/v3_launcher_attribution.py` contains a bounded pure
  classifier for caller-supplied in-memory launch descriptions. It counts
  known repo launcher signatures (`Start-UPAB-ExactRelay.ps1`,
  `upab.ps1`, `python -m upab relay-watch`), ambiguous UPAB hints,
  unreadable entries and other hosts; it NEVER emits raw commands,
  private paths, credentials or identifiers, and NEVER treats a match
  or non-match as real watcher identity, owner consent or v1 quiescence.
- `scripts/Get-UPABWatcherLauncherEvidence.ps1` is an explicit opt-in
  READ-ONLY Windows PowerShell audit of process command-line metadata
  (Win32_Process), registered Task Scheduler names/actions and service
  names/launch paths (Win32_Service). All raw launch descriptions are
  matched only in memory and not returned. The auditor excludes its own
  process ID from process classification, limits record counts and string
  lengths, distinguishes each partial scan from blocked/unavailable
  evidence, and returns counts only. Its default mode does NOT scan.
  `-FixtureOnly` uses public synthetic data; `-InspectLocal` requests
  local read-only OS enumeration. Modes cannot be combined.
- `tests/test_v3_launcher_attribution.py` tests known/ambiguous
  signatures, malformed or oversized descriptors, empty candidate
  lists never proving shutdown, PowerShell synthetic/test-default modes,
  conflicting mode rejection and absence of system-changing operations.
- Optional reviewed Windows PowerShell call from the candidate checkout:

      .\scripts\Get-UPABWatcherLauncherEvidence.ps1 -InspectLocal

  A local read-only audit was independently performed on the connected
  Windows laptop during this stage. The initial observation detected
  zero known launcher signatures, one ambiguous string and no visible
  scheduler/service matches; it likely counted the inspector's own
  PowerShell command text. A corrected process-only observation excluding
  the inspector found 0 known and 0 ambiguous signatures among 9
  remaining generic candidate host processes, with one inspector excluded.
  The earlier scheduler/service enumeration observed zero possible
  matches visible to the current account. No installed-runtime path,
  PID, command line, task definition, service configuration or private
  data was included in the report.
- **Critical boundary:** Neither a zero count nor the presence of an
  exact signature proves a watcher is stopped, active, authorized, or
  unable to restart. Alternative interpreters, renamed binaries,
  in-memory scripts, other users, inaccessible accounts and races
  remain possible. This stage DOES NOT disable a service, delete a
  task, lock out v1, enroll credentials, migrate state or execute work.

Full device-level exclusion still requires the owner's supervised
inventory of all installed launchers, protected shutdown and restart
prevention, independent security review, rollback backup and authentic
Windows Hello owner approval before any live activation.

## Stage 26 — explicit checkout source fingerprint, local baseline (READ ONLY)

- `src/upab/relay/v3_installation_baseline.py` hashes exactly six
  known, versioned development artifacts: three old launcher scripts,
  v1/v2 ledger Python modules and the disabled v3 example feature
  catalog. This is a selected CHECKOUT preview, not actual installer
  detection, runtime examination, package signature verification or
  a release-chain attestation.
- Requires an explicitly supplied, already-existing absolute checkout
  path; guards ancestor/file reparse indicators, enforces per-file
  size limits and verifies size/metadata did not change during reading.
  It NEVER reads private `config/local.json`, state nonce, replay JSONL,
  personal workspace content or arbitrary subfolders.
- The canonical aggregate SHA-256 is a comparison fingerprint ONLY;
  an optional externally supplied pin is validated and compared, but
  neither matching values nor filenames authenticate GitHub origin,
  owner approval, old-process shutdown, real installation or migration.
  Result ALWAYS reports `safe_to_install=false`,
  `safe_to_migrate=false`, `task_execution_authorized=false`, and
  `files_changed=false`.
- The disabled catalog must show exactly 12 known candidate upgrades
  with zero activated, exactly 64 registered project slots and a
  32 monitored-folder limit. Unexpected stage labels, unknown feature
  IDs or changes to these limits fail closed.
- Windows CI tests cover six-file fixture integrity, original byte
  preservation, expected fingerprint match/mismatch, changed source
  detection, added feature activation, schema drift, redirected/oversize
  files, invalid input and a non-authorizing command-line preview.

From a reviewed checkout in Windows PowerShell, the read-only command
requires an explicitly selected existing checkout root:

    $env:PYTHONPATH = '.\src'
    python -m upab.relay.v3_installation_baseline --checkout 'C:\EXISTING\REVIEWED\CHECKOUT'

**Real laptop evidence (narrow non-recursive, read-only scope):**
the independently verified `UASN-Local-AI-Watchdog` scheduled task was
still **Disabled / Not running**. An exact-name directory check across
three common desktop/document roots found one candidate folder by name.
None of the six expected repository artifacts was present at its
immediate expected relative paths. This DOES NOT prove a watcher
installation exists there or anywhere else; the real binary/checkout
location and installed version remain **UNKNOWN**. No installed source
was executed, modified, installed, deleted, migrated or deactivated.

Before live installation, explicitly locate the real installed watcher
via owner-reviewed local software inventory, verify signed source/release
identity, every old launch mechanism, old process quiescence, protected
backup with rollback, interactive Windows Hello owner authentication
and independently approved task-execution governance.

## Stage 27 — targeted read-only runtime-layout and installed-product discovery

- `src/upab/relay/v3_runtime_layout_inventory.py` inventories only an
  EXPLICIT pre-existing absolute candidate folder. It inspects a bounded
  top-level entry count and fixed source marker file metadata at relative
  paths. It does not open or hash private `local.json`, nonce, task
  ledger, credentials, unknown workspace files, process command lines,
  Git credentials or unrelated project repositories.
- Empty directories are labeled `EMPTY_DIRECTORY_NOT_INSTALLATION`.
  Missing/partial source markers are distinguished from a plausible
  v1 source layout; v2/v3 markers are reported separately. Even all
  expected filenames mean only `POSSIBLE_SOURCE_LAYOUT_NOT_AUTHENTICATED`.
  Path symlinks/reparse indicators, unexpected file types, oversized
  markers, excessive root entries and missing path components fail closed.
- No output claims source authenticity, installed runtime identification,
  execution, approval, old watcher shutdown, comprehensive discovery or
  an authenticated owner. It never starts an executable, installs, writes,
  disables tasks or changes feature settings.
- `tests/test_v3_runtime_layout_inventory.py` tests empty, partial,
  complete-looking and unrelated folders, unchanged bytes, symlinks,
  bounds, invalid roots, CLI redaction and explicit false authority.

Read-only preview from an owner-reviewed candidate checkout, selecting
an EXISTING local folder without auto-discovery:

    $env:PYTHONPATH = '.\src'
    python -m upab.relay.v3_runtime_layout_inventory --candidate 'C:\EXISTING\SELECTED\FOLDER'

**Owner laptop read-only inventory (partial, not proof of absence):**
the earlier watcher-named folder is named `UPAB`, contained zero
immediate entries, and had zero of eight expected watcher source
markers. A separate bounded inspection sampled four common
installation directory roots, 54 immediate subdirectories and three
Windows uninstall registry views. It found zero exact watcher-named
subdirectory candidates and zero matching registered product display
names in those sampled views. The old/v3 watcher might still live under
a different folder name, user account, portable script, unregistered
package or non-enumerated path; **no installed runtime or version is
verified**. The previously paused UASN scheduled watchdog remains
Disabled/Not running per the separate earlier read-only verification.

Independent trusted owner inspection of a SPECIFIC real installation
path, signed release/source identity, active launch mechanism, legacy
quiescence and protected rollback remains mandatory before a real
migration. A folder or uninstall-entry absence must never grant
permission to install or run a new watcher.

## Stage 28 — bounded package metadata and installation discovery (READ ONLY)

- `src/upab/relay/v3_python_distribution_inventory.py` inspects
  **only the selected interpreter** for exact distribution metadata
  `universal-powershell-agent-bridge`. It validates bounded version
  syntax, declared distribution identity and whether `upab` maps to
  `upab.cli:main`. It **never imports or executes the target package,**
  invokes the CLI, accesses another Python environment or installs it.
- Optionally compare with one explicitly selected existing absolute
  checkout's bounded `pyproject.toml` package version and `upab`
  entry-point declaration; check path/parent reparse indicators and
  before/after file metadata. An unsigned matching version or entry
  point remains UNTRUSTED and cannot establish an authentic installed
  executable, a running process or the authority to deploy.
- `scripts/Get-UPABWatcherInstallCandidates.ps1` performs an
  explicit-opt-in **bounded** metadata-only scan of fixed common
  user/Desktop/Documents/LocalAppData Programs roots and a shallow
  set of subdirectories. It checks existence of three fixed source
  markers (legacy launcher, ledger, pyproject) and emits only counts.
  It does not enumerate entire drives, read arbitrary file contents,
  follow reparse-point directory roots, invoke Git hooks or return
  private paths. `-FixtureOnly` evaluates public synthetic inputs
  and the default mode scans NOTHING.
- New negative tests check no-request opt-out, missing distribution,
  mismatched version, malicious or forged metadata, missing/oversized/
  redirected pyproject files, no-authority outputs and PowerShell
  fixture, default and conflicting-mode behavior.

Candidate Windows PowerShell previews (no installation or execution):

    $env:PYTHONPATH = '.\src'
    python -m upab.relay.v3_python_distribution_inventory --inspect-python-env
    .\scripts\Get-UPABWatcherInstallCandidates.ps1 -FixtureOnly

Run `-InspectLocal` only for explicitly approved, read-only folder
discovery. A matching source shape or distribution entry is NOT proof of
package origin, activated service, old watcher shutdown or owner consent.

**Laptop evidence:** Python `pip show` did not identify the declared
distribution in the currently invoked Python environment. An earlier
bounded common-root/Windows-uninstall registration search had likewise
not identified an actual installed Watcher, and the only `UPAB`-named
folder observed was empty. These negative checks do not exclude
portable scripts, alternative Python installations, renamed source
trees, differently named programs or other users. No installed
Watcher version or authenticated location is established.

**Release remains blocked.** Explicit owner-verified binary/checkout
identification, protected source provenance, old launcher exclusion,
live Windows Hello credential enrollment, rollback and approved
limited-scope executor acceptance must precede any installation,
migration or task execution. All twelve feature flags stay disabled,
with exactly 64 registered project slots and 32 active monitors.

## Approval and migration

The future execution controller must enforce ALL of:

1. Owner-authenticated request via a protected local channel.
2. Fresh, single-use, scope-bound approval for the exact task, repository and
   authorized operations. Raw model/chat/clipboard content cannot approve itself.
3. Exact Git root, branch/head and authorized path checks at execution time.
4. Startup exclusion of legacy v1, including its CLI and old launch paths.
5. Exclusive v2/v3 state ownership; atomic ledger replay/nonce rotation.
6. Bounded queue and per-operation timeout under the existing governance gate.
7. A crash must mark uncertain writes INTERRUPTED, not automatically replay them.
8. Protected local backup, expected SHA-256 and rollback record before migration.
9. Redacted logs without secrets or clipboard/task payloads.
10. Windows acceptance, independent security review and explicit promotion.

Changing project files must NEVER implicitly start a task. Do not treat
"review complete" as "approved for execution." A priority setting does not
grant permissions; a release hash match does not prove authenticity or grant
deployment authorization.

## Tests and performance

GitHub Actions on Windows Python 3.11 and 3.12 is required at the exact
candidate head; inspect the logs before claiming a pass. Unit tests cover
dependency order, duplicate limits, bounded backoff, resource policy,
stale watchdog, checkpoint digest immutability and restart quarantine,
sanitized logs, archive bounds, read-only manifest checking, and disarmed
feature registry.

Before a real installation, baseline idle CPU/RAM of the v1 clipboard loop
against v2 event notifications, check event-to-observation latency p50/p95,
and measure real tasks' wall times, failures, concurrency and restart behavior
under the actual laptop permissions. CI test speed is NOT a benchmark.

## Release status

The v3 workstream is staged, not merged. v1 and v2 must not share a state
directory during any migration. This PR must remain draft until the protected
execution adapter, migration lockout, Windows hardware acceptance and security
review gates have passed.
