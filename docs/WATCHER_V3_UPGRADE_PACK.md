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
