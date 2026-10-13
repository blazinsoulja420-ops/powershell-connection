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
