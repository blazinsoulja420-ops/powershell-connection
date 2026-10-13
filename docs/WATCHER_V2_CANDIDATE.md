# UPAB Watcher v2 — candidate safety milestones

**Status:** Stage 1 review candidate, not installed, enabled, merged, or production-ready.

**Source:** `src/upab/relay/ledger_v2.py`.
The existing `src/upab/relay/ledger.py`, `watcher.py`, CLI commands, launcher, and the user-private config/state remain unchanged.

## Stage 1 — Atomic replay state

- The candidate uses local SQLite (no external dependencies) in `<state>/relay/relay_v2.sqlite3`.
- A `BEGIN IMMEDIATE` transaction checks the current nonce, detects task-ID replay, inserts a consumed nonce hash and task ID, and rotates the current nonce **as one commit**. SQLite `synchronous=FULL` is requested.
- After a power loss, a committed task remains consumed; an uncommitted transaction is rolled back. Existing v1 ledger task IDs are imported on first initialization; malformed legacy ledger records stop migration instead of being silently skipped. The nonce is *always rotated* on first migration, invalidating any previously copied v1 task blocks.
- Tests cover restart durability, legacy import, stale nonce, thread/process races, and aborted transactions.
- The v2 ledger is not invoked by v1 `relay-watch` or `relay-run`. Creating it alone does not change deployed behavior.

## Critical activation constraint

**Never allow v1 and v2 to operate against the same state directory at the same time.** v1 reads and writes `nonce.txt` and `seen_tasks.jsonl` without a cross-process SQLite lock. v2 uses a different authoritative store. Concurrent operation or rolling back to v1 with old state risks replay or nonce divergence.

For future activation: stop all v1 processes, back up the private state directory securely, check filesystem permissions, migrate exactly once, and lock out v1 launch paths. Rollback must explicitly rotate/quarantine nonce state, not simply restart the old watcher. This stage provides neither activation nor rollback tooling.

## Missing for a deployable Watcher v2

- Windows event-driven clipboard listener with startup snapshot suppression.
- Guaranteed process exclusivity (same repository + channel + state).
- Bounded single-worker execution and backpressure; no concurrent task execution.
- Clipboard retry/recovery, timeout watchdog without unsafe worker termination.
- Sanitized metrics and bounded/retained logs.
- Safe migration launcher, version lockout, rollback procedure and Windows operational acceptance.
- Before/after latency and CPU measurement on the real laptop.
- Security review of durability, crash interruption, races, and fail-closed behavior.

**Promotion gate:** Windows CI + same-machine functional tests + independent security review + approval. Do not merge or run a task until those gates pass.
