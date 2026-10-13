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


## Stage 2 — Event-driven Windows observation (added; STILL NON-EXECUTING)

New additive modules:
- src/upab/relay/clipboard_events_v2.py: invisible Win32 message-only
  window + AddClipboardFormatListener, event wake-ups instead of constant
  500 ms clipboard reads. Processes only the latest clipboard state; multiple
  notifications are coalesced (no unbounded copy buffer).
- src/upab/relay/clipboard_limited_v2.py: checks Windows GlobalSize of
  clipboard CF_UNICODETEXT handle before decoding, default cap 131,072 chars.
- tests/test_clipboard_events_v2.py: startup snapshot suppression,
  same-content notification deduplication, transient clipboard read retry
  (max 3), oversized inputs, and no implicit execution.

Candidate dry-run on a Windows interactive desktop, NOT a service:

    $env:PYTHONPATH = ".\src"
    python -m upab.relay.clipboard_events_v2 --once

Only observes clipboard format updates and prints sanitized event categories.
The observer does not parse/validate task JSON, create a task queue, execute
an operation, inspect a repository, modify clipboard content, or consume a
relay nonce. Its named mutex protects just this candidate observer: it does
NOT lock out an existing v1 relay-watch process.

**Stage 2 is not an executable Watcher v2.** Do not install startup services
or infer desktop integration from Windows CI alone. The Win32 event window
still needs same-machine interactive-desktop validation, clipboard open/read
fault tests, and before/after idle CPU and event latency measurements.

## Stage 3 — indexed lookup + single-flight lock (candidate)

- src/upab/relay/ledger_v2.py now provides has_seen(task_id), an indexed
  SQLite lookup instead of materializing every consumed task ID during
  replay checks. The authoritative check remains inside consume(), in an
  atomic SQLite transaction; has_seen() is advisory only.
- src/upab/relay/single_flight_v2.py provides a per-state-directory persistent
  file lock using Windows msvcrt.locking (fcntl on other platforms).
  Cooperating future v2 executors can use it for a single-flight owner,
  fail-fast collision and automatic OS release on process exit.
- tests/test_single_flight_v2.py verifies process isolation, re-acquisition,
  collision and release. The lock is **not wired to an executor**.

This lock does NOT prevent unmodified legacy v1 processes from using their
own ledger. Activation still requires stopping and preventing v1, securely
migrating state, and testing rollback. Neither the event observer nor the
file lock grants permission to execute a task.

## Critical activation constraint

**Never allow v1 and v2 to operate against the same state directory at the same time.** v1 reads and writes `nonce.txt` and `seen_tasks.jsonl` without a cross-process SQLite lock. v2 uses a different authoritative store. Concurrent operation or rolling back to v1 with old state risks replay or nonce divergence.

For future activation: stop all v1 processes, back up the private state directory securely, check filesystem permissions, migrate exactly once, and lock out v1 launch paths. Rollback must explicitly rotate/quarantine nonce state, not simply restart the old watcher. This stage provides neither activation nor rollback tooling.

## Missing for a deployable Watcher v2

- Windows event-driven clipboard listener/startup suppression are now passive candidate components; real laptop acceptance NOT yet verified.
- Per-state cross-process single-flight lock implemented as a candidate; no verified v1 lockout or active executor integration yet.
- Bounded single-worker execution and backpressure; no concurrent task execution.
- Clipboard retry/recovery, timeout watchdog without unsafe worker termination.
- Sanitized metrics and bounded/retained logs.
- Safe migration launcher, version lockout, rollback procedure and Windows operational acceptance.
- Before/after latency and CPU measurement on the real laptop.
- Security review of durability, crash interruption, races, and fail-closed behavior.

**Promotion gate:** Windows CI + same-machine functional tests + independent security review + approval. Do not merge or run a task until those gates pass.
