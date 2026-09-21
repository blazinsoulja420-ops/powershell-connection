# UPAB v1.1 Exact Relay Protocol

## Purpose

Exact Relay lets **ChatGPT decide the code and exact operations** while UPAB acts only as a deterministic, governed local executor.
There is no local-model interpretation in the relay path.

## Human handoff boundary

Regular ChatGPT cannot directly push data into the local UPAB process. The user's explicit **Copy** action is the handoff boundary:

1. UPAB watcher is armed locally.
2. User gives ChatGPT the current relay channel, nonce, repository root, HEAD, and authorized scope.
3. ChatGPT returns one complete task block.
4. User copies the task block.
5. UPAB detects it on the Windows clipboard and executes only after all gates pass.
6. UPAB replaces the clipboard with one result block.
7. User pastes the result block back to ChatGPT.

## Exact task envelope

```text
-----BEGIN UPAB EXACT RELAY TASK-----
{
  "schema": "upab.exact-relay.task.v1",
  "task_id": "unique-id",
  "channel_id": "upab-poindexter-local",
  "relay_nonce": "one-time-nonce",
  "issued_at_utc": "2026-09-16T21:30:00Z",
  "expires_at_utc": "2026-09-16T21:40:00Z",
  "repository": {
    "root": "C:\\...\\repo",
    "expected_head": "40-hex-head-for-mutation"
  },
  "mode": "read_only | mutation",
  "stop_on_failure": true,
  "rollback_on_failure": true,
  "operations": [
    {
      "operation_id": "status",
      "op": "git_status",
      "args": {}
    }
  ],
  "result": {
    "copy_to_clipboard": true
  }
}
-----END UPAB EXACT RELAY TASK-----
```

## Supported operation names

- `read_file`
- `list_files`
- `hash_file`
- `git_status`
- `git_diff`
- `run_powershell` — existing read-only allowlist still applies
- `run_tests` — operator-configured test command
- `write_file` — existing exact manifest, hash and canonical-governance gates still apply

## Nonce and replay behavior

- Only the current nonce is accepted.
- Accepted tasks consume the nonce before execution.
- The task ID is permanently recorded in the relay ledger and cannot be reused.
- A fresh nonce is returned in every accepted task result.
- Expired tasks are rejected.
- Mutation tasks require a supplied expected Git HEAD by default.

## Transaction behavior

When `rollback_on_failure=true`, if a later operation fails after one or more successful `write_file` operations, UPAB restores **all writes made by that relay task in reverse order**. Each write has a unique backup outside the repository.

## Fail-closed conditions

Examples include:

- wrong channel or nonce;
- replayed task ID;
- expired task;
- wrong repository root;
- baseline/HEAD mismatch;
- read-only task containing a write;
- mutation authority unavailable;
- canonical UPGS package missing/mismatched when required;
- path outside exact write manifest;
- overwrite hash mismatch;
- PowerShell command outside allowlist or matching denied patterns;
- unexpected repository state change;
- rollback failure.

## Result envelope

```text
-----BEGIN UPAB EXACT RELAY RESULT-----
{ ...structured result... }
-----END UPAB EXACT RELAY RESULT-----
```

The result contains the task SHA-256, status, HEAD before/after, operation outputs, rollback evidence, evidence-log location, and next relay nonce.
