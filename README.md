# Universal PowerShell Agent Bridge v1.1 — Exact Relay Autopilot

Local-first Windows agent bridge for **LM Studio + local coding models + governed PowerShell/Git/test/file tools**.

## Design goals

- $0 API usage by default.
- LM Studio on `localhost`; no OpenAI API key required.
- Model proposes actions; a separate governance gate authorizes or denies them.
- Exact repository-root sandboxing and exact write manifests.
- Fail closed on scope, baseline, canonical-governance, or authorization uncertainty.
- Read-only bootstrap mode.
- Structured evidence logs and rollback backups outside the repository.
- No shell execution for writes: file mutation uses a structured `write_file` tool.
- PowerShell is intentionally restricted to an allow-listed read-only command surface.
- No `git push`, commit, delete, package install, registry/system changes, privilege escalation, or network side effects in v1.
- Provider abstraction keeps future cloud providers optional.

## Governance binding

This build is bound to the adopted Universal Project Ecosystem metadata:

- UPE: `v1.0.1`
- UPGS: `v3.1.1`
- Inheritance: `STRICT_AUTOMATIC_NON_WEAKENING`
- Expected UPGS package SHA-256:
  `B73996A3D1EC43DF679AAF1CAD4170A5F8FBDD9E9112C53A1C4F2032ABDE8A3D`

The bridge enforces the execution boundary directly. For a **mutating** session, the configured
canonical UPGS package must exist and match the expected SHA-256 when
`require_canonical_for_mutation=true`.

This does **not** claim that this repository independently reimplements or proves all 321 UPGS
controls. The external canonical package remains authoritative.

## Security model

The model never receives unrestricted shell authority.

Allowed model tools:

- `read_file`
- `list_files`
- `hash_file`
- `git_status`
- `git_diff`
- `run_powershell` — read-only allow-listed command prefixes only
- `run_tests` — fixed command configured by the operator, no shell
- `write_file` — exact manifest + hash guarded + atomic write + backup
- `rollback_last_write`

Default-denied surfaces include:

- delete / recursive delete
- privilege escalation
- Windows registry and service changes
- execution-policy changes
- disk/partition operations
- network download/upload commands
- package installation
- `git push`
- `git commit`
- `git reset --hard`
- arbitrary shell chaining
- environment-variable enumeration

## Requirements

- Windows 10/11
- Python 3.11+
- Git when targeting a Git repository
- LM Studio with a local model loaded
- A model with good tool-use support is strongly recommended

LM Studio currently exposes OpenAI-compatible local endpoints, including
`/v1/chat/completions` and `/v1/responses`. This project uses
`/v1/chat/completions` so the runtime stays Python-standard-library only.

## 1. Start LM Studio

In LM Studio:

1. Download and load a local model.
2. Prefer a model marked for native tool use.
3. Open **Developer**.
4. Start the local server.
5. Default endpoint is commonly `http://127.0.0.1:1234/v1`.

Or, if the LM Studio CLI is installed:

```powershell
lms server start
```

## 2. Configure the bridge

Copy:

```powershell
Copy-Item .\config\upab.example.json .\config\local.json
```

Edit `config\local.json`:

- set `provider.model` to the exact model identifier returned by LM Studio;
- set `repository.root` to the target repository;
- set `governance.canonical_package_path` to the actual canonical UPGS v3.1.1 package;
- keep `authorized_write_paths` empty until you have an exact authorized manifest.

For Poindexter, a prepared template is included at:

```text
config/poindexter.example.json
```

## 3. Run the doctor

No install is required:

```powershell
.\scripts\upab.ps1 doctor --config .\config\local.json
```

The doctor checks:

- repository root;
- Git HEAD/status;
- UPGS package verification;
- LM Studio connectivity;
- loaded model visibility.

## 4. Read-only task

Keep:

```json
"read_only": true
```

Then:

```powershell
.\scripts\upab.ps1 run --config .\config\local.json --task "Inspect the repository and report current HEAD, status, relevant files, and risks. Do not modify anything."
```

## 5. Authorized mutation

Before allowing mutation:

1. verify the canonical UPGS package path/hash;
2. set `"read_only": false`;
3. list **every exact file path** allowed to change in `authorized_write_paths`;
4. optionally pin `repository.expected_head`;
5. run `doctor`;
6. run the task.

Example:

```json
"authorized_write_paths": [
  "src/example.py",
  "tests/test_example.py"
]
```

If the model attempts any other path, execution stops fail-closed.

## 6. Tests

The default test command is operator-controlled in config:

```json
"test_command": ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
```

The model may provide additional argument tokens, but they are passed directly to the process
without a shell.

Run bridge self-tests:

```powershell
.\scripts\test.ps1
```

## Evidence and recovery

By default, state is stored outside the repository at:

```text
~/.upab
```

Each session receives:

- JSONL evidence log;
- redacted command/test outputs;
- file backups before mutation;
- session ID and timestamps.

`write_file` is atomic. Existing files require an expected SHA-256 before overwrite.
`rollback_last_write` only restores a write made by the current session.

## Important limitation

Running tests executes repository code. A test suite can itself contain arbitrary code.
Treat test execution as trusted-code execution. The bridge strips obvious secret-bearing
environment variables before child processes, but this is not a full OS sandbox.

For stronger isolation later, add Windows Sandbox, Hyper-V/VM isolation, or a dedicated
low-privilege Windows account.

## LM Studio references

- https://lmstudio.ai/docs/developer/openai-compat
- https://lmstudio.ai/docs/developer/openai-compat/tools
- https://lmstudio.ai/docs/developer/core/server


## v1.1 Exact Relay Autopilot

v1.1 adds a **non-AI exact relay** so ChatGPT can decide the code while UPAB performs only the copied, machine-readable transaction.
LM Studio is no longer required for Exact Relay mode.

Flow:

```text
ChatGPT decides exact task
        ↓
user copies complete UPAB task block
        ↓
UPAB clipboard watcher recognizes exact markers
        ↓
strict schema + fresh nonce + expiry + replay + repository/head checks
        ↓
existing UPGS/governance/executor gates
        ↓
ordered exact operations
        ↓
rollback session writes on failure (when enabled)
        ↓
structured result + next one-time nonce copied to clipboard
        ↓
user pastes result back into ChatGPT
```

### Why copying ordinary text cannot execute

The watcher ignores all clipboard content unless the **entire clipboard** is wrapped in:

```text
-----BEGIN UPAB EXACT RELAY TASK-----
{ strict JSON task }
-----END UPAB EXACT RELAY TASK-----
```

A task also needs:

- the configured `channel_id`;
- the relay's current one-time `relay_nonce`;
- a unique, never-reused `task_id`;
- an unexpired short lifetime;
- the exact configured repository root;
- an exact expected Git HEAD for mutation tasks;
- operations supported by the relay schema;
- all normal UPGS/governance authorization.

The nonce is consumed before execution and rotated. Old task blocks cannot be replayed.

### Enable Exact Relay

Keep it disabled until validation is complete. In `config/local.json`:

```json
"exact_relay": {
  "enabled": true,
  "channel_id": "upab-poindexter-local",
  "poll_interval_ms": 500,
  "max_task_lifetime_seconds": 900,
  "max_operations": 50,
  "auto_copy_result": true,
  "rollback_on_failure": true,
  "require_task_expected_head_for_mutation": true
}
```

`read_only` remains authoritative. Turning on Exact Relay does **not** grant write authority.
For mutation, the existing canonical-governance and exact `authorized_write_paths` gates still apply.

### Show the current nonce

```powershell
.\scripts\Show-UPAB-RelayNonce.ps1 -Config .\config\local.json
```

Paste the displayed `CHANNEL`, `NONCE`, repository root, and current HEAD into ChatGPT when requesting an Exact Relay task.
Every result returns `next_relay_nonce` for the next task.

### Start automatic clipboard execution

```powershell
.\scripts\Start-UPAB-ExactRelay.ps1 -Config .\config\local.json
```

The watcher does not scrape ChatGPT and does not monitor the browser. It only observes the local Windows clipboard.
**Your explicit Copy action is the handoff boundary.**

### One-shot execution

You can execute a saved task block instead of running the watcher:

```powershell
python -m upab relay-run --config .\config\local.json --task-file .\task.txt
```

Or from the clipboard:

```powershell
python -m upab relay-run --config .\config\local.json --clipboard --copy-result
```

### Result package

UPAB returns:

- task ID and canonical task SHA-256;
- PASS / FAIL / FAIL_CLOSED / BLOCKED status;
- repository HEAD before/after;
- every operation and its result;
- rollback result when used;
- evidence-log path;
- next one-time relay nonce.

### Security limitation

Exact Relay makes local execution automatic **after you copy a valid task block**. It does not create a direct API connection from regular ChatGPT to the PC and does not automatically paste the result back into regular ChatGPT. That final paste remains manual under the regular-chat product boundary.
