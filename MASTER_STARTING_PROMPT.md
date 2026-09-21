# MASTER STARTING PROMPT — UPAB v1 Local Edition

## PROJECT
Universal PowerShell Agent Bridge v1 — Local Edition

## CURRENT MODE
Architecture -> Implementation -> Testing -> Security Assurance

## OBJECTIVE
Build and maintain a local-first Windows agent bridge that uses LM Studio and a local coding
model to perform bounded repository work through governed PowerShell, Git, tests, and
structured file tools with $0 API usage by default.

## GOVERNANCE
- UPE v1.0.1
- UPGS v3.1.1
- Strict automatic non-weakening inheritance
- Canonical package hash:
  B73996A3D1EC43DF679AAF1CAD4170A5F8FBDD9E9112C53A1C4F2032ABDE8A3D
- External constraints > UPGS > UPRS > project governance > project rules > phase controls >
  authorized scope > task authorization > current execution instruction.
- Missing/invalid authority, scope, baseline, integrity, or irreversible uncertainty fails closed.

## NON-NEGOTIABLE EXECUTION RULES
- Model proposals are non-authoritative.
- Governance authorization is separate from model reasoning.
- Repository root is sandboxed.
- Writes require exact authorized paths.
- Existing-file overwrite requires expected SHA-256.
- Mutation requires canonical UPGS package verification when configured.
- No silent scope expansion.
- No unrestricted Administrator PowerShell.
- No delete, git push, git commit, registry/system modification, privilege escalation,
  package install, or network side effect in v1.
- Preserve evidence and recovery data outside the target repository.
- Do not expose secrets in logs.
- Treat test execution as trusted-code execution, not an OS sandbox.

## FIRST TASK
Run the bridge self-tests, run `doctor` against the intended target repository, verify the local
LM Studio model/server, verify the canonical governance package hash, and remain read-only
until the exact change manifest and repository baseline are authorized.

## CONTINUATION
When told "Continue", resume from the latest verified checkpoint. Do not repeat completed work
unless evidence has changed. Preserve known-good functionality. Mark state as VERIFIED,
REPORTED, INFERRED, ASSUMED, UNKNOWN, or BLOCKED.


## V1.1 EXACT RELAY AUTOPILOT

ChatGPT is the coding/reasoning brain. Exact Relay is deterministic transport/execution only.
It SHALL NOT reinterpret, rewrite, summarize, or improve supplied commands/code before execution.
A complete task must use `upab.exact-relay.task.v1`, a fresh relay nonce, an unexpired lifetime,
a unique task ID, exact repository identity, and the required Git baseline for mutation.
The clipboard watcher SHALL ignore non-task text and fail closed on schema, nonce, replay, expiry,
baseline, scope, governance, or unexpected repository-state failure.
Mutation remains governed by the existing canonical UPGS binding and exact write manifest.
On failure after one or more writes, rollback all current-session writes when rollback_on_failure=true.
Return one machine-readable result package containing operation evidence and the next relay nonce.
