# UPAB Multi-Project Watcher Manager — five-project bootstrap

**Stage:** non-production candidate, registry and read-only binding preflight only.
**Host repository:** blazinsoulja420-ops/powershell-connection.
**Related but separate:** Watcher v2 atomic replay ledger draft PR #2.

## Exact initial project profiles

| Profile ID | Approved GitHub repository |
| --- | --- |
| poindexter | blazinsoulja420-ops/UP-UHAIB-001-Poindexter |
| universal-ai | blazinsoulja420-ops/Universal-AI- |
| uasn | blazinsoulja420-ops/UASN-AI-Specialist |
| kali-linux | blazinsoulja420-ops/Kali-Linux- |
| researchos | blazinsoulja420-ops/UP-RES-001-Autonomous-Research-System |

An existing GitHub repo **does not prove a matching laptop checkout**.
The example intentionally has watch_enabled=false, execution_enabled=false,
local_root=null, state_directory=null for every project. Do not guess local paths.

## Dry-run (no side effects on project repositories)

From the UPAB repository checkout, with Python >=3.11:

    $env:PYTHONPATH = ".\src"
    python -m upab.multiwatch --config .\config\multi-projects.example.json

Expected for unconfigured template: five NOT_ARMED, five DISABLED.
This command parses the registry and performs read-only Git origin checks only
for profiles manually configured with watch_enabled=true. It does not start a
watcher, alter state, pull/commit Git changes, download models, or dispatch tasks.

Before enabling a *preflight* profile in a PRIVATE copy of this config:
1. Verify the exact independent clone of that GitHub repository on the laptop.
2. Select the canonical absolute local_root and a separate existing private
   state_directory unique to that project and outside *all* repo roots.
3. Keep execution_enabled=false (the prototype rejects true).
4. Set watch_enabled=true only for read-only identity preflight; this is NOT
   a running watcher or approval to process clipboard tasks.
5. Run the preflight and verify it reports READY_READ_ONLY_PREFLIGHT.
6. Store the PRIVATE config outside Git; never commit machine paths, secrets or nonces.

## Authority boundaries

- One future Windows host coordinator and one global clipboard event listener.
- Each project gets an exact allow-listed repository root, distinct channel,
  isolated nonce/task ledger, task queue, audit/evidence path and approval rules.
- Project folders must not be nested/overlap. State directories must not overlap
  any project repo root or another project's state.
- A GitHub remote must match its configured project identity. Wrong remote,
  missing root, ambiguous IDs, duplicate channel or unknown config fields deny
  operation. No inference from folder names alone.
- Never treat a repo file, prompt, commit, incoming chat, or clipboard content as
  owner authorization. Untrusted input cannot grant execution privileges.
- Kali-Linux profile does not permit scanning third-party systems or executing
  security utilities. Its preflight remains read-only.
- ResearchOS and UASN remain independent projects, not delegated root
  controllers over Poindexter or Universal AI.
- Existing Exact Relay v1 and draft v2 ledger are not wired into this registry.
  No watcher is installed, enabled or scheduled by this candidate.

## Remaining implementation gates

1. Windows event-loop and process-wide single-instance lock; one clipboard
   listener for all profiles, no competing clipboard writers.
2. Secure per-project task dispatcher with explicit routing binding, independent
   durable ledgers, authentication/provenance, expiry and human-approval gates.
3. Bounded single-flight execution per profile with backpressure; global
   resource ceilings, safe retry classification, cancellation and restart
   recovery. Never silently replay consumed tasks.
4. Event notification for changed repositories; status-only mode first.
   Project file changes must NOT automatically initiate task execution.
5. Sanitized audit logs, retention, health and telemetry with no copied prompts,
   secrets, or raw clipboard data.
6. Secure migration from v1 to v2; lock out v1 while using v2 ledger, rotate
   nonces and preserve immutable rollback evidence.
7. Tests: project-confusion/forged remote, duplicate folders/channels, Windows
   permission boundaries, concurrency, failure injection, idle CPU/latency,
   crash recovery and no unauthorized cross-repo writes.
8. Independent security review and explicit owner-approved activation.

Do not merge, deploy, start services, or activate execution based on this stage.
