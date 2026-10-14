# Watcher v3 — Stage 34 project/module health roll-up (inert)

**Status:** REVIEW CANDIDATE ONLY. This is a synthetic, metadata-only evaluator—not a running watcher, not a health check of the owner's machine, and not a GitHub monitoring connection.

## Purpose and architecture

One shared Watcher supervisor, at most 32 approved active folder monitors, and up to 64 registered project slots is preferable to launching an independent watcher for every Poindexter application category. Poindexter's 19 categories are **modules** of the single existing `UP-UHAIB-001-Poindexter` project. A Poindexter module named Digital Twin does not inherit the separate Digital Twin repository's rights or reveal its files. The nine selected repositories are maintained by the Stage 33 roster; `online-store` remains excluded.

Stage 34 adds `src/upab/relay/v3_portfolio_health_rollup.py`: a bounded **pure read-only** aggregator for caller-supplied untrusted synthetic observations. It validates the same exact nine projects and 19 module IDs with Stage 33; accepts a maximum of 28 distinct synthetic observations; rejects unknown, duplicate, or mislabeled entities, including unapproved extra repositories and claims of owner verification.

## Health classification

- Missing project observation means **UNKNOWN**, never OK.
- Missing module observation means **UNKNOWN**, never OK.
- Stale observation (older than the caller-specified 1–3600-second freshness window) means **UNKNOWN**, even if the prior reported status was OK or ALERT.
- Future-dated or malformed observations are **BLOCKED**.
- Fresh reported OK, ALERT, DEGRADED and PAUSED are returned in **unverified** aggregate categories. They are not independent hardware/source health attestations. Explicit UNKNOWN is retained.
- The output contains only counts, fixed security-denial flags and a reviewer status. It contains **no private repository names, local file paths, credentials, payloads, signatures or tasks**. All authority, trust, monitor enablement, repo connections, and Windows mutation flags are FALSE.

A fake provider that supplies 28 fresh "OK" reports still produces **zero verified healthy projects or modules**. This is essential to avoid falsely displaying green health when no authenticated local monitoring exists.

## Testing and release boundaries

`tests/test_v3_portfolio_health_rollup.py` covers no signals (28 unknown), mixed module/project reports, distinct failure states, exact stale boundaries, forged "verified" claims, wrong/project-spoofed module IDs, future timestamps, duplicate report override, full bounded inventory and prohibited activation methods. These are **fixture tests only**. They do not authenticate a source, run a host process, confirm Windows Hello, or establish actual project health.

The next necessary acceptance stages are: verify exact installed watcher launcher/provenance and actual owner Windows device constraints; complete protected owner presence, single-use scoped approvals, legacy watcher stop/rollback proof; independently approve project-specific observation sources and privacy; then test a narrowly scoped real read-only watcher in the selected environment. Do not infer deployment readiness from a synthetic health count or passing CI.

The Stage 31/32 publisher key review remains non-authorizing. The 12 v3 feature flags are OFF. Nine project selections are inert. No execution, device commands, cloud provider integration, paid API, folder creation, new chats or repository connection is introduced by this stage.
