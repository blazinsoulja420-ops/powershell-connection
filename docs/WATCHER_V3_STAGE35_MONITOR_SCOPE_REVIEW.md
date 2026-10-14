# Watcher v3 Stage 35 — Monitoring Scope Admission REVIEW

**Status: INERT DEVELOPMENT CANDIDATE. NO MONITORING ACTIVATED.**

## Why keep Watcher?

Watcher can serve as one bounded project-monitoring control plane even when each project remains in an independently governed repository. Monitors should report verified, fresh evidence or UNKNOWN; the code/approval broker must remain separate. A watcher must not interpret chat text, model outputs, README documents, repository additions or a valid test report as permission to start software, read secrets, create chats, change a repository, or execute tasks.

## Stage 35 tested candidate

- `src/upab/relay/v3_monitor_scope_review.py` reviews **only** a synthetic scope intent against the exact owner-selected 9-repository Stage 33 portfolio. It never opens any path, uses an external service, starts a process, or installs a watcher.
- Strict schema with `preview_only: true`, a bounded subset of selected exact GitHub repository names, and optional Poindexter module IDs. Duplicate, missing-parent, foreign, malformed or over-capacity intent is rejected. Scope settings, commands, paths, activation fields, arbitrary repositories or connections are forbidden.
- Each of the nine selected repositories is at most **one potential folder root** in a future separate owner approval, subject to the existing 32-concurrent-monitor cap and 64-registered-project cap. The **19 Poindexter feature categories consume zero extra root slots**, and cannot be promoted to standalone repos through this preview.
- `NSFW` and `Kali-Linux-` receive special restricted-scope review counts and **never** inherit reading/monitoring authority. Self-monitoring of `powershell-connection` is also singled out as a separate acceptance risk, not allowed to self-authorize its own execution.
- Explicitly excluded `online-store` and unapproved candidate repositories (School.tutor, RAID-AI, Tasker, Master-Mechanic-AI, etc.) are rejected. Such a candidate needs separate human-controlled roster review before inclusion.
- All reports are sanitized counts without repository identities or local directory names. `approved_local_directory_roots=0`, `actual_monitored_root_count=0`, `live_monitoring_enabled=false`, `task_execution_authorized=false`, no installation, chat/folder creation, repo connection, or filesystem mutation.
- `tests/test_v3_monitor_scope_review.py` exercises safe empty plan, all nine repos and 19 modules, nested-only slots, restricted/self categories, order-independent outputs, duplicated/foreign identities, forged authority/paths/commands, malicious containers and tampered baseline.

## Release remains blocked

Real Windows watcher installation not independently located; no exact owner-reviewed local root mapping exists for the selected projects; old launcher/service/process absence not proven; authenticated release trust, Windows Hello owner approval, secure counter, protected backup/rollback, and real device acceptance incomplete. Stage 33 and 34 are portfolio/health REVIEW only. Stage 35 only provides capacity and approval-scope *planning*. It does not authorize or implement run-time monitoring.

**Current roster:** 9 selected; 19 internal Poindexter modules; `online-store` excluded; 64 project limit; 32 concurrent monitor limit; all 12 watcher features OFF. PR #4 DRAFT/UNMERGED. No repo access or cross-project integration implied.
