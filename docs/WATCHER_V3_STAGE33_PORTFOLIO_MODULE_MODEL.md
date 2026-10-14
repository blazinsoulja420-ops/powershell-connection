# Watcher v3 — Stage 33 portfolio and module-aware review

**Status:** REVIEW CANDIDATE. The owner selected nine standalone repositories; **no** watcher instance is installed, started or authorized by this proposal. This configuration is a human-reviewed documentation/CI example, never a runtime credentials/monitor subscription.

## Why keep the Watcher?

A single governed Watcher can eventually monitor many owner-approved independent repository projects, each using approved local folder/event scopes, and report **module-level** failures inside shared apps without creating a repository or independent watcher process for every UI category. Poindexter's 19 categories are modules in its main repository; separately owned services such as Digital Twin remain independently governed. A module called Digital Twin does not automatically connect the independent Digital Twin repository.

## Stage 33 deliverables

- config/watcher-v3-owner-selected-portfolio.example.json — exactly nine owner-selected repository names, with every project monitor OFF; the 19 Poindexter application categories nested under UP-UHAIB-001-Poindexter, each module monitor OFF. Fixed limits 64 projects and 32 concurrent monitors, auto-activation forbidden, no connections.
- src/upab/relay/v3_portfolio_review.py — fail-closed READ-ONLY proposal parser taking a selected absolute file, bounded input size, duplicate JSON-key rejection, filesystem redirection detection and sanitized counts-only output. It validates exact project identities, numbered module IDs and category labels (using the October 14 Repository Master Plan's category TABLE rather than the differently positioned diagram labels), distinct NSFW and Kali isolation scopes, and the absence of implied repo connections. It cannot actually monitor folders or open GitHub connections.
- tests/test_v3_portfolio_review.py — strict tests for nine projects, nineteen nested modules, unchanged input bytes, duplicate or omitted repositories, excluded Online Store, unauthorized School Tutor/RAID/Tasker inclusion, changed or misplaced module identifiers, accidental monitor activation, forbidden repository links, altered capacity, scope downgrades, malformed/symlink/oversized files and unavailable execution APIs.

## Exact owner-selected projects

1. UP-UHAIB-001-Poindexter
2. Universal-AI-
3. UP-RES-001-Autonomous-Research-System
4. UASN-AI-Specialist
5. powershell-connection
6. P-DT-001-Digital-Twin
7. Universal-AI-Behavior-Requirements-Registry
8. NSFW (INDEPENDENT_RESTRICTED)
9. Kali-Linux- (DEFENSIVE_OFFLINE_ONLY)

**Explicitly excluded:** online-store. Other known repositories are NOT silently absorbed.

## Operational and trust gates

**A schema PASS is not proof that nine monitors are running.** To monitor one project in the future, independently approve its actual installed watcher identity, local project folder, event types, rate limits, principal, privacy class, identity and backup/rollback. Monitoring does not grant repository write permissions, API tokens or access to adjacent projects.

The Stage 31/32 cryptographic reviews remain review-only. The owner Windows Hello credential, independently anchored signing publisher, old runtime quiescence, protected monotonic store, scoped Windows acceptance and proven rollback are NOT yet present. All twelve watcher upgrades remain OFF, 64 project capacity/32 monitor capacity unchanged.

## Preview only — Windows PowerShell from the code checkout

    $env:PYTHONPATH = '.\src'
    python -m upab.relay.v3_portfolio_review --config 'C:\EXISTING\CHECKOUT\config\watcher-v3-owner-selected-portfolio.example.json'

Exit code zero means only that the proposal passed strict static review, NOT execution approval.

## Later optional inclusion

School Tutor, Tasker AutoInput Bridge, RAID AI and Master Mechanic AI are independent owner-approval candidates, NOT registered now. For future additions: choose exact repository identity, define watcher data scope, preserve isolation, revise the reviewed allowlist and negative tests and authorize separately. No project folder or chat may be created automatically on the basis of metadata.
