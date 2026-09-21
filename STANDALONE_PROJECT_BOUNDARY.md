# Standalone Repository Boundary

Status: ACTIVE
Mode: INDEPENDENT_PROJECT
Repository: blazinsoulja420-ops/powershell-connection

This repository SHALL be built, tested, documented, released, and completed as an independent project.

Rules:
- This repository owns its own implementation, requirements, architecture, state, tests, evidence, release decisions, and completion criteria.
- No other repository is automatically a runtime dependency, authority source, integration target, shared service, or required component.
- References to another repository are informational only unless an explicit, repository-specific integration authorization is added later.
- Do not create cross-repository imports, API dependencies, shared runtime state, automatic inheritance, synchronized releases, or coupled completion gates without explicit authorization.
- Do not move this repository's source code, project state, or canonical artifacts into another repository.
- Shared ideas may be copied or independently implemented only when appropriate licensing/provenance is preserved and duplication is intentional.
- Completion of this repository must be evaluated independently from all other repositories.
- Changes in another repository must not silently alter this repository's behavior, authority, scope, or completion state.

Cross-repository work is prohibited by default. Any future integration must identify both repositories, exact interfaces, authority, data flow, rollback plan, tests, and explicit approval.
