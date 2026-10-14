# Watcher v3 — Stage 41 hardware-readiness evidence and exact owner-approval gate

**Status:** DRAFT / REVIEW-ONLY / NO DEVICE PROBE / NO HARDWARE TRUST.  
**Scope:** `blazinsoulja420-ops/powershell-connection`, candidate PR #4 only. Do not merge or run any local laptop command from this stage.

## Why this stage exists

Stage 40 proved that paired rollback of a disposable SQLite database and its Python in-memory fake witness can replay an already accepted signed report. Device capability discovery is a useful **separate** prerequisite, not a solution to that vulnerability. The presence of TPM 2.0 or Windows Hello does not demonstrate that the Watcher has an enrolled identity, owner authorization, protected NV counter, or durable anti-rollback storage.

Stage 16 already contains a separate read-only Windows Hello API preflight. **Do not duplicate that preflight or invoke it merely because the Stage 41 validator returns an all-positive report.** Stage 41 adds a source-neutral, pure and bounded contract for handling *untrusted reported* capability data without probing any Windows machine.

## Evidence schema and trust rules

Source: `src/upab/relay/v3_stage41_hardware_readiness_review.py`. Tests: `tests/test_v3_stage41_hardware_readiness_review.py`.

Input keys, all mandatory, no extensions:
- `schema`: `upab.watcher-v3.hardware-readiness-report.v1`
- `source_kind`: `CALLER_REPORTED` or `SYNTHETIC_FIXTURE` (both untrusted)
- `captured_at_epoch_s`: bounded integer UNIX seconds
- `platform`: `WINDOWS`, `OTHER`, `UNKNOWN`
- `tpm_present`, `tpm_ready`, `tpm_enabled`, `tpm_activated`, `webauthn_api_present`: exact boolean or `null` (null = unknown, not pass)

Pure assessment uses a caller-supplied `now_epoch_s` with max age 1–86400 seconds, default 900. It never independently authenticates this clock, source, computer, user or collector. Future or stale values receive `STALE_OR_FUTURE_UNTRUSTED_REPORT`; unsupported/missing data receive `INCOMPLETE_OR_UNSUPPORTED_UNTRUSTED_REPORT`; any reported false capability receives `REPORTED_CAPABILITY_GAP`; only a fresh all-true **claim** receives `UNTRUSTED_CAPABILITY_CLAIM_ONLY`.

**Even an all-true report always says false** for device inspected, owner authorization, TPM NV availability, protected monotonic store, Windows Hello user presence, collector enrollment, credential creation, TPM provisioning, monitoring and execution. The output cannot authorize a command, API call or project change. Extra fields such as `owner_authorized` are rejected, rather than copied into authority flags. The validator returns no raw device identifiers, key material or commands.

## Explicit approval gate BEFORE any real Windows read-only device probe

1. **Approval needed:** The owner must separately authorize a *specific* local Windows computer, exact *read-only* commands, operator/session, capture window and collection/redaction boundaries. A generic `Continue` or development authorization is **not** this permission. Prefer an owner-visible interactive session and review of command text before invocation.
2. **Allowed read-only observation candidates (NOT executed here):**
   - `Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated` (status only)
   - `Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm | Select-Object SpecVersion` (version only)
   - `Get-CimInstance Win32_OperatingSystem | Select-Object Version,BuildNumber` (version only)
   - Existing `preflight_owner_enrollment()` may be separately reviewed and authorized for its current implementation, but is NOT automatically part of these commands.
3. **Not allowed:** `Initialize-Tpm`, `Clear-Tpm`, `Enable-TpmAutoProvisioning`, `Set-TpmOwnerAuth`, TPM NV define/write/increment/delete, ownership changes, UEFI/firmware settings, BitLocker operations, Windows Hello credential creation, `WebAuthNAuthenticatorMakeCredential`, installation, admin elevation, scheduled tasks or Windows services.
4. **Safe collection:** Only sanitized, bounded TPM booleans, TPM spec version, OS version/build and explicit error category. Do not collect passwords, recovery keys, endorsement/public/private keys, device serial, detailed machine identity, user SID, usernames, identifiers, security prompts or raw diagnostic dumps. Errors and missing permissions => UNKNOWN/BLOCKED, not an automatic request for admin privileges.
5. **Permission expiry:** Owner consent to read hardware status does **not** consent to use TPM hardware, provision NV storage, create keys, enroll collectors, connect GitHub, activate monitors, install a service, execute jobs or reuse an approval for Poindexter.
6. **Provenance:** Any manually pasted output is `CALLER_REPORTED`, not independently proven device telemetry. An authorized future collector must attest to exact executable identity, process/session, approved command, bounded read-only execution and source before any claim may be promoted.
7. **Stop conditions:** Unexpected prompt, privileged request, secret exposure, device mismatch, unavailable TPM interface, conflicting state, system fault, unexpected side effect or missing approval => stop and record sanitized blocker.

## Remaining architecture prerequisites (must stay blocked)

- Independent security review of the TPM NV monotonic-provider design: exact Windows API/support, NV index authorization policy, privilege boundary, counter read/write budget and endurance, manufacturer/firmware behavior, reset, lockout, recovery and replacement.
- Protected service or broker (single writer, verified local peer, privileged endpoint isolation), independent collector and publisher identity enrollment, expiry/revocation, signed state commitment plus protected monotonic epoch.
- No same-epoch trust reseal for revocation; protected epoch must advance and preserve revocation records even after offline database restore.
- Crash-consistent **two-resource** transition protocol; exact pending/finalized states and independent power-loss/reboot acceptance. Atomicity between SQLite and TPM must not be presumed.
- Trusted GitHub CI provenance adapter: verified repository/commit/run/workflow via narrowly scoped authenticated retrieval; local telemetry signed by enrolled verified collector. Caller-supplied `GITHUB_CI` label is not proof.
- Separately authenticated Windows Hello/WebAuthn owner approval with verified RP/origin, fresh single-use challenge, presence, exact action and expiry. No use of Poindexter's independently governed authority.
- Independent tester and reviewer evidence, exact-head Windows CI, owner-reviewed operational acceptance and rollback/disable plan.

## Invariants and current verdict

**DENY:** production monitoring, automation, integration, job execution, hardware use, owner key enrollment or Windows changes. PR #4 must remain draft/unmerged. The proposed nine-project roster is preserved (including Kali-Linux-, with Online Store excluded), 19 Poindexter modules remain nested, capacity is 64/32, all 12 feature flags OFF. No new project mappings are approved by this document.

**Stage 41 completion criteria:** Strict schema and denial tests PASS on Windows Python 3.11/3.12 at the exact commit; written approval scope and source references documented; no actual device access, permission upgrades or hardware changes. Further Windows TPM hardware verification is a *future separately authorized* milestone, not part of Stage 41.

## Authoritative Windows references

- Microsoft Get-Tpm: https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm
- Microsoft Win32_Tpm: https://learn.microsoft.com/en-us/windows/win32/secprov/win32-tpm
- Microsoft Windows WebAuthn APIs: https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis
- Microsoft TPM Recommendations: https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-recommendations
