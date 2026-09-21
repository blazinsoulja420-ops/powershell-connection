# Upgrade from UPAB v1 to v1.1 Exact Relay Autopilot

The safest deployment is **side-by-side**, keeping the verified v1 folder intact until v1.1 passes on the Windows host.

Existing v1 location used during setup:

```text
C:\Users\chaot\Documents\UPAB-v1\universal-powershell-agent-bridge-v1
```

Recommended v1.1 location:

```text
C:\Users\chaot\Documents\UPAB-v1.1\universal-powershell-agent-bridge-v1.1
```

## Preserve the existing local configuration

Copy the existing `config\local.json` into the new v1.1 folder. The v1.1 loader supplies safe defaults if the old file has no `exact_relay` section.

Then run:

```powershell
.\scripts\Test-UPAB-v1.1.ps1 -Config .\config\local.json
```

Expected suite result:

```text
Ran 23 tests
OK
```

## Enable the relay transport only

```powershell
.\scripts\Enable-UPAB-ExactRelay.ps1 -Config .\config\local.json -ChannelId "upab-poindexter-local"
```

This script:

- backs up `local.json` first;
- adds/enables the Exact Relay transport settings;
- does **not** set `governance.read_only=false`;
- does **not** add authorized write paths;
- does **not** weaken the canonical-governance mutation gate.

## First live host gate — read only

Show the relay nonce:

```powershell
.\scripts\Show-UPAB-RelayNonce.ps1 -Config .\config\local.json
```

Then start one-shot watcher mode:

```powershell
.\scripts\Start-UPAB-ExactRelay.ps1 -Config .\config\local.json -Once
```

The first copied task SHALL be read-only and limited to `git_status`, `hash_file`, or other read operations.
Do not enable mutation until the Windows clipboard watcher and result-copy loop are verified.
