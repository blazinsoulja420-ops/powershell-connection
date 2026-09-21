param(
    [string]$Config = ".\config\local.json",
    [string]$ChannelId = "upab-poindexter-local"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ConfigPath = if ([System.IO.Path]::IsPathRooted($Config)) { $Config } else { Join-Path $Root $Config }

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}

$Backup = "$ConfigPath.before-exact-relay.bak"
Copy-Item -LiteralPath $ConfigPath -Destination $Backup -Force

$Cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

$Relay = [ordered]@{
    enabled = $true
    channel_id = $ChannelId
    poll_interval_ms = 500
    max_task_lifetime_seconds = 900
    max_operations = 50
    auto_copy_result = $true
    rollback_on_failure = $true
    require_task_expected_head_for_mutation = $true
}

$Cfg | Add-Member -NotePropertyName exact_relay -NotePropertyValue $Relay -Force
$Json = $Cfg | ConvertTo-Json -Depth 20
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ConfigPath, $Json + [Environment]::NewLine, $Utf8NoBom)

Write-Host "EXACT RELAY CONFIG ENABLED" -ForegroundColor Green
Write-Host "Config: $ConfigPath"
Write-Host "Backup: $Backup"
Write-Host "Channel: $ChannelId"
Write-Host "Read-only remains: $($Cfg.governance.read_only)"
Write-Host "Authorized write paths: $($Cfg.governance.authorized_write_paths.Count)"
Write-Host "Canonical mutation gate remains: $($Cfg.governance.require_canonical_for_mutation)"
Write-Host "No governance write authority was added by this script."
