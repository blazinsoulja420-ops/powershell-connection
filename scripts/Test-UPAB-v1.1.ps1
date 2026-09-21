param([string]$Config = ".\config\local.json")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PYTHONPATH = Join-Path $Root "src"
Push-Location $Root
try {
    Write-Host "=== UPAB v1.1 SELF-TESTS ===" -ForegroundColor Cyan
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if (Test-Path -LiteralPath $Config) {
        Write-Host "`n=== EXACT RELAY NONCE ===" -ForegroundColor Cyan
        python -m upab relay-nonce --config $Config
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    else {
        Write-Host "Config not found yet: $Config" -ForegroundColor Yellow
    }
    exit 0
}
finally { Pop-Location }
