param([string]$Config = ".\config\local.json")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PYTHONPATH = Join-Path $Root "src"
Push-Location $Root
try {
    python -m upab relay-nonce --config $Config
    exit $LASTEXITCODE
}
finally { Pop-Location }
