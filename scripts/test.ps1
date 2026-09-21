$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PYTHONPATH = Join-Path $Root "src"
Push-Location $Root
try {
    python -m unittest discover -s tests -v
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
