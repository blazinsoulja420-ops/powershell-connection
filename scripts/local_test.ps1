$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "UPAB PowerShell Connection local test gate"
Write-Host "Repository: $RepoRoot"

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python -m unittest discover -s tests -p "test*.py" -v
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -m unittest discover -s tests -p "test*.py" -v
} else {
    throw "Python was not found."
}
if ($LASTEXITCODE -ne 0) { throw "UPAB local test gate failed with exit code $LASTEXITCODE" }

Write-Host "UPAB PowerShell Connection local test gate PASSED."
