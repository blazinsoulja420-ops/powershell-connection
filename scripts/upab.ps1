param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PYTHONPATH = Join-Path $Root "src"

python -m upab @RemainingArgs
exit $LASTEXITCODE
