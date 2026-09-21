param(
    [string]$Config = ".\config\local.json",
    [switch]$Once
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PYTHONPATH = Join-Path $Root "src"
Push-Location $Root
try {
    $Args = @("-m", "upab", "relay-watch", "--config", $Config)
    if ($Once) { $Args += "--once" }
    & python @Args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
