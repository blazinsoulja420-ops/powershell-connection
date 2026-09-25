param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('GetItem', 'ResolvePath', 'SelectString')]
    [string]$Operation,
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$Pattern = ''
)

$ErrorActionPreference = 'Stop'
switch ($Operation) {
    'GetItem' { Get-Item -LiteralPath $Path | Select-Object FullName, Length, Attributes, LastWriteTimeUtc | ConvertTo-Json -Compress }
    'ResolvePath' { (Resolve-Path -LiteralPath $Path).Path }
    'SelectString' { Select-String -LiteralPath $Path -SimpleMatch -Pattern $Pattern | Select-Object Path, LineNumber, Line | ConvertTo-Json -Compress }
    default { throw 'Unsupported trusted operation' }
}
