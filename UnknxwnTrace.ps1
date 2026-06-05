param(
    [switch]$Legacy,
    [switch]$SkipPause,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$LegacyArgs
)

$ErrorActionPreference = 'Stop'

$RootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulePath = Join-Path $RootPath 'UnknxwnTrace.psm1'

Import-Module $ModulePath -Force

if ($Legacy) {
    $arguments = @()
    if ($SkipPause) { $arguments += '-SkipPause' }
    if ($LegacyArgs) { $arguments += $LegacyArgs }
    Start-UnknxwnTraceLegacy -RootPath $RootPath -Arguments $arguments
    return
}

Show-UnknxwnTraceHelp
