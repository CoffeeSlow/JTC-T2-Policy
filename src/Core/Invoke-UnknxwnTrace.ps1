function Invoke-UnknxwnTrace {
    param(
        [string]$DatabasePath,

        [string]$JsonPath,

        [string]$CsvPath,

        [switch]$SkipBAM,

        [switch]$SkipPrefetch,

        [switch]$SkipRegistry,

        [switch]$SkipThreatHistory,

        [switch]$SkipPeripherals,

        [switch]$SkipHardware,

        [switch]$SkipSystemContext,

        [switch]$SkipModuleAudit
    )

    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

    $deps = @(
        @{Path = 'src\Core\Console.ps1';               Command = 'Write-ColoredLine'}
        @{Path = 'src\Reporting\ConsoleReport.ps1';    Command = 'Write-EvidenceSummary'}
        @{Path = 'src\Reporting\ExportReport.ps1';     Command = 'Export-EvidenceJson'}
        @{Path = 'src\Core\ScanEngine.ps1';            Command = 'Invoke-UnknxwnTraceScan'}
    )
    foreach ($dep in $deps) {
        if (-not (Get-Command $dep.Command -ErrorAction SilentlyContinue)) {
            . (Join-Path $projectRoot $dep.Path)
        }
    }

    $params = @{}
    if ($DatabasePath) { $params.DatabasePath = $DatabasePath }
    if ($SkipBAM) { $params.SkipBAM = $true }
    if ($SkipPrefetch) { $params.SkipPrefetch = $true }
    if ($SkipRegistry) { $params.SkipRegistry = $true }
    if ($SkipThreatHistory) { $params.SkipThreatHistory = $true }
    if ($SkipPeripherals) { $params.SkipPeripherals = $true }
    if ($SkipHardware) { $params.SkipHardware = $true }
    if ($SkipSystemContext) { $params.SkipSystemContext = $true }
    if ($SkipModuleAudit) { $params.SkipModuleAudit = $true }

    $evidence = Invoke-UnknxwnTraceScan @params

    $evidence | Write-EvidenceSummary | Out-Null
    $evidence | Write-EvidenceReport | Out-Null

    if ($JsonPath) {
        $evidence | Export-EvidenceJson -Path $JsonPath
    }

    if ($CsvPath) {
        $evidence | Export-EvidenceCsv -Path $CsvPath
    }

    return $evidence
}
