$ModuleRoot = $PSScriptRoot

. (Join-Path $ModuleRoot 'src\Core\Console.ps1')
. (Join-Path $ModuleRoot 'src\Core\Logging.ps1')
. (Join-Path $ModuleRoot 'src\Core\Evidence.ps1')
. (Join-Path $ModuleRoot 'src\Intelligence\KnownTools.ps1')
. (Join-Path $ModuleRoot 'src\Intelligence\ToolMatching.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\SystemContext.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\BAM.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\Prefetch.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\Processes.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\Peripherals.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\Hardware.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\Defender.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\Downloads.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\RegistryScan.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\ThreatHistory.ps1')
. (Join-Path $ModuleRoot 'src\Collectors\ModuleAudit.ps1')
. (Join-Path $ModuleRoot 'src\Reporting\ConsoleReport.ps1')
. (Join-Path $ModuleRoot 'src\Reporting\Timeline.ps1')
. (Join-Path $ModuleRoot 'src\Reporting\ExportReport.ps1')
. (Join-Path $ModuleRoot 'src\Core\ScanEngine.ps1')
. (Join-Path $ModuleRoot 'src\Core\Invoke-UnknxwnTrace.ps1')
. (Join-Path $ModuleRoot 'src\Monitoring\DefenderMonitor.ps1')
. (Join-Path $ModuleRoot 'src\Monitoring\FileWatcher.ps1')

function Show-UnknxwnTraceHelp {
    Write-Host ''
    Write-Host 'Unknxwn Trace v2.0' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Usage:' -ForegroundColor Yellow
    Write-Host '  .\UnknxwnTrace.ps1 [Mode]'
    Write-Host ''
    Write-Host 'Available modes:' -ForegroundColor Yellow
    Write-Host '  -Legacy    Run preserved legacy JTC scanner'
    Write-Host ''
    Write-Host 'Planned modes:' -ForegroundColor Yellow
    Write-Host '  -Collect   Run modular evidence collectors'
    Write-Host '  -Monitor   Start live monitoring tools'
    Write-Host '  -Report    Generate reports from existing evidence'
    Write-Host '  -Full      Run collect + timeline + report workflow'
    Write-Host ''
    Write-Host 'Examples:' -ForegroundColor Yellow
    Write-Host '  .\UnknxwnTrace.ps1'
    Write-Host '  .\UnknxwnTrace.ps1 -Legacy'
    Write-Host ''
}

function Start-UnknxwnTraceLegacy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [string[]]$Arguments = @()
    )

    $legacyScanner = Join-Path $RootPath 'legacy\JTC_Scanner.ps1'
    if (-not (Test-Path -LiteralPath $legacyScanner)) {
        throw "Legacy scanner not found: $legacyScanner"
    }

    & $legacyScanner @Arguments
}

Export-ModuleMember -Function Show-UnknxwnTraceHelp, Start-UnknxwnTraceLegacy, Write-ColoredLine, Wait-ForEnter, Show-CustomLoadingBar, Write-BoxedHeader, Write-Log, New-EvidenceRecord, Test-EvidenceRecord, Import-KnownTools, Get-KnownToolIndicators, Test-KnownToolMatch, Resolve-KnownToolCategory, Get-SystemContextEvidence, Get-BAMEvidence, Get-PrefetchEvidence, Get-ProcessEvidence, Get-DefenderStatusEvidence, Get-DefenderExclusionsEvidence, Get-DownloadsEvidence, Get-RegistryEvidence, Get-PeripheralEvidence, Get-HardwareEvidence, Get-DefenderThreatHistoryEvidence, Get-ModuleAuditEvidence, Start-DefenderMonitor, Start-DefenderEventMonitor, Stop-DefenderMonitor, Stop-DefenderEventMonitor, Get-DefenderMonitorChanges, Start-FileWatcherMonitor, Stop-FileWatcherMonitor, Write-EvidenceReport, Write-EvidenceSummary, Get-EvidenceTimeline, Write-EvidenceTimeline, Export-EvidenceJson, Export-EvidenceCsv, Invoke-UnknxwnTraceScan, Invoke-UnknxwnTrace