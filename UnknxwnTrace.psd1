@{
    RootModule        = 'UnknxwnTrace.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'f84dfd38-0f3d-4c1b-a184-88d56d6df4f3'
    Author            = 'CoffeeSlow'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2026 CoffeeSlow. All rights reserved.'
    Description       = 'Unknxwn Trace v2.0 evidence collection, monitoring, and reporting suite.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Show-UnknxwnTraceHelp',
        'Start-UnknxwnTraceLegacy',
        'Write-ColoredLine',
        'Wait-ForEnter',
        'Show-CustomLoadingBar',
        'Write-BoxedHeader',
        'Write-Log',
        'New-EvidenceRecord',
        'Test-EvidenceRecord',
        'Import-KnownTools',
        'Get-KnownToolIndicators',
        'Test-KnownToolMatch',
        'Resolve-KnownToolCategory',
        'Get-SystemContextEvidence',
        'Get-BAMEvidence',
        'Get-PrefetchEvidence',
        'Get-ProcessEvidence',
        'Get-DefenderStatusEvidence',
        'Get-DefenderExclusionsEvidence',
        'Get-DownloadsEvidence',
        'Get-RegistryEvidence',
        'Get-DefenderThreatHistoryEvidence',
        'Get-ModuleAuditEvidence',
        'Get-DefenderMonitorChanges',
        'Get-PeripheralEvidence',
        'Start-DefenderMonitor',
        'Start-DefenderEventMonitor',
        'Start-FileWatcherMonitor',
        'Stop-DefenderEventMonitor',
        'Stop-DefenderMonitor',
        'Stop-FileWatcherMonitor',
        'Get-HardwareEvidence',
        'Write-EvidenceReport',
        'Write-EvidenceSummary',
        'Get-EvidenceTimeline',
        'Write-EvidenceTimeline',
        'Export-EvidenceJson',
        'Export-EvidenceCsv',
        'Invoke-UnknxwnTraceScan',
        'Invoke-UnknxwnTrace'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
}
