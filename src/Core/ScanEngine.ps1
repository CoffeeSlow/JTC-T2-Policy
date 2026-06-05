function Invoke-UnknxwnTraceScan {
    param(
        [string]$DatabasePath,

        [switch]$SkipBAM,

        [switch]$SkipPrefetch,

        [switch]$SkipProcesses,

        [switch]$SkipDefender,

        [switch]$SkipDownloads,

        [switch]$SkipRegistry,

        [switch]$SkipThreatHistory,

        [switch]$SkipPeripherals,

        [switch]$SkipHardware,

        [switch]$SkipSystemContext,

        [switch]$SkipModuleAudit
    )

    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

    $deps = @(
        @{Path = 'src\Core\Evidence.ps1';             Command = 'New-EvidenceRecord'}
        @{Path = 'src\Intelligence\KnownTools.ps1';   Command = 'Import-KnownTools'}
        @{Path = 'src\Intelligence\ToolMatching.ps1'; Command = 'Test-KnownToolMatch'}
    )
    foreach ($dep in $deps) {
        if (-not (Get-Command $dep.Command -ErrorAction SilentlyContinue)) {
            . (Join-Path $projectRoot $dep.Path)
        }
    }

    $collectors = @()
    if (-not $SkipSystemContext) {
        $collectors += @{Path = 'src\Collectors\SystemContext.ps1'; Command = 'Get-SystemContextEvidence'}
    }
    if (-not $SkipBAM) {
        $collectors += @{Path = 'src\Collectors\BAM.ps1';           Command = 'Get-BAMEvidence'}
    }
    if (-not $SkipPrefetch) {
        $collectors += @{Path = 'src\Collectors\Prefetch.ps1';      Command = 'Get-PrefetchEvidence'}
    }
    if (-not $SkipProcesses) {
        $collectors += @{Path = 'src\Collectors\Processes.ps1';     Command = 'Get-ProcessEvidence'}
    }
    if (-not $SkipDefender) {
        $collectors += @{Path = 'src\Collectors\Defender.ps1';      Command = 'Get-DefenderStatusEvidence'}
    }
    if (-not $SkipDownloads) {
        $collectors += @{Path = 'src\Collectors\Downloads.ps1';        Command = 'Get-DownloadsEvidence'}
    }
    if (-not $SkipRegistry) {
        $collectors += @{Path = 'src\Collectors\RegistryScan.ps1';     Command = 'Get-RegistryEvidence'}
    }
    if (-not $SkipThreatHistory) {
        $collectors += @{Path = 'src\Collectors\ThreatHistory.ps1';    Command = 'Get-DefenderThreatHistoryEvidence'}
    }
    if (-not $SkipPeripherals) {
        $collectors += @{Path = 'src\Collectors\Peripherals.ps1';     Command = 'Get-PeripheralEvidence'}
    }
    if (-not $SkipHardware) {
        $collectors += @{Path = 'src\Collectors\Hardware.ps1';        Command = 'Get-HardwareEvidence'}
    }
    if (-not $SkipModuleAudit) {
        $collectors += @{Path = 'src\Collectors\ModuleAudit.ps1';     Command = 'Get-ModuleAuditEvidence'}
    }

    foreach ($c in $collectors) {
        if (-not (Get-Command $c.Command -ErrorAction SilentlyContinue)) {
            . (Join-Path $projectRoot $c.Path)
        }
    }

    $db = $null
    if ($DatabasePath) {
        $resolvedPath = if ([System.IO.Path]::IsPathRooted($DatabasePath)) { $DatabasePath } else { Join-Path $projectRoot $DatabasePath }
        $db = Import-KnownTools -Path $resolvedPath
    }

    $allEvidence = @()

    if (-not $SkipSystemContext) {
        $allEvidence += Get-SystemContextEvidence
    }

    if (-not $SkipBAM) {
        $allEvidence += Get-BAMEvidence -Database $db
    }

    if (-not $SkipPrefetch) {
        $allEvidence += Get-PrefetchEvidence -Database $db
    }

    if (-not $SkipProcesses) {
        $allEvidence += Get-ProcessEvidence -Database $db
    }

    if (-not $SkipDefender) {
        $allEvidence += Get-DefenderStatusEvidence
        $allEvidence += Get-DefenderExclusionsEvidence
    }

    if (-not $SkipDownloads) {
        $allEvidence += Get-DownloadsEvidence -Database $db
    }

    if (-not $SkipRegistry) {
        $allEvidence += Get-RegistryEvidence -Database $db
    }

    if (-not $SkipThreatHistory) {
        $allEvidence += Get-DefenderThreatHistoryEvidence
    }

    if (-not $SkipPeripherals) {
        $allEvidence += Get-PeripheralEvidence
    }

    if (-not $SkipHardware) {
        $allEvidence += Get-HardwareEvidence
    }

    if (-not $SkipModuleAudit) {
        $allEvidence += Get-ModuleAuditEvidence
    }

    $allEvidence = $allEvidence | Where-Object { $_ -and ($_ | Test-EvidenceRecord) }

    return $allEvidence
}
