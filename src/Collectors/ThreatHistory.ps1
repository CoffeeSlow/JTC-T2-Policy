function Get-DefenderThreatHistoryEvidence {
    $records = @()

    try {
        $threats = Get-MpThreat -ErrorAction Stop
    } catch {
        $records += New-EvidenceRecord -Source 'DefenderThreatHistory' -Category 'Security' -Type 'ThreatAccess' -Name 'Defender Threat History' -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message}
        return $records
    }

    if (-not $threats -or $threats.Count -eq 0) {
        $records += New-EvidenceRecord -Source 'DefenderThreatHistory' -Category 'Security' -Type 'ThreatHistory' -Name 'Defender Threat History' -Value 'None' -Severity 'Info' -Confidence 'High'
        return $records
    }

    $severityMap = @{1='Low'; 2='Medium'; 3='High'; 4='Severe'; 5='Info'}
    $statusMap = @{0='Active'; 1='Removed'; 2='Quarantined'; 3='Cleaned'; 4='Allowed'; 6='Detected'}

    foreach ($threat in $threats) {
        $threatSeverity = if ($null -ne $threat.SeverityID) { $severityMap[[int]$threat.SeverityID] } else { 'Unknown' }
        if (-not $threatSeverity) { $threatSeverity = 'Unknown' }
        $actionStatus = if ($null -ne $threat.ThreatStatusID) { $statusMap[[int]$threat.ThreatStatusID] } else { 'Unknown' }
        if (-not $actionStatus) { $actionStatus = 'Unknown' }
        $resourcePath = if ($threat.Resources) { $threat.Resources -join '; ' } else { 'N/A' }

        $records += New-EvidenceRecord -Source 'DefenderThreatHistory' -Category 'Security' -Type 'Threat' -Name $threat.ThreatName -Value "$threatSeverity / $actionStatus" -Severity $threatSeverity -Confidence 'High' -Details @{
            ThreatName      = $threat.ThreatName
            Severity        = $threatSeverity
            ResourcePath    = $resourcePath
            ActionStatus    = $actionStatus
            ThreatID        = $threat.ThreatID
            CategoryID      = $threat.CategoryID
            IsActive        = $threat.IsActive
            DidThreatExecute = $threat.DidThreatExecute
        }
    }

    return $records
}
