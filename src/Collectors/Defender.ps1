function Get-DefenderStatusEvidence {
    $records = @()

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'StatusAccess' -Name 'Defender Status' -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message}
        return $records
    }

    $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'RealTimeProtection' -Name 'Real-Time Protection' -Value "$($status.RealTimeProtectionEnabled)" -Severity 'Info' -Confidence 'High'

    $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'AntivirusEnabled' -Name 'Antivirus Enabled' -Value "$($status.AntivirusEnabled)" -Severity 'Info' -Confidence 'High'

    $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'AntispywareEnabled' -Name 'Antispyware Enabled' -Value "$($status.AntispywareEnabled)" -Severity 'Info' -Confidence 'High'

    if ($null -ne $status.TamperProtection -and $status.TamperProtection -is [int]) {
        $tamperLabels = @{0='Off'; 1='On'; 2='Audit'}
        $tamperValue = if ($tamperLabels.ContainsKey($status.TamperProtection)) { $tamperLabels[$status.TamperProtection] } else { "$($status.TamperProtection)" }
        $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'TamperProtection' -Name 'Tamper Protection' -Value $tamperValue -Severity 'Info' -Confidence 'High'
    }

    if ($status.LastQuickScanDateTime) {
        $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'LastScan' -Name 'Last Quick Scan' -Value "$($status.LastQuickScanDateTime)" -Severity 'Info' -Confidence 'High'
    }

    return $records
}

function Get-DefenderExclusionsEvidence {
    $records = @()

    try {
        $pref = Get-MpPreference -ErrorAction Stop
    } catch {
        $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'ExclusionsAccess' -Name 'Defender Exclusions' -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message}
        return $records
    }

    $hasExclusions = $false

    $pathExclusions = $pref.ExclusionPath
    if ($pathExclusions -and @($pathExclusions)[0] -notlike 'N/A*') {
        $hasExclusions = $true
        foreach ($path in $pathExclusions) {
            $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'PathExclusion' -Name 'Path Exclusion' -Path $path -Value $path -Severity 'Medium' -Confidence 'High'
        }
    }

    $procExclusions = $pref.ExclusionProcess
    if ($procExclusions -and @($procExclusions)[0] -notlike 'N/A*') {
        $hasExclusions = $true
        foreach ($proc in $procExclusions) {
            $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'ProcessExclusion' -Name 'Process Exclusion' -Path $proc -Value $proc -Severity 'Medium' -Confidence 'High'
        }
    }

    $extExclusions = $pref.ExclusionExtension
    if ($extExclusions -and @($extExclusions)[0] -notlike 'N/A*') {
        $hasExclusions = $true
        foreach ($ext in $extExclusions) {
            $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'ExtensionExclusion' -Name 'Extension Exclusion' -Value $ext -Severity 'Medium' -Confidence 'High'
        }
    }

    if (-not $hasExclusions) {
        $records += New-EvidenceRecord -Source 'Defender' -Category 'SecurityProduct' -Type 'Exclusions' -Name 'Defender Exclusions' -Value 'None' -Severity 'Info' -Confidence 'High'
    }

    return $records
}
