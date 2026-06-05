function Get-BAMEvidence {
    param(
        [PSCustomObject]$Database
    )

    $records = @()

    try {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $bamEntries = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid" -ErrorAction Stop
    } catch {
        $records += New-EvidenceRecord -Source 'BAM' -Category 'ExecutionArtifact' -Type 'BAM' -Name 'RegistryAccess' -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message}
        return $records
    }

    $entries = $bamEntries.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }

    foreach ($entry in $entries) {
        if ($entry.Value.Length -lt 8) { continue }

        $appPath = $entry.Name
        $timestamp = [BitConverter]::ToInt64($entry.Value, 0)
        $lastRunDate = [DateTime]::FromFileTime($timestamp)

        $rawRecord = New-EvidenceRecord -Source 'BAM' -Category 'ExecutionArtifact' -Type 'BAM' -Name $appPath -Path $appPath -Value $lastRunDate.ToString('yyyy-MM-dd HH:mm:ss') -Severity 'Info' -Confidence 'Medium' -Details @{
            FileTime     = $timestamp
            LastRunDate  = $lastRunDate.ToString('yyyy-MM-dd HH:mm:ss')
            LastAccessTime = if (Test-Path $appPath) { (Get-Item $appPath).LastAccessTime.ToString() } else { 'N/A' }
        }
        $records += $rawRecord

        if ($Database) {
            $exeName = Split-Path $appPath -Leaf
            $matchRecords = Test-KnownToolMatch -Database $Database -Value $appPath
            $matchRecords += Test-KnownToolMatch -Database $Database -Value $exeName
            $records += $matchRecords
        }
    }

    return $records
}
