function Get-ProcessEvidence {
    param(
        [PSCustomObject]$Database
    )

    $records = @()

    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        $procPath = $null
        try { $procPath = $proc.Path } catch {}

        $startTime = $null
        try { $startTime = $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch {}

        $rawRecord = New-EvidenceRecord -Source 'Processes' -Category 'ProcessSnapshot' -Type 'Process' -Name $proc.ProcessName -Path $procPath -Value "$($proc.Id)" -Severity 'Info' -Confidence 'Medium' -Details @{
            PID       = $proc.Id
            StartTime = $startTime
        }
        $records += $rawRecord

        if ($Database -and $proc.ProcessName) {
            $nameMatches = Test-KnownToolMatch -Database $Database -Value $proc.ProcessName
            foreach ($m in $nameMatches) { if ($m) { $records += $m } }
            if ($procPath) {
                $pathMatches = Test-KnownToolMatch -Database $Database -Value $procPath
                foreach ($m in $pathMatches) { if ($m) { $records += $m } }
            }
        }
    }

    return $records
}
