function Get-PrefetchEvidence {
    param(
        [PSCustomObject]$Database
    )

    $records = @()
    $prefetchPath = "$env:SystemRoot\Prefetch"

    try {
        $prefetchFiles = Get-ChildItem $prefetchPath -Filter '*.pf' -ErrorAction Stop
    } catch {
        $records += New-EvidenceRecord -Source 'Prefetch' -Category 'ExecutionArtifact' -Type 'Prefetch' -Name 'FolderAccess' -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message; Path = $prefetchPath}
        return $records
    }

    foreach ($file in $prefetchFiles) {
        $appName = $file.BaseName.Split('-')[0]
        $fileSizeKB = [math]::Round($file.Length / 1KB, 2)

        $rawRecord = New-EvidenceRecord -Source 'Prefetch' -Category 'ExecutionArtifact' -Type 'Prefetch' -Name $appName -Path $file.Name -Value $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') -Severity 'Info' -Confidence 'Medium' -Details @{
            FileName   = $file.Name
            FileSizeKB = $fileSizeKB
            FullPath   = $file.FullName
            LastWrite  = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $records += $rawRecord

        if ($Database) {
            $matchRecords = Test-KnownToolMatch -Database $Database -Value $file.Name
            $matchRecords += Test-KnownToolMatch -Database $Database -Value $appName
            $records += $matchRecords
        }
    }

    return $records
}
