function Get-DownloadsEvidence {
    param(
        [PSCustomObject]$Database
    )

    $records = @()
    $downloadsPath = [Environment]::GetFolderPath('UserProfile') + '\Downloads'

    try {
        $files = Get-ChildItem $downloadsPath -File -ErrorAction Stop
    } catch {
        $records += New-EvidenceRecord -Source 'Downloads' -Category 'FileArtifact' -Type 'DownloadsFolder' -Name 'FolderAccess' -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message; Path = $downloadsPath}
        return $records
    }

    foreach ($file in $files) {
        $sizeKB = [math]::Round($file.Length / 1KB, 2)

        $rawRecord = New-EvidenceRecord -Source 'Downloads' -Category 'FileArtifact' -Type 'Download' -Name $file.Name -Path $file.FullName -Value $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') -Severity 'Info' -Confidence 'Medium' -Details @{
            FileName     = $file.Name
            Extension    = $file.Extension
            SizeKB       = $sizeKB
            FullPath     = $file.FullName
            CreationTime = $file.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
            LastWrite    = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $records += $rawRecord

        if ($Database) {
            $nameMatches = Test-KnownToolMatch -Database $Database -Value $file.Name
            if ($nameMatches) { foreach ($m in $nameMatches) { if ($m) { $records += $m } } }
            $pathMatches = Test-KnownToolMatch -Database $Database -Value $file.FullName
            if ($pathMatches) { foreach ($m in $pathMatches) { if ($m) { $records += $m } } }
        }
    }

    return $records
}
