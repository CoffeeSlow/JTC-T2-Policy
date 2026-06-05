function Get-RegistryEvidence {
    param(
        [PSCustomObject]$Database
    )

    $records = @()

    $registryPaths = @(
        'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($regPath in $registryPaths) {
        try {
            if (-not (Test-Path $regPath)) { continue }
            $entries = Get-ItemProperty -Path $regPath -ErrorAction Stop
        } catch {
            $records += New-EvidenceRecord -Source 'RegistryScan' -Category 'RegistryArtifact' -Type 'RegistryAccess' -Name $regPath -Value 'Failed' -Severity 'Warning' -Confidence 'High' -Details @{Error = $_.Exception.Message; RegistryPath = $regPath}
            continue
        }

        $props = $entries.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }

        foreach ($prop in $props) {
            $propName = $prop.Name
            $propValue = if ($prop.Value) { $prop.Value.ToString() } else { '' }

            $rawRecord = New-EvidenceRecord -Source 'RegistryScan' -Category 'RegistryArtifact' -Type 'RegistryEntry' -Name $propName -Path $regPath -Value $propValue -Severity 'Info' -Confidence 'Medium' -Details @{
                RegistryPath = $regPath
                PropertyName = $propName
                PropertyValue = $propValue
            }
            $records += $rawRecord

            if ($Database) {
                $nameMatches = Test-KnownToolMatch -Database $Database -Value $propName
                if ($nameMatches) { foreach ($m in $nameMatches) { if ($m) { $records += $m } } }
                if ($propValue) {
                    $valueMatches = Test-KnownToolMatch -Database $Database -Value $propValue
                    if ($valueMatches) { foreach ($m in $valueMatches) { if ($m) { $records += $m } } }
                }
            }
        }
    }

    return $records
}
