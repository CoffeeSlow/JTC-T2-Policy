function Get-HardwareEvidence {
    $records = @()

    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cpu) {
        $records += New-EvidenceRecord -Source 'Hardware' -Category 'SystemInformation' -Type 'CPU' -Name 'CPU Model' -Value "$($cpu.Name)" -Severity 'Info' -Confidence 'High' -Details @{
            Cores           = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
            MaxClockSpeedMHz = $cpu.MaxClockSpeed
        }
    }

    $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
    if ($gpus) {
        $gpuIndex = 1
        foreach ($gpu in $gpus) {
            $gpuLabel = if ($gpus.Count -gt 1) { "GPU Model ($gpuIndex)" } else { "GPU Model" }
            $records += New-EvidenceRecord -Source 'Hardware' -Category 'SystemInformation' -Type 'GPU' -Name $gpuLabel -Value "$($gpu.Name)" -Severity 'Info' -Confidence 'High' -Details @{
                AdapterRAMBytes = $gpu.AdapterRAM
                DriverVersion   = $gpu.DriverVersion
            }
            $gpuIndex++
        }
    }

    try {
        $hvciEnabled = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction Stop
        $hvciValue = if ($hvciEnabled -eq 1) { 'Enabled' } else { 'Disabled' }
        $hvciSeverity = if ($hvciEnabled -eq 1) { 'Info' } else { 'Warning' }
        $records += New-EvidenceRecord -Source 'Hardware' -Category 'SystemSecurity' -Type 'MemoryIntegrity' -Name 'Memory Integrity' -Value $hvciValue -Severity $hvciSeverity -Confidence 'High' -Details @{
            RegistryPath  = 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
            RawValue      = $hvciEnabled
        }
    } catch {
        $records += New-EvidenceRecord -Source 'Hardware' -Category 'SystemSecurity' -Type 'MemoryIntegrity' -Name 'Memory Integrity' -Value 'CheckFailed' -Severity 'Warning' -Confidence 'Medium' -Details @{
            RegistryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
            Error        = $_.Exception.Message
        }
    }

    try {
        $psPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $sig = Get-AuthenticodeSignature $psPath -ErrorAction Stop
        $sigValid = ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft Windows*')
        $sigValue = if ($sigValid) { 'Valid' } else { 'Invalid' }
        $sigSeverity = if ($sigValid) { 'Info' } else { 'Warning' }
        $records += New-EvidenceRecord -Source 'Hardware' -Category 'SystemSecurity' -Type 'PowerShellSignature' -Name 'PowerShell Signature' -Value $sigValue -Severity $sigSeverity -Confidence 'High' -Details @{
            Path           = $psPath
            SignatureStatus = "$($sig.Status)"
            SignerSubject   = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'N/A' }
        }
    } catch {
        $records += New-EvidenceRecord -Source 'Hardware' -Category 'SystemSecurity' -Type 'PowerShellSignature' -Name 'PowerShell Signature' -Value 'CheckFailed' -Severity 'Warning' -Confidence 'Medium' -Details @{
            Path  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            Error = $_.Exception.Message
        }
    }

    return $records
}
