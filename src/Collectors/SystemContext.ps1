function Get-SystemContextEvidence {
    $records = @()

    $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "ComputerName" -Name "Computer Name" -Value $env:COMPUTERNAME -Severity "Info" -Confidence "High"

    $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "Username" -Name "Username" -Value $env:USERNAME -Severity "Info" -Confidence "High"

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($os) {
        $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "WindowsVersion" -Name "Windows Version" -Value "$($os.Caption)" -Severity "Info" -Confidence "High" -Details @{Version=$os.Version; BuildNumber=$os.BuildNumber; Architecture=$os.OSArchitecture}

        $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "BuildNumber" -Name "Build Number" -Value "$($os.BuildNumber)" -Severity "Info" -Confidence "High"
    }

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cs) {
        $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "RAM" -Name "Installed RAM" -Value "$ramGB GB" -Severity "Info" -Confidence "High" -Details @{TotalPhysicalMemoryBytes=$cs.TotalPhysicalMemory}
    }

    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cpu) {
        $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "CPU" -Name "CPU Model" -Value "$($cpu.Name)" -Severity "Info" -Confidence "High" -Details @{Cores=$cpu.NumberOfCores; LogicalProcessors=$cpu.NumberOfLogicalProcessors; MaxClockSpeedMHz=$cpu.MaxClockSpeed}
    }

    $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
    if ($gpus) {
        $gpuIndex = 1
        foreach ($gpu in $gpus) {
            $gpuLabel = if ($gpus.Count -gt 1) { "GPU Model ($gpuIndex)" } else { "GPU Model" }
            $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "GPU" -Name $gpuLabel -Value "$($gpu.Name)" -Severity "Info" -Confidence "High" -Details @{AdapterRAMBytes=$gpu.AdapterRAM; DriverVersion=$gpu.DriverVersion}
            $gpuIndex++
        }
    }

    $psVersion = $PSVersionTable.PSVersion.ToString()
    $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "PowerShellVersion" -Name "PowerShell Version" -Value $psVersion -Severity "Info" -Confidence "High" -Details @{PSVersionTable=$PSVersionTable}

    $execPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    $records += New-EvidenceRecord -Source "SystemContext" -Category "SystemInformation" -Type "ExecutionPolicy" -Name "Execution Policy" -Value "$execPolicy" -Severity "Info" -Confidence "High"

    return $records
}
