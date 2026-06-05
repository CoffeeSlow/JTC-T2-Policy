function Get-PeripheralEvidence {
    $records = @()

    $peripherals = @(
        @{Name='Razer';      Paths=@('C:\Program Files\Razer\Synapse3\Razer Synapse.exe','C:\Program Files (x86)\Razer\Synapse3\Razer Synapse.exe')}
        @{Name='Corsair';    Paths=@('C:\Program Files (x86)\Corsair\CORSAIR iCUE Software\iCUE.exe','C:\Program Files\Corsair\CORSAIR iCUE 5 Software\iCUE.exe')}
        @{Name='Logitech';   Paths=@('C:\Program Files\Logitech\G HUB\lghub.exe','C:\Program Files\Logitech Gaming Software\LCore.exe')}
        @{Name='SteelSeries';Paths=@('C:\Program Files\SteelSeries\SteelSeries Engine 3\SteelSeriesEngine3.exe','C:\Program Files\SteelSeries\GG\SteelSeriesGG.exe')}
        @{Name='HyperX';     Paths=@('C:\Program Files\HyperX\NGenuity\Ngenuity.exe','C:\Program Files (x86)\HyperX\NGenuity\Ngenuity.exe')}
        @{Name='Glorious';   Paths=@('C:\Program Files\Glorious\Glorious Core\GloriousCore.exe','C:\Program Files (x86)\Glorious\Glorious Core\GloriousCore.exe')}
        @{Name='Finalmouse'; Paths=@('C:\Program Files\Finalmouse\Finalmouse.exe','C:\Program Files (x86)\Finalmouse\Finalmouse.exe')}
        @{Name='Roccat';     Paths=@('C:\Program Files (x86)\ROCCAT\Swarm\ROCCAT_Swarm_Monitor.exe','C:\Program Files\ROCCAT\Swarm\ROCCAT_Swarm_Monitor.exe')}
        @{Name='Redragon';   Paths=@('C:\Program Files\Redragon\RedragonSoftware.exe','C:\Program Files (x86)\Redragon\RedragonSoftware.exe')}
        @{Name='Bloody';     Paths=@('C:\Program Files\Bloody\BloodyGameCenter\BloodyGameCenter.exe','C:\Program Files (x86)\Bloody\BloodyGameCenter\BloodyGameCenter.exe')}
    )

    $usbDevices = Get-PnpDevice -Class 'Keyboard','Mouse','HIDClass' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' }

    foreach ($periph in $peripherals) {
        $deviceDetected = $usbDevices | Where-Object { $_.FriendlyName -like "*$($periph.Name)*" }
        $softwarePath = $null
        foreach ($sw in $periph.Paths) {
            if (Test-Path $sw) { $softwarePath = $sw; break }
        }

        $isDetected = $deviceDetected -or $softwarePath
        if (-not $isDetected) { continue }

        if ($deviceDetected) {
            foreach ($dev in $deviceDetected) {
                $manufacturer = if ($dev.Manufacturer) { $dev.Manufacturer } else { 'Unknown' }
                $className = if ($dev.Class) { $dev.Class } else { 'Unknown' }
                $description = if ($dev.FriendlyName) { $dev.FriendlyName } else { $dev.DeviceID }

                $records += New-EvidenceRecord -Source 'Peripherals' -Category 'HardwareDetection' -Type 'PeripheralDevice' -Name "$($periph.Name) Device" -Value $manufacturer -Severity 'Info' -Confidence 'Medium' -Details @{
                    Brand        = $periph.Name
                    Manufacturer = $manufacturer
                    Class        = $className
                    Description  = $description
                }
            }
        }

        if ($softwarePath) {
            $records += New-EvidenceRecord -Source 'Peripherals' -Category 'HardwareDetection' -Type 'PeripheralSoftware' -Name "$($periph.Name) Software" -Value $periph.Name -Severity 'Info' -Confidence 'Medium' -Details @{
                Brand      = $periph.Name
                InstallPath = $softwarePath
            }
        }
    }

    return $records
}
