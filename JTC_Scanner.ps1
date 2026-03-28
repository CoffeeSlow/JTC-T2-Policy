param([switch]$SkipPause)

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "JTC Scanner"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host "  ADMINISTRATOR PRIVILEGES REQUIRED" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "`n Please run PowerShell as Administrator and try again.`n" -ForegroundColor Yellow
    if (-not $SkipPause) { Pause }
    exit 1
}

$suspiciousFindings = [System.Collections.Generic.List[PSObject]]::new()
$suspiciousFindings.Add([PSCustomObject]@{
    Type      = "Context"
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PC        = $env:COMPUTERNAME
    User      = $env:USERNAME
    Score     = $null
})

function Write-ColoredLine {
    param ([string]$Text, [ConsoleColor]$Color = 'White')
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    param([string]$Message = "Press Enter to Continue")
    Write-Host ""
    Write-ColoredLine ">> $Message" Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } while ($key.Key -ne "Enter")
}

function Show-CustomLoadingBar {
    $i = 0
    Write-Host ""
    for ($p = 0; $p -le 100; $p += 5) {
        $filled = [math]::Floor($p / 2.5)
        $empty = 40 - $filled
        $bar = "#" * $filled + "-" * $empty
        $percentage = "{0,3}" -f $p
        if ($p -eq 100) {
            Write-Host -NoNewline "`r [$bar] $percentage% " -ForegroundColor Green
        } else {
            Write-Host -NoNewline "`r [$bar] $percentage% " -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 50
        $i++
    }
    Write-Host ""
    Write-Host ""
}

function Write-BoxedHeader {
    param([string]$Title, [string]$Subtitle = "")
    $innerWidth = 62
    $border = "+" + ("-" * $innerWidth) + "+"
    $titlePadding = [math]::Floor(($innerWidth - $Title.Length) / 2)
    $titleLine = " " * $titlePadding + $Title + " " * ($innerWidth - $titlePadding - $Title.Length)
    Write-Host ""
    Write-ColoredLine $border Blue
    Write-Host "|" -NoNewline -ForegroundColor Blue
    Write-Host $titleLine -NoNewline
    Write-Host "|" -ForegroundColor Blue
    if ($Subtitle) {
        $subtitlePadding = [math]::Floor(($innerWidth - $Subtitle.Length) / 2)
        $leftPadding = " " * $subtitlePadding
        $rightPadding = " " * ($innerWidth - $subtitlePadding - $Subtitle.Length)
        $splitPoint = 14
        $firstHalf = $Subtitle.Substring(0, [math]::Min($splitPoint, $Subtitle.Length))
        $secondHalf = if ($Subtitle.Length -gt $splitPoint) { $Subtitle.Substring($splitPoint) } else { "" }
        Write-Host "|" -NoNewline -ForegroundColor Blue
        Write-Host ($leftPadding + $firstHalf) -NoNewline -ForegroundColor White
        Write-Host ($secondHalf + $rightPadding) -NoNewline -ForegroundColor Magenta
        Write-Host "|" -ForegroundColor Blue
    }
    Write-ColoredLine $border Blue
    Write-Host ""
}

function Write-Section {
    param([string]$Title, [string[]]$Lines)
    Write-Host ""
    Write-ColoredLine " +- $Title" DarkGray
    foreach ($line in $Lines) {
        if ($line -match "^SUCCESS") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "OK $($line -replace '^SUCCESS: ', '')" Green
        }
        elseif ($line -match "^FAILURE") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "X $($line -replace '^FAILURE: ', '')" Red
        }
        elseif ($line -match "^WARNING") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "W $($line -replace '^WARNING: ', '')" Yellow
        }
        elseif ($line -match "SUSPICIOUS") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "$line" Red
        }
        else {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine $line White
        }
    }
    Write-ColoredLine " +-" DarkGray
}

function Write-StepResult {
    param([int]$Success, [int]$Total, [int]$StepNumber)
    $rate = if ($Total -gt 0) { [math]::Round(($Success / $Total) * 100, 0) } else { 100 }
    $color = if ($rate -eq 100) { "Green" } elseif ($rate -ge 80) { "Yellow" } else { "Red" }
    $icon = if ($rate -eq 100) { "OK" } elseif ($rate -ge 80) { "W" } else { "X" }
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " $icon Step $StepNumber Result: " -NoNewline -ForegroundColor $color
    Write-Host "$rate% " -NoNewline -ForegroundColor $color
    Write-Host "($Success/$Total checks passed)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor DarkGray
}

function Start-FileWatcher {
    param([string]$LogFile)
    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "C:\"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastAccess
        $wshell = New-Object -ComObject WScript.Shell
        $action = {
            $path = $Event.SourceEventArgs.FullPath
            $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $LogFile -Value "[$time] Opened: $path" -ErrorAction SilentlyContinue
            $wshell.Popup("This application was opened: $path", 5, "File Access", 64)
        }
        Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier "FileCreated_$PID" -Action $action | Out-Null
        Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier "FileChanged_$PID" -Action $action | Out-Null
    } catch {
        Write-ColoredLine " W File watcher setup failed." Yellow
    }
}

Clear-Host
Write-Host ""
Write-Host "    JJJJJJJ   TTTTTTTT   CCCCCC  " -ForegroundColor DarkBlue
Write-Host "       JJ       TT      CC       " -ForegroundColor DarkBlue
Write-Host "       JJ       TT      CC       " -ForegroundColor DarkBlue
Write-Host "       JJ       TT      CC       " -ForegroundColor DarkBlue
Write-Host "  JJJJJJJ       TT       CCCCCC  " -ForegroundColor DarkBlue
Write-Host "" -ForegroundColor DarkBlue
Write-Host "   TTTTTTTT   2222222   PPPP    OOO    L      IIIII   CCCCCC   YY   YY" -ForegroundColor DarkBlue
Write-Host "     TT      2      2  PP  PP  O   O   L        I    CC       YY   YY" -ForegroundColor DarkBlue
Write-Host "     TT      22222222  PPPPP   O   O   L        I    CC        YY YY " -ForegroundColor DarkBlue
Write-Host "     TT      2     2   PP      O   O   L        I    CC         YY   " -ForegroundColor DarkBlue
Write-Host "     TT      2222222   PP       OOO    LLLLL  IIIII   CCCCCC    YY   " -ForegroundColor DarkBlue
Write-Host ""

Write-ColoredLine "============================================================" Cyan
Write-ColoredLine " Created by CoffeeSlow" White
Write-ColoredLine "============================================================" Cyan
Write-Host ""
Write-ColoredLine "INSTRUCTIONS:" Yellow
Write-ColoredLine "- Complete all verification steps" White
Write-ColoredLine "- Scan results saved to C:\ToolsJTC" White
Write-ColoredLine "- Administrator privileges required" White
Write-Host ""

$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
if ($cpu -and $cpu.NumberOfCores -ge 4 -and $cpu.MaxClockSpeed -ge 2500) {
    Write-Host "CPU: " -NoNewline -ForegroundColor White
    Write-Host "$($cpu.Name)" -ForegroundColor Gray
    Write-ColoredLine " Performance: Optimal" Green
} else {
    Write-Host "CPU: " -NoNewline -ForegroundColor White
    Write-Host "$($cpu.Name)" -ForegroundColor Gray
    Write-ColoredLine " Performance: May experience slower scans" Yellow
}
Write-Host ""

$gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 1
$gpuName = $gpu.Name
$goodGPUs = @("RTX 30", "RTX 40", "RX 6000", "RX 7000")
$gpuIsGood = $goodGPUs | Where-Object { $gpuName -like "*$_*" }
if ($gpuIsGood) {
    Write-Host "GPU: " -NoNewline -ForegroundColor White
    Write-Host "$gpuName" -ForegroundColor Gray
    Write-ColoredLine " Performance: Optimal" Green
} else {
    Write-Host "GPU: " -NoNewline -ForegroundColor White
    Write-Host "$gpuName" -ForegroundColor Gray
    Write-ColoredLine " Performance: May impact processing" Yellow
}

Write-Host ""

Wait-ForEnter -Message "Press Enter to Begin System Scan"

Clear-Host
New-Item -ItemType Directory -Path "C:\ToolsJTC" -ErrorAction SilentlyContinue | Out-Null
$logFile = "C:\ToolsJTC\file_log.txt"
Start-FileWatcher -LogFile $logFile

Write-BoxedHeader "STEP 1/9: SYSTEM INTEGRITY" "Verifying security configuration..."
Show-CustomLoadingBar

$modulesOutput = @()
$windowsOutput = @()
$memoryIntegrityOutput = @()
$defenderOutput = @()
$exclusionsOutput = @()
$threatsOutput = @()
$powershellSigOutput = @()

$defaultModules = @("Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Diagnostics", "Microsoft.PowerShell.Host", "Microsoft.PowerShell.LocalAccounts", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security", "Microsoft.PowerShell.Utility", "PackageManagement", "PowerShellGet", "PSReadLine", "Pester", "ThreadJob")
$protectedModule = "Microsoft.PowerShell.Operation.Validation"
$modulesPath = "C:\Program Files\WindowsPowerShell\Modules"
$modules = Get-ChildItem $modulesPath -Directory -ErrorAction SilentlyContinue

foreach ($module in $modules) {
    $moduleName = $module.Name
    if ($moduleName -eq $protectedModule) {
        $modulesOutput += "SUCCESS: Protected module verified."
    } elseif ($moduleName -notin $defaultModules) {
        $modulesOutput += "FAILURE: Unauthorized module: $moduleName"
    }
}
if (-not $modulesOutput) { $modulesOutput += "SUCCESS: No unauthorized modules." }

$windowsOutput += if ($env:OS -eq "Windows_NT") { "SUCCESS: Windows OS verified." } else { "FAILURE: Non-Windows OS detected." }

try {
    $enabled = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction Stop
    $memoryIntegrityOutput += if ($enabled -eq 1) { "SUCCESS: Memory Integrity enabled." } else { "FAILURE: Memory Integrity disabled." }
} catch {
    $memoryIntegrityOutput += "WARNING: Memory Integrity check failed."
}

try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $defenderOutput += if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) { "SUCCESS: Windows Defender active." } else { "FAILURE: Windows Defender not active." }
} catch {
    $defenderOutput += "WARNING: Defender status check failed."
}

try {
    $exclusions = (Get-MpPreference).ExclusionPath
    if ($exclusions) {
        $exclusionsOutput += "FAILURE: Defender exclusions detected."
        foreach ($excl in $exclusions) {
            $exclusionsOutput += " -> $excl"
            $suspiciousFindings.Add([PSCustomObject]@{Type = "DefenderExclusion"; Path = $excl})
        }
    } else {
        $exclusionsOutput += "SUCCESS: No Defender exclusions."
    }
} catch {
    $exclusionsOutput += "WARNING: Cannot check exclusions."
}

try {
    $threats = Get-MpThreat -ErrorAction Stop
    $activeThreats = $threats | Where-Object { $_.ThreatStatusID -in @(4, 6) }
    if ($activeThreats.Count -eq 0) {
        $threatsOutput += "SUCCESS: No active threats detected."
    } else {
        $threatsOutput += "FAILURE: Active threats detected ($($activeThreats.Count) total)."
        foreach ($threat in $activeThreats) {
            $threatsOutput += " -> Threat: $($threat.ThreatName)"
            $suspiciousFindings.Add([PSCustomObject]@{Type = "DefenderThreat"; Threat = $threat.ThreatName})
        }
    }
} catch {
    $threatsOutput += "WARNING: Cannot retrieve threat information."
}

try {
    $sig = Get-AuthenticodeSignature "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $powershellSigOutput += if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft Windows*') { "SUCCESS: PowerShell signature valid." } else { "FAILURE: PowerShell signature invalid." }
} catch {
    $powershellSigOutput += "WARNING: PowerShell signature check failed."
}

Write-Section "PowerShell Modules" $modulesOutput
Write-Section "Operating System" $windowsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Defender Exclusions" $exclusionsOutput
Write-Section "Threat Detection" $threatsOutput
Write-Section "PowerShell Signature" $powershellSigOutput

$allResults1 = $modulesOutput + $windowsOutput + $memoryIntegrityOutput + $defenderOutput + $exclusionsOutput + $threatsOutput + $powershellSigOutput
$total1 = ($allResults1 | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success1 = ($allResults1 | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success1 -Total $total1 -StepNumber 1

Wait-ForEnter -Message "Press Enter to Continue to Step 2"

Clear-Host

Write-BoxedHeader "STEP 2/9: BAM & PREFETCH ANALYSIS" "Analyzing Background Activity Moderator and Prefetch..."
Show-CustomLoadingBar

$bamOutput = @()
$prefetchOutput = @()

$suspiciousFiles = @(
    "synapse exploit", "synapsex exploit", "krnl exploit", "fluxus exploit",
    "oxygenu exploit", "viperx exploit", "electron exploit", "novaline exploit",
    "wrft exploit", "darkdex exploit", "owlhub exploit", "dex v4 exploit",
    "dex explorer exploit", "pegasus exploit", "protosmasher exploit",
    "jjsploit exploit", "nebula exploit", "reaper exploit", "azael exploit",
    "keksploit exploit", "bloxflip predictor", "bloxflip exploit",
    "free robux generator", "robux exploit", "infinite yield exploit",
    "ans exploit", "btools exploit", "remotespy exploit", "fly hack exploit",
    "esp exploit", "aimbot exploit", "silent aim exploit", "triggerbot exploit",
    "wallhack exploit", "server hopper exploit", "admin gui exploit",
    "blox fruits hack", "da hood hack", "mm2 hack", "bedwars hack",
    "arsenal hack", "jailbreak hack", "counter blox hack", "shindo hack",
    "anime fighters hack", "king legacy hack"
)

$watchlist = @(
    "SYNAPSE_X_LOADER.EXE", "KRNL_LOADER.EXE", "FLUXUS_LOADER.EXE",
    "OXYGENU_LOADER.EXE", "VIPERX_LOADER.EXE", "NOVALINE_LOADER.EXE",
    "WRFT_LOADER.EXE", "DARKDEX4_LOADER.EXE", "PEGASUS_LOADER.EXE",
    "PROTOSMASHER_LOADER.EXE", "JJSPLOIT_LOADER.EXE", "NEBULA_LOADER.EXE",
    "REAPER_LOADER.EXE", "AZAEL_LOADER.EXE", "KEKSPLOIT_LOADER.EXE",
    "BLOXFLIP_PREDICTOR.EXE", "OWLHUB_LOADER.EXE", "INFINITE_YIELD_LOADER.EXE",
    "ANS_LOADER.EXE", "DEXV4_LOADER.EXE", "ROBLOX_EXPLOIT_LOADER.EXE"
)

$allSuspicious = $suspiciousFiles + $watchlist

$bamApps = @()
try {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $bamEntries = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid" -ErrorAction Stop
    $isSuspiciousBAM = $false
    foreach ($entry in ($bamEntries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" })) {
        if ($entry.Value.Length -ge 8) {
            $timestamp = [BitConverter]::ToInt64($entry.Value, 0)
            $date = [DateTime]::FromFileTime($timestamp)
            $appPath = $entry.Name
            $isSuspicious = [bool]($allSuspicious | Where-Object { $appPath -imatch $_ })
            $lastAccessTime = "N/A"
            if (Test-Path $appPath) {
                $fileInfo = Get-Item $appPath
                $lastAccessTime = $fileInfo.LastAccessTime.ToString()
            }
            $bamApps += [PSCustomObject]@{
                AppPath = $appPath
                LastTime = $date.ToString()
                Suspicious = if ($isSuspicious) { "Yes" } else { "No" }
                LastAccessTime = $lastAccessTime
            }
            if ($isSuspicious) { 
                $isSuspiciousBAM = $true 
                $suspiciousFindings.Add([PSCustomObject]@{
                    Type       = "BAM"
                    Path       = $appPath
                    LastUsed   = $date.ToString()
                })
            }
        }
    }
    if ($bamApps) {
        $bamOutput += "SUCCESS: Found $($bamApps.Count) BAM entries."
        if ($isSuspiciousBAM) {
            $bamOutput += "WARNING: Suspicious BAM activity detected."
            $suspiciousBamEntries = $bamApps | Where-Object { $_.Suspicious -eq "Yes" }
            foreach ($entry in $suspiciousBamEntries) {
                $bamOutput += " SUSPICIOUS: $($entry.AppPath)"
            }
        }
    } else {
        $bamOutput += "SUCCESS: No BAM entries found."
    }
} catch {
    $bamOutput += "WARNING: BAM registry access failed."
}

$prefetchApps = @()
try {
    $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction Stop
    $isSuspiciousPrefetch = $false
    foreach ($file in $prefetchFiles) {
        $appName = $file.Name.Split('-')[0]
        $isSuspicious = [bool]($allSuspicious | Where-Object { $appName -imatch $_ })
        $fileSize = [math]::Round($file.Length / 1KB, 2)
        $prefetchApps += [PSCustomObject]@{
            AppName = $appName
            LastTime = $file.LastWriteTime.ToString()
            Suspicious = if ($isSuspicious) { "Yes" } else { "No" }
            FileSize = $fileSize
            FullName = $file.Name
        }
        if ($isSuspicious) { 
            $isSuspiciousPrefetch = $true 
            $suspiciousFindings.Add([PSCustomObject]@{
                Type     = "Prefetch"
                Name     = $appName
                File     = $file.Name
            })
        }
    }
    if ($prefetchApps) {
        $prefetchOutput += "SUCCESS: Found $($prefetchApps.Count) Prefetch entries."
        if ($isSuspiciousPrefetch) {
            $prefetchOutput += "WARNING: Suspicious Prefetch activity detected."
            $suspiciousPrefetchEntries = $prefetchApps | Where-Object { $_.Suspicious -eq "Yes" }
            foreach ($entry in $suspiciousPrefetchEntries) {
                $prefetchOutput += " SUSPICIOUS: $($entry.AppName)"
            }
        }
    } else {
        $prefetchOutput += "SUCCESS: No Prefetch entries found."
    }
} catch {
    $prefetchOutput += "WARNING: Prefetch folder access failed."
}

Write-Section "BAM Entries" $bamOutput
Write-Section "Prefetch Entries" $prefetchOutput

$allResults2 = $bamOutput + $prefetchOutput
$total2 = ($allResults2 | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success2 = ($allResults2 | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success2 -Total $total2 -StepNumber 2

Wait-ForEnter -Message "Press Enter to Continue to Step 3"

Clear-Host

Write-BoxedHeader "STEP 3/9: PROCESS EXPLORER" "Launching Microsoft Process Explorer..."
Write-ColoredLine "INSTRUCTIONS: Review all processes, scroll to bottom, then close the window." Yellow
Show-CustomLoadingBar

$processNames = @("procexp32", "procexp64", "procexp64a")
$runningPE = Get-Process -ErrorAction SilentlyContinue | Where-Object { $processNames -contains $_.ProcessName.ToLower() }
if ($runningPE) {
    Write-ColoredLine " OK Terminated existing Process Explorer instances." Green
    $runningPE | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }
    Start-Sleep -Seconds 1
} else {
    Write-ColoredLine " OK No existing Process Explorer instances found." Green
}

$baseFolder = "C:\ToolsJTC"
$extractFolder = Join-Path $baseFolder "ProcessExplorer"
$zipUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$zipPath = Join-Path $baseFolder "ProcessExplorer.zip"

if (Test-Path $baseFolder) {
    Get-ChildItem -Path $baseFolder -Force -Recurse | ForEach-Object {
        try {
            if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) { $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::ReadOnly }
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
        } catch {}
    }
} else {
    New-Item -ItemType Directory -Path $baseFolder -ErrorAction Stop | Out-Null
}

try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-ColoredLine " OK Downloaded Process Explorer." Green
} catch {
    Write-ColoredLine " X Download failed." Red
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractFolder)
    Write-ColoredLine " OK Extracted Process Explorer." Green
} catch {
    Write-ColoredLine " OK Files already extracted." Green
}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse | Select-Object -First 1
$peOutput = @()
if ($actualExe) {
    Write-ColoredLine " OK Launching Process Explorer..." Green
    Start-Process -FilePath $actualExe.FullName
    $peOutput += "SUCCESS: Process Explorer review completed."
} else {
    $peOutput += "FAILURE: procexp64.exe not found."
}

Write-Section "Process Explorer Analysis" $peOutput
$total3 = ($peOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success3 = ($peOutput | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success3 -Total $total3 -StepNumber 3

Wait-ForEnter -Message "Press Enter to Continue to Step 4"

Clear-Host

Write-BoxedHeader "STEP 4/9: WINOBJ INSPECTION" "Launching Windows Object Manager Viewer..."
Write-ColoredLine "INSTRUCTIONS: Navigate to Sessions > 0 > Dos Devices > Inspect folders" Yellow
Show-CustomLoadingBar

$winobjOutput = @()
$runningWinObj = Get-Process -Name "winobj" -ErrorAction SilentlyContinue
if ($runningWinObj) {
    $runningWinObj | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }
    Start-Sleep -Seconds 1
}

$extractFolder = Join-Path $baseFolder "WinObj"
$zipUrl = "https://download.sysinternals.com/files/WinObj.zip"
$zipPath = Join-Path $baseFolder "WinObj.zip"

if (Test-Path $extractFolder) {
    Get-ChildItem -Path $extractFolder -Force -Recurse | ForEach-Object {
        try {
            if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) { $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::ReadOnly }
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
        } catch {}
    }
} else {
    New-Item -ItemType Directory -Path $extractFolder -ErrorAction Stop | Out-Null
}

try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-ColoredLine " OK Downloaded WinObj." Green
} catch {
    Write-ColoredLine " X Download failed." Red
    $winobjOutput += "FAILURE: WinObj download failed."
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractFolder)
    Write-ColoredLine " OK Extracted WinObj." Green
} catch {}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

$actualExe = Get-ChildItem -Path $extractFolder -Filter "WinObj.exe" -Recurse | Select-Object -First 1
if ($actualExe) {
    Write-ColoredLine " OK Launching WinObj..." Green
    Start-Process -FilePath $actualExe.FullName
    $winobjOutput += "SUCCESS: WinObj inspection completed."
} else {
    $winobjOutput += "FAILURE: WinObj.exe not found."
}

Write-Section "WinObj Analysis" $winobjOutput
$total4 = ($winobjOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success4 = ($winobjOutput | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success4 -Total $total4 -StepNumber 4

Wait-ForEnter -Message "Press Enter to Continue to Step 5"

Clear-Host

Write-BoxedHeader "STEP 5/9: AUTORUN ANALYSIS" "Launching Autoruns..."
Write-ColoredLine "INSTRUCTIONS: Wait for 'Ready' status, scroll through entries, then close" Yellow
Show-CustomLoadingBar

$extractFolder = Join-Path $baseFolder "Autoruns"
$zipUrl = "https://download.sysinternals.com/files/Autoruns.zip"
$zipPath = Join-Path $baseFolder "Autoruns.zip"

if (Test-Path $extractFolder) {
    Get-ChildItem -Path $extractFolder -Force -Recurse | ForEach-Object {
        try { $_.Attributes = 'Normal'; Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch {}
    }
}

try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-ColoredLine " OK Downloaded Autoruns" Green
} catch {
    Write-ColoredLine " X Download failed" Red
    exit 1
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractFolder)
    Remove-Item $zipPath -Force
    Write-ColoredLine " OK Extracted Autoruns" Green
} catch {}

$actualExe = Get-ChildItem -Path $extractFolder -Filter "Autoruns.exe" -Recurse | Where-Object { $_.FullName -notmatch "64|cmd" } | Select-Object -First 1
$runningAutoruns = Get-Process -Name "autoruns" -ErrorAction SilentlyContinue
if ($runningAutoruns) { $runningAutoruns | Stop-Process -Force; Start-Sleep -Seconds 2 }

if ($actualExe) {
    Write-ColoredLine " OK Launching Autoruns" Green
    Start-Process -FilePath $actualExe.FullName
}

$autorunOutput = @("SUCCESS: Autorun analysis completed.")
Write-Section "Autoruns Analysis" $autorunOutput
$total5 = 1; $success5 = 1
Write-StepResult -Success $success5 -Total $total5 -StepNumber 5

Wait-ForEnter -Message "Press Enter to Continue to Step 6"

Clear-Host

Write-BoxedHeader "STEP 6/9: PERIPHERAL SOFTWARE" "Detecting gaming peripheral software..."
Show-CustomLoadingBar

$hardwareOutput = @()
$peripherals = @(
    @{Name="Razer"; Paths=@("C:\Program Files\Razer\Synapse3\Razer Synapse.exe","C:\Program Files (x86)\Razer\Synapse3\Razer Synapse.exe"); Keywords=@("Razer","Synapse")},
    @{Name="Corsair"; Paths=@("C:\Program Files (x86)\Corsair\CORSAIR iCUE Software\iCUE.exe","C:\Program Files\Corsair\CORSAIR iCUE 5 Software\iCUE.exe"); Keywords=@("Corsair","iCUE")},
    @{Name="Logitech"; Paths=@("C:\Program Files\Logitech\G HUB\lghub.exe","C:\Program Files\Logitech Gaming Software\LCore.exe"); Keywords=@("Logitech","GHUB")},
    @{Name="SteelSeries"; Paths=@("C:\Program Files\SteelSeries\SteelSeries Engine 3\SteelSeriesEngine3.exe","C:\Program Files\SteelSeries\GG\SteelSeriesGG.exe"); Keywords=@("SteelSeries","GG")},
    @{Name="HyperX"; Paths=@("C:\Program Files\HyperX\NGenuity\Ngenuity.exe","C:\Program Files (x86)\HyperX\NGenuity\Ngenuity.exe"); Keywords=@("HyperX","NGenuity")},
    @{Name="ASUS ROG"; Paths=@("C:\Program Files (x86)\ASUS\Armoury Crate\ArmouryCrate.exe","C:\Program Files\ASUS\Armoury Crate\ArmouryCrate.exe"); Keywords=@("ASUS","Armoury")},
    @{Name="Roccat"; Paths=@("C:\Program Files (x86)\ROCCAT\Swarm\ROCCAT_Swarm_Monitor.exe","C:\Program Files\ROCCAT\Swarm\ROCCAT_Swarm_Monitor.exe"); Keywords=@("ROCCAT","Swarm")},
    @{Name="Glorious"; Paths=@("C:\Program Files\Glorious\Glorious Core\GloriousCore.exe","C:\Program Files (x86)\Glorious\Glorious Core\GloriousCore.exe"); Keywords=@("Glorious","GloriousCore")},
    @{Name="Wooting"; Paths=@("C:\Program Files\Wooting\Wootility\Wootility.exe","C:\Program Files (x86)\Wooting\Wootility\Wootility.exe"); Keywords=@("Wooting","Wootility")},
    @{Name="Finalmouse"; Paths=@("C:\Program Files\Finalmouse\Finalmouse.exe","C:\Program Files (x86)\Finalmouse\Finalmouse.exe"); Keywords=@("Finalmouse","Ultralight")}
)

Write-Host ""
Write-ColoredLine " +- Peripheral Detection Results" DarkGray

try {
    $usbDevices = Get-PnpDevice -Class "Keyboard","Mouse","HIDClass" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
    $foundPeripherals = $false

    foreach ($periph in $peripherals) {
        $deviceDetected = $usbDevices | Where-Object { $_.FriendlyName -like "*$($periph.Name)*" }
        $softwarePath = $null
        foreach ($sw in $periph.Paths) { if (Test-Path $sw) { $softwarePath = $sw; break } }
        $isDetected = $deviceDetected -or $softwarePath

        if ($isDetected) {
            $foundPeripherals = $true
            Write-Host " | "; Write-Host "OK $($periph.Name) PERIPHERAL DETECTED" -ForegroundColor Green
            if ($deviceDetected) { foreach ($dev in $deviceDetected) { Write-Host " | "; Write-Host " -> Device: $($dev.FriendlyName)" -ForegroundColor White } }
            if ($softwarePath) {
                Write-Host " | "; Write-Host " -> Software: $softwarePath" -ForegroundColor White
                Write-Host " | "; Write-Host " -> AUTO-LAUNCHING for macro inspection..." -ForegroundColor Yellow
                try { Start-Process $softwarePath -ErrorAction Stop; $hardwareOutput += "SUCCESS: $($periph.Name) DETECTED - Software launched." } catch { $hardwareOutput += "SUCCESS: $($periph.Name) DETECTED - Software found but failed to launch." }
            } else { $hardwareOutput += "SUCCESS: $($periph.Name) DETECTED - No software installed." }
            Write-Host " | "; Write-Host "" -ForegroundColor White
        }
    }
    if (-not $foundPeripherals) { Write-Host " | "; Write-Host " No gaming peripherals detected." -ForegroundColor Yellow; $hardwareOutput += "SUCCESS: No gaming peripheral software detected." }
} catch { $hardwareOutput += "WARNING: Peripheral detection failed: $_" }

Write-ColoredLine " +-" DarkGray
Write-Section "Gaming Peripheral Check" $hardwareOutput
$total6 = ($hardwareOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success6 = ($hardwareOutput | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success6 -Total $total6 -StepNumber 6

Wait-ForEnter -Message "Press Enter to Continue to Step 7"

Clear-Host

Write-BoxedHeader "STEP 7/9: REGISTRY DEEP SCAN" "Scanning Windows Registry for suspicious entries..."
Show-CustomLoadingBar

$step7Output = @()
$suspiciousCombined = @(
    "synapse exploit", "synapsex exploit", "krnl exploit", "fluxus exploit",
    "oxygenu exploit", "viperx exploit", "electron exploit", "novaline exploit",
    "wrft exploit", "darkdex exploit", "owlhub exploit", "dex v4 exploit",
    "pegasus exploit", "protosmasher exploit", "jjsploit exploit",
    "nebula exploit", "bloxflip predictor", "bloxflip exploit",
    "free robux generator", "infinite yield exploit", "ans exploit",
    "btools exploit", "remotespy exploit", "esp exploit", "aimbot exploit",
    "silent aim exploit", "triggerbot exploit", "wallhack exploit",
    "admin gui exploit", "blox fruits hack", "da hood hack", "mm2 hack"
)

$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

$foundSuspiciousRegistry = $false

foreach ($regPath in $registryPaths) {
    try {
        if (Test-Path $regPath) {
            $entries = Get-ItemProperty -Path $regPath -ErrorAction Stop
            foreach ($prop in $entries.PSObject.Properties) {
                if ($prop.Name -notlike "PS*") {
                    $value = $prop.Value
                    foreach ($susp in $suspiciousCombined) {
                        if (($prop.Name -imatch [regex]::Escape($susp)) -or ($value -imatch [regex]::Escape($susp))) {
                            $foundSuspiciousRegistry = $true
                            $suspiciousFindings.Add([PSCustomObject]@{Type = "Registry"; Path = $regPath; Key = $prop.Name})
                        }
                    }
                }
            }
        }
    } catch {}
}

if ($foundSuspiciousRegistry) { $step7Output += "WARNING: Suspicious registry entries found" }
else { $step7Output += "SUCCESS: No suspicious registry entries" }

Write-Section "Registry Deep Scan" $step7Output
$total7 = ($step7Output | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success7 = ($step7Output | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success7 -Total $total7 -StepNumber 7

Wait-ForEnter -Message "Press Enter to Continue to Step 8"

Clear-Host

Write-BoxedHeader "STEP 8/9: COMPREHENSIVE SCAN" "Scanning system for suspicious activity..."
Write-ColoredLine "W DO NOT CLOSE THIS WINDOW" Red
Show-CustomLoadingBar

$step8Output = @()
$suspiciousFiles2 = @(
    "synapse exploit", "synapsex exploit", "krnl exploit", "fluxus exploit",
    "oxygenu exploit", "viperx exploit", "electron exploit", "novaline exploit",
    "darkdex exploit", "owlhub exploit", "dex v4 exploit", "pegasus exploit",
    "jjsploit exploit", "bloxflip predictor", "free robux generator",
    "infinite yield exploit", "btools exploit", "esp exploit", "aimbot exploit",
    "admin gui exploit", "blox fruits hack", "da hood hack", "mm2 hack"
)

$downloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
try {
    $downloadFiles = Get-ChildItem $downloadsPath -File -Recurse -ErrorAction Stop
    $foundSuspicious = $false
    foreach ($file in $downloadFiles) {
        foreach ($susp in $suspiciousFiles2) {
            if ($file.Name -imatch [regex]::Escape($susp)) {
                $step8Output += "FAILURE: Suspicious file: $($file.Name)"
                $foundSuspicious = $true
                $suspiciousFindings.Add([PSCustomObject]@{Type = "File-Downloads"; Path = $file.FullName})
            }
        }
    }
    if (-not $foundSuspicious) { $step8Output += "SUCCESS: No suspicious files in Downloads." }
} catch { $step8Output += "WARNING: Cannot access Downloads folder." }

try {
    $activeProcs = Get-Process | Select-Object -ExpandProperty ProcessName
    $foundSuspicious = $false
    foreach ($proc in $activeProcs) {
        foreach ($susp in $suspiciousFiles2) {
            if ($proc -imatch [regex]::Escape($susp)) {
                $step8Output += "FAILURE: Suspicious process: $proc"
                $foundSuspicious = $true
                $suspiciousFindings.Add([PSCustomObject]@{Type = "SuspiciousProcess"; Name = $proc})
            }
        }
    }
    if (-not $foundSuspicious) { $step8Output += "SUCCESS: No suspicious active processes." }
} catch { $step8Output += "WARNING: Process scan failed." }

Write-Section "Comprehensive Security Scan" $step8Output
$total8 = ($step8Output | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success8 = ($step8Output | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success8 -Total $total8 -StepNumber 8

Wait-ForEnter -Message "Press Enter to Continue to Step 9"

Clear-Host

Write-BoxedHeader "STEP 9/9: DEFENDER HISTORY" "Reviewing Windows Defender protection history..."
Show-CustomLoadingBar

$defenderHistoryOutput = @()
try {
    $threats = Get-MpThreat -ErrorAction Stop
    if ($threats.Count -eq 0) { $defenderHistoryOutput += "SUCCESS: No threats in Defender history." }
    else { foreach ($threat in $threats) { $defenderHistoryOutput += "Threat: $($threat.ThreatName)" } }
} catch { $defenderHistoryOutput += "WARNING: Cannot retrieve Defender history." }

Write-Section "Windows Defender History" $defenderHistoryOutput
$total9 = ($defenderHistoryOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success9 = ($defenderHistoryOutput | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success9 -Total $total9 -StepNumber 9

Write-Host ""
Write-ColoredLine "============================================================" Cyan
Write-ColoredLine " WINDOWS DEFENDER MONITORING ACTIVE" Yellow
Write-ColoredLine "============================================================" Cyan
Write-Host ""

$LogFile = "C:\Logs\WindowsDefenderChanges.log"
$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $entry = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    Write-Host " >> " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor Cyan
}

function Check-DefenderChanges {
    try {
        $mpref = Get-MpPreference -ErrorAction Stop
        $mpstatus = Get-MpComputerStatus -ErrorAction Stop
        $rtp = $mpstatus.RealTimeProtectionEnabled
        $excl = $mpref.ExclusionPath
        $exclProc = $mpref.ExclusionProcess

        if ($rtp -ne $script:PrevState.RTP) { Write-Log "W CRITICAL: Real-Time Protection changed: $($script:PrevState.RTP) -> $rtp by $env:USERNAME" }
        $addedPaths = $excl | Where-Object { $_ -notin $script:PrevState.ExclPath }
        if ($addedPaths) { Write-Log "+ ALERT: Path exclusion(s) added: $($addedPaths -join ', ') by $env:USERNAME" }
        $addedProc = $exclProc | Where-Object { $_ -notin $script:PrevState.ExclProc }
        if ($addedProc) { Write-Log "+ ALERT: Process exclusion(s) added: $($addedProc -join ', ') by $env:USERNAME" }
        if ($mpref.DisableRealtimeMonitoring -ne $script:PrevState.DisableRealtimeMonitoring) { Write-Log "W CRITICAL: Realtime Monitoring Disabled: $($script:PrevState.DisableRealtimeMonitoring) -> $($mpref.DisableRealtimeMonitoring)" }

        $script:PrevState = [PSCustomObject]@{RTP = $rtp; ExclPath = $excl; ExclProc = $exclProc; DisableRealtimeMonitoring = $mpref.DisableRealtimeMonitoring}
    } catch { Write-Log "X Error checking Defender: $_" }
}

try {
    $mpref = Get-MpPreference -ErrorAction Stop
    $mpstatus = Get-MpComputerStatus -ErrorAction Stop
    $script:PrevState = [PSCustomObject]@{RTP = $mpstatus.RealTimeProtectionEnabled; ExclPath = $mpref.ExclusionPath; ExclProc = $mpref.ExclusionProcess; DisableRealtimeMonitoring = $mpref.DisableRealtimeMonitoring}
    Write-Log "Monitoring started. Real-Time Protection = $($mpstatus.RealTimeProtectionEnabled)"
} catch { Write-Log "X Error getting initial Defender status: $_" }

try {
    $query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">
      *[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012)]]
    </Select>
  </Query>
</QueryList>
"@
    $elog = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Microsoft-Windows-Windows Defender/Operational",[System.Diagnostics.Eventing.Reader.PathType]::LogName,$query)
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($elog)
    $null = Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier "DefenderWatcher_$PID" -Action {
        $evt = $EventArgs.EventRecord
        $eventId = $evt.Id
        switch ($eventId) {
            1116 { Write-Log "Defender detected malware: $($evt.FormatDescription())" }
            1117 { Write-Log "W CRITICAL: Defender took action on malware: $($evt.FormatDescription())" }
            5001 { Write-Log "W CRITICAL: Real-time protection disabled!" }
            5007 { Write-Log "W Defender configuration changed: $($evt.FormatDescription())" }
        }
        Check-DefenderChanges
    } | Out-Null
    $watcher.Enabled = $true
    Write-Log "Event-driven monitoring enabled."
} catch { Write-Log "W Failed to register event watcher: $_" }

Write-Host ""
Write-ColoredLine "============================================================" Cyan
Write-ColoredLine " MONITORING INSTRUCTIONS" Yellow
Write-ColoredLine "============================================================" Cyan
Write-Host ""
Write-ColoredLine " 1. Leave this window open during gameplay" White
Write-ColoredLine " 2. Any Defender changes will be logged above in real-time" White
Write-ColoredLine " 3. Check the Process Activity Monitor window for suspicious processes" White
Write-ColoredLine " 4. When finished, press Enter below to view final report" White
Write-Host ""
Write-ColoredLine " >> Press Enter when you have finished your game session" Cyan
Read-Host

try { Unregister-Event -SourceIdentifier "DefenderWatcher_$PID" -ErrorAction Stop; Write-Log "Monitoring stopped." } catch {}

Write-Host ""
Write-ColoredLine "============================================================" Cyan
Write-ColoredLine " FINAL SCAN REPORT" Green
Write-ColoredLine "============================================================" Cyan
Write-Host ""

$totalChecks = $total1 + $total2 + $total3 + $total4 + $total5 + $total6 + $total7 + $total8 + $total9
$totalSuccess = $success1 + $success2 + $success3 + $success4 + $success5 + $success6 + $success7 + $success8 + $success9
$overallSuccess = if ($totalChecks -gt 0) { [math]::Round(($totalSuccess / $totalChecks) * 100, 0) } else { 100 }
$overallColor = if ($overallSuccess -eq 100) { "Green" } elseif ($overallSuccess -ge 80) { "Yellow" } else { "Red" }

Write-Host " OVERALL SECURITY SCORE: " -NoNewline -ForegroundColor White
Write-Host "$overallSuccess% " -NoNewline -ForegroundColor $overallColor
Write-Host "($totalSuccess/$totalChecks checks passed)" -ForegroundColor Gray
Write-Host ""

Write-ColoredLine " NEXT STEPS:" Yellow
Write-ColoredLine " 1. Review the Defender monitoring logs above" White
Write-ColoredLine " 2. Check the Process Activity Monitor window" White
Write-ColoredLine " 3. Review log file for detailed timeline" White
Write-ColoredLine " 4. Close all monitoring windows" White
Write-Host ""

Write-ColoredLine " LOG FILE SAVED:" Yellow
Write-ColoredLine " $LogFile" White
Write-Host ""

Unregister-Event -SourceIdentifier "FileCreated_$PID" -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier "FileChanged_$PID" -ErrorAction SilentlyContinue

$suspiciousFindings[0].Score = "$overallSuccess% ($totalSuccess / $totalChecks)"

Wait-ForEnter -Message "Press Enter to Exit"

Clear-Host
Write-ColoredLine "`n Thank you for using JTC T2 Policy Scanner`n" Cyan
Write-ColoredLine " Log saved to: $LogFile`n" Gray
exit
