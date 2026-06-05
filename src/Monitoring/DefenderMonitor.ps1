$script:DefenderMonitorBaseline = $null

function Get-DefenderStateSnapshot {
    $mpref = Get-MpPreference -ErrorAction Stop
    $mpstatus = Get-MpComputerStatus -ErrorAction Stop

    return [PSCustomObject]@{
        Timestamp               = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        RealTimeProtectionEnabled = [bool]$mpstatus.RealTimeProtectionEnabled
        DisableRealtimeMonitoring = [bool]$mpref.DisableRealtimeMonitoring
        ExclusionPath            = @($mpref.ExclusionPath) | Where-Object { $_ }
        ExclusionProcess         = @($mpref.ExclusionProcess) | Where-Object { $_ }
        ExclusionExtension       = @($mpref.ExclusionExtension) | Where-Object { $_ }
    }
}

function Start-DefenderMonitor {
    [CmdletBinding()]
    param(
        [switch]$PassThru
    )

    $snapshot = Get-DefenderStateSnapshot
    $script:DefenderMonitorBaseline = $snapshot

    if ($PassThru) {
        return $snapshot
    }
}

function Stop-DefenderMonitor {
    [CmdletBinding()]
    param()

    $script:DefenderMonitorBaseline = $null
}

function Compare-DefenderMonitorState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Baseline,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Current
    )

    $records = @()

    if ($Current.RealTimeProtectionEnabled -ne $Baseline.RealTimeProtectionEnabled) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'RTPChange' -Name 'Real-Time Protection' -Value "$($Baseline.RealTimeProtectionEnabled) -> $($Current.RealTimeProtectionEnabled)" -Severity 'High' -Confidence 'High' -Details @{
            Property     = 'RealTimeProtectionEnabled'
            Previous     = $Baseline.RealTimeProtectionEnabled
            Current      = $Current.RealTimeProtectionEnabled
        }
    }

    if ($Current.DisableRealtimeMonitoring -ne $Baseline.DisableRealtimeMonitoring) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'DisableMonitoringChange' -Name 'Disable Realtime Monitoring' -Value "$($Baseline.DisableRealtimeMonitoring) -> $($Current.DisableRealtimeMonitoring)" -Severity 'High' -Confidence 'High' -Details @{
            Property     = 'DisableRealtimeMonitoring'
            Previous     = $Baseline.DisableRealtimeMonitoring
            Current      = $Current.DisableRealtimeMonitoring
        }
    }

    $addedPaths = $Current.ExclusionPath | Where-Object { $_ -notin $Baseline.ExclusionPath }
    $removedPaths = $Baseline.ExclusionPath | Where-Object { $_ -notin $Current.ExclusionPath }
    foreach ($p in $addedPaths) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'PathExclusionAdded' -Name 'Path Exclusion Added' -Path $p -Value $p -Severity 'Medium' -Confidence 'High'
    }
    foreach ($p in $removedPaths) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'PathExclusionRemoved' -Name 'Path Exclusion Removed' -Path $p -Value $p -Severity 'Info' -Confidence 'High'
    }

    $addedProcs = $Current.ExclusionProcess | Where-Object { $_ -notin $Baseline.ExclusionProcess }
    $removedProcs = $Baseline.ExclusionProcess | Where-Object { $_ -notin $Current.ExclusionProcess }
    foreach ($p in $addedProcs) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'ProcessExclusionAdded' -Name 'Process Exclusion Added' -Path $p -Value $p -Severity 'Medium' -Confidence 'High'
    }
    foreach ($p in $removedProcs) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'ProcessExclusionRemoved' -Name 'Process Exclusion Removed' -Path $p -Value $p -Severity 'Info' -Confidence 'High'
    }

    $addedExts = $Current.ExclusionExtension | Where-Object { $_ -notin $Baseline.ExclusionExtension }
    $removedExts = $Baseline.ExclusionExtension | Where-Object { $_ -notin $Current.ExclusionExtension }
    foreach ($e in $addedExts) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'ExtensionExclusionAdded' -Name 'Extension Exclusion Added' -Value $e -Severity 'Medium' -Confidence 'High'
    }
    foreach ($e in $removedExts) {
        $records += New-EvidenceRecord -Source 'DefenderMonitor' -Category 'SecurityProduct' -Type 'ExtensionExclusionRemoved' -Name 'Extension Exclusion Removed' -Value $e -Severity 'Info' -Confidence 'High'
    }

    return $records
}

function Get-DefenderMonitorChanges {
    [CmdletBinding()]
    param()

    if ($null -eq $script:DefenderMonitorBaseline) {
        Write-Warning 'No baseline stored. Run Start-DefenderMonitor first.'
        return
    }

    $current = Get-DefenderStateSnapshot
    $records = Compare-DefenderMonitorState -Baseline $script:DefenderMonitorBaseline -Current $current
    $script:DefenderMonitorBaseline = $current

    return $records
}

$script:DefenderEventWatcher = $null
$script:DefenderEventRecords = @()

function Start-DefenderEventMonitor {
    [CmdletBinding()]
    param()

    if ($script:DefenderEventWatcher) {
        return
    }

    $query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">
      *[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012)]]
    </Select>
  </Query>
</QueryList>
"@

    $elog = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Microsoft-Windows-Windows Defender/Operational', [System.Diagnostics.Eventing.Reader.PathType]::LogName, $query)
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($elog)

    $sourceId = "DefenderEventWatcher_$PID"
    Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier $sourceId -Action {
        $evt = $EventArgs.EventRecord
        $eventId = $evt.Id
        $timestamp = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        $message = $evt.FormatDescription()

        $severityMap = @{
            1116 = 'High'
            1117 = 'High'
            5001 = 'High'
            5007 = 'Medium'
            5010 = 'High'
            5012 = 'Info'
        }
        $severity = if ($severityMap.ContainsKey($eventId)) { $severityMap[$eventId] } else { 'Info' }

        $nameMap = @{
            1116 = 'Malware Detected'
            1117 = 'Malware Action Taken'
            5001 = 'Real-Time Protection Disabled'
            5007 = 'Defender Configuration Changed'
            5010 = 'Spyware Scanning Disabled'
            5012 = 'Real-Time Protection Enabled'
        }
        $name = if ($nameMap.ContainsKey($eventId)) { $nameMap[$eventId] } else { "Defender Event $eventId" }

        $record = New-EvidenceRecord -Source 'DefenderEventMonitor' -Category 'SecurityProduct' -Type "DefenderEvent$eventId" -Name $name -Value $message -Severity $severity -Confidence 'High' -Details @{
            Timestamp = $timestamp
            EventId   = $eventId
            Source    = 'Microsoft-Windows-Windows Defender/Operational'
            Severity  = $severity
            Message   = $message
        }

        $script:DefenderEventRecords += $record
    } | Out-Null

    $watcher.Enabled = $true

    $script:DefenderEventWatcher = @{
        Watcher    = $watcher
        SourceId   = $sourceId
    }
}

function Stop-DefenderEventMonitor {
    [CmdletBinding()]
    param()

    if (-not $script:DefenderEventWatcher) {
        return
    }

    $state = $script:DefenderEventWatcher

    $subscriber = Get-EventSubscriber -SourceIdentifier $state.SourceId -ErrorAction SilentlyContinue
    if ($subscriber) {
        Unregister-Event -SourceIdentifier $state.SourceId -Force -ErrorAction SilentlyContinue
    }

    if ($state.Watcher) {
        $state.Watcher.Enabled = $false
        $state.Watcher.Dispose()
    }

    $script:DefenderEventWatcher = $null
}
