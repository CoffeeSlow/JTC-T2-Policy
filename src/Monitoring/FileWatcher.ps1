$script:FileWatcherState = $null

function Start-FileWatcherMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Filter = '*.*',

        [switch]$IncludeSubdirectories
    )

    if ($script:FileWatcherState) {
        return
    }

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $Path
    $watcher.Filter = $Filter
    $watcher.IncludeSubdirectories = $IncludeSubdirectories.IsPresent
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
    $watcher.EnableRaisingEvents = $true

    $createdId = "FileWatcherCreated_$PID"
    Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier $createdId -Action {
        $path = $Event.SourceEventArgs.FullPath
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

        New-EvidenceRecord -Source 'FileWatcher' -Category 'FileArtifact' -Type 'FileCreated' -Name $name -Path $path -Value $path -Severity 'Info' -Confidence 'High' -Details @{
            Timestamp  = $time
            ChangeType = $changeType.ToString()
            Path       = $path
        }
    } | Out-Null

    $changedId = "FileWatcherChanged_$PID"
    Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier $changedId -Action {
        $path = $Event.SourceEventArgs.FullPath
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

        New-EvidenceRecord -Source 'FileWatcher' -Category 'FileArtifact' -Type 'FileChanged' -Name $name -Path $path -Value $path -Severity 'Info' -Confidence 'High' -Details @{
            Timestamp  = $time
            ChangeType = $changeType.ToString()
            Path       = $path
        }
    } | Out-Null

    $script:FileWatcherState = @{
        Watcher          = $watcher
        CreatedSourceId  = $createdId
        ChangedSourceId  = $changedId
        Path             = $Path
        Filter           = $Filter
        IncludeSubdirs   = $IncludeSubdirectories.IsPresent
    }
}

function Stop-FileWatcherMonitor {
    [CmdletBinding()]
    param()

    if (-not $script:FileWatcherState) {
        return
    }

    $state = $script:FileWatcherState

    $subscribers = Get-EventSubscriber -SourceIdentifier $state.CreatedSourceId -ErrorAction SilentlyContinue
    if ($subscribers) {
        Unregister-Event -SourceIdentifier $state.CreatedSourceId -Force -ErrorAction SilentlyContinue
    }

    $subscribers = Get-EventSubscriber -SourceIdentifier $state.ChangedSourceId -ErrorAction SilentlyContinue
    if ($subscribers) {
        Unregister-Event -SourceIdentifier $state.ChangedSourceId -Force -ErrorAction SilentlyContinue
    }

    if ($state.Watcher) {
        $state.Watcher.EnableRaisingEvents = $false
        $state.Watcher.Dispose()
    }

    $script:FileWatcherState = $null
}
