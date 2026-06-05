function Get-EvidenceTimeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record
    )

    begin {
        $all = @()
    }

    process {
        $all += $Record
    }

    end {
        $timeline = $all | Where-Object { $_ -and $_.Timestamp } | ForEach-Object {
            $sortTime = if ($_.Timestamp -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$') {
                [DateTime]::ParseExact($_.Timestamp, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            } else {
                [DateTime]::MinValue
            }
            [PSCustomObject]@{
                Timestamp     = $_.Timestamp
                SortTimestamp = $sortTime
                Source        = $_.Source
                Category      = $_.Category
                Type          = $_.Type
                Name          = $_.Name
                Severity      = $_.Severity
            }
        }

        $timeline = $timeline | Sort-Object SortTimestamp, Source, Name

        $timeline | Select-Object Timestamp, Source, Category, Type, Name, Severity
    }
}

function Write-EvidenceTimeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record
    )

    begin {
        $all = @()
        $severityColor = @{
            Critical = 'Red'
            High     = 'DarkRed'
            Medium   = 'Yellow'
            Low      = 'DarkYellow'
            Info     = 'DarkGray'
        }
    }

    process {
        $all += $Record
    }

    end {
        $total = $all.Count
        if ($total -eq 0) {
            Write-Host 'No timeline records to display.' -ForegroundColor DarkGray
            return
        }

        Write-Host ''
        Write-Host ('=' * 68) -ForegroundColor DarkGray
        Write-Host '  EVIDENCE TIMELINE' -ForegroundColor White
        Write-Host "  $total record(s) sorted chronologically" -ForegroundColor DarkGray
        Write-Host ('=' * 68) -ForegroundColor DarkGray
        Write-Host ''

        $currentDate = ''
        foreach ($item in $all) {
            $itemDate = if ($item.Timestamp -and $item.Timestamp.Length -ge 10) { $item.Timestamp.Substring(0, 10) } else { '' }
            if ($itemDate -and $itemDate -ne $currentDate) {
                $currentDate = $itemDate
                Write-Host "  --- $currentDate ---" -ForegroundColor Cyan
                Write-Host ''
            }

            $color = if ($item.Severity -and $severityColor.ContainsKey($item.Severity)) { $severityColor[$item.Severity] } else { 'Gray' }
            $time = if ($item.Timestamp -and $item.Timestamp.Length -ge 19) { $item.Timestamp.Substring(11, 8) } else { '--:--:--' }

            $srcPad = '{0,-14}' -f $item.Source
            $catPad = '{0,-22}' -f $item.Category
            $typePad = '{0,-20}' -f $item.Type
            $nameVal = if ($item.Name) { $item.Name } else { '' }

            Write-Host "  [$time] " -NoNewline -ForegroundColor DarkGray
            Write-Host "$srcPad " -NoNewline -ForegroundColor $color
            Write-Host "$catPad " -NoNewline -ForegroundColor Gray
            Write-Host "$typePad " -NoNewline -ForegroundColor DarkGray
            Write-Host "$nameVal" -ForegroundColor $color
        }

        Write-Host ''
        Write-Host ('=' * 68) -ForegroundColor DarkGray
        Write-Host "  END OF TIMELINE  |  $total record(s)" -ForegroundColor DarkGray
        Write-Host ('=' * 68) -ForegroundColor DarkGray
        Write-Host ''

        $all | Write-Output
    }
}
