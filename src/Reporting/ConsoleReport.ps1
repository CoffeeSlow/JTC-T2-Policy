function Write-EvidenceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record
    )

    begin {
        $all = @()
        $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
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
            Write-ColoredLine 'No evidence records to report.' DarkGray
            return
        }

        Write-Host ''
        Write-BoxedHeader 'EVIDENCE REPORT' "$total total records"
        Write-Host ''

        foreach ($sev in $severityOrder) {
            $sevGroup = $all | Where-Object { $_.Severity -eq $sev }
            if (-not $sevGroup) { continue }

            $sevColor = $severityColor[$sev]
            Write-ColoredLine "=== $sev ($($sevGroup.Count)) ===" $sevColor

            $catGroups = $sevGroup | Group-Object Category | Sort-Object Name
            foreach ($catGroup in $catGroups) {
                Write-Host "  $($catGroup.Name):" -ForegroundColor Gray
                $srcGroups = $catGroup.Group | Group-Object Source | Sort-Object Name
                foreach ($srcGroup in $srcGroups) {
                    Write-Host "    $($srcGroup.Name) ($($srcGroup.Count))" -ForegroundColor DarkGray
                    foreach ($item in $srcGroup.Group) {
                        $name = if ($item.Name) { $item.Name } else { '(no name)' }
                        $value = if ($item.Value) { $item.Value } else { '' }
                        $time = if ($item.Timestamp) { $item.Timestamp } else { '' }
                        Write-Host "      $name  $value  $time" -ForegroundColor $sevColor
                    }
                }
            }
            Write-Host ''
        }

        Write-Host ''
        Write-ColoredLine ('=' * 64) DarkGray
        Write-ColoredLine "  END OF REPORT  |  $total evidence record(s)" DarkGray
        Write-ColoredLine ('=' * 64) DarkGray
        Write-Host ''

        $all | Write-Output
    }
}

function Write-EvidenceSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record
    )

    begin {
        $all = @()
        $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
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
            Write-ColoredLine 'No evidence records to summarize.' DarkGray
            return
        }

        Write-Host ''
        Write-BoxedHeader 'EVIDENCE SUMMARY' "$total total records"
        Write-Host ''

        Write-Host '  By Severity:' -ForegroundColor White
        foreach ($sev in $severityOrder) {
            $count = @($all | Where-Object { $_.Severity -eq $sev }).Count
            if ($count -gt 0) {
                $sevColor = $severityColor[$sev]
                Write-Host "    $($sev.PadRight(12)) $count" -ForegroundColor $sevColor
            }
        }

        Write-Host ''
        Write-Host '  By Source:' -ForegroundColor White
        $srcGroups = $all | Group-Object Source | Sort-Object Name
        foreach ($g in $srcGroups) {
            Write-Host "    $($g.Name.PadRight(20)) $($g.Count)" -ForegroundColor DarkGray
        }

        Write-Host ''
        Write-Host '  By Category:' -ForegroundColor White
        $catGroups = $all | Group-Object Category | Sort-Object Name
        foreach ($g in $catGroups) {
            Write-Host "    $($g.Name.PadRight(24)) $($g.Count)" -ForegroundColor DarkGray
        }

        Write-Host ''
        Write-ColoredLine ('-' * 48) DarkGray
        Write-Host "    TOTAL$(''.PadRight(19)) $total" -ForegroundColor Cyan
        Write-ColoredLine ('-' * 48) DarkGray
        Write-Host ''

        $all | Write-Output
    }
}
