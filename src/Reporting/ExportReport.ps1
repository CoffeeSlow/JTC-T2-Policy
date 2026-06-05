function Export-EvidenceJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    begin {
        $all = @()
    }

    process {
        $all += $Record
    }

    end {
        if ($all.Count -eq 0) {
            Write-Warning 'No evidence records to export.'
            return
        }

        $dir = Split-Path $Path -Parent
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $all | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
    }
}

function Export-EvidenceCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    begin {
        $all = @()
    }

    process {
        $all += $Record
    }

    end {
        if ($all.Count -eq 0) {
            Write-Warning 'No evidence records to export.'
            return
        }

        $dir = Split-Path $Path -Parent
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $all | Select-Object Timestamp, Source, Category, Type, Name, Path, Value, Severity, Confidence | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}
