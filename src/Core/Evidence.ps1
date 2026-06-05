function New-EvidenceRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [string]$Name = '',
        [string]$Path = '',
        [string]$Value = '',
        [string]$Severity = 'Info',
        [string]$Confidence = 'Low',
        [PSObject]$Details = $null
    )
    $record = [PSCustomObject]@{
        Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Source     = $Source
        Category   = $Category
        Type       = $Type
        Name       = $Name
        Path       = $Path
        Value      = $Value
        Severity   = $Severity
        Confidence = $Confidence
        Details    = $Details
    }
    return $record
}

function Test-EvidenceRecord {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$Record,

        [switch]$ThrowOnError
    )
    begin {
        $errors = @()
    }
    process {
        if ($null -eq $Record) { return }
        $required = @('Timestamp', 'Source', 'Category', 'Type', 'Severity', 'Confidence')
        $valid = $true

        foreach ($prop in $required) {
            if (-not (Get-Member -InputObject $Record -Name $prop -MemberType Properties)) {
                $errors += "Missing required property: $prop"
                $valid = $false
            }
        }

        if ($valid -and [string]::IsNullOrEmpty($Record.Source)) {
            $errors += "Property 'Source' is empty"
            $valid = $false
        }
        if ($valid -and [string]::IsNullOrEmpty($Record.Category)) {
            $errors += "Property 'Category' is empty"
            $valid = $false
        }
        if ($valid -and [string]::IsNullOrEmpty($Record.Type)) {
            $errors += "Property 'Type' is empty"
            $valid = $false
        }

        if (-not $valid -and $ThrowOnError) {
            throw "Evidence record validation failed: $($errors -join '; ')"
        }
    }
    end {
        return ($errors.Count -eq 0)
    }
}
