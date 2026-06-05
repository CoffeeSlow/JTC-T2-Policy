function Import-KnownTools {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$SkipValidation
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "KnownTools file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $db = $raw | ConvertFrom-Json

    if (-not $SkipValidation) {
        $errors = @()

        if (-not $db.version) {
            $errors += "Missing required field: version"
        }

        if ($null -eq $db.tools -or -not ($db.tools -is [array])) {
            $errors += "Missing or invalid required field: tools (must be an array)"
        }

        if ($errors.Count -gt 0) {
            throw "KnownTools validation failed: $($errors -join '; ')"
        }
    }

    return $db
}

function Get-KnownToolIndicators {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$Database,

        [ValidateSet('Executables', 'PathPatterns', 'PrefetchPatterns', 'RegistryPatterns', 'WindowTitlePatterns', 'ModuleIndicators', 'SuspiciousKeywords')]
        [string]$IndicatorType = 'Executables'
    )

    process {
        foreach ($tool in $Database.tools) {
            $indicators = $tool.$IndicatorType
            if (-not $indicators) { continue }

            foreach ($indicator in $indicators) {
                [PSCustomObject]@{
                    ToolName    = $tool.Name
                    Category    = $tool.Category
                    Risk        = $tool.Risk
                    Confidence  = $tool.Confidence
                    Indicator   = $indicator
                    IndicatorType = $IndicatorType
                }
            }
        }
    }
}
