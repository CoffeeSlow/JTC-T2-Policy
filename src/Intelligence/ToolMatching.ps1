function Test-KnownToolMatch {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [ValidateSet('Executables', 'PathPatterns', 'PrefetchPatterns', 'RegistryPatterns', 'WindowTitlePatterns', 'ModuleIndicators', 'SuspiciousKeywords')]
        [string[]]$IndicatorType,

        [switch]$CaseSensitive
    )

    $records = @()
    $compareOp = if ($CaseSensitive) { 'cmatch' } else { 'imatch' }

    $typesToCheck = if ($PSBoundParameters.ContainsKey('IndicatorType')) {
        $IndicatorType
    } else {
        @('Executables', 'PathPatterns', 'PrefetchPatterns', 'RegistryPatterns', 'WindowTitlePatterns', 'ModuleIndicators', 'SuspiciousKeywords')
    }

    foreach ($type in $typesToCheck) {
        $flattened = $Database | Get-KnownToolIndicators -IndicatorType $type

        foreach ($entry in $flattened) {
            $pattern = $entry.Indicator
            $pattern = [regex]::Escape($pattern)
            $pattern = $pattern -replace '\\\*', '.*' -replace '\\\?', '.'

            $matched = $false
            try {
                $matched = if ($CaseSensitive) { $Value -cmatch $pattern } else { $Value -imatch $pattern }
            } catch {
                continue
            }
            if (-not $matched) { continue }

            $records += New-EvidenceRecord -Source 'ToolMatching' -Category $entry.Category -Type $type -Name $entry.ToolName -Path $Value -Value $entry.Indicator -Severity $entry.Risk -Confidence $entry.Confidence -Details @{
                IndicatorType = $type
                Pattern       = $entry.Indicator
                MatchValue    = $Value
            }
        }
    }

    return $records
}

function Resolve-KnownToolCategory {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Database,

        [Parameter(ParameterSetName = 'ByName')]
        [string]$ToolName,

        [Parameter(ParameterSetName = 'ByCategory')]
        [string]$CategoryName
    )

    $records = @()

    if ($ToolName) {
        $matching = $Database.tools | Where-Object { $_.Name -imatch [regex]::Escape($ToolName) }
        foreach ($tool in $matching) {
            $indicatorTypes = @('Executables', 'PathPatterns', 'PrefetchPatterns', 'RegistryPatterns', 'WindowTitlePatterns', 'ModuleIndicators', 'SuspiciousKeywords')
            $totalCount = 0
            foreach ($it in $indicatorTypes) {
                if ($tool.$it) { $totalCount += @($tool.$it).Count }
            }
            $records += New-EvidenceRecord -Source 'ToolMatching' -Category $tool.Category -Type 'ToolDefinition' -Name $tool.Name -Value $tool.Category -Severity $tool.Risk -Confidence $tool.Confidence -Details @{
                Risk           = $tool.Risk
                IndicatorCount = $totalCount
            }
        }
    }

    if ($CategoryName) {
        $matching = $Database.tools | Where-Object { $_.Category -imatch [regex]::Escape($CategoryName) }
        foreach ($tool in $matching) {
            $records += New-EvidenceRecord -Source 'ToolMatching' -Category $tool.Category -Type 'CategoryMember' -Name $tool.Name -Value $tool.Category -Severity $tool.Risk -Confidence $tool.Confidence -Details @{
                Risk = $tool.Risk
            }
        }
    }

    return $records
}
