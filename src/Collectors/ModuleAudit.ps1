function Get-ModuleAuditEvidence {
    $records = @()

    $defaultModules = @(
        'Microsoft.PowerShell.Archive',
        'Microsoft.PowerShell.Diagnostics',
        'Microsoft.PowerShell.Host',
        'Microsoft.PowerShell.LocalAccounts',
        'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Security',
        'Microsoft.PowerShell.Utility',
        'PackageManagement',
        'PowerShellGet',
        'PSReadLine',
        'Pester',
        'ThreadJob'
    )
    $protectedModule = 'Microsoft.PowerShell.Operation.Validation'
    $modulesPath = 'C:\Program Files\WindowsPowerShell\Modules'

    $modules = Get-ChildItem $modulesPath -Directory -ErrorAction SilentlyContinue

    if (-not $modules -or $modules.Count -eq 0) {
        $records += New-EvidenceRecord -Source 'ModuleAudit' -Category 'SystemIntegrity' -Type 'PowerShellModule' -Name 'Module Path Access' -Value 'NoModulesFound' -Severity 'Info' -Confidence 'High' -Details @{
            Path = $modulesPath
        }
        return $records
    }

    foreach ($module in $modules) {
        $moduleName = $module.Name
        $manifestPath = Join-Path $module.FullName "$moduleName.psd1"
        $moduleVersion = 'Unknown'

        if (Test-Path $manifestPath) {
            try {
                $manifest = Import-PowerShellDataFile $manifestPath -ErrorAction Stop
                $moduleVersion = if ($manifest.ModuleVersion) { $manifest.ModuleVersion.ToString() } else { 'Unknown' }
            } catch {
                $moduleVersion = 'Unknown'
            }
        }

        $details = @{
            ModuleName    = $moduleName
            ModulePath    = $module.FullName
            ModuleVersion = $moduleVersion
        }

        if ($moduleName -eq $protectedModule) {
            $records += New-EvidenceRecord -Source 'ModuleAudit' -Category 'SystemIntegrity' -Type 'PowerShellModule' -Name $moduleName -Value 'Protected' -Severity 'Info' -Confidence 'High' -Details $details
        } elseif ($moduleName -in $defaultModules) {
            $records += New-EvidenceRecord -Source 'ModuleAudit' -Category 'SystemIntegrity' -Type 'PowerShellModule' -Name $moduleName -Value 'Known' -Severity 'Info' -Confidence 'High' -Details $details
        } else {
            $records += New-EvidenceRecord -Source 'ModuleAudit' -Category 'SystemIntegrity' -Type 'PowerShellModule' -Name $moduleName -Value 'Unexpected' -Severity 'Medium' -Confidence 'Medium' -Details $details
        }
    }

    return $records
}
