function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )
    $entry = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    Write-Host " >> " -NoNewline -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor Cyan
}
