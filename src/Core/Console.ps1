function Write-ColoredLine {
    param ([string]$Text, [ConsoleColor]$Color = 'White')
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    param([string]$Message = "Press Enter to Continue")
    Write-Host ""
    Write-ColoredLine ">> $Message" Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } while ($key.Key -ne "Enter")
}

function Show-CustomLoadingBar {
    $i = 0
    Write-Host ""
    for ($p = 0; $p -le 100; $p += 5) {
        $filled = [math]::Floor($p / 2.5)
        $empty = 40 - $filled
        $bar = "#" * $filled + "-" * $empty
        $percentage = "{0,3}" -f $p
        if ($p -eq 100) {
            Write-Host -NoNewline "`r [$bar] $percentage% " -ForegroundColor Green
        } else {
            Write-Host -NoNewline "`r [$bar] $percentage% " -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 50
        $i++
    }
    Write-Host ""
    Write-Host ""
}

function Write-BoxedHeader {
    param([string]$Title, [string]$Subtitle = "")
    $innerWidth = 62
    $border = "+" + ("-" * $innerWidth) + "+"
    $titlePadding = [math]::Floor(($innerWidth - $Title.Length) / 2)
    $titleLine = " " * $titlePadding + $Title + " " * ($innerWidth - $titlePadding - $Title.Length)
    Write-Host ""
    Write-ColoredLine $border Blue
    Write-Host "|" -NoNewline -ForegroundColor Blue
    Write-Host $titleLine -NoNewline
    Write-Host "|" -ForegroundColor Blue
    if ($Subtitle) {
        $subtitlePadding = [math]::Floor(($innerWidth - $Subtitle.Length) / 2)
        $leftPadding = " " * $subtitlePadding
        $rightPadding = " " * ($innerWidth - $subtitlePadding - $Subtitle.Length)
        $splitPoint = 14
        $firstHalf = $Subtitle.Substring(0, [math]::Min($splitPoint, $Subtitle.Length))
        $secondHalf = if ($Subtitle.Length -gt $splitPoint) { $Subtitle.Substring($splitPoint) } else { "" }
        Write-Host "|" -NoNewline -ForegroundColor Blue
        Write-Host ($leftPadding + $firstHalf) -NoNewline -ForegroundColor White
        Write-Host ($secondHalf + $rightPadding) -NoNewline -ForegroundColor Magenta
        Write-Host "|" -ForegroundColor Blue
    }
    Write-ColoredLine $border Blue
    Write-Host ""
}
