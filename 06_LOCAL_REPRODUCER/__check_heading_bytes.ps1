$ErrorActionPreference = 'Stop'
$base = 'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'
Set-Location -LiteralPath $base
$b = [System.IO.File]::ReadAllBytes('05_IOC\ioc_catalog.md')
$text = [System.Text.Encoding]::UTF8.GetString($b)
foreach ($line in $text -split "`n") {
    if ($line -match 'Datation') {
        Write-Host 'STRING:'
        Write-Host $line
        Write-Host 'BYTES:'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
        $hex = ($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
        Write-Host $hex
        break
    }
}
