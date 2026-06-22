# Ghidra Headless Analysis - PowerShell Wrapper for Windows
# Usage: ghidra-analyze.ps1 -Binary <path> -Script <script_name> [-OutputDir <dir>] [-Processor <id>] [-NoAnalysis] [-Timeout <sec>]

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Binary,
    [string]$OutputDir = ".\ghidra_output",
    [string[]]$Scripts = @("ExportAll.java"),
    [string]$Processor = "AARCH64:LE:64:v8A",
    [string]$Cspec = "default",
    [switch]$NoAnalysis,
    [int]$Timeout = 600,
    [switch]$KeepProject,
    [string]$ProjectDir = "C:\Temp\ghidra_projects",
    [string]$ProjectName,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Set GHIDRA_HOME
$env:GHIDRA_HOME = "C:\Tools\ghidra_11.2.1_PUBLIC"
$analyzeHeadless = "$env:GHIDRA_HOME\support\analyzeHeadless.bat"

if (-not (Test-Path $analyzeHeadless)) {
    throw "analyzeHeadless.bat not found at $analyzeHeadless"
}

# Verify binary
if (-not (Test-Path $Binary)) {
    throw "Binary not found: $Binary"
}

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Set project name
if (-not $ProjectName) {
    $ProjectName = "ghidra_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$(Split-Path $Binary -Leaf)"
}

# Ghidra scripts location
$ghidraScripts = "C:\Users\amine\.agents\.agents\skills\ghidra-headless\scripts\ghidra_scripts"

# Build arguments
$args = @(
    $ProjectDir,
    $ProjectName,
    "-import", $Binary
)

if ($Processor) {
    $args += @("-processor", $Processor)
}

if ($Cspec -and $Cspec -ne "default") {
    $args += @("-cspec", $Cspec)
}

foreach ($script in $Scripts) {
    $args += @("-postScript", $script)
}

if ($NoAnalysis) {
    $args += "-noAnalysis"
}

if ($Timeout -gt 0) {
    $args += @("-analysisTimeoutPerFile", $Timeout)
}

if (-not $KeepProject) {
    $args += "-deleteProject"
}

# Add script path
$args += @("-scriptPath", $ghidraScripts)

# Output dir env var for post-scripts
$env:GHIDRA_OUTPUT_DIR = (Resolve-Path $OutputDir).Path

$logFile = Join-Path $OutputDir "ghidra_analysis.log"
$outLog = Join-Path $OutputDir "ghidra_output.log"

Write-Host "[*] Ghidra Headless Analysis" -ForegroundColor Cyan
Write-Host "    Binary:       $Binary" -ForegroundColor Gray
Write-Host "    Processor:    $Processor" -ForegroundColor Gray
Write-Host "    Scripts:      $($Scripts -join ', ')" -ForegroundColor Gray
Write-Host "    Output:       $OutputDir" -ForegroundColor Gray
Write-Host "    Project:      $ProjectDir\$ProjectName" -ForegroundColor Gray
Write-Host ""

if ($Verbose) {
    Write-Host "[*] Command:" -ForegroundColor Yellow
    Write-Host "    $analyzeHeadless $($args -join ' ')" -ForegroundColor DarkGray
    Write-Host ""
}

# Run Ghidra
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $analyzeHeadless
$psi.Arguments = $args -join ' '
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $OutputDir

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi

# Capture output streamingly
$sb = New-Object System.Text.StringBuilder
$proc.add_OutputDataReceived({ if ($_.Data) { [void]$sb.AppendLine($_.Data); Write-Host $_.Data } })
$proc.add_ErrorDataReceived({ if ($_.Data) { [void]$sb.AppendLine("ERROR: " + $_.Data); Write-Host $_.Data -ForegroundColor Red } })

$proc.Start() | Out-Null
$proc.BeginOutputReadLine()
$proc.BeginErrorReadLine()
$proc.WaitForExit()

# Save logs
$sb.ToString() | Out-File -FilePath $outLog -Encoding UTF8

Write-Host ""
if ($proc.ExitCode -eq 0) {
    Write-Host "[+] Analysis complete" -ForegroundColor Green
    Write-Host "    Output files:" -ForegroundColor Gray
    Get-ChildItem -Path $OutputDir -File | Where-Object { $_.Name -notmatch '^(ghidra_)' } | ForEach-Object {
        $size = "{0:N0}" -f $_.Length
        Write-Host "      $($_.Name) ($size bytes)" -ForegroundColor Gray
    }
} else {
    Write-Host "[!] Analysis failed with exit code $($proc.ExitCode)" -ForegroundColor Red
    Write-Host "    Check log: $outLog" -ForegroundColor Red
    exit $proc.ExitCode
}
