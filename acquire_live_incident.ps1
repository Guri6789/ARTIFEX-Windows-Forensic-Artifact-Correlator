# ==============================================================================
# ARTIFEX: Windows Live Incident Forensics & FTK Imager Triage Collector
# ==============================================================================
# Requires Administrator privileges to access locked Event Logs & Registry hives.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$CaseId = "INC-$((Get-Date).ToString('yyyyMMdd-HHmm'))",
    [string]$Examiner = "Incident Responder",
    [string]$OutputDir = ".\case_evidence_$((Get-Date).ToString('yyyyMMdd_HHmm'))",
    [string]$Tool = "auto",
    [string]$FtkPath = "",
    [switch]$AutoAnalyze = $true
)

# 1. Administrator Privilege Verification
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[!] Administrator elevation required. Relaunching in elevated PowerShell..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -CaseId `"$CaseId`" -Examiner `"$Examiner`" -OutputDir `"$OutputDir`" -Tool `"$Tool`""
    exit
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   ARTIFEX: Live Incident Response & FTK Imager Acquisition" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[*] Case Identifier:  $CaseId"
Write-Host "[*] Examiner:         $Examiner"
Write-Host "[*] Output Directory: $OutputDir"
Write-Host "[*] Acquisition Mode: $Tool"

# 2. Check Python environment
$pythonCmd = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $pythonCmd) {
    $pythonCmd = (Get-Command py -ErrorAction SilentlyContinue)
}
if (-not $pythonCmd) {
    Write-Error "[!] Python 3.9+ was not found on PATH. Please install Python to run ARTIFEX."
    exit 1
}

# 3. Resolve Script Directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 4. Construct Command
$cliArgs = @(
    "cli.py", "acquire",
    "--output", $OutputDir,
    "--tool", $Tool,
    "--case-id", $CaseId,
    "--examiner", $Examiner
)

if ($FtkPath -and (Test-Path $FtkPath)) {
    $cliArgs += @("--ftk-path", $FtkPath)
}

if ($AutoAnalyze) {
    $cliArgs += "--auto-analyze"
}

Write-Host "`n[*] Starting Forensic Acquisition..." -ForegroundColor Yellow
& $pythonCmd.Source @cliArgs

Write-Host "`n[+] Operation Finished. Preserved forensic data and reports are in: $OutputDir" -ForegroundColor Green

