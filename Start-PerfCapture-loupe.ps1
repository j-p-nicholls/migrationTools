<#
.SYNOPSIS
    Captures 3 performance counters at 1-minute intervals for 30 minutes,
    outputting to CSV, then stops automatically. No manual intervention required.

.DESCRIPTION
    Uses logman to create a Data Collector Set with a fixed end time 30 minutes
    from launch. Safe to run on headless / Server Core systems. Cleans up any
    existing collector set of the same name before starting.

.NOTES
    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [string[]]$Counters = @(
        "\Processor(_Total)\% Processor Time",
        "\Memory\Available MBytes",
        "\PhysicalDisk(_Total)\Disk Bytes/sec"
    ),

    [string]$OutputPath = "C:\PerfLogs\PerfCapture.csv",

    [int]$DurationMinutes = 30,

    [int]$SampleIntervalSeconds = 60,

    [string]$CollectorSetName = "PerfCapture"
)

$ErrorActionPreference = "Stop"

# Ensure output directory exists
$outputDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    Write-Verbose "Created output directory: $outputDir"
}

# Clean up any existing collector set with the same name (avoids "already exists" errors)
$existing = logman query $CollectorSetName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Verbose "Existing collector set '$CollectorSetName' found — stopping and deleting."
    logman stop $CollectorSetName 2>$null | Out-Null
    logman delete $CollectorSetName 2>$null | Out-Null
}

# Calculate the fixed end time
$endTime = (Get-Date).AddMinutes($DurationMinutes).ToString("MM/dd/yyyy HH:mm:ss")

Write-Host "Creating collector set '$CollectorSetName'..."
Write-Host "  Counters: $($Counters -join ', ')"
Write-Host "  Interval: $SampleIntervalSeconds seconds"
Write-Host "  Duration: $DurationMinutes minutes (auto-stop at $endTime)"
Write-Host "  Output:   $OutputPath"

# Create the collector set with a hard stop time — no manual intervention needed
logman create counter $CollectorSetName `
    -c $Counters `
    -si "00:00:$($SampleIntervalSeconds.ToString('00'))" `
    -o $OutputPath `
    -f csv `
    -et $endTime `
    -v mmddhhmm

if ($LASTEXITCODE -ne 0) {
    throw "Failed to create collector set '$CollectorSetName'."
}

# Start it
logman start $CollectorSetName | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Failed to start collector set '$CollectorSetName'."
}

Write-Host "`nCapture started. It will run for $DurationMinutes minutes and stop automatically."
Write-Host "You can close this session — logman runs as a background service, not tied to your console."
Write-Host "Check status any time with: logman query $CollectorSetName"
Write-Host "Output will be written to: $OutputPath"
