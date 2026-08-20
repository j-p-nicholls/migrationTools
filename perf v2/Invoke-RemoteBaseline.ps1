<#
.SYNOPSIS
    Runs poll-metrics.sh on a remote RHEL host over SSH and copies the
    resulting CSV back to the local machine — one command, one login.

.DESCRIPTION
    Uses OpenSSH connection multiplexing (ControlMaster) so the password
    (or passphrase) is only requested once, even though the script makes
    three separate ssh/scp calls under the hood (copy script, run script,
    copy CSV back).

    For fully unattended runs (e.g. scheduled task, looping over many
    hosts), set up SSH key-based auth instead — see notes at the bottom
    of this file.

.PARAMETER LinuxHost
    Hostname or IP of the target RHEL server.

.PARAMETER User
    Username to connect as.

.PARAMETER DurationMinutes
    How long to poll for, in minutes. Passed straight through to
    poll-metrics.sh.

.PARAMETER IntervalSeconds
    Sample interval in seconds. Default: 5.

.PARAMETER ScriptPath
    Local path to poll-metrics.sh. Default: same folder as this script.

.PARAMETER OutputDir
    Local folder to save the returned CSV into. Default: current directory.

.EXAMPLE
    .\Invoke-RemoteBaseline.ps1 -LinuxHost rhel01.contoso.local -User jdoe -DurationMinutes 30

.EXAMPLE
    .\Invoke-RemoteBaseline.ps1 -LinuxHost 10.0.1.15 -User jdoe -DurationMinutes 5 -IntervalSeconds 2
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LinuxHost,

    [Parameter(Mandatory = $true)]
    [string]$User,

    [Parameter(Mandatory = $true)]
    [int]$DurationMinutes,

    [int]$IntervalSeconds = 5,

    [string]$ScriptPath = (Join-Path $PSScriptRoot "poll-metrics.sh"),

    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ScriptPath)) {
    throw "poll-metrics.sh not found at: $ScriptPath"
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$target      = "${User}@${LinuxHost}"
$timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$remoteScript = "/tmp/poll-metrics_$timestamp.sh"
$remoteCsvGlob = "~/*_metrics_$timestamp*.csv"

# Unique control socket per host so parallel runs against different hosts don't collide
$controlDir  = Join-Path $env:TEMP "ssh-mux"
if (-not (Test-Path $controlDir)) { New-Item -ItemType Directory -Path $controlDir | Out-Null }
$controlPath = Join-Path $controlDir "$LinuxHost.sock"

$sshMuxOpts = @(
    "-o", "ControlMaster=auto"
    "-o", "ControlPath=$controlPath"
    "-o", "ControlPersist=5m"
)

function Start-MasterConnection {
    Write-Host "Connecting to $target (you'll be prompted once)..."
    # -f backgrounds after auth, -N opens no command channel, -M forces master mode
    $args = @("-f", "-N", "-M") + $sshMuxOpts + @($target)
    $proc = Start-Process -FilePath "ssh" -ArgumentList $args -NoNewWindow -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        throw "Failed to establish SSH master connection to $target"
    }
}

function Stop-MasterConnection {
    $args = @("-O", "exit") + $sshMuxOpts + @($target)
    Start-Process -FilePath "ssh" -ArgumentList $args -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
}

try {
    Start-MasterConnection

    Write-Host "Copying poll-metrics.sh to $LinuxHost..."
    & scp @sshMuxOpts $ScriptPath "${target}:${remoteScript}"
    if ($LASTEXITCODE -ne 0) { throw "scp (upload) failed" }

    Write-Host "Running poll-metrics.sh on $LinuxHost for $DurationMinutes minute(s), $IntervalSeconds`s interval..."
    $remoteCmd = "chmod +x $remoteScript && $remoteScript $DurationMinutes $IntervalSeconds && rm -f $remoteScript"
    & ssh @sshMuxOpts $target $remoteCmd
    if ($LASTEXITCODE -ne 0) { throw "Remote script execution failed" }

    Write-Host "Copying CSV back to $OutputDir..."
    & scp @sshMuxOpts "${target}:~/${LinuxHost}_metrics_*.csv" $OutputDir
    if ($LASTEXITCODE -ne 0) { throw "scp (download) failed" }

    Write-Host ""
    Write-Host "Done. CSV saved under: $OutputDir"
}
finally {
    Stop-MasterConnection
}

<#
NOTES

1. Password prompts: with ControlMaster multiplexing, you're prompted once
   at the start (Start-MasterConnection). The scp upload, ssh run, and scp
   download all reuse that authenticated connection.

2. For zero prompts (fully unattended / scheduled runs), set up SSH key
   auth instead of relying on multiplexing alone:
     - Generate a key locally:      ssh-keygen -t ed25519
     - Copy it to the target:       type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh <user>@<host> "cat >> ~/.ssh/authorized_keys"
   Once key auth works, this script needs no password at all, and
   ControlMaster just saves you the repeated handshake overhead.

3. Multiple hosts: wrap a call to this script in a foreach loop, e.g.
     $hosts = "rhel01","rhel02","rhel03"
     foreach ($h in $hosts) {
         .\Invoke-RemoteBaseline.ps1 -LinuxHost $h -User jdoe -DurationMinutes 30
     }
   Each host gets its own control socket, so they won't interfere with
   each other even if run in parallel via Start-Job/ForEach-Object -Parallel.

4. Requires the Windows OpenSSH client (ssh, scp) — confirm with
   Get-Command ssh. Included by default from Windows 10 1809 / Server 2019
   onward.
#>
