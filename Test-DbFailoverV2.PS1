<#
.SYNOPSIS
    Repeatedly connects to a SQL Server / Azure SQL database for a set duration,
    logging success/fail and timings. Optionally polls Windows cluster node state
    and Availability Group replica health and logs every state change.
    Intended to run during a failover test.

.EXAMPLE
    .\Test-DbFailover.ps1 -Server "sqllistener.contoso.com" -Database "AppDb" -DurationSeconds 300

.EXAMPLE
    .\Test-DbFailover.ps1 -Server "sqllistener.contoso.com" -Database "AppDb" -DurationSeconds 600 `
        -ClusterName "SQLCLU01" -CheckReplicas -PollSeconds 3 -LogPath .\failover.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'master',
    [Parameter(Mandatory)][int]$DurationSeconds,
    [int]$IntervalMs = 1000,
    [int]$ConnectTimeoutSeconds = 5,
    [System.Management.Automation.PSCredential]$Credential,   # omit for Windows integrated auth
    [switch]$MultiSubnetFailover,                               # use for AG listeners across subnets
    [switch]$TrustServerCertificate,
    [string]$ClusterName,                                       # poll Windows cluster node/role state
    [switch]$CheckReplicas,                                     # poll AG replica health via the connection
    [int]$PollSeconds = 5,                                      # how often to poll cluster/replica state
    [string]$LogPath                                            # optional CSV output (+ <name>-events.csv)
)

# ---------- Setup ----------
if ($ClusterName -and -not (Get-Module -ListAvailable -Name FailoverClusters)) {
    Write-Warning "FailoverClusters module not found (install RSAT: Failover Clustering Tools). Cluster polling disabled."
    $ClusterName = $null
}

$sb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
$sb['Data Source']       = $Server
$sb['Initial Catalog']   = $Database
$sb['Connect Timeout']   = $ConnectTimeoutSeconds
$sb['Pooling']           = $false        # force a genuinely new connection every attempt
$sb['Application Name']  = 'FailoverTest'
if ($MultiSubnetFailover)    { $sb['MultiSubnetFailover'] = $true }
if ($TrustServerCertificate) { $sb['TrustServerCertificate'] = $true }
if ($Credential) {
    $sb['User ID']  = $Credential.UserName
    $sb['Password'] = $Credential.GetNetworkCredential().Password
} else {
    $sb['Integrated Security'] = $true
}
$connString = $sb.ConnectionString

$results      = New-Object System.Collections.Generic.List[object]
$outages      = New-Object System.Collections.Generic.List[object]
$events       = New-Object System.Collections.Generic.List[object]
$prevState    = @{ Cluster = $null; Replica = $null }
$pollEnabled  = [bool]($ClusterName -or $CheckReplicas)
$pollClock    = $null
$inOutage     = $false
$outageStart  = $null
$lastServer   = $null
$attempt      = 0

# ---------- Helpers ----------
function Get-ClusterSnapshot {
    $snap = @{}
    try {
        foreach ($n in Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop) {
            $snap["Node $($n.Name)"] = [string]$n.State
        }
        foreach ($g in Get-ClusterGroup -Cluster $ClusterName -ErrorAction Stop) {
            $snap["Role $($g.Name)"] = "$($g.OwnerNode) ($($g.State))"
        }
    }
    catch { $snap['Cluster query'] = 'FAILED' }
    $snap
}

function Register-StateChange {
    param([string]$Layer, [hashtable]$Current)
    $prev = $script:prevState[$Layer]
    $now  = Get-Date
    if ($null -eq $prev) {
        Write-Host "  Baseline ($Layer):" -ForegroundColor DarkCyan
        foreach ($k in ($Current.Keys | Sort-Object)) {
            Write-Host ("    {0} = {1}" -f $k, $Current[$k]) -ForegroundColor DarkCyan
        }
    }
    else {
        $keys = @($prev.Keys) + @($Current.Keys) | Select-Object -Unique
        foreach ($k in $keys) {
            $old = if ($prev.ContainsKey($k))    { $prev[$k] }    else { '(absent)' }
            $new = if ($Current.ContainsKey($k)) { $Current[$k] } else { '(absent)' }
            if ($old -ne $new) {
                Write-Host ("[{0}] STATE CHANGE ({1}) {2}: {3} -> {4}" -f $now.ToString('HH:mm:ss.fff'), $Layer, $k, $old, $new) -ForegroundColor Magenta
                $script:events.Add([pscustomobject]@{
                    Timestamp = $now.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    Layer     = $Layer
                    Item      = $k
                    From      = $old
                    To        = $new
                })
            }
        }
    }
    $script:prevState[$Layer] = $Current
}

# ---------- Main loop ----------
$testClock = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "Starting failover test: $Server / $Database for $DurationSeconds s (interval $IntervalMs ms)" -ForegroundColor Cyan
if ($ClusterName)   { Write-Host "Cluster polling : $ClusterName every $PollSeconds s" -ForegroundColor Cyan }
if ($CheckReplicas) { Write-Host "Replica polling : via connection every $PollSeconds s" -ForegroundColor Cyan }
Write-Host "Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

while ($testClock.Elapsed.TotalSeconds -lt $DurationSeconds) {
    $attempt++
    $loopClock  = [System.Diagnostics.Stopwatch]::StartNew()
    $timestamp  = Get-Date
    $success    = $false
    $connectMs  = $null
    $queryMs    = $null
    $serverName = $null
    $err        = $null
    $replicaSnap = $null
    $pollDue    = $pollEnabled -and ($null -eq $pollClock -or $pollClock.Elapsed.TotalSeconds -ge $PollSeconds)
    $conn       = New-Object System.Data.SqlClient.SqlConnection $connString

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $conn.Open()
        $connectMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

        $sw.Restart()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText    = 'SELECT @@SERVERNAME'
        $cmd.CommandTimeout = $ConnectTimeoutSeconds
        $serverName = [string]$cmd.ExecuteScalar()
        $queryMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
        $success = $true

        # Replica health (needs VIEW SERVER STATE). Failure here does not fail the connection test.
        if ($pollDue -and $CheckReplicas) {
            try {
                $cmd2 = $conn.CreateCommand()
                $cmd2.CommandTimeout = $ConnectTimeoutSeconds
                $cmd2.CommandText = @"
SELECT ar.replica_server_name, ars.role_desc, ars.connected_state_desc, ars.synchronization_health_desc
FROM sys.availability_replicas ar
JOIN sys.dm_hadr_availability_replica_states ars ON ar.replica_id = ars.replica_id
"@
                $rdr = $cmd2.ExecuteReader()
                $replicaSnap = @{}
                while ($rdr.Read()) {
                    $replicaSnap["Replica $($rdr[0])"] = "role=$($rdr[1]) connected=$($rdr[2]) health=$($rdr[3])"
                }
                $rdr.Close()
            }
            catch { $replicaSnap = @{ 'Replica query' = 'FAILED' } }
        }
    }
    catch {
        $err = $_.Exception.Message -replace '\s+', ' '
        if ($null -eq $connectMs) { $connectMs = [math]::Round($loopClock.Elapsed.TotalMilliseconds, 1) }
    }
    finally {
        $conn.Dispose()
    }

    # Outage tracking
    if (-not $success -and -not $inOutage) {
        $inOutage = $true; $outageStart = $timestamp
    }
    elseif ($success -and $inOutage) {
        $inOutage = $false
        $outages.Add([pscustomobject]@{
            Start    = $outageStart
            End      = $timestamp
            Duration = [math]::Round(($timestamp - $outageStart).TotalSeconds, 1)
        })
    }

    # Console output
    $ts = $timestamp.ToString('HH:mm:ss.fff')
    if ($success) {
        Write-Host ("[{0}] #{1,-4} OK    connect={2}ms query={3}ms server={4}" -f $ts, $attempt, $connectMs, $queryMs, $serverName) -ForegroundColor Green
        if ($lastServer -and $serverName -ne $lastServer) {
            Write-Host "        >> Server changed: $lastServer -> $serverName" -ForegroundColor Yellow
        }
        $lastServer = $serverName
    } else {
        Write-Host ("[{0}] #{1,-4} FAIL  after={2}ms  {3}" -f $ts, $attempt, $connectMs, $err) -ForegroundColor Red
    }

    $results.Add([pscustomobject]@{
        Attempt   = $attempt
        Timestamp = $timestamp.ToString('yyyy-MM-dd HH:mm:ss.fff')
        Success   = $success
        ConnectMs = $connectMs
        QueryMs   = $queryMs
        Server    = $serverName
        Error     = $err
    })

    # Cluster / replica state polling
    if ($pollDue) {
        if ($ClusterName)  { Register-StateChange -Layer 'Cluster' -Current (Get-ClusterSnapshot) }
        if ($replicaSnap)  { Register-StateChange -Layer 'Replica' -Current $replicaSnap }
        $pollClock = [System.Diagnostics.Stopwatch]::StartNew()
    }

    # Wait out the remainder of the interval
    $sleep = $IntervalMs - [int]$loopClock.Elapsed.TotalMilliseconds
    if ($sleep -gt 0 -and $testClock.Elapsed.TotalSeconds -lt $DurationSeconds) {
        Start-Sleep -Milliseconds $sleep
    }
}

# Close off an outage still in progress at test end
if ($inOutage) {
    $outages.Add([pscustomobject]@{
        Start    = $outageStart
        End      = $null
        Duration = [math]::Round(((Get-Date) - $outageStart).TotalSeconds, 1)
    })
}

# ---------- Summary ----------
$ok   = @($results | Where-Object Success)
$fail = @($results | Where-Object { -not $_.Success })

Write-Host "`n=========== SUMMARY ===========" -ForegroundColor Cyan
Write-Host ("Total attempts : {0}" -f $results.Count)
Write-Host ("Successful     : {0}" -f $ok.Count)   -ForegroundColor Green
Write-Host ("Failed         : {0}" -f $fail.Count) -ForegroundColor $(if ($fail.Count) { 'Red' } else { 'Green' })

if ($ok.Count) {
    $c = $ok.ConnectMs | Measure-Object -Average -Minimum -Maximum
    Write-Host ("Connect time   : avg {0:N1} ms, min {1:N1} ms, max {2:N1} ms" -f $c.Average, $c.Minimum, $c.Maximum)
}

if ($outages.Count) {
    Write-Host "`nOutage windows (first failure -> first success):" -ForegroundColor Yellow
    foreach ($o in $outages) {
        $endText = if ($o.End) { $o.End.ToString('HH:mm:ss.fff') } else { 'NOT RECOVERED' }
        Write-Host ("  {0} -> {1}  ({2} s)" -f $o.Start.ToString('HH:mm:ss.fff'), $endText, $o.Duration)
    }
} else {
    Write-Host "`nNo outages detected."
}

if ($pollEnabled) {
    Write-Host "`nCluster / replica state timeline:" -ForegroundColor Magenta
    if ($events.Count) {
        foreach ($e in $events) {
            Write-Host ("  {0}  [{1}] {2}: {3} -> {4}" -f $e.Timestamp.Substring(11), $e.Layer, $e.Item, $e.From, $e.To)
        }
    } else {
        Write-Host "  No state changes detected."
    }
}

if ($LogPath) {
    $results | Export-Csv -Path $LogPath -NoTypeInformation
    Write-Host "`nDetailed log written to $LogPath"
    if ($pollEnabled -and $events.Count) {
        $eventsPath = ($LogPath -replace '\.csv$', '') + '-events.csv'
        $events | Export-Csv -Path $eventsPath -NoTypeInformation
        Write-Host "State change log written to $eventsPath"
    }
}
