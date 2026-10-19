<#
.SYNOPSIS
    Repeatedly connects to a SQL Server / Azure SQL database for a set duration,
    logging success/fail and timings. Optionally runs a custom query on every attempt.
    Intended to run during a failover test.

.EXAMPLE
    .\Test-DbFailover-Query.ps1 -Server "sqllistener.contoso.com" -Database "AppDb" -DurationSeconds 300

.EXAMPLE
    .\Test-DbFailover-Query.ps1 -Server "sqllistener.contoso.com" -Database "AppDb" -DurationSeconds 300 `
        -Query "SELECT COUNT(*) FROM dbo.Orders" -LogPath .\failover.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'master',
    [Parameter(Mandatory)][int]$DurationSeconds,
    [int]$IntervalMs = 1000,
    [int]$ConnectTimeoutSeconds = 5,
    [string]$Query,                                             # optional extra query run every attempt
    [int]$QueryTimeoutSeconds = 30,                             # timeout for the custom query
    [System.Management.Automation.PSCredential]$Credential,   # omit for Windows integrated auth
    [switch]$MultiSubnetFailover,                               # use for AG listeners across subnets
    [switch]$TrustServerCertificate,
    [string]$LogPath                                            # optional CSV output
)

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

$results     = New-Object System.Collections.Generic.List[object]
$outages     = New-Object System.Collections.Generic.List[object]
$inOutage    = $false
$outageStart = $null
$lastServer  = $null
$attempt     = 0
$testClock   = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Starting failover test: $Server / $Database for $DurationSeconds s (interval $IntervalMs ms)" -ForegroundColor Cyan
if ($Query) { Write-Host "Custom query   : $Query" -ForegroundColor Cyan }
Write-Host "Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

while ($testClock.Elapsed.TotalSeconds -lt $DurationSeconds) {
    $attempt++
    $loopClock   = [System.Diagnostics.Stopwatch]::StartNew()
    $timestamp   = Get-Date
    $success     = $false
    $stage       = 'Connect'
    $connectMs   = $null
    $pingMs      = $null
    $queryMs     = $null
    $queryResult = $null
    $serverName  = $null
    $err         = $null
    $conn        = New-Object System.Data.SqlClient.SqlConnection $connString

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $conn.Open()
        $connectMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

        # Basic check: which server answered
        $stage = 'Ping'
        $sw.Restart()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText    = 'SELECT @@SERVERNAME'
        $cmd.CommandTimeout = $ConnectTimeoutSeconds
        $serverName = [string]$cmd.ExecuteScalar()
        $pingMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

        # Optional custom query (first column of first row is recorded)
        if ($Query) {
            $stage = 'Query'
            $sw.Restart()
            $cmd2 = $conn.CreateCommand()
            $cmd2.CommandText    = $Query
            $cmd2.CommandTimeout = $QueryTimeoutSeconds
            $r = $cmd2.ExecuteScalar()
            $queryMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
            $queryResult = if ($null -eq $r -or $r -is [System.DBNull]) { 'NULL' } else { [string]$r }
        }

        $success = $true
    }
    catch {
        $err = $_.Exception.Message -replace '\s+', ' '
        if ($stage -eq 'Connect' -and $null -eq $connectMs) {
            $connectMs = [math]::Round($loopClock.Elapsed.TotalMilliseconds, 1)
        }
    }
    finally {
        $conn.Dispose()
    }

    # Outage tracking (a failed custom query counts as a failure)
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
        $line = "[{0}] #{1,-4} OK    connect={2}ms ping={3}ms" -f $ts, $attempt, $connectMs, $pingMs
        if ($Query) { $line += " query={0}ms result={1}" -f $queryMs, $queryResult }
        $line += " server=$serverName"
        Write-Host $line -ForegroundColor Green
        if ($lastServer -and $serverName -ne $lastServer) {
            Write-Host "        >> Server changed: $lastServer -> $serverName" -ForegroundColor Yellow
        }
        $lastServer = $serverName
    } else {
        Write-Host ("[{0}] #{1,-4} FAIL  stage={2} after={3}ms  {4}" -f $ts, $attempt, $stage, [math]::Round($loopClock.Elapsed.TotalMilliseconds, 1), $err) -ForegroundColor Red
    }

    $results.Add([pscustomobject]@{
        Attempt     = $attempt
        Timestamp   = $timestamp.ToString('yyyy-MM-dd HH:mm:ss.fff')
        Success     = $success
        FailedStage = if ($success) { $null } else { $stage }
        ConnectMs   = $connectMs
        PingMs      = $pingMs
        QueryMs     = $queryMs
        QueryResult = $queryResult
        Server      = $serverName
        Error       = $err
    })

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

# Summary
$ok   = @($results | Where-Object Success)
$fail = @($results | Where-Object { -not $_.Success })

Write-Host "`n=========== SUMMARY ===========" -ForegroundColor Cyan
Write-Host ("Total attempts : {0}" -f $results.Count)
Write-Host ("Successful     : {0}" -f $ok.Count)   -ForegroundColor Green
Write-Host ("Failed         : {0}" -f $fail.Count) -ForegroundColor $(if ($fail.Count) { 'Red' } else { 'Green' })

if ($fail.Count) {
    $byStage = $fail | Group-Object FailedStage | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
    Write-Host ("Failures by stage: {0}" -f ($byStage -join ', '))
}

if ($ok.Count) {
    $c = $ok.ConnectMs | Measure-Object -Average -Minimum -Maximum
    Write-Host ("Connect time   : avg {0:N1} ms, min {1:N1} ms, max {2:N1} ms" -f $c.Average, $c.Minimum, $c.Maximum)
    if ($Query) {
        $q = $ok.QueryMs | Measure-Object -Average -Minimum -Maximum
        Write-Host ("Query time     : avg {0:N1} ms, min {1:N1} ms, max {2:N1} ms" -f $q.Average, $q.Minimum, $q.Maximum)
        $distinct = @($ok.QueryResult | Select-Object -Unique)
        Write-Host ("Query results  : {0}" -f ($distinct -join ', '))
    }
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

if ($LogPath) {
    $results | Export-Csv -Path $LogPath -NoTypeInformation
    Write-Host "`nDetailed log written to $LogPath"
}
