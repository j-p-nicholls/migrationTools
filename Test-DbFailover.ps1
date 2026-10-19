<#
.SYNOPSIS
    Repeatedly connects to a SQL Server / Azure SQL database for a set duration,
    logging success/fail and timings. Intended to run during a failover test.

.EXAMPLE
    .\Test-DbFailover.ps1 -Server "sqllistener.contoso.com" -Database "AppDb" -DurationSeconds 300

.EXAMPLE
    .\Test-DbFailover.ps1 -Server "myserver.database.windows.net" -Database "AppDb" `
        -DurationSeconds 600 -IntervalMs 500 -Credential (Get-Credential) -LogPath .\failover.csv
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
    [string]$LogPath                                            # optional CSV output
)

$sb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
$sb['Data Source']       = $Server
$sb['Initial Catalog']   = $Database
$sb['Connect Timeout']   = $ConnectTimeoutSeconds
$sb['Pooling']           = $false        # force a genuinely new connection every attempt
$sb['Application Name']  = 'FailoverTest'
if ($MultiSubnetFailover)   { $sb['MultiSubnetFailover'] = $true }
if ($TrustServerCertificate){ $sb['TrustServerCertificate'] = $true }
if ($Credential) {
    $sb['User ID']  = $Credential.UserName
    $sb['Password'] = $Credential.GetNetworkCredential().Password
} else {
    $sb['Integrated Security'] = $true
}
$connString = $sb.ConnectionString

$results    = New-Object System.Collections.Generic.List[object]
$outages    = New-Object System.Collections.Generic.List[object]
$inOutage   = $false
$outageStart = $null
$lastServer = $null
$attempt    = 0
$testClock  = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Starting failover test: $Server / $Database for $DurationSeconds s (interval $IntervalMs ms)" -ForegroundColor Cyan
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

if ($LogPath) {
    $results | Export-Csv -Path $LogPath -NoTypeInformation
    Write-Host "`nDetailed log written to $LogPath"
}
