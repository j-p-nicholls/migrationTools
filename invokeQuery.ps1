<#
.SYNOPSIS
    Runs a long-running query against SQL Server / Azure SQL and reports connection time
    and query time. Query output is discarded. No command timeout by default.

.EXAMPLE
    .\Invoke-LongQuery.ps1 -Server "sqlserver01" -Database "AppDb" -Query "SELECT COUNT(*) FROM dbo.BigTable"

.EXAMPLE
    .\Invoke-LongQuery.ps1 -Server "myserver.database.windows.net" -Database "AppDb" `
        -QueryFile .\slow-report.sql -Credential (Get-Credential) -HeartbeatSeconds 60
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'master',
    [string]$Query,                                   # inline T-SQL
    [string]$QueryFile,                               # or a .sql file (no GO separators)
    [int]$QueryTimeoutSeconds = 0,                    # 0 = no timeout
    [int]$ConnectTimeoutSeconds = 15,
    [int]$HeartbeatSeconds = 30,                      # progress message interval while query runs
    [System.Management.Automation.PSCredential]$Credential,   # omit for Windows integrated auth
    [switch]$MultiSubnetFailover,
    [switch]$TrustServerCertificate
)

if (-not $Query -and -not $QueryFile) { throw "Specify -Query or -QueryFile." }
if ($Query -and $QueryFile)           { throw "Specify only one of -Query or -QueryFile." }
if ($QueryFile) {
    if (-not (Test-Path $QueryFile)) { throw "Query file not found: $QueryFile" }
    $Query = Get-Content -Path $QueryFile -Raw
}

$sb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
$sb['Data Source']      = $Server
$sb['Initial Catalog']  = $Database
$sb['Connect Timeout']  = $ConnectTimeoutSeconds
$sb['Application Name'] = 'LongQueryTest'
if ($MultiSubnetFailover)    { $sb['MultiSubnetFailover'] = $true }
if ($TrustServerCertificate) { $sb['TrustServerCertificate'] = $true }
if ($Credential) {
    $sb['User ID']  = $Credential.UserName
    $sb['Password'] = $Credential.GetNetworkCredential().Password
} else {
    $sb['Integrated Security'] = $true
}

$conn      = New-Object System.Data.SqlClient.SqlConnection $sb.ConnectionString
$connectMs = $null
$queryMs   = $null
$rows      = $null
$failure   = $null
$totalClock = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Server   : $Server" -ForegroundColor Cyan
Write-Host "Database : $Database" -ForegroundColor Cyan
Write-Host ("Timeout  : {0}" -f $(if ($QueryTimeoutSeconds -eq 0) { 'none' } else { "$QueryTimeoutSeconds s" })) -ForegroundColor Cyan
Write-Host "Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

try {
    # --- Connect ---
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $conn.Open()
    $connectMs = $sw.Elapsed.TotalMilliseconds
    Write-Host ("Connected in {0:N1} ms" -f $connectMs) -ForegroundColor Green

    # --- Run query ---
    $cmd = $conn.CreateCommand()
    $cmd.CommandText    = $Query
    $cmd.CommandTimeout = $QueryTimeoutSeconds

    Write-Host "Running query..."
    $sw.Restart()
    $task = $cmd.ExecuteNonQueryAsync()      # runs the full query; result rows are read and discarded

    while (-not $task.Wait($HeartbeatSeconds * 1000)) {
        Write-Host ("  ...still running ({0:mm\:ss} elapsed)" -f $sw.Elapsed) -ForegroundColor DarkGray
    }
    $queryMs = $sw.Elapsed.TotalMilliseconds
    $rows    = $task.Result                  # -1 for SELECT; rows affected for DML
}
catch {
    if ($sw) { $queryMs = $sw.Elapsed.TotalMilliseconds }
    $failure = $_.Exception.GetBaseException().Message -replace '\s+', ' '
}
finally {
    if ($conn.State -ne 'Closed') { $conn.Close() }
    $conn.Dispose()
}

# --- Report ---
Write-Host "`n=========== RESULT ===========" -ForegroundColor Cyan
if ($null -ne $connectMs) { Write-Host ("Connection time : {0:N1} ms" -f $connectMs) }
else                      { Write-Host "Connection time : n/a (connection failed)" -ForegroundColor Red }

if ($failure) {
    if ($null -ne $connectMs -and $null -ne $queryMs) {
        Write-Host ("Query time      : {0:N1} s (failed after)" -f ($queryMs / 1000)) -ForegroundColor Red
    }
    Write-Host "Status          : FAILED" -ForegroundColor Red
    Write-Host "Error           : $failure" -ForegroundColor Red
    Write-Host ("Total elapsed   : {0:hh\:mm\:ss\.fff}" -f $totalClock.Elapsed)
    exit 1
}

Write-Host ("Query time      : {0:N1} s ({1:hh\:mm\:ss\.fff})" -f ($queryMs / 1000), [timespan]::FromMilliseconds($queryMs))
if ($rows -ge 0) { Write-Host "Rows affected   : $rows" }
Write-Host "Status          : SUCCESS" -ForegroundColor Green
Write-Host ("Total elapsed   : {0:hh\:mm\:ss\.fff}" -f $totalClock.Elapsed)
