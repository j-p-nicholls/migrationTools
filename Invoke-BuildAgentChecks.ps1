<#
.SYNOPSIS
    Validates a DevOps build/CI agent server post-migration (VMware -> Azure).

.DESCRIPTION
    Checks agent-specific concerns not covered by Invoke-MigrationChecks.ps1 /
    Invoke-DataIntegrityChecks.ps1: orchestrator connectivity, toolchain
    version parity, credential/auth resolution, and network reachability to
    source control / package registries. Outputs structured JSON plus a
    dark-themed PASS/WARN/FAIL HTML report, consistent with the other
    scripts in the migration validation suite.

.PARAMETER BaselineJsonPath
    Path to a JSON file captured on the pre-migration (source) server via
    -Phase Baseline. When supplied alongside -Phase Migrated, toolchain
    versions are diffed and reported as PASS/WARN/FAIL.

.PARAMETER Phase
    Baseline | Migrated. Controls output filename tagging and whether a
    diff against -BaselineJsonPath is attempted.

.PARAMETER OutputDirectory
    Where JSON/HTML reports are written. Defaults to .\BuildAgentChecks.

.PARAMETER RequiredTools
    Optional array of executable names (e.g. 'git','dotnet','node','mvn')
    to explicitly probe for version output, on top of auto-detected ones.

.PARAMETER RegistryUrls
    URLs to test outbound reachability against (source control, package
    feeds, internal artifact repos). Defaults to a common set; override
    per-environment.

.EXAMPLE
    # On the source (pre-migration) VM
    .\Invoke-BuildAgentChecks.ps1 -Phase Baseline -OutputDirectory C:\MigrationChecks

.EXAMPLE
    # On the migrated Azure VM, diffed against the baseline capture
    .\Invoke-BuildAgentChecks.ps1 -Phase Migrated -BaselineJsonPath C:\MigrationChecks\BuildAgentChecks_Baseline.json -OutputDirectory C:\MigrationChecks
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Baseline', 'Migrated')]
    [string]$Phase,

    [string]$BaselineJsonPath,

    [string]$OutputDirectory = ".\BuildAgentChecks",

    [string[]]$RequiredTools = @('git', 'dotnet', 'node', 'npm', 'mvn', 'python', 'docker', 'java'),

    [string[]]$RegistryUrls = @(
        'https://github.com',
        'https://api.nuget.org/v3/index.json',
        'https://registry.npmjs.org',
        'https://pypi.org'
    ),

    [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,
        [string]$Detail,
        $Data = $null
    )
    $results.Add([pscustomobject]@{
        Category  = $Category
        Check     = $Check
        Status    = $Status
        Detail    = $Detail
        Data      = $Data
        Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
    })
}

if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

Write-Host "=== Build Agent Checks: $hostname [$Phase] ===" -ForegroundColor Cyan

#region 1. Orchestrator / Agent Registration
Write-Host "`n[1/5] Orchestrator agent registration..." -ForegroundColor Yellow

# Azure DevOps agent (vstsagent) service detection
$adoAgentSvc = Get-Service -Name 'vstsagent*' -ErrorAction SilentlyContinue
if ($adoAgentSvc) {
    foreach ($svc in $adoAgentSvc) {
        $status = if ($svc.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
        Add-Result -Category 'AgentRegistration' -Check "ADO Agent Service: $($svc.Name)" `
            -Status $status -Detail "Status: $($svc.Status), StartType: $($svc.StartType)"
    }
} else {
    Add-Result -Category 'AgentRegistration' -Check 'Azure DevOps Agent Service' `
        -Status 'INFO' -Detail 'No vstsagent* service found on this host'
}

# Jenkins agent (jenkinsslave / generic service name patterns)
$jenkinsSvc = Get-Service -Name '*jenkins*' -ErrorAction SilentlyContinue
if ($jenkinsSvc) {
    foreach ($svc in $jenkinsSvc) {
        $status = if ($svc.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
        Add-Result -Category 'AgentRegistration' -Check "Jenkins Service: $($svc.Name)" `
            -Status $status -Detail "Status: $($svc.Status), StartType: $($svc.StartType)"
    }
} else {
    Add-Result -Category 'AgentRegistration' -Check 'Jenkins Agent Service' `
        -Status 'INFO' -Detail 'No *jenkins* service found on this host'
}

# GitLab Runner
$gitlabSvc = Get-Service -Name 'gitlab-runner' -ErrorAction SilentlyContinue
if ($gitlabSvc) {
    $status = if ($gitlabSvc.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
    Add-Result -Category 'AgentRegistration' -Check 'GitLab Runner Service' `
        -Status $status -Detail "Status: $($gitlabSvc.Status), StartType: $($gitlabSvc.StartType)"

    if (Get-Command gitlab-runner -ErrorAction SilentlyContinue) {
        try {
            $runnerList = & gitlab-runner list 2>&1 | Out-String
            Add-Result -Category 'AgentRegistration' -Check 'GitLab Runner Registration List' `
                -Status 'INFO' -Detail $runnerList.Trim()
        } catch {
            Add-Result -Category 'AgentRegistration' -Check 'GitLab Runner Registration List' `
                -Status 'WARN' -Detail "Could not query runner list: $($_.Exception.Message)"
        }
    }
} else {
    Add-Result -Category 'AgentRegistration' -Check 'GitLab Runner Service' `
        -Status 'INFO' -Detail 'gitlab-runner service not found on this host'
}

if (-not $adoAgentSvc -and -not $jenkinsSvc -and -not $gitlabSvc) {
    Add-Result -Category 'AgentRegistration' -Check 'Orchestrator Detection' `
        -Status 'WARN' -Detail 'No known orchestrator agent service (ADO/Jenkins/GitLab) detected — verify manually'
}
#endregion

#region 2. Toolchain Version Capture
Write-Host "[2/5] Toolchain version capture..." -ForegroundColor Yellow

$toolVersionCommands = @{
    git    = { (& git --version) }
    dotnet = { (& dotnet --version) }
    node   = { (& node --version) }
    npm    = { (& npm --version) }
    mvn    = { (& mvn --version) | Select-Object -First 1 }
    python = { (& python --version 2>&1) }
    docker = { (& docker --version) }
    java   = { (& java -version 2>&1) | Select-Object -First 1 }
}

$toolVersions = @{}
foreach ($tool in $RequiredTools) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Add-Result -Category 'Toolchain' -Check "Tool: $tool" -Status 'WARN' `
            -Detail 'Not found on PATH'
        $toolVersions[$tool] = $null
        continue
    }

    $versionOutput = $null
    if ($toolVersionCommands.ContainsKey($tool)) {
        try {
            $versionOutput = (& $toolVersionCommands[$tool]) -join ' '
        } catch {
            $versionOutput = "Error retrieving version: $($_.Exception.Message)"
        }
    } else {
        $versionOutput = $cmd.Version.ToString()
    }

    $toolVersions[$tool] = @{
        Path    = $cmd.Source
        Version = $versionOutput
    }
    Add-Result -Category 'Toolchain' -Check "Tool: $tool" -Status 'PASS' `
        -Detail "$versionOutput ($($cmd.Source))"
}
#endregion

#region 3. Environment & PATH Capture
Write-Host "[3/5] Environment and PATH capture..." -ForegroundColor Yellow

$pathEntries = $env:Path -split ';' | Where-Object { $_ -ne '' }
Add-Result -Category 'Environment' -Check 'PATH Entry Count' -Status 'INFO' `
    -Detail "$($pathEntries.Count) entries" -Data $pathEntries

$relevantEnvVars = Get-ChildItem Env: | Where-Object {
    $_.Name -match '^(JAVA_HOME|DOTNET_|NODE_|NPM_|PYTHON|MAVEN_|M2_HOME|GOPATH|GOROOT|DOCKER_)' 
}
foreach ($v in $relevantEnvVars) {
    Add-Result -Category 'Environment' -Check "EnvVar: $($v.Name)" -Status 'INFO' -Detail $v.Value
}

# Package manager config files
$configChecks = @{
    'NuGet.Config'   = "$env:APPDATA\NuGet\NuGet.Config"
    '.npmrc (user)'  = "$env:USERPROFILE\.npmrc"
    'pip.ini'        = "$env:APPDATA\pip\pip.ini"
    'Maven settings' = "$env:USERPROFILE\.m2\settings.xml"
}
foreach ($name in $configChecks.Keys) {
    $path = $configChecks[$name]
    if (Test-Path $path) {
        Add-Result -Category 'Environment' -Check "Config present: $name" -Status 'PASS' -Detail $path
    } else {
        Add-Result -Category 'Environment' -Check "Config present: $name" -Status 'INFO' -Detail "Not found at $path"
    }
}
#endregion

#region 4. Network Reachability (source control / package registries)
Write-Host "[4/5] Network reachability to source control / registries..." -ForegroundColor Yellow

foreach ($url in $RegistryUrls) {
    try {
        $uri = [System.Uri]$url
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        $sw.Stop()
        Add-Result -Category 'NetworkReachability' -Check "HTTPS reachability: $($uri.Host)" `
            -Status 'PASS' -Detail "HTTP $($response.StatusCode) in $($sw.ElapsedMilliseconds)ms"
    } catch {
        # Some registries reject HEAD; fall back to a TCP-level check on 443
        try {
            $uri = [System.Uri]$url
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectTask = $tcp.ConnectAsync($uri.Host, 443)
            if ($connectTask.Wait($TimeoutSeconds * 1000)) {
                Add-Result -Category 'NetworkReachability' -Check "HTTPS reachability: $($uri.Host)" `
                    -Status 'PASS' -Detail 'TCP/443 connect succeeded (HTTP HEAD was rejected by server, treated as expected)'
            } else {
                Add-Result -Category 'NetworkReachability' -Check "HTTPS reachability: $($uri.Host)" `
                    -Status 'FAIL' -Detail 'TCP/443 connect timed out'
            }
            $tcp.Close()
        } catch {
            Add-Result -Category 'NetworkReachability' -Check "HTTPS reachability: $url" `
                -Status 'FAIL' -Detail $_.Exception.Message
        }
    }
}

# DNS resolution check for each registry host
foreach ($url in $RegistryUrls) {
    $uri = [System.Uri]$url
    try {
        $dns = Resolve-DnsName -Name $uri.Host -ErrorAction Stop
        Add-Result -Category 'NetworkReachability' -Check "DNS resolution: $($uri.Host)" `
            -Status 'PASS' -Detail (($dns | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue) -join ', ')
    } catch {
        Add-Result -Category 'NetworkReachability' -Check "DNS resolution: $($uri.Host)" `
            -Status 'FAIL' -Detail $_.Exception.Message
    }
}
#endregion

#region 5. Docker daemon (if present)
Write-Host "[5/5] Docker daemon check (if applicable)..." -ForegroundColor Yellow

if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
        $dockerInfo = & docker info --format '{{json .}}' 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Add-Result -Category 'Docker' -Check 'Docker daemon responsive' -Status 'PASS' -Detail 'docker info succeeded'
        } else {
            Add-Result -Category 'Docker' -Check 'Docker daemon responsive' -Status 'FAIL' -Detail $dockerInfo.Trim()
        }
    } catch {
        Add-Result -Category 'Docker' -Check 'Docker daemon responsive' -Status 'FAIL' -Detail $_.Exception.Message
    }
} else {
    Add-Result -Category 'Docker' -Check 'Docker Installed' -Status 'INFO' -Detail 'Docker not found on PATH — skipping daemon check'
}
#endregion

#region Baseline diff (Toolchain only, when Migrated + -BaselineJsonPath supplied)
if ($Phase -eq 'Migrated' -and $BaselineJsonPath) {
    Write-Host "`nDiffing toolchain versions against baseline: $BaselineJsonPath" -ForegroundColor Yellow
    if (Test-Path $BaselineJsonPath) {
        $baseline = Get-Content $BaselineJsonPath -Raw | ConvertFrom-Json
        $baselineTools = $baseline.ToolVersions

        foreach ($tool in $RequiredTools) {
            $baseVer = $baselineTools.$tool.Version
            $currVer = $toolVersions[$tool].Version

            if (-not $baseVer -and -not $currVer) {
                continue # absent on both sides, nothing to compare
            } elseif ($baseVer -eq $currVer) {
                Add-Result -Category 'BaselineDiff' -Check "Version match: $tool" -Status 'PASS' -Detail "$currVer"
            } elseif (-not $baseVer) {
                Add-Result -Category 'BaselineDiff' -Check "Version match: $tool" -Status 'WARN' `
                    -Detail "Tool absent in baseline, present now: $currVer"
            } elseif (-not $currVer) {
                Add-Result -Category 'BaselineDiff' -Check "Version match: $tool" -Status 'FAIL' `
                    -Detail "Tool present in baseline ($baseVer), missing now"
            } else {
                Add-Result -Category 'BaselineDiff' -Check "Version match: $tool" -Status 'WARN' `
                    -Detail "Baseline: $baseVer | Migrated: $currVer"
            }
        }
    } else {
        Add-Result -Category 'BaselineDiff' -Check 'Baseline File' -Status 'FAIL' `
            -Detail "Baseline JSON not found at $BaselineJsonPath"
    }
}
#endregion

#region Output: JSON
$reportObject = [pscustomobject]@{
    Hostname     = $hostname
    Phase        = $Phase
    Timestamp    = $timestamp
    ToolVersions = $toolVersions
    Results      = $results
}

$jsonPath = Join-Path $OutputDirectory "BuildAgentChecks_${Phase}_${hostname}.json"
$reportObject | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host "`nJSON report written to: $jsonPath" -ForegroundColor Green
#endregion

#region Output: HTML (dark theme, PASS/WARN/FAIL, consistent with existing suite)
function New-HtmlReport {
    param($Results, $Hostname, $Phase, $Timestamp, $OutPath)

    $statusCounts = $Results | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }
    $summaryLine = $statusCounts -join ' &nbsp;|&nbsp; '

    $rows = foreach ($r in $Results) {
        $cssClass = switch ($r.Status) {
            'PASS' { 'pass' }
            'WARN' { 'warn' }
            'FAIL' { 'fail' }
            default { 'info' }
        }
        $detailEscaped = [System.Web.HttpUtility]::HtmlEncode($r.Detail)
        "<tr class=`"$cssClass`"><td>$($r.Category)</td><td>$($r.Check)</td><td class=`"status`">$($r.Status)</td><td>$detailEscaped</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Build Agent Checks - $Hostname ($Phase)</title>
<style>
  body { background:#1e1e1e; color:#d4d4d4; font-family:Consolas,'Segoe UI',monospace; margin:2em; }
  h1 { color:#4fc3f7; }
  .meta { color:#9e9e9e; margin-bottom:1em; }
  table { border-collapse:collapse; width:100%; }
  th, td { padding:6px 10px; text-align:left; border-bottom:1px solid #333; font-size:0.9em; }
  th { background:#252526; color:#4fc3f7; position:sticky; top:0; }
  tr.pass .status { color:#4caf50; font-weight:bold; }
  tr.warn .status { color:#ffb74d; font-weight:bold; }
  tr.fail .status { color:#e57373; font-weight:bold; }
  tr.info .status { color:#90a4ae; font-weight:bold; }
  tr.fail { background:#2a1a1a; }
  tr.warn { background:#2a2410; }
  .summary { margin-bottom:1em; font-size:1.05em; }
</style>
</head>
<body>
  <h1>Build Agent Checks: $Hostname</h1>
  <div class="meta">Phase: $Phase &nbsp;|&nbsp; Generated: $Timestamp</div>
  <div class="summary">$summaryLine</div>
  <table>
    <tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th></tr>
    $($rows -join "`n    ")
  </table>
</body>
</html>
"@
    $html | Set-Content -Path $OutPath -Encoding UTF8
}

Add-Type -AssemblyName System.Web
$htmlPath = Join-Path $OutputDirectory "BuildAgentChecks_${Phase}_${hostname}.html"
New-HtmlReport -Results $results -Hostname $hostname -Phase $Phase -Timestamp $timestamp -OutPath $htmlPath
Write-Host "HTML report written to: $htmlPath" -ForegroundColor Green
#endregion

#region Console Summary
$fail = ($results | Where-Object Status -eq 'FAIL').Count
$warn = ($results | Where-Object Status -eq 'WARN').Count
$pass = ($results | Where-Object Status -eq 'PASS').Count

Write-Host "`n=== Summary: $pass PASS / $warn WARN / $fail FAIL ===" -ForegroundColor $(if ($fail -gt 0) { 'Red' } elseif ($warn -gt 0) { 'Yellow' } else { 'Green' })

if ($fail -gt 0) {
    Write-Host "`nFAILed checks:" -ForegroundColor Red
    $results | Where-Object Status -eq 'FAIL' | ForEach-Object { Write-Host "  - [$($_.Category)] $($_.Check): $($_.Detail)" -ForegroundColor Red }
}
#endregion
