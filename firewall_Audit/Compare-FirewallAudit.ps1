#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Compares firewall audit JSON files produced by Invoke-FirewallAudit.ps1.
    Any two or all three phase files can be supplied - only the diffs possible
    with the provided inputs are run.

    Includes ASG membership diff, ASG-scoped NSG rule diff, and ASG-aware
    IP Flow Verify comparison.

.PARAMETER PreMigrationFile
    Path to the JSON output from the pre-migration (VMware) run.

.PARAMETER ReferenceFile
    Path to the JSON output from the Azure reference VM run.

.PARAMETER MigratedFile
    Path to the JSON output from the migrated Azure VM run.

.PARAMETER OutputPath
    Directory to write the HTML comparison report. Defaults to the script directory.

.EXAMPLE
    # All three phases
    .\Compare-FirewallAudit.ps1 `
        -PreMigrationFile ".\PreMigration_SERVER01_20240101-090000.json" `
        -ReferenceFile    ".\AzureReference_REFVM_20240101-100000.json" `
        -MigratedFile     ".\AzureMigrated_SERVER01_20240101-110000.json"

.EXAMPLE
    # Reference vs Migrated only
    .\Compare-FirewallAudit.ps1 `
        -ReferenceFile ".\AzureReference_REFVM_20240101-100000.json" `
        -MigratedFile  ".\AzureMigrated_SERVER01_20240101-110000.json"
#>
param(
    [string] $PreMigrationFile,
    [string] $ReferenceFile,
    [string] $MigratedFile,
    [string] $OutputPath = $PSScriptRoot
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Validate - at least two files must be supplied
# ---------------------------------------------------------------------------
$suppliedCount = @($PreMigrationFile, $ReferenceFile, $MigratedFile) |
    Where-Object { $_ -ne '' -and $null -ne $_ } |
    Measure-Object | Select-Object -ExpandProperty Count

if ($suppliedCount -lt 2) {
    Write-Host "ERROR: At least two phase files must be supplied." -ForegroundColor Red
    Write-Host "       Use -PreMigrationFile, -ReferenceFile, and/or -MigratedFile."
    exit 1
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "========== $Title ==========" -ForegroundColor Cyan
}

function Read-AuditFile {
    param([string]$Path, [string]$Label)
    if (-not $Path) { return $null }
    if (-not (Test-Path $Path)) {
        Write-Host "File not found for $Label : $Path" -ForegroundColor Red
        exit 1
    }
    return Get-Content $Path -Raw | ConvertFrom-Json
}

function Get-RuleKey {
    param($Rule)
    return "$($Rule.DisplayName)|$($Rule.Enabled)|$($Rule.Action)|$($Rule.Profile)|$($Rule.Protocol)|$($Rule.LocalPort)|$($Rule.RemoteAddress)"
}

function Get-NsgEffectiveKey {
    param($r)
    return "$($r.Priority)|$($r.Access)|$($r.Protocol)|$($r.SourceAddressPrefix)|$($r.SourcePortRange)|$($r.DestinationPortRange)"
}

# Raw NSG rule key preserves ASG names rather than resolved IPs
function Get-NsgRawKey {
    param($r)
    $src = if ($r.SourceASGs) { "ASG:$($r.SourceASGs)" } else { $r.SourceAddressPrefix }
    $dst = if ($r.DestinationASGs) { "ASG:$($r.DestinationASGs)" } else { $r.DestinationAddressPrefix }
    return "$($r.Priority)|$($r.Access)|$($r.Protocol)|$src|$($r.SourcePortRange)|$dst|$($r.DestinationPortRange)"
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Description,
        [string]$Detail = ''
    )
    $findings.Add([PSCustomObject]@{
        Category    = $Category
        Severity    = $Severity
        Description = $Description
        Detail      = $Detail
    })
    $colour = switch ($Severity) {
        'FAIL'  { 'Red'    }
        'WARN'  { 'Yellow' }
        'PASS'  { 'Green'  }
        default { 'White'  }
    }
    Write-Host "  [$Severity] $Description" -ForegroundColor $colour
    if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

function Test-FirewallProfiles {
    param([string]$Label, $Data)
    foreach ($cp in $Data.ConnectionProfiles) {
        if ($cp.NetworkCategory -ne 'DomainAuthenticated') {
            Add-Finding -Category "FirewallProfile" -Severity "FAIL" `
                -Description "$Label : Interface '$($cp.InterfaceAlias)' on '$($cp.NetworkCategory)' - expected DomainAuthenticated" `
                -Detail "The wrong firewall rule set will apply."
        } else {
            Add-Finding -Category "FirewallProfile" -Severity "PASS" `
                -Description "$Label : Interface '$($cp.InterfaceAlias)' correctly on DomainAuthenticated"
        }
    }
}

function Compare-FirewallRules {
    param([string]$LabelA, $DataA, [string]$LabelB, $DataB)
    Write-Section "Firewall Rule Comparison: $LabelA vs $LabelB"

    if (-not $DataA.FirewallRules -or -not $DataB.FirewallRules) {
        Add-Finding -Category "FirewallRules" -Severity "INFO" `
            -Description "One or both datasets have no firewall rules - skipping rule diff for $LabelA vs $LabelB"
        return
    }

    $keysA      = $DataA.FirewallRules | ForEach-Object { Get-RuleKey $_ }
    $keysB      = $DataB.FirewallRules | ForEach-Object { Get-RuleKey $_ }
    $missingInB = $DataA.FirewallRules | Where-Object { (Get-RuleKey $_) -notin $keysB }
    $newInB     = $DataB.FirewallRules | Where-Object { (Get-RuleKey $_) -notin $keysA }

    foreach ($r in $missingInB) {
        Add-Finding -Category "FirewallRules" -Severity "WARN" `
            -Description "Rule in $LabelA missing from $LabelB" `
            -Detail "$($r.DisplayName) | Action:$($r.Action) | Ports:$($r.LocalPort) | Profile:$($r.Profile)"
    }
    foreach ($r in $newInB) {
        Add-Finding -Category "FirewallRules" -Severity "INFO" `
            -Description "Rule in $LabelB not present in $LabelA (new rule)" `
            -Detail "$($r.DisplayName) | Action:$($r.Action) | Ports:$($r.LocalPort) | Profile:$($r.Profile)"
    }
    if (-not $missingInB -and -not $newInB) {
        Add-Finding -Category "FirewallRules" -Severity "PASS" `
            -Description "Firewall rules identical between $LabelA and $LabelB"
    }
}

function Compare-ASGMembership {
    param([string]$LabelA, $DataA, [string]$LabelB, $DataB)
    Write-Section "ASG Membership Comparison: $LabelA vs $LabelB"

    if (-not $DataA.IsAzure -or -not $DataB.IsAzure) {
        Add-Finding -Category "ASGMembership" -Severity "INFO" `
            -Description "ASG comparison skipped - one or both phases are not Azure ($LabelA IsAzure:$($DataA.IsAzure) | $LabelB IsAzure:$($DataB.IsAzure))"
        return
    }

    $asgNamesA = @($DataA.ASGMemberships | ForEach-Object { $_.ASGName } | Sort-Object)
    $asgNamesB = @($DataB.ASGMemberships | ForEach-Object { $_.ASGName } | Sort-Object)

    $missingInB = $asgNamesA | Where-Object { $_ -notin $asgNamesB }
    $newInB     = $asgNamesB | Where-Object { $_ -notin $asgNamesA }

    foreach ($asg in $missingInB) {
        Add-Finding -Category "ASGMembership" -Severity "FAIL" `
            -Description "ASG '$asg' present in $LabelA but MISSING from $LabelB" `
            -Detail "Any NSG rules scoped to this ASG will NOT apply to $LabelB."
    }
    foreach ($asg in $newInB) {
        Add-Finding -Category "ASGMembership" -Severity "INFO" `
            -Description "ASG '$asg' present in $LabelB but not in $LabelA (new membership)" `
            -Detail "Verify this ASG membership is intentional."
    }
    if (-not $missingInB -and -not $newInB) {
        Add-Finding -Category "ASGMembership" -Severity "PASS" `
            -Description "ASG memberships identical between $LabelA and $LabelB ($($asgNamesA -join ', '))"
    }
}

function Compare-NSGRawRules {
    param([string]$LabelA, $DataA, [string]$LabelB, $DataB)
    Write-Section "NSG Raw Rule Comparison (ASG names preserved): $LabelA vs $LabelB"

    if (-not $DataA.IsAzure -or -not $DataB.IsAzure) {
        Add-Finding -Category "NSGRawRules" -Severity "INFO" `
            -Description "Raw NSG rule comparison skipped - one or both phases are not Azure"
        return
    }

    $rulesA = $DataA.NSGRawRules
    $rulesB = $DataB.NSGRawRules

    if (-not $rulesA -or $rulesA.Count -eq 0) {
        Add-Finding -Category "NSGRawRules" -Severity "INFO" `
            -Description "No raw NSG rules recorded in $LabelA"
        return
    }
    if (-not $rulesB -or $rulesB.Count -eq 0) {
        Add-Finding -Category "NSGRawRules" -Severity "WARN" `
            -Description "No raw NSG rules recorded in $LabelB"
        return
    }

    $keysA = $rulesA | ForEach-Object { Get-NsgRawKey $_ }
    $keysB = $rulesB | ForEach-Object { Get-NsgRawKey $_ }

    # All rules
    $missingInB = $rulesA | Where-Object { (Get-NsgRawKey $_) -notin $keysB }
    $newInB     = $rulesB | Where-Object { (Get-NsgRawKey $_) -notin $keysA }

    foreach ($r in $missingInB) {
        $sev    = if ($r.IsASGRule) { 'FAIL' } else { 'WARN' }
        $srcStr = if ($r.SourceASGs) { "SourceASG:$($r.SourceASGs)" } else { "Src:$($r.SourceAddressPrefix)" }
        $dstStr = if ($r.DestinationASGs) { "DstASG:$($r.DestinationASGs)" } else { "Dst:$($r.DestinationAddressPrefix)" }
        Add-Finding -Category "NSGRawRules" -Severity $sev `
            -Description "NSG rule '$($r.Name)' in $LabelA missing from $LabelB$(if ($r.IsASGRule) {' [ASG-SCOPED]'})" `
            -Detail "P:$($r.Priority) | $($r.Access) | $($r.Protocol) | $srcStr | DstPort:$($r.DestinationPortRange) | $dstStr"
    }
    foreach ($r in $newInB) {
        $srcStr = if ($r.SourceASGs) { "SourceASG:$($r.SourceASGs)" } else { "Src:$($r.SourceAddressPrefix)" }
        $dstStr = if ($r.DestinationASGs) { "DstASG:$($r.DestinationASGs)" } else { "Dst:$($r.DestinationAddressPrefix)" }
        Add-Finding -Category "NSGRawRules" -Severity "INFO" `
            -Description "NSG rule '$($r.Name)' in $LabelB not present in $LabelA$(if ($r.IsASGRule) {' [ASG-SCOPED]'})" `
            -Detail "P:$($r.Priority) | $($r.Access) | $($r.Protocol) | $srcStr | DstPort:$($r.DestinationPortRange) | $dstStr"
    }
    if (-not $missingInB -and -not $newInB) {
        Add-Finding -Category "NSGRawRules" -Severity "PASS" `
            -Description "All NSG raw rules (including ASG-scoped) identical between $LabelA and $LabelB"
    }
}

function Compare-NSGEffectiveRules {
    param([string]$LabelA, $DataA, [string]$LabelB, $DataB)
    Write-Section "NSG Effective Rule Comparison (resolved/flattened): $LabelA vs $LabelB"

    if (-not $DataA.IsAzure -or -not $DataB.IsAzure) {
        Add-Finding -Category "NSGEffective" -Severity "INFO" `
            -Description "NSG effective comparison skipped - one or both phases are not Azure"
        return
    }

    $rulesA = $DataA.NSGEffectiveRules
    $rulesB = $DataB.NSGEffectiveRules

    if (-not $rulesA -or $rulesA.Count -eq 0) {
        Add-Finding -Category "NSGEffective" -Severity "INFO" `
            -Description "No effective NSG rules in $LabelA - Az.Network may not have been available"
        return
    }
    if (-not $rulesB -or $rulesB.Count -eq 0) {
        Add-Finding -Category "NSGEffective" -Severity "WARN" `
            -Description "No effective NSG rules in $LabelB - Az.Network may not have been available"
        return
    }

    $keysA      = $rulesA | ForEach-Object { Get-NsgEffectiveKey $_ }
    $keysB      = $rulesB | ForEach-Object { Get-NsgEffectiveKey $_ }
    $missingInB = $rulesA | Where-Object { (Get-NsgEffectiveKey $_) -notin $keysB }
    $newInB     = $rulesB | Where-Object { (Get-NsgEffectiveKey $_) -notin $keysA }

    foreach ($r in $missingInB) {
        Add-Finding -Category "NSGEffective" -Severity "FAIL" `
            -Description "Effective NSG rule in $LabelA missing from $LabelB" `
            -Detail "P:$($r.Priority) | $($r.Access) | $($r.Protocol) | Src:$($r.SourceAddressPrefix) | DstPort:$($r.DestinationPortRange)"
    }
    foreach ($r in $newInB) {
        Add-Finding -Category "NSGEffective" -Severity "INFO" `
            -Description "Effective NSG rule in $LabelB not present in $LabelA" `
            -Detail "P:$($r.Priority) | $($r.Access) | $($r.Protocol) | Src:$($r.SourceAddressPrefix) | DstPort:$($r.DestinationPortRange)"
    }
    if (-not $missingInB -and -not $newInB) {
        Add-Finding -Category "NSGEffective" -Severity "PASS" `
            -Description "NSG effective inbound rules identical between $LabelA and $LabelB"
    }
}

function Compare-IPFlow {
    param([string]$LabelA, $DataA, [string]$LabelB, $DataB)
    Write-Section "IP Flow Verify Comparison: $LabelA vs $LabelB"

    if (-not $DataA.IsAzure -or -not $DataB.IsAzure) {
        Add-Finding -Category "IPFlow" -Severity "INFO" `
            -Description "IP Flow comparison skipped - one or both phases are not Azure"
        return
    }

    $flowsA = $DataA.IPFlowResults
    $flowsB = $DataB.IPFlowResults

    if (-not $flowsA -or $flowsA.Count -eq 0) {
        Add-Finding -Category "IPFlow" -Severity "INFO" `
            -Description "No IP Flow results in $LabelA - Az.Network may not have been available"
        return
    }
    if (-not $flowsB -or $flowsB.Count -eq 0) {
        Add-Finding -Category "IPFlow" -Severity "WARN" `
            -Description "No IP Flow results in $LabelB - Az.Network may not have been available"
        return
    }

    foreach ($flowA in $flowsA) {
        $flowB = $flowsB | Where-Object {
            $_.SourceLabel -eq $flowA.SourceLabel -and $_.Port -eq $flowA.Port
        } | Select-Object -First 1

        if (-not $flowB) {
            Add-Finding -Category "IPFlow" -Severity "WARN" `
                -Description "No IP Flow result for '$($flowA.SourceLabel)':$($flowA.Port) in $LabelB"
            continue
        }

        $asgTag = if ($flowA.SourceType -eq 'ASGMember') { ' [ASG]' } else { '' }

        if ($flowA.Access -ne $flowB.Access) {
            $sev = if ($flowB.Access -eq 'Deny') { 'FAIL' } else { 'WARN' }
            Add-Finding -Category "IPFlow" -Severity $sev `
                -Description "IP Flow access changed$asgTag : '$($flowA.SourceLabel)' -> :$($flowA.Port)" `
                -Detail "$LabelA : $($flowA.Access) [$($flowA.RuleName)]  |  $LabelB : $($flowB.Access) [$($flowB.RuleName)]"
        } else {
            Add-Finding -Category "IPFlow" -Severity "PASS" `
                -Description "IP Flow$asgTag '$($flowA.SourceLabel)' -> :$($flowA.Port) : $($flowA.Access) (consistent)"
        }
    }

    # Flag any Deny in B outright
    $denied = $flowsB | Where-Object { $_.Access -eq 'Deny' }
    foreach ($d in $denied) {
        $asgTag = if ($d.SourceType -eq 'ASGMember') { ' [ASG]' } else { '' }
        Add-Finding -Category "IPFlow" -Severity "FAIL" `
            -Description "Inbound DENIED in $LabelB$asgTag : '$($d.SourceLabel)' -> :$($d.Port)" `
            -Detail "Blocking rule: $($d.RuleName)"
    }
}

# ---------------------------------------------------------------------------
# Load files
# ---------------------------------------------------------------------------
Write-Section "Loading Audit Files"

$pre = Read-AuditFile -Path $PreMigrationFile -Label "PreMigration"
$ref = Read-AuditFile -Path $ReferenceFile    -Label "AzureReference"
$mig = Read-AuditFile -Path $MigratedFile     -Label "AzureMigrated"

if ($pre) { Write-Host "Pre-Migration  : $($pre.Hostname) @ $($pre.Timestamp)"  -ForegroundColor Yellow }
if ($ref) { Write-Host "Azure Reference: $($ref.Hostname) @ $($ref.Timestamp)"  -ForegroundColor Yellow }
if ($mig) { Write-Host "Azure Migrated : $($mig.Hostname) @ $($mig.Timestamp)"  -ForegroundColor Yellow }

Write-Host ""
if      ($pre -and $ref -and $mig) { Write-Host "Mode: Full three-phase comparison"              -ForegroundColor Cyan }
elseif  ($ref -and $mig)           { Write-Host "Mode: Reference vs Migrated"                    -ForegroundColor Cyan }
elseif  ($pre -and $mig)           { Write-Host "Mode: Pre-Migration vs Migrated"                -ForegroundColor Cyan }
elseif  ($pre -and $ref)           { Write-Host "Mode: Pre-Migration vs Reference (planning)"    -ForegroundColor Cyan }

# ---------------------------------------------------------------------------
# Run checks
# ---------------------------------------------------------------------------

# Connection profile checks (Azure phases only)
Write-Section "Firewall Connection Profile Checks"
if ($ref) { Test-FirewallProfiles -Label "AzureReference" -Data $ref }
if ($mig) { Test-FirewallProfiles -Label "AzureMigrated"  -Data $mig }

# Firewall profile default action diffs
$pairs = @()
if ($pre -and $ref) { $pairs += @{ LA='PreMigration';   A=$pre; LB='AzureReference'; B=$ref } }
if ($pre -and $mig) { $pairs += @{ LA='PreMigration';   A=$pre; LB='AzureMigrated';  B=$mig } }
if ($ref -and $mig) { $pairs += @{ LA='AzureReference'; A=$ref; LB='AzureMigrated';  B=$mig } }

foreach ($p in $pairs) {
    Write-Section "Firewall Profile Defaults: $($p.LA) vs $($p.LB)"
    foreach ($profA in $p.A.FirewallProfiles) {
        $profB = $p.B.FirewallProfiles | Where-Object { $_.Name -eq $profA.Name }
        if (-not $profB) { continue }
        if ($profA.DefaultInboundAction -ne $profB.DefaultInboundAction) {
            Add-Finding -Category "FirewallProfile" -Severity "WARN" `
                -Description "Profile '$($profA.Name)' DefaultInboundAction differs: $($p.LA) vs $($p.LB)" `
                -Detail "$($p.LA): $($profA.DefaultInboundAction)  |  $($p.LB): $($profB.DefaultInboundAction)"
        }
        if ($profA.Enabled -ne $profB.Enabled) {
            Add-Finding -Category "FirewallProfile" -Severity "WARN" `
                -Description "Profile '$($profA.Name)' Enabled state differs: $($p.LA) vs $($p.LB)" `
                -Detail "$($p.LA): $($profA.Enabled)  |  $($p.LB): $($profB.Enabled)"
        }
    }
}

# Firewall rules
if ($pre -and $ref) { Compare-FirewallRules -LabelA "PreMigration"   -DataA $pre -LabelB "AzureReference" -DataB $ref }
if ($pre -and $mig) { Compare-FirewallRules -LabelA "PreMigration"   -DataA $pre -LabelB "AzureMigrated"  -DataB $mig }
if ($ref -and $mig) { Compare-FirewallRules -LabelA "AzureReference" -DataA $ref -LabelB "AzureMigrated"  -DataB $mig }

# ASG membership - Azure pairs only
if ($ref -and $mig) { Compare-ASGMembership -LabelA "AzureReference" -DataA $ref -LabelB "AzureMigrated"  -DataB $mig }
if ($pre -and $ref) { Compare-ASGMembership -LabelA "PreMigration"   -DataA $pre -LabelB "AzureReference" -DataB $ref }
if ($pre -and $mig) { Compare-ASGMembership -LabelA "PreMigration"   -DataA $pre -LabelB "AzureMigrated"  -DataB $mig }

# NSG raw rules (ASG names preserved) - Azure pairs only
if ($ref -and $mig) { Compare-NSGRawRules -LabelA "AzureReference" -DataA $ref -LabelB "AzureMigrated"  -DataB $mig }
if ($pre -and $ref) { Compare-NSGRawRules -LabelA "PreMigration"   -DataA $pre -LabelB "AzureReference" -DataB $ref }
if ($pre -and $mig) { Compare-NSGRawRules -LabelA "PreMigration"   -DataA $pre -LabelB "AzureMigrated"  -DataB $mig }

# NSG effective rules (flattened) - Azure pairs only
if ($ref -and $mig) { Compare-NSGEffectiveRules -LabelA "AzureReference" -DataA $ref -LabelB "AzureMigrated"  -DataB $mig }
if ($pre -and $ref) { Compare-NSGEffectiveRules -LabelA "PreMigration"   -DataA $pre -LabelB "AzureReference" -DataB $ref }
if ($pre -and $mig) { Compare-NSGEffectiveRules -LabelA "PreMigration"   -DataA $pre -LabelB "AzureMigrated"  -DataB $mig }

# IP Flow Verify - Azure pairs only
if ($ref -and $mig) { Compare-IPFlow -LabelA "AzureReference" -DataA $ref -LabelB "AzureMigrated"  -DataB $mig }
if ($pre -and $ref) { Compare-IPFlow -LabelA "PreMigration"   -DataA $pre -LabelB "AzureReference" -DataB $ref }
if ($pre -and $mig) { Compare-IPFlow -LabelA "PreMigration"   -DataA $pre -LabelB "AzureMigrated"  -DataB $mig }

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section "Summary"

$fails  = $findings | Where-Object { $_.Severity -eq 'FAIL' }
$warns  = $findings | Where-Object { $_.Severity -eq 'WARN' }
$passes = $findings | Where-Object { $_.Severity -eq 'PASS' }

Write-Host ""
Write-Host "  PASS : $($passes.Count)" -ForegroundColor Green
Write-Host "  WARN : $($warns.Count)"  -ForegroundColor Yellow
Write-Host "  FAIL : $($fails.Count)"  -ForegroundColor Red

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
$timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportFile = Join-Path $OutputPath "FirewallAuditComparison_$timestamp.html"

$phaseCardsHtml = @()
if ($pre) { $phaseCardsHtml += "<div class='phase-item'><strong>Pre-Migration</strong><br>$($pre.Hostname) &mdash; $($pre.Timestamp)</div>" }
if ($ref) { $phaseCardsHtml += "<div class='phase-item'><strong>Azure Reference</strong><br>$($ref.Hostname) &mdash; $($ref.Timestamp)</div>" }
if ($mig) { $phaseCardsHtml += "<div class='phase-item'><strong>Azure Migrated</strong><br>$($mig.Hostname) &mdash; $($mig.Timestamp)</div>" }

$rowsHtml = foreach ($f in $findings) {
    $bgColor = switch ($f.Severity) {
        'FAIL'  { '#4a1010' }
        'WARN'  { '#4a3a10' }
        'PASS'  { '#0f3320' }
        default { '#1e1e1e' }
    }
    $badge = switch ($f.Severity) {
        'FAIL'  { '<span style="background:#c0392b;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">FAIL</span>' }
        'WARN'  { '<span style="background:#d4880a;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">WARN</span>' }
        'PASS'  { '<span style="background:#27ae60;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">PASS</span>' }
        default { '<span style="background:#555;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">INFO</span>' }
    }
    "<tr style='background:$bgColor'>
        <td style='padding:8px 12px'>$($f.Category)</td>
        <td style='padding:8px 12px'>$badge</td>
        <td style='padding:8px 12px'>$($f.Description)</td>
        <td style='padding:8px 12px;color:#aaa;font-size:0.9em'>$($f.Detail)</td>
    </tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Firewall Audit Comparison Report</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #111; color: #e0e0e0; margin: 0; padding: 24px; }
  h1   { color: #56b6f7; margin-bottom: 4px; }
  .meta { color: #888; font-size: 0.9em; margin-bottom: 24px; }
  .summary { display: flex; gap: 16px; margin-bottom: 28px; }
  .card { padding: 16px 28px; border-radius: 8px; font-size: 1.4em; font-weight: bold; }
  .card-pass { background: #0f3320; color: #2ecc71; }
  .card-warn { background: #4a3a10; color: #f39c12; }
  .card-fail { background: #4a1010; color: #e74c3c; }
  table { width: 100%; border-collapse: collapse; font-size: 0.93em; }
  th    { background: #1e2a38; color: #56b6f7; text-align: left; padding: 10px 12px; }
  tr:hover td { filter: brightness(1.15); }
  td    { border-bottom: 1px solid #2a2a2a; vertical-align: top; }
  .phases { margin-bottom: 24px; background: #1a1a2e; border-radius: 8px; padding: 16px 20px; }
  .phases h2 { color: #56b6f7; margin: 0 0 10px 0; font-size: 1em; text-transform: uppercase; letter-spacing: 0.05em; }
  .phase-row { display: flex; gap: 32px; flex-wrap: wrap; }
  .phase-item { font-size: 0.88em; color: #aaa; }
  .phase-item strong { color: #e0e0e0; }
</style>
</head>
<body>
<h1>Firewall Audit - Migration Comparison Report</h1>
<p class="meta">Generated: $(Get-Date -Format 'dd MMM yyyy HH:mm:ss')</p>

<div class="phases">
  <h2>Phases Compared</h2>
  <div class="phase-row">
    $($phaseCardsHtml -join "`n    ")
  </div>
</div>

<div class="summary">
  <div class="card card-pass">&#10003; $($passes.Count) PASS</div>
  <div class="card card-warn">&#9888; $($warns.Count) WARN</div>
  <div class="card card-fail">&#10007; $($fails.Count) FAIL</div>
</div>

<table>
  <thead>
    <tr>
      <th style="width:140px">Category</th>
      <th style="width:80px">Result</th>
      <th>Description</th>
      <th>Detail</th>
    </tr>
  </thead>
  <tbody>
    $($rowsHtml -join "`n")
  </tbody>
</table>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host ""
Write-Host "HTML report written to: $reportFile" -ForegroundColor Green
