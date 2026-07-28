#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects inbound firewall and NSG rule state for a given phase of migration.
    Outputs a structured JSON file for later comparison with Compare-FirewallAudit.ps1.

.PARAMETER Phase
    Label for this run. Suggested values: "PreMigration", "AzureReference", "AzureMigrated"

.PARAMETER OutputPath
    Directory to write the JSON results file. Defaults to the script directory.

.PARAMETER InboundHosts
    List of source hostnames or IPs expected to send inbound traffic to this VM.
    Used for IP Flow Verify checks when running in Azure.

.PARAMETER InboundPorts
    List of TCP ports this VM should be accepting inbound. Used for firewall rule
    audit and IP Flow Verify.

.EXAMPLE
    # Pre-migration (VMware) — no Az module needed
    .\Invoke-FirewallAudit.ps1 -Phase "PreMigration" `
        -InboundHosts @("Dummy01","Dummy02","Dummy03") `
        -InboundPorts @(135, 445, 5985, 50055)

.EXAMPLE
    # Azure reference VM or migrated VM — Az module used automatically if present
    .\Invoke-FirewallAudit.ps1 -Phase "AzureReference" `
        -InboundHosts @("Dummy01","Dummy02","Dummy03") `
        -InboundPorts @(135, 445, 5985, 50055)
#>
param(
    [Parameter(Mandatory)][string]   $Phase,
    [string]                         $OutputPath  = $PSScriptRoot,
    [string[]]                       $InboundHosts = @("Dummy01","Dummy02","Dummy03"),
    [int[]]                          $InboundPorts = @(135, 445, 5985, 50055)
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$Name)
    Write-Host ""
    Write-Host "========== $Name ==========" -ForegroundColor Cyan
}

function Resolve-HostToIP {
    param([string]$Hostname)
    try {
        $addr = [System.Net.Dns]::GetHostAddresses($Hostname) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1
        return $addr.IPAddressToString
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# 1. Detect whether we are running in Azure via IMDS
# ---------------------------------------------------------------------------
Write-Step "Environment Detection"

$isAzure   = $false
$imdsData  = $null

try {
    $imdsData = Invoke-RestMethod `
        -Uri     "http://169.254.169.254/metadata/instance?api-version=2021-02-01" `
        -Headers @{ Metadata = "true" } `
        -TimeoutSec 3 `
        -ErrorAction Stop
    $isAzure = $true
    Write-Host "Azure IMDS reachable — running in Azure." -ForegroundColor Green
    Write-Host "  VM Name        : $($imdsData.compute.name)"
    Write-Host "  Location       : $($imdsData.compute.location)"
    Write-Host "  VM Size        : $($imdsData.compute.vmSize)"
    Write-Host "  Subscription   : $($imdsData.compute.subscriptionId)"
    Write-Host "  Resource Group : $($imdsData.compute.resourceGroupName)"
} catch {
    Write-Host "Azure IMDS not reachable — assuming non-Azure (VMware / on-prem) environment." -ForegroundColor Yellow
}

# Check for Az.Network module when in Azure
$azModuleAvailable = $false
if ($isAzure) {
    if (Get-Module -ListAvailable -Name Az.Network -ErrorAction SilentlyContinue) {
        $azModuleAvailable = $true
        Import-Module Az.Network -ErrorAction SilentlyContinue
        Write-Host "Az.Network module available — NSG and IP Flow Verify checks enabled." -ForegroundColor Green
    } else {
        Write-Host "Az.Network module NOT found — NSG and IP Flow Verify checks will be skipped." -ForegroundColor Yellow
        Write-Host "  Install with: Install-Module Az.Network -Scope CurrentUser" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Local Windows Firewall — inbound rules
# ---------------------------------------------------------------------------
Write-Step "Local Windows Firewall — Inbound Rules"

$firewallRules = @()

$rawRules = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue

foreach ($rule in $rawRules) {
    $portFilter    = $rule | Get-NetFirewallPortFilter    -ErrorAction SilentlyContinue
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

    $firewallRules += [PSCustomObject]@{
        Name             = $rule.Name
        DisplayName      = $rule.DisplayName
        Enabled          = $rule.Enabled.ToString()
        Action           = $rule.Action.ToString()
        Profile          = $rule.Profile.ToString()
        Protocol         = $portFilter.Protocol
        LocalPort        = $portFilter.LocalPort   -join ','
        RemoteAddress    = $addressFilter.RemoteAddress -join ','
        Group            = $rule.Group
    }
}

Write-Host "Total inbound rules found: $($firewallRules.Count)"

# Show rules relevant to our ports of interest
$relevantRules = $firewallRules | Where-Object {
    $rp = $_.LocalPort -split ','
    $match = $false
    foreach ($p in $InboundPorts) {
        if ($rp -contains [string]$p -or $rp -contains 'Any') { $match = $true }
    }
    $match
}

Write-Host "Rules matching monitored ports ($($InboundPorts -join ',')):"
$relevantRules | Format-Table DisplayName, Enabled, Action, Profile, Protocol, LocalPort, RemoteAddress -AutoSize

# ---------------------------------------------------------------------------
# 3. Firewall profile active state
# ---------------------------------------------------------------------------
Write-Step "Firewall Profile State"

$profileState = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
$profileState | Format-Table -AutoSize

$connectionProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity

$connectionProfiles | Format-Table -AutoSize

# ---------------------------------------------------------------------------
# 4. NSG effective rules (Azure only)
# ---------------------------------------------------------------------------
$nsgEffectiveRules = @()

if ($isAzure -and $azModuleAvailable) {
    Write-Step "NSG Effective Inbound Rules"

    try {
        # Ensure we are connected — attempt silent connect using managed identity first
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx) {
            Write-Host "No Az context found — attempting Connect-AzAccount..." -ForegroundColor Yellow
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }

        $subscriptionId = $imdsData.compute.subscriptionId
        $resourceGroup  = $imdsData.compute.resourceGroupName
        $vmName         = $imdsData.compute.name

        Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

        $vm   = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName -ErrorAction Stop
        $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
        $nic  = Get-AzNetworkInterface -ResourceGroupName $resourceGroup `
                    -Name ($nicId -split '/')[-1] -ErrorAction Stop

        Write-Host "NIC: $($nic.Name)"

        $effective = Get-AzEffectiveNetworkSecurityGroup `
            -NetworkInterfaceName $nic.Name `
            -ResourceGroupName $resourceGroup `
            -ErrorAction Stop

        foreach ($nsg in $effective.EffectiveSecurityRules) {
            if ($nsg.Direction -eq 'Inbound') {
                $nsgEffectiveRules += [PSCustomObject]@{
                    Name                   = $nsg.Name
                    Priority               = $nsg.Priority
                    Direction              = $nsg.Direction
                    Access                 = $nsg.Access
                    Protocol               = $nsg.Protocol
                    SourceAddressPrefix    = $nsg.SourceAddressPrefix    -join ','
                    SourcePortRange        = $nsg.SourcePortRange        -join ','
                    DestinationPortRange   = $nsg.DestinationPortRange   -join ','
                    DestinationAddressPrefix = $nsg.DestinationAddressPrefix -join ','
                }
            }
        }

        Write-Host "Effective inbound NSG rules retrieved: $($nsgEffectiveRules.Count)"
        $nsgEffectiveRules | Sort-Object Priority | Format-Table -AutoSize

    } catch {
        Write-Host "NSG query failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} elseif ($isAzure -and -not $azModuleAvailable) {
    Write-Host "Skipping NSG check — Az.Network not available." -ForegroundColor Yellow
} else {
    Write-Host "Skipping NSG check — not running in Azure." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 5. IP Flow Verify (Azure only)
# ---------------------------------------------------------------------------
$ipFlowResults = @()

if ($isAzure -and $azModuleAvailable) {
    Write-Step "IP Flow Verify (per source host / port)"

    try {
        $subscriptionId = $imdsData.compute.subscriptionId
        $resourceGroup  = $imdsData.compute.resourceGroupName
        $vmName         = $imdsData.compute.name
        $location       = $imdsData.compute.location

        # Resolve local VM private IP
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
            Select-Object -First 1).IPAddress

        # Get or create Network Watcher for this region
        $nw = Get-AzNetworkWatcher -ErrorAction SilentlyContinue |
            Where-Object { $_.Location -eq $location } |
            Select-Object -First 1

        if (-not $nw) {
            Write-Host "No Network Watcher found in $location — IP Flow Verify unavailable." -ForegroundColor Yellow
        } else {
            $vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName -ErrorAction Stop

            foreach ($srcHost in $InboundHosts) {
                $srcIP = Resolve-HostToIP -Hostname $srcHost
                if (-not $srcIP) {
                    Write-Host "Could not resolve $srcHost — skipping." -ForegroundColor Yellow
                    $ipFlowResults += [PSCustomObject]@{
                        SourceHost  = $srcHost
                        SourceIP    = 'Unresolved'
                        Port        = 'N/A'
                        Direction   = 'Inbound'
                        Access      = 'SKIPPED'
                        RuleName    = 'N/A'
                    }
                    continue
                }

                foreach ($port in $InboundPorts) {
                    try {
                        $result = Test-AzNetworkWatcherIPFlow `
                            -NetworkWatcher        $nw `
                            -TargetVirtualMachineId $vm.Id `
                            -Direction             Inbound `
                            -Protocol              TCP `
                            -RemoteIPAddress       $srcIP `
                            -LocalIPAddress        $localIP `
                            -LocalPort             $port `
                            -RemotePort            (Get-Random -Minimum 49152 -Maximum 65535) `
                            -ErrorAction Stop

                        $colour = if ($result.Access -eq 'Allow') { 'Green' } else { 'Red' }
                        Write-Host "  $srcHost ($srcIP) -> :$port  $($result.Access)  [$($result.RuleName)]" -ForegroundColor $colour

                        $ipFlowResults += [PSCustomObject]@{
                            SourceHost  = $srcHost
                            SourceIP    = $srcIP
                            Port        = $port
                            Direction   = 'Inbound'
                            Access      = $result.Access
                            RuleName    = $result.RuleName
                        }
                    } catch {
                        Write-Host "  $srcHost -> :$port  ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        $ipFlowResults += [PSCustomObject]@{
                            SourceHost  = $srcHost
                            SourceIP    = $srcIP
                            Port        = $port
                            Direction   = 'Inbound'
                            Access      = 'ERROR'
                            RuleName    = $_.Exception.Message
                        }
                    }
                }
            }
        }
    } catch {
        Write-Host "IP Flow Verify failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} elseif ($isAzure -and -not $azModuleAvailable) {
    Write-Host "Skipping IP Flow Verify — Az.Network not available." -ForegroundColor Yellow
} else {
    Write-Host "Skipping IP Flow Verify — not running in Azure." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 6. Assemble and write JSON output
# ---------------------------------------------------------------------------
Write-Step "Writing Results"

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$outFile   = Join-Path $OutputPath "$($Phase)_$($hostname)_$($timestamp).json"

$result = [PSCustomObject]@{
    Phase              = $Phase
    Hostname           = $hostname
    Timestamp          = (Get-Date -Format 'o')
    IsAzure            = $isAzure
    AzureContext       = if ($isAzure) {
                             [PSCustomObject]@{
                                 VMName        = $imdsData.compute.name
                                 Location      = $imdsData.compute.location
                                 VMSize        = $imdsData.compute.vmSize
                                 Subscription  = $imdsData.compute.subscriptionId
                                 ResourceGroup = $imdsData.compute.resourceGroupName
                             }
                         } else { $null }
    MonitoredPorts     = $InboundPorts
    MonitoredHosts     = $InboundHosts
    FirewallRules      = $firewallRules
    FirewallProfiles   = $profileState
    ConnectionProfiles = $connectionProfiles
    NSGEffectiveRules  = $nsgEffectiveRules
    IPFlowResults      = $ipFlowResults
}

$result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outFile -Encoding UTF8

Write-Host ""
Write-Host "Results written to: $outFile" -ForegroundColor Green
Write-Host "Run Compare-FirewallAudit.ps1 with all three phase files to diff results."
