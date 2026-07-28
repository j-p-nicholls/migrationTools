#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects inbound firewall, NSG, ASG, and IP Flow state for a given migration phase.
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
    # Pre-migration (VMware) - no Az module needed
    .\Invoke-FirewallAudit.ps1 -Phase "PreMigration" `
        -InboundHosts @("Dummy01","Dummy02","Dummy03") `
        -InboundPorts @(135, 445, 5985, 50055)

.EXAMPLE
    # Azure reference VM or migrated VM - Az module used automatically if present
    .\Invoke-FirewallAudit.ps1 -Phase "AzureReference" `
        -InboundHosts @("Dummy01","Dummy02","Dummy03") `
        -InboundPorts @(135, 445, 5985, 50055)
#>
param(
    [Parameter(Mandatory)][string] $Phase,
    [string]                       $OutputPath   = $PSScriptRoot,
    [string[]]                     $InboundHosts = @("Dummy01","Dummy02","Dummy03"),
    [int[]]                        $InboundPorts = @(135, 445, 5985, 50055)
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

$isAzure  = $false
$imdsData = $null

try {
    $imdsData = Invoke-RestMethod `
        -Uri     "http://169.254.169.254/metadata/instance?api-version=2021-02-01" `
        -Headers @{ Metadata = "true" } `
        -TimeoutSec 3 `
        -ErrorAction Stop
    $isAzure = $true
    Write-Host "Azure IMDS reachable - running in Azure." -ForegroundColor Green
    Write-Host "  VM Name        : $($imdsData.compute.name)"
    Write-Host "  Location       : $($imdsData.compute.location)"
    Write-Host "  VM Size        : $($imdsData.compute.vmSize)"
    Write-Host "  Subscription   : $($imdsData.compute.subscriptionId)"
    Write-Host "  Resource Group : $($imdsData.compute.resourceGroupName)"
} catch {
    Write-Host "Azure IMDS not reachable - assuming non-Azure (VMware / on-prem) environment." -ForegroundColor Yellow
}

# Check for Az.Network module when in Azure
$azModuleAvailable = $false
if ($isAzure) {
    if (Get-Module -ListAvailable -Name Az.Network -ErrorAction SilentlyContinue) {
        $azModuleAvailable = $true
        Import-Module Az.Network -ErrorAction SilentlyContinue
        Write-Host "Az.Network module available - NSG, ASG and IP Flow Verify checks enabled." -ForegroundColor Green
    } else {
        Write-Host "Az.Network module NOT found - NSG, ASG and IP Flow Verify checks will be skipped." -ForegroundColor Yellow
        Write-Host "  Install with: Install-Module Az.Network -Scope CurrentUser" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Local Windows Firewall - inbound rules
# ---------------------------------------------------------------------------
Write-Step "Local Windows Firewall - Inbound Rules"

$firewallRules = @()
$rawRules = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue

foreach ($rule in $rawRules) {
    $portFilter    = $rule | Get-NetFirewallPortFilter    -ErrorAction SilentlyContinue
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

    $firewallRules += [PSCustomObject]@{
        Name          = $rule.Name
        DisplayName   = $rule.DisplayName
        Enabled       = $rule.Enabled.ToString()
        Action        = $rule.Action.ToString()
        Profile       = $rule.Profile.ToString()
        Protocol      = $portFilter.Protocol
        LocalPort     = $portFilter.LocalPort      -join ','
        RemoteAddress = $addressFilter.RemoteAddress -join ','
        Group         = $rule.Group
    }
}

Write-Host "Total inbound rules found: $($firewallRules.Count)"

$relevantRules = $firewallRules | Where-Object {
    $rp    = $_.LocalPort -split ','
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

$profileState = Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
$profileState | Format-Table -AutoSize

$connectionProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity
$connectionProfiles | Format-Table -AutoSize

# ---------------------------------------------------------------------------
# 4. Azure-only setup - shared across sections 5, 6, 7
# ---------------------------------------------------------------------------
$nic                = $null
$nsgEffectiveRules  = @()
$nsgRawRules        = @()
$asgMemberships     = @()
$ipFlowResults      = @()

if ($isAzure -and $azModuleAvailable) {

    # Ensure Az context
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-Host "No Az context - attempting Connect-AzAccount..." -ForegroundColor Yellow
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }

    $subscriptionId = $imdsData.compute.subscriptionId
    $resourceGroup  = $imdsData.compute.resourceGroupName
    $vmName         = $imdsData.compute.name
    $location       = $imdsData.compute.location

    Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

    $vm    = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName -ErrorAction Stop
    $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
    $nic   = Get-AzNetworkInterface -ResourceGroupName $resourceGroup `
                 -Name ($nicId -split '/')[-1] -ErrorAction Stop

    Write-Host "NIC: $($nic.Name)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. ASG membership (Azure only)
#    Records which Application Security Groups this VM's NIC belongs to.
#    ASG membership controls which NSG rules apply - a VM not in the right
#    ASG will silently miss rules even if the NSG is correctly configured.
# ---------------------------------------------------------------------------
$asgMemberships = @()

if ($isAzure -and $azModuleAvailable -and $nic) {
    Write-Step "ASG Membership"

    if ($nic.IpConfigurations) {
        foreach ($ipConfig in $nic.IpConfigurations) {
            if ($ipConfig.ApplicationSecurityGroups -and $ipConfig.ApplicationSecurityGroups.Count -gt 0) {
                foreach ($asg in $ipConfig.ApplicationSecurityGroups) {
                    # ASG Id format: /subscriptions/.../resourceGroups/.../providers/Microsoft.Network/applicationSecurityGroups/<name>
                    $asgName = ($asg.Id -split '/')[-1]
                    $asgRg   = ($asg.Id -split '/')[4]

                    Write-Host "  ASG: $asgName (RG: $asgRg)" -ForegroundColor Green

                    $asgMemberships += [PSCustomObject]@{
                        ASGName       = $asgName
                        ASGId         = $asg.Id
                        ResourceGroup = $asgRg
                        IPConfig      = $ipConfig.Name
                    }
                }
            }
        }
    }

    if ($asgMemberships.Count -eq 0) {
        Write-Host "  No ASG memberships found on this NIC." -ForegroundColor Yellow
    }
} elseif ($isAzure -and -not $azModuleAvailable) {
    Write-Host "Skipping ASG check - Az.Network not available." -ForegroundColor Yellow
} else {
    Write-Host "Skipping ASG check - not running in Azure." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 6. NSG rules - effective (flattened) and raw (ASG names preserved)
#
#    Effective rules: what Azure actually evaluates after resolving all ASG
#    memberships to IPs. Used for verdict comparison.
#
#    Raw rules: pulled directly from the NSG object with ASG references
#    intact. Used to diff ASG-scoped rule intent, independent of which IPs
#    are currently members of each ASG.
# ---------------------------------------------------------------------------
if ($isAzure -and $azModuleAvailable -and $nic) {
    Write-Step "NSG Effective Inbound Rules"

    try {
        $effective = Get-AzEffectiveNetworkSecurityGroup `
            -NetworkInterfaceName $nic.Name `
            -ResourceGroupName    $resourceGroup `
            -ErrorAction Stop

        foreach ($rule in $effective.EffectiveSecurityRules) {
            if ($rule.Direction -eq 'Inbound') {
                $nsgEffectiveRules += [PSCustomObject]@{
                    Name                     = $rule.Name
                    Priority                 = $rule.Priority
                    Direction                = $rule.Direction
                    Access                   = $rule.Access
                    Protocol                 = $rule.Protocol
                    SourceAddressPrefix      = $rule.SourceAddressPrefix      -join ','
                    SourcePortRange          = $rule.SourcePortRange          -join ','
                    DestinationPortRange     = $rule.DestinationPortRange     -join ','
                    DestinationAddressPrefix = $rule.DestinationAddressPrefix -join ','
                }
            }
        }

        Write-Host "Effective inbound NSG rules: $($nsgEffectiveRules.Count)"
        $nsgEffectiveRules | Sort-Object Priority | Format-Table -AutoSize

    } catch {
        Write-Host "NSG effective rule query failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Step "NSG Raw Rules (ASG names preserved)"

    try {
        # Find the NSG associated with this NIC (NIC-level association first, then subnet)
        $nsgObject = $null

        if ($nic.NetworkSecurityGroup) {
            $nsgName   = ($nic.NetworkSecurityGroup.Id -split '/')[-1]
            $nsgObject = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup `
                             -Name $nsgName -ErrorAction Stop
            Write-Host "NSG (NIC-level): $nsgName"
        } elseif ($nic.IpConfigurations[0].Subnet.Id) {
            # Fall back to subnet-level NSG
            $subnetId     = $nic.IpConfigurations[0].Subnet.Id
            $vnetName     = ($subnetId -split '/')[8]
            $subnetName   = ($subnetId -split '/')[-1]
            $vnetRg       = ($subnetId -split '/')[4]
            $vnet         = Get-AzVirtualNetwork -ResourceGroupName $vnetRg -Name $vnetName -ErrorAction Stop
            $subnet       = $vnet.Subnets | Where-Object { $_.Name -eq $subnetName }
            if ($subnet.NetworkSecurityGroup) {
                $nsgName   = ($subnet.NetworkSecurityGroup.Id -split '/')[-1]
                $nsgObject = Get-AzNetworkSecurityGroup -ResourceGroupName $vnetRg `
                                 -Name $nsgName -ErrorAction Stop
                Write-Host "NSG (subnet-level): $nsgName"
            }
        }

        if ($nsgObject) {
            foreach ($rule in $nsgObject.SecurityRules | Where-Object { $_.Direction -eq 'Inbound' }) {

                # Capture ASG names from source if present
                $srcAsgNames = @()
                if ($rule.SourceApplicationSecurityGroups) {
                    $srcAsgNames = $rule.SourceApplicationSecurityGroups |
                        ForEach-Object { ($_.Id -split '/')[-1] }
                }

                # Capture ASG names from destination if present
                $dstAsgNames = @()
                if ($rule.DestinationApplicationSecurityGroups) {
                    $dstAsgNames = $rule.DestinationApplicationSecurityGroups |
                        ForEach-Object { ($_.Id -split '/')[-1] }
                }

                $nsgRawRules += [PSCustomObject]@{
                    Name                         = $rule.Name
                    Priority                     = $rule.Priority
                    Direction                    = $rule.Direction
                    Access                       = $rule.Access
                    Protocol                     = $rule.Protocol
                    SourceAddressPrefix          = $rule.SourceAddressPrefix          -join ','
                    SourcePortRange              = $rule.SourcePortRange              -join ','
                    DestinationAddressPrefix     = $rule.DestinationAddressPrefix     -join ','
                    DestinationPortRange         = $rule.DestinationPortRange         -join ','
                    SourceASGs                   = $srcAsgNames -join ','
                    DestinationASGs              = $dstAsgNames -join ','
                    IsASGRule                    = ($srcAsgNames.Count -gt 0 -or $dstAsgNames.Count -gt 0)
                }
            }

            Write-Host "Raw inbound NSG rules: $($nsgRawRules.Count)"

            $asgRules = $nsgRawRules | Where-Object { $_.IsASGRule }
            if ($asgRules.Count -gt 0) {
                Write-Host "ASG-scoped rules ($($asgRules.Count)):"
                $asgRules | Sort-Object Priority |
                    Format-Table Name, Priority, Access, Protocol, SourceASGs, DestinationASGs, DestinationPortRange -AutoSize
            } else {
                Write-Host "No ASG-scoped rules found in this NSG." -ForegroundColor Yellow
            }
        } else {
            Write-Host "No NSG found associated with this NIC or its subnet." -ForegroundColor Yellow
        }

    } catch {
        Write-Host "NSG raw rule query failed: $($_.Exception.Message)" -ForegroundColor Red
    }

} elseif ($isAzure -and -not $azModuleAvailable) {
    Write-Host "Skipping NSG checks - Az.Network not available." -ForegroundColor Yellow
} else {
    Write-Host "Skipping NSG checks - not running in Azure." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 7. IP Flow Verify (Azure only)
#    Tests each InboundHost/port pair. Where a source host resolves to an IP
#    that is a member of an ASG, the result validates that the ASG-scoped
#    rule is firing correctly for that source.
# ---------------------------------------------------------------------------
if ($isAzure -and $azModuleAvailable -and $nic) {
    Write-Step "IP Flow Verify (per source host / port)"

    try {
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
            Select-Object -First 1).IPAddress

        $nw = Get-AzNetworkWatcher -ErrorAction SilentlyContinue |
            Where-Object { $_.Location -eq $location } |
            Select-Object -First 1

        if (-not $nw) {
            Write-Host "No Network Watcher found in $location - IP Flow Verify unavailable." -ForegroundColor Yellow
        } else {
            # Build the test list from InboundHosts, then supplement with one
            # representative IP per ASG (if we can resolve a member IP)
            $flowTestTargets = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($h in $InboundHosts) {
                $ip = Resolve-HostToIP -Hostname $h
                $flowTestTargets.Add([PSCustomObject]@{
                    Label      = $h
                    SourceIP   = $ip
                    SourceType = 'Host'
                })
            }

            # For each ASG this VM is a member of, find other NIC members and
            # pick one representative IP to test - this validates ASG-scoped rules
            foreach ($asgEntry in $asgMemberships) {
                try {
                    Write-Host "  Resolving member IPs for ASG: $($asgEntry.ASGName)..." -ForegroundColor Yellow
                    # Get all NICs in the subscription and filter by ASG membership
                    $allNics = Get-AzNetworkInterface -ErrorAction SilentlyContinue
                    $asgNics = $allNics | Where-Object {
                        $_.IpConfigurations | ForEach-Object {
                            $_.ApplicationSecurityGroups
                        } | Where-Object {
                            $_ -and ($_.Id -split '/')[-1] -eq $asgEntry.ASGName
                        }
                    } | Where-Object { $_.Id -ne $nic.Id }  # exclude self

                    if ($asgNics) {
                        $rep = $asgNics | Select-Object -First 1
                        $repIP = $rep.IpConfigurations[0].PrivateIpAddress
                        $repName = $rep.Name

                        Write-Host "    Representative member: $repName ($repIP)" -ForegroundColor Green
                        $flowTestTargets.Add([PSCustomObject]@{
                            Label      = "ASG:$($asgEntry.ASGName) ($repName)"
                            SourceIP   = $repIP
                            SourceType = 'ASGMember'
                        })
                    } else {
                        Write-Host "    No other NIC members found in ASG $($asgEntry.ASGName) - skipping representative IP test." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "    Failed to resolve ASG members for $($asgEntry.ASGName): $($_.Exception.Message)" -ForegroundColor Red
                }
            }

            # Run IP Flow Verify for all targets
            foreach ($target in $flowTestTargets) {
                if (-not $target.SourceIP) {
                    Write-Host "  $($target.Label) - could not resolve IP, skipping." -ForegroundColor Yellow
                    $ipFlowResults += [PSCustomObject]@{
                        SourceLabel = $target.Label
                        SourceIP    = 'Unresolved'
                        SourceType  = $target.SourceType
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
                            -NetworkWatcher         $nw `
                            -TargetVirtualMachineId $vm.Id `
                            -Direction              Inbound `
                            -Protocol               TCP `
                            -RemoteIPAddress        $target.SourceIP `
                            -LocalIPAddress         $localIP `
                            -LocalPort              $port `
                            -RemotePort             (Get-Random -Minimum 49152 -Maximum 65535) `
                            -ErrorAction Stop

                        $colour = if ($result.Access -eq 'Allow') { 'Green' } else { 'Red' }
                        Write-Host "  $($target.Label) ($($target.SourceIP)) -> :$port  $($result.Access)  [$($result.RuleName)]" `
                            -ForegroundColor $colour

                        $ipFlowResults += [PSCustomObject]@{
                            SourceLabel = $target.Label
                            SourceIP    = $target.SourceIP
                            SourceType  = $target.SourceType
                            Port        = $port
                            Direction   = 'Inbound'
                            Access      = $result.Access
                            RuleName    = $result.RuleName
                        }
                    } catch {
                        Write-Host "  $($target.Label) -> :$port  ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        $ipFlowResults += [PSCustomObject]@{
                            SourceLabel = $target.Label
                            SourceIP    = $target.SourceIP
                            SourceType  = $target.SourceType
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
    Write-Host "Skipping IP Flow Verify - Az.Network not available." -ForegroundColor Yellow
} else {
    Write-Host "Skipping IP Flow Verify - not running in Azure." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 8. Assemble and write JSON output
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
    ASGMemberships     = $asgMemberships
    NSGEffectiveRules  = $nsgEffectiveRules
    NSGRawRules        = $nsgRawRules
    IPFlowResults      = $ipFlowResults
}

$result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outFile -Encoding UTF8

Write-Host ""
Write-Host "Results written to: $outFile" -ForegroundColor Green
Write-Host "Run Compare-FirewallAudit.ps1 with your phase files to diff results."
