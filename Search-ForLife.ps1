[CmdletBinding()]
param()


################################################################################
# Find out if a server is in use (potentially).
# Can also be used to detect malicious activity in a very crude and basic way.
# Server lifecycle management.
# 
# Author: Joakim Borger Svendsen. Svendsen Tech
# Apache 2 license
# Copyright 2019-present
#
################################################################################

$MyEAP = "Continue"
$ErrorActionPreference = $MyEAP
$AliveFile = "$Env:SystemDrive\Svendsen.Tech.Signs.of.Life\SignsOfLifeOn_$Env:ComputerName.txt"
New-Item -Path (Split-Path -Path $AliveFile -Parent) -ItemType Directory -Force | Out-Null

function Write-Log {
    param([String] $Message)
    Write-Verbose -Message "$([DateTime]::Now.ToString('yyyy-MM-dd HH\:mm\:ss')) # $Message"
    while ($True) {
        try {
            Add-Content -ErrorAction Stop -LiteralPath $AliveFile -Value "$([DateTime]::Now.ToString('yyyy-MM-dd HH\:mm\:ss')) # $Message" -Encoding UTF8
            Write-Verbose -Message "$([DateTime]::Now.ToString('yyyy-MM-dd HH\:mm\:ss')) # $Message" -Verbose
            break
        }
        catch {
            Write-Verbose -Message "Add-Content failed. Retried in 25-500 ms." -Verbose
            Start-Sleep -Milliseconds (25..500 | Get-Random)
        }
    }
}
Write-Log -Message "Starting Search-ForLife.ps1"
Write-Log -Message "Logging to $AliveFile"
# Using .NET instead of Get-Date consistently here because it's significantly less resource-expensive.
$EventTime = [DateTime]::Now
$FirstReadEventFlag = $True
$PortCache = @{}
$CycleCounter = 0
while ($True) {
    $CycleCounter += 1
    if ($CycleCounter -gt 250) {
        $CycleCounter = 0
        [System.GC]::Collect()
    }
    $CycleStartTime = [DateTime]::Now
    $NetworkProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $LowPortsInUse = @($NetworkProperties.GetActiveTcpConnections() | Where { $_ |
        Select-Object -ExpandProperty LocalEndPoint | Select-Object -ExpandProperty Port | ForEach-Object {
            if ($_ -lt 10000) {
                $True
            }
            else {
                $False
            }
        }
    })
    if ($LowPortsInUse.Count -gt 0) {
        foreach ($LowPort in $LowPortsInUse) {
            if ($PortCache.ContainsKey(($LowPort | Select-Object -ExpandProperty LocalEndPoint | Select-Object -ExpandProperty Port))) {
                if ($PortCache[($LowPort | Select-Object -ExpandProperty LocalEndPoint |
                    Select-Object -ExpandProperty Port)].Address -contains ($LowPort |
                        Select-Object -ExpandProperty RemoteEndPoint | Select-Object -ExpandProperty Address)) {
                    continue
                }
                else {
                    $PortCache[($LowPort | Select-Object -ExpandProperty LocalEndPoint | 
                        Select-Object -ExpandProperty Port)].Address += @($LowPort | Select-Object -ExpandProperty RemoteEndPoint |
                            Select-Object -ExpandProperty Address)
                    $ErrorActionPreference = "SilentlyContinue"
                    $PortCache[($LowPort | Select-Object -ExpandProperty LocalEndPoint |
                        Select-Object -ExpandProperty Port)].DNS += @([Net.Dns]::GetHostByAddress(($LowPort |
                            Select-Object -ExpandProperty RemoteEndPoint |
                            Select-Object -ExpandProperty Address)) | ForEach-Object {
                        @(@($_.HostName) + @($_.Aliases)) -join ', '
                    })
                    $ErrorActionPreference = $MyEAP
                }
            } # port 0 lyttende.
            else {
                $ErrorActionPreference = "SilentlyContinue"
                $PortCache[$LowPort.LocalEndPoint.Port] = @{
                    Address = @($LowPort.RemoteEndPoint.Address)
                    DateTime = [DateTime]::Now
                    DNS = @([Net.Dns]::GetHostByAddress(($LowPort | Select-Object -ExpandProperty RemoteEndPoint |
                        Select-Object -ExpandProperty Address)) | ForEach-Object {
                        @(@($_.HostName) + @($_.Aliases)) -join ', '
                    })
                }
                $ErrorActionPreference = $MyEAP
            }
        }
    }
    foreach ($PortEntry in $PortCache.Clone().GetEnumerator()) {
        if (([DateTime]::Now - $PortEntry.Value.DateTime).TotalMinutes -gt 60) { # remove after 24 hours, log again
            Write-Log -Message "[$($PortEntry.Name)] Has been in the cache for over 1 hour and is now removed. It will be logged again on the next run (probably a few times)."
            $PortCache.Remove($PortEntry.Name)
        }
        elseif (([DateTime]::Now - $PortEntry.Value.DateTime).TotalSeconds -lt 10) { # will log the same 2-3 times sometimes
            Write-Log -Message "[LOW_PORT_IN_USE] Port $($PortEntry.Name) (low = below 10000) is in use by the following address(es): $(
                $PortEntry.Value.Address -join ', '). DNS: $($PortEntry.Value.DNS -join '; ')."
        }
    }
    <#if ($PortCache.Keys.Count -gt 0) {
        foreach ($PortEntry in $PortCache.GetEnumerator()) {
                        
        }
    }#>
    if ($FirstReadEventFlag -eq $True -or ([DateTime]::Now - $EventTime).TotalMinutes -ge 1439) {
        $FirstReadEventFlag = $False
        $LogonEvents = @(Get-EventLog -LogName Security -After ([DateTime]::Now.AddMinutes(-1440)) | Where-Object {
            # Find all the bloody IDs that are not consistent across Windows versions... These are the two main logon IDs I found on the web.
            $_.InstanceID -match '^(?:4624|528)$' -and $_.ReplacementStrings[5] -notlike "$Env:ComputerName$" -and $_.ReplacementStrings[6] -notlike "NT AUTHORITY"
        })
        $Global:TempLogonEvents = $LogonEvents
        if ($LogonEvents.Count -gt 0) {
            Write-Log -Message "Found $($LogonEvents.Count) logon events since $(
                [DateTime]::Now.AddMinutes(-1440).ToString('yyyy-MM-dd HH:mm:ss')) (last 1440 minutes, 24 hours)."
            foreach ($Event in $LogonEvents) {
                Write-Log -Message "[USER_LOGON] Account: $($Event.ReplacementStrings[5]). Domain: $(
                    $Event.ReplacementStrings[6]). SID: $($Event.ReplacementStrings[4]). Remote endpoint: $($Event.ReplacementStrings[18])."
            }
        }
        $EventTime = [DateTime]::Now
    }
    while ($True) {
        Start-Sleep -Milliseconds 100
        if (([DateTime]::Now - $CycleStartTime).TotalMilliseconds -ge 4890) {
            break
        }
    }
}
