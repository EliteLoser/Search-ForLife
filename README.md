# Search-ForLife
Use Svendsen Tech's Search-ForLife PowerShell code in an attempt to detect if a server is in use, as part of server lifecycle management/removal/investigation of unknown servers, etc.

You start it once and then just let it run, preferably for a few days or weeks. I suggest at least one week, depending on a lot of factors I can't really base an estimate on... Starting it as a startup script that backgrounds it, or just in a scheduled task you only trigger once, are probably good approaches.

It needs to run in an elevated administrator PowerShell shell to get access to the event log, but can scan ports without. You will then see regularly (daily) occuring error text.

Only start it once and let it run "forever". It will log to `$Env:SystemDrive\Svendsen.Tech.Signs.of.Life\SignsOfLifeOn_$Env:ComputerName.txt`.

You can edit and adapt the code to suit your needs.

I discovered something was accessing port 7680 on my home workstation when I was going to document this. It hit me over three checks about 5 seconds apart, then it was cached, and would have reappeared in one hour or if you restart the script. This caching is a feature to avoid spamming the log with repeated entries of the same, excessively. The address on my LAN does not respond to ping or any ports I know are common for equipment I own. Who knows what it is and what it does...

Here's my example in a non-elevated shell so you see the Get-EventLog error:

```
PS C:\temp> C:\Users\sporr\OneDrive\Documents\PowerShell\Search-ForLife.ps1
VERBOSE: 2019-05-13 02:13:53 # Starting Search-ForLife.ps1
VERBOSE: 2019-05-13 02:13:53 # Logging to \Svendsen.Tech.Signs.of.Life\SignsOfLifeOn_DESKTOP-42.txt
VERBOSE: 2019-05-13 02:13:58 # [LOW_PORT_IN_USE] Port 7680 (low = below 10000) is in use by the following address(es): 192.168.0.29. DNS: .
Get-EventLog : Requested registry access is not allowed.
At C:\Users\sporr\OneDrive\Documents\PowerShell\Search-ForLife.ps1:102 char:26
+ ... nEvents = @(Get-EventLog -LogName Security -After ([DateTime]::Now.Ad ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-EventLog], SecurityException
    + FullyQualifiedErrorId : System.Security.SecurityException,Microsoft.PowerShell.Commands.GetEventLogCommand
 
VERBOSE: 2019-05-13 02:13:58 # [LOW_PORT_IN_USE] Port 7680 (low = below 10000) is in use by the following address(es): 192.168.0.29. DNS: .
VERBOSE: 2019-05-13 02:14:03 # [LOW_PORT_IN_USE] Port 7680 (low = below 10000) is in use by the following address(es): 192.168.0.29. DNS: .


PS C:\temp> gc C:\Svendsen.Tech.Signs.of.Life\SignsOfLifeOn_DESKTOP-42.txt
2019-05-13 02:13:53 # Starting Search-ForLife.ps1
2019-05-13 02:13:53 # Logging to \Svendsen.Tech.Signs.of.Life\SignsOfLifeOn_DESKTOP-42.txt
2019-05-13 02:13:58 # [LOW_PORT_IN_USE] Port 7680 (low = below 10000) is in use by the following address(es): 192.168.0.29. DNS: .
2019-05-13 02:13:58 # [LOW_PORT_IN_USE] Port 7680 (low = below 10000) is in use by the following address(es): 192.168.0.29. DNS: .
2019-05-13 02:14:03 # [LOW_PORT_IN_USE] Port 7680 (low = below 10000) is in use by the following address(es): 192.168.0.29. DNS: .
```

# Logon events

Here's the code where you can see what's logged about user logon events.

```powershell
if ($LogonEvents.Count -gt 0) {
    Write-Log -Message "Found $($LogonEvents.Count) logon events since $(
        [DateTime]::Now.AddMinutes(-1440).ToString('yyyy-MM-dd HH:mm:ss')) (last 1440 minutes, 24 hours)."
    foreach ($Event in $LogonEvents) {
        Write-Log -Message "[USER_LOGON] Account: $($Event.ReplacementStrings[5]). Domain: $(
            $Event.ReplacementStrings[6]). SID: $($Event.ReplacementStrings[4]). Remote endpoint: $(
            $Event.ReplacementStrings[18])."
    }
}
```

