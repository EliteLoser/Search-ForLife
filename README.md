# Search-ForLife
Use Svendsen Tech's Search-ForLife PowerShell code in an attempt to detect if a server is in use, as part of server lifecycle management/removal/investigation of unknown servers, etc.

It needs to run in an elevated administrator PowerShell shell to get access to the event log, but can scan ports without (you will then see regularly occuring error text).

Only start it once and let it run "forever". It will log to `$Env:SystemDrive\Svendsen.Tech.Signs.of.Life\SignsOfLifeOn_$Env:ComputerName.txt`.

Of course you can edit and adapt the code to suit your needs.

I discovered something was accessing port 7680 on my home workstation when I was going to document this. It hit me over three checks about 5 seconds apart, then went away. The address does not respond to ping or any ports I know are common for equipment I own. Who knows...

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

