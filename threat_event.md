## Threat Event (Encoded Powershell Execution)

## 👣Steps the Bad Actor Took
## 1. Open a Command Prompt or Run Terminal with Admin Rights. Ensures elevated privileges for executing PowerShell commands if needed.
## 2. Execute PowerShell with an Encoded Command
Command used: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==
## 3. Deleted PowerShell history or cleared artifacts to evade detection.


## 💡Explanation of the Parameters Used:

-NoProfile: Prevents PowerShell profiles from loading, making execution faster and stealthier.

-WindowStyle Hidden: Runs the process without opening a visible window — to stay unnoticed.

-EncodedCommand: Accepts a Base64-encoded string — typically used to obfuscate the command.
## What the Encoded Command Does
The Base64 string "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==" decodes to: Start-Sleep 10
This command makes the system pause for 10 seconds. It's harmless for simulation, but commonly used in real attacks as a placeholder or evasion delay.
## Result of the Action:
There is no visible activity on screen. However, logs will capture:

-The invocation of "powershell.exe"

-The "-EncodedCommand" parameter

-The use of hidden window mode (-WindowStyle Hidden)
## Why This Simulates Threat Activity
Real attackers often encode PowerShell commands avoid detection by traditional logging tools, hide malicious logic from basic review and execute in-memory attacks (fileless malware).

| **Parameter** | **Description**                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceProcessEvents                                                                                                                                                                    |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**   | Detects suspicious use of PowerShell with encoded commands, hidden execution, and C2-like activity.                                                                                    |
| **Parameter** | **Description**                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceNetworkEvents                                                                                                                                                                    |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**   | Detects PowerShell-initiated network activity to external URLs or suspicious IPs.                                                                                                      |

## Related Queries:

// Suspicious use of PowerShell with obfuscation
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("-EncodedCommand", "-w hidden", "-WindowStyle Hidden", "-NoProfile")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

// Network activity from PowerShell
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp desc

Created By:
Author Name: Jordan Stewart

Author Contact: https://github.com/jordanstewart-hub

Date: April 30, 2025
