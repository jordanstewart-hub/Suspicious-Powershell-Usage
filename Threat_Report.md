# 🚨 Threat Hunt Report: Suspicious PowerShell Activity

**Detection of Potential Malicious PowerShell Execution on Endpoints**

![Powershell DANGER image](https://github.com/user-attachments/assets/5bced840-cf99-4047-a897-bc9e9afee0f9)

[Scenario Creation](https://github.com/jordanstewart-hub/Suspicious-Powershell-Usage/blob/main/threat_event.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


## 📘 Scenario Overview

Security analysts observed unusual outbound traffic on several endpoints between 9 AM-10:30 AM May 8th 2025 which prompted a hunt for signs of PowerShell misuse by a user in their organization — a common tactic used by threat actors to bypass security controls, download payloads, or exfiltrate data. The hunt focuses on detecting potentially malicious PowerShell executions across Windows 10 endpoints.
---


## High-Level Discovery Plan:
1. Search for PowerShell processes with suspicious command-line arguments.

2. Analyze user accounts and endpoints executing encoded or obfuscated commands.

3. Correlate execution timestamps with any unusual network behavior or alerts.


---

## Steps Taken
1. Queried process execution logs for PowerShell usage with base64 or suspicious flags (-EncodedCommand, -nop, -w hidden, etc.).

**Query used to locate events:**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("-EncodedCommand", "-w hidden", "-NoProfile")
| where DeviceName == "jrs-threathunt" or InitiatingProcessAccountName == "juser1"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

```
![Screenshot (3)](https://github.com/user-attachments/assets/e23514e4-b82b-432c-bc8b-f8c0b47139b0)


3. Analyzed command-line arguments for signs of obfuscation.

4. Monitored activity in MDE using Advanced Hunting (KQL).

5. Checked network logs for correlated activity following script execution. Verified activity was captured in "DeviceProcessEvents" and "DeviceNetworkEvents".

## 🕓 Chronological Events
April 12, 2025 – Alert triggered by Defender for Endpoint: Unusual outbound connection.

April 13, 2025 – Identified use of PowerShell with encoded payload on WIN10-VM01.

April 13, 2025 – User jsmith ran powershell.exe -nop -w hidden -encodedCommand....

April 13, 2025 – Connection made to external IP over port 443 immediately after execution.

## Summary
A suspicious PowerShell script was executed with the -EncodedCommand flag, often used to obfuscate malicious activity. It was launched by a standard user and connected to an external IP. The timing and technique suggest potential malware staging or data exfiltration behavior. This lab replicates a common PowerShell abuse technique seen in the wild. It highlights how even benign commands can be used with obfuscation flags to mimic adversary behavior. Using MDE's hunting features we demonstrated how to detect and analyze such activity quickly.

## 🛠️ Response Taken
Confirmed suspicious PowerShell execution on endpoint jrs-threathunt. The endpoint jrs-threathunt was isolated via Microsoft Defender for Endpoint.
No signs of lateral movement or real threat beyond the simulation. The users direct manager was notified.





## Created By:
Author: Jordan Stewart

GitHub: jordanstewart-hub

Date: April 30, 2025


