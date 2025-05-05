# 🛡️ Threat Hunt Report: Suspicious PowerShell Activity

**Detection of Potential Malicious PowerShell Execution on Endpoints**

---

## 📘 Scenario Overview

Security analysts observed unusual outbound traffic on several endpoints, which prompted a hunt for signs of PowerShell misuse — a common tactic used by threat actors to bypass security controls, download payloads, or exfiltrate data. The hunt focuses on detecting potentially malicious PowerShell executions across Windows 10 endpoints.
---


## 🧭 High-Level Discovery Plan:
1. Search for PowerShell processes with suspicious command-line arguments.

2. Analyze user accounts and endpoints executing encoded or obfuscated commands.

3. Correlate execution timestamps with any unusual network behavior or alerts.


---

## 🔍 Steps Taken
1. Queried process execution logs for PowerShell usage with base64 or suspicious flags (-EncodedCommand, -nop, -w hidden, etc.).

2. Analyzed command-line arguments for signs of obfuscation or URL downloads.

3. Mapped executed scripts to user accounts and verified with endpoint security telemetry.

4. Checked network logs for correlated activity following script execution.

## 🕓 Chronological Events
April 12, 2025 – Alert triggered by Defender for Endpoint: Unusual outbound connection.

April 13, 2025 – Identified use of PowerShell with encoded payload on WIN10-VM01.

April 13, 2025 – User jsmith ran powershell.exe -nop -w hidden -encodedCommand....

April 13, 2025 – Connection made to external IP over port 443 immediately after execution.

## 🧾 Summary
A suspicious PowerShell script was executed with the -EncodedCommand flag, often used to obfuscate malicious activity. It was launched by a standard user and connected to an external IP. The timing and technique suggest potential malware staging or data exfiltration behavior.

## 🛠️ Response Taken
The endpoint WIN10-VM01 was isolated via Microsoft Defender for Endpoint.

The user's credentials were reset, and MFA was enforced.

A full scan was initiated and confirmed no persistent threats.

The incident was documented, and a PowerShell execution detection rule was tuned.

## 📊 MDE Tables Referenced:
| **Table**           | **Purpose**                                                             |
| ------------------- | ----------------------------------------------------------------------- |
| DeviceProcessEvents | Detected PowerShell execution and command-line arguments                |
| DeviceNetworkEvents | Confirmed post-execution outbound connection                            |
| DeviceEvents        | Tracked correlated security events, including alerts and device actions |

## 🧪 Detection Queries Used (KQL):
// Detect PowerShell execution with suspicious flags
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-nop", "-w hidden")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

// Check for network activity shortly after
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort



## 👨‍💻 Created By:
Author: Jordan Stewart

GitHub: jordanstewart-hub

Date: April 30, 2025


