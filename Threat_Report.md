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
### 1. Queried process execution logs for PowerShell usage with base64 or suspicious flags (-EncodedCommand, -nop, -w hidden, etc.).
At 9:36 AM on May 8, 2025, a PowerShell process was executed matching these criteria, indicating possible script-based execution with intent to evade detection. This activity was logged and correlated with host jrs-threathunt and user juser1 for further investigation.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("-EncodedCommand", "-w hidden", "-NoProfile")
| where DeviceName == "jrs-threathunt" or InitiatingProcessAccountName == "juser1"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

```
![Screenshot (3)](https://github.com/user-attachments/assets/e23514e4-b82b-432c-bc8b-f8c0b47139b0)


### 2. Analyzed command-line arguments for signs of obfuscation.
The encoded command found "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==" translates to: The PowerShell command Start-Sleep 10 which pauses the script for 10 seconds then exits. It runs, waits and then quits with no visible output.
   ![Screenshot (4)](https://github.com/user-attachments/assets/62969b1e-bbe7-4004-8a75-9bc2f80c52d1)


### 3. Checked network logs for correlated activity following script execution.
Verified activity was captured in "DeviceProcessEvents" and "DeviceNetworkEvents". At 9:40 AM on May 8, 2025, a network connection was observed from device jrs-threathunt to the external IP 23.53.11.202 over port 443 (HTTPS). The associated remote URL was www.example.com, and the event was flagged with a Low severity level in the Defender logs.

**Query used to locate events:**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl
```


![Screenshot (5)](https://github.com/user-attachments/assets/d0b336b1-a901-491f-a0ff-9d38b1aae032)


## 🕓 Chronological Events
---
**1. Process Execution – Suspicious PowerShell Command**  
**Timestamp:** 2025-05-08T09:36:00Z  
**Event:** The user **"juser1"** executed PowerShell with suspicious arguments on device **"jrs-threathunt"**. The command included obfuscation indicators such as `-EncodedCommand`, `-NoProfile`, and `-WindowStyle Hidden`.  
**Action:** Suspicious PowerShell execution detected.  
**Command:** `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==`  
**File Path:** Not explicitly logged  

---

**2. Command Decoding – Obfuscated Activity Analysis**  
**Timestamp:** 2025-05-08T09:36:10Z *(approximate)*  
**Event:** The Base64-encoded command was decoded to `Start-Sleep 10`, indicating a pause behavior often used to delay execution or evade sandbox detection.  
**Action:** Obfuscated command identified and analyzed.  
**Decoded Command:** `Start-Sleep 10`  
**Purpose:** Introduces a 10-second execution delay with no visible output  

---

**3. Network Connection – Post-Execution Activity**  
**Timestamp:** 2025-05-08T09:40:20Z  
**Event:** A network connection was established from device **"jrs-threathunt"** to external IP **23.53.11.202** over **port 443 (HTTPS)**. The destination URL was **www.example.com**, and the event severity was flagged as **Low** in Microsoft Defender logs.  
**Action:** Outbound HTTPS connection detected.


## Summary
A suspicious PowerShell script was executed with the -EncodedCommand flag, often used to obfuscate malicious activity. It was launched by a standard user and connected to an external IP. The timing and technique suggest potential malware staging or data exfiltration behavior. This lab replicates a common PowerShell abuse technique seen in the wild. It highlights how even benign commands can be used with obfuscation flags to mimic adversary behavior. Using MDE's hunting features we demonstrated how to detect and analyze such activity quickly.

## Response Taken
Confirmed suspicious PowerShell execution on endpoint jrs-threathunt. The endpoint jrs-threathunt was isolated via Microsoft Defender for Endpoint.
No signs of lateral movement or real threat beyond the simulation. The user "juser1" had their direct manager notified of incident.





## Created By:
Author: Jordan Stewart

GitHub: jordanstewart-hub

Date: May 8th, 2025


