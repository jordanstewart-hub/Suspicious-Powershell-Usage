# 🛡️ Threat Hunt Report: Suspicious PowerShell Activity

**Detection of Suspicious PowerShell Usage via Encoded Commands**

---

## 📘 Scenario Overview

Adversaries often use obfuscated or encoded PowerShell commands to evade detection and persist on a system. Security teams must identify when PowerShell is used in suspicious ways, such as with `-EncodedCommand`, `-WindowStyle Hidden`, or `Invoke-WebRequest`. In this lab, we simulate and detect this activity on a Windows 10 VM in Microsoft Azure using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL).

---

## 🔍 High-Level Threat Simulation Plan

1. Launch a PowerShell process using `-EncodedCommand` and `-WindowStyle Hidden`
2. Optionally simulate remote connection via `Invoke-WebRequest`
3. Query DeviceProcessEvents and DeviceNetworkEvents in MDE to detect the behavior

---

## 💻 Simulated Threat Details

### Simulated PowerShell Command
```powershell
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==
