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


