# 🔎 Threat Hunt Report (Unauthorized RDP Access)

**Detection of Unauthorized Remote Desktop Protocol (RDP) Connections**

---

## Example Scenario:
Management suspects that unauthorized RDP connection attempts are being made against Windows 10 VMs hosted in Azure. Recent security event logs indicate an increased number of failed login attempts, and there are concerns about possible brute-force attacks targeting these systems. The goal is to detect unauthorized RDP access attempts, identify suspicious behavior, and recommend mitigations.

---

## 🎯 High-Level RDP-related IoC Discovery Plan:
- Check **Security Event Logs (Event ID 4625)** for multiple failed login attempts over RDP.
- Check for **successful RDP logins (Event ID 4624, LogonType 10)** from suspicious IP addresses.
- Check for **unusual login times and geolocations**.

---

## Steps Taken
1. Deployed Azure Monitor Agent on all Windows 10 VMs.
2. Collected Security Events into Log Analytics Workspace.
3. Ran Kusto Query Language (KQL) queries to detect failed and successful RDP attempts.
4. Correlated IP addresses with known geo-threat intelligence.
5. Investigated the time, source IP, and user account of the RDP connections.

---

## 📅 Chronological Events
1. Noticed 15 failed login attempts from external IP `178.62.XXX.XXX` within 5 minutes.
2. Observed 1 successful RDP login from the same IP immediately after multiple failures.
3. Login occurred outside of business hours (03:47 AM local time).
4. Account used: **testadmin**.

---

## Summary
Suspicious RDP activity was confirmed on Azure Windows 10 VM **AZ-VM-01**.  
A foreign IP address outside expected business regions performed multiple failed login attempts followed by a successful login using an administrative account during non-business hours.

---

## 🚨 Response Taken
- The compromised VM was immediately isolated from the network.
- Password for the affected account was reset.
- NSG rules were updated to restrict RDP access to trusted IPs only.
- Just-In-Time VM Access (JIT) was configured to further protect RDP access.

---

## 📊 MDE Tables Referenced

| **Parameter**  | **Description** |
|----------------|------------------|
| **Name** | `SecurityEvent` (Azure Monitor / Log Analytics) |
| **Info** | [Microsoft Docs - SecurityEvent Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| **Purpose** | Used to query failed (4625) and successful (4624) RDP login events. |

---

## 🕵️ Detection Queries

```kql
// Multiple failed RDP login attempts (Event ID 4625)
SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedAttempts = count() by Account, bin(TimeGenerated, 1h), IPAddress = tostring(parse_json(AdditionalFields)["IpAddress"])
| where FailedAttempts > 5
| order by FailedAttempts desc

// Successful RDP login from external IP (Event ID 4624)
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, DeviceName, Account, IPAddress = tostring(parse_json(AdditionalFields)["IpAddress"])
| order by TimeGenerated desc
