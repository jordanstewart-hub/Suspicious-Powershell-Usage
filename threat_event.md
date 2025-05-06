## Threat Event (Encoded Powershell Execution)

## 👣Steps the Bad Actor Took
## 1. Open a Command Prompt or Run Terminal with Admin Rights. Ensures elevated privileges for executing PowerShell commands if needed.
## 2. Execute PowerShell with an Encoded Command
Command used: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==
## 3. Explanation of the Parameters Used:
-NoProfile: Prevents PowerShell profiles from loading, making execution faster and stealthier.
-WindowStyle Hidden: Runs the process without opening a visible window — to stay unnoticed.
-EncodedCommand: Accepts a Base64-encoded string — typically used to obfuscate the command.
## 4. What the Encoded Command Does
The Base64 string "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==" decodes to: Start-Sleep 10
This command makes the system pause for 10 seconds. It's harmless for simulation, but commonly used in real attacks as a placeholder or evasion delay.
## 5. Result of the Action:
There is no visible activity on screen. However, logs will capture:
-The invocation of "powershell.exe"
-The "-EncodedCommand" parameter
-The use of hidden window mode (-WindowStyle Hidden)
## 6. Why This Simulates Threat Activity
Real attackers often encode PowerShell commands to:
-Avoid detection by traditional logging tools.
-Hide malicious logic from basic review.
-Execute in-memory attacks (fileless malware).

