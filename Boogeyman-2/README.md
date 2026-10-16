# Boogeyman 2 — Windows Memory Forensics Investigation

## 1. Investigation Overview

This project documents a memory forensic investigation conducted as part of the TryHackMe Boogeyman 2 lab.

The investigation focused on identifying evidence of a phishing-related compromise, suspicious process activity, command-and-control (C2) communication, and persistence mechanisms on a Windows workstation.

**Objectives:**
- Identify the suspicious email attachment.
- Investigate malicious processes and network connections.
- Identify the attacker's persistence mechanism.
- Extract indicators of compromise (IOCs).
- Reconstruct the attack sequence from memory artifacts.

**Tools Used:** Volatility 3, Linux `strings`, `grep`.

**Evidence Source:** `WKSTN-2961.raw`

**Investigation Type:** Windows Memory Forensics / Incident Investigation

---

## 2. Investigation Findings

### Finding 1 — Suspicious Email Attachment

**Objective:** Identify the full file path of the malicious email attachment.

**Command:**

```bash
vol -f WKSTN-2961.raw windows.filescan | grep -i "Resume_WesleyTaylor"
```

**Evidence:**

```text
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

**Analysis:**

The memory scan identified a Microsoft Word document located in the Outlook temporary attachment cache belonging to the user `maxine.beck`.

The document was presented as a résumé, consistent with a phishing attachment used as an initial attack vector.

The file path provides an important forensic artifact, although its presence alone does not prove malicious execution.

### Finding 2 — Suspicious Network Connection

**Objective:** Identify the process associated with suspicious outbound network communication.

**Command:**

```bash
vol -f WKSTN-2961.raw windows.netscan
```

**Evidence:**

```text
Protocol: TCPv4
Local Address: 10.10.49.181:63331
Remote Address: 128.199.95.189:8080
State: CLOSED
PID: 6216
Process: updater.exe
```

**Analysis:**

Volatility identified a TCP connection associated with `updater.exe` (PID 6216).

The process communicated with the external IP address `128.199.95.189` over port `8080`.

This connection was investigated as a potential C2 communication channel in the context of the compromise.

The `CLOSED` state indicates that the connection was no longer active at the time represented by the memory artifact; it does not negate the evidence of previous communication.

### Finding 3 — Process Investigation

**Objective:** Investigate the suspicious process and its relationship to other running processes.

**Commands:**

```bash
vol -f WKSTN-2961.raw windows.pstree
```

```bash
vol -f WKSTN-2961.raw windows.dlllist --pid 6216
```

**Analysis:**

The process tree and DLL listing were used to investigate the suspicious process `updater.exe`.

The process tree helps establish parent-child relationships, while the DLL listing provides information about modules loaded by the process and can help identify its executable path.

These artifacts support process-level investigation and help correlate suspicious execution with network activity.

### Finding 4 — Scheduled Task Persistence

**Objective:** Identify the command used to establish persistent access.

**Command:**

```bash
strings WKSTN-2961.raw | grep -i "schtasks /create"
```

**Evidence:**

```powershell
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
```

**Analysis:**

The attacker created a scheduled task named `Updater` configured to run daily at 09:00.

The task launches PowerShell with a hidden window and retrieves an encoded payload from the Windows Registry.

The command then decodes the payload and executes it using `Invoke-Expression` (`IEX`).

**Key indicators:**

- `schtasks /Create` — Creates a scheduled task.
- `/SC DAILY` — Configures daily execution.
- `/ST 09:00` — Specifies the execution time.
- `/TN Updater` — Defines the scheduled task name.
- `-W hidden` — Hides the PowerShell window.
- `FromBase64String` — Decodes Base64 content.
- `IEX` — Executes the decoded PowerShell code.

**Security Significance:**

The scheduled task provides a persistence mechanism that can execute the attack
