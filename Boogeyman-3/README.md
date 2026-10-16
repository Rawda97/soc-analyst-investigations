# Boogeyman 3 — SIEM-Based Incident Investigation
# Boogeyman 3 — SIEM-Based Incident Investigation

## 1. Investigation Overview

This project documents an incident investigation conducted in the TryHackMe Boogeyman 3 lab using Kibana and Windows event logs.

The investigation focuses on a multi-stage attack against Quick Logistics LLC, beginning with a phishing attachment and progressing through malicious code execution, persistence, credential theft, lateral movement, and attempts to compromise domain accounts.

**Investigation Objectives:**
- Identify the initial malicious execution.
- Investigate process relationships and suspicious PowerShell activity.
- Identify persistence mechanisms.
- Examine credential dumping and Pass-the-Hash activity.
- Trace lateral movement between compromised systems.
- Investigate attempted DCSync activity.

**Tools Used:** Kibana (Elastic), Windows Event Logs, Sysmon.

**Investigation Type:** SOC Alert Investigation / Endpoint Threat Detection / Lateral Movement Analysis

---

## 2. Investigation Findings

### Finding 1 — Initial Phishing Execution

The attack began with a phishing email sent to the CEO of Quick Logistics LLC. The email contained an ISO attachment with an HTA file disguised as a PDF document.

**Suspicious file:**

`ProjectFinancialSummary_Q3.pdf.hta`

The HTA file was executed using `mshta.exe`, initiating the first-stage payload.

**Process identified:**
- Process: `mshta.exe`
- PID: `6392`

**Analysis:**

The use of a double file extension (`.pdf.hta`) helped disguise the executable HTA file as a PDF document.

`mshta.exe` is a legitimate Windows utility that can execute HTML applications, making it useful for attackers attempting to run malicious scripts through trusted system binaries.

### Finding 2 — Payload Execution and Persistence

The first-stage payload used `xcopy.exe` to copy a malicious file into another location on the compromised workstation.

The implanted payload was subsequently executed using `rundll32.exe`.

**Observed payload reference:**

```text
C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer
```

**Scheduled task creation:**

```powershell
$A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'
$T = New-ScheduledTaskTrigger -Daily -At 06:00
$S = New-ScheduledTaskSettingsSet
$P = New-ScheduledTaskPrincipal $env:username
$D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S
Register-ScheduledTask Review -InputObject $D -Force
```

**Analysis:**

The attacker established persistence by registering a scheduled task named `Review`.

The task was configured to execute daily at 06:00 and launch the implanted payload using `rundll32.exe`.

The use of a `.dat` extension disguised the payload as a data file, while `rundll32.exe` provided a legitimate Windows execution mechanism.

### Finding 3 — Privilege Escalation and Credential Access

The investigation identified `fodhelper.exe` as a process associated with the attacker's attempted User Account Control (UAC) bypass.

The attacker also downloaded Mimikatz, a credential access tool, from its GitHub release page.

**Observed download URL:**

```text
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
```

**Analysis:**

The activity indicates an attempt to obtain elevated execution privileges and access credentials stored on the compromised Windows system.

The presence of `fodhelper.exe` is relevant in the context of a suspected UAC bypass, but the process name alone is not sufficient to confirm successful privilege escalation.

### Finding 4 — Pass-the-Hash Activity

Mimikatz was used to initiate Pass-the-Hash authentication attempts.

**Observed command:**

```text
"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:itadmin /domain:QUICKLOGISTICS /ntlm:F84769D250EB95EB2D7D8B4A1C5613F2 /run:powershell.exe" exit
```

**Analysis:**

The `sekurlsa::pth` command attempts to create a process using the supplied NTLM hash for network authentication.

This technique may allow an attacker to authenticate without knowing the account's plaintext password.

The command provides evidence of attempted Pass-the-Hash activity. Successful access must be confirmed through correlated authentication or remote execution events.

### Finding 5 — Lateral Movement Using PowerShell Remoting

The attacker used credentials associated with the domain account `QUICKLOGISTICS\allan.smith` to attempt remote command execution on another workstation.

**Target workstation:** `WKSTN-1327`

**Observed command:**

```powershell
$credential = New-Object PSCredential -ArgumentList (
  'QUICKLOGISTICS\allan.smith',
  (ConvertTo-SecureString 'Tr!ckyP@ssw0rd987' -AsPlainText -Force)
)

Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}
```

**Analysis:**

The attacker constructed a PowerShell credential object and used `Invoke-Command` to attempt remote execution.

The `whoami` command was used to identify the execution context on the remote workstation.

A subsequent command attempted to execute a Base64-encoded PowerShell payload on the same target.

This activity demonstrates an attempted lateral movement technique using PowerShell Remoting and compromised credentials.

### Finding 6 — Credential Dumping on the Second Workstation

Following the attempted lateral movement, the attacker conducted additional credential access activity on the second workstation.

**Credential artifact identified:**

```text
administrator:00f80f2538dcb54e7adc715c0e7091ec
```

**Analysis:**

The artifact contains an account name and a corresponding NTLM hash.

Such hashes can potentially be abused for Pass-the-Hash authentication when the attacker has the necessary network access and permissions.

The discovery of additional credentials represents an opportunity for an attacker to expand access across the environment.

### Finding 7 — DCSync Activity

The investigation identified an attempted DCSync attack targeting domain account credentials.

**Accounts identified:**
- `Administrator`
- `backupda`

**Analysis:**

DCSync is a technique that abuses Active Directory replication functionality to request credential material from a domain controller.

The activity indicates an attempt to obtain additional domain account hashes, potentially enabling broader compromise.

---

## 3. Attack Sequence

The following sequence represents the reconstructed attack progression. It is based on observed commands and lab findings rather than a fully timestamped event timeline.

| Stage | Activity | Evidence |
|---|---|---|
| 1 | Phishing and initial execution | `.pdf.hta` file executed through `mshta.exe` |
| 2 | Payload implantation | `xcopy.exe` and `rundll32.exe` |
| 3 | Persistence | Scheduled task `Review` |
| 4 | Privilege escalation attempt | `fodhelper.exe` |
| 5 | Credential access | Mimikatz |
| 6 | Pass-the-Hash attempt | `sekurlsa::pth` |
| 7 | Lateral movement | PowerShell `Invoke-Command` |
| 8 | Additional credential access | NTLM hash artifact |
| 9 | Domain credential theft attempt | DCSync |

---

## 4. Indicators and Investigation Artifacts

| Type | Indicator |
|---|---|
| Initial payload | `ProjectFinancialSummary_Q3.pdf.hta` |
| Execution utility | `mshta.exe` |
| Initial execution PID | `6392` |
| Implanted payload | `review.dat` |
| Persistence task | `Review` |
| UAC bypass utility | `fodhelper.exe` |
| Credential access tool | `mimikatz.exe` |
| Authentication technique | Pass-the-Hash |
| Remote workstation | `WKSTN-1327` |
| Remote execution utility | PowerShell |
| Domain credential attack | DCSync |

---

## 5. Detection and Response Recommendations

1. Monitor suspicious `mshta.exe` execution, particularly when launched from user-controlled directories.
2. Investigate unexpected `rundll32.exe` executions referencing nonstandard file extensions.
3. Monitor newly registered scheduled tasks and unusual task actions.
4. Correlate suspected UAC bypass behavior with Registry modifications and elevated process creation.
5. Detect suspicious Mimikatz execution and credential access patterns.
6. Investigate Pass-the-Hash activity using authentication and process telemetry.
7. Monitor remote PowerShell execution between workstations.
8. Alert on unexpected Active Directory replication requests associated with DCSync.

---

## 6. Conclusion

This investigation demonstrated how a phishing-related compromise can progress through multiple stages, including persistence, credential access, lateral movement, and attempted domain credential theft.

Using Kibana, Windows event logs, and Sysmon telemetry, I examined suspicious process execution, credential misuse, and remote command activity.

**Skills Demonstrated:**
- SIEM investigation using Kibana
- Windows process and event log analysis
- Persistence identification
- Credential access investigation
- Pass-the-Hash analysis
- Lateral movement detection
- DCSync investigation
- Incident reconstruction

**Platform:** TryHackMe

**Lab:** Boogeyman 3

**Focus:** SOC Level 1 / Incident Investigation / Windows Threat Detection

*This investigation was conducted in an authorized training environment for educational purposes.*
