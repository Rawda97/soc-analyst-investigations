# Boogeyman 3 — SIEM-Based Incident Investigation

## 1. Investigation Overview

This report documents a security investigation conducted in the TryHackMe Boogeyman 3 lab, involving a multi-stage attack against Quick Logistics LLC.

The investigation examines how an attacker progressed from phishing and initial code execution to persistence, credential access, lateral movement, and attempted Active Directory compromise.

**Investigation Objectives:**
- Identify the initial malicious execution.
- Analyze suspicious processes and their relationships.
- Investigate persistence mechanisms.
- Examine credential dumping and Pass-the-Hash activity.
- Trace lateral movement between compromised workstations.
- Investigate DCSync activity targeting domain accounts.

**Tools and Data Sources:** Kibana (Elastic), Windows Event Logs, Sysmon.

**Investigation Type:** SOC Investigation / Windows Threat Detection / Incident Analysis.

**Environment:** Authorized TryHackMe training lab.

---

## 2. Investigation Findings

### Finding 1 — Initial Phishing and Payload Execution

The attack began with a phishing email targeting the CEO of Quick Logistics LLC.

The attachment contained an HTA file disguised as a PDF document.

**Suspicious file:**

`ProjectFinancialSummary_Q3.pdf.hta`

**Observed execution:**
- Process: `mshta.exe`
- Process ID: `6392`

**Analysis:**

The double extension `.pdf.hta` was used to make an executable HTML Application appear to be a PDF document.

The attacker used `mshta.exe`, a legitimate Windows utility capable of executing HTA files, to launch the initial payload.

This activity is consistent with the abuse of trusted Windows utilities for malicious execution.

### Finding 2 — Payload Implantation and Persistence

The first-stage payload used `xcopy.exe` to implant a file in another location.

The implanted payload was associated with `rundll32.exe` execution.

**Observed payload reference:**

```text
C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer
```

**Scheduled task command:**

```powershell
$A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'
$T = New-ScheduledTaskTrigger -Daily -At 06:00
$S = New-ScheduledTaskSettingsSet
$P = New-ScheduledTaskPrincipal $env:username
$D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S
Register-ScheduledTask Review -InputObject $D -Force
```

**Analysis:**

The attacker registered a scheduled task named `Review`, configured to execute daily at 06:00.

The task launches `rundll32.exe` and references a payload stored with a `.dat` extension.

This mechanism allows the malicious payload to be executed repeatedly without requiring the original phishing attachment to be reopened.

**Security Significance:** Scheduled task persistence can allow an attacker to maintain execution on a compromised endpoint.

### Finding 3 — UAC Bypass and Credential Access

The investigation identified `fodhelper.exe` in activity
