# Boogeyman 2 — Memory Forensics Investigation
## Investigation Overview

This investigation focuses on analyzing a Windows memory dump from the TryHackMe Boogeyman 2 lab to identify evidence of a phishing-related compromise, malicious process execution, command-and-control (C2) communication, and persistence mechanisms.

**Objective:** Reconstruct the attack activity and identify key indicators of compromise (IOCs) using memory forensic techniques.

**Tools Used:** Volatility 3, Linux strings, grep.

**Evidence Source:** `WKSTN-2961.raw` (Windows memory dump).
## Investigation Findings

### 1. Identifying the Malicious Email Attachment

**Objective:** Identify the full path of the suspicious email attachment from the Windows memory dump.

**Command Used:**

```bash
vol -f WKSTN-2961.raw windows.filescan | grep -i "Resume_WesleyTaylor"
```

**Evidence Identified:**

```text
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

**Analysis:**

The memory scan revealed a Microsoft Word document located in the Outlook temporary attachment cache under the user profile `maxine.beck`.

The file was presented as a résumé attachment. Its location suggests that Outlook had cached the attachment on the workstation.

**Security Significance:**

This finding helps identify the suspected initial phishing attachment and provides a file path for further investigation. The path alone does not prove that the document executed malicious code.
