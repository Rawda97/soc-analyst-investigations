# Windows Threat Detection — Scheduled Task Persistence Investigation

## 1. Investigation Overview

This report documents a Windows security alert investigation conducted during the TryHackMe SOC Level 1 learning path.

The investigation focused on suspicious scheduled task creation, Windows authentication activity, local group enumeration, and potential privilege-related account changes.

The objective was to assess whether a scheduled task alert represented legitimate administrative activity or potentially malicious persistence.

### Investigation Environment

| Field | Value |
|---|---|
| Investigation platform | Splunk |
| Dataset | `index=win-alert` |
| Alert | Potential Task Scheduler Persistence Identified |
| Alert timestamp | August 30, 2025, 10:06:07 AM |
| Target host | `WIN-H015` |
| Associated user | `oliver.thompson` |
| Suspicious task | `AssessmentTaskOne` |
| Log sources | Windows Security Events and process-related telemetry |

*The alert timestamp is the time displayed in the lab, not necessarily the exact time of initial compromise.*

---

## 2. Investigation Objectives

- Investigate the scheduled task persistence alert.
- Identify the task name and associated account.
- Examine the scheduled task's execution behavior.
- Investigate suspicious process activity.
- Correlate Windows logon events.
- Examine local group enumeration and account changes.
- Assess whether escalation to a higher-tier analyst is appropriate.

---

## 3. Finding 1 — Suspicious Scheduled Task

The initial alert identified a scheduled task named:

```text
AssessmentTaskOne
```

The activity was associated with the host `WIN-H015` and the user `oliver.thompson`.

### Investigation Query

```spl
index=win-alert "AssessmentTaskOne"
```

This query searches for events containing the suspicious scheduled task name.

### Windows Event ID 4698

Windows Security Event ID `4698` records scheduled task creation when the relevant auditing is enabled.

A focused investigation can use:

```spl
index=win-alert "AssessmentTaskOne" "4698"
```

Alternatively, when the event identifier is parsed into the `EventCode` field:

```spl
index=win-alert EventCode=4698 "AssessmentTaskOne"
```

**Analysis:**

Scheduled tasks can be used legitimately by administrators and software applications. However, attackers can also use them to execute payloads automatically and maintain persistence.

The investigation should examine the task's creation time, creator account, action, trigger, and executable path.

---

## 4. Finding 2 — Suspicious Task Execution Behavior

The scheduled task's recorded action referenced the Windows utility `certutil` and an executable payload.

The investigated activity included a download reference to a file named:

```text
rv.exe
```

The payload was associated with a temporary-file destination named:

```text
DataCollector.exe
```

### Analysis

`certutil.exe` is a legitimate Windows utility with certificate-related functionality. It can also be abused to download files.

A scheduled task that downloads an executable and subsequently launches it is suspicious, particularly when the source is untrusted or the behavior does not match approved administrative operations.

The combination of a scheduled trigger, file retrieval, and executable launch provides stronger evidence of suspicious persistence than the task name alone.

**Assessment:** The task warrants further investigation and escalation because its behavior is consistent with a potential malicious persistence mechanism.

*The full command line and remote download URL are not reproduced because their original event output was not retained for independent validation.*

---

## 5. Finding 3 — Process Activity Investigation

The next step was to identify processes associated with the suspicious scheduled task and determine whether the referenced executable was launched.

### Investigation Query

```spl
index=win-alert ("AssessmentTaskOne" OR "DataCollector.exe" OR "certutil.exe")
```

### Analysis

Relevant process telemetry can help establish:

- Which executable was launched.
- The account responsible for execution.
- The process command line.
- The parent process.
- The time of execution.
- Any associated network connections.

When Sysmon process creation events are available, Event ID `1` can provide useful execution context.

### Sysmon Event ID 1

**Purpose:** Process creation monitoring.

The process command line and parent process information can help distinguish a legitimate administrative task from suspicious execution.

An analyst should correlate process identifiers, timestamps, executable paths, and command lines rather than relying on a process name alone.

---

## 6. Finding 4 — Windows Authentication Investigation

The investigation also examined Windows authentication activity to identify potentially suspicious logons.

### Windows Security Event ID 4624

Event ID `4624` indicates that a logon session was successfully created.

### Investigation Query

```spl
index=win-alert EventCode=4624
```

### Host-Focused Search

```spl
index=win-alert EventCode=4624 "WIN-H015"
```

### Analysis

Relevant fields may include:

| Field | Purpose |
|---|---|
| Account name | Identifies the account involved |
| Logon type | Indicates the category of logon |
| Source network address | Helps identify remote sources |
| Workstation name | Provides source-system context when populated |
| Logon ID | Helps correlate related activity |

A successful logon is not inherently malicious.

To identify suspicious access, the analyst should compare authentication events with the alert timeline, source information, account privileges, and subsequent actions.

---

## 7. Finding 5 — Local Group Enumeration

The investigation included examining commands that enumerate Windows local groups.

### Investigation Query

```spl
index=win-alert ("net localgroup" OR "Get-LocalGroup")
```

### Analysis

Local group enumeration can help an attacker identify privileged groups and determine which accounts have administrative access.

However, the same commands are also used by legitimate administrators.

The security significance depends on the initiating account, process lineage, execution time, and surrounding activity.

**Investigation objective:** Determine whether group discovery occurred as part of a suspicious post-compromise sequence.

---

## 8. Finding 6 — Account and Privilege Changes

Windows Security Events can help identify changes to local accounts and security groups.

### Event ID 4720 — User Account Creation

Event ID `4720` records the creation of a user account when the relevant auditing is enabled.

```spl
index=win-alert EventCode=4720
```

### Event ID 4732 — Member Added to a Security-Enabled Local Group

Event ID `4732` records when a member is added to a security-enabled local group.

```spl
index=win-alert EventCode=4732
```

### Analysis

Event ID `4732` is particularly useful when investigating unauthorized additions to a local Administrators group.

An analyst should inspect the target group, added member, initiating account, and surrounding events.

The event's `record_id` identifies a particular event record and is different from the `event_id`, which identifies the event category.

**Evidence limitation:** The exact account-change outcomes and event record identifiers are not asserted here because their original values were not preserved in the available investigation notes.

---

## 9. Investigation Sequence

The following table describes the investigation workflow rather than a fully verified chronological attack timeline.

| Stage | Investigation activity | Evidence |
|---|---|---|
| 1 | Review scheduled task persistence alert | Alert metadata |
| 2 | Identify suspicious scheduled task | `AssessmentTaskOne` |
| 3 | Examine task action and executable references | `certutil`, `rv.exe`, `DataCollector.exe` |
| 4 | Investigate process execution | Process telemetry / Sysmon |
| 5 | Examine successful Windows logons | Event ID 4624 |
| 6 | Investigate local group enumeration | Process command lines |
| 7 | Check account creation | Event ID 4720 |
| 8 | Check local group membership changes | Event ID 4732 |

---

## 10. Indicators and Investigation Artifacts

| Category | Indicator |
|---|---|
| Alert | Potential Task Scheduler Persistence Identified |
| Host | `WIN-H015` |
| Associated account | `oliver.thompson` |
| Scheduled task | `AssessmentTaskOne` |
| Download-related utility | `certutil.exe` |
| Referenced source filename | `rv.exe` |
| Referenced local executable | `DataCollector.exe` |
| Scheduled task creation | Windows Event ID 4698 |
| Successful logon | Windows Event ID 4624 |
| Account creation | Windows Event ID 4720 |
| Local group membership change | Windows Event ID 4732 |
| Process creation | Sysmon Event ID 1 |

*The indicators are associated with a controlled training environment. Not every listed event category represents a confirmed malicious action.*

---

## 11. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | T1053.005 | Suspicious scheduled task persistence |
| Ingress Tool Transfer | T1105 | Downloading a payload onto a system |
| System Owner/User Discovery | T1033 | Potential account enumeration |
| Permission Groups Discovery: Local Groups | T1069.001 | Local group enumeration |
| Create Account: Local Account | T1136.001 | Relevant to investigated account creation |
| Account Manipulation | T1098 | Relevant to investigated privilege-related changes |

Mappings reflect observed or investigated behaviors and do not imply that every technique was confirmed successful.

---

## 12. Detection and Response Recommendations

1. Monitor newly created or modified scheduled tasks.
2. Investigate tasks executing programs from temporary or user-writable directories.
3. Alert on suspicious `certutil.exe` download activity.
4. Correlate scheduled task creation with process execution and network telemetry.
5. Review successful logons occurring near suspicious administrative changes.
6. Monitor local group enumeration when associated with other suspicious behavior.
7. Alert on unauthorized account creation and additions to privileged groups.
8. Preserve task definitions, event logs, and relevant executable artifacts.
9. Escalate suspected persistence activity for deeper investigation and containment.

---

## 13. Investigation Assessment

The alert contained meaningful indicators of suspicious scheduled task behavior.

The combination of an automatically executed task and references to downloading and launching an executable supports treating the activity as a potential security incident rather than dismissing it as benign.

**Recommended disposition:** Escalate for further investigation.

The available evidence supports a suspicious persistence assessment. It does not independently establish every subsequent authentication or privilege-escalation outcome.

---

## 14. Skills Demonstrated

- Windows security alert triage
- Splunk log investigation
- Scheduled task persistence analysis
- Windows Security Event ID interpretation
- Sysmon process investigation
- Process and command-line analysis
- Authentication event correlation
- Account and group modification investigation
- MITRE ATT&CK mapping
- SOC escalation decision-making

---

## 15. Conclusion

This investigation demonstrated how a SOC analyst can assess a Windows persistence alert by correlating scheduled task information, process activity, authentication logs, and account-related security events.

The suspicious task `AssessmentTaskOne`, associated with `WIN-H015`, provided a starting point for investigating potential malicious execution and persistence.

The exercise strengthened practical skills in evidence-based alert triage, Windows event analysis, and determining when suspicious activity requires escalation.

**Platform:** TryHackMe

**Learning Path:** SOC Level 1

**Focus:** Windows Threat Detection / Persistence / Splunk / Security Event Analysis

*This investigation was conducted in an authorized cybersecurity training environment.*
