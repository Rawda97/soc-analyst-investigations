# Investigating Web Attacks — Kibana SIEM Investigation

## 1. Investigation Overview

This report documents a web application security investigation conducted in the TryHackMe SOC Level 1 training environment.

The investigation focused on suspicious HTTP requests targeting a Windows web server, followed by activity consistent with web-shell access and post-exploitation behavior.

The investigation used Kibana to correlate web server requests, Windows authentication events, and process creation telemetry.

### Investigation Objectives

- Analyze suspicious HTTP requests from an identified source IP.
- Investigate possible exploitation of an Exchange-related endpoint.
- Identify subsequent web-shell activity.
- Correlate web requests with Windows authentication logs.
- Investigate suspicious process execution.
- Determine the appropriate SOC alert disposition.

### Investigation Environment

| Component | Details |
|---|---|
| Platform | TryHackMe |
| Investigation interface | Kibana |
| Log sources | Web logs, Windows Security Events, Sysmon |
| Source IP | `203.0.113.55` |
| Target host | `winserv2019.some.corp` |
| Initial alert | `SOC-20250720-0012` |
| Related alert | `SOC-20250720-0013` |
| Initial alert timestamp | July 20, 2025, 04:38:40 |
| Web-shell alert timestamp | July 20, 2025, 04:45:31 |

All timestamps are taken from the lab's displayed alert information.

---

## 2. Finding 1 — Suspicious HTTP POST Requests

The initial alert identified repeated HTTP POST requests originating from:

```text
203.0.113.55
```

The requests targeted:

```text
proxyLogon.ecp
```

**Destination host:**

```text
winserv2019.some.corp
```

### Kibana Investigation

The investigation began by filtering web logs for the suspicious source IP and HTTP method.

Example KQL:

```kql
client.ip: "203.0.113.55" and http.request.method: "POST"
```

The relevant events were reviewed chronologically to identify repeated requests to the targeted endpoint.

### Analysis

The `proxyLogon.ecp` endpoint is associated with the ProxyLogon-related attack scenario in this lab.

Repeated POST requests targeting a sensitive application endpoint can indicate attempted exploitation.

However, request frequency and endpoint targeting alone do not establish successful exploitation.

**Security significance:** The alert provided a starting point for investigating potential unauthorized access to the web server.

---

## 3. Finding 2 — Subsequent Web-Shell Activity

A related alert was observed approximately seven minutes after the initial suspicious POST activity.

**Alert ID:**

```text
SOC-20250720-0013
```

**Alert timestamp:**

```text
2025-07-20 04:45:31
```

The subsequent activity involved HTTP GET requests targeting:

```text
errorEE.aspx
```

The requests included a query parameter:

```text
cmd=
```

### Kibana Investigation

Example KQL:

```kql
client.ip: "203.0.113.55" and http.request.method: "GET"
```

The results were examined for requests containing `errorEE.aspx` and the `cmd` parameter.

### Analysis

An ASPX file receiving commands through an HTTP query parameter is suspicious, particularly when it appears immediately after attempted exploitation of a vulnerable endpoint.

The sequence of suspicious POST requests followed by command-bearing GET requests is consistent with web-shell access.

**Security significance:** This correlation substantially increases the likelihood that the initial exploitation activity was malicious and led to post-exploitation behavior.

---

## 4. Finding 3 — Windows Authentication Correlation

The investigation continued by pivoting from web logs to Windows Security Events.

### Event ID 4624 — Successful Logon

Windows Security Event ID `4624` records the creation of a successful logon session.

The investigation identified authentication activity involving:

- Host: `winserv2019.some.corp`
- Account: `Administrator`
- Source IP: `203.0.113.55`

### Example Kibana Query

```kql
winlog.event_id: 4624 and host.name: "winserv2019.some.corp" and winlog.event_data.TargetUserName: "Administrator"
```

### Analysis

The authentication event provided host-level evidence that could be correlated with the suspicious web traffic.

The source IP, account name, target host, and timestamps were important for determining whether the web activity was followed by unauthorized access.

**Security significance:** A successful privileged logon associated with the suspicious source supports escalation of the investigation.

---

## 5. Finding 4 — Process Creation Investigation

The investigation also used Sysmon telemetry to examine processes executed on the Windows host.

### Sysmon Event ID 1

Sysmon Event ID `1` records process creation.

Relevant fields include:

| Field | Purpose |
|---|---|
| `process.name` | Executable name |
| `process.command_line` | Command-line arguments |
| `process.parent.name` | Parent process |
| `user.name` | Execution account |
| `host.name` | System where the process ran |
| `@timestamp` | Event time |

### Example Kibana Query

```kql
host.name: "winserv2019.some.corp" and user.name: "Administrator" and process.parent.name: "cmd.exe"
```

### Analysis

Process creation telemetry can help identify commands launched after web-shell access.

The parent-child process relationship is particularly useful because web shells frequently result in command interpreters launching additional Windows utilities.

In this investigation, Sysmon was used to correlate Administrator-context process activity with the earlier suspicious web requests and authentication evidence.

The exact command sequence is not reproduced because the complete original process event output was not retained.

---

## 6. Finding 5 — Additional Account Management Activity

A later alert in the same investigation involved user account management.

**Related alert:**

```text
SOC-20250720-0015
```

The alert indicated activity associated with the creation of a new account.

### Windows Event ID 4720

Windows Security Event ID `4720` records user account creation when the relevant auditing is enabled.

### Investigation Approach

The analyst should inspect:

- The newly created account name.
- The account responsible for creating it.
- The target host.
- The creation timestamp.
- Subsequent authentication or group membership changes.

### Analysis

Unauthorized account creation can indicate persistence following a successful compromise.

However, the exact account name and privilege level are not included here because the corresponding original event output was not retained.

---

## 7. Correlated Investigation Timeline

| Time | Event | Evidence |
|---|---|---|
| 04:38:40 | Initial suspicious web attack alert | `SOC-20250720-0012` |
| 04:45:31 | Web-shell-related alert | `SOC-20250720-0013` |
| Subsequent investigation | Administrator authentication correlation | Windows Event ID 4624 |
| Subsequent investigation | Process creation correlation | Sysmon Event ID 1 |
| Later alert | User account management activity | `SOC-20250720-0015` |

**Note:** The two alert timestamps are directly identified in the lab. Other rows describe correlated investigation stages without assigning unsupported exact times.

---

## 8. Indicators and Investigation Artifacts

| Category | Indicator |
|---|---|
| Suspicious source IP | `203.0.113.55` |
| Target host | `winserv2019.some.corp` |
| Initial targeted endpoint | `proxyLogon.ecp` |
| Suspected web-shell file | `errorEE.aspx` |
| Suspicious query parameter | `cmd=` |
| Initial alert | `SOC-20250720-0012` |
| Web-shell alert | `SOC-20250720-0013` |
| Account management alert | `SOC-20250720-0015` |
| Privileged account investigated | `Administrator` |
| Authentication telemetry | Windows Security Event ID 4624 |
| Process telemetry | Sysmon Event ID 1 |
| Account creation telemetry | Windows Security Event ID 4720 |

*The IP address and hostnames are training-environment indicators and should not be interpreted as evidence of a real-world incident.*

---

## 9. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Suspicious requests to an exposed application endpoint |
| Server Software Component: Web Shell | T1505.003 | Command-bearing requests to an ASPX file |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Relevant to investigated command execution |
| Create Account: Local Account | T1136.001 | Relevant if account creation was unauthorized and local |

The mappings represent the observed or investigated behavior. The account-creation technique requires confirmation of the account scope and context.

---

## 10. SOC Alert Assessment

### Initial Web Attack Alert

**Disposition:** True Positive — suspicious exploitation activity.

The initial POST requests were correlated with subsequent web-shell-related traffic, supporting a malicious interpretation of the alert.

### Web-Shell Alert

**Disposition:** True Positive — activity consistent with web-shell command execution.

The GET requests to `errorEE.aspx` with the `cmd` parameter, combined with subsequent host investigation findings, support escalation.

### Recommended SOC Action

Escalate the incident for containment and deeper investigation.

Relevant next steps include:

1. Preserve web server, authentication, and Sysmon logs.
2. Isolate confirmed compromised systems according to incident response procedures.
3. Investigate the suspicious ASPX file and its origin.
4. Review privileged account activity.
5. Examine newly created accounts and permission changes.
6. Identify any additional affected systems.
7. Remediate the exploited application vulnerability and validate recovery.

---

## 11. Skills Demonstrated

- Kibana and KQL investigation
- Web server log analysis
- HTTP POST and GET request correlation
- Web-shell detection
- Windows authentication analysis
- Windows Security Event ID 4624 investigation
- Sysmon Event ID 1 analysis
- Parent-child process investigation
- Account creation alert triage
- Cross-source event correlation
- SOC alert classification and escalation

---

## 12. Conclusion

This investigation demonstrated how a SOC analyst can move from a web application alert to a broader host-level investigation.

The analysis began with suspicious HTTP POST requests to `proxyLogon.ecp` and progressed to web-shell-related GET requests targeting `errorEE.aspx`.

Correlating these requests with Windows authentication and process creation events strengthened the assessment that the activity represented a security incident requiring escalation.

The exercise reinforced the importance of combining multiple log sources rather than relying on a single alert.

**Platform:** TryHackMe

**Learning Path:** SOC Level 1

**Focus:** Kibana / Web Attack Investigation / Windows Event Correlation / Incident Triage

*This investigation was conducted in an authorized cybersecurity training environment.*
