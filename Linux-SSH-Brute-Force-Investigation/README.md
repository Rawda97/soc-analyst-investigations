# Linux SSH Brute-Force & Persistence Investigation — Splunk SIEM

## 1. Investigation Overview

This report documents a Linux security investigation conducted during the TryHackMe SOC Level 1 learning path.

The investigation focused on analyzing suspicious SSH authentication activity, identifying potential brute-force attempts, examining account activity, and investigating indicators of privilege escalation and persistence.

The exercise used Splunk to correlate Linux authentication logs and investigate an SSH-related security alert.

### Investigation Objectives

- Investigate an SSH brute-force alert.
- Identify the targeted Linux host and suspicious source IP address.
- Analyze failed and successful SSH authentication events.
- Count failed login attempts for individual accounts.
- Determine the duration of suspicious authentication activity.
- Investigate possible privilege escalation.
- Examine suspicious account creation as a persistence mechanism.
- Document findings using an evidence-based SOC investigation approach.

### Environment

| Component | Details |
|---|---|
| Platform | TryHackMe |
| Investigation tool | Splunk |
| Primary log source | Linux authentication logs |
| Dataset | `index=linux-alert` |
| Target host | `tryhackme-2404` |
| Investigated source IP | `10.10.242.248` |
| Alert name | Brute Force Activity Detection |
| Alert timestamp | September 17, 2025, 09:00:21 AM (as displayed in the lab) |

The timestamp is the alert's displayed time, not necessarily the beginning of the attack.

---

## 2. Linux Log Sources

Two important Linux log sources were considered during the investigation.

### Authentication Logs — `auth.log`

Authentication logs provide visibility into:

- SSH login attempts.
- Failed authentication.
- Successful authentication.
- Sudo activity.
- User account and authentication-related events.

These logs are particularly valuable for investigating brute-force attacks and unauthorized access.

### System Logs — `syslog`

System logs provide broader operating system visibility, including:

- Service activity.
- Scheduled jobs.
- System processes.
- Background service events.

Correlating authentication and system logs can help analysts reconstruct an attack timeline and identify potential persistence mechanisms.

---

## 3. Initial Alert Investigation

### Finding 1 — SSH Brute-Force Alert

The investigation began with a Splunk alert named:

```text
Brute Force Activity Detection
```

**Alert context:**

```text
Target host: tryhackme-2404
Source IP: 10.10.242.248
```

The alert provided the initial indicators needed to narrow the investigation.

### Investigation Query

```spl
index=linux-alert "10.10.242.248"
```

**Analysis:**

This query searches the investigation dataset for events containing the source IP address associated with the alert.

The analyst can then examine the timestamps, event messages, affected usernames, and authentication outcomes.

**Security significance:**

Repeated SSH authentication failures originating from a single IP address may indicate password guessing or brute-force activity.

However, failed authentication events alone do not confirm successful access.

---

## 4. Authentication Event Analysis

### Finding 2 — Failed SSH Login Attempts

The next objective was to identify failed authentication events and determine which accounts were targeted.

### Investigation Query

```spl
index=linux-alert "Failed password"
```

### Targeted Investigation

```spl
index=linux-alert "Failed password" "10.10.242.248"
```

**Analysis:**

Linux SSH authentication logs commonly include messages such as `Failed password` when a password-based login attempt is unsuccessful.

These messages may contain:

- Target username.
- Source IP address.
- Source port.
- Authentication method.
- Event timestamp.

By examining these fields, the analyst can determine whether the activity is concentrated against one account or distributed across multiple usernames.

### Investigating a Specific User

The lab included an investigation question concerning failed authentication attempts against:

```text
john.smith
```

A focused query can be used to inspect matching events:

```spl
index=linux-alert "Failed password" "john.smith"
```

To obtain a count:

```spl
index=linux-alert "Failed password" "john.smith"
| stats count as failed_attempts
```

**Analysis:**

The `stats count` command calculates the number of matching events.

The result should be interpreted in the context of the selected time range and any additional filters.

The exact count is not reproduced here because the original Splunk result was not retained in the available investigation notes.

---

## 5. Extracting Fields from Raw Linux Logs

### Finding 3 — Structured Analysis of SSH Events

Linux authentication messages are often stored as unstructured or partially structured text.

Regular expressions can be used to extract important values for further analysis.

### Example — Extracting an IPv4 Address

```spl
| rex field=_raw "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
```

**Explanation:**

- `rex` extracts values using a regular expression.
- `field=_raw` tells Splunk to examine the original event text.
- `(?<src_ip>...)` creates a field named `src_ip`.
- `\d{1,3}` matches one to three digits.
- `(?:\.\d{1,3}){3}` matches three additional dot-separated numeric groups.

This pattern identifies IPv4-shaped strings. It does not independently validate that every numeric group is within the valid IPv4 range.

### Example — Extracting Failed SSH Usernames

```spl
index=linux-alert "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?<username>\S+)"
| stats count as failed_attempts by username
| sort - failed_attempts
```

**Analysis:**

The query extracts usernames from typical SSH failed-password messages and groups the events by account.

The optional `invalid user` portion allows the expression to match both known-user and invalid-user login attempts.

This makes it easier to identify accounts receiving the highest number of failed login attempts.

**Limitation:**

Log message formats vary between systems and configurations. Extraction expressions must be validated against the actual event format before relying on the resulting fields.

---

## 6. Attack Duration Analysis

### Finding 4 — Measuring the Authentication Attack Window

Determining the duration of suspicious activity helps an analyst understand the scale and intensity of an attack.

### Investigation Query

```spl
index=linux-alert "Failed password" "10.10.242.248"
| stats min(_time) as start_time max(_time) as end_time count as failed_attempts
| eval duration_minutes=round((end_time-start_time)/60,2)
| convert ctime(start_time) ctime(end_time)
| table start_time end_time duration_minutes failed_attempts
```

### Explanation

- `min(_time)` identifies the earliest matching event.
- `max(_time)` identifies the latest matching event.
- Subtracting the timestamps calculates the elapsed time in seconds.
- Dividing by `60` converts the duration to minutes.
- `round(...,2)` rounds the result to two decimal places.

**Security significance:**

Duration analysis helps distinguish a short burst of authentication attempts from activity sustained over a longer period.

The calculation measures the time between the first and last matching events, not necessarily the complete attacker dwell time.

---

## 7. Successful Authentication Investigation

### Finding 5 — Checking for Potential Account Compromise

After identifying repeated authentication failures, the next step was to investigate whether successful SSH logins occurred.

### Investigation Query

```spl
index=linux-alert "Accepted password"
```

### Source-Focused Investigation

```spl
index=linux-alert "Accepted password" "10.10.242.248"
```

**Analysis:**

An `Accepted password` message indicates that the SSH service accepted password authentication for an account.

If a successful authentication event follows repeated failures from the same source, it may indicate that the attacker obtained valid credentials.

However, a successful login should be correlated with account activity, session information, and other evidence before concluding that it was unauthorized.

**Security significance:**

Distinguishing failed attempts from successful authentication is essential for determining whether an incident requires escalation.

---

## 8. Privilege Escalation Investigation

### Finding 6 — Investigating Elevated Account Activity

The investigation included examining whether the attacker attempted to access an account with higher privileges.

### Example Investigation Query

```spl
index=linux-alert ("sudo" OR "su:" OR "session opened")
```

**Analysis:**

Relevant authentication events can help identify:

- Use of `sudo`.
- Attempts to switch users.
- Privileged session activity.
- Authentication events associated with elevated accounts.

These events must be interpreted together with the surrounding log messages.

For example, the presence of `sudo` in a log does not automatically mean an attacker successfully escalated privileges.

### Investigation Considerations

A SOC analyst should establish:

1. Which account initiated the action.
2. Which account or privilege level was targeted.
3. Whether the operation succeeded.
4. Whether the activity followed suspicious SSH authentication.
5. Whether the resulting privileges were used for additional actions.

The exact privilege escalation outcome is not asserted here because the corresponding original result was not retained.

---

## 9. Persistence Investigation

### Finding 7 — Suspicious Account Creation

The lab also required investigation of a user account potentially created for persistence.

Account creation is an important post-compromise indicator because an attacker may establish an additional means of accessing the system.

### Investigation Query

```spl
index=linux-alert ("useradd" OR "adduser" OR "new user")
```

### Additional Investigation

```spl
index=linux-alert ("usermod" OR "sudo" OR "group")
```

**Analysis:**

These searches help locate events potentially associated with:

- New user creation.
- Account modifications.
- Group membership changes.
- Privileged account activity.

A newly created account should be evaluated against legitimate administrative activity and the incident timeline.

**Security significance:**

Unauthorized account creation can provide persistent access after the original compromised credentials have been changed.

The account name is intentionally not included because its exact value was not preserved in the available investigation evidence.

---

## 10. Reconstructed Investigation Sequence

The following sequence represents the analytical workflow and potential attack stages investigated. It is not a timestamp-verified reconstruction of every attacker action.

| Stage | Activity | Evidence source |
|---|---|---|
| 1 | SSH brute-force alert triggered | Splunk alert |
| 2 | Suspicious source IP identified | Alert context |
| 3 | Failed SSH authentication investigated | Linux authentication logs |
| 4 | Targeted user accounts examined | Username extraction and event filtering |
| 5 | Attack duration calculated | Splunk timestamp aggregation |
| 6 | Successful authentication investigated | SSH accepted-password events |
| 7 | Privilege escalation indicators examined | Sudo and session logs |
| 8 | Persistence indicators investigated | User and account modification events |

---

## 11. Indicators and Investigation Artifacts

| Type | Value |
|---|---|
| Alert | Brute Force Activity Detection |
| Target host | `tryhackme-2404` |
| Source IP | `10.10.242.248` |
| Targeted account investigated | `john.smith` |
| Service | SSH |
| Relevant log source | `auth.log` |
| Investigation platform | Splunk |
| Authentication failure indicator | `Failed password` |
| Authentication success indicator | `Accepted password` |
| Potential persistence activity | User account creation |

*These indicators originate from an authorized training environment and require contextual validation before being used in production detection rules.*

---

## 12. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated authentication attempts |
| Password Guessing | T1110.001 | Possible repeated password attempts |
| Valid Accounts | T1078 | Relevant when compromised credentials are successfully used |
| Create Account: Local Account | T1136.001 | Relevant to unauthorized local account creation |
| Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 | Relevant to suspicious sudo-based privilege escalation |

These mappings include investigated behaviors and possible post-compromise techniques. They do not independently confirm that every technique succeeded.

---

## 13. Detection and Response Recommendations

1. Monitor repeated SSH authentication failures from the same source IP.
2. Correlate failed authentication events with subsequent successful logins.
3. Investigate unusual authentication activity outside normal operating patterns.
4. Apply appropriate SSH access controls and rate-limiting protections.
5. Use key-based authentication and disable password authentication where operationally appropriate.
6. Monitor sudo activity and privileged session creation.
7. Alert on unauthorized user creation and privilege-related account modifications.
8. Correlate authentication, account management, and system events during incident triage.
9. Isolate confirmed compromised systems and revoke exposed credentials according to incident response procedures.

---

## 14. Skills Demonstrated

- Linux authentication log analysis
- Splunk SPL investigations
- SSH brute-force detection
- Source IP correlation
- Username extraction using regular expressions
- Failed authentication counting
- Time-based incident analysis
- Successful login investigation
- Privilege escalation investigation
- Persistence and account creation analysis
- Evidence-based SOC reporting

---

## 15. Conclusion

This investigation demonstrated a structured approach to investigating suspicious SSH authentication activity on a Linux system using Splunk.

Starting from a brute-force alert, the workflow examined failed login attempts, account targeting, authentication outcomes, privilege-related events, and potential persistence indicators.

The exercise strengthened practical SOC Level 1 skills in log filtering, regular expression extraction, statistical aggregation, and incident triage.

The investigation also reinforced the importance of distinguishing suspicious indicators from confirmed compromise.

**Platform:** TryHackMe

**Learning Path:** SOC Level 1

**Focus:** Linux Threat Detection / Splunk SIEM / SSH Brute-Force Investigation

*This investigation was conducted in an authorized cybersecurity training environment.*
