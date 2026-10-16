# WordPress Brute-Force Investigation — Splunk SIEM

## 1. Investigation Overview

This project documents a security investigation performed during the TryHackMe SOC Level 1 learning path using Splunk.

The investigation focused on identifying potentially malicious authentication activity against a WordPress login endpoint by analyzing HTTP request logs.

**Investigation Objectives:**
- Identify repeated authentication requests.
- Analyze suspicious HTTP POST activity.
- Group requests into five-minute intervals.
- Identify source IP addresses exceeding an investigation threshold.
- Examine HTTP status codes and user-agent information.
- Determine whether the observed behavior is consistent with a brute-force attack.

**Tool:** Splunk Enterprise

**Data Source:** Web server HTTP logs

**Dataset:** `index=task6`

**Investigation Type:** SIEM Investigation / Web Attack Detection / Authentication Abuse

---

## 2. Investigation Methodology

### Step 1 — Identify WordPress Login Requests

The investigation began by filtering HTTP POST requests targeting the WordPress authentication endpoint.

```spl
index=task6 method=POST uri_path="/wp-login.php"
```

**Analysis:**

- `index=task6` selects the investigation dataset.
- `method=POST` identifies HTTP POST requests.
- `uri_path="/wp-login.php"` focuses on the WordPress login endpoint.

Repeated POST requests to this endpoint may indicate automated login attempts, although the requests must be evaluated in context.

### Step 2 — Group Events into Five-Minute Intervals

```spl
| bin _time span=5m
```

**Analysis:**

The `bin` command groups event timestamps into fixed five-minute intervals.

This allows authentication activity to be analyzed over consistent time windows rather than examining each request individually.

Time-based aggregation helps reveal concentrated bursts of login attempts.

### Step 3 — Aggregate Requests by Source IP

```spl
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
```

**Analysis:**

The `stats` command aggregates events by source IP address and five-minute time interval.

It calculates the number of requests within each group while retaining relevant contextual fields.

**Fields analyzed:**

| Field | Purpose |
|---|---|
| `clientip` | Source IP address |
| `_time` | Five-minute time window |
| `count` | Number of matching requests |
| `status` | HTTP response status codes |
| `useragent` | Client software information |
| `uri_path` | Requested endpoint |
| `referer_domain` | Referring domain, when available |

This approach helps identify which source addresses generated concentrated authentication traffic.

### Step 4 — Identify High-Volume Activity

```spl
| where count > 25
```

**Analysis:**

This condition retains only source IP and time-window combinations containing more than 25 matching requests.

The threshold was used as an investigation criterion in the lab.

It is not a universal brute-force detection threshold. In production environments, thresholds should be adjusted according to normal application traffic and authentication behavior.

### Step 5 — Present Investigation Results

```spl
| table referer_domain clientip UserAgent uri_path count status
```

**Analysis:**

The `table` command organizes the aggregated results into readable columns.

This allows an analyst to compare source IP addresses, request volumes, client information, and HTTP response patterns.

---

## 3. Complete Splunk Detection Query

The following SPL query was used to investigate concentrated WordPress login activity.

```spl
index=task6 method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 25
| table referer_domain clientip UserAgent uri_path count status
```

### Detection Logic

The query identifies source IP addresses generating more than 25 HTTP POST requests to `/wp-login.php` within a fixed five-minute window.

It combines three useful detection elements:

1. **Endpoint targeting:** Requests to a login endpoint.
2. **Request frequency:** High volumes of requests over a short interval.
3. **Source correlation:** Grouping activity by client IP address.

This is a practical starting point for detecting suspected brute-force behavior.

---

## 4. Security Analysis

### Potential Attack Classification

High-frequency POST requests targeting a login endpoint can be consistent with password brute-forcing or automated credential attacks.

However, request volume alone does not establish that an attack succeeded or that every request was malicious.

Additional evidence is needed to distinguish between failed authentication attempts, successful logins, automated testing, and legitimate high-volume traffic.

### Important Investigation Considerations

**HTTP Status Codes**

Response codes can help identify unusual behavior, but a status code alone does not necessarily indicate authentication success or failure.

For example, WordPress may return HTTP 200 for both a successful page response and a failed login attempt.

**User-Agent Analysis**

Repeated requests using the same user-agent string may support an automation hypothesis, but user-agent values can be changed or spoofed.

**Source IP Analysis**

Multiple login attempts from one source may indicate automated activity. However, shared proxies, NAT, and other network infrastructure can cause multiple users to appear under one public IP address.

**Authentication Outcome**

Confirming successful account compromise requires additional evidence, such as application authentication logs, session activity, or correlated events.

---

## 5. Investigation Findings

The investigation developed and applied a Splunk query to identify high-frequency POST requests targeting the WordPress login endpoint.

The query aggregates requests by source IP and five-minute intervals, retaining groups that exceed the specified threshold.

This provides a structured method for identifying suspicious authentication activity and prioritizing events for further investigation.

**Evidence limitations:**

The original event-result table, specific source IP addresses, exact request counts, and authentication outcomes are not reproduced in this report because their original values were not retained in the available investigation notes.

Accordingly, this report documents the investigation method and detection logic without asserting an unverified account compromise.

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated authentication attempts |
| Password Guessing | T1110.001 | Possible repeated password attempts against an account |

These mappings describe behavior that the detection is designed to investigate. They do not independently confirm a successful attack.

---

## 7. Detection and Response Recommendations

1. Monitor login endpoints for unusual request frequency.
2. Correlate source IP addresses with authentication failures and successes.
3. Investigate repeated attempts targeting the same account.
4. Apply appropriate rate limiting and account protection controls.
5. Enable multi-factor authentication where supported.
6. Use contextual detection thresholds to reduce false positives.
7. Escalate confirmed suspicious authentication activity according to incident response procedures.

---

## 8. Skills Demonstrated

- Splunk Search Processing Language (SPL)
- SIEM log filtering
- HTTP request analysis
- Time-based event aggregation
- Statistical analysis using `stats`
- Threshold-based detection
- Source IP correlation
- Web authentication attack investigation
- Alert triage and interpretation

---

## 9. Conclusion

This investigation demonstrated how Splunk can be used to identify potentially malicious authentication activity by combining endpoint filtering, time-based aggregation, and request-volume analysis.

The exercise strengthened practical SOC Level 1 skills in writing SPL queries, investigating web application logs, and distinguishing suspicious indicators from confirmed security incidents.

**Platform:** TryHackMe

**Learning Path:** SOC Level 1

**Focus:** Splunk / Web Security Monitoring / Brute-Force Detection

*This investigation was conducted in an authorized cybersecurity training environment.*
