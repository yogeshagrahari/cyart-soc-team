#  Document Security Events — Complete README

> **Topic:** How to Document Security Events Systematically
> **Skill Level:** Beginner to Intermediate
> **Purpose:** Build a professional habit of logging cybersecurity incidents with precision and consistency

---

##  Table of Contents

1. [What Is Security Event Documentation?](#1-what-is-security-event-documentation)
2. [Why It Matters](#2-why-it-matters)
3. [Understanding the Template Fields](#3-understanding-the-template-fields)
4. [The Security Event Log Template](#4-the-security-event-log-template)
5. [Step-by-Step: How to Use the Template](#5-step-by-step-how-to-use-the-template)
6. [Mock Event Practice — Failed Login Scenario](#6-mock-event-practice--failed-login-scenario)
7. [Filled-In Mock Event Template](#7-filled-in-mock-event-template)
8. [Multiple Mock Events for Practice](#8-multiple-mock-events-for-practice)
9. [Common Event IDs Reference Table](#9-common-event-ids-reference-table)
10. [Best Practices & Rules](#10-best-practices--rules)
11. [Common Mistakes to Avoid](#11-common-mistakes-to-avoid)
12. [Escalation Levels Guide](#12-escalation-levels-guide)
13. [Tools You Can Use](#13-tools-you-can-use)
14. [Glossary of Terms](#14-glossary-of-terms)

---

## 1. What Is Security Event Documentation?

Security event documentation is the **formal process of recording cybersecurity-related activities** that occur within a network, system, or organization. These events can include:

- Failed or suspicious login attempts
- Unauthorized access to files or systems
- Malware detections
- Firewall rule violations
- User privilege escalations
- Data exfiltration attempts
- Network intrusion alerts

A **Security Event Log** is a structured record that captures each of these incidents in a consistent, readable, and auditable format.

>  Think of it as a "black box recorder" for your IT environment — if something goes wrong, the log tells you exactly what happened, when, where, and what was done about it.

---

## 2. Why It Matters

Security event documentation is not optional — it is a **cornerstone of professional cybersecurity practice** for the following reasons:

| Reason | Explanation |
|--------|-------------|
| **Incident Response** | Helps responders understand the timeline and scope of an attack |
| **Forensic Investigation** | Provides evidence for investigating what happened after a breach |
| **Compliance** | Required by standards like ISO 27001, PCI-DSS, HIPAA, SOC 2 |
| **Pattern Recognition** | Repeated entries reveal attack trends over time |
| **Legal Evidence** | Logs can be used in court or disciplinary proceedings |
| **Post-Incident Review** | Enables teams to learn from and prevent future incidents |
| **Communication** | Allows clear hand-off between shifts, teams, or management |

---

## 3. Understanding the Template Fields

Before you start documenting, understand what each field means and why it is captured:

---

###  Field 1: Date/Time

- **What it is:** The exact timestamp when the event was observed or detected
- **Format:** `YYYY-MM-DD HH:MM:SS` (use 24-hour format for clarity)
- **Why it matters:** Establishes a chronological timeline; critical for forensics
- **Tip:** Always use UTC or specify the timezone (e.g., `2025-07-15 14:32:10 IST`)

=
```

---

###  Field 2: Source IP

- **What it is:** The IP address of the machine or system that triggered the event
- **Format:** Standard IPv4 (`192.168.1.10`) or IPv6 (`2001:db8::1`)
- **Why it matters:** Identifies the origin of the suspicious activity
- **Tip:** Include port number if relevant (e.g., `192.168.1.10:4444`)


```
192.168.1.10
```

>  Note: Internal IPs (192.168.x.x, 10.x.x.x) may indicate insider threat or compromised internal machine. External IPs may indicate external attacker.

---

###  Field 3: Event ID

- **What it is:** A standardized numeric code identifying the type of security event
- **Format:** Numeric (Windows) or alphanumeric code
- **Why it matters:** Allows quick categorization; maps to known threat types
- **Common sources:** Windows Event Viewer, Syslog, SIEM platforms


```
4625  ← Windows Event ID for Failed Login
```

---

###  Field 4: Description

- **What it is:** A clear, concise human-readable explanation of what happened
- **Format:** Plain English, factual, no assumptions
- **Why it matters:** Allows anyone (including non-technical managers) to understand the event
- **Include:**
  - What action occurred
  - Which account or resource was involved
  - How many times (if repeated)
  - Any anomalies noticed

```
Multiple failed login attempts detected from internal IP 192.168.1.10 targeting
the domain admin account 'admin@corp.local'. 15 failed attempts within 3 minutes.
Possible brute-force or credential stuffing attack.
```

---

###  Field 5: Action Taken

- **What it is:** The response actions performed by the security analyst or system
- **Format:** Ordered list of steps taken
- **Why it matters:** Creates accountability and enables review of response effectiveness
- **Include:**
  - Immediate containment steps
  - Who was notified
  - Tools used
  - Follow-up tasks assigned


```
1. Blocked IP 192.168.1.10 at the firewall
2. Locked the targeted user account
3. Notified IT Manager via email
4. Opened Ticket #INC-2025-041
5. Scheduled forensic review of affected machine
```

---

## 4. The Security Event Log Template

Below is the **master template** you should use for all security event documentation:

---

###  BLANK TEMPLATE

```

║              SECURITY EVENT LOG — INCIDENT RECORD                   ║
╠══════════════════════════════════════════════════════════════════════╣
║ Log Entry #    :  [ENTRY NUMBER]                                     ║
║ Logged By      :  [ANALYST NAME / ROLE]                              ║
║ Severity Level :  [ ] LOW   [ ] MEDIUM   [ ] HIGH   [ ] CRITICAL     ║
╠══════════════════════════════════════════════════════════════════════╣
║ DATE / TIME    :  [YYYY-MM-DD HH:MM:SS TZ]                          ║
╠══════════════════════════════════════════════════════════════════════╣
║ SOURCE IP      :  [IP ADDRESS]                                       ║
╠══════════════════════════════════════════════════════════════════════╣
║ EVENT ID       :  [EVENT ID / CODE]                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║ DESCRIPTION    :                                                      ║
║                   [Detailed description of the security event]       ║
║                                                                       ║
╠══════════════════════════════════════════════════════════════════════╣
║ ACTION TAKEN   :                                                      ║
║                   1.                                                  ║
║                   2.                                                  ║
║                   3.                                                  ║
║                   4.                                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║ STATUS         :  [ ] Open    [ ] In Progress    [ ] Resolved        ║
║ TICKET / REF # :  [TICKET NUMBER]                                    ║
║ FOLLOW-UP DATE :  [DATE]                                             ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

###  TABLE FORMAT (For Spreadsheets / Logs)

| Date/Time | Source IP | Event ID | Description | Action Taken |
|-----------|-----------|----------|-------------|--------------|
| `YYYY-MM-DD HH:MM:SS` | `X.X.X.X` | `XXXXX` | Brief description | Actions performed |

---

## 5. Step-by-Step: How to Use the Template

Follow these steps **every time** you document a security event:

---

###  STEP 1 — Detect the Event

**What to do:**
- Monitor your SIEM (Security Information and Event Management) alerts
- Check Windows Event Viewer, firewall logs, IDS/IPS alerts, or antivirus reports
- Identify that an event worthy of logging has occurred

**Questions to ask yourself:**
- Is this unusual behavior?
- Does it deviate from the baseline?
- Could this be a threat indicator?

---

### STEP 2 — Record the Date and Time Immediately

**What to do:**
- Write down the timestamp **the moment you detect the event**
- Use `YYYY-MM-DD HH:MM:SS` format with timezone
- Do NOT rely on memory — capture it in real-time

**Why immediately?**
- Delayed timestamps reduce forensic reliability
- Multiple events may overlap; accurate time separates them

**Command to get current timestamp (Linux):**
```bash
date +"%Y-%m-%d %H:%M:%S %Z"
```

**Command to get current timestamp (Windows PowerShell):**
```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss"
```

---

### STEP 3 — Identify and Record the Source IP

**What to do:**
- Find the originating IP address from your log source
- Check if it is internal (LAN) or external (WAN)
- Run a reverse DNS or WHOIS lookup for external IPs

**Linux command to look up IP info:**
```bash
whois 192.168.1.10
nslookup 192.168.1.10
```

**Windows command:**
```cmd
nslookup 192.168.1.10
```

**Record:**
```
Source IP: 192.168.1.10 (Internal — Engineering Subnet)
```

---

###  STEP 4 — Identify the Event ID

**What to do:**
- Look at the alert source (Event Viewer, SIEM, Syslog)
- Find the numeric Event ID associated with the activity
- Cross-reference the Event ID against a reference table (see Section 9)

**In Windows Event Viewer:**
1. Open `Event Viewer` → `Windows Logs` → `Security`
2. Locate the relevant event entry
3. Note the `Event ID` field (e.g., 4625 = Failed Logon)

**In Linux Syslog:**
```bash
grep "Failed password" /var/log/auth.log
```

---

###  STEP 5 — Write a Clear Description

**What to do:**
- Answer these questions in your description:
  - **What** happened?
  - **Who** (or which account) was involved?
  - **When** did it start? How long did it last?
  - **How many** times did it occur?
  - **Where** on the network did it occur?
  - **What is suspicious** about this?

**Bad description (avoid this):**
```
Login failed multiple times.
```

**Good description (use this):**
```
   15 consecutive failed login attempts detected between 14:32:10 and 14:35:02 UTC
   targeting domain admin account 'admin@corp.local' from internal IP 192.168.1.10
   (assigned to workstation WS-ENGG-07 in the Engineering Department).
   Failure reason: "Wrong Password" (Event ID 4625). Pattern consistent with
   brute-force or credential stuffing attack.
```

---

###  STEP 6 — Document All Actions Taken

**What to do:**
- List every single action performed in response to the event
- Number each action in the order performed
- Include who was notified and when
- Note any tools or commands used

**Template for actions:**
```
1. [TIME] — [ACTION PERFORMED] — By: [YOUR NAME]
2. [TIME] — [NOTIFICATION SENT TO] — Via: [EMAIL/PHONE/TICKET]
3. [TIME] — [CONTAINMENT STEP TAKEN]
4. [TIME] — [FOLLOW-UP TASK CREATED / ASSIGNED]
```

---

###  STEP 7 — Set Status and Assign a Ticket Number

**What to do:**
- Mark the event status: `Open`, `In Progress`, or `Resolved`
- Create a ticket in your ITSM system (Jira, ServiceNow, Freshdesk, etc.)
- Record the ticket number in the log entry for traceability


```
Status: In Progress
Ticket: INC-2025-041
Assigned To: Ravi Kumar (SOC Analyst)
```

---

###  STEP 8 — Review and Store the Log Entry

**What to do:**
- Review the entry for completeness before saving
- Store it in your centralized log system (SIEM, spreadsheet, or database)
- Ensure the file is protected and backed up
- Do not modify a log entry after it has been saved — add amendments as new entries

---

## 6. Mock Event Practice — Failed Login Scenario

**Scenario:**

> You are a SOC Analyst. At 14:32:10 UTC on July 15, 2025, your SIEM triggers an alert. The alert shows that IP address `192.168.1.10` has made **15 consecutive failed login attempts** targeting the domain admin account `admin@corp.local` within 3 minutes. The source machine is identified as workstation `WS-ENGG-07` in the Engineering Department. Windows Event Viewer shows **Event ID 4625** for each failure.

---

**Your task:** Document this event using the security event log template.

---

###  Step-by-Step Walkthrough of This Mock Event

**Step 1 — Detection:**
SIEM alert fires → Category: Authentication Failure → Priority: HIGH

**Step 2 — Date/Time:**
```
2025-07-15 14:32:10 UTC  ← First failure detected
2025-07-15 14:35:02 UTC  ← Last failure detected (event window)
```

**Step 3 — Source IP:**
```
192.168.1.10
Internal IP → Belongs to workstation WS-ENGG-07, Engineering Dept
```

**Step 4 — Event ID:**
```
4625  ← Windows Security Event: "An account failed to log on"
```

**Step 5 — Description:**
Write using the W's: What, Who, When, How Many, Where, Why suspicious.

**Step 6 — Action Taken:**
- Block IP at firewall
- Lock the targeted admin account
- Physically investigate WS-ENGG-07
- Notify IT Manager
- Open incident ticket

**Step 7 — Status:**
```
Status: In Progress → Ticket: INC-2025-041
```

---

## 7. Filled-In Mock Event Template

```
╔══════════════════════════════════════════════════════════════════════╗
║              SECURITY EVENT LOG — INCIDENT RECORD                   ║
╠══════════════════════════════════════════════════════════════════════╣
║ Log Entry #    :  001                                                ║
║ Logged By      :  Ravi Kumar — SOC Analyst                          ║
║ Severity Level :  [ ] LOW   [ ] MEDIUM   [X] HIGH   [ ] CRITICAL    ║
╠══════════════════════════════════════════════════════════════════════╣
║ DATE / TIME    :  2025-07-15 14:32:10 UTC                           ║
╠══════════════════════════════════════════════════════════════════════╣
║ SOURCE IP      :  192.168.1.10                                       ║
║                   (Internal — Workstation WS-ENGG-07,               ║
║                    Engineering Department, 2nd Floor)                ║
╠══════════════════════════════════════════════════════════════════════╣
║ EVENT ID       :  4625                                               ║
║                   (Windows: An account failed to log on)             ║
╠══════════════════════════════════════════════════════════════════════╣
║ DESCRIPTION    :                                                      ║
║  15 consecutive failed login attempts detected between               ║
║  14:32:10 UTC and 14:35:02 UTC. All attempts targeted the           ║
║  domain administrator account 'admin@corp.local' from               ║
║  internal IP 192.168.1.10, assigned to workstation                  ║
║  WS-ENGG-07 in the Engineering Department.                          ║
║                                                                       ║
║  Failure reason: "Wrong Password" on all 15 attempts.               ║
║  Pattern is consistent with a brute-force or credential             ║
║  stuffing attack targeting a privileged account.                    ║
║  No successful logins were recorded.                                 ║
╠══════════════════════════════════════════════════════════════════════╣
║ ACTION TAKEN   :                                                      ║
║  1. [14:36:00] — Blocked IP 192.168.1.10 at perimeter              ║
║                  firewall (Rule ID: FW-BLOCK-0049)                  ║
║  2. [14:36:30] — Locked account 'admin@corp.local' via              ║
║                  Active Directory                                     ║
║  3. [14:37:00] — Notified IT Manager (manager@corp.local)           ║
║                  via email and phone call                            ║
║  4. [14:38:00] — Opened Ticket #INC-2025-041 in ServiceNow         ║
║  5. [14:40:00] — Dispatched physical check of WS-ENGG-07           ║
║                  to verify no unauthorized physical access           ║
║  6. [14:45:00] — Initiated forensic log capture from               ║
║                  SIEM for WS-ENGG-07 (last 24 hours)               ║
╠══════════════════════════════════════════════════════════════════════╣
║ STATUS         :  [ ] Open    [X] In Progress    [ ] Resolved       ║
║ TICKET / REF # :  INC-2025-041                                       ║
║ FOLLOW-UP DATE :  2025-07-16 10:00:00 UTC                           ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

###  Same Event in Table Format

| Date/Time | Source IP | Event ID | Description | Action Taken |
|-----------|-----------|----------|-------------|--------------|
| 2025-07-15 14:32:10 UTC | 192.168.1.10 | 4625 | 15 failed logins targeting admin@corp.local from WS-ENGG-07 within 3 minutes. Brute-force pattern suspected. | Blocked IP at firewall; locked admin account; notified IT Manager; opened INC-2025-041; physical investigation dispatched |

---

## 8. Multiple Mock Events for Practice

Practice documenting these additional mock scenarios:

---

###  Mock Event 2 — Malware Detection

| Field | Value |
|-------|-------|
| **Date/Time** | 2025-07-16 09:15:33 UTC |
| **Source IP** | 10.0.0.55 |
| **Event ID** | 1116 (Windows Defender: Malware detected) |
| **Description** | Windows Defender detected Trojan:Win32/Emotet.AA on workstation HR-PC-03 (10.0.0.55) in the HR Department. The malware was found in the file path `C:\Users\hr_user\Downloads\invoice_July.exe`. File was quarantined automatically. User `hr_user` had downloaded the file from an unverified email attachment at 09:12 UTC. |
| **Action Taken** | 1. Quarantine confirmed via Defender console. 2. Isolated HR-PC-03 from network VLAN. 3. Notified HR Manager and CISO. 4. Opened Ticket INC-2025-042. 5. Sent phishing awareness reminder to HR team. 6. Submitted file hash to VirusTotal for analysis. |

---

###  Mock Event 3 — Unauthorized Port Scan

| Field | Value |
|-------|-------|
| **Date/Time** | 2025-07-17 22:48:05 UTC |
| **Source IP** | 203.0.113.45 (External — Unidentified) |
| **Event ID** | FW-IDS-0031 (Firewall: Port Scan Detected) |
| **Description** | IDS alert triggered for a port scan originating from external IP 203.0.113.45. Scan covered ports 22, 80, 443, 3389, and 8080 on DMZ server 172.16.0.10. Duration: 4 minutes 12 seconds. 1,240 packets detected. No open port exploitation occurred. WHOIS identifies IP to an anonymous proxy service. |
| **Action Taken** | 1. Added 203.0.113.45 to firewall blacklist. 2. Reviewed DMZ server 172.16.0.10 for vulnerabilities. 3. Increased IDS sensitivity on DMZ segment. 4. Opened Ticket INC-2025-043. 5. Added IP to threat intelligence feed. |

---

###  Mock Event 4 — Privilege Escalation Attempt

| Field | Value |
|-------|-------|
| **Date/Time** | 2025-07-18 11:05:22 UTC |
| **Source IP** | 192.168.2.30 |
| **Event ID** | 4672 (Windows: Special privileges assigned to new logon) |
| **Description** | User account `john.doe@corp.local` on workstation WS-FIN-12 (192.168.2.30) attempted to run `net localgroup administrators john.doe /add` at 11:05 UTC. The command was blocked by Group Policy. Account john.doe is a standard Finance Department user with no admin rights. No prior history of privilege escalation attempts. |
| **Action Taken** | 1. Verified block via Group Policy audit log. 2. Disabled john.doe account pending investigation. 3. Interviewed John Doe — claims no knowledge of command. 4. Initiated forensic investigation of WS-FIN-12. 5. Opened Ticket INC-2025-044. 6. Escalated to HR for policy review. |

---

## 9. Common Event IDs Reference Table

### Windows Security Event IDs

| Event ID | Event Name | Severity | Description |
|----------|-----------|----------|-------------|
| **4624** | Successful Logon | INFO | A user successfully logged on |
| **4625** | Failed Logon | MEDIUM–HIGH | An account failed to log on |
| **4634** | Account Logoff | INFO | An account was logged off |
| **4648** | Explicit Credential Logon | MEDIUM | Logon using explicit credentials |
| **4672** | Admin Privileges Assigned | HIGH | Special privileges assigned to new logon |
| **4697** | Service Installed | HIGH | A service was installed on the system |
| **4698** | Scheduled Task Created | MEDIUM | A scheduled task was created |
| **4719** | Audit Policy Changed | HIGH | System audit policy was changed |
| **4720** | User Account Created | MEDIUM | A user account was created |
| **4722** | User Account Enabled | LOW | A user account was enabled |
| **4725** | User Account Disabled | LOW | A user account was disabled |
| **4728** | Member Added to Group | MEDIUM | A member was added to a security group |
| **4732** | Member Added to Local Group | HIGH | A member was added to a local admin group |
| **4738** | User Account Changed | MEDIUM | A user account was changed |
| **4740** | Account Locked Out | HIGH | A user account was locked out |
| **4756** | Member Added to Universal Group | MEDIUM | Added to universal security group |
| **4771** | Kerberos Pre-Auth Failed | MEDIUM | Kerberos authentication failure |
| **4776** | NTLM Auth Attempt | MEDIUM | Computer attempted NTLM credential validation |

### Linux / Syslog Event Types

| Syslog Pattern | Severity | Description |
|---------------|----------|-------------|
| `Failed password` | MEDIUM | SSH failed login attempt |
| `Invalid user` | HIGH | Login attempt with non-existent username |
| `sudo: authentication failure` | HIGH | Failed sudo authentication |
| `POSSIBLE BREAK-IN ATTEMPT` | CRITICAL | Reverse lookup failure (possible spoofing) |
| `accepted publickey` | INFO | Successful SSH key authentication |
| `session opened for user root` | HIGH | Root session started |

---

## 10. Best Practices & Rules

###  Golden Rules of Security Event Documentation

1. **Document in real time** — Never reconstruct events from memory hours later
2. **Be factual, not speculative** — Write what happened, not what you think happened
3. **Be precise with timestamps** — Include timezone; use 24-hour clock
4. **Never delete or alter entries** — Add amendment entries instead
5. **Use standardized formats** — Consistent formatting enables faster analysis
6. **Classify severity every time** — LOW / MEDIUM / HIGH / CRITICAL must always be marked
7. **Link to tickets** — Every event should have a trackable ticket number
8. **Include context** — Add department, hostname, username where known
9. **Document negative findings too** — "No malicious activity found" is a valid log entry
10. **Protect your logs** — Store logs with restricted access; tampered logs are worthless

---

## 11. Common Mistakes to Avoid

|  Mistake |  Correct Approach |
|-----------|-------------------|
| Writing vague descriptions like "weird activity" | Be specific: what, where, when, how many times |
| Forgetting the timezone in timestamps | Always append UTC or local TZ: `2025-07-15 14:32 IST` |
| Skipping the "Action Taken" field | Every event must have a response, even if "No action needed" |
| Using abbreviations without explaining them | Spell out acronyms first: "SIEM (Security Information and Event Management)" |
| Documenting events days after they occurred | Log within minutes of detection |
| Not assigning a ticket number | Always link to your ITSM system for accountability |
| Over-explaining assumptions | Stick to verified facts only |
| Using the same description for multiple similar events | Each event deserves its own unique, specific description |

---

## 12. Escalation Levels Guide

Use this guide to determine how urgently to escalate an event:

| Severity | Criteria | Response Time | Notify |
|----------|----------|--------------|--------|
| 🟢 **LOW** | Informational alert, no immediate threat, single occurrence | 24 hours | Log only |
| 🟡 **MEDIUM** | Suspicious but not confirmed threat, limited scope | 4 hours | SOC Lead |
| 🔴 **HIGH** | Active threat, multiple systems affected, privileged accounts involved | 1 hour | IT Manager + CISO |
| ⚫ **CRITICAL** | Active breach, data exfiltration, ransomware, full system compromise | Immediate | CISO + Executive Team + Legal |

---

## 13. Tools You Can Use

### SIEM Platforms
- **Splunk** — Industry-standard log aggregation and alerting
- **IBM QRadar** — Enterprise SIEM with built-in event correlation
- **Microsoft Sentinel** — Cloud-native SIEM for Azure environments
- **Elastic SIEM** — Open-source option with powerful search

### Log Management
- **Graylog** — Open-source log management
- **Syslog-ng** — Advanced log collection and routing
- **Wazuh** — Open-source security platform

### Documentation & Ticketing
- **ServiceNow** — ITSM platform for incident tickets
- **Jira** — Flexible issue tracker widely used in IT
- **TheHive** — Open-source incident response platform
- **MISP** — Malware Information Sharing Platform

### Investigation Tools
- **Wireshark** — Network packet analysis
- **Sysinternals Suite** — Windows forensic tools
- **VirusTotal** — Online malware and file hash checker
- **Shodan** — Internet-connected device search engine

---

## 14. Glossary of Terms

| Term | Definition |
|------|-----------|
| **SOC** | Security Operations Center — team responsible for monitoring and responding to security events |
| **SIEM** | Security Information and Event Management — software that aggregates and analyzes logs |
| **Event ID** | A numeric code assigned to a specific type of security event by an operating system |
| **Source IP** | The IP address of the device or system that initiated an event |
| **Brute Force** | An attack method where an attacker tries many passwords rapidly to gain access |
| **Credential Stuffing** | Using leaked username/password pairs from other breaches to try to gain access |
| **Privilege Escalation** | An attack where a user gains higher permissions than they are authorized for |
| **IOC** | Indicator of Compromise — evidence that a system has been breached |
| **Forensics** | The scientific examination of digital evidence after a security incident |
| **ITSM** | IT Service Management — system for managing IT services and incident tickets |
| **DMZ** | Demilitarized Zone — a network segment exposed to the internet, separated from internal LAN |
| **Quarantine** | Isolating a file or system to prevent spread of malware |
| **TTPs** | Tactics, Techniques, and Procedures — the behavior patterns of threat actors |
| **CISO** | Chief Information Security Officer — executive responsible for cybersecurity strategy |

---

##  Quick Checklist — Before You Save a Log Entry

Use this checklist every time before saving:

- [ ] Date and Time recorded with correct timezone?
- [ ] Source IP address identified and verified?
- [ ] Event ID noted and looked up?
- [ ] Description is factual, specific, and complete?
- [ ] Description answers: What, Who, When, How Many, Where?
- [ ] All actions taken are documented in order?
- [ ] Each action has a timestamp?
- [ ] Severity level marked (LOW / MEDIUM / HIGH / CRITICAL)?
- [ ] Status set (Open / In Progress / Resolved)?
- [ ] Ticket number assigned and recorded?
- [ ] Follow-up date set if needed?
- [ ] Log entry stored securely and backed up?

---

*This README was created for cybersecurity training and practice purposes.*
*Always follow your organization's incident response policies and procedures.*

---

**End of Document**