#  Day 8–9 | Documenting Security Events

**Lab Dates:** 12 Mar 2026 – 13 Mar 2026

---

##  Objectives

- Understand why proper documentation is critical in security investigations
- Use the standardized CSV template for event logging
- Complete a full mock incident documentation exercise
- Generate a professional Markdown incident report

---

##  The Security Event Template

Every security event you discover should be logged using this format:

```
Date/Time | Source IP | Event ID | Description | Action Taken
```

### Full CSV Template Fields

| Field | Format | Example |
|-------|--------|---------|
| **Date/Time** | YYYY-MM-DD HH:MM:SS | `2026-03-08 14:35:22` |
| **Source IP** | IPv4 or IPv6 | `192.168.1.10` |
| **Destination IP** | IPv4 or IPv6 | `192.168.1.100` |
| **Event ID** | Integer | `4625` |
| **Log Source** | Log name | `Windows Security Log` |
| **Username** | String | `Administrator` |
| **Hostname** | String | `WORKSTATION01` |
| **Description** | Plain English | `Multiple failed login attempts` |
| **Severity** | LOW / MED / HIGH / CRITICAL | `HIGH` |
| **Action Taken** | What was done | `Blocked IP at firewall` |
| **Analyst** | Your name | `J. Smith` |

---

##  Mock Event Documentation Exercise

### Scenario

You are a SOC Analyst. The SIEM has alerted you to suspicious activity on **08 March 2026** at **14:30 UTC**. You check the Security logs and find:

- **15 failed logins** (Event ID 4625) from `192.168.1.10` in 3 minutes
- All attempts targeted the `Administrator` account
- Logon Type: `3` (Network)
- At **14:33 UTC**, one **successful login** (Event ID 4624) from the same IP

### Step 1 — Fill in the CSV Template

Open `templates/security_event_template.csv` and add these rows:

```
Date/Time,Source IP,Destination IP,Event ID,Log Source,Username,Hostname,Description,Severity,Action Taken,Analyst
2026-03-08 14:30:12,192.168.1.10,192.168.1.100,4625,Windows Security Log,Administrator,WORKSTATION01,Failed login attempt #1 of 15,HIGH,Monitoring,J. Smith
2026-03-08 14:30:19,192.168.1.10,192.168.1.100,4625,Windows Security Log,Administrator,WORKSTATION01,Failed login attempt #2 of 15,HIGH,Monitoring,J. Smith
2026-03-08 14:33:01,192.168.1.10,192.168.1.100,4624,Windows Security Log,Administrator,WORKSTATION01,SUCCESSFUL LOGIN after 15 failed attempts - likely breach,CRITICAL,Isolated host - blocked IP at firewall,J. Smith
```

### Step 2 — Generate the Report

```bash
python scripts/reporting/generate_report.py \
  --csv templates/security_event_template.csv \
  --output reports/incident_report_20260308.md \
  --title "Brute-Force Attack on WORKSTATION01"
```

---

## Documentation Best Practices

### DO 

- Use UTC timestamps consistently
- Be specific: "15 failed logins in 3 minutes" not "many failed logins"
- Record the Event ID, not just a description
- Document what action you took and when
- Include the hostname AND IP (IPs can change)
- Note your name as analyst

### DON'T 

- Write "suspicious activity" without specifics
- Use vague time ranges like "around noon"
- Skip the Action Taken field
- Document after memory fades — log in real time
- Mix timezones (always UTC)

---

## Severity Classification Guide

Use this guide to determine the Severity field:

| Severity | Criteria | Examples |
|----------|----------|---------|
| **LOW** | Isolated, no impact, expected | 1–2 failed logins, policy scan |
| **MEDIUM** | Unusual, potential risk, investigate | 5+ failed logins, unknown service |
| **HIGH** | Clear attack pattern, imminent risk | Brute-force with 10+ attempts |
| **CRITICAL** | Confirmed breach, active attack | Successful login after brute-force |

---

## Action Taken Field Examples

| Situation | Action Taken Entry |
|-----------|-------------------|
| Just monitoring | `Monitoring — no action yet` |
| Blocked attacker | `Blocked 192.168.1.10 at perimeter firewall at 14:35 UTC` |
| Escalated | `Escalated to Tier 2 analyst — ticket #INC-4872` |
| Isolated machine | `Isolated WORKSTATION01 from network at 14:40 UTC` |
| Password reset | `Forced password reset for Administrator account` |
| Notified user | `Notified user J. Smith via Slack at 15:00 UTC` |

---

##  Incident Report Template Structure

The Markdown template (`templates/incident_report_template.md`) includes:

```markdown
# Incident Report — [TITLE]
**Report Date:** [DATE]
**Analyst:** [NAME]
**Severity:** [LEVEL]

## Executive Summary
[2–3 sentence summary of what happened]

## Timeline of Events
| Time (UTC) | Event |
|------------|-------|
| HH:MM | ... |

## Technical Details
### Source IP: xxx.xxx.xxx.xxx
...

## Indicators of Compromise (IOCs)
- IP: xxx.xxx.xxx.xxx
- Username targeted: ...

## Actions Taken
1. ...

## Recommendations
1. ...
```

---

##  Final Checklist — Day 8 & 9

- [ ] Filled in `templates/security_event_template.csv` with all events from the lab
- [ ] Used consistent UTC timestamps throughout
- [ ] Assigned correct severity levels
- [ ] Documented Action Taken for each critical event
- [ ] Generated final incident report with `generate_report.py`
- [ ] Reviewed report for completeness and accuracy
- [ ] Saved all reports in the `reports/` directory

---

## Lab Complete!

You have now completed all 9 days of the Cybersecurity Log Analysis lab. Summary of skills acquired:

 Windows Event Viewer filtering (Event IDs 4625, 7045)  
 CLI log analysis with `wevtutil` and PowerShell `Get-WinEvent`  
 Simulating and detecting brute-force attacks  
 Browser history forensics with Eric Zimmerman's tools  
 Chrome SQLite database analysis  
 Professional security event documentation  
 Automated incident report generation  
