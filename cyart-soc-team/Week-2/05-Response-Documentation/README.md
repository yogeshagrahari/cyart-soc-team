# 05 — Response Documentation

> **Tools:** Google Docs · Draw.io  
> **Goal:** Create IR templates, investigation logs, checklists, and post-mortems.

---

##  Incident Response Report Template

```

         SECURITY INCIDENT RESPONSE REPORT                     
          CyArt Security Operations Center                    


Incident ID:        INC-2025-001
Report Version:     1.0
Classification:     CONFIDENTIAL — TLP: AMBER
Report Date:        2025-08-18
Prepared By:        SOC Analyst-A
Reviewed By:        SOC Lead

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━
On 2025-08-18 at 11:43 UTC, a ransomware infection was detected
on production database server prod-db-01 (10.0.0.25). The malware
was delivered via a phishing email and encrypted approximately
2.3GB of data. The host was isolated within 2 minutes of detection.
Services were restored from backup within 4.5 hours. No data
was confirmed exfiltrated.

Impact:   Production database offline for 4h 32m
Severity: P1 — Critical
CVSS:     9.8 (Critical)



2. INCIDENT TIMELINE

│ 2025-08-18 10:15 UTC  │ Phishing email received by user        │
│                       │ john.doe@company.com                   │
------------------------------------------------------------------
│ 2025-08-18 11:10 UTC  │ User clicked malicious link in email   │
-----------------------------------------------------------------
│ 2025-08-18 11:41 UTC  │ Malware crypto_locker.exe downloaded   │
│                       │ to C:\Users\Admin\AppData\Local\Temp\  │
------------------------------------------------------------------
│ 2025-08-18 11:43 UTC  │ Wazuh FIM Alert triggered (Rule 550)   │
│                       │ Alert ID: ALT-004                      │
------------------------------------------------------------------
│ 2025-08-18 11:45 UTC  │ Analyst-A notified and began triage    │
------------------------------------------------------------------
│ 2025-08-18 11:47 UTC  │ Host isolated via iptables rules       │
-----------------------------------------------------------------
│ 2025-08-18 11:50 UTC  │ Incident ticket opened in TheHive:     │
│                       │ CS-2025-001                            │
------------------------------------------------------------------
│ 2025-08-18 12:00 UTC  │ Memory dump collected + hashed         │
------------------------------------------------------------------
│ 2025-08-18 12:15 UTC  │ Escalated to Tier 2                    │
------------------------------------------------------------------
│ 2025-08-18 14:00 UTC  │ Malware removed, disk sanitized        │
------------------------------------------------------------------
│ 2025-08-18 16:15 UTC  │ System restored from 2025-08-17 backup │
-----------------------------------------------------------------
│ 2025-08-18 16:17 UTC  │ System monitoring confirmed clean      │
------------------------------------------------------------------


3. AFFECTED ASSETS
━━━━━━━━━━━━━━━━━━

│ Hostname       │ IP Address   │ OS       │ Impact             │
-----------------------------------------------------------------
│ prod-db-01     │ 10.0.0.25    │ Win 2019 │ Files encrypted    │
│ workstation-07 │ 10.0.0.82    │ Win 10   │ Initial vector     │
-----------------------------------------------------------------

4. INDICATORS OF COMPROMISE

Type      Indicator                                    Confirmed?
────────────────────────────────────────────────────────────────
SHA256    a3f7d12e4b9c0e5f8a1d3c7e9b2f4a6d...        YES
Filename  crypto_locker.exe                            YES
C2 IP     45.33.32.156                                 YES
C2 Domain evil-c2.ru                                   YES
Registry  HKCU\Software\Microsoft\Windows\...\Run     YES



5. ROOT CAUSE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━
Primary:    Phishing email with malicious link not filtered
Secondary:  No endpoint DLP / email gateway configured
Tertiary:   User lacked phishing awareness training
            Principle of least privilege not enforced

MITRE ATT&CK Kill Chain:
  T1566.001  → Phishing via link (Initial Access)
  T1204.001  → User clicked link (Execution)
  T1059.001  → PowerShell dropper (Execution)
  T1486      → Data encrypted for impact (Impact)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

6. RESPONSE ACTIONS TAKEN
━━━━━━━━━━━━━━━━━━━━━━━━━
  [x] Host isolated from network (iptables)
  [x] Memory dump collected and preserved
  [x] Malware sample submitted to sandbox
  [x] C2 IP and domain blocked at firewall
  [x] Compromised user account disabled
  [x] Backup restored and validated
  [x] System monitoring re-enabled

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

7. LESSONS LEARNED
━━━━━━━━━━━━━━━━━━
What went well:
  + Wazuh detected malware within 2 minutes of execution
  + Clean backup available (daily backup policy effective)
  + Analyst responded quickly (2 min to isolate)

Gaps identified:
  - No email filtering or anti-phishing gateway
  - Users not trained on phishing awareness
  - No EDR on workstations for early detection
  - Flat network — no segmentation between workstations/servers

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

8. REMEDIATION RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

│ #   │ Action                         │ Owner    │ Due Date  │
--------------------------------------------------------------
│ R1  │ Deploy email security gateway  │ IT Ops   │ 2025-09-01│
│ R2  │ Phishing simulation + training │ HR/SOC   │ 2025-09-15│
│ R3  │ Deploy EDR on all workstations │ IT Ops   │ 2025-10-01│
│ R4  │ Implement network segmentation │ Net Team │ 2025-10-15│
│ R5  │ Review and tighten user privs  │ IT Ops   │ 2025-09-08│

```

---

## Phishing Incident Response Checklist

```
PHISHING INCIDENT RESPONSE CHECKLIST
CyArt SOC — Tier 1 Analyst


Incident ID: _____________    Analyst: _____________
Date: _____________           Start Time: _____________

INITIAL TRIAGE
───────────────
[ ] 1. Confirm email is malicious (not a false positive)
[ ] 2. Check email headers (SPF/DKIM/DMARC failures)
      - Return-Path: ________________
      - Received-From: ________________
      - SPF Result: [ ] Pass  [ ] Fail  [ ] Softfail
[ ] 3. Extract and document URL/attachment from email
[ ] 4. Assign incident priority (P1/P2/P3/P4): ____

THREAT INTELLIGENCE
────────────────────
[ ] 5. Check URL in VirusTotal: https://virustotal.com
      - VT Score: ___/72 engines flagged
[ ] 6. Check URL/IP in AlienVault OTX
      - OTX Pulses: [ ] Found  [ ] Not found
[ ] 7. Check email sender domain reputation
[ ] 8. Search hash (if attachment) in Hybrid Analysis

USER & SYSTEM IMPACT
─────────────────────
[ ] 9.  Identify all recipients of phishing email
[ ] 10. Determine which users clicked the link
[ ] 11. Check if any users entered credentials
[ ] 12. Identify affected endpoints/systems

CONTAINMENT
────────────
[ ] 13. Block malicious URL/domain at web proxy
[ ] 14. Block sender domain in email gateway
[ ] 15. Quarantine all copies of the email
[ ] 16. Isolate any compromised endpoints

EVIDENCE COLLECTION
────────────────────
[ ] 17. Export phishing email as .eml file
[ ] 18. Screenshot email headers and body
[ ] 19. Save VirusTotal/OTX reports as PDF
[ ] 20. Log all IOCs in TheHive case

NOTIFICATION
─────────────
[ ] 21. Notify affected users
[ ] 22. Alert IT to reset passwords if credentials entered
[ ] 23. Brief manager if P1/P2
[ ] 24. Document all actions in incident ticket

CLOSE-OUT
──────────
[ ] 25. Verify all malicious URLs/domains blocked
[ ] 26. Confirm no active malware from link
[ ] 27. Update SIEM rules if new pattern detected
[ ] 28. Document lessons learned
[ ] 29. Close TheHive ticket with resolution summary

Completion Time: _____________   Total Duration: _____________
```

---

##  Investigation Steps Log Template

```
INVESTIGATION LOG — INC-2025-001

│ Timestamp (UTC)          │ Action Taken                        │
------------------------------------------------------------------
│ 2025-08-18 11:43:00     │ Alert received from Wazuh (Rule 550) │
│ 2025-08-18 11:44:30     │ Alert validated — True Positive      │
│ 2025-08-18 11:45:00     │ Host prod-db-01 isolated (iptables)  │
│ 2025-08-18 11:47:00     │ TheHive ticket CS-2025-001 opened    │
│ 2025-08-18 11:50:00     │ Priority assigned: P1-Critical       │
│ 2025-08-18 11:55:00     │ IOC hash checked in VirusTotal       │
│ 2025-08-18 12:00:00     │ Memory dump collected via Velociraptor│
│ 2025-08-18 12:05:00     │ Memory dump hashed: SHA256 a3f7d12e  │
│ 2025-08-18 12:15:00     │ Escalated to Tier 2 via email        │
│ 2025-08-18 12:20:00     │ Attacker C2 IP blocked at firewall   │
│ 2025-08-18 12:30:00     │ IOC cross-referenced with OTX        │
│ 2025-08-18 14:00:00     │ Tier 2: malware removed              │
│ 2025-08-18 16:00:00     │ IT Ops: backup restore initiated     │
│ 2025-08-18 16:15:00     │ System restored and validated        │

```

---

## Non-Technical Manager Briefing

```
TO:      [Manager Name]
FROM:    SOC Team
SUBJECT: Security Incident Summary — Ransomware (Aug 18, 2025)
DATE:    2025-08-18

Dear [Manager],

Today at 11:43 AM, our security monitoring system detected
ransomware (malicious software that locks files) on one of our
production database servers (prod-db-01).

The SOC team immediately isolated the server to prevent spread,
preserved evidence, and escalated to senior analysts. The
malware was removed and the system was restored from a clean
backup made yesterday. The server was back online by 4:15 PM —
a total downtime of approximately 4.5 hours.

No customer data was confirmed as leaked. The attack originated
from a phishing email (a deceptive email designed to trick users).
We have blocked the attacker's address and are deploying additional
email filtering to prevent recurrence.

Action Items:
  - Email security gateway to be deployed by September 1
  - Staff phishing awareness training scheduled for September 15

I am available to discuss further.

CyArt SOC Team
```
