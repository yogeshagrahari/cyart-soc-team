# 02 — Incident Classification

> **Goal:** Accurately classify security incidents using MITRE ATT&CK, ENISA taxonomy, and VERIS framework.

---

## Theory Notes

### 2.1 Incident Categories

| Category | Description | MITRE Tactic | Example |
|----------|-------------|-------------|---------|
| **Malware** | Malicious code execution | Execution (TA0002) | Ransomware, Trojans, Worms |
| **Phishing** | Deceptive email/social engineering | Initial Access (TA0001) | Spear-phishing, BEC |
| **DDoS** | Distributed denial of service | Impact (TA0040) | SYN flood, DNS amplification |
| **Insider Threat** | Malicious/accidental internal actor | Exfiltration (TA0010) | Unauthorized data export |
| **Data Exfiltration** | Unauthorized data transfer | Exfiltration (TA0010) | Sensitive data sent to C2 |
| **Unauthorized Access** | Compromised credentials / privilege escalation | Privilege Escalation (TA0004) | Admin account compromise |
| **Web Attack** | Application layer attacks | Initial Access (TA0001) | SQL injection, XSS |
| **Supply Chain** | Compromised software/hardware | Initial Access (TA0001) | SolarWinds-type attack |

---

### 2.2 MITRE ATT&CK Framework Overview


#### Key Techniques for Tier 1 Analysts

| Technique ID | Name | Description | Detection Method |
|-------------|------|-------------|-----------------|
| T1566 | Phishing | Email with malicious link/attachment | Email header analysis, URL scanning |
| T1078 | Valid Accounts | Use of stolen credentials | Failed/successful login correlation |
| T1059 | Command Scripting | PowerShell, cmd, bash abuse | Process monitoring, Sysmon |
| T1486 | Data Encrypted for Impact | Ransomware | File integrity monitoring |
| T1071 | App Layer Protocol | C2 over HTTP/S/DNS | Proxy logs, DNS analysis |
| T1190 | Exploit Public App | Web/service exploitation | WAF alerts, patch status |
| T1110 | Brute Force | Password spraying, guessing | Auth log analysis |
| T1041 | Exfil over C2 Channel | Data sent to attacker | Outbound traffic analysis |

---

### 2.3 VERIS Framework — Contextual Metadata

The **Vocabulary for Event Recording and Incident Sharing (VERIS)** provides standardized schema.

```
VERIS Incident Record Structure:
═══════════════════════════════

incident_id:    INC-2025-001
summary:        Phishing email led to credential theft
status:         Closed

actors:
  external:
    motive:     Financial
    variety:    Unknown group

actions:
  social:
    variety:    Phishing
    vector:     Email

assets:
  affected:
    - variety:  User Device
      attribute: Confidentiality

impact:
  overall_rating:   High
  loss:
    - variety:      Data
      amount:       500 records
```

---

### 2.4 Enrichment with Contextual Metadata

Every classified incident should include:

| Metadata Field | Description | Example |
|---------------|-------------|---------|
| **Affected Systems** | Hostnames/IPs involved | prod-web-01, 10.0.0.15 |
| **Timestamps** | Detection, start, end times | 2025-08-18 11:00 UTC |
| **IOCs** | Indicators of Compromise | Hash, IP, domain, email |
| **Source/Destination** | Traffic origin and target | 45.33.32.156 → 10.0.0.20 |
| **User Accounts** | Involved user/service accounts | admin@company.com |
| **MITRE Technique** | Mapped ATT&CK technique | T1566.001 |
| **Severity** | Assigned priority | P2-High |

---

## Practical: MITRE ATT&CK Alert Mapping Table

### How to Use MITRE ATT&CK Navigator

**Step 1:** Go to https://mitre-attack.github.io/attack-navigator/

**Step 2:** Click "Create New Layer" → "Enterprise ATT&CK"

**Step 3:** Select techniques you've encountered and color-code by priority level.

---

### Incident Classification Log Template

| Inc ID | Date | Category | MITRE Tactic | Technique ID | Source IP | Target Asset | IOCs | Severity |
|--------|------|----------|-------------|-------------|-----------|-------------|------|---------|
| INC-001 | 2025-08-18 | Phishing | Initial Access | T1566.001 | External | User Mailbox | malicious-link.ru | P2-High |
| INC-002 | 2025-08-18 | Malware | Execution | T1059.001 | 10.0.0.50 | workstation-22 | crypto_locker.exe | P1-Critical |
| INC-003 | 2025-08-18 | Brute Force | Credential Access | T1110.001 | 192.168.1.100 | SSH Server | 240 failed attempts | P3-Medium |

---

## Resources

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [VERIS Framework](http://veriscommunity.net/)
- [ENISA Incident Taxonomy](https://www.enisa.europa.eu/publications/reference-incident-classification-taxonomy)
- [SANS Phishing Case Studies](https://www.sans.org/reading-room/)
