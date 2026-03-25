# Google Sheets — Alert Classification Tracker

> Tool: Google Sheets  
> Purpose: Track, score, and prioritize alerts with CVSS scoring and MITRE ATT&CK mapping

---

##  Sheet Structure
### Step 1: Create the spreadsheet
```
1. Open Google Sheets → Create new sheet
2. Name it: "SOC-Alert-Tracker"
3. Create headers in Row 1:
```
###  Alert Log

| Column | Field | Description | Example |
|--------|-------|-------------|---------|
| A | Alert ID | Sequential ID | ALT-001 |
| B | Date/Time | Timestamp | 2025-08-18 11:00 |
| C | Alert Source | Tool that generated it | Wazuh |
| D | Alert Description | What happened | SSH Brute Force |
| E | Source IP | Attacker/source IP | 192.168.1.100 |
| F | Target Asset | Affected host | prod-web-01 |
| G | Asset Tier | Criticality tier | Tier 1 |
| H | MITRE Technique | ATT&CK technique | T1110.001 |
| I | CVSS Score | Manual or NVD score | 7.5 |
| J | Priority | Auto-calculated | P2-High |
| K | Analyst | Assigned to | Analyst-A |
| L | Status | Open/In Progress/Closed | Open |
| M | Ticket ID | TheHive ticket | CS-2025-001 |
| N | Notes | Additional context | Correlated with INC-001 |

---

##  Formulas

### Auto-Priority Assignment (Column J)
```
=IF(I2>=9," P1-Critical",IF(I2>=7," P2-High",IF(I2>=4," P3-Medium"," P4-Low")))
```

### Auto-Color Coding (Conditional Formatting Rules)
```
Rule 1: If J = "P1-Critical"  → Background: #FF0000 (Red)
Rule 2: If J = "P2-High"      → Background: #FF8C00 (Orange)
Rule 3: If J = "P3-Medium"    → Background: #FFD700 (Yellow)
Rule 4: If J = "P4-Low"       → Background: #00FF7F (Green)
```

### Count by Priority (Summary Sheet)
```
=COUNTIF(Log!J:J,"*Critical*")   → Count Critical alerts
=COUNTIF(Log!J:J,"*High*")       → Count High alerts
=COUNTIF(Log!J:J,"*Medium*")     → Count Medium alerts
=COUNTIF(Log!J:J,"*Low*")        → Count Low alerts
```

---

##  Sample Data — Alert Log

```
Alert Classification Sheet — Week 2 Practice
══════════════════════════════════════════════════════════════════════════════════


│ Alert ID │ Date/Time         │ Source │ Description             │ Source IP     │ Target       │ Asset Tier│ CVSS     │ Priority   │ Status         │
-------------------------------------------------------------------------------------------------------------------------------------------------------
│ ALT-001  │ 2025-08-18 11:00  │ Wazuh  │ Log4Shell Exploit       │ 45.33.32.156  │ prod-web-01  │ Tier 1    │ 10.0     │ P1-Crit  │ Open           │
│ ALT-002  │ 2025-08-18 11:15  │ Wazuh  │ Port Scan Detected      │ 192.168.1.200 │ test-vm-03   │ Tier 4    │ 2.1      │ P4-Low   │ Closed         │
│ ALT-003  │ 2025-08-18 11:45  │ Wazuh  │ SSH Brute Force         │ 192.168.1.100 │ ssh-server   │ Tier 2    │ 7.5      │ P2-High  │ In Progress    │
│ ALT-004  │ 2025-08-18 12:00  │ Wazuh  │ Ransomware File Create  │ 10.0.0.25     │ prod-db-01   │ Tier 1    │ 9.8      │ P1-Crit  │ Open           │
│ ALT-005  │ 2025-08-18 12:30  │ Wazuh  │ Failed Admin Login      │ 10.0.0.55     │ ad-dc-01     │ Tier 1    │ 5.4      │ P3-Med   │ Closed         │

```

---

##  Sheet 2: MITRE ATT&CK Mapping

```

│ Alert ID │ Technique ID         │ Technique Name    │ Tactic       │ Detection Method            │

│ ALT-001  │ T1190                │ Exploit Public App│ Initial Acc. │ Wazuh web rule + WAF        │
│ ALT-002  │ T1595.001            │ Active Scanning   │ Recon        │ Network IDS signature       │
│ ALT-003  │ T1110.001            │ Password Guessing │ Cred Access  │ Auth log correlation        │
│ ALT-004  │ T1486                │ Data Encrypted    │ Impact       │ FIM + entropy analysis      │
│ ALT-005  │ T1078                │ Valid Accounts    │ Priv Esc     │ Auth log + baseline         │

```

---

##  Setting Up the Sheet (Step by Step)

### Step 1: Create New Google Sheet
1. Go to https://sheets.google.com
2. Click "Blank Spreadsheet"
3. Rename to "CyArt SOC — Week 2 Alert Tracker"

### Step 2: Create Headers (Row 1)
```
A1: Alert ID
B1: Date/Time
C1: Source
D1: Alert Description
E1: Source IP
F1: Target Asset
G1: Asset Tier
H1: MITRE Technique
I1: CVSS Score
J1: Priority
K1: Analyst
L1: Status
M1: TheHive Ticket
N1: Notes
```

### Step 3: Add Priority Formula to J2
```
=IF(I2="","No Score",IF(I2>=9,"P1-Critical",IF(I2>=7,"P2-High",IF(I2>=4,"P3-Medium"," P4-Low"))))
```
Then drag down to J100 to apply to all rows.

### Step 4: Freeze Header Row
- Select Row 1 → View → Freeze → 1 Row

### Step 5: Add Data Validation for Status Column (L)
- Select column L → Data → Data Validation
- List: `Open, In Progress, Closed, False Positive`

### Step 6: Protect Header Row
- Right-click Row 1 → Protect Range → Only allow editors

---

##  Sheet 3: Priority Summary Dashboard

```
=== PRIORITY SUMMARY (Auto-updating) ===

Priority     | Count | % of Total
─────────────────────────────────────
 Critical  |   2   |   28.6%
 High      |   1   |   14.3%
 Medium    |   1   |   14.3%
 Low       |   1   |   14.3%
Total        |   7   |  100.0%

=== STATUS SUMMARY ===
Open         |   2   |
In Progress  |   1   |
Closed       |   2   |
False Positive|  0   |
```

Formulas:
```
=COUNTIF(Log!J:J,"*Critical*")
=COUNTIF(Log!J:J,"*High*")
=COUNTIF(Log!L:L,"Open")
=COUNTIF(Log!L:L,"In Progress")
=COUNTIF(Log!L:L,"Closed")
```
