# 06 — Alert Triage Practice

> **Tools:** Wazuh · VirusTotal · AlienVault OTX  
> **Goal:** Simulate alert triage, validate IOCs with threat intelligence, distinguish true positives from false positives.
> **Difficulty:** Intermediate
---

## Prerequisites
- Wazuh manager running
- Wazuh agent installed on a Windows or Linux test VM
- Internet access for threat intel lookups 

##  Alert Triage Workflow

```
INCOMING ALERT
     │
 STEP 1: Read the Alert                                     
    What is the rule? What triggered it?                   
    What is the source IP / hostname?                      
    What is the timestamp?                               


STEP 2: Is this a known false positive pattern?         
   YES → Mark as FP, document, and close               
    NO  → Continue to Step 3                           

 STEP 3: Threat Intelligence Check                         
   Check IP in VirusTotal / AlienVault OTX               
   Check file hash in VirusTotal                         
    Check domain/URL reputation                           

                          │
              -------------------------
               |                      |
      MALICIOUS / SUSPICIOUS     CLEAN / UNKNOWN
              │                       │
                                  
       Open TheHive Ticket         Monitor, log, escalate
        Assign Priority               if pattern repeats
        Contain if P1/P2
```

---

##  Section 1: Wazuh Triage

Simulate a Brute Force SSH Alert
### Step 1: Generate the attack (on Kali Linux)

```bash
# Install Hydra if not present
sudo apt-get install hydra -y

# Create a small wordlist for testing
echo -e "password\n123456\nadmin\nroot\ntest" > /tmp/test-wordlist.txt

# Run SSH brute force against your test VM (ONLY on your own lab!)
# Replace TARGET_IP with your test Ubuntu VM IP
hydra -l root -P /tmp/test-wordlist.txt ssh://TARGET_IP -t 4 -V

# Expected output:
# [22][ssh] host: TARGET_IP   login: root   password: (none found)
# (Wazuh should detect and alert on this)
```

### Accessing Alerts in Wazuh

**Step 2:** Login to Wazuh Dashboard - `https://[wazuh-ip]`

**Step 3:** Navigate to **Security Events** - **Threat Detection**
##Wazuh → Security Events → Filter: rule.id:5763 (or 5760 for SSH failures)
**Step4:** Document the alert

```
TRIAGE LOG — ALERT INC-2026-002
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Field             | Value                    |
|-------------------|--------------------------|
| Alert ID          | WZ-10043                 |
| Alert Type        | Brute-force SSH          |
| Source IP         | 10.0.0.20 (Kali)     |
| Destination IP    | 192.168.1.101 (Target)   |
| Destination Port  | 22 (SSH)                 |
| Attempts          | 47 in 60 seconds         |
| CVSS Score        | 5.3                      |
| Priority          | Medium                   |
| MITRE Tactic      | TA0006 - Credential Access|
| MITRE Technique   | T1110 - Brute Force      |
| Status            | Open                     |
| Analyst           | SOC Analyst-1            |
| Timestamp         | 2026-03-24 11:00 UTC     |
```

## Threat Intelligence Validation

##  Section 2: VirusTotal Analysis

 VirusTotal IP Lookup
```
1. Go to: https://www.virustotal.com/gui/search
2. Enter source IP: 185.220.101.45 (example malicious IP)
3. Check:
   - Detection ratio (engines flagging as malicious)
   - Community comments
   - Last analysis date
   - Associated malware samples
Document findings:
```
**VirusTotal Findings Template:**
```
| Field               | Result                              |
|---------------------|-------------------------------------|
| IP Address          | 10.0.0.25                           |
| Detection Ratio     | 12/87 engines = malicious           |
| Categories          | Phishing, Malware C2                |
| AS Name             | Frantech Solutions                  |
| Country             | Luxembourg                          |
| Last Analysis       | 2026-03-24                          |
| Community Score     | Malicious (17 votes)                |
| Verdict             | ✅ CONFIRMED MALICIOUS              |
```

#### VirusTotal via API (Automated)

```bash
# Install requests if needed
pip3 install requests

# Query hash via API
VT_API_KEY="YOUR_API_KEY_HERE"
FILE_HASH="a3f7d12e4b9c0e5f8a1d3c7e9b2f4a6d8c0e2f4a6d8b0c2e4a6d8f0a2c4e6d"

curl -s "https://www.virustotal.com/api/v3/files/${FILE_HASH}" \
  -H "x-apikey: ${VT_API_KEY}" | python3 -m json.tool | grep -A5 "last_analysis_stats"

# Query IP address
IP="45.33.32.156"
curl -s "https://www.virustotal.com/api/v3/ip_addresses/${IP}" \
  -H "x-apikey: ${VT_API_KEY}" | python3 -m json.tool | grep -A5 "last_analysis_stats"
```

---

##  Section 3: AlienVault OTX Analysis:

# OTX API lookup (replace YOUR_API_KEY with your OTX API key)
# Sign up free at: https://otx.alienvault.com

OTX_API_KEY="your_api_key_here"
```bash

# Look up an IP address
curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/IPv4/185.220.101.45/general" \
  | python3 -m json.tool

# Look up a domain
curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/domain/malicious-domain.xyz/general" \
  | python3 -m json.tool

# Look up a file hash
curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/file/HASH_HERE/general" \
  | python3 -m json.tool
```
**OTX Findings Template:**
```
| Field               | Result                              |
|---------------------|-------------------------------------|
| IP/Hash/Domain      | 10.0.0.25                           |
| Pulse Count         | 8 pulses mention this IOC           |
| Threat Type         | Malware C2, Phishing                |
| Malware Families    | Emotet, TrickBot                    |
| First Seen          | 2025-11-15                          |
| Last Seen           | 2026-03-20                          |
| Related CVEs        | None                                |
| Verdict             | ✅ CONFIRMED MALICIOUS              |
```

### How to Use AlienVault OTX

**Website:** https://otx.alienvault.com  
**Free Registration Required**

#### Step-by-Step IOC Lookup

**Step 1:** Register at https://otx.alienvault.com

**Step 2:** Click **"Indicators"** in the top menu

**Step 3:** Search your IOC (IP, hash, domain, URL)


#### OTX via API (Automated)

```bash
# Install OTX SDK
pip3 install OTXv2

# Python script: check IP in OTX
cat > otx_check.py << 'EOF'
from OTXv2 import OTXv2, IndicatorTypes

API_KEY = "YOUR_OTX_API_KEY"
otx = OTXv2(API_KEY)

# Check IP reputation
ip = "IP"
alerts = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
print(f"\nIP: {ip}")
print(f"Pulse Count: {len(alerts['general']['pulse_info']['pulses'])}")
print(f"Reputation: {alerts['general'].get('reputation', 'N/A')}")

# Check file hash
file_hash = "a3f7d12e4b9c0e5f8a1d3c7e9b2f4a6d8c0e2f4a6d8f0a2c4e6d"
hash_alerts = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, file_hash)
print(f"\nHash: {file_hash[:16]}...")
print(f"Pulse Count: {len(hash_alerts['general']['pulse_info']['pulses'])}")
EOF

python3 otx_check.py
```
## AbuseIPDB Lookup
```bash
# AbuseIPDB API (free account needed)
# Sign up at: https://www.abuseipdb.com

ABUSEIPDB_KEY="your_api_key_here"

curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=185.220.101.45" \
  -d maxAgeInDays=90 \
  -H "Key: $ABUSEIPDB_KEY" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

---

---

##  Triage Results Documentation

### Triage Log Template


### Scenario: Analyze these 5 alerts

**Alert 1: SSH Brute Force**
```
Source IP: 192.168.1.100  Destination: 10.0.0.5:22
Events:    47 failed SSH logins in 60 seconds
```
→ Triage steps:
1. Check if source IP is internal or external
2. Look up in AbuseIPDB (if external)
3. Check if any login was SUCCESSFUL (critical difference!)
4. Check Wazuh for post-login activity if success found
5. Priority: Medium (no success) or Critical (success)

**Alert 2: Suspicious PowerShell**
```
Host: WORKSTATION-03   User: john.doe
Command: powershell.exe -EncodedCommand JABXAGM...
Parent: WINWORD.EXE (Word)
```
→ Triage steps:
1. Decode the base64 payload:
   ```bash
   echo "JABXAGM..." | base64 -d
   ```
2. Identify what the command does (download? reverse shell? persistence?)
3. Check if WINWORD.EXE spawning PowerShell = T1566.001 (Malicious Attachment)
4. MITRE: T1059.001 PowerShell under T1566.001 Phishing Attachment
5. Priority: HIGH (macro malware indicator)

**Alert 3: Nmap Port Scan**
```
Source: 192.168.1.200  Target: 10.0.0.0/24
Wazuh rule: 40101 (Nmap scan detected)
```
→ Triage steps:
1. Is 192.168.1.200 an authorized scanner (IT asset)?
2. Check asset management database
3. Check if scan was during authorized window
4. If unauthorized: Medium-High, document, investigate source
5. Priority: Low-Medium (reconnaissance only)

**Alert 4: Large Data Upload**
```
User: contractor01    Destination: dropbox.com
Data: 2.3 GB upload in 10 minutes  Time: 11:45 PM
```
→ Triage steps:
1. Is Dropbox authorized for this user?
2. Is contractor normally working at 11:45 PM?
3. What data was uploaded? (query DLP/proxy logs)
4. MITRE: T1048 Exfiltration Over Web Service
5. Priority: HIGH (potential data exfiltration)

**Alert 5: Ransomware Behavior**
```
Host: FINANCE-PC-08   Process: explorer.exe
Activity: Mass file renaming (.docx → .locked)
         Shadow copy deletion (vssadmin delete shadows)
```
→ Triage steps:
1. ISOLATE IMMEDIATELY — do not wait
2. This is CONFIRMED ransomware behavior
3. MITRE: T1486 Data Encrypted for Impact
4. Check for lateral movement from this host
5. Priority: CRITICAL — RESPOND NOW

---

## Task 4: Create Triage Summary Table

```
TRIAGE SUMMARY REPORT — 2026-03-24
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| ID  | Alert Type         | Source IP       | Priority | MITRE     | Action Taken            | Status   |
|-----|--------------------|-----------------|----------|-----------|-------------------------|----------|
| 001 | SSH Brute Force    | 192.168.1.100   | Medium   | T1110     | Blocked IP, monitor     | Closed   |
| 002 | Suspicious PS      | WORKSTATION-03  | High     | T1059.001 | Isolated host, IR opened| Escalated|
| 003 | Port Scan          | 192.168.1.200   | Low      | T1046     | Confirmed authorized    | Closed   |
| 004 | Data Upload        | contractor01    | High     | T1048     | User suspended, HR notif| Escalated|
| 005 | Ransomware         | FINANCE-PC-08   | Critical | T1486     | ISOLATED, IR team called| Active   |
```


```
ALERT TRIAGE LOG
--------------------------------------------------------

Alert ID:       ALT-004
Date/Time:      2025-08-18 11:43 UTC
Alert Source:   Wazuh (Rule 100001)
Description:    Brute-force SSH Attempts — 547 in 60 seconds
Source IP:      10.0.0.25
Target:         prod-db-01:22 (10.0.0.25)
Analyst:        Analyst-A

TRIAGE STEPS:
----------------------------------------

Step 1 — False Positive Check:
  Is 192.168.1.100 a known scanner? NO
  Is this a scheduled maintenance window? NO
  → Result: Likely TRUE POSITIVE

Step 2 — VirusTotal IP Check:
  IP: 192.168.1.100
  VT Score: 8/94 vendors flagged
  Categories: SSH Scanner, Brute Force
  → Result: SUSPICIOUS / MALICIOUS

Step 3 — AlienVault OTX Check:
  IP: 192.168.1.100
  OTX Pulses: 3 threat reports
  Associated with: "SSH Brute Force Campaign 2025"
  → Result: CONFIRMED MALICIOUS

Step 4 — Priority Assignment:
  Target Asset Tier: Tier 2 (SSH server)
  Active exploitation: YES (ongoing brute force)
  CVSS (estimated): 7.5
  Priority: P2-HIGH

Step 5 — Action Taken:
  [x] Opened TheHive ticket CS-2025-003
  [x] Source IP blocked via iptables
  [x] Notified Tier 2 analyst

Threat Intel Summary (50 words):
  IP 192.168.1.100 confirmed malicious per AlienVault OTX (3 pulse
  reports) and VirusTotal (8/94 detections). IP associated with SSH
  brute-force campaign active since July 2025. Target prod-db-01 SSH
  service had 547 failed login attempts in 60 seconds. IP has been
  blocked and incident escalated to Tier 2.
```
## OTX Threat Intel Summary (50-word exercise)

**Template:**
```
After cross-referencing [ALERT TYPE] with AlienVault OTX, IP address
[IP] was found in [NUMBER] threat intelligence pulses. The indicator
is associated with [MALWARE/CAMPAIGN NAME]. First observed [DATE],
last seen [DATE]. Confidence: HIGH/MEDIUM/LOW. Recommended action:
[BLOCK/MONITOR/ESCALATE].

After cross-referencing the SSH brute-force alert with AlienVault OTX, 
IP 185.220.101.45 appeared in 8 threat intelligence pulses. The indicator
is associated with the Emotet botnet scanning campaign. First observed 
November 2025, last seen March 2026. Confidence: HIGH. Recommended action:
Block at perimeter firewall and create Wazuh active response rule.
```
## Lab Completion Checklist

- [ ] SSH brute force generated and detected in Wazuh
- [ ] Alert documented in triage log table
- [ ] VirusTotal lookup performed and documented
- [ ] OTX API query executed and results documented
- [ ] All 5 scenario alerts triaged with priorities
- [ ] Triage summary table completed
- [ ] OTX 50-word summary written
- [ ] Screenshots saved to `assets/screenshots/lab03/`

