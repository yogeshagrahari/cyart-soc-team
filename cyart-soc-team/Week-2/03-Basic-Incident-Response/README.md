#  03 — Basic Incident Response

> **Goal:** Master the NIST SP 800-61 Incident Response lifecycle and execute response procedures effectively.

---

##  Theory Notes

### 3.1 The 6-Phase IR Lifecycle (NIST SP 800-61)


### 3.2 Phase-by-Phase Guide

#### Phase 1: Preparation

| Task | Description | Tools |
|------|-------------|-------|
| Create playbooks | Document step-by-step response for each incident type | Google Docs, Confluence |
| Deploy SIEM | Configure log ingestion and correlation rules | Wazuh, Splunk |
| Define roles | Assign Tier 1/2/3 responsibilities | RACI Matrix |
| Setup communication | Establish escalation contacts | Slack, Email templates |
| Baseline assets | Document normal behavior | Asset inventory |

#### Phase 2: Detection & Analysis

```
Detection Sources:
  SIEM Alerts    → Wazuh / Splunk correlation rules
  IDS/IPS        → Snort / Suricata signatures
  Endpoint EDR   → CrowdStrike, Defender ATP
  User Reports   → Help desk tickets
  Threat Intel   → VirusTotal, AlienVault OTX feeds

Analysis Steps:
  Step 1: Verify alert is a true positive (not false positive)
  Step 2: Determine scope — single system or widespread?
  Step 3: Identify affected users/systems
  Step 4: Map to MITRE ATT&CK technique
  Step 5: Assign priority (P1/P2/P3/P4)
  Step 6: Open incident ticket (TheHive)
```

#### Phase 3: Containment

**Short-term Containment (Immediate):**
```bash
# Isolate compromised Linux host from network
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP
sudo iptables -I FORWARD -j DROP

# Disable compromised user account (Linux)
sudo usermod -L compromised_user

# Disable compromised user account (Windows — PowerShell)
Disable-ADAccount -Identity "compromised_user"

# Block attacker IP via iptables
sudo iptables -A INPUT -s 45.33.32.156 -j DROP
sudo iptables -A OUTPUT -d 45.33.32.156 -j DROP

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4
```

**Long-term Containment:**
```bash
# Snapshot the compromised VM before cleanup (VirtualBox)
VBoxManage snapshot "Compromised-VM" take "pre-eradication-snapshot"

# Or VMware
vmrun snapshot /path/to/vm.vmx "pre-eradication"
```

#### Phase 4: Eradication

```bash
# Remove malicious file
sudo rm -f /tmp/crypto_locker.exe
sudo shred -u /tmp/malware_payload.sh   # Secure delete

# Kill malicious process
sudo kill -9 $(pgrep -f "malware_process")

# Remove malicious cron job
crontab -l | grep -v "malicious_command" | crontab -

# Check for persistence mechanisms
sudo systemctl list-units --state=failed
cat /etc/cron.d/*
ls /etc/init.d/
```

#### Phase 5: Recovery

```bash
# Restore from clean backup (rsync example)
sudo rsync -av /backup/clean_system/ /mnt/recovered_system/

# Verify system integrity
sudo aide --check          # AIDE file integrity check
sudo chkrootkit            # Rootkit check
sudo rkhunter --check      # Rootkit hunter

# Re-enable services after validation
sudo systemctl start apache2
sudo systemctl enable apache2
```

#### Phase 6: Lessons Learned

```
Post-Mortem Report Template:
─────────────────────────────
Incident ID:        INC-2025-001
Date of Incident:   2025-08-18
Severity:           P1-Critical
Duration:           4h 32m

What happened?      Ransomware deployed via phishing email
How detected?       Wazuh file integrity alert
Response actions:   Isolated host, removed malware, restored backup
Root cause:         User clicked malicious link; no email filtering
Time to detect:     47 minutes
Time to contain:    1h 15m
Time to recover:    4h 32m

What went well?
  - Fast detection by Wazuh
  - Clean backup available

What needs improvement?
  - Email filtering not configured
  - No phishing awareness training

Action items:
  - [ ] Deploy email gateway filtering (Owner: IT, Due: 2025-09-01)
  - [ ] Conduct phishing simulation (Owner: SOC, Due: 2025-09-15)
  - [ ] Update detection rules (Owner: SOC Lead, Due: 2025-08-25)
```

---

### 3.3 Communication Templates

#### Escalation Email to Tier 2

```
Subject: [P1-CRITICAL] Ransomware Detected — Server: prod-db-01

Hi [Tier 2 Lead],

INCIDENT SUMMARY:
  Time Detected:  2025-08-18 11:43 UTC
  Alert Type:     Ransomware / File Encryption
  Affected Host:  prod-db-01 (10.0.0.25)
  CVSS Score:     9.8 (Critical)

INDICATORS OF COMPROMISE:
  File Hash:  sha256: a3f7d12e4b9c0e5f8a1d3c7e9b2f4a6d8c0e2f4a6d8b0c2e4a6d8f0a2c4e6d
  Filename:   crypto_locker.exe
  Source IP:  45.33.32.156

ACTIONS TAKEN:
  [11:45] Host isolated from network via iptables
  [11:47] Incident ticket created: INC-2025-001 (TheHive)
  [11:50] Memory dump collected and hashed

REQUEST:
  Please take over investigation and authorize recovery procedures.

Analyst: [Your Name]
Tier 1 SOC | CyArt Security Team
```

---

## Resources

- [NIST SP 800-61 Rev 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [Let's Defend SOC Simulations](https://letsdefend.io)
- [Splunk Phantom SOAR](https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html)
