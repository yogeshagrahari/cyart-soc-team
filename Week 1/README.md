#  Cybersecurity Log Analysis — Practical Lab

> **Lab Duration:** 05 March 2026 – 13 March 2026  
> **Skill Level:** Beginner → Intermediate  
> **Environment:** Windows 10/11 VM + Python 3.x

A hands-on cybersecurity lab covering **Windows Event Log analysis**, **browser history forensics**, **brute-force detection**, and **security event documentation** using industry-standard tools.

---

##  Repository Structure

```
cybersecurity-log-analysis/
├── README.md                          ← You are here
├── docs/
│   ├── 01-windows-event-viewer.md     ← Event Viewer filtering guide
│   ├── 02-browser-history-analysis.md ← Chrome history forensics
│   ├── 03-brute-force-detection.md    ← Brute-force lab walkthrough
│   ├── 04-zimmerman-tools.md          ← LECmd & Eric Zimmerman tools
│   └── 05-documentation-template.md  ← How to document security events
├── scripts/
│   ├── windows/
│   │   ├── generate_failed_logins.ps1  ← Simulate brute-force attempts
│   │   ├── filter_event_4625.ps1       ← Extract failed login events
│   │   ├── filter_event_7045.ps1       ← Extract new service creations
│   │   └── export_events_csv.ps1       ← Export Security log to CSV
│   ├── analysis/
│   │   ├── brute_force_detector.py     ← Python brute-force analyzer
│   │   └── parse_chrome_history.py     ← Chrome SQLite history parser
│   └── reporting/
│       └── generate_report.py          ← Auto-generate incident report
├── templates/
│   ├── security_event_template.csv     ← Blank CSV template
│   └── incident_report_template.md     ← Markdown report template
├── logs/
│   └── sample/
│       ├── sample_events_4625.xml      ← Sample failed login events
│       ├── sample_events_7045.xml      ← Sample service install events
│       └── sample_chrome_history.db   ← Mock Chrome history DB
└── reports/
    └── sample_incident_report.md       ← Example completed report
```

---

##  Lab Schedule

| Day | Date | Task |
|-----|------|------|
| Day 1 | 05 Mar 2026 | Setup: VM, Python, tools installation |
| Day 2 | 06 Mar 2026 | Windows Event Viewer — filter Event ID 4625 |
| Day 3 | 07 Mar 2026 | Windows Event Viewer — filter Event ID 7045 |
| Day 4 | 08 Mar 2026 | Generate fake brute-force & detect it |
| Day 5 | 09 Mar 2026 | Export Security log events to CSV |
| Day 6 | 10 Mar 2026 | Download & run Eric Zimmerman's LECmd |
| Day 7 | 11 Mar 2026 | Parse Chrome history for malicious URLs |
| Day 8 | 12 Mar 2026 | Document security events using template |
| Day 9 | 13 Mar 2026 | Generate final incident report |

---

##  Prerequisites

### System Requirements
- Windows 10 or Windows 11 (physical or VM)
- Python 3.9 or later
- PowerShell 5.1 or later (built-in)
- Administrator privileges on the Windows machine

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Required Tools (Free)
| Tool | Purpose | Download |
|------|---------|----------|
| Eric Zimmerman's LECmd | Parse LNK/Chrome history | [ericzimmerman.github.io](https://ericzimmerman.github.io) |
| LogParser Lizard | GUI for Windows log queries | [lizard-labs.com](https://lizard-labs.com) |
| DB Browser for SQLite | View Chrome history DB | [sqlitebrowser.org](https://sqlitebrowser.org) |

---

##  Quick Start

### Step 1 — Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/cybersecurity-log-analysis.git
cd cybersecurity-log-analysis
```

### Step 2 — Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — (Windows) Run PowerShell Scripts as Administrator
```powershell
# Right-click PowerShell → Run as Administrator
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 4 — Follow the Day-by-Day Docs
Start with [`docs/01-windows-event-viewer.md`](docs/01-windows-event-viewer.md)

---

##  Lab Tasks Overview

### Task 1 — Windows Event Viewer Analysis
- Filter **Event ID 4625** (failed logins) from Security log
- Filter **Event ID 7045** (new service installed)
- Identify patterns consistent with brute-force attacks

### Task 2 — Browser History Forensics
- Parse Chrome's `History` SQLite database
- Search for visits to suspicious/test URLs
- Export findings to CSV

### Task 3 — Brute-Force Detection (Advanced)
- Use PowerShell to simulate 10+ failed login attempts
- Filter Event ID 4625 and look for repeated source IPs
- Export results to `reports/brute_force_results.csv`

### Task 4 — Security Event Documentation
- Use the CSV template to log each discovered event
- Fill in: `Date/Time | Source IP | Event ID | Description | Action Taken`
- Generate a final Markdown incident report

---

#  Mini SOC Lab — Security Operations Center Setup

> **Project Duration:** 05-03-2026 to 13-03-2026  
> **Stack:** Wazuh (SIEM) + Elastic SIEM + Kibana + Grafana + Osquery  
> **Framework:** MITRE ATT&CK  

---

##  Table of Contents

1. [Project Overview](#-project-overview)
2. [Architecture](#-architecture)
3. [Prerequisites](#-prerequisites)
4. [Day-by-Day Timeline](#-day-by-day-timeline)
5. [Quick Start](#-quick-start)
6. [Step 3: Monitoring Dashboards](#-step-3-monitoring-dashboards)
7. [Step 4: Alert Rules Configuration](#-step-4-alert-rules-configuration)
8. [Advanced Tasks](#-advanced-tasks)
9. [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
10. [Validation & Testing](#-validation--testing)
11. [Troubleshooting](#-troubleshooting)
12. [References](#-references)

---

##  Project Overview

This repository documents the complete setup of a **Mini Security Operations Center (SOC) Lab** for hands-on practice in:

- Real-time security monitoring with Wazuh and Elastic SIEM
- Visualization of threats using Kibana and Grafana dashboards
- Custom alert rules for detecting brute-force attacks
- Endpoint visibility using Osquery
- Threat mapping using MITRE ATT&CK framework

| Component       | Role                          | Version  |
|----------------|-------------------------------|----------|
| Wazuh          | SIEM / EDR                    | 4.7.x    |
| Elastic Stack  | Log indexing & SIEM rules     | 8.12.x   |
| Kibana         | Visualization & dashboards    | 8.12.x   |
| Grafana        | Metrics & monitoring charts   | 10.x     |
| Osquery        | Endpoint visibility           | 5.x      |

---

##  Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     MINI SOC LAB                        │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │ Endpoint │───│  Wazuh   │───│  Wazuh Dashboard │  │
│  │  Agent   │    │  Manager │    │   (Port 443)     │  │
│  └──────────┘    └────┬─────┘    └──────────────────┘  │
│                       │                                  │
│  ┌──────────┐    ┌────▼─────┐    ┌──────────────────┐  │
│  │ Osquery  │───│ Elastic  │───│  Kibana SIEM     │  │
│  │ Agent    │    │  Stack   │    │   (Port 5601)    │  │
│  └──────────┘    └────┬─────┘    └──────────────────┘  │
│                       │                                  │
│                  ┌─────────┐    ┌──────────────────┐  │
│                  │Prometheus│───│  Grafana         │  │
│                  │ Metrics  │    │   (Port 3000)    │  │
│                  └──────────┘    └──────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

##  Prerequisites

### System Requirements

| Resource | Minimum  | Recommended |
|----------|----------|-------------|
| RAM      | 8 GB     | 16 GB       |
| CPU      | 4 cores  | 8 cores     |
| Disk     | 50 GB    | 100 GB SSD  |
| OS       | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

### Software Requirements

```bash
# Install Docker & Docker Compose
sudo apt update && sudo apt install -y docker.io docker-compose git curl wget

# Install Osquery
wget -qO- https://pkg.osquery.io/deb/pubkey.gpg | sudo tee /etc/apt/trusted.gpg.d/osquery.asc
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt update && sudo apt install -y osquery
```

---

##  Day-by-Day Timeline

| Date       | Day | Task                                          | 
|------------|-----|-----------------------------------------------|
| 05-03-2026 | 1   | Environment setup, Docker, Wazuh install      |
| 06-03-2026 | 2   | Elastic Stack + Kibana deployment             |
| 07-03-2026 | 3   | Wazuh-Elastic integration, index setup        |
| 08-03-2026 | 4   | Osquery installation and endpoint enrollment  |
| 09-03-2026 | 5   | **Kibana & Grafana dashboards (Step 3)**      |
| 10-03-2026 | 6   | **Elastic SIEM alert rules (Step 4)**         |
| 11-03-2026 | 7   | **Wazuh custom alert rule + SSH simulation**  |
| 12-03-2026 | 8   | MITRE ATT&CK mapping + alert validation       |
| 13-03-2026 | 9   | Documentation, reporting, final review        |

---

##  Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/mini-soc-lab.git
cd mini-soc-lab

# 2. Set environment variables
cp .env.example .env
nano .env   # Edit passwords and IPs

# 3. Start the full stack
docker-compose up -d

# 4. Wait for services to be healthy (~3-5 minutes)
docker-compose ps

# 5. Access dashboards
# Kibana:  http://localhost:5601  (elastic/changeme)
# Grafana: http://localhost:3000  (admin/admin)
# Wazuh:   https://localhost:443  (admin/SecretPassword)
```

---

## Monitoring Dashboards

> **When to apply:** Day 5 (09-03-2026)  
> **Where to apply:** Kibana UI (port 5601) and Grafana UI (port 3000)

### 3.1 Kibana — Top 10 Source IPs Dashboard

**Where:** Kibana → Stack Management → Saved Objects → Import  
**File:** [`dashboards/kibana-top10-ips.ndjson`](dashboards/kibana-top10-ips.ndjson)

#### Manual Steps in Kibana UI:

1. Open **Kibana** at `http://localhost:5601`
2. Navigate to **Visualize Library** → **Create Visualization**
3. Select **Lens** → Choose index pattern `security-login-*`
4. Set:
   - X-axis: `source.ip` (Top 10, by count)
   - Y-axis: `Count of records`
   - Chart type: **Horizontal Bar**
5. Add filter: `event.outcome: failure`
6. Save as: `"Top 10 Source IPs - Failed Logins"`

#### Import via API:
```bash
# Run from repo root on 09-03-2026
bash scripts/setup/import-kibana-dashboards.sh
```

---

### 3.2 Kibana — Critical Event IDs Frequency

**Where:** Kibana → Visualize Library → Create new  
**File:** [`dashboards/kibana-event-ids.ndjson`](dashboards/kibana-event-ids.ndjson)

#### Manual Steps:

1. In Kibana → **Visualize Library** → **Create Visualization**
2. Select **Aggregation-based** → **Vertical Bar**
3. Index: `wazuh-alerts-*`
4. Configure:
   - X-axis: `rule.id` (Terms, Top 20)
   - Y-axis: `Count`
   - Add filter: `rule.level >= 10`
5. Save as: `"Critical Event IDs Frequency"`

---

### 3.3 Grafana — Import Pre-built Dashboards

**Where:** Grafana UI → Dashboards → Import  
**File:** [`dashboards/grafana-soc-overview.json`](dashboards/grafana-soc-overview.json)

```bash
# Import Grafana dashboard via API on 09-03-2026
curl -X POST http://admin:admin@localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d @dashboards/grafana-soc-overview.json
```

#### Manual Grafana Steps:

1. Open **Grafana** at `http://localhost:3000`
2. Go to **Dashboards** → **Import**
3. Upload file: `dashboards/grafana-soc-overview.json`
4. Set data source: **Elasticsearch** (pointing to `http://localhost:9200`)
5. Click **Import**

---

### 3.4 Sigma Detection Rules (Pre-built Dashboards)

**Where:** Kibana → Security → Rules → Import  
**File:** [`alerts/elastic/sigma-rules.ndjson`](alerts/elastic/sigma-rules.ndjson)

```bash
# Apply Sigma rules via script on 09-03-2026
bash scripts/setup/import-sigma-rules.sh
```

---

## Configure Alert Rules

> **When to apply:** Day 6 (10-03-2026)  
> **Where to apply:** Kibana → Security → Rules

### 4.1 Elastic SIEM — Detect 5+ Failed Logins in 5 Minutes

**Where:** Kibana → Security → Detection Rules → Create Rule

#### Via Kibana UI:

1. Go to **Kibana** → **Security** → **Detection Rules**
2. Click **Create Rule** → Select **Threshold Rule**
3. Fill in:

```
Rule Name:    Detect 5+ Failed Logins in 5 Minutes
Index:        security-login-*
Query:        event.category:authentication AND event.outcome:failure
Threshold:    group by source.ip, COUNT >= 5
Time window:  5 minutes
Severity:     High
Risk Score:   73
```

4. Set **Actions**: Send email / Slack notification
5. Click **Create & Enable Rule**

#### Via API (apply on 10-03-2026):

```bash
bash scripts/setup/create-elastic-alert-rule.sh
```

This calls:
```json
PUT /api/detection_engine/rules
{
  "name": "Detect 5+ failed logins in 5 minutes",
  "description": "Alerts when a single IP generates 5 or more failed login attempts within 5 minutes",
  "risk_score": 73,
  "severity": "high",
  "index": ["security-login-*"],
  "type": "threshold",
  "query": "event.category:authentication AND event.outcome:failure",
  "threshold": {
    "field": ["source.ip"],
    "value": 5
  },
  "from": "now-5m",
  "enabled": true,
  "tags": ["brute-force", "T1110", "credential-access"]
}
```

---

### 4.2 Test with Simulated Failed SSH Logins

**Where:** Run from attacker VM or local terminal  
**When:** 10-03-2026 (after rule creation)

```bash
# Simulate 6 failed SSH logins to trigger the alert
bash scripts/simulation/simulate-failed-ssh.sh 192.168.1.100

# Or manually:
for i in {1..6}; do
  ssh wronguser@192.168.1.100 -o StrictHostKeyChecking=no 2>/dev/null || true
  sleep 5
done
```

**Verify alert triggered:**
1. Go to **Kibana** → **Security** → **Alerts**
2. Look for: `"Detect 5+ failed logins in 5 minutes"`
3. Check source IP matches your test machine

---

## Advanced Tasks

> **When to apply:** Day 7 (11-03-2026)  
> **Where to apply:** Wazuh Manager configuration files

### Advanced Task 1: Wazuh Custom Alert Rule

**Where:** Wazuh Manager at `/var/ossec/etc/rules/local_rules.xml`  
**File in repo:** [`configs/wazuh/local_rules.xml`](configs/wazuh/local_rules.xml)

#### Step-by-step:

**1. SSH into Wazuh Manager:**
```bash
docker exec -it wazuh-manager bash
# OR if running natively:
ssh admin@<wazuh-manager-ip>
```

**2. Edit the local rules file:**
```bash
nano /var/ossec/etc/rules/local_rules.xml
```

**3. Add the custom rule (copy from `configs/wazuh/local_rules.xml`):**
```xml
<group name="local,syslog,authentication_failed,">

  <!-- Rule: Detect 3+ failed logins in 2 minutes -->
  <rule id="100100" level="10" frequency="3" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <description>Multiple failed SSH logins - Possible brute force attack (3+ in 2 min)</description>
    <mitre>
      <id>T1110</id>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,gpg13_7.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <!-- Rule: Alert when IP is blocked after repeated failures -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <description>SSH brute force attack - IP blocked by active response</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,brute_force,</group>
  </rule>

</group>
```

**4. Apply and restart Wazuh:**
```bash
# Validate config
/var/ossec/bin/wazuh-logtest

# Restart manager
systemctl restart wazuh-manager
# OR inside Docker:
docker restart wazuh-manager
```

**5. Verify rule is loaded:**
```bash
/var/ossec/bin/wazuh-control info
grep "100100" /var/ossec/var/db/rules.db 2>/dev/null || echo "Rule loaded in memory"
```

---

### Advanced Task 2: SSH Failed Login Simulation

**Where:** Run from a separate terminal/VM targeting your monitored host  
**When:** 11-03-2026

```bash
# Full simulation script
bash scripts/simulation/simulate-wazuh-brute-force.sh

# Or manually attempt 4 failed SSH logins within 2 minutes:
TARGET="192.168.1.x"   # Replace with your target IP
for i in {1..4}; do
  echo "Attempt $i..."
  ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
      wrongpassword_user@${TARGET} 2>/dev/null
  sleep 20
done
echo "Simulation complete. Check Wazuh dashboard."
```

---

### Advanced Task 3: Alert Validation in Wazuh Dashboard

**Where:** Wazuh Dashboard → `https://localhost:443`  
**When:** 11-03-2026 (immediately after simulation)

#### Validation Steps:

1. **Login to Wazuh Dashboard**
   ```
   URL:      https://localhost:443
   Username: admin
   Password: SecretPassword  (set in .env)
   ```

2. **Navigate to Security Events:**
   - Go to **Security Events** → **Overview**
   - Filter by: `rule.id: 100100`
   - Time range: Last 15 minutes

3. **Confirm alert fields:**

   | Field            | Expected Value                              |
   |-----------------|---------------------------------------------|
   | `rule.id`       | `100100`                                    |
   | `rule.level`    | `10`                                        |
   | `rule.description` | "Multiple failed SSH logins..."          |
   | `agent.name`    | Your monitored hostname                     |
   | `data.srcip`    | Your attacker IP                            |
   | `mitre.id`      | `T1110`, `T1110.001`                        |

4. **Export evidence:**
   ```bash
   bash scripts/validation/export-wazuh-alert-evidence.sh
   ```

5. **Document rule effectiveness:**
   - Fill in: [`docs/alert-validation-report.md`](docs/alert-validation-report.md)

---

##  MITRE ATT&CK Mapping

> **When to apply:** Day 8 (12-03-2026)  
> **Where:** Wazuh rules + Elastic detection rules

| Technique ID | Technique Name              | Detection Method               | Rule ID  |
|-------------|------------------------------|-------------------------------|----------|
| T1110       | Brute Force                  | Wazuh Rule 100100              | 100100   |
| T1110.001   | Password Guessing            | Wazuh Rule 100100              | 100100   |
| T1078       | Valid Accounts               | Elastic SIEM threshold rule    | custom-1 |
| T1059       | Command & Scripting Interpreter | Osquery process monitor    | osq-001  |
| T1059.001   | PowerShell                   | Wazuh syscheck + auditd        | 92000    |
| T1021.004   | Remote Services: SSH         | auth.log monitoring            | 5760     |

See full mapping: [`mitre-mapping/attack-mapping.md`](mitre-mapping/attack-mapping.md)

---

##  Validation & Testing

```bash
# Run complete validation suite (12-03-2026)
bash scripts/validation/run-all-validations.sh
```

### Checklist

- [ ] Wazuh manager running: `systemctl status wazuh-manager`
- [ ] Elastic indices created: `curl localhost:9200/_cat/indices`
- [ ] Kibana dashboards imported: check Visualize Library
- [ ] Grafana dashboards loaded: `http://localhost:3000`
- [ ] Elastic SIEM rule active: Kibana → Security → Rules
- [ ] Wazuh rule 100100 loaded: check rules file
- [ ] SSH simulation triggered alert: Wazuh dashboard
- [ ] Alert documented: `docs/alert-validation-report.md`

---

##  Troubleshooting

| Problem                         | Solution                                                    |
|--------------------------------|-------------------------------------------------------------|
| Wazuh not starting             | `docker logs wazuh-manager` → check memory (needs 4GB+)    |
| Kibana can't connect to Elastic| Verify `ELASTICSEARCH_HOSTS` in `.env`                     |
| Alert not triggering           | Check index name matches `security-login-*`                 |
| Grafana shows no data          | Set correct Elasticsearch data source URL                   |
| Rule 100100 not matching       | Run `/var/ossec/bin/wazuh-logtest` to debug                 |
| SSH simulation blocked by firewall | `sudo ufw allow 22` on target host                    |

---

##  References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Elastic SIEM Detection Rules](https://github.com/elastic/detection-rules)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Osquery Documentation](https://osquery.readthedocs.io/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)

---

*Lab conducted: 05-03-2026 to 13-03-2026*


## License

MIT License — see [LICENSE](LICENSE)

---

## References

- [Microsoft Docs — Windows Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [Eric Zimmerman Tools](https://ericzimmerman.github.io/#!index.md)
- [SANS Log Management Cheat Sheet](https://www.sans.org/blog/log-management-cheat-sheet/)
- [Elastic SIEM Documentation](https://www.elastic.co/siem)
