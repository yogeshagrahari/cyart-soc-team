#  Step 3: Set Up Monitoring Dashboards

> **Complete Step-by-Step Guide** — Kibana & Grafana | Top 10 Source IPs | Critical Event IDs | Sigma Detection Rules

---

##  Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Part A — Kibana Setup](#part-a--kibana-setup)
   - [A1. Connect Kibana to Elasticsearch](#a1-connect-kibana-to-elasticsearch)
   - [A2. Create Index Pattern](#a2-create-index-pattern)
   - [A3. Visualization: Top 10 Source IPs](#a3-visualization-top-10-source-ips)
   - [A4. Visualization: Frequency of Critical Event IDs](#a4-visualization-frequency-of-critical-event-ids)
   - [A5. Build the Kibana Dashboard](#a5-build-the-kibana-dashboard)
   - [A6. Import Sigma Detection Rules into Kibana](#a6-import-sigma-detection-rules-into-kibana)
4. [Part B — Grafana Setup](#part-b--grafana-setup)
   - [B1. Install & Start Grafana](#b1-install--start-grafana)
   - [B2. Add Elasticsearch as a Data Source](#b2-add-elasticsearch-as-a-data-source)
   - [B3. Create Panel: Top 10 Source IPs](#b3-create-panel-top-10-source-ips)
   - [B4. Create Panel: Critical Event ID Frequency](#b4-create-panel-critical-event-id-frequency)
   - [B5. Build the Grafana Dashboard](#b5-build-the-grafana-dashboard)
   - [B6. Import Pre-Built Grafana Dashboards](#b6-import-pre-built-grafana-dashboards)
5. [Part C — Sigma Detection Rules](#part-c--sigma-detection-rules)
   - [C1. What Are Sigma Rules?](#c1-what-are-sigma-rules)
   - [C2. Install Sigma CLI Tools](#c2-install-sigma-cli-tools)
   - [C3. Download Sigma Rules Repository](#c3-download-sigma-rules-repository)
   - [C4. Convert Sigma Rules to Elasticsearch/Kibana Format](#c4-convert-sigma-rules-to-elasticsearchkibana-format)
   - [C5. Convert Sigma Rules to Grafana/Loki Format](#c5-convert-sigma-rules-to-grafanaloki-format)
   - [C6. Deploy Rules as Kibana Alerts](#c6-deploy-rules-as-kibana-alerts)
6. [Critical Event IDs Reference](#critical-event-ids-reference)
7. [Alerting & Notifications](#alerting--notifications)
8. [Troubleshooting](#troubleshooting)
9. [Security Best Practices](#security-best-practices)

---

## Prerequisites

Before starting, ensure the following are in place:

| Requirement | Minimum Version | Notes |
|---|---|---|
| Elasticsearch | 8.x | Running and accessible |
| Kibana | 8.x (same as ES) | Same cluster as Elasticsearch |
| Grafana | 9.x or later | Installed separately |
| Python | 3.8+ | Required for Sigma CLI |
| pip | Latest | Python package manager |
| curl / wget | Any | For downloading tools |
| Internet access | — | For downloading Sigma rules repo |

**Verify services are running before proceeding:**

```bash
# Check Elasticsearch
curl -X GET "http://localhost:9200/_cluster/health?pretty"

# Check Kibana
curl -X GET "http://localhost:5601/api/status"

# Check Grafana
curl -X GET "http://localhost:3000/api/health"
```

Expected output for a healthy cluster:

```json
{
  "cluster_name" : "my-cluster",
  "status" : "green",
  "number_of_nodes" : 1
}
```

---

## Architecture Overview

```
Log Sources (Windows/Linux/Network)
        │
        
  [Beats / Logstash]
        │
        
  [Elasticsearch]  ──── Sigma Rules (converted queries)
        │
   ┌────┴────┐
   |         |
[Kibana]  [Grafana]
   │         │
   |         |
Dashboards & Alerts
```

- **Elasticsearch** stores all logs and alert data.
- **Kibana** provides native SIEM dashboards, detection rules, and visualizations.
- **Grafana** provides flexible, metric-style dashboards using Elasticsearch as a data source.
- **Sigma Rules** are vendor-neutral detection rules converted to query formats for each platform.

---

## Part A — Kibana Setup

### A1. Connect Kibana to Elasticsearch

**Step 1:** Open the Kibana configuration file:

```bash
sudo nano /etc/kibana/kibana.yml
```

**Step 2:** Set the Elasticsearch host:

```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "your_password_here"
```

**Step 3:** Save the file and restart Kibana:

```bash
sudo systemctl restart kibana
sudo systemctl status kibana
```

**Step 4:** Open Kibana in your browser:

```
http://localhost:5601
```

Login with your Elasticsearch credentials (default: `elastic` / your password).

---

### A2. Create Index Pattern

An index pattern tells Kibana which Elasticsearch index to read from.

**Step 1:** In the Kibana left sidebar, click **Stack Management**.

**Step 2:** Under **Kibana**, click **Index Patterns** (or **Data Views** in Kibana 8+).

**Step 3:** Click **Create index pattern** (or **Create data view**).

**Step 4:** In the **Name** field, enter your index pattern. Common patterns:

```
winlogbeat-*          # Windows Event Logs
filebeat-*            # General file logs
syslog-*              # Linux syslog
logs-*                # Elastic Agent logs
```

**Step 5:** Select **@timestamp** as the time field.

**Step 6:** Click **Create index pattern**.

**Step 7:** Verify data is flowing:

```bash
# In Kibana Dev Tools (Menu → Dev Tools), run:
GET winlogbeat-*/_count
```

Expected response:

```json
{
  "count": 45231,
  "_shards": { "total": 5, "successful": 5, "failed": 0 }
}
```

---

### A3. Visualization: Top 10 Source IPs Generating Alerts

This creates a bar chart or data table showing the top 10 source IP addresses generating the most alerts.

**Step 1:** In Kibana, go to **Analytics → Visualize Library**.

**Step 2:** Click **Create visualization**.

**Step 3:** Select **Lens** (recommended for ease of use).

**Step 4:** Choose your index pattern (e.g., `winlogbeat-*`).

**Step 5:** In the Lens editor:

- **Visualization type:** Select **Bar vertical stacked** or **Top values table**.
- **Horizontal axis (X-axis):** Drag the field `source.ip` (or `winlog.event_data.IpAddress`) to the horizontal axis.
- **Vertical axis (Y-axis):** Set to **Count of records**.

**Step 6:** Configure the Top Values bucket:

- Click on the X-axis field configuration.
- Set **Number of values** to `10`.
- Set **Order by** to `Count (descending)`.

**Step 7:** Add a filter to show only alerts (optional but recommended):

- Click **+ Add filter** at the top.
- Field: `event.kind`
- Operator: `is`
- Value: `alert`

**Step 8:** Click **Save and return** — name it:

```
Top 10 Source IPs - Alerts
```

---

**Alternative: Using Dev Tools query to verify the data:**

```json
GET winlogbeat-*/_search
{
  "size": 0,
  "query": {
    "term": { "event.kind": "alert" }
  },
  "aggs": {
    "top_source_ips": {
      "terms": {
        "field": "source.ip",
        "size": 10,
        "order": { "_count": "desc" }
      }
    }
  }
}
```

---

### A4. Visualization: Frequency of Critical Event IDs

This creates a time-series or bar chart showing how often critical Windows Event IDs appear.

**Critical Event IDs to monitor** (full reference in [Section 6](#critical-event-ids-reference)):

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Admin privilege assigned |
| 4688 | Process creation |
| 4697 | Service installed |
| 4719 | Audit policy changed |
| 4720 | User account created |
| 4732 | User added to privileged group |
| 7045 | New service installed |

**Step 1:** Go to **Analytics → Visualize Library → Create visualization**.

**Step 2:** Select **Lens**.

**Step 3:** Choose your index pattern.

**Step 4:** Configure the visualization:

- **Visualization type:** Select **Bar vertical**.
- **Horizontal axis:** Drag `winlog.event_id` field.
- Set **Number of values** to `20` (to capture all critical IDs).
- **Vertical axis:** Set to **Count of records**.

**Step 5:** Filter to only show critical Event IDs:

- Click **+ Add filter**.
- Use **KQL (Kibana Query Language)**:

```kql
winlog.event_id: (4624 OR 4625 OR 4648 OR 4672 OR 4688 OR 4697 OR 4719 OR 4720 OR 4732 OR 7045)
```

**Step 6:** Add a date histogram for time-series view (optional):

- Switch to visualization type **Area** or **Line**.
- X-axis: `@timestamp` (auto date histogram).
- Break down by: `winlog.event_id` (top 10 values).

**Step 7:** Save as:

```
Critical Event ID Frequency
```

---

### A5. Build the Kibana Dashboard

Now combine both visualizations into a single dashboard.

**Step 1:** In Kibana, go to **Analytics → Dashboard**.

**Step 2:** Click **Create dashboard**.

**Step 3:** Click **Add from library**.

**Step 4:** Search and add:

- `Top 10 Source IPs - Alerts`
- `Critical Event ID Frequency`

**Step 5:** Arrange panels by dragging them to desired positions.

**Step 6:** Add a time filter control:

- Click **Controls** → **Add control**.
- Type: **Time slider** or use the top-right time picker.
- Set default range: **Last 24 hours**.

**Step 7:** Add a saved search panel (optional):

- Click **Add panel → Add from library**.
- Add a **Discover** saved search showing raw alert events.

**Step 8:** Save the dashboard:

- Click **Save** (top right).
- Name: `Security Monitoring Dashboard`
- Enable **Store time with dashboard** if you want a fixed time range.

**Step 9:** Set auto-refresh:

- Click the clock icon at the top right.
- Set refresh interval: **Every 30 seconds** or **Every 1 minute**.

---

### A6. Import Sigma Detection Rules into Kibana

Kibana SIEM supports importing detection rules that are compatible with the Elastic Common Schema (ECS).

**Step 1:** Go to **Security → Rules → Detection rules (SIEM)**.

**Step 2:** Click **Import rules**.

**Step 3:** Download pre-built Elastic detection rules:

```bash
# Download the Elastic detection rules package
curl -L -o elastic-detection-rules.zip \
  https://github.com/elastic/detection-rules/archive/refs/heads/main.zip

unzip elastic-detection-rules.zip -d elastic-rules/
```

**Step 4:** Import NDJSON rule files:

```bash
# Rules are in the rules/ directory
ls elastic-rules/detection-rules-main/rules/windows/
```

**Step 5:** In Kibana, drag and drop `.ndjson` files into the import dialog, or use the API:

```bash
curl -X POST "http://localhost:5601/api/detection_engine/rules/_import" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  -u elastic:your_password \
  --form "file=@elastic-rules/detection-rules-main/rules/windows/4625_failed_logon.ndjson"
```

**Step 6:** Enable the imported rules:

- In the Rules list, select all imported rules.
- Click **Actions → Enable**.

**Step 7:** Verify rules are running:

- Go to **Security → Rules**.
- Check the **Last response** column — it should show `succeeded`.

---

## Part B — Grafana Setup

### B1. Install & Start Grafana

**On Ubuntu/Debian:**

```bash
# Step 1: Add Grafana GPG key
sudo apt-get install -y software-properties-common wget
sudo wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key

# Step 2: Add Grafana repository
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" \
  | sudo tee /etc/apt/sources.list.d/grafana.list

# Step 3: Update and install
sudo apt-get update
sudo apt-get install -y grafana

# Step 4: Start and enable Grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server

# Step 5: Check status
sudo systemctl status grafana-server
```

**On CentOS/RHEL:**

```bash
# Step 1: Add Grafana repository
sudo tee /etc/yum.repos.d/grafana.repo <<EOF
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF

# Step 2: Install Grafana
sudo yum install grafana -y

# Step 3: Start Grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

**Access Grafana:**

```
http://localhost:3000
Default credentials: admin / admin
(You will be prompted to change the password on first login)
```

---

### B2. Add Elasticsearch as a Data Source

**Step 1:** In Grafana, click the **gear icon (⚙)** in the left sidebar → **Data sources**.

**Step 2:** Click **Add data source**.

**Step 3:** Search for and select **Elasticsearch**.

**Step 4:** Configure the data source:

```
Name:       Elasticsearch-Security
URL:        http://localhost:9200
Access:     Server (default)

Auth:
  Basic auth:  Enabled
  User:       elastic
  Password:   your_password

Elasticsearch details:
  Index name:   winlogbeat-*
  Time field:   @timestamp
  Version:      8.0+
```

**Step 5:** Click **Save & Test**.

Expected message:  `Index OK. Time field name OK.`

---

### B3. Create Panel: Top 10 Source IPs

**Step 1:** In Grafana, click **+ (Plus icon) → Dashboard → Add visualization**.

**Step 2:** Select your **Elasticsearch-Security** data source.

**Step 3:** In the query editor, switch to **Lucene** mode.

**Step 4:** Enter the query:

```
event.kind:alert
```

**Step 5:** Configure the metrics and buckets:

- **Metrics:** Count
- **Group by:** Terms
  - Field: `source.ip.keyword`
  - Size: `10`
  - Order by: `Count`
  - Order: `desc`
  - Min doc count: `1`

**Step 6:** Set visualization type to **Bar gauge** or **Table**:

- In the right panel, under **Visualization**, select **Bar gauge** or **Table**.
- For Table: enable **Show header** and set column widths.

**Step 7:** Set the panel title:

- Click the panel title area.
- Title: `Top 10 Source IPs Generating Alerts`

**Step 8:** Configure display options:

- Under **Standard options**, set **Unit** to `short`.
- Under **Bar gauge**, set **Orientation** to `Horizontal`.
- Set **Display mode** to `Gradient`.

**Step 9:** Click **Apply** to save the panel.

---

### B4. Create Panel: Critical Event ID Frequency

**Step 1:** In the dashboard, click **Add panel → Add visualization**.

**Step 2:** Select **Elasticsearch-Security** data source.

**Step 3:** Enter the Lucene query to filter critical Event IDs:

```
winlog.event_id:(4624 OR 4625 OR 4648 OR 4672 OR 4688 OR 4697 OR 4719 OR 4720 OR 4732 OR 7045)
```

**Step 4:** Configure the metrics:

- **Metrics:** Count
- **Group by:**
  - First bucket: **Date Histogram** on `@timestamp`, interval: `Auto` or `1h`
  - Second bucket (nested): **Terms** on `winlog.event_id.keyword`, size: `10`

**Step 5:** Set visualization type to **Time series** or **Bar chart**:

- For **Time series**: each Event ID becomes a separate series line/area.
- For **Bar chart**: shows total counts per Event ID.

**Step 6:** Set panel title: `Critical Event ID Frequency`

**Step 7:** Configure legend:

- Enable **Legend** → placement: **Bottom**.
- Mode: **Table** (shows count totals in legend).

**Step 8:** Click **Apply**.

---

### B5. Build the Grafana Dashboard

**Step 1:** Add both panels from B3 and B4 to the same dashboard.

**Step 2:** Add a row separator:

- Click **Add panel → Add row**.
- Name the rows: `Source IP Analysis` and `Event ID Analysis`.

**Step 3:** Add a time range variable:

- Click **Dashboard Settings (⚙)** → **Variables** → **Add variable**.
- Type: **Interval**
- Name: `interval`
- Values: `1m,5m,10m,30m,1h,6h,12h,24h`

**Step 4:** Add a text panel with dashboard summary (optional):

- Add panel → **Text** visualization.
- Content (Markdown):

```markdown
## Security Monitoring Dashboard
**Last refreshed:** ${__to:date}
Monitoring: Top Source IPs | Critical Event IDs | Active Alerts
```

**Step 5:** Save the dashboard:

- Click the ** Save** icon.
- Name: `Security Monitoring - SIEM Overview`
- Folder: `Security`
- Click **Save**.

**Step 6:** Set auto-refresh:

- In the top-right time picker, click the refresh icon.
- Set: `30s` auto-refresh.

---

### B6. Import Pre-Built Grafana Dashboards

Grafana has a public dashboard marketplace at [grafana.com/grafana/dashboards](https://grafana.com/grafana/dashboards).

**Step 1:** In Grafana, click **+ → Import**.

**Step 2:** Use the following dashboard IDs for security monitoring:

| Dashboard Name | ID | Purpose |
|---|---|---|
| Elasticsearch – Logs | 5442 | General Elasticsearch log analysis |
| Winlogbeat Overview | 10123 | Windows event logs |
| Filebeat System | 6671 | Linux/system log monitoring |
| Network Traffic Analysis | 11092 | Network flow/IP monitoring |
| SIEM - Security Events | 11992 | Security event overview |

**Step 3:** Enter the dashboard ID in the **Import via grafana.com** field:

```
Example: 10123
```

**Step 4:** Click **Load**.

**Step 5:** Select the data source:

- In the dropdown, select **Elasticsearch-Security**.

**Step 6:** Click **Import**.

**Step 7:** The dashboard is now available under **Dashboards → Browse**.

---

## Part C — Sigma Detection Rules

### C1. What Are Sigma Rules?

Sigma is a generic and open signature format for SIEM systems. A Sigma rule is written in YAML and can be converted to queries for Elasticsearch, Splunk, QRadar, Azure Sentinel, and more.

**Example Sigma Rule (Failed Logon Detection):**

```yaml
title: Failed Logon Attempts
id: dc01e5c0-91f3-4b84-af9c-65a5a7e95f81
status: stable
description: Detects multiple failed logon attempts (Event ID 4625)
author: Sigma Community
date: 2023/01/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
falsepositives:
    - Legitimate failed logon attempts by users
level: medium
tags:
    - attack.credential_access
    - attack.t1110
```

---

### C2. Install Sigma CLI Tools

**Step 1:** Ensure Python 3.8+ is installed:

```bash
python3 --version
```

**Step 2:** Install the Sigma CLI tool using pip:

```bash
pip3 install sigma-cli
```

**Step 3:** Install the Elasticsearch and Kibana backends:

```bash
pip3 install pysigma-backend-elasticsearch
pip3 install pysigma-backend-opensearch
pip3 install pysigma-pipeline-winlogbeat
pip3 install pysigma-pipeline-sysmon
```

**Step 4:** Verify installation:

```bash
sigma version
sigma list backends
sigma list pipelines
```

Expected output:

```
sigma 0.x.x
Available backends:
  elasticsearch  - Elasticsearch Query String and EQL backend
  opensearch     - OpenSearch backend
  ...
```

---

### C3. Download Sigma Rules Repository

**Step 1:** Clone the official Sigma rules repository:

```bash
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
```

**Step 2:** Explore the directory structure:

```bash
ls rules/
# windows/   linux/   cloud/   network/   web/
ls rules/windows/
# builtin/   process_creation/   registry/   network/   ...
```

**Step 3:** Find rules relevant to your environment:

```bash
# Search for logon-related rules
grep -rl "EventID: 4625" rules/windows/

# List all high-severity rules
grep -rl "level: high" rules/windows/ | head -20
```

---

### C4. Convert Sigma Rules to Elasticsearch/Kibana Format

**Step 1:** Convert a single rule to Elasticsearch Lucene query:

```bash
sigma convert \
  -t elasticsearch \
  -p winlogbeat \
  rules/windows/builtin/security/win_security_failed_logon.yml
```

Output example:

```
EventID:4625 AND EventLog.Channel:Security
```

**Step 2:** Convert rules to KQL (Kibana Query Language) format:

```bash
sigma convert \
  -t kibana-ndjson \
  -p ecs-winlogbeat \
  rules/windows/builtin/security/win_security_failed_logon.yml \
  -o failed_logon_rule.ndjson
```

**Step 3:** Convert an entire folder of rules at once:

```bash
# Convert all Windows security rules
sigma convert \
  -t kibana-ndjson \
  -p ecs-winlogbeat \
  rules/windows/builtin/security/ \
  -o windows_security_rules.ndjson
```

**Step 4:** Convert to EQL (Event Query Language) for Elastic SIEM:

```bash
sigma convert \
  -t eql \
  -p ecs-winlogbeat \
  rules/windows/builtin/security/ \
  -o windows_security_eql.txt
```

**Step 5:** Verify the output file:

```bash
cat failed_logon_rule.ndjson | python3 -m json.tool | head -40
```

---

### C5. Convert Sigma Rules to Grafana/Loki Format

If you are using Grafana with Loki (for log storage instead of Elasticsearch):

**Step 1:** Install the Loki backend:

```bash
pip3 install pysigma-backend-loki
```

**Step 2:** Convert rules to LogQL format:

```bash
sigma convert \
  -t loki \
  rules/windows/builtin/security/win_security_failed_logon.yml
```

Output example (LogQL):

```
{job="winlogbeat"} | json | EventID=`4625`
```

---

### C6. Deploy Rules as Kibana Alerts

**Step 1:** Import converted NDJSON rules into Kibana:

```bash
curl -X POST "http://localhost:5601/api/detection_engine/rules/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -u elastic:your_password \
  --form "file=@windows_security_rules.ndjson"
```

**Step 2:** Verify import was successful:

```bash
curl -X GET "http://localhost:5601/api/detection_engine/rules/_find?per_page=100" \
  -H "kbn-xsrf: true" \
  -u elastic:your_password | python3 -m json.tool | grep '"name"'
```

**Step 3:** Enable all imported rules via the API:

```bash
# Get all rule IDs and enable them
curl -X GET "http://localhost:5601/api/detection_engine/rules/_find?per_page=100" \
  -H "kbn-xsrf: true" \
  -u elastic:your_password > rules_list.json

# Enable rules by ID (example for one rule)
curl -X PATCH "http://localhost:5601/api/detection_engine/rules" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -u elastic:your_password \
  -d '{"id": "your-rule-id-here", "enabled": true}'
```

**Step 4:** Configure rule schedule (set to run every 5 minutes):

In Kibana UI:
- Go to **Security → Rules → Detection Rules**.
- Select a rule → **Edit rule settings**.
- Under **Schedule**, set: `Runs every: 5 minutes`.
- Under **Actions**, add notification channels (email, Slack, webhook).

---

## Critical Event IDs Reference

The following Windows Event IDs are the most important to monitor in a security context:

### Authentication Events

| Event ID | Channel | Severity | Description | What to Watch For |
|---|---|---|---|---|
| 4624 | Security | Medium | Successful account logon | Unusual hours, new source IPs |
| 4625 | Security | High | Failed account logon | Brute force (>5 failures/min) |
| 4634 | Security | Low | Account logoff | Abnormally short sessions |
| 4648 | Security | High | Logon with explicit credentials | Pass-the-hash, lateral movement |
| 4672 | Security | High | Special privileges assigned | Unexpected admin logins |
| 4776 | Security | Medium | NTLM authentication | Legacy auth usage |

### Account Management Events

| Event ID | Channel | Severity | Description | What to Watch For |
|---|---|---|---|---|
| 4720 | Security | High | User account created | Unauthorized account creation |
| 4722 | Security | Medium | User account enabled | Dormant account activation |
| 4725 | Security | Medium | User account disabled | Mass account disabling |
| 4726 | Security | High | User account deleted | Evidence tampering |
| 4732 | Security | Critical | Member added to security group | Privilege escalation |
| 4756 | Security | Critical | Member added to universal group | Privilege escalation |

### Process & System Events

| Event ID | Channel | Severity | Description | What to Watch For |
|---|---|---|---|---|
| 4688 | Security | Medium | New process created | Malicious process launch |
| 4697 | Security | High | Service installed | Persistence mechanisms |
| 4698 | Security | High | Scheduled task created | Persistence via task scheduler |
| 4702 | Security | High | Scheduled task modified | Hijacking existing tasks |
| 7045 | System | High | New service installed | Rootkit/backdoor installation |
| 1102 | Security | Critical | Audit log cleared | Evidence tampering |
| 4719 | Security | Critical | Audit policy changed | Disabling security logging |

### Network & Lateral Movement

| Event ID | Channel | Severity | Description | What to Watch For |
|---|---|---|---|---|
| 4768 | Security | Medium | Kerberos TGT requested | Kerberoasting attacks |
| 4769 | Security | Medium | Kerberos service ticket | Ticket harvesting |
| 4771 | Security | High | Kerberos pre-auth failed | Brute force against AD |
| 5156 | Security | Low | Network connection permitted | Unusual outbound connections |
| 5158 | Security | Low | Bind to local port | Port binding by malware |

---

## Alerting & Notifications

### Configure Kibana Alert Actions

**Step 1:** Go to **Stack Management → Rules and Connectors → Connectors**.

**Step 2:** Click **Create connector**.

**Step 3:** Add connectors for notification channels:

**Email Connector:**

```json
{
  "name": "Security Alerts Email",
  "connector_type_id": ".email",
  "config": {
    "from": "siem-alerts@yourdomain.com",
    "host": "smtp.yourdomain.com",
    "port": 587,
    "secure": false
  },
  "secrets": {
    "user": "your_email_user",
    "password": "your_email_password"
  }
}
```

**Slack Connector:**

```json
{
  "name": "Security Alerts Slack",
  "connector_type_id": ".slack",
  "secrets": {
    "webhookUrl": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }
}
```

### Configure Grafana Alert Rules

**Step 1:** In a Grafana panel (e.g., Top 10 IPs), click **Edit**.

**Step 2:** Go to the **Alert** tab.

**Step 3:** Click **Create alert rule from this panel**.

**Step 4:** Configure alert conditions:

```
Condition: WHEN count() OF query(A, 5m, now) IS ABOVE 100
```

**Step 5:** Set evaluation interval: `Every 1m` for `5m`.

**Step 6:** Add notification policy:

- Go to **Alerting → Notification policies**.
- Add a policy routing alerts with label `severity=critical` to your on-call channel.

---

## Troubleshooting

### Problem: No data appearing in Kibana visualizations

**Check 1:** Verify the index pattern matches your actual indices:

```bash
curl -X GET "http://localhost:9200/_cat/indices?v" | grep winlogbeat
```

**Check 2:** Confirm data is within the selected time range:

```bash
curl -X GET "http://localhost:9200/winlogbeat-*/_search?size=1&sort=@timestamp:desc&pretty"
```

**Check 3:** Check the field names match your mapping:

```bash
curl -X GET "http://localhost:9200/winlogbeat-*/_mapping/field/source.ip?pretty"
```

---

### Problem: Sigma rule conversion fails

**Check 1:** Verify the correct pipeline is installed:

```bash
pip3 list | grep pysigma
```

**Check 2:** Use the `--debug` flag:

```bash
sigma convert -t elasticsearch -p winlogbeat rules/windows/... --debug
```

**Check 3:** Check for unsupported rule fields:

```bash
sigma check rules/windows/builtin/security/win_security_failed_logon.yml
```

---

### Problem: Grafana cannot connect to Elasticsearch

**Check 1:** Test the connection from the Grafana server:

```bash
curl -u elastic:password http://localhost:9200/_cluster/health
```

**Check 2:** Check Elasticsearch CORS settings in `elasticsearch.yml`:

```yaml
http.cors.enabled: true
http.cors.allow-origin: "http://localhost:3000"
http.cors.allow-headers: Authorization,X-Requested-With,Content-Type,Content-Length
```

**Check 3:** Restart Elasticsearch after config change:

```bash
sudo systemctl restart elasticsearch
```

---

### Problem: Kibana SIEM detection rules show "failed" status

**Check 1:** Check the rule's exception log:

- Go to **Security → Rules** → click the failed rule → **Failure history** tab.

**Check 2:** Verify the index pattern is set correctly in the rule:

- Edit the rule → **Index patterns** should match your data (e.g., `winlogbeat-*`).

**Check 3:** Ensure the field referenced in the rule exists in the index:

```bash
curl -X GET "http://localhost:9200/winlogbeat-*/_field_caps?fields=winlog.event_id&pretty"
```

---

## Security Best Practices

1. **Use TLS for all communications** — Enable HTTPS for Kibana and Grafana in production. Never send credentials over plain HTTP.

2. **Apply role-based access control (RBAC)** — Create dedicated read-only roles for dashboard viewers. Do not use the `elastic` superuser for dashboards.

3. **Enable audit logging** — In `kibana.yml`, add:
   ```yaml
   xpack.security.audit.enabled: true
   ```

4. **Rotate credentials regularly** — Change Elasticsearch/Kibana passwords every 90 days. Use secrets management tools (Vault, AWS Secrets Manager) in production.

5. **Lock down network access** — Bind Kibana and Grafana to localhost (127.0.0.1) and use a reverse proxy (Nginx/HAProxy) with authentication for external access.

6. **Back up dashboards and rules** — Export dashboard JSON and detection rules regularly:
   ```bash
   # Export Kibana dashboards
   curl -X GET "http://localhost:5601/api/kibana/dashboards/export?dashboard=DASHBOARD_ID" \
     -u elastic:password -o backup_dashboard.json
   ```

7. **Set data retention policies** — Configure ILM (Index Lifecycle Management) in Elasticsearch to control how long logs are kept:
   ```bash
   # 30-day hot, 60-day warm, delete after 90 days
   PUT /_ilm/policy/security-logs-policy
   ```

8. **Monitor the monitors** — Create a meta-alert for when the SIEM rule engine itself fails. Set up an uptime check for Kibana and Grafana availability.

---

*README generated for: Step 3 — Set Up Monitoring Dashboards*
*Covers: Kibana 8.x | Grafana 9.x+ | Sigma CLI | Elasticsearch 8.x*