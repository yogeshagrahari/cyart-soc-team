# Configure Alert Rules — Elastic SIEM & Wazuh
### Complete Step-by-Step Guide: Detect Failed Login Attempts

---

## Table of Contents

1. [Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
2. [Elastic SIEM — Configure Alert Rule](#2-elastic-siem--configure-alert-rule)
   - 2.1 [Access Elastic SIEM Dashboard](#21-access-elastic-siem-dashboard)
   - 2.2 [Create Detection Rule](#22-create-detection-rule)
   - 2.3 [Configure Rule Conditions](#23-configure-rule-conditions)
   - 2.4 [Set Alert Actions & Notifications](#24-set-alert-actions--notifications)
   - 2.5 [Save and Enable the Rule](#25-save-and-enable-the-rule)
3. [Test Elastic SIEM Rule with Simulated SSH Failures](#3-test-elastic-siem-rule-with-simulated-ssh-failures)
4. [Advanced Task — Wazuh Custom Alert Rule](#4-advanced-task--wazuh-custom-alert-rule)
   - 4.1 [Access Wazuh Manager](#41-access-wazuh-manager)
   - 4.2 [Understand Wazuh Rule Structure](#42-understand-wazuh-rule-structure)
   - 4.3 [Create Custom Rule File](#43-create-custom-rule-file)
   - 4.4 [Write the Custom Rule XML](#44-write-the-custom-rule-xml)
   - 4.5 [Reload Wazuh Rules](#45-reload-wazuh-rules)
   - 4.6 [Verify Rule is Loaded](#46-verify-rule-is-loaded)
5. [Test Wazuh Rule with Simulated Failed SSH Logins](#5-test-wazuh-rule-with-simulated-failed-ssh-logins)
   - 5.1 [Identify Target Machine IP](#51-identify-target-machine-ip)
   - 5.2 [Execute Failed SSH Login Attempts](#52-execute-failed-ssh-login-attempts)
   - 5.3 [Automated Test Script](#53-automated-test-script)
6. [Alert Validation in Wazuh Dashboard](#6-alert-validation-in-wazuh-dashboard)
   - 6.1 [Access Wazuh Dashboard](#61-access-wazuh-dashboard)
   - 6.2 [Navigate to Security Events](#62-navigate-to-security-events)
   - 6.3 [Filter for Custom Rule Alerts](#63-filter-for-custom-rule-alerts)
   - 6.4 [Verify Alert Details](#64-verify-alert-details)
7. [Documentation — Rule Effectiveness Report](#7-documentation--rule-effectiveness-report)
8. [Troubleshooting Common Issues](#8-troubleshooting-common-issues)
9. [Reference — Rule IDs & Log Paths](#9-reference--rule-ids--log-paths)

---

## 1. Prerequisites & Environment Setup

Before starting, ensure the following components are installed and running.

### Required Components

| Component        | Minimum Version | Purpose                        |
|------------------|-----------------|--------------------------------|
| Elastic Stack    | 8.x             | SIEM platform & log ingestion  |
| Kibana           | 8.x             | UI for Elastic SIEM            |
| Elasticsearch    | 8.x             | Data storage & search engine   |
| Wazuh Manager    | 4.x             | HIDS & custom rule engine      |
| Wazuh Agent      | 4.x             | Installed on monitored hosts   |
| Filebeat/Winlogbeat | 8.x          | Log shipper to Elasticsearch   |
| OpenSSH Server   | Any             | Target for SSH brute-force test|

### Step 1.1 — Verify Elastic Stack is Running

```bash
# Check Elasticsearch status
sudo systemctl status elasticsearch

# Check Kibana status
sudo systemctl status kibana

# Test Elasticsearch connectivity
curl -X GET "http://localhost:9200/_cluster/health?pretty"
```

**Expected Output:**
```json
{
  "cluster_name" : "my-cluster",
  "status" : "green",
  "number_of_nodes" : 1
}
```

### Step 1.2 — Verify Wazuh Manager is Running

```bash
# Check Wazuh Manager status
sudo systemctl status wazuh-manager

# Alternatively
sudo /var/ossec/bin/ossec-control status
```

**Expected Output:**
```
wazuh-execd is running...
wazuh-analysisd is running...
wazuh-syscheckd is running...
wazuh-monitord is running...
wazuh-logcollector is running...
wazuh-remoted is running...
wazuh-maild is running...
```

### Step 1.3 — Verify Log Index Exists in Elasticsearch

```bash
# List all indices matching the pattern
curl -X GET "http://localhost:9200/security-login-*?pretty"
```

If the index does not exist, create it:

```bash
curl -X PUT "http://localhost:9200/security-login-000001" -H 'Content-Type: application/json' -d'
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "@timestamp":     { "type": "date" },
      "event.outcome":  { "type": "keyword" },
      "user.name":      { "type": "keyword" },
      "source.ip":      { "type": "ip" },
      "host.name":      { "type": "keyword" },
      "message":        { "type": "text" }
    }
  }
}
'
```

### Step 1.4 — Verify Filebeat is Shipping SSH Logs

```bash
# Check Filebeat status
sudo systemctl status filebeat

# Tail Filebeat logs to ensure no errors
sudo tail -f /var/log/filebeat/filebeat

# Verify auth.log is being monitored
sudo grep -A 5 "auth" /etc/filebeat/filebeat.yml
```

---

## 2. Elastic SIEM — Configure Alert Rule

### 2.1 Access Elastic SIEM Dashboard

**Step 1:** Open your web browser and navigate to:
```
http://<your-kibana-host>:5601
```

**Step 2:** Log in with your Kibana credentials:
- **Username:** `elastic` (or your admin username)
- **Password:** `<your-elastic-password>`

**Step 3:** From the left navigation panel, click on the **hamburger menu (☰)** at the top-left corner.

**Step 4:** Scroll down and click on **"Security"** under the Analytics section.

**Step 5:** The Elastic Security overview page will open. Click on **"Alerts"** in the left sub-menu.

**Step 6:** Click on **"Manage Rules"** button (top right of the Alerts page).

---

### 2.2 Create Detection Rule

**Step 1:** On the Rules page, click the blue **"Create new rule"** button in the top-right corner.

**Step 2:** You will see the rule type selection screen. Choose **"Threshold"** rule type.

> **Why Threshold?** Threshold rules trigger when an event count exceeds a defined number within a time window — perfect for detecting repeated failed logins.

**Step 3:** Click **"Continue"** to proceed to rule configuration.

---

### 2.3 Configure Rule Conditions

**Step 1 — Define the Index Pattern:**

In the **"Index patterns"** field, enter:
```
security-login-*
```

Click **"+ Add index pattern"** if you need to add more indices.

**Step 2 — Write the Custom KQL Query:**

In the **"Custom query"** field, enter the following KQL (Kibana Query Language) to filter for failed login events:

```kql
event.outcome: "failure" AND event.category: "authentication"
```

> **Optional — More specific SSH failed login query:**
> ```kql
> event.outcome: "failure" AND event.category: "authentication" AND process.name: "sshd"
> ```

**Step 3 — Set the Threshold Condition:**

Scroll to the **"Threshold"** section and configure:

| Parameter        | Value              | Description                                      |
|------------------|--------------------|--------------------------------------------------|
| **Field**        | `source.ip`        | Group failed logins by source IP address         |
| **Threshold**    | `5`                | Alert after 5 failed attempts from same IP       |
| **Cardinality**  | *(leave blank)*    | Not required for this rule                       |

> This means: **"Alert when the same source IP has more than 5 failed login events"**

**Step 4 — Set the Time Window:**

In the **"Time window"** section:
- Set the time window to **`5 minutes`** (select `5` and choose `Minutes` from dropdown)

**Step 5 — Review the final rule condition summary:**
```
Rule: "Detect 5+ failed logins in 5 minutes"
Index: security-login-*
Condition: count(event.outcome: "failure") > 5
Group by: source.ip
Window: Last 5 minutes
```

Click **"Continue"** to go to the About section.

---

### 2.4 Set Alert Actions & Notifications

**Step 1 — Fill in Rule Details:**

| Field              | Value                                              |
|--------------------|----------------------------------------------------|
| **Rule name**      | `Detect 5+ Failed Logins in 5 Minutes`             |
| **Description**    | `Triggers when a single IP fails to login 5+ times within any 5-minute window. Indicates brute-force or credential-stuffing attack.` |
| **Severity**       | `High`                                             |
| **Risk score**     | `73`                                               |
| **Tags**           | `brute-force`, `authentication`, `ssh`, `T1110`    |

**Step 2 — Set MITRE ATT&CK Mapping (Optional but recommended):**
- **Tactic:** `Credential Access`
- **Technique:** `T1110 — Brute Force`
- **Sub-technique:** `T1110.001 — Password Guessing`

**Step 3 — Configure Alert Actions (Optional):**

Click on **"Actions"** tab:

- **Email Notification:** Click **"+ Add action"** → Select **"Email"**
  - Fill in: recipient email, subject: `[SIEM ALERT] Brute Force Detected`
  - Message: `Alert triggered: {{context.rule.name}} on {{context.date}}`

- **Slack Notification:** Click **"+ Add action"** → Select **"Slack"**
  - Fill in your webhook URL and message template.

**Step 4 — Set Schedule:**

| Parameter         | Value           |
|-------------------|-----------------|
| **Runs every**    | `1 minute`      |
| **Additional look-back time** | `1 minute` |

Click **"Continue"**.

---

### 2.5 Save and Enable the Rule

**Step 1:** Review the rule summary on the final confirmation page. Verify all details are correct.

**Step 2:** Click **"Create & enable rule"** button.

**Step 3:** You will be redirected to the rule details page. Confirm the rule shows **"Enabled"** status (green badge).

**Step 4:** Verify rule activation:

```bash
# Using Elastic API to confirm rule is active
curl -X GET "http://localhost:5601/api/detection_engine/rules?filter=alert.attributes.name:%22Detect%205%2B%20Failed%20Logins%22" \
  -H "kbn-xsrf: true" \
  -u elastic:<password>
```

---

## 3. Test Elastic SIEM Rule with Simulated SSH Failures

### Step 3.1 — Identify the Target Host

```bash
# Get the IP address of the SIEM-monitored host
ip addr show eth0 | grep "inet " | awk '{print $2}'
# OR
hostname -I
```

Note down the IP (example: `192.168.1.100`)

### Step 3.2 — Generate Failed SSH Login Attempts

Open a terminal on your attacker/test machine and run:

```bash
# Attempt 6 failed SSH logins (wrong password) to trigger the rule
for i in {1..6}; do
  echo "Attempt $i..."
  ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no wronguser@192.168.1.100
  sleep 5
done
```

> **Note:** When prompted for a password, enter a wrong password each time. Press `Ctrl+C` or let it timeout.

### Step 3.3 — Verify Logs are Indexed

```bash
# Check if failed login events appeared in the index
curl -X GET "http://localhost:9200/security-login-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.outcome": "failure" } },
        { "range": { "@timestamp": { "gte": "now-10m" } } }
      ]
    }
  },
  "size": 10
}
'
```

### Step 3.4 — Check for Triggered Alerts in Kibana

1. Go to **Kibana → Security → Alerts**
2. Look for the rule **"Detect 5+ Failed Logins in 5 Minutes"**
3. You should see an alert with status **"Open"**
4. Click the alert to inspect: source IP, user name, timestamp, event count

---

## 4. Advanced Task — Wazuh Custom Alert Rule

### 4.1 Access Wazuh Manager

```bash
# SSH into the Wazuh Manager server
ssh admin@<wazuh-manager-ip>

# Switch to root (required for rule editing)
sudo su -
```

### 4.2 Understand Wazuh Rule Structure

Wazuh rules are stored as XML files in:

```
/var/ossec/ruleset/rules/        ← Built-in Wazuh rules (DO NOT EDIT)
/var/ossec/etc/rules/            ← Custom user rules (EDIT HERE)
```

**Wazuh Rule XML Anatomy:**

```xml
<group name="rule_group_name,">

  <!-- Base rule: match the individual event -->
  <rule id="XXXXX" level="N">
    <if_sid>PARENT_RULE_ID</if_sid>
    <match>pattern to match in log</match>
    <description>Human-readable description</description>
    <group>event_group_tags</group>
  </rule>

  <!-- Frequency rule: trigger when base rule fires N+ times in T seconds -->
  <rule id="XXXXX" level="N" frequency="N" timeframe="T">
    <if_matched_sid>BASE_RULE_ID</if_matched_sid>
    <same_source_ip />          <!-- Group by same source IP -->
    <description>Alert after N occurrences in T seconds</description>
    <group>event_group_tags</group>
  </rule>

</group>
```

**Key XML Attributes:**

| Attribute     | Description                                                     |
|---------------|-----------------------------------------------------------------|
| `id`          | Unique rule ID (100000–109999 for custom rules)                 |
| `level`       | Alert severity (1=low, 15=highest/critical)                     |
| `frequency`   | Number of times rule must fire before triggering               |
| `timeframe`   | Time window in seconds                                          |
| `if_sid`      | Trigger if specified rule ID fires                              |
| `if_matched_sid` | Frequency-match against specified rule ID                   |
| `same_source_ip` | Group events by same source IP address                      |
| `same_user`   | Group events by same username                                   |

**Wazuh Parent Rule IDs for SSH (Reference):**

| Rule ID | Event                                          |
|---------|------------------------------------------------|
| `5710`  | SSH authentication failure (PAM)               |
| `5716`  | SSH authentication failed                      |
| `5720`  | SSH brute force attempt (built-in, 8 in 120s)  |
| `5758`  | Maximum authentication attempts exceeded       |

---

### 4.3 Create Custom Rule File

```bash
# Navigate to the custom rules directory
cd /var/ossec/etc/rules/

# Create a new custom rule file
sudo touch local_rules_ssh_bruteforce.xml

# Set correct permissions
sudo chown root:wazuh local_rules_ssh_bruteforce.xml
sudo chmod 640 local_rules_ssh_bruteforce.xml

# Verify
ls -la /var/ossec/etc/rules/
```

---

### 4.4 Write the Custom Rule XML

Open the file with a text editor:

```bash
sudo nano /var/ossec/etc/rules/local_rules_ssh_bruteforce.xml
```

Paste the following complete rule set:

```xml
<!-- ============================================================
     Custom Wazuh Rule: SSH Brute Force Detection
     Detect 3+ failed SSH logins within 2 minutes (120 seconds)
     Author: Security Team
     Date: 2025
     ============================================================ -->

<group name="custom_ssh_bruteforce,authentication_failed,">

  <!-- ─────────────────────────────────────────────────────────
       Rule 100100: Match individual SSH authentication failure
       Parent: 5716 (SSH auth failed) or 5710 (PAM auth fail)
       Level 3 = low severity for individual failure
       ───────────────────────────────────────────────────────── -->
  <rule id="100100" level="3">
    <if_sid>5710, 5716</if_sid>
    <description>SSH authentication failure detected (individual event)</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,gpg13_7.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.2,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <!-- ─────────────────────────────────────────────────────────
       Rule 100101: Brute Force Alert
       Triggers when rule 100100 fires 3+ times in 120 seconds
       from the SAME source IP address.
       Level 10 = high severity (will generate alert)
       frequency="3" means: alert after the 3rd occurrence
       timeframe="120" = 2-minute window
       ───────────────────────────────────────────────────────── -->
  <rule id="100101" level="10" frequency="3" timeframe="120">
    <if_matched_sid>100100</if_matched_sid>
    <same_source_ip />
    <description>Possible SSH Brute Force Attack: 3 or more failed logins from the same IP in 2 minutes</description>
    <group>authentication_failures,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,gpg13_7.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.2,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <!-- ─────────────────────────────────────────────────────────
       Rule 100102: Extended Brute Force (sustained attack)
       Triggers when rule 100101 fires 2+ more times (total 6+)
       Level 12 = critical severity
       ───────────────────────────────────────────────────────── -->
  <rule id="100102" level="12" frequency="2" timeframe="300">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />
    <description>CRITICAL: Sustained SSH Brute Force Attack from same IP — 6+ failed logins in 5 minutes</description>
    <group>authentication_failures,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.2,</group>
  </rule>

</group>
```

Save and exit: `Ctrl+O` → `Enter` → `Ctrl+X`

---

### 4.5 Reload Wazuh Rules

**Step 1 — Validate the XML Syntax:**

```bash
# Test XML syntax before reloading
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | head -30
```

**If the output shows no errors, proceed.** If errors exist, fix the XML and re-validate.

**Step 2 — Reload the Wazuh Manager:**

```bash
# Graceful reload (no data loss)
sudo systemctl reload wazuh-manager

# OR use ossec-control
sudo /var/ossec/bin/ossec-control reload

# OR full restart (if reload doesn't apply changes)
sudo systemctl restart wazuh-manager
```

**Step 3 — Verify the manager restarted cleanly:**

```bash
sudo systemctl status wazuh-manager
# Look for: "Active: active (running)"
```

---

### 4.6 Verify Rule is Loaded

```bash
# Method 1: Search for the rule ID in the compiled ruleset
sudo grep -r "100101" /var/ossec/ruleset/ /var/ossec/etc/rules/

# Method 2: Use wazuh-analysisd test to see all loaded rules
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -i "100101"

# Method 3: Check ossec.log for rule loading confirmation
sudo tail -100 /var/ossec/logs/ossec.log | grep -E "(rule|100100|100101)"
```

**Expected confirmation output:**
```
2025/XX/XX XX:XX:XX wazuh-analysisd: INFO: Read local rules.
```

---

## 5. Test Wazuh Rule with Simulated Failed SSH Logins

### 5.1 Identify Target Machine IP

On the target machine (where the Wazuh agent is installed):

```bash
ip addr show | grep "inet " | grep -v "127.0.0.1"
# Example output: inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
```

Note: Replace `192.168.1.x` with your actual IP in the commands below.

### 5.2 Execute Failed SSH Login Attempts

On a test/attacker machine (or a second terminal on the same network):

```bash
# Attempt 3 failed SSH logins within 2 minutes to trigger rule 100101
# Use wrong password each time

ssh user@192.168.1.100    # Attempt 1 — enter wrong password
ssh user@192.168.1.100    # Attempt 2 — enter wrong password  
ssh user@192.168.1.100    # Attempt 3 — ALERT TRIGGERS HERE
```

> **Tip:** You can also use a non-existent user account to guarantee failure:
> ```bash
> ssh nonexistentuser@192.168.1.100
> ```

### 5.3 Automated Test Script

Create and run this script to automatically generate failed logins:

```bash
# Create the test script
cat > /tmp/test_ssh_bruteforce.sh << 'EOF'
#!/bin/bash

TARGET_IP="192.168.1.100"          # ← Change this to your target IP
TARGET_USER="testuser"              # ← Change to any username
ATTEMPTS=5                          # Number of attempts
DELAY=10                            # Seconds between attempts

echo "========================================"
echo "SSH Brute Force Simulation Test"
echo "Target: ${TARGET_USER}@${TARGET_IP}"
echo "Attempts: ${ATTEMPTS} | Delay: ${DELAY}s"
echo "========================================"
echo ""

for i in $(seq 1 $ATTEMPTS); do
    echo "[$(date '+%H:%M:%S')] Attempt ${i}/${ATTEMPTS} — connecting to ${TARGET_IP}..."
    
    # sshpass with wrong password, timeout after 5 seconds
    # -o BatchMode=yes disables interactive prompts
    ssh -o BatchMode=yes \
        -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=no \
        -o PasswordAuthentication=yes \
        ${TARGET_USER}@${TARGET_IP} \
        exit 2>/dev/null
    
    echo "[$(date '+%H:%M:%S')] Attempt ${i} completed (expected failure)"
    
    if [ $i -lt $ATTEMPTS ]; then
        echo "  Waiting ${DELAY} seconds before next attempt..."
        sleep $DELAY
    fi
done

echo ""
echo "========================================"
echo "Test complete. Check Wazuh dashboard for alerts."
echo "Rule IDs to look for: 100100, 100101"
echo "========================================"
EOF

chmod +x /tmp/test_ssh_bruteforce.sh

# Run the test
/tmp/test_ssh_bruteforce.sh
```

> **Alternative — using sshpass for automated wrong-password injection:**
> ```bash
> # Install sshpass
> sudo apt install sshpass   # Debian/Ubuntu
> sudo yum install sshpass   # CentOS/RHEL
>
> # Run with explicit wrong password
> for i in {1..4}; do
>   sshpass -p "wrongpassword123" ssh -o StrictHostKeyChecking=no user@192.168.1.100
>   sleep 15
> done
> ```

### 5.4 Monitor Auth Logs in Real-Time

While running the test, monitor the target machine's auth log in a second terminal:

```bash
# On the TARGET machine — watch auth.log in real-time
sudo tail -f /var/log/auth.log | grep -E "(Failed|Invalid|sshd)"
```

**Expected log entries:**
```
Apr 10 14:22:01 hostname sshd[12345]: Failed password for testuser from 192.168.1.50 port 44322 ssh2
Apr 10 14:22:16 hostname sshd[12346]: Failed password for testuser from 192.168.1.50 port 44356 ssh2
Apr 10 14:22:31 hostname sshd[12347]: Failed password for testuser from 192.168.1.50 port 44378 ssh2
```

### 5.5 Monitor Wazuh Alerts in Real-Time

On the **Wazuh Manager**, watch for triggered alerts:

```bash
# Method 1: Watch alerts.log
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -A 8 "100101"

# Method 2: Watch alerts.json (structured output)
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool | grep -A 5 '"id":"100101"'

# Method 3: Watch ossec.log for rule matches
sudo tail -f /var/ossec/logs/ossec.log | grep -E "(100100|100101|brute)"
```

**Expected alert in alerts.log:**
```
** Alert 1681234567.12345: - custom_ssh_bruteforce,authentication_failures,
2025 Apr 10 14:22:31 (agent-hostname) 192.168.1.100->/var/log/auth.log
Rule: 100101 (level 10) -> 'Possible SSH Brute Force Attack: 3 or more failed logins from the same IP in 2 minutes'
Src IP: 192.168.1.50
User: testuser
Apr 10 14:22:31 hostname sshd[12347]: Failed password for testuser from 192.168.1.50 port 44378 ssh2
```

---

## 6. Alert Validation in Wazuh Dashboard

### 6.1 Access Wazuh Dashboard

**Step 1:** Open a browser and navigate to:
```
https://<wazuh-dashboard-ip>:443
```
or
```
https://<wazuh-dashboard-ip>:5601
```

**Step 2:** Log in:
- **Username:** `admin`
- **Password:** `<your-wazuh-admin-password>`

---

### 6.2 Navigate to Security Events

**Step 1:** From the left sidebar, click on **"Security events"** (shield icon).

**Step 2:** In the top navigation, ensure the time range is set to **"Last 15 minutes"** or **"Last 1 hour"** to capture your recent test.

**Step 3:** Click **"Refresh"** to load the latest events.

---

### 6.3 Filter for Custom Rule Alerts

**Step 1:** In the search bar at the top, enter the following filter:

```
rule.id: 100101
```

Press **Enter** to apply.

**Step 2:** Additional useful filters:

```kql
# Filter by rule group
rule.groups: "custom_ssh_bruteforce"

# Filter by severity level
rule.level >= 10

# Filter by source IP (replace with actual attacker IP)
data.srcip: 192.168.1.50

# Combined filter
rule.id: 100101 AND data.srcip: 192.168.1.50
```

**Step 3:** Look for the alert card showing:
- **Rule ID:** 100101
- **Rule Description:** "Possible SSH Brute Force Attack..."
- **Level:** 10 (High)
- **Source IP:** *(your test machine IP)*

---

### 6.4 Verify Alert Details

**Step 1:** Click on the alert entry to expand its full details.

**Step 2:** Verify all of the following fields are populated correctly:

| Field               | Expected Value                                    |
|---------------------|---------------------------------------------------|
| `rule.id`           | `100101`                                          |
| `rule.level`        | `10`                                              |
| `rule.description`  | `Possible SSH Brute Force Attack...`              |
| `rule.groups`       | `custom_ssh_bruteforce, authentication_failures`  |
| `agent.name`        | *(hostname of monitored machine)*                 |
| `data.srcip`        | *(IP of your test/attacker machine)*              |
| `data.dstuser`      | *(username used in SSH attempts)*                 |
| `timestamp`         | *(time matching your test)*                       |

**Step 3:** Take screenshots of:
1. The alert list showing rule 100101 triggered
2. The expanded alert detail view
3. The alert count/frequency chart

**Step 4 — View the Event Timeline:**

Navigate to **"Events"** tab within the alert detail to see the individual SSH failure events that composed the alert.

---

## 7. Documentation — Rule Effectiveness Report

After completing all tests, document your findings using this template:

```
==============================================================
 ALERT RULE EFFECTIVENESS REPORT
 Date: [DATE]
 Author: [YOUR NAME]
==============================================================

RULE 1: Elastic SIEM — Failed Login Detection
----------------------------------------------
Rule Name:    Detect 5+ Failed Logins in 5 Minutes
Index:        security-login-*
Condition:    count(event.outcome: failure) > 5 in 5 min
Severity:     High (Risk score: 73)

Test Results:
  - Simulated Attempts: 6 failed SSH logins
  - Time between attempts: 30 seconds each
  - Alert Triggered: YES / NO
  - Time to Alert: X minutes X seconds
  - False Positives Observed: YES / NO
  
Effectiveness Rating: [1-5 stars]
Notes: [Observations, improvements needed]


RULE 2: Wazuh — Custom SSH Brute Force Rule
---------------------------------------------
Rule File:    /var/ossec/etc/rules/local_rules_ssh_bruteforce.xml
Rule IDs:     100100 (base), 100101 (alert), 100102 (critical)
Condition:    3+ failures from same IP within 120 seconds
Severity:     Level 10 (High)

Test Results:
  - Simulated Attempts: [N] failed SSH logins
  - Target IP: 192.168.1.x
  - Source IP: 192.168.1.x  
  - Alert Triggered: YES / NO
  - Rule ID Matched: 100101
  - Alert Level: 10
  - Time to Alert: X seconds
  - False Positives: YES / NO
  - Logs Verified: /var/ossec/logs/alerts/alerts.log

Dashboard Validation:
  - Alert visible in Wazuh dashboard: YES / NO
  - Source IP correctly identified: YES / NO
  - Timestamp accurate: YES / NO
  - Rule group tags correct: YES / NO

Improvements Considered:
  - Reduce timeframe from 120s to 60s for faster detection
  - Add geo-IP enrichment for source IP
  - Integrate with active response to auto-block the IP
  - Add alert for failed logins from new/unknown source IPs

Conclusion:
  The custom Wazuh rule successfully detects SSH brute-force 
  behavior by correlating multiple individual auth failures 
  from the same source IP within a 2-minute window. The rule 
  is effective with minimal false positives in a lab environment.
==============================================================
```

---

## 8. Troubleshooting Common Issues

### Issue 1: Elastic SIEM rule not triggering

**Symptom:** No alerts appear after simulated logins.

**Check 1 — Verify events are indexed:**
```bash
curl -X GET "http://localhost:9200/security-login-*/_count?pretty" -H 'Content-Type: application/json' -d'
{"query": {"range": {"@timestamp": {"gte": "now-30m"}}}}'
```

**Check 2 — Verify Filebeat is running:**
```bash
sudo systemctl status filebeat
sudo tail -50 /var/log/filebeat/filebeat
```

**Check 3 — Check event field mapping:**
```bash
curl -X GET "http://localhost:9200/security-login-*/_mapping/field/event.outcome?pretty"
```

**Fix:** Ensure `event.outcome` field is mapped as `keyword`, not `text`.

---

### Issue 2: Wazuh rule not triggering

**Symptom:** Alerts.log shows individual rule 100100 but not 100101.

**Check 1 — Verify rule loaded correctly:**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -i error
```

**Check 2 — Verify SSH logs are being monitored:**
```bash
sudo grep -r "auth.log\|sshd" /var/ossec/etc/ossec.conf
```

If not present, add to ossec.conf:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

**Check 3 — Verify attempts are within timeframe:**
- Ensure all 3 attempts happen within 120 seconds.
- Check timestamps in `/var/log/auth.log`

**Check 4 — Check if parent rule fires:**
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep "5716\|100100"
```

---

### Issue 3: Wazuh agent not sending logs

**Symptom:** No events appear in dashboard despite SSH failures.

```bash
# On agent machine — check agent status
sudo /var/ossec/bin/ossec-control status

# Check agent connection to manager
sudo tail -20 /var/ossec/logs/ossec.log | grep -E "(connected|error|warn)"

# Restart agent
sudo systemctl restart wazuh-agent

# Verify agent is listed in manager
sudo /var/ossec/bin/agent_control -l
```

---

### Issue 4: XML syntax error in custom rule

**Symptom:** `wazuh-analysisd -t` reports error near rule file.

```bash
# Validate XML syntax directly
xmllint --noout /var/ossec/etc/rules/local_rules_ssh_bruteforce.xml
echo "Exit code: $?"   # 0 = valid, non-zero = error
```

Common XML errors:
- Missing closing tag (`</rule>` or `</group>`)
- Unclosed attribute quotes
- Special characters not escaped (`&` should be `&amp;`)

---

## 9. Reference — Rule IDs & Log Paths

### Important File Paths

| File/Directory                              | Purpose                                      |
|---------------------------------------------|----------------------------------------------|
| `/var/ossec/etc/rules/`                     | Custom Wazuh rules directory                 |
| `/var/ossec/ruleset/rules/`                 | Built-in Wazuh rules (read-only)             |
| `/var/ossec/etc/ossec.conf`                 | Main Wazuh configuration file                |
| `/var/ossec/logs/alerts/alerts.log`         | All triggered alerts (text)                  |
| `/var/ossec/logs/alerts/alerts.json`        | All triggered alerts (JSON)                  |
| `/var/ossec/logs/ossec.log`                 | Wazuh manager operational log                |
| `/var/log/auth.log`                         | Linux SSH/PAM authentication log             |
| `/var/log/secure`                           | RHEL/CentOS SSH auth log                     |
| `/etc/filebeat/filebeat.yml`                | Filebeat configuration                       |

### Wazuh Built-in SSH Rule IDs (Reference)

| Rule ID | Level | Description                                         |
|---------|-------|-----------------------------------------------------|
| `5700`  | 3     | SSH generic error                                   |
| `5710`  | 5     | SSH authentication failure (PAM)                    |
| `5712`  | 10    | SSH brute force (8 times in 120 sec)                |
| `5716`  | 5     | SSH authentication failed                           |
| `5720`  | 10    | Multiple SSH authentication failures (SSHD)         |
| `5758`  | 8     | SSH maximum authentication attempts exceeded        |

### Custom Rule IDs Created

| Rule ID | Level | Trigger                                             |
|---------|-------|-----------------------------------------------------|
| `100100`| 3     | Individual SSH authentication failure               |
| `100101`| 10    | **3+ failures from same IP in 120 seconds (ALERT)** |
| `100102`| 12    | Sustained brute force: 6+ failures in 5 minutes    |

### Quick Command Reference

```bash
# Reload Wazuh rules
sudo systemctl reload wazuh-manager

# Test rule configuration
sudo /var/ossec/bin/wazuh-analysisd -t

# Watch live alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Check agent connectivity
sudo /var/ossec/bin/agent_control -l

# Search Elastic index
curl -X GET "localhost:9200/security-login-*/_search?pretty&size=5"

# Restart all services
sudo systemctl restart elasticsearch kibana wazuh-manager filebeat
```

---

*README generated for: Security Lab Task — Alert Rules Configuration*  
*Covers: Elastic SIEM threshold rule + Wazuh custom XML rule for SSH brute-force detection*