#  Quick Command Reference — All Lab Commands

Copy-paste reference for every command used in the lab.
**Run PowerShell commands as Administrator. Run Python from repo root.**

---

##  Day 1 — Setup (05 Mar 2026)

```bash
# Clone repo
git clone https://github.com/YOUR_USERNAME/cybersecurity-log-analysis.git
cd cybersecurity-log-analysis

# Install Python deps
pip install -r requirements.txt

# Allow PowerShell scripts (run as Admin)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

##  Day 2 — Event ID 4625 Filtering (06 Mar 2026)

```powershell
# GUI: Open Event Viewer
eventvwr.msc

# CLI: List last 20 failed logins
wevtutil qe Security /q:"*[System[EventID=4625]]" /c:20 /f:text /rd:true

# PowerShell: Get-WinEvent (last 60 min)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    Select-Object TimeCreated, Message | Out-GridView

# Run the filter script
.\scripts\windows\filter_event_4625.ps1 -LastMinutes 60 -Threshold 3
```

---

##  Day 3 — Event ID 7045 Filtering (07 Mar 2026)

```powershell
# GUI: Open Event Viewer → System log
eventvwr.msc

# CLI: Query for new service installs (last 7 days)
wevtutil qe System /q:"*[System[EventID=7045]]" /f:text /rd:true /c:20

# PowerShell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Format-List TimeCreated, Message

# Run filter script
.\scripts\windows\filter_event_7045.ps1 -LastDays 7
```

---

##  Day 4 — Generate Brute-Force (08 Mar 2026)

```powershell
# Step 1: Enable audit policy
auditpol /set /subcategory:"Logon" /failure:enable

# Verify audit policy
auditpol /get /subcategory:"Logon"

# Step 2: Run login simulator (generates 15 failed logins)
.\scripts\windows\generate_failed_logins.ps1 -Username "Administrator" -Attempts 15

# Step 3: Verify events appeared
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-10)
} | Measure-Object | Select-Object Count
```

---

## Day 5 — Detect & Export (09 Mar 2026)

```powershell
# Detect brute-force from logs
.\scripts\windows\filter_event_4625.ps1 -LastMinutes 60 -Threshold 3

# Export to CSV
.\scripts\windows\filter_event_4625.ps1 `
    -LastMinutes 60 `
    -Threshold 3 `
    -ExportCsv "reports\failed_logins.csv"

# Export Security log via PowerShell
.\scripts\windows\export_events_csv.ps1 `
    -EventID 4625 `
    -OutputPath "reports\failed_logins_full.csv"

# OR via wevtutil
wevtutil qe Security /q:"*[System[EventID=4625]]" /f:XML > logs\exported\failed_logins.xml
```

```bash
# Analyze the exported XML with Python
python scripts/analysis/brute_force_detector.py \
    --log logs/sample/sample_events_4625.xml \
    --threshold 3 \
    --output reports/brute_force_report.csv
```

---

##  Day 6 — Eric Zimmerman's Tools (10 Mar 2026)

```powershell
# Navigate to EZTools directory
cd C:\EZTools\

# Parse ALL LNK files in Recent folder
.\LECmd.exe -d "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Recent\" `
    --csv C:\Output\ `
    --csvf lnk_recent_files.csv

# Close Chrome, copy History DB
Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" "C:\Output\ChromeHistory" -Force

# Parse Chrome History with SQLECmd
.\SQLECmd.exe -f "C:\Output\ChromeHistory" --csv C:\Output\ --hunt

# Search for test.com in output CSV
Import-Csv "C:\Output\*ChromiumBrowser_History*.csv" |
    Where-Object { $_.URL -like "*test.com*" } |
    Format-Table URL, Title, VisitCount, LastVisitTime -AutoSize
```

---

##  Day 7 — Chrome History Analysis (11 Mar 2026)

```bash
# Parse Chrome History with Python (sample DB)
python scripts/analysis/parse_chrome_history.py \
    --db logs/sample/sample_chrome_history.db \
    --search "test.com" \
    --output reports/chrome_history_results.csv

# Parse REAL Chrome History (Windows path)
python scripts/analysis/parse_chrome_history.py \
    --db "C:/Users/$USER/AppData/Local/Google/Chrome/User Data/Default/History" \
    --search "test.com" \
    --output reports/chrome_history_results.csv
```

```sql
-- DB Browser for SQLite — manual SQL queries
-- Find test.com visits
SELECT url, title, visit_count,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') as visit_time
FROM urls
WHERE url LIKE '%test.com%'
ORDER BY last_visit_time DESC;

-- Find all URLs (sorted by most visited)
SELECT url, title, visit_count
FROM urls
ORDER BY visit_count DESC
LIMIT 50;

-- Find URLs in lab date range (05-13 Mar 2026)
SELECT url, title,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS visit_dt
FROM urls
WHERE visit_dt BETWEEN '2026-03-05' AND '2026-03-13'
ORDER BY last_visit_time DESC;
```

---

##  Day 8 — Document Events (12 Mar 2026)

```bash
# Open the CSV template and fill it in
# File: templates/security_event_template.csv
# Fields: Date/Time | Source IP | Destination IP | Event ID | Log Source
#         Username | Hostname | Description | Severity | Action Taken | Analyst

# View current template contents
cat templates/security_event_template.csv
```

---

##  Day 9 — Generate Final Report (13 Mar 2026)

```bash
# Generate incident report from your completed CSV
python scripts/reporting/generate_report.py \
    --csv templates/security_event_template.csv \
    --output reports/final_incident_report.md \
    --title "Brute-Force Attack on WORKSTATION01" \
    --analyst "Your Name"

# View the report
cat reports/final_incident_report.md
```

```powershell
# PowerShell — open report in Notepad
notepad reports\final_incident_report.md
```

---

## Utility Commands

```powershell
# Check Windows audit policy
auditpol /get /category:*

# Clear Security log (use with caution — VM only!)
wevtutil cl Security

# List all event logs
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} |
    Select-Object LogName, RecordCount | Sort-Object RecordCount -Descending

# Count 4625 events in Security log
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}).Count

# Export Security log to EVTX backup
wevtutil epl Security C:\Backup\Security_$(Get-Date -Format yyyyMMdd).evtx
```

```bash
# Git — commit your findings
git add reports/ templates/
git commit -m "Lab complete: added brute-force findings and incident report"
git push
```
