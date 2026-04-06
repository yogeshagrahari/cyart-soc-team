#  Log Analysis Practice — Complete Step-by-Step Guide

> **Skill Level:** Beginner to Intermediate  
> **Platform:** Windows (VM recommended)  
> **Goal:** Perform forensic log analysis using Windows Event Viewer and Eric Zimmerman's Tools to detect brute-force attacks and analyze browser history for malicious URLs.

---

## Table of Contents

1. [Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
2. [Understanding Key Event IDs](#2-understanding-key-event-ids)
3. [Windows Event Viewer — Core Usage](#3-windows-event-viewer--core-usage)
4. [Filter Event ID 4625 — Failed Logins](#4-filter-event-id-4625--failed-logins)
5. [Filter Event ID 7045 — New Service Creation](#5-filter-event-id-7045--new-service-creation)
6. [Brute-Force Attack Detection from Security Logs](#6-brute-force-attack-detection-from-security-logs)
7. [Advanced Task: Generate Failed Logins in Windows VM](#7-advanced-task-generate-failed-logins-in-windows-vm)
8. [Export Event Logs to CSV](#8-export-event-logs-to-csv)
9. [Browser History Analysis Overview](#9-browser-history-analysis-overview)
10. [Install Eric Zimmerman's Tools (LECmd)](#10-install-eric-zimmermans-tools-lecmd)
11. [Locate Chrome History File](#11-locate-chrome-history-file)
12. [Parse Chrome History Using LECmd](#12-parse-chrome-history-using-lecmd)
13. [Identify Malicious URLs in Parsed Output](#13-identify-malicious-urls-in-parsed-output)
14. [Using wevtutil CLI for Log Analysis](#14-using-wevtutil-cli-for-log-analysis)
15. [Using LogParser Lizard (GUI Tool)](#15-using-logparser-lizard-gui-tool)
16. [Setting Up Elastic SIEM (Optional Advanced)](#16-setting-up-elastic-siem-optional-advanced)
17. [Summary Checklist](#17-summary-checklist)
18. [Troubleshooting Common Issues](#18-troubleshooting-common-issues)
19. [References & Resources](#19-references--resources)

---

## 1. Prerequisites & Environment Setup

### 1.1 System Requirements

| Component        | Requirement                                      |
|------------------|--------------------------------------------------|
| OS               | Windows 10 / Windows 11 / Windows Server 2019+  |
| RAM              | Minimum 4 GB (8 GB recommended for VM)          |
| Disk Space       | At least 20 GB free                             |
| VM Software      | VMware Workstation Player or VirtualBox (free)  |
| Internet Access  | Required for tool downloads                     |
| Privileges       | Administrator / Local Admin account             |

### 1.2 Set Up a Windows Virtual Machine

> **Always perform security analysis and attack simulations inside a VM, never on your host machine.**

**Step 1 — Download VirtualBox (Free)**
```
https://www.virtualbox.org/wiki/Downloads
```

**Step 2 — Download Windows 10 ISO**
```
https://www.microsoft.com/en-us/software-download/windows10ISO
```

**Step 3 — Create a New VM in VirtualBox**
1. Open VirtualBox → Click **New**
2. Name: `WindowsAnalysisLab`
3. Type: `Microsoft Windows` → Version: `Windows 10 (64-bit)`
4. RAM: Allocate at least `4096 MB`
5. Hard Disk: Create a virtual hard disk → `VDI` → `Dynamically allocated` → `50 GB`
6. Click **Create**

**Step 4 — Attach the ISO**
1. Select your VM → Click **Settings** → **Storage**
2. Under **Controller: IDE** click the empty disk icon
3. Click the disk icon on the right → **Choose a disk file**
4. Select your downloaded Windows 10 ISO
5. Click **OK** → **Start**

**Step 5 — Install Windows 10**
1. Follow the on-screen Windows installation wizard
2. Choose **Custom Install** → Select the virtual disk → Click **Next**
3. Complete setup with a **local account** (do NOT use a Microsoft account for lab environments)
4. Set username: `LabUser` | Password: `Lab@1234`

**Step 6 — Install VirtualBox Guest Additions (Recommended)**
1. Start the VM
2. In VirtualBox menu: **Devices** → **Insert Guest Additions CD Image**
3. Run `VBoxWindowsAdditions.exe` inside the VM → Follow prompts → Restart

---

## 2. Understanding Key Event IDs

Before diving in, understand the Windows Security Event IDs you will be working with:

| Event ID | Log Channel | Description                                    | Security Relevance                        |
|----------|-------------|------------------------------------------------|-------------------------------------------|
| **4625** | Security    | An account failed to log on                   | Brute-force / password spray detection   |
| **4624** | Security    | An account successfully logged on             | Successful login tracking                 |
| **4648** | Security    | Logon attempted with explicit credentials     | Pass-the-hash / lateral movement          |
| **4720** | Security    | A user account was created                    | Unauthorized account creation             |
| **4732** | Security    | Member added to security-enabled local group  | Privilege escalation                      |
| **7045** | System      | A new service was installed in the system     | Malware persistence / backdoor detection  |
| **7036** | System      | A service entered running/stopped state       | Service activity tracking                 |
| **1102** | Security    | The audit log was cleared                     | Anti-forensics / log tampering            |

---

## 3. Windows Event Viewer — Core Usage

### 3.1 Open Event Viewer

**Method 1 — Run Dialog (Fastest)**
1. Press `Windows Key + R`
2. Type `eventvwr.msc`
3. Press `Enter`

**Method 2 — Start Menu**
1. Click **Start**
2. Search `Event Viewer`
3. Click the result

**Method 3 — Command Prompt / PowerShell**
```cmd
eventvwr.msc
```

### 3.2 Understanding the Event Viewer Interface

```
Event Viewer (Local)
├── Custom Views
│   └── Administrative Events
├── Windows Logs
│   ├── Application       ← App crashes, errors
│   ├── Security          ← Login events, audit logs  ← PRIMARY FOCUS
│   ├── Setup
│   ├── System            ← Service events (7045)     ← PRIMARY FOCUS
│   └── Forwarded Events
├── Applications and Services Logs
└── Subscriptions
```

### 3.3 Ensure Audit Logging is Enabled

>  Without audit policy enabled, Event ID 4625 will NOT be logged.

**Step 1 — Open Local Security Policy**
1. Press `Windows Key + R`
2. Type `secpol.msc` → Press Enter

**Step 2 — Enable Logon Auditing**
1. Navigate to: `Security Settings` → `Local Policies` → `Audit Policy`
2. Double-click **Audit account logon events**
3. Check both **Success** and **Failure**
4. Click **OK**

**Step 3 — Also enable via PowerShell (Alternative)**
```powershell
# Run PowerShell as Administrator
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable

# Verify settings
auditpol /get /category:*
```

---

## 4. Filter Event ID 4625 — Failed Logins

### 4.1 Navigate to Security Log
1. In Event Viewer left panel, expand **Windows Logs**
2. Click **Security**
3. Wait for logs to load (may take a moment if log is large)

### 4.2 Create a Custom Filter

**Step 1 — Open Filter Dialog**
1. In the right-hand **Actions** panel, click **Filter Current Log...**
   - OR: Right-click **Security** → **Filter Current Log...**

**Step 2 — Configure the Filter**
1. Click the **Filter** tab
2. In the **Event IDs** field: type `4625`
3. Leave **Event level** unchecked (to capture all severities)
4. Optionally set a **time range** under **Logged**
5. Click **OK**

**Step 3 — Review Filtered Results**
- Event Viewer now shows ONLY Event ID 4625 entries
- Each entry shows:
  - **Date and Time** of the failed attempt
  - **Account Name** that was targeted
  - **Workstation Name** / **Source IP Address** (in event details)

**Step 4 — Click an Event to Read Details**
1. Double-click any 4625 event
2. In the **General** tab, look for:
   ```
   Account Name:      TargetUser
   Account Domain:    WORKGROUP or DOMAIN
   Logon Type:        3 (Network) or 2 (Interactive)
   Failure Reason:    Unknown user name or bad password
   Caller Process ID: 0x0
   Network Information:
       Workstation Name: ATTACKER-PC
       Source Network Address: 192.168.1.100
       Source Port: 49220
   ```

### 4.3 Logon Type Reference

| Logon Type | Name             | Description                              |
|------------|------------------|------------------------------------------|
| 2          | Interactive      | Local keyboard login                    |
| 3          | Network          | Net use, SMB, shared folder             |
| 4          | Batch            | Scheduled task                          |
| 5          | Service          | Service account logon                   |
| 7          | Unlock           | Screen unlock                           |
| 8          | NetworkCleartext | FTP, Basic Auth with cleartext password |
| 10         | RemoteInteractive| RDP session                             |

---

## 5. Filter Event ID 7045 — New Service Creation

### 5.1 Navigate to System Log
1. In Event Viewer, expand **Windows Logs**
2. Click **System**

### 5.2 Apply Filter for Event ID 7045

**Step 1 — Open Filter**
1. Right-click **System** → **Filter Current Log...**

**Step 2 — Set Event ID**
1. In the **Event IDs** field: type `7045`
2. Click **OK**

**Step 3 — Analyze Events**
Each 7045 event contains:
```
Service Name:    SuspiciousServiceName
Service File Name: C:\Windows\Temp\malware.exe
Service Type:    user mode service
Service Start Type: demand start
Service Account: LocalSystem
```

### 5.3 Red Flags in 7045 Events

Look for these suspicious indicators:

- Service binary located in: `C:\Temp\`, `C:\Windows\Temp\`, `%AppData%\`
- Service names that look random: `svc_xk29fj`, `Windows32Update`
- Services running as **LocalSystem** with temp-directory binaries
- Services installed at odd hours (2 AM, 3 AM)
- Service file names mimicking legitimate tools: `svchost32.exe`, `lsas.exe`

---

## 6. Brute-Force Attack Detection from Security Logs

### 6.1 What a Brute-Force Pattern Looks Like

A brute-force attack generates **multiple Event ID 4625 entries** in rapid succession from the **same source IP** targeting the **same or multiple accounts**.

**Indicators:**
- 5+ failed logins within 60 seconds from one IP → Brute-force
- Failed logins against non-existent usernames → Username enumeration
- Failures followed by one success → Successful compromise

### 6.2 Create a Custom View for Brute-Force Monitoring

**Step 1 — Create Custom View**
1. In Event Viewer left panel, right-click **Custom Views**
2. Click **Create Custom View...**

**Step 2 — Configure View**
1. Set **Logged** → `Last 24 hours` (or your desired range)
2. **Event level:** Check `Information`, `Warning`, `Error`
3. **By log:** Select `Windows Logs` → `Security`
4. **Event IDs:** `4625`
5. Click **OK**
6. Name it: `Brute Force Detection - Failed Logins`
7. Click **OK**

### 6.3 Analyze with PowerShell — Automated Brute-Force Detection

Open **PowerShell as Administrator** and run:

```powershell
# =====================================================
# SCRIPT: Detect Brute-Force via Event ID 4625
# =====================================================

# Define threshold: more than 5 failures = brute-force
$threshold = 5
$timeWindowMinutes = 10
$startTime = (Get-Date).AddMinutes(-$timeWindowMinutes)

# Pull all 4625 events in the time window
$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $failedLogins) {
    Write-Host "No failed login events found in the last $timeWindowMinutes minutes." -ForegroundColor Green
    exit
}

# Parse each event for IP address and username
$results = foreach ($event in $failedLogins) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    [PSCustomObject]@{
        TimeCreated  = $event.TimeCreated
        TargetUser   = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        SourceIP     = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        LogonType    = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        WorkStation  = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    }
}

# Group by Source IP and count
$grouped = $results | Group-Object -Property SourceIP | Where-Object { $_.Count -ge $threshold }

if ($grouped) {
    Write-Host "`n[!] BRUTE-FORCE ACTIVITY DETECTED" -ForegroundColor Red
    Write-Host "=================================" -ForegroundColor Red
    foreach ($g in $grouped) {
        Write-Host "`nSource IP  : $($g.Name)" -ForegroundColor Yellow
        Write-Host "Attempts   : $($g.Count)" -ForegroundColor Yellow
        Write-Host "Targets    : $(($g.Group.TargetUser | Select-Object -Unique) -join ', ')"
    }
} else {
    Write-Host "[+] No brute-force pattern detected (threshold: $threshold attempts in $timeWindowMinutes min)" -ForegroundColor Green
}

# Export full results
$results | Export-Csv -Path "$env:USERPROFILE\Desktop\FailedLogins_Analysis.csv" -NoTypeInformation
Write-Host "`n[+] Full results exported to Desktop\FailedLogins_Analysis.csv" -ForegroundColor Cyan
```

---

## 7. Advanced Task: Generate Failed Logins in Windows VM

>  **Do this ONLY inside your VM lab environment, never on a production or personal machine.**

### 7.1 Method 1 — Manual Wrong Password Attempts

**Step 1 — Open a Command Prompt**

**Step 2 — Attempt login with wrong password using `net use`**
```cmd
:: Run this 10 times with wrong passwords to generate 4625 events
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword1
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword2
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword3
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword4
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword5
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword6
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword7
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword8
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword9
net use \\127.0.0.1\IPC$ /user:Administrator WrongPassword10
```

### 7.2 Method 2 — PowerShell Automated Simulator

```powershell
# =====================================================
# SCRIPT: Simulate Brute-Force Failed Logins (LAB ONLY)
# =====================================================

$targetUser = "FakeUser"          # Use a non-existent user
$targetIP   = "127.0.0.1"
$attempts   = 15

Write-Host "[*] Starting brute-force simulation ($attempts attempts)..." -ForegroundColor Cyan

for ($i = 1; $i -le $attempts; $i++) {
    $password = "WrongPass$i"
    $attempt = net use \\$targetIP\IPC$ /user:$targetUser $password 2>&1
    Write-Host "  Attempt $i with password '$password': $attempt"
    Start-Sleep -Milliseconds 500   # Small delay between attempts
}

Write-Host "`n[+] Simulation complete. Check Event Viewer Security log for Event ID 4625." -ForegroundColor Green
```

### 7.3 Verify Events Were Generated

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Apply filter for **Event ID 4625**
3. You should see your simulated failed logins with:
   - Source IP: `127.0.0.1` (loopback)
   - Target username: `FakeUser`
   - Logon Type: `3` (Network)

---

## 8. Export Event Logs to CSV

### 8.1 Export via Event Viewer GUI

**Step 1 — Filter the log first** (apply the 4625 filter as shown in Section 4)

**Step 2 — Save Filtered Log**
1. In the **Actions** panel on the right, click **Save Filtered Log File As...**
2. Choose file format: **CSV (Comma Separated)** or **XML** or **EVTX**
3. Save to your Desktop: `FailedLogins_4625.csv`
4. Click **Save**

>  **Note:** Event Viewer's built-in CSV export has limited fields. Use the PowerShell method below for richer data.

### 8.2 Export via PowerShell (Recommended — More Data)

```powershell
# =====================================================
# SCRIPT: Export Event ID 4625 to Rich CSV
# =====================================================

$outputPath = "$env:USERPROFILE\Desktop\FailedLogins_4625_Detailed.csv"

Write-Host "[*] Pulling Event ID 4625 from Security log..." -ForegroundColor Cyan

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4625
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "[!] No events found. Make sure audit logging is enabled." -ForegroundColor Red
    exit
}

$parsed = foreach ($event in $events) {
    $xml  = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    [PSCustomObject]@{
        TimeCreated       = $event.TimeCreated
        EventID           = $event.Id
        TargetUserName    = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        TargetDomainName  = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        LogonType         = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        FailureReason     = ($data | Where-Object { $_.Name -eq 'FailureReason' }).'#text'
        SourceIP          = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        SourcePort        = ($data | Where-Object { $_.Name -eq 'IpPort' }).'#text'
        WorkstationName   = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
        ProcessName       = ($data | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
    }
}

$parsed | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] Exported $($parsed.Count) events to: $outputPath" -ForegroundColor Green
Write-Host "[+] Open the CSV in Excel or Notepad++ to review." -ForegroundColor Cyan
```

### 8.3 Export via wevtutil CLI

```cmd
:: Export Security log filtered for Event ID 4625 to XML
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /f:XML /e:root > C:\Users\Public\FailedLogins.xml

:: Export System log filtered for Event ID 7045 to XML
wevtutil qe System "/q:*[System[(EventID=7045)]]" /f:XML /e:root > C:\Users\Public\ServiceInstalls.xml

:: Export last 100 Security events as text
wevtutil qe Security /c:100 /rd:true /f:text > C:\Users\Public\Last100SecurityEvents.txt
```

---

## 9. Browser History Analysis Overview

### 9.1 Why Analyze Browser History?

In digital forensics and incident response, browser history reveals:
- Malicious URLs visited by a compromised user
- Downloads of malware or exploit kits
- Command & control (C2) communication
- Data exfiltration endpoints
- Phishing sites accessed

### 9.2 Where Chrome Stores Its History

Chrome stores history in an **SQLite database** file:

| OS      | Chrome History File Path                                                                     |
|---------|----------------------------------------------------------------------------------------------|
| Windows | `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\History`                 |
| Linux   | `~/.config/google-chrome/Default/History`                                                   |
| macOS   | `~/Library/Application Support/Google/Chrome/Default/History`                               |

>  The file is named **`History`** (no extension). It is a SQLite database.

>  **Important:** Chrome locks this file while the browser is open. Always close Chrome before trying to copy or parse the file.

### 9.3 Chrome History Database — Key Tables

| Table            | Contents                                            |
|------------------|-----------------------------------------------------|
| `urls`           | URL, title, visit count, last visit time           |
| `visits`         | Individual visit records with timestamps            |
| `downloads`      | Downloaded file URLs and local file paths          |
| `keyword_search_terms` | Search queries typed into the address bar   |

---

## 10. Install Eric Zimmerman's Tools (LECmd)

### 10.1 About Eric Zimmerman's Tools

Eric Zimmerman is a forensic expert whose free tools are widely used by digital forensic investigators. **LECmd** (LNK Explorer Command) is one of his tools — however for browser history, the correct tool is **BrowsingHistoryView** or **parsing via SQLite**.

>  For Chrome history parsing specifically, we use a combination of:
> - **BrowsingHistoryView** by NirSoft (GUI)
> - **DB Browser for SQLite** (direct DB inspection)
> - **Hindsight** (dedicated Chrome forensics tool)

We will cover all three options below.

### 10.2 Download Eric Zimmerman's Full Tool Suite

**Step 1 — Go to the official website**
```
https://ericzimmerman.github.io/#!index.md
```

**Step 2 — Download the Tools**
1. Scroll down to find the download links
2. Download **Get-ZimmermanTools.zip** OR use the PowerShell downloader

**Step 3 — Use PowerShell to Download All Tools**
```powershell
# Run PowerShell as Administrator

# Create a folder for tools
New-Item -ItemType Directory -Path "C:\ForensicsTools\ZimmermanTools" -Force

# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" `
    -OutFile "C:\ForensicsTools\Get-ZimmermanTools.ps1"

# Execute the downloader script
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\ForensicsTools\Get-ZimmermanTools.ps1 -Dest C:\ForensicsTools\ZimmermanTools
```

**Step 4 — Verify Tools Downloaded**
```cmd
dir C:\ForensicsTools\ZimmermanTools
```
You should see tools like: `LECmd.exe`, `JLECmd.exe`, `PECmd.exe`, `MFTECmd.exe`, etc.

### 10.3 Download BrowsingHistoryView (NirSoft)

```
https://www.nirsoft.net/utils/browsing_history_view.html
```

1. Scroll down → Click **Download BrowsingHistoryView** (32-bit or 64-bit)
2. Extract to: `C:\ForensicsTools\BrowsingHistoryView\`

### 10.4 Download DB Browser for SQLite

```
https://sqlitebrowser.org/dl/
```

1. Download the Windows installer
2. Install to default location
3. This allows you to directly query Chrome's SQLite database

### 10.5 Download Hindsight (Dedicated Chrome Forensics)

```
https://github.com/obsidianforensics/hindsight/releases
```

1. Download the latest `hindsight_gui.exe`
2. Save to: `C:\ForensicsTools\Hindsight\`

---

## 11. Locate Chrome History File

### 11.1 Step-by-Step: Find the History File

**Step 1 — Close Google Chrome completely**
- Right-click Chrome in taskbar → **Close all windows**
- Check Task Manager (`Ctrl + Shift + Esc`) → confirm no `chrome.exe` processes running

**Step 2 — Navigate to the History file**
1. Press `Windows Key + R`
2. Type: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
3. Press Enter
4. Look for a file named **`History`** (no extension)

**Step 3 — Copy the file for analysis (never work on the original)**
```cmd
:: Copy Chrome history to a working directory
mkdir C:\ForensicsLab\ChromeHistory
copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\History" C:\ForensicsLab\ChromeHistory\History_copy
```

**Step 4 — Rename for SQLite tools**
```cmd
:: Rename to add .db extension so SQLite tools recognize it
copy C:\ForensicsLab\ChromeHistory\History_copy C:\ForensicsLab\ChromeHistory\History.db
```

---

## 12. Parse Chrome History Using LECmd & Other Tools

### 12.1 Method 1 — Using Hindsight (Recommended for Chrome)

**Step 1 — Open Hindsight GUI**
1. Navigate to `C:\ForensicsTools\Hindsight\`
2. Double-click `hindsight_gui.exe`

**Step 2 — Configure the Analysis**
1. **Profile path:** Click **Browse** → Navigate to:
   `C:\Users\<YourUser>\AppData\Local\Google\Chrome\User Data\Default`
2. **Browser:** Select `Chrome/Chromium`
3. **Output format:** Select `XLSX` or `SQLite`
4. **Output location:** `C:\ForensicsLab\ChromeHistory\`

**Step 3 — Run Analysis**
1. Click **Run**
2. Hindsight parses: URLs, downloads, cookies, search terms, cache

**Step 4 — Open the output Excel file**
1. Navigate to your output folder
2. Open the `.xlsx` file
3. Review the **URLs** sheet for suspicious entries

---

### 12.2 Method 2 — Using DB Browser for SQLite (Direct Query)

**Step 1 — Open DB Browser for SQLite**

**Step 2 — Open the History database**
1. Click **Open Database**
2. Navigate to: `C:\ForensicsLab\ChromeHistory\History.db`
3. Click **Open**

**Step 3 — Browse the `urls` Table**
1. Click the **Browse Data** tab
2. Select Table: `urls`
3. You will see columns: `id`, `url`, `title`, `visit_count`, `last_visit_time`

**Step 4 — Execute SQL Queries**
Click the **Execute SQL** tab and run these queries:

```sql
-- Query 1: Get all URLs sorted by last visit time
SELECT 
    url,
    title,
    visit_count,
    -- Chrome stores time as microseconds since Jan 1, 1601
    datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') AS last_visit_time_utc
FROM urls
ORDER BY last_visit_time DESC;
```

```sql
-- Query 2: Search for specific URL (test.com example)
SELECT 
    url,
    title,
    visit_count,
    datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') AS last_visit_time_utc
FROM urls
WHERE url LIKE '%test.com%'
ORDER BY last_visit_time DESC;
```

```sql
-- Query 3: Find all http:// (non-HTTPS) visits — potential risk
SELECT 
    url,
    title,
    visit_count,
    datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') AS last_visit
FROM urls
WHERE url LIKE 'http://%'
ORDER BY last_visit_time DESC;
```

```sql
-- Query 4: Find downloaded files
SELECT 
    current_path,
    target_path,
    tab_url,
    referrer,
    total_bytes,
    datetime(start_time / 1000000 - 11644473600, 'unixepoch') AS download_time
FROM downloads
ORDER BY start_time DESC;
```

**Step 5 — Export Query Results**
1. After running a query, click **File** → **Export** → **Results to CSV**
2. Save to: `C:\ForensicsLab\ChromeHistory\Parsed_URLs.csv`

---

### 12.3 Method 3 — Using BrowsingHistoryView (GUI)

**Step 1 — Open BrowsingHistoryView**
1. Navigate to `C:\ForensicsTools\BrowsingHistoryView\`
2. Run `BrowsingHistoryView.exe`

**Step 2 — Configure Data Source**
1. On first launch, a configuration window appears
2. Select: **Load history from the specified profile folder**
3. Path: `C:\Users\<YourUser>\AppData\Local\Google\Chrome\User Data\Default`
4. Check **Google Chrome**
5. Click **OK**

**Step 3 — Review and Filter Results**
- The tool displays all browsing history in a table
- Use **Edit** → **Find** to search for specific URLs
- Sort by **Visit Time** or **Visit Count**

**Step 4 — Export to CSV**
1. **File** → **Save Selected Items** (or Ctrl+S)
2. Choose **Comma Delimited Text File (*.csv)**
3. Save to: `C:\ForensicsLab\ChromeHistory\BrowsingHistory_Export.csv`

---

### 12.4 Method 4 — Using LECmd for LNK File Analysis (Zimmerman Tool)

>  LECmd analyzes Windows **LNK (shortcut) files**, which can reveal recently accessed files including downloaded malware.

**Step 1 — Parse LNK files from Recent folder**
```cmd
cd C:\ForensicsTools\ZimmermanTools

:: Parse all LNK files from the Recent folder
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent" --csv C:\ForensicsLab\ --csvf RecentFiles.csv
```

**Step 2 — Review Output**
```cmd
:: Open the CSV
start C:\ForensicsLab\RecentFiles.csv
```

**Step 3 — Look for suspicious entries**
- Files accessed from Temp directories
- Recently opened executables or scripts
- Files with suspicious names

---

## 13. Identify Malicious URLs in Parsed Output

### 13.1 Manual Indicators of Malicious URLs

When reviewing the Chrome history CSV/output, flag these patterns:

| Indicator               | Example                                              | Why Suspicious                         |
|-------------------------|------------------------------------------------------|----------------------------------------|
| IP-based URLs           | `http://192.168.1.50/payload.exe`                   | Bypasses DNS; common in C2             |
| Unusual TLDs            | `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`                  | Free/abused domains                    |
| Long random subdomains  | `a8f3k2.malware.com`                                | DGA (Domain Generation Algorithm)     |
| URL shorteners          | `bit.ly/xyz`, `tinyurl.com/abc`                     | Masking real destination               |
| Download links for EXE  | `http://evil.com/update.exe`                        | Direct malware download                |
| Port in URL             | `http://example.com:4444/shell`                     | Non-standard port; C2 communication   |
| Base64-like strings     | `http://evil.com/?q=aHR0cDovL...`                   | Encoded payload in URL                 |

### 13.2 PowerShell: Search for Suspicious URLs in CSV

```powershell
# =====================================================
# SCRIPT: Scan Chrome History CSV for Malicious Patterns
# =====================================================

$csvPath = "C:\ForensicsLab\ChromeHistory\Parsed_URLs.csv"
$outputPath = "C:\ForensicsLab\ChromeHistory\Suspicious_URLs.csv"

# Define suspicious patterns
$suspiciousPatterns = @(
    'http://',                      # Non-HTTPS
    '\.exe',                        # Executable downloads
    '\.ps1',                        # PowerShell downloads
    '\.bat',                        # Batch file downloads
    '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP-based URLs
    'bit\.ly', 'tinyurl', 'goo\.gl',        # URL shorteners
    '\.xyz', '\.tk', '\.ml', '\.ga',        # Suspicious TLDs
    ':4444', ':8080', ':1337',              # Suspicious ports
    'test\.com'                             # Your test URL
)

$data = Import-Csv $csvPath

$suspicious = $data | Where-Object {
    $url = $_.URL
    $matched = $false
    foreach ($pattern in $suspiciousPatterns) {
        if ($url -match $pattern) {
            $matched = $true
            break
        }
    }
    $matched
}

if ($suspicious) {
    Write-Host "`n[!] Found $($suspicious.Count) suspicious URLs:" -ForegroundColor Red
    $suspicious | ForEach-Object { Write-Host "  -> $($_.URL)" -ForegroundColor Yellow }
    $suspicious | Export-Csv -Path $outputPath -NoTypeInformation
    Write-Host "`n[+] Exported to: $outputPath" -ForegroundColor Cyan
} else {
    Write-Host "[+] No suspicious URLs detected." -ForegroundColor Green
}
```

### 13.3 Test URL Verification (http://test.com)

To practice finding a specific URL in the history:

**Step 1 — Visit the test URL in Chrome (inside VM)**
1. Open Chrome inside the VM
2. Navigate to `http://test.com`
3. Close Chrome

**Step 2 — Copy the History file**
```cmd
copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\History" C:\ForensicsLab\ChromeHistory\History.db
```

**Step 3 — Query for test.com in DB Browser**
```sql
SELECT url, title, visit_count,
       datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') AS visit_time
FROM urls
WHERE url LIKE '%test.com%';
```

**Expected Result:**
```
url              | title    | visit_count | visit_time
http://test.com  | test.com | 1           | ---------
```

---

## 14. Using wevtutil CLI for Log Analysis

`wevtutil` is a built-in Windows command-line tool for querying event logs.

### 14.1 Basic wevtutil Commands

```cmd
:: List all available logs
wevtutil el

:: Get information about Security log
wevtutil gl Security

:: Count events in Security log
wevtutil gli Security

:: Query last 20 events from Security log
wevtutil qe Security /c:20 /rd:true /f:text
```

### 14.2 Query Specific Event IDs

```cmd
:: Query Event ID 4625 (Failed Logins) - last 50 events
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:50 /rd:true /f:text

:: Query Event ID 7045 (New Service)
wevtutil qe System "/q:*[System[(EventID=7045)]]" /c:20 /rd:true /f:text

:: Query multiple Event IDs (4625 and 4624)
wevtutil qe Security "/q:*[System[(EventID=4625 or EventID=4624)]]" /c:30 /f:text

:: Query with time filter (last 1 hour)
wevtutil qe Security "/q:*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 3600000]]]" /f:text
```

### 14.3 Export Logs

```cmd
:: Export to EVTX format
wevtutil epl Security C:\ForensicsLab\Security_Export.evtx

:: Export to XML with filter
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /f:XML /e:root > C:\ForensicsLab\FailedLogins.xml

:: Export using a saved custom view (from Event Viewer)
wevtutil qe C:\ForensicsLab\MyCustomView.xml /sq:true /f:text
```

### 14.4 Useful wevtutil Queries Reference

```cmd
:: Find log clear events (anti-forensics detection!)
wevtutil qe Security "/q:*[System[(EventID=1102)]]" /f:text

:: Find new user account creation
wevtutil qe Security "/q:*[System[(EventID=4720)]]" /f:text

:: Find privilege escalation (group membership changes)
wevtutil qe Security "/q:*[System[(EventID=4732)]]" /f:text

:: Find RDP logins (Logon Type 10)
wevtutil qe Security "/q:*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" /f:text
```

---

## 15. Using LogParser Lizard (GUI Tool)

### 15.1 Download and Install

```
https://www.lizard-labs.com/log_parser_lizard.aspx
```

1. Download the installer
2. Install with default settings
3. LogParser Lizard provides a GUI over Microsoft's LogParser engine

### 15.2 Query Windows Event Logs

**Step 1 — Open LogParser Lizard**

**Step 2 — Create a new query**
1. Click **New Query**
2. Select **Event Log (EVT/EVTX)** as the data source

**Step 3 — Enter SQL-like query**
```sql
-- Find failed logins with source IP
SELECT 
    TimeGenerated,
    EXTRACT_TOKEN(Strings, 5, '|') AS TargetUser,
    EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP,
    EXTRACT_TOKEN(Strings, 10, '|') AS LogonType
FROM Security
WHERE EventID = 4625
ORDER BY TimeGenerated DESC
```

**Step 4 — Run and Export**
1. Click **Execute**
2. Review results in the grid
3. Click **Export** → **CSV**

---

## 16. Setting Up Elastic SIEM (Optional Advanced)

### 16.1 Overview

Elastic SIEM (now part of Elastic Security) provides centralized log analysis with visual dashboards. This is an advanced setup for those wanting enterprise-level analysis.

### 16.2 Quick Setup with Docker

**Step 1 — Install Docker Desktop**
```
https://www.docker.com/products/docker-desktop/
```

**Step 2 — Pull and Start Elasticsearch + Kibana**
```cmd
:: Pull Elasticsearch
docker pull docker.elastic.co/elasticsearch/elasticsearch:8.12.0

:: Run Elasticsearch
docker run -d --name elasticsearch -p 9200:9200 -p 9300:9300 ^
  -e "discovery.type=single-node" ^
  -e "xpack.security.enabled=false" ^
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0

:: Pull Kibana
docker pull docker.elastic.co/kibana/kibana:8.12.0

:: Run Kibana
docker run -d --name kibana -p 5601:5601 ^
  --link elasticsearch:elasticsearch ^
  docker.elastic.co/kibana/kibana:8.12.0
```

**Step 3 — Access Kibana**
1. Open browser → `http://localhost:5601`
2. Wait 2-3 minutes for full startup

**Step 4 — Install Winlogbeat (Sends Windows logs to Elastic)**
```
https://www.elastic.co/downloads/beats/winlogbeat
```

```yaml
# winlogbeat.yml configuration
winlogbeat.event_logs:
  - name: Security
    event_id: 4625, 4624, 4720, 4732, 1102
  - name: System
    event_id: 7045, 7036

output.elasticsearch:
  hosts: ["http://localhost:9200"]

setup.kibana:
  host: "http://localhost:5601"
```

```cmd
:: Install and start Winlogbeat service
cd C:\Program Files\Winlogbeat
winlogbeat.exe setup -e
Start-Service winlogbeat
```

**Step 5 — View in Kibana SIEM**
1. In Kibana → **Security** → **SIEM**
2. View dashboards for Authentication failures, Rare processes, Network connections

---

## 17. Summary Checklist

Use this checklist to confirm you have completed all steps:

### Environment Setup
- [ ] Windows VM created and running
- [ ] Audit logging enabled for logon events (Success + Failure)
- [ ] Administrator access confirmed
- [ ] ForensicsLab folder created: `C:\ForensicsLab\`

### Event ID 4625 — Failed Logins
- [ ] Opened Event Viewer → Windows Logs → Security
- [ ] Applied filter for Event ID 4625
- [ ] Reviewed individual event details (source IP, username, logon type)
- [ ] Identified brute-force pattern (multiple failures from same IP)
- [ ] Exported filtered events to CSV

### Event ID 7045 — Service Creation
- [ ] Opened Event Viewer → Windows Logs → System
- [ ] Applied filter for Event ID 7045
- [ ] Reviewed service details (name, binary path, account)
- [ ] Identified any suspicious service characteristics

### Brute-Force Simulation (Advanced)
- [ ] Generated at least 10 failed login events using `net use` or PowerShell script
- [ ] Verified events appeared in Event Viewer
- [ ] Ran PowerShell brute-force detection script
- [ ] Exported results to CSV on Desktop

### Browser History Analysis
- [ ] Closed Google Chrome in the VM
- [ ] Located Chrome History file
- [ ] Copied History file to `C:\ForensicsLab\ChromeHistory\`
- [ ] Renamed to `History.db`
- [ ] Opened with DB Browser for SQLite
- [ ] Executed SQL queries to retrieve URLs
- [ ] Searched for test URL (`http://test.com`)
- [ ] Exported results to CSV
- [ ] Ran suspicious URL detection PowerShell script

### Tools Used
- [ ] Windows Event Viewer (built-in)
- [ ] wevtutil CLI (built-in)
- [ ] DB Browser for SQLite
- [ ] Hindsight or BrowsingHistoryView
- [ ] Eric Zimmerman's Tools (LECmd)
- [ ] LogParser Lizard (optional)
- [ ] Elastic SIEM (optional advanced)

---

## 18. Troubleshooting Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| No 4625 events in Security log | Audit logging not enabled | Run `auditpol /set /subcategory:"Logon" /failure:enable` |
| Event Viewer shows "Access Denied" | Not running as Administrator | Right-click Event Viewer → Run as Administrator |
| Chrome History file is locked | Chrome is still running | Close all Chrome windows; check Task Manager |
| DB Browser can't open History | File still named without extension | Rename the copy to `History.db` |
| wevtutil returns no results | Wrong query syntax or no events | Test with `wevtutil qe Security /c:5 /f:text` first |
| Hindsight shows no data | Wrong profile path specified | Use the path to the `Default` folder, not `User Data` |
| PowerShell script blocked | Execution policy restricted | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| VM very slow | Not enough RAM allocated | Increase VM RAM to 4-8 GB in VirtualBox settings |

---

## 19. References & Resources

### Official Documentation
- Microsoft Event ID Reference: `https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/`
- Eric Zimmerman Tools: `https://ericzimmerman.github.io/`
- Elastic Security Documentation: `https://www.elastic.co/guide/en/security/current/`

### Downloadable Tools
| Tool | URL |
|------|-----|
| VirtualBox | `https://www.virtualbox.org/` |
| Eric Zimmerman's Tools | `https://ericzimmerman.github.io/#!index.md` |
| DB Browser for SQLite | `https://sqlitebrowser.org/` |
| Hindsight | `https://github.com/obsidianforensics/hindsight` |
| BrowsingHistoryView | `https://www.nirsoft.net/utils/browsing_history_view.html` |
| LogParser Lizard | `https://www.lizard-labs.com/log_parser_lizard.aspx` |
| Winlogbeat | `https://www.elastic.co/downloads/beats/winlogbeat` |

### Learning Resources
- SANS Windows Forensics Cheat Sheet: `https://www.sans.org/posters/windows-forensics-evidence-of/`
- Ultimate Windows Security Event ID Encyclopedia: `https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/`
- Malware Archaeology Windows Logging Cheat Sheet: `https://www.malwarearchaeology.com/cheat-sheets`

---

*This README was created for educational and cybersecurity training purposes only. All simulated attack exercises should be performed exclusively within isolated virtual machine environments. Never perform these tests on production systems or networks without explicit authorization.*