# 🔐 Day 4–5 | Brute-Force Detection Lab

**Lab Dates:** 08 Mar 2026 – 09 Mar 2026

---

##  Objectives

- Simulate failed login attempts in a Windows VM
- Use Event Viewer and PowerShell to detect the pattern
- Automate detection with a Python script
- Export findings to CSV for reporting

---

##  Safety Notice

> **Only perform these steps on a VM or machine you own.**  
> Generating failed login attempts against systems you do not own is illegal.  
> This lab is designed for a **local Windows Virtual Machine only**.

---

## Part A — Generate Failed Login Attempts

### Step 1 — Ensure Audit Policy is Enabled

Before failed logins generate Event ID 4625, auditing must be on.

Open **Command Prompt as Administrator**:

```cmd
:: Check current audit policy
auditpol /get /subcategory:"Logon"

:: Enable auditing of logon failures
auditpol /set /subcategory:"Logon" /failure:enable

:: Verify
auditpol /get /subcategory:"Logon"
```

Expected output after enabling:
```
System audit policy
Category/Subcategory                      Setting
Logon/Logon                               Failure
```

---

### Step 2 — Run the PowerShell Login Simulator

Use the included script:

```powershell
# From repo root — run as Administrator
.\scripts\windows\generate_failed_logins.ps1 -Username "Administrator" -Attempts 15
```

Or manually:

```powershell
# Manual simulation — generates 10 failed logins
$credential = New-Object System.Management.Automation.PSCredential(
    "FakeUser_BruteForce",
    (ConvertTo-SecureString "WrongPassword123" -AsPlainText -Force)
)

for ($i = 1; $i -le 10; $i++) {
    Write-Host "Attempt $i of 10..."
    try {
        Start-Process -FilePath "cmd.exe" -Credential $credential -NoNewWindow -ErrorAction Stop
    } catch {
        Write-Host "  [Expected] Login failed — event logged."
    }
    Start-Sleep -Seconds 2
}
Write-Host "`n[Done] 10 failed login attempts generated."
```

> ⏱ Wait 30 seconds after this before checking Event Viewer — events can take a moment to appear.

---

### Step 3 — Verify Events Were Logged

```powershell
# Count recent 4625 events (last 10 minutes)
$startTime = (Get-Date).AddMinutes(-10)

$count = (Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
}).Count

Write-Host "Failed login events in last 10 min: $count"
```

---

## Part B — Detect the Brute-Force Pattern

### Method 1 — Event Viewer GUI

1. Open Event Viewer → **Windows Logs → Security**
2. Click **Filter Current Log…**
3. Enter Event ID: `4625`
4. Set time range: Last 1 hour
5. Look for repeated entries with the same `Account Name`

---

### Method 2 — PowerShell Detection Script

```powershell
# Run from PowerShell as Administrator

# Gather all 4625 events from last 60 minutes
$startTime = (Get-Date).AddMinutes(-60)
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
}

Write-Host "Total failed logins found: $($events.Count)"
Write-Host "---"

# Parse and group by Source IP + Username
$parsed = $events | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time       = $_.TimeCreated
        Username   = ($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        Domain     = ($data | Where-Object {$_.Name -eq 'TargetDomainName'}).'#text'
        SourceIP   = ($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        LogonType  = ($data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        Status     = ($data | Where-Object {$_.Name -eq 'Status'}).'#text'
    }
}

# Show top attacking IPs
Write-Host "`n[!] Top Source IPs (potential attackers):"
$parsed | Group-Object SourceIP |
    Sort-Object Count -Descending |
    Select-Object @{N='Source IP';E={$_.Name}}, Count |
    Format-Table -AutoSize

# Flag IPs with > 3 attempts
Write-Host "`n[ALERT] IPs with more than 3 failed attempts:"
$parsed | Group-Object SourceIP |
    Where-Object {$_.Count -gt 3} |
    ForEach-Object {
        Write-Host "  ⚠️  IP: $($_.Name) — $($_.Count) attempts"
    }
```

---

### Method 3 — Automated Python Analyzer

```bash
# Parse the exported XML log
python scripts/analysis/brute_force_detector.py \
  --log logs/sample/sample_events_4625.xml \
  --threshold 5 \
  --output reports/brute_force_report.csv
```

---

## Part C — Export Events to CSV

### Using the PowerShell Export Script

```powershell
# Run from repo root as Administrator
.\scripts\windows\export_events_csv.ps1 -EventID 4625 -OutputPath "reports\failed_logins.csv"
```

Or manually:

```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    Select-Object -First 200

$results = $events | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        DateTime    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID     = $_.Id
        Username    = ($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        SourceIP    = ($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        LogonType   = ($data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        Computer    = $_.MachineName
        Description = "Failed login attempt"
    }
}

$results | Export-Csv -Path "reports\failed_logins.csv" -NoTypeInformation
Write-Host "[Done] Exported $($results.Count) events to reports\failed_logins.csv"
```

---

##  Interpreting Results

### Logon Type Reference

| Logon Type | Meaning | Attack Relevance |
|------------|---------|-----------------|
| 2 | Interactive (keyboard) | Local physical attacker |
| 3 | Network | Remote brute-force |
| 7 | Unlock | Screen unlock attack |
| 10 | RemoteInteractive | RDP brute-force |

### Status Code Reference

| Status Code | Meaning |
|-------------|---------|
| `0xC000006D` | Bad username or password |
| `0xC000006A` | Wrong password (user exists) |
| `0xC0000064` | Username doesn't exist |
| `0xC0000234` | Account locked out |
| `0xC0000072` | Account disabled |

---

##  Checklist — Day 4 & 5

- [ ] Enabled audit policy for logon failures
- [ ] Ran login simulator — generated 10+ failed attempts
- [ ] Verified events appeared in Security log
- [ ] Filtered Event Viewer for Event ID 4625
- [ ] Ran PowerShell detection script — identified suspicious IP
- [ ] Exported results to `reports/failed_logins.csv`
- [ ] Documented findings using the security event template

---

##  Next Step

Proceed to [`04-zimmerman-tools.md`](04-zimmerman-tools.md) for browser forensics.
