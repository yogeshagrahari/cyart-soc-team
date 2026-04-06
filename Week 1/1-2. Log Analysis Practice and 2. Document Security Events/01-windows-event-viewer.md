#  Day 2–3 | Windows Event Viewer — Filtering Security Events

**Lab Dates:** 06 Mar 2026 – 07 Mar 2026

---

##  Objectives

By the end of this section you will be able to:
- Open and navigate Windows Event Viewer
- Apply filters to isolate specific Event IDs
- Identify signs of brute-force attacks and suspicious service installs
- Export filtered events for further analysis

---

##  What is Windows Event Viewer?

Windows Event Viewer (`eventvwr.msc`) is a built-in Microsoft Management Console (MMC) snap-in that lets you browse and search Windows event logs. Key logs for security analysis:

| Log Name | Location in Event Viewer | What it Contains |
|----------|--------------------------|-----------------|
| **Security** | Windows Logs → Security | Login attempts, privilege use, object access |
| **System** | Windows Logs → System | Service installs, hardware events, crashes |
| **Application** | Windows Logs → Application | App errors, crashes |

---

##  Critical Event IDs

| Event ID | Log | Meaning | Why It Matters |
|----------|-----|---------|----------------|
| **4625** | Security | An account failed to log on | Brute-force indicator |
| **4624** | Security | Successful logon | Baseline / post-attack access |
| **4648** | Security | Logon using explicit credentials | Pass-the-hash, lateral movement |
| **7045** | System | A new service was installed | Malware persistence |
| **4720** | Security | A new user account was created | Backdoor account creation |
| **4732** | Security | A member was added to a group | Privilege escalation |

---

##  How To: Filter Event ID 4625 (Failed Logins)

### Method A — GUI (Event Viewer)

1. Press `Win + R` → type `eventvwr.msc` → press **Enter**
2. In the left panel expand: **Windows Logs → Security**
3. In the right **Actions** panel click **Filter Current Log…**
4. In the dialog box:
   - **Event level:** ☑ Information ☑ Warning ☑ Error
   - **Event IDs:** type `4625`
   - Click **OK**
5. You will now see only failed login attempts.

**Reading an Event ID 4625 entry:**

```
Subject:
    Security ID:      SYSTEM
    Account Name:     WORKSTATION01$

Account For Which Logon Failed:
    Account Name:     Administrator       ← target username
    Account Domain:   WORKSTATION01

Failure Information:
    Failure Reason:   Unknown user name or bad password
    Status:           0xC000006D
    Sub Status:       0xC0000064

Network Information:
    Workstation Name: ATTACKER-PC
    Source Network Address: 192.168.1.10   ← attacker IP
    Source Port:      51234
```

**Key fields to note:**
- `Account Name` (who was targeted)
- `Source Network Address` (attacker IP)
- `Logon Type` (3 = Network, 10 = RemoteInteractive/RDP)

---

### Method B — wevtutil CLI (Command Prompt / PowerShell)

Open **Command Prompt as Administrator**, then:

```cmd
:: List last 50 failed logins
wevtutil qe Security /q:"*[System[EventID=4625]]" /c:50 /f:text /rd:true
```

```cmd
:: Export to XML file
wevtutil qe Security /q:"*[System[EventID=4625]]" /f:XML > C:\Logs\failed_logins.xml
```

```powershell
# PowerShell equivalent — output to grid view
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    Select-Object TimeCreated, Message |
    Out-GridView
```

---

##  How To: Filter Event ID 7045 (New Service Installed)

### GUI Method

1. Open Event Viewer → **Windows Logs → System**
2. Click **Filter Current Log…**
3. Enter Event ID: `7045`
4. Click **OK**

**Reading a 7045 entry — what to look for:**

```
A new service was installed in the system.

Service Name:  MaliciousSvc          ← suspicious name
Service File Name: C:\Temp\evil.exe  ← path outside System32 = red flag
Service Type:  user mode service
Service Start Type: auto start       ← auto = persistence
Service Account: LocalSystem         ← high privilege = dangerous
```

**Red flags in 7045:**
- Service binary path is in `%TEMP%`, `%APPDATA%`, or root `C:\`
- Service name looks random (e.g., `svchost32`, `WindowsUpdate2`)
- Service runs as `LocalSystem` or `NT AUTHORITY\SYSTEM`
- Service installed outside business hours

### CLI Method

```cmd
wevtutil qe System /q:"*[System[EventID=7045]]" /f:text /rd:true /c:20
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Format-List TimeCreated, Message
```

---

##  Identifying Brute-Force Attacks from Event ID 4625

A brute-force attack shows these patterns in the Security log:

| Indicator | What to Look For |
|-----------|-----------------|
| **Frequency** | Many 4625 events in a short time (>5 per minute) |
| **Same Source IP** | Repeated `Source Network Address` value |
| **Same Target Account** | Repeated `Account Name` (often `Administrator`) |
| **Logon Type 3** | Network-based attack (not local keyboard) |
| **Followed by 4624** | Success after many failures = successful breach |

### Correlation Query (PowerShell)

```powershell
# Find IPs with more than 5 failed logins
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}

$events | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $ip = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
    [PSCustomObject]@{
        Time = $_.TimeCreated
        IP   = $ip
    }
} | Group-Object IP | Where-Object {$_.Count -gt 5} |
  Sort-Object Count -Descending |
  Format-Table Name, Count -AutoSize
```

---

##  Checklist — Day 2 & 3

- [ ] Opened Event Viewer and navigated to Security log
- [ ] Filtered for Event ID 4625 — found at least one entry
- [ ] Filtered for Event ID 7045 — reviewed System log
- [ ] Ran `wevtutil` from command line
- [ ] Ran PowerShell Get-WinEvent query
- [ ] Identified at least one suspicious pattern

---

##  Next Step

Proceed to [`03-brute-force-detection.md`](03-brute-force-detection.md) to simulate and detect a brute-force attack.
