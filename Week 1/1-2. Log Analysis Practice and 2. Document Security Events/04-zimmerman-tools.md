# Day 6 | Eric Zimmerman's Tools — Complete Setup & Usage

**Lab Date:** 10 Mar 2026

---

##  Objectives

- Download and set up Eric Zimmerman's forensic toolkit
- Use LECmd to parse LNK files (recently opened files)
- Use SQLECmd to parse Chrome browser history
- Export all parsed data to CSV for analysis

---

##  Who is Eric Zimmerman?

Eric Zimmerman is a senior SANS instructor and digital forensics expert who has developed over 20 free, open-source forensic tools. His tools are widely used by DFIR (Digital Forensics and Incident Response) professionals globally. All tools are free and available at:

**https://ericzimmerman.github.io/#!index.md**

---

##  Step 1 — Download the Tools

### Option A — Download via PowerShell (Recommended)

```powershell
# Create tools directory
New-Item -ItemType Directory -Path "C:\EZTools" -Force

# Download the Get-ZimmermanTools script
Invoke-WebRequest -Uri "https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip" `
    -OutFile "C:\EZTools\Get-ZimmermanTools.zip"

# Extract the downloader script
Expand-Archive "C:\EZTools\Get-ZimmermanTools.zip" -DestinationPath "C:\EZTools\" -Force

# Run it to download ALL tools (requires .NET 6+)
cd C:\EZTools
.\Get-ZimmermanTools.ps1 -Dest C:\EZTools\
```

### Option B — Manual Download

1. Visit: https://ericzimmerman.github.io/#!index.md
2. Click **"Get .NET 6 Version (Preferred)"**
3. Extract to `C:\EZTools\`

### Install .NET 6 (Required)

```powershell
# Check if .NET 6 is installed
dotnet --list-runtimes

# If not installed, download from:
# https://dotnet.microsoft.com/en-us/download/dotnet/6.0
# Download: .NET 6.0 Runtime (x64)
```

---

##  Step 2 — Verify Extracted Tools

After extraction, `C:\EZTools\` should contain:

```
C:\EZTools\
├── LECmd.exe        ← LNK file parser
├── SQLECmd.exe      ← SQLite database parser (Chrome, Firefox, etc.)
├── MFTECmd.exe      ← Master File Table parser
├── PECmd.exe        ← Prefetch file parser
├── JLECmd.exe       ← Jump List parser
├── RBCmd.exe        ← Recycle Bin parser
├── RECmd.exe        ← Registry parser
└── Maps\            ← SQLECmd maps for various databases
```

---

##  Part A — LECmd (LNK File Parser)

### What are LNK files?

LNK (shortcut) files are automatically created by Windows when a user opens a file. They contain:
- Path to the original file
- Timestamps (created, modified, accessed)
- Drive serial number, MAC address of the machine
- Metadata useful for forensics

### Where LNK files are stored:

```
C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Office\Recent\
```

### Parse a single LNK file

```powershell
cd C:\EZTools

# Parse single LNK file
.\LECmd.exe -f "C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\document.lnk"
```

### Parse entire Recent folder (recommended)

```powershell
# Parse ALL LNK files in Recent folder, export to CSV
.\LECmd.exe -d "C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Recent\" `
    --csv C:\Output\ `
    --csvf lnk_recent_files.csv

Write-Host "Done. Check C:\Output\lnk_recent_files.csv"
```

### What to look for in LECmd output

| Column | What It Reveals |
|--------|----------------|
| `TargetCreated` | When original file was created |
| `TargetModified` | Last time original was modified |
| `TargetPath` | Full path to the opened file |
| `VolumeLabel` | Drive label (e.g., USB drive name) |
| `DriveType` | Fixed / Removable — detects USB usage |
| `NetworkShareName` | File was opened from a network share |

**Forensic insight:** If `DriveType` = Removable, the user opened a file from a USB drive — the `VolumeLabel` and serial number can identify the specific USB device.

---

##  Part B — SQLECmd (Chrome History Parser)

### What SQLECmd does

SQLECmd parses SQLite databases used by many applications. It uses **Maps** (JSON config files) to know the schema of each database.

### Built-in Maps include:

- Chrome / Chromium History
- Chrome / Chromium Downloads
- Firefox History (`places.sqlite`)
- Edge History
- Discord Database
- Signal Database

### Step 1 — Copy Chrome History (Chrome must be closed)

```powershell
# Close Chrome first!
Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Copy the History file
$src = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
$dst = "C:\Output\ChromeHistory"
Copy-Item $src $dst -Force
Write-Host "Copied Chrome History to: $dst"
```

### Step 2 — Parse with SQLECmd

```powershell
cd C:\EZTools

# Parse Chrome History
.\SQLECmd.exe -f "C:\Output\ChromeHistory" --csv C:\Output\ --hunt

# --hunt flag: SQLECmd auto-detects the database type using Maps
```

**Output files created in `C:\Output\`:**
```
C:\Output\
├── 20260310_ChromiumBrowser_History.csv
├── 20260310_ChromiumBrowser_Downloads.csv
└── 20260310_ChromiumBrowser_KeywordSearchTerms.csv
```

### Step 3 — Search for the Test URL

```powershell
# Import and search CSV
$history = Import-Csv "C:\Output\20260310_ChromiumBrowser_History.csv"

# Search for test.com
$matches = $history | Where-Object { $_.URL -like "*test.com*" }

if ($matches.Count -gt 0) {
    Write-Host "[!] Found $($matches.Count) visit(s) to test.com:"
    $matches | Format-Table URL, Title, VisitCount, LastVisitTime -AutoSize
} else {
    Write-Host "[*] No visits to test.com found."
}

# Export matches
$matches | Export-Csv "C:\Output\testcom_visits.csv" -NoTypeInformation
```

### Step 4 — Parse an Entire Directory

If you want to parse all Chrome profiles at once:

```powershell
.\SQLECmd.exe -d "$env:LOCALAPPDATA\Google\Chrome\User Data\" `
    --csv C:\Output\ `
    --hunt
```

---

##  Part C — SQLECmd Maps Reference

Maps tell SQLECmd how to interpret specific databases. They're located in `C:\EZTools\Maps\`.

To list all available Maps:

```powershell
Get-ChildItem "C:\EZTools\Maps\" -Filter "*.smap" |
    Select-Object Name, LastWriteTime |
    Format-Table -AutoSize
```

To check which Map matches your DB:

```powershell
.\SQLECmd.exe -f "C:\Output\ChromeHistory" --hunt
# SQLECmd will show which Map it used
```

---

##  Understanding Chrome Timestamps

Chrome stores timestamps as **microseconds since January 1, 1601** (not Unix epoch). To convert:

```python
# Python conversion
import datetime
chrome_time = 13348579342000000  # example value from DB
unix_time = (chrome_time / 1000000) - 11644473600
readable = datetime.datetime.utcfromtimestamp(unix_time)
print(readable)  # 2026-03-10 14:22:22
```

```sql
-- SQL conversion in DB Browser
SELECT url,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS visit_time
FROM urls
ORDER BY last_visit_time DESC;
```

---

##  Checklist — Day 6

- [ ] Downloaded Eric Zimmerman's tools to `C:\EZTools\`
- [ ] Verified .NET 6 is installed
- [ ] Ran LECmd on the Recent files folder
- [ ] Reviewed LNK output — noted any removable drives or unusual paths
- [ ] Closed Chrome and copied the History database
- [ ] Ran SQLECmd with `--hunt` flag on Chrome History
- [ ] Found the CSV output files in `C:\Output\`
- [ ] Searched for `test.com` in the history CSV

---

##  Next Step

Proceed to [`02-browser-history-analysis.md`](02-browser-history-analysis.md) for deeper URL analysis, or jump to [`05-documentation-template.md`](05-documentation-template.md) to document your findings.
