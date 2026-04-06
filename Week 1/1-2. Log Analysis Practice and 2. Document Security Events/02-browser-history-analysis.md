#  Day 7 | Browser History Analysis with Eric Zimmerman's Tools

**Lab Date:** 11 Mar 2026

---

##  Objectives

- Locate Chrome's `History` SQLite database on a Windows system
- Use Eric Zimmerman's tools to parse browser artifacts
- Search for visits to suspicious or test URLs
- Export parsed history to CSV for documentation

---

##  Where Chrome Stores History

Chrome stores browsing history in a SQLite database at:

```
C:\Users\<USERNAME>\AppData\Local\Google\Chrome\User Data\Default\History
```

>  **Important:** Chrome must be closed before copying or parsing this file.  
> While Chrome is running, the database is locked.

Other browser paths for reference:

| Browser | History File Location |
|---------|----------------------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite` |

---

##  Method 1 — Eric Zimmerman's Tools

### What are Eric Zimmerman's Tools?

Eric Zimmerman is a SANS instructor who developed a free suite of digital forensics tools. For browser history, we use:

- **LECmd** — LNK file parser (useful for recently opened files)
- **MFTECmd** — Master File Table parser
- **SQLECmd** — parses multiple SQLite databases including browser history

### Download Steps

1. Go to: **https://ericzimmerman.github.io/#!index.md**
2. Click **"Get .NET 6 Version"** (recommended)
3. Download the ZIP archive
4. Extract to a folder, e.g., `C:\EZTools\`

### Run SQLECmd to Parse Chrome History

Open **PowerShell as Administrator**:

```powershell
# Navigate to EZTools directory
cd C:\EZTools\

# Parse Chrome History file
.\SQLECmd.exe -f "C:\Users\<USERNAME>\AppData\Local\Google\Chrome\User Data\Default\History" --csv C:\Output\

# Replace <USERNAME> with your actual Windows username
```

**Expected output files in `C:\Output\`:**
```
ChromiumHistory_<timestamp>.csv
ChromiumDownloads_<timestamp>.csv
ChromiumKeywordSearchTerms_<timestamp>.csv
```

### Read the CSV Output

Open `ChromiumHistory_<timestamp>.csv` in Excel or run:

```powershell
Import-Csv "C:\Output\ChromiumHistory_*.csv" | Format-Table -AutoSize
```

**Key columns in the history CSV:**

| Column | Description |
|--------|-------------|
| `URL` | The full URL visited |
| `Title` | Page title |
| `VisitCount` | How many times visited |
| `LastVisitTime` | Timestamp of last visit |
| `TypedCount` | Times URL was typed manually |

---

##  Method 2 — Python SQLite Parser

Use the included script if EZTools is not available:

```bash
# From the repo root
python scripts/analysis/parse_chrome_history.py \
  --db "C:\Users\<USERNAME>\AppData\Local\Google\Chrome\User Data\Default\History" \
  --search "test.com" \
  --output reports/chrome_history_results.csv
```

**Script output example:**

```
[*] Parsing Chrome history database...
[*] Total URLs found: 1,482
[!] Suspicious URL matches (test.com):
+---------------------------+------------------+------------+
| URL                       | Last Visit       | Visit Count|
+---------------------------+------------------+------------+
| http://test.com           | 2026-03-11 14:22 | 3          |
| http://test.com/payload   | 2026-03-11 14:23 | 1          |
+---------------------------+------------------+------------+
[*] Results saved to: reports/chrome_history_results.csv
```

---

##  Method 3 — DB Browser for SQLite (Manual)

1. Download **DB Browser for SQLite** from https://sqlitebrowser.org/
2. Copy the History file to your Desktop (Chrome must be closed):
   ```powershell
   Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" "$env:USERPROFILE\Desktop\ChromeHistory"
   ```
3. Open DB Browser → **Open Database** → select `ChromeHistory`
4. Click **Browse Data** → select table: `urls`
5. To search for a URL, go to **Execute SQL** tab:

```sql
-- Find all visits to test.com
SELECT url, title, visit_count, last_visit_time
FROM urls
WHERE url LIKE '%test.com%'
ORDER BY last_visit_time DESC;
```

```sql
-- Find all URLs with high visit count (possible beaconing)
SELECT url, title, visit_count
FROM urls
WHERE visit_count > 10
ORDER BY visit_count DESC
LIMIT 50;
```

```sql
-- Find URLs visited in a specific time range
-- Chrome uses microseconds since 1601-01-01
SELECT url, title, last_visit_time,
       datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS visit_datetime
FROM urls
WHERE visit_datetime BETWEEN '2026-03-05' AND '2026-03-13'
ORDER BY last_visit_time DESC;
```

---

##  What to Look For — Malicious URL Indicators

| Indicator | Example | Risk |
|-----------|---------|------|
| IP address URLs | `http://192.168.1.200/shell` | High |
| Non-standard ports | `http://evil.com:8080` | Medium |
| Base64 in URL params | `?cmd=aGVsbG8=` | High |
| File download URLs | `.exe`, `.bat`, `.ps1` in URL | High |
| Typosquatted domains | `g00gle.com`, `paypa1.com` | High |
| Onion links | `.onion` URLs | High |
| URL shorteners | `bit.ly`, `tinyurl.com` to unknown dest. | Medium |

---

##  Checklist — Day 7

- [ ] Located Chrome History file at `AppData\Local\...`
- [ ] Copied History DB (Chrome closed first)
- [ ] Ran SQLECmd or Python script to parse history
- [ ] Searched for `test.com` visits
- [ ] Exported results to CSV
- [ ] Documented any suspicious findings using the template

---

##  Next Step

Proceed to [`05-documentation-template.md`](05-documentation-template.md) to document your findings.
