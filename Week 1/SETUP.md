#  Complete Setup Guide

This guide walks you through every installation step required to run this lab from scratch.

---

## Step 1 — Install Git

### Windows
1. Download from: https://git-scm.com/download/win
2. Run the installer — accept all defaults
3. Verify: open **Git Bash** or **Command Prompt** and run:
   ```
   git --version
   ```

---

## Step 2 — Clone the Repository

Open **Git Bash** or **PowerShell**:

```bash
git clone https://github.com/YOUR_USERNAME/cybersecurity-log-analysis.git
cd cybersecurity-log-analysis
```

Replace `YOUR_USERNAME` with your actual GitHub username after you push.

---

## Step 3 — Install Python 3.11+

### Windows
1. Download from: https://www.python.org/downloads/
2.  **Check "Add Python to PATH"** during installation
3. Verify:
   ```
   python --version
   pip --version
   ```

---

## Step 4 — Install Python Dependencies

From inside the repo folder:

```bash
pip install -r requirements.txt
```

Packages installed:
- `pandas` — CSV/data analysis
- `colorama` — Terminal color output
- `tabulate` — Formatted table output
- `python-dateutil` — Flexible date parsing
- `rich` — Rich terminal output

---

## Step 5 — Configure PowerShell Execution Policy (Windows)

To run the included `.ps1` scripts, you must allow script execution.

Open **PowerShell as Administrator**:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Type `Y` to confirm.

To verify:
```powershell
Get-ExecutionPolicy -Scope CurrentUser
# Should output: RemoteSigned
```

---

## Step 6 — Verify Everything Works

### Test Python Scripts

```bash
# Test brute-force detector (uses sample XML)
python scripts/analysis/brute_force_detector.py --log logs/sample/sample_events_4625.xml

# Test Chrome history parser (uses sample DB)
python scripts/analysis/parse_chrome_history.py --db logs/sample/sample_chrome_history.db --search "test.com"

# Test report generator
python scripts/reporting/generate_report.py --csv templates/security_event_template.csv
```

All three should run without errors and produce output.

### Test PowerShell Scripts (Windows VM — as Administrator)

```powershell
# Check your PowerShell version (need 5.1+)
$PSVersionTable.PSVersion

# Test that you can query Security log
Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object Id, TimeCreated
```

---

## Step 7 — Optional Tools

### Eric Zimmerman's Tools
1. Go to: https://ericzimmerman.github.io/#!index.md
2. Download ZIP → extract to `C:\EZTools\`
3. Install .NET 6 if prompted: https://dotnet.microsoft.com/download/dotnet/6.0

### LogParser Lizard (GUI)
Download: https://lizard-labs.com/log_parser_lizard.aspx

### DB Browser for SQLite
Download: https://sqlitebrowser.org/dl/

### Elastic SIEM (Optional Advanced)
Follow: https://www.elastic.co/guide/en/siem/guide/current/index.html

---

## Step 8 — Create Your GitHub Repository

```bash
# Initialize git (if not already cloned)
git init
git add .
git commit -m "Initial commit — Cybersecurity Log Analysis Lab"

# Create repo on GitHub (via browser) then:
git remote add origin https://github.com/YOUR_USERNAME/cybersecurity-log-analysis.git
git branch -M main
git push -u origin main
```

---

## Troubleshooting

### "Access denied" on Security log (PowerShell)
→ Run PowerShell as Administrator

### "No events were found" for Event ID 4625
→ Enable audit policy first:
```cmd
auditpol /set /subcategory:"Logon" /failure:enable
```
Then run `generate_failed_logins.ps1`

### Python `ModuleNotFoundError`
→ Run: `pip install -r requirements.txt`

### Chrome History locked / busy
→ Fully close Chrome before running parser:
```powershell
Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
```

### PowerShell "execution of scripts is disabled"
→ Run: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`
