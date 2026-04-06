import argparse
import csv
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


# ── Chrome Timestamp Conversion ───────────────────────────────────────────────
# Chrome stores timestamps as microseconds since 1601-01-01 00:00:00 UTC
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def chrome_time_to_datetime(chrome_time: int) -> datetime | None:
    """Convert Chrome timestamp (microseconds since 1601) to Python datetime."""
    if not chrome_time or chrome_time == 0:
        return None
    try:
        unix_ts = (chrome_time / 1_000_000) - CHROME_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return None


def format_dt(dt: datetime | None) -> str:
    """Format datetime as readable string."""
    if dt is None:
        return 'Unknown'
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


# ── Database Parsing ───────────────────────────────────────────────────────────

def copy_db_to_temp(db_path: Path) -> Path:
    """
    Copy the SQLite database to a temp file.
    Chrome locks the DB while running — copying avoids lock errors.
    """
    tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    tmp.close()
    shutil.copy2(db_path, tmp.name)
    return Path(tmp.name)


def parse_history(db_path: Path, search_term: str = '') -> list[dict]:
    """
    Parse the Chrome History SQLite database.
    Returns list of URL records, optionally filtered by search_term.
    """
    # Work on a copy so we don't lock the original
    tmp_path = copy_db_to_temp(db_path)

    results = []

    try:
        conn = sqlite3.connect(f'file:{tmp_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Query: join urls and visits tables for full visit history
        query = """
            SELECT
                u.url,
                u.title,
                u.visit_count,
                u.typed_count,
                u.last_visit_time,
                u.hidden,
                v.visit_time,
                v.transition
            FROM urls u
            LEFT JOIN visits v ON u.id = v.url
            ORDER BY v.visit_time DESC
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            url        = row['url'] or ''
            title      = row['title'] or ''
            visit_time = chrome_time_to_datetime(row['visit_time'])
            last_visit = chrome_time_to_datetime(row['last_visit_time'])

            # Apply search filter
            if search_term and search_term.lower() not in url.lower():
                continue

            results.append({
                'url':          url,
                'title':        title,
                'visit_count':  row['visit_count'],
                'typed_count':  row['typed_count'],
                'visit_time':   format_dt(visit_time),
                'last_visit':   format_dt(last_visit),
                'hidden':       bool(row['hidden']),
                'transition':   decode_transition(row['transition']),
            })

        conn.close()

    except sqlite3.OperationalError as e:
        print(f"[ERROR] Database error: {e}", file=sys.stderr)
        print("[HINT] Make sure Chrome is closed before running this script.", file=sys.stderr)
        sys.exit(1)
    finally:
        tmp_path.unlink(missing_ok=True)

    return results


def decode_transition(transition: int | None) -> str:
    """Decode Chrome page transition type."""
    if transition is None:
        return 'Unknown'

    CORE_MASK = 0xFF
    core = transition & CORE_MASK

    types = {
        0:  'Typed URL',
        1:  'Auto bookmark',
        2:  'Auto subframe',
        3:  'Manual subframe',
        4:  'Generated',
        5:  'Auto toplevel',
        6:  'Form submit',
        7:  'Reload',
        8:  'Keyword',
        9:  'Keyword generated',
    }
    return types.get(core, f'Transition({core})')


# ── Suspicious URL Detection ───────────────────────────────────────────────────

SUSPICIOUS_PATTERNS = [
    ('.exe', 'Executable download'),
    ('.bat', 'Batch file download'),
    ('.ps1', 'PowerShell script download'),
    ('.vbs', 'VBScript download'),
    ('base64', 'Possible Base64 payload in URL'),
    ('cmd=',  'Command parameter in URL'),
    ('eval(', 'JavaScript eval in URL'),
    (':8080', 'Non-standard port 8080'),
    (':4444', 'Common reverse shell port 4444'),
    (':9999', 'Non-standard port 9999'),
    ('onion', 'Tor .onion address'),
    ('pastebin.com', 'Pastebin (common C2 staging)'),
    ('bit.ly',  'URL shortener'),
    ('tinyurl', 'URL shortener'),
]


def check_suspicious(url: str) -> list[str]:
    """Return list of suspicious patterns found in a URL."""
    flags = []
    url_lower = url.lower()
    for pattern, description in SUSPICIOUS_PATTERNS:
        if pattern in url_lower:
            flags.append(description)
    return flags


# ── Report Output ──────────────────────────────────────────────────────────────

def print_report(results: list[dict], search_term: str, all_count: int) -> None:
    """Print analysis report to stdout."""
    sep = "=" * 66

    print(f"\n{sep}")
    print("  CHROME HISTORY FORENSIC ANALYSIS REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep)

    if search_term:
        print(f"\n[*] Search term  : '{search_term}'")
        print(f"    Total URLs in DB : {all_count}")
        print(f"    Matching results : {len(results)}")
    else:
        print(f"\n[*] Total visits parsed: {len(results)}")

    if not results:
        print("\n[INFO] No results found.")
        return

    # Show matches
    print(f"\n{'URL':<55} {'Visits':>6}  {'Last Visit'}")
    print(f"{'-'*55} {'-'*6}  {'-'*24}")

    for r in results[:50]:  # Show up to 50
        url_display = r['url'][:52] + '...' if len(r['url']) > 55 else r['url']
        print(f"{url_display:<55} {r['visit_count']:>6}  {r['last_visit']}")

    if len(results) > 50:
        print(f"\n  ... and {len(results) - 50} more. Export to CSV to see all.")

    # Suspicious URL check
    suspicious_found = []
    for r in results:
        flags = check_suspicious(r['url'])
        if flags:
            suspicious_found.append((r['url'], flags))

    if suspicious_found:
        print(f"\n{sep}")
        print(f"  🚨 SUSPICIOUS URL INDICATORS FOUND ({len(suspicious_found)} URLs)")
        print(sep)
        for url, flags in suspicious_found[:20]:
            print(f"\n  URL   : {url[:80]}")
            for flag in flags:
                print(f"  Flag  : ⚠️  {flag}")


def export_csv(results: list[dict], output_path: Path) -> None:
    """Export results to CSV file."""
    if not results:
        print("[INFO] No results to export.")
        return

    fields = ['url', 'title', 'visit_count', 'typed_count', 'visit_time', 'last_visit', 'transition']

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[OK] Exported {len(results)} results to: {output_path}")


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Parse Chrome browser History SQLite database for forensic analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Default Chrome History paths:
  Windows : C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History
  macOS   : ~/Library/Application Support/Google/Chrome/Default/History
  Linux   : ~/.config/google-chrome/Default/History

Important: Close Chrome before running this script.

Examples:
  python parse_chrome_history.py --db History
  python parse_chrome_history.py --db History --search test.com
  python parse_chrome_history.py --db History --search evil.com --output reports/chrome_hits.csv
        """
    )

    parser.add_argument('--db',     required=True, help='Path to Chrome History SQLite file')
    parser.add_argument('--search', default='',    help='URL/domain to search for (optional)')
    parser.add_argument('--output', default='',    help='Path to export results CSV (optional)')

    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[ERROR] Database file not found: {db_path}", file=sys.stderr)
        print("[HINT] Default path: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing Chrome History: {db_path}")

    # Get total count (without filter)
    all_results = parse_history(db_path, search_term='')
    total = len(all_results)

    # Get filtered results
    if args.search:
        filtered = parse_history(db_path, search_term=args.search)
    else:
        filtered = all_results

    print_report(filtered, args.search, total)

    if args.output:
        export_csv(filtered, Path(args.output))


if __name__ == '__main__':
    main()
