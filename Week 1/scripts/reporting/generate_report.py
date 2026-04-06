import argparse
import csv
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


# ── CSV Loading ────────────────────────────────────────────────────────────────

REQUIRED_COLUMNS = ['Date/Time', 'Event ID', 'Description']

def load_events(csv_path: Path) -> list[dict]:
    """Load security events from CSV file."""
    if not csv_path.exists():
        print(f"[ERROR] CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    events = []
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)

        # Check required columns
        if reader.fieldnames is None:
            print("[ERROR] CSV file is empty or has no header row.", file=sys.stderr)
            sys.exit(1)

        missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
        if missing:
            print(f"[ERROR] CSV is missing required columns: {missing}", file=sys.stderr)
            print(f"        Found columns: {reader.fieldnames}", file=sys.stderr)
            sys.exit(1)

        for row in reader:
            if any(row.values()):  # Skip empty rows
                events.append(dict(row))

    return events


# ── Analysis ───────────────────────────────────────────────────────────────────

def analyze_events(events: list[dict]) -> dict:
    """Compute statistics from event list."""
    event_ids     = [e.get('Event ID', '').strip() for e in events if e.get('Event ID', '').strip()]
    source_ips    = [e.get('Source IP', '').strip() for e in events if e.get('Source IP', '').strip() not in ('', 'N/A', '-')]
    severities    = [e.get('Severity', 'N/A').strip() for e in events if e.get('Severity', '').strip()]
    actions_taken = [e.get('Action Taken', '').strip() for e in events if e.get('Action Taken', '').strip()]
    usernames     = [e.get('Username', '').strip() for e in events if e.get('Username', '').strip() not in ('', 'N/A', '-')]

    critical_events = [e for e in events if e.get('Severity', '').strip().upper() == 'CRITICAL']
    high_events     = [e for e in events if e.get('Severity', '').strip().upper() == 'HIGH']

    # Timestamps
    timestamps = []
    for e in events:
        ts_str = e.get('Date/Time', '').strip()
        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%m/%d/%Y %H:%M', '%d/%m/%Y %H:%M:%S']:
            try:
                timestamps.append(datetime.strptime(ts_str, fmt))
                break
            except ValueError:
                continue

    return {
        'total_events':    len(events),
        'unique_event_ids': list(dict.fromkeys(event_ids)),
        'top_event_ids':   Counter(event_ids).most_common(5),
        'unique_ips':      list(dict.fromkeys(source_ips)),
        'top_ips':         Counter(source_ips).most_common(5),
        'severity_counts': Counter(severities),
        'unique_users':    list(dict.fromkeys(usernames)),
        'critical_events': critical_events,
        'high_events':     high_events,
        'actions_taken':   list(dict.fromkeys(actions_taken)),
        'earliest':        min(timestamps).strftime('%Y-%m-%d %H:%M:%S') if timestamps else 'Unknown',
        'latest':          max(timestamps).strftime('%Y-%m-%d %H:%M:%S') if timestamps else 'Unknown',
    }


# ── Markdown Report Generation ─────────────────────────────────────────────────

def generate_markdown(events: list[dict], analysis: dict, title: str, analyst: str) -> str:
    """Generate a complete Markdown incident report."""

    now      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    severity = 'CRITICAL' if analysis['critical_events'] else \
               'HIGH'     if analysis['high_events']     else 'MEDIUM'

    sev_badge = {
        'CRITICAL': ' CRITICAL',
        'HIGH':     ' HIGH',
        'MEDIUM':   ' MEDIUM',
        'LOW':      ' LOW',
    }.get(severity, severity)

    lines = []

    # ── Header ──────────────────────────────────────────────────
    lines += [
        f"#  Incident Report — {title}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Report Date** | {now} |",
        f"| **Lab Period** | 05 March 2026 – 13 March 2026 |",
        f"| **Analyst** | {analyst} |",
        f"| **Overall Severity** | {sev_badge} |",
        f"| **Total Events** | {analysis['total_events']} |",
        f"| **Time Range** | {analysis['earliest']} → {analysis['latest']} |",
        "",
    ]

    # ── Executive Summary ────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
    ]

    if analysis['critical_events']:
        first_critical = analysis['critical_events'][0]
        lines.append(
            f"A **CRITICAL severity** security incident was detected. "
            f"{analysis['total_events']} events were logged between "
            f"{analysis['earliest']} and {analysis['latest']}. "
            f"The most severe event was: *{first_critical.get('Description', 'N/A')}*. "
            f"Immediate action was required and has been taken."
        )
    else:
        lines.append(
            f"A security investigation identified {analysis['total_events']} events "
            f"between {analysis['earliest']} and {analysis['latest']}. "
            f"Events were reviewed and documented per standard procedure."
        )

    lines += ["", "---", ""]

    # ── Event Summary Statistics ─────────────────────────────────
    lines += [
        "## Event Summary Statistics",
        "",
        "### Events by Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = analysis['severity_counts'].get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")

    lines += [
        "",
        "### Top Event IDs",
        "",
        "| Event ID | Occurrences | Description |",
        "|----------|-------------|-------------|",
    ]

    event_id_descriptions = {
        '4625': 'Failed login attempt',
        '4624': 'Successful logon',
        '4648': 'Logon with explicit credentials',
        '4720': 'New user account created',
        '4732': 'User added to security group',
        '7045': 'New service installed',
    }

    for eid, count in analysis['top_event_ids']:
        desc = event_id_descriptions.get(eid, 'See event log for details')
        lines.append(f"| {eid} | {count} | {desc} |")

    lines += ["", "---", ""]

    # ── Timeline ─────────────────────────────────────────────────
    lines += [
        "## Timeline of Events",
        "",
        "| Date/Time | Event ID | Source IP | Description | Severity |",
        "|-----------|----------|-----------|-------------|----------|",
    ]

    for e in events:
        dt      = e.get('Date/Time', '').strip()
        eid     = e.get('Event ID', '').strip()
        src_ip  = e.get('Source IP', 'N/A').strip()
        desc    = e.get('Description', '').strip().replace('|', '\\|')
        sev_e   = e.get('Severity', 'N/A').strip()
        lines.append(f"| {dt} | {eid} | {src_ip} | {desc} | {sev_e} |")

    lines += ["", "---", ""]

    # ── Indicators of Compromise ──────────────────────────────────
    lines += [
        "## Indicators of Compromise (IOCs)",
        "",
    ]

    if analysis['unique_ips']:
        lines += ["### Suspicious IP Addresses", ""]
        for ip in analysis['unique_ips']:
            lines.append(f"- `{ip}`")
        lines.append("")

    if analysis['unique_users']:
        lines += ["### Targeted Usernames", ""]
        for user in analysis['unique_users']:
            lines.append(f"- `{user}`")
        lines.append("")

    if analysis['unique_event_ids']:
        lines += ["### Event IDs Observed", ""]
        for eid in analysis['unique_event_ids']:
            lines.append(f"- Event ID `{eid}`")
        lines.append("")

    lines += ["---", ""]

    # ── Actions Taken ─────────────────────────────────────────────
    lines += [
        "## Actions Taken",
        "",
    ]
    if analysis['actions_taken']:
        for i, action in enumerate(analysis['actions_taken'], 1):
            if action and action.strip() not in ('', 'N/A', '-'):
                lines.append(f"{i}. {action}")
    else:
        lines.append("_No actions documented. Update the CSV `Action Taken` column._")

    lines += ["", "---", ""]

    # ── Recommendations ───────────────────────────────────────────
    lines += [
        "## Recommendations",
        "",
    ]

    recommendations = []

    if any(eid in analysis['unique_event_ids'] for eid in ['4625']):
        recommendations += [
            "Implement account lockout policy (lock after 5 failed attempts in 10 minutes).",
            "Enable multi-factor authentication (MFA) for all privileged accounts.",
            "Block suspicious source IPs at the perimeter firewall.",
            "Consider disabling direct `Administrator` account network logons.",
        ]

    if '7045' in analysis['unique_event_ids']:
        recommendations += [
            "Audit all recently installed services and verify against approved software list.",
            "Restrict service installation privileges to administrators only.",
            "Deploy application whitelisting to prevent unauthorized service binaries.",
        ]

    if not recommendations:
        recommendations = [
            "Continue monitoring Security and System event logs daily.",
            "Ensure audit policies are configured to log all logon events.",
            "Review and update incident response procedures.",
        ]

    for i, rec in enumerate(recommendations, 1):
        lines.append(f"{i}. {rec}")

    lines += ["", "---", ""]

    # ── Footer ────────────────────────────────────────────────────
    lines += [
        "## Report Metadata",
        "",
        f"- **Generated by:** Cybersecurity Log Analysis Lab — automated report generator",
        f"- **Report date:** {now}",
        f"- **Lab period:** 05 March 2026 – 13 March 2026",
        f"- **Analyst:** {analyst}",
        f"- **Source data:** Security Event Log (Windows) + Browser History",
        "",
        "> This report was generated as part of a cybersecurity training lab.",
        "> All events documented are from a controlled Windows VM environment.",
    ]

    return "\n".join(lines)


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Generate a Markdown incident report from a security event CSV.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_report.py
  python generate_report.py --csv templates/security_event_template.csv
  python generate_report.py --csv events.csv --output reports/report.md --title "RDP Attack"
        """
    )

    parser.add_argument('--csv',     default='templates/security_event_template.csv',
                        help='Path to security event CSV (default: templates/security_event_template.csv)')
    parser.add_argument('--output',  default='reports/incident_report.md',
                        help='Output Markdown report path (default: reports/incident_report.md)')
    parser.add_argument('--title',   default='Security Incident Investigation',
                        help='Report title')
    parser.add_argument('--analyst', default='Lab Analyst',
                        help='Analyst name to include in report')

    args = parser.parse_args()

    csv_path    = Path(args.csv)
    output_path = Path(args.output)

    print(f"[*] Loading events from: {csv_path}")
    events = load_events(csv_path)
    print(f"[OK] Loaded {len(events)} events.")

    analysis = analyze_events(events)

    print(f"[*] Generating report: '{args.title}'")
    markdown = generate_markdown(events, analysis, args.title, args.analyst)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding='utf-8')

    print(f"[OK] Report saved to: {output_path}")
    print(f"\n  Events analyzed  : {analysis['total_events']}")
    print(f"  Unique IPs found : {len(analysis['unique_ips'])}")
    print(f"  Time range       : {analysis['earliest']} → {analysis['latest']}")
    print(f"  Overall severity : {'CRITICAL' if analysis['critical_events'] else 'HIGH' if analysis['high_events'] else 'MEDIUM'}")


if __name__ == '__main__':
    main()
