import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────────────────

NAMESPACE = {
    'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'
}

STATUS_CODES = {
    '0xC000006D': 'Bad username or password',
    '0xC000006A': 'Wrong password (user exists)',
    '0xC0000064': 'Username does not exist',
    '0xC0000234': 'Account locked out',
    '0xC0000072': 'Account disabled',
    '0xC000015B': 'User not granted logon type',
}

LOGON_TYPES = {
    '2':  'Interactive (local keyboard)',
    '3':  'Network',
    '4':  'Batch',
    '5':  'Service',
    '7':  'Unlock',
    '8':  'NetworkCleartext',
    '9':  'NewCredentials',
    '10': 'RemoteInteractive (RDP)',
    '11': 'CachedInteractive',
}


# ── XML Parsing ────────────────────────────────────────────────────────────────

def parse_event_xml(xml_path: Path) -> list[dict]:
    """Parse Windows Event XML export and return list of event dicts."""
    events = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[ERROR] Could not parse XML file: {e}", file=sys.stderr)
        sys.exit(1)

    # Handle both single <Event> root and <Events> wrapper
    if root.tag.endswith('Events'):
        event_nodes = root.findall('.//ns:Event', NAMESPACE)
    elif root.tag.endswith('Event'):
        event_nodes = [root]
    else:
        event_nodes = root.findall('.//ns:Event', NAMESPACE)

    for node in event_nodes:
        event = extract_event_fields(node)
        if event:
            events.append(event)

    return events


def extract_event_fields(node: ET.Element) -> dict | None:
    """Extract fields from a single <Event> XML node."""
    try:
        # System fields
        system = node.find('ns:System', NAMESPACE)
        event_id_node = system.find('ns:EventID', NAMESPACE)
        time_node     = system.find('ns:TimeCreated', NAMESPACE)
        computer_node = system.find('ns:Computer', NAMESPACE)

        event_id = event_id_node.text if event_id_node is not None else 'Unknown'
        time_str = time_node.get('SystemTime', '') if time_node is not None else ''
        computer = computer_node.text if computer_node is not None else 'Unknown'

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            ts = None

        # EventData fields
        event_data = node.find('ns:EventData', NAMESPACE)
        data_fields = {}
        if event_data is not None:
            for data in event_data.findall('ns:Data', NAMESPACE):
                name = data.get('Name', '')
                value = data.text or ''
                data_fields[name] = value

        logon_type_num  = data_fields.get('LogonType', '')
        logon_type_name = LOGON_TYPES.get(logon_type_num, f'Unknown ({logon_type_num})')
        status_code     = data_fields.get('Status', '')
        status_desc     = STATUS_CODES.get(status_code, status_code)

        return {
            'event_id':       event_id,
            'timestamp':      ts,
            'timestamp_str':  ts.strftime('%Y-%m-%d %H:%M:%S') if ts else time_str,
            'computer':       computer,
            'target_user':    data_fields.get('TargetUserName', '-'),
            'target_domain':  data_fields.get('TargetDomainName', '-'),
            'source_ip':      data_fields.get('IpAddress', '-'),
            'source_port':    data_fields.get('IpPort', '-'),
            'logon_type':     logon_type_name,
            'status':         status_code,
            'status_desc':    status_desc,
            'workstation':    data_fields.get('WorkstationName', '-'),
        }

    except Exception as e:
        print(f"[WARN] Skipping malformed event node: {e}", file=sys.stderr)
        return None


# ── Analysis ───────────────────────────────────────────────────────────────────

def analyze_events(events: list[dict], threshold: int) -> dict:
    """Analyze events for brute-force patterns."""
    by_ip       = defaultdict(list)
    by_username = defaultdict(list)

    for e in events:
        ip   = e['source_ip']
        user = e['target_user']
        if ip and ip not in ('-', '', '::1', '127.0.0.1'):
            by_ip[ip].append(e)
        if user and user not in ('-', ''):
            by_username[user].append(e)

    # Find suspicious IPs
    suspicious_ips = {
        ip: attempts for ip, attempts in by_ip.items()
        if len(attempts) >= threshold
    }

    return {
        'total_events':    len(events),
        'unique_ips':      len(by_ip),
        'unique_users':    len(by_username),
        'by_ip':           by_ip,
        'by_username':     by_username,
        'suspicious_ips':  suspicious_ips,
    }


# ── Report Output ──────────────────────────────────────────────────────────────

def print_report(events: list[dict], analysis: dict, threshold: int) -> None:
    """Print analysis report to stdout."""
    sep = "=" * 62

    print(f"\n{sep}")
    print("  BRUTE-FORCE DETECTION REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep)

    print(f"\n[*] Summary")
    print(f"    Total Event ID 4625 entries : {analysis['total_events']}")
    print(f"    Unique source IPs           : {analysis['unique_ips']}")
    print(f"    Unique target usernames     : {analysis['unique_users']}")
    print(f"    Detection threshold         : {threshold} attempts")

    # Time range
    timestamps = [e['timestamp'] for e in events if e['timestamp']]
    if timestamps:
        print(f"    Earliest event              : {min(timestamps).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Latest event                : {max(timestamps).strftime('%Y-%m-%d %H:%M:%S')}")

    # IP summary
    print(f"\n[*] Source IPs — Sorted by Attempt Count")
    print(f"    {'Source IP':<20} {'Attempts':>8}  {'Flag'}")
    print(f"    {'-'*20} {'-'*8}  {'-'*10}")
    for ip, attempts in sorted(analysis['by_ip'].items(), key=lambda x: -len(x[1])):
        flag = "⚠️  SUSPICIOUS" if len(attempts) >= threshold else "   OK"
        print(f"    {ip:<20} {len(attempts):>8}  {flag}")

    # Username summary
    print(f"\n[*] Targeted Usernames — Sorted by Attempt Count")
    print(f"    {'Username':<25} {'Attempts':>8}")
    print(f"    {'-'*25} {'-'*8}")
    for user, attempts in sorted(analysis['by_username'].items(), key=lambda x: -len(x[1])):
        print(f"    {user:<25} {len(attempts):>8}")

    # Brute-force alerts
    print(f"\n{'=' * 62}")
    if analysis['suspicious_ips']:
        print(f"  ⚠️  BRUTE-FORCE ALERTS ({len(analysis['suspicious_ips'])} IP(s) flagged)")
        print("=" * 62)
        for ip, attempts in analysis['suspicious_ips'].items():
            sorted_attempts = sorted(attempts, key=lambda x: x['timestamp'] or datetime.min)
            users = list({a['target_user'] for a in attempts})
            first_time = sorted_attempts[0]['timestamp_str'] if sorted_attempts else 'Unknown'
            last_time  = sorted_attempts[-1]['timestamp_str'] if sorted_attempts else 'Unknown'

            print(f"\n  Source IP  : {ip}")
            print(f"  Attempts   : {len(attempts)}")
            print(f"  Targets    : {', '.join(users)}")
            print(f"  First seen : {first_time}")
            print(f"  Last seen  : {last_time}")
            print(f"  Logon type : {attempts[0]['logon_type']}")
            print(f"  Recommended: Block {ip} at firewall")
    else:
        print(f"  ✅ No IPs exceeded the threshold of {threshold} attempts.")
        print("=" * 62)

    print()


def export_csv(events: list[dict], output_path: Path) -> None:
    """Export parsed events to CSV file."""
    if not events:
        print(f"[INFO] No events to export.")
        return

    fields = [
        'timestamp_str', 'event_id', 'computer', 'target_user',
        'target_domain', 'source_ip', 'source_port', 'logon_type',
        'status', 'status_desc', 'workstation'
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(events)

    print(f"[OK] Exported {len(events)} events to: {output_path}")


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Windows Event ID 4625 XML exports for brute-force attacks.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python brute_force_detector.py --log logs/sample/sample_events_4625.xml
  python brute_force_detector.py --log events.xml --threshold 5
  python brute_force_detector.py --log events.xml --output reports/bf_report.csv
        """
    )

    parser.add_argument('--log',       required=True,  help='Path to Event ID 4625 XML export')
    parser.add_argument('--threshold', type=int, default=3, help='Min attempts to flag as suspicious (default: 3)')
    parser.add_argument('--output',    default='',     help='Path to export results CSV (optional)')

    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing: {log_path}")
    events = parse_event_xml(log_path)
    print(f"[OK] Parsed {len(events)} events.")

    analysis = analyze_events(events, args.threshold)
    print_report(events, analysis, args.threshold)

    if args.output:
        export_csv(events, Path(args.output))


if __name__ == '__main__':
    main()
