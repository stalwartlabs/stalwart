#!/usr/bin/env python3
"""
IMAP Log sanitizer - Extracts and groups IMAP transactions from log files
"""

# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL

import re
import json
from collections import defaultdict
from datetime import datetime
import argparse

def unescape_imap_content(content):

    if content.startswith('"') and content.endswith('"'):
        content = content[1:-1]

    replacements = {
        '\\r\\n': '\r\n',
        '\\n': '\n',
        '\\r': '\r',
        '\\t': '\t',
        '\\"': '"',
        '\\\\': '\\'
    }

    for escaped, unescaped in replacements.items():
        content = content.replace(escaped, unescaped)

    return content

def parse_imap_log_line(line):

    pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+TRACE\s+Raw IMAP\s+(input received|output sent)\s+.*?remoteIp\s*=\s*([^,]+),\s*remotePort\s*=\s*(\d+).*?contents\s*=\s*(.+)$'

    match = re.search(pattern, line)
    if not match:
        return None

    timestamp, direction, remote_ip, remote_port, contents = match.groups()

    return {
        'timestamp': timestamp,
        'direction': direction,
        'remote_ip': remote_ip.strip(),
        'remote_port': int(remote_port),
        'contents': unescape_imap_content(contents.strip()),
        'raw_line': line.strip()
    }

def group_by_connection(log_entries):

    connections = defaultdict(list)

    for entry in log_entries:
        if entry:
            key = f"{entry['remote_ip']}:{entry['remote_port']}"
            connections[key].append(entry)

    for key in connections:
        connections[key].sort(key=lambda x: x['timestamp'])

    return dict(connections)

def format_imap_transaction(entries):

    transaction = []

    for entry in entries:
        direction_symbol = "C: " if "input received" in entry['direction'] else "S: "
        timestamp = entry['timestamp']
        content = entry['contents']

        if content.endswith('\\r\\n') or content.endswith('\r\n'):
            content = content.rstrip('\\r\\n\r\n')

        transaction.append(f"[{timestamp}] {direction_symbol}{content}")

    return transaction

def write_output_file(connections, output_file):

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("IMAP Transaction Log Analysis\n")
        f.write("=" * 50 + "\n\n")

        for connection_key, entries in connections.items():
            f.write(f"Connection: {connection_key}\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total messages: {len(entries)}\n")
            f.write(f"Duration: {entries[0]['timestamp']} to {entries[-1]['timestamp']}\n\n")

            transaction = format_imap_transaction(entries)
            for line in transaction:
                f.write(line + "\n")

            f.write("\n" + "=" * 50 + "\n\n")

def main():
    parser = argparse.ArgumentParser(description='Parse IMAP log files and group transactions by connection')
    parser.add_argument('input_file', help='Input log file path')
    parser.add_argument('-o', '--output', default='imap_transactions.txt',
                       help='Output file path (default: imap_transactions.txt)')
    parser.add_argument('-j', '--json', action='store_true',
                       help='Also output raw data as JSON')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    if args.verbose:
        print(f"Reading log file: {args.input_file}")

    log_entries = []
    imap_line_count = 0

    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if 'Raw IMAP' in line:
                    imap_line_count += 1
                    parsed_entry = parse_imap_log_line(line)
                    if parsed_entry:
                        log_entries.append(parsed_entry)
                    elif args.verbose:
                        print(f"Warning: Could not parse line {line_num}: {line.strip()}")

    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found")
        return 1
    except Exception as e:
        print(f"Error reading file: {e}")
        return 1

    if args.verbose:
        print(f"Found {imap_line_count} Raw IMAP lines")
        print(f"Successfully parsed {len(log_entries)} entries")

    connections = group_by_connection(log_entries)

    if args.verbose:
        print(f"Found {len(connections)} unique connections:")
        for conn_key, entries in connections.items():
            print(f"  {conn_key}: {len(entries)} messages")

    try:
        write_output_file(connections, args.output)
        print(f"IMAP transactions written to: {args.output}")

        if args.json:
            json_file = args.output.rsplit('.', 1)[0] + '.json'
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(connections, f, indent=2, ensure_ascii=False)
            print(f"Raw data written to: {json_file}")

    except Exception as e:
        print(f"Error writing output: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
