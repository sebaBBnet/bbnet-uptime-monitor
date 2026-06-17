#!/usr/bin/env python3
"""
csv_to_hosts.py — Convert a CSV file to hosts.yml for Uptime Monitor

Usage:
    python csv_to_hosts.py hosts.csv              # overwrites hosts.yml
    python csv_to_hosts.py hosts.csv output.yml   # write to custom file

CSV columns:
    level1, level2, level3, ...   Hierarchy levels (add more columns for deeper nesting)
    name                          Display name of the host (required)
    host                          IP address or hostname (required)
    ping_interval                 Ping interval in seconds (optional)

Rules:
    - Leave level columns empty to place a host at a higher level
    - Add as many levelN columns as you need (level1, level2, level3, level4, ...)
    - Rows with empty name or host are skipped
    - Lines starting with # are treated as comments and skipped
"""

import csv
import sys
from collections import OrderedDict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)


def load_csv(csv_path: str) -> list:
    rows = []
    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        for line in f:
            if line.strip().startswith('#') or not line.strip():
                continue
            rows.append(line)

    reader = csv.DictReader(rows)
    result = []
    for row in reader:
        result.append({k.strip().lower(): v.strip() for k, v in row.items()})
    return result


def build_tree(rows: list) -> list:
    """Build a nested OrderedDict tree from CSV rows, then convert to list."""

    # Detect level columns in order: level1, level2, level3, ...
    if not rows:
        return []
    headers = list(rows[0].keys())
    level_cols = sorted(
        [h for h in headers if h.startswith('level') and h[5:].isdigit()],
        key=lambda x: int(x[5:])
    )

    if not level_cols:
        print("ERROR: No 'level1', 'level2', ... columns found in CSV.")
        sys.exit(1)

    # Use a list-based tree to preserve insertion order
    # Each node: {'name': str, 'host': str|None, 'ping_interval': int|None, 'children': []}
    root_children = []

    def find_or_create(children: list, name: str) -> dict:
        for node in children:
            if node['name'] == name and node['host'] is None:
                return node
        node = {'name': name, 'host': None, 'ping_interval': None, 'children': []}
        children.append(node)
        return node

    skipped = 0
    for i, row in enumerate(rows, start=2):  # start=2 accounts for header row
        name = row.get('name', '').strip()
        host = row.get('host', '').strip()
        ping_str = row.get('ping_interval', '').strip()

        if not name:
            skipped += 1
            continue
        if not host:
            print(f"  Warning: Row {i} ('{name}') has no host — skipped.")
            skipped += 1
            continue

        ping_interval = None
        if ping_str:
            try:
                ping_interval = int(ping_str)
            except ValueError:
                print(f"  Warning: Row {i} ('{name}') has invalid ping_interval '{ping_str}' — ignored.")

        # Build the path from level columns, stopping at the first empty value
        path = []
        for col in level_cols:
            val = row.get(col, '').strip()
            if val:
                path.append(val)
            # Stop at first empty level — all subsequent levels must also be empty
            # (a host can't be at level3 if level2 is empty)

        # Navigate/create the hierarchy
        current = root_children
        for level_name in path:
            parent = find_or_create(current, level_name)
            current = parent['children']

        # Add leaf node
        current.append({
            'name': name,
            'host': host,
            'ping_interval': ping_interval,
            'children': []
        })

    if skipped:
        print(f"  Skipped {skipped} row(s) with missing data.")

    return root_children


def tree_to_yaml_structure(nodes: list) -> list:
    """Convert internal tree to the clean structure expected by hosts.yml."""
    result = []
    for node in nodes:
        if node['host']:
            # Leaf node
            entry = {'name': node['name'], 'host': node['host']}
            if node['ping_interval']:
                entry['ping_interval'] = node['ping_interval']
            result.append(entry)
        else:
            # Group node
            entry = {'name': node['name']}
            if node['ping_interval']:
                entry['ping_interval'] = node['ping_interval']
            if node['children']:
                entry['children'] = tree_to_yaml_structure(node['children'])
            result.append(entry)
    return result


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    csv_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'hosts.yml'

    if not Path(csv_path).exists():
        print(f"ERROR: File not found: {csv_path}")
        sys.exit(1)

    print(f"Reading {csv_path} ...")
    rows = load_csv(csv_path)
    print(f"  Found {len(rows)} data rows.")

    tree = build_tree(rows)
    yaml_data = tree_to_yaml_structure(tree)

    # Count totals
    def count_hosts(nodes):
        total = 0
        for n in nodes:
            if n.get('host'):
                total += 1
            else:
                total += count_hosts(n.get('children', []))
        return total

    host_count = count_hosts(yaml_data)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("# Auto-generated by csv_to_hosts.py\n\n")
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"  Written {host_count} hosts to {out_path}")
    print("Done. Reload hosts in the UI or restart the container to apply.")


if __name__ == '__main__':
    main()
