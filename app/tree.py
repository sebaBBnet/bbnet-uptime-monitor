"""
Host tree management — parses Xymon-compatible hosts.cfg format.

File format:
  page <slug> <Display Name>        — top-level page
  subpage <slug> <Display Name>     — sub-page under the current page
  subsubpage <slug> <Display Name>  — sub-sub-page under the current subpage
  include <filename>                — include another file (relative to hosts.cfg location)
  IP HOSTNAME # flags               — active host entry (ICMP-pinged)
  # anything                        — comment / disabled host (always skipped)

Hierarchy rules:
  - Hosts go under the deepest active context: subsubpage > subpage > page.
  - A new 'page' resets subpage and subsubpage context.
  - A new 'subpage' resets subsubpage context.
"""

import re
import threading
import yaml
from pathlib import Path

HOSTS_FILE = Path('/app/hostsconf/hosts.cfg')
CONFIG_FILE = Path('/app/config.yml')

_tree_data = None
_default_interval = 60
_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    return slug.strip('-')


def _parse_flags(comment: str) -> dict:
    """Parse 'key=value' pairs from a host-line comment string (after the #)."""
    flags = {}
    for m in re.finditer(r'([\w][\w-]*)=([\S]+)', comment):
        flags[m.group(1)] = m.group(2)
    return flags


def _unique_path(parent: dict, candidate: str) -> str:
    """Return candidate path, appending a suffix if it already exists among siblings."""
    existing = {c['path'] for c in parent['children']}
    if candidate not in existing:
        return candidate
    i = 2
    while f"{candidate}-{i}" in existing:
        i += 1
    return f"{candidate}-{i}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_file(filepath: Path, default_interval: int) -> list:
    """
    Parse a hosts.cfg file and return a list of top-level page nodes.
    Handles 'include' directives by recursively parsing the named file.
    """
    try:
        text = filepath.read_text(encoding='utf-8', errors='replace')
    except FileNotFoundError:
        print(f"[tree] WARNING: hosts file not found: {filepath}")
        return []

    base_dir = filepath.parent
    nodes = []          # top-level page nodes produced by this file
    current_page    = None
    current_subpage = None
    current_subsubpage = None

    for raw in text.splitlines():
        line = raw.strip()

        # Skip blank lines and any line starting with # (comments + disabled hosts)
        if not line or line.startswith('#'):
            continue

        # ── include ────────────────────────────────────────────────────────
        if re.match(r'^include\s+', line, re.IGNORECASE):
            inc_name = line.split(None, 1)[1].strip()
            inc_path = base_dir / inc_name
            inc_nodes = _parse_file(inc_path, default_interval)
            nodes.extend(inc_nodes)
            # After returning from an included file, reset context so the next
            # 'page' in the main file starts fresh.
            current_page       = None
            current_subpage    = None
            current_subsubpage = None
            continue

        # ── page ───────────────────────────────────────────────────────────
        m = re.match(r'^page\s+(\S+)\s+(.+)$', line, re.IGNORECASE)
        if m:
            slug, display = m.group(1), m.group(2).strip()
            current_page       = _make_node(display, slug, slug, None, default_interval)
            current_subpage    = None
            current_subsubpage = None
            nodes.append(current_page)
            continue

        # ── subpage ────────────────────────────────────────────────────────
        m = re.match(r'^subpage\s+(\S+)\s+(.+)$', line, re.IGNORECASE)
        if m:
            slug, display = m.group(1), m.group(2).strip()
            if current_page is None:
                current_page = _make_node('Default', 'default', 'default', None, default_interval)
                nodes.append(current_page)
            path = f"{current_page['path']}/{slug}"
            current_subpage    = _make_node(display, slug, path, None, default_interval)
            current_subsubpage = None
            current_page['children'].append(current_subpage)
            continue

        # ── subsubpage ─────────────────────────────────────────────────────
        m = re.match(r'^subsubpage\s+(\S+)\s+(.+)$', line, re.IGNORECASE)
        if m:
            slug, display = m.group(1), m.group(2).strip()
            if current_subpage is None:
                # No parent subpage — treat as a regular subpage
                if current_page is None:
                    current_page = _make_node('Default', 'default', 'default', None, default_interval)
                    nodes.append(current_page)
                path = f"{current_page['path']}/{slug}"
                current_subpage = _make_node(display, slug, path, None, default_interval)
                current_page['children'].append(current_subpage)
            else:
                path = f"{current_subpage['path']}/{slug}"
                current_subsubpage = _make_node(display, slug, path, None, default_interval)
                current_subpage['children'].append(current_subsubpage)
            continue

        # ── skip other Xymon directives ────────────────────────────────────
        if re.match(r'^(title|group|NAME:|subparent)\b', line, re.IGNORECASE):
            continue

        # ── kuma line: kuma HOSTNAME # kuma-id=N ──────────────────────────
        m = re.match(r'^kuma\s+(\S+)(.*)', line, re.IGNORECASE)
        if m:
            hostname = m.group(1)
            flags    = _parse_flags(m.group(2))
            kuma_id_str = flags.get('kuma-id')
            if not kuma_id_str or not kuma_id_str.isdigit():
                print(f"[tree] WARNING: kuma host '{hostname}' has no valid kuma-id — skipping")
                continue
            parent = current_subsubpage if current_subsubpage is not None \
                else current_subpage if current_subpage is not None \
                else current_page
            if parent is None:
                continue
            host_slug = _slugify(hostname)
            candidate = f"{parent['path']}/{host_slug}"
            path = _unique_path(parent, candidate)
            node = _make_node(hostname, host_slug, path, 'kuma', default_interval,
                              kuma_id=int(kuma_id_str))
            parent['children'].append(node)
            continue

        # ── host line: IP HOSTNAME [# flags] ──────────────────────────────
        m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)', line)
        if m:
            ip, hostname = m.group(1), m.group(2)
            parent = current_subsubpage if current_subsubpage is not None \
                else current_subpage if current_subpage is not None \
                else current_page
            if parent is None:
                # Host with no page context — skip silently
                continue

            host_slug = _slugify(hostname)
            candidate = f"{parent['path']}/{host_slug}"
            path = _unique_path(parent, candidate)

            node = _make_node(hostname, host_slug, path, ip, default_interval)
            parent['children'].append(node)
            continue

        # Everything else (empty after strip, unknown directives) is ignored.

    return nodes


def _make_node(name: str, slug: str, path: str, host, interval: int,
               kuma_id: int = None) -> dict:
    return {
        'name':         name,
        'slug':         slug,
        'path':         path,
        'host':         host,       # IP string | 'kuma' | None (groups)
        'ping_interval': interval,
        'children':     [],
        'kuma_id':      kuma_id,    # int if this is a Kuma monitor, else None
    }


# ---------------------------------------------------------------------------
# Public API  (same interface as the old YAML-based tree.py)
# ---------------------------------------------------------------------------

def load_tree() -> list:
    global _tree_data, _default_interval

    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)
    default_interval = config.get('default_ping_interval', 60)

    nodes = _parse_file(HOSTS_FILE, default_interval)

    with _lock:
        _tree_data = nodes
        _default_interval = default_interval

    leaf_count = len(get_all_leaves(nodes))
    print(f"[tree] Loaded {len(nodes)} top-level pages, {leaf_count} hosts total.")
    return nodes


def get_tree() -> list:
    with _lock:
        return _tree_data or []


def find_node(path: str, nodes: list = None) -> dict:
    if nodes is None:
        nodes = get_tree()
    for node in nodes:
        if node['path'] == path:
            return node
        found = find_node(path, node['children'])
        if found:
            return found
    return None


def get_children(path: str = None) -> list:
    """Return direct children of the node at `path`, or root nodes if path is None/empty."""
    if not path:
        return get_tree()
    node = find_node(path)
    return node['children'] if node else []


def get_all_leaves(nodes: list = None) -> list:
    """Recursively collect all leaf nodes (those with a host IP) in the subtree."""
    if nodes is None:
        nodes = get_tree()
    leaves = []
    for node in nodes:
        if node['host']:
            leaves.append(node)
        else:
            leaves.extend(get_all_leaves(node['children']))
    return leaves


def get_leaves_under(path: str) -> list:
    """All leaf nodes that are descendants of the node at `path`."""
    if not path:
        return get_all_leaves()
    node = find_node(path)
    if not node:
        return []
    if node['host']:
        return [node]
    return get_all_leaves(node['children'])


def build_breadcrumb(path: str) -> list:
    crumbs = [{'name': 'All', 'path': ''}]
    if not path:
        return crumbs
    parts = path.split('/')
    for i in range(len(parts)):
        current = '/'.join(parts[:i + 1])
        node = find_node(current)
        crumbs.append({'name': node['name'] if node else parts[i], 'path': current})
    return crumbs
