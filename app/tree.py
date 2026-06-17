"""
Host tree management — loads and parses hosts.yml into a navigable tree.
"""
import re
import threading
import yaml
from pathlib import Path

HOSTS_FILE = Path('/app/hosts.yml')
CONFIG_FILE = Path('/app/config.yml')

_tree_data = None
_default_interval = 60
_lock = threading.RLock()


def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    return slug.strip('-')


def _process_node(node: dict, parent_path: str, inherited_interval: int) -> dict:
    name = node['name']
    slug = _slugify(name)
    path = f"{parent_path}/{slug}" if parent_path else slug
    interval = node.get('ping_interval', inherited_interval)
    host = node.get('host')

    children = []
    if not host:
        for child in node.get('children', []):
            children.append(_process_node(child, path, interval))

    return {
        'name': name,
        'path': path,
        'ping_interval': interval,
        'host': host,
        'children': children,
    }


def load_tree() -> list:
    global _tree_data, _default_interval
    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)
    default_interval = config.get('default_ping_interval', 60)

    with open(HOSTS_FILE) as f:
        raw = yaml.safe_load(f)

    nodes = []
    for node in (raw or []):
        nodes.append(_process_node(node, '', default_interval))

    with _lock:
        _tree_data = nodes
        _default_interval = default_interval

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
