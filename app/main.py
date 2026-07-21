"""
Uptime Monitor — Flask web application.
"""
import json
import os
import re
import secrets
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

import yaml
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import alerter
import database
import kuma_poller as kuma_module
import pinger as pinger_module
import tree as tree_mgr

# Set by wsgi.py / __main__ if kuma is configured
kuma_poller = None

CONFIG_FILE = Path('/app/config.yml')

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

config = load_config()

# ---------------------------------------------------------------------------
# Rate limiting — in-memory, per IP
# ---------------------------------------------------------------------------

_LOCKOUT_ATTEMPTS = 5
_LOCKOUT_SECONDS  = 86400  # 24 hours

# {ip: {'count': int, 'locked_until': float}}
_login_attempts: dict = {}


def _client_ip() -> str:
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


def _is_locked(ip: str) -> bool:
    entry = _login_attempts.get(ip)
    if not entry:
        return False
    if entry.get('locked_until', 0) > time.time():
        return True
    # Lockout expired — clear it
    _login_attempts.pop(ip, None)
    return False


def _record_failure(ip: str):
    entry = _login_attempts.setdefault(ip, {'count': 0, 'locked_until': 0})
    entry['count'] += 1
    if entry['count'] >= _LOCKOUT_ATTEMPTS:
        entry['locked_until'] = time.time() + _LOCKOUT_SECONDS


def _clear_failures(ip: str):
    _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Flask app setup
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['X-XSS-Protection']          = '1; mode=block'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy']   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


# Secret key — persisted in DB so sessions survive container restarts
def get_secret_key():
    if config.get('secret_key', 'auto') != 'auto':
        return config['secret_key']
    key = database.get_kv('secret_key')
    if not key:
        key = secrets.token_hex(32)
        database.set_kv('secret_key', key)
    return key

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def csrf_required(f):
    """Validate CSRF token on state-changing POST requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (
            request.headers.get('X-CSRF-Token')
            or request.form.get('csrf_token')
        )
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated


LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Uptime Monitor — Login</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0f1117;
    color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2.5rem;
    width: 100%;
    max-width: 380px;
  }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; color: #fff; }
  p { color: #718096; font-size: 0.875rem; margin-bottom: 2rem; }
  label { display: block; font-size: 0.8rem; color: #a0aec0; margin-bottom: 0.4rem; }
  input[type=password] {
    width: 100%;
    padding: 0.65rem 0.9rem;
    background: #0f1117;
    border: 1px solid #2d3748;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: 1rem;
    margin-bottom: 1.25rem;
    outline: none;
    transition: border-color .2s;
  }
  input[type=password]:focus { border-color: #4299e1; }
  button {
    width: 100%;
    padding: 0.7rem;
    background: #3182ce;
    border: none;
    border-radius: 8px;
    color: #fff;
    font-size: 1rem;
    cursor: pointer;
    transition: background .2s;
  }
  button:hover { background: #2b6cb0; }
  .error {
    background: #742a2a;
    border: 1px solid #fc8181;
    border-radius: 6px;
    padding: 0.6rem 0.9rem;
    font-size: 0.875rem;
    margin-bottom: 1rem;
    color: #fed7d7;
  }
  .icon { font-size: 2rem; margin-bottom: 1rem; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">📡</div>
  <h1>Uptime Monitor</h1>
  <p>Enter your password to continue</p>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autofocus placeholder="••••••••">
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>"""

STATUS_PASSWORD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — Status</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f1117; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px;
          padding: 2.5rem; width: 100%; max-width: 360px; }
  .icon { font-size: 2rem; margin-bottom: 1rem; }
  h1 { font-size: 1.3rem; margin-bottom: .25rem; color: #fff; }
  p { color: #718096; font-size: .875rem; margin-bottom: 1.5rem; }
  input { width: 100%; padding: .6rem .9rem; background: #0f1117; border: 1px solid #2d3748;
          border-radius: 8px; color: #e2e8f0; font-size: 1rem; margin-bottom: 1rem; outline: none; }
  input:focus { border-color: #4299e1; }
  button { width: 100%; padding: .65rem; background: #3182ce; border: none;
           border-radius: 8px; color: #fff; font-size: 1rem; cursor: pointer; }
  button:hover { background: #2b6cb0; }
  .err { background: #742a2a; border: 1px solid #fc8181; border-radius: 6px;
         padding: .5rem .9rem; font-size: .875rem; margin-bottom: 1rem; color: #fed7d7; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">📊</div>
  <h1>{{ title }}</h1>
  <p>This status page is password protected.</p>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="post">
    <input type="password" name="password" autofocus placeholder="Enter password">
    <button type="submit">View status page</button>
  </form>
</div>
</body>
</html>"""


def _build_status_group(node: dict, latest_batch: dict, paused_set: set) -> dict:
    """Recursively build a status group for the status page data API."""
    if node.get('host'):
        is_paused = node['path'] in paused_set
        row = latest_batch.get(node['path'])
        is_up = bool(row['is_up']) if (row and not is_paused) else None
        return {
            'name':       node['name'],
            'path':       node['path'],
            'is_leaf':    True,
            'is_up':      is_up,
            'is_paused':  is_paused,
            'latency_ms': row['latency_ms'] if row else None,
            'last_check': row['timestamp']  if row else None,
            'host_count': 0 if is_paused else 1,
            'up_count':   (1 if is_up else 0) if (is_up is not None and not is_paused) else 0,
            'down_count': (0 if is_up else 1) if (is_up is not None and not is_paused) else 0,
        }
    else:
        children = [_build_status_group(c, latest_batch, paused_set) for c in node.get('children', [])]
        host_count = sum(c['host_count'] for c in children)
        up_count   = sum(c['up_count']   for c in children)
        return {
            'name':       node['name'],
            'path':       node['path'],
            'is_leaf':    False,
            'children':   children,
            'host_count': host_count,
            'up_count':   up_count,
            'down_count': host_count - up_count,
        }


def _node_included(path: str, included: list) -> str:
    """Return 'full', 'partial', or 'none' for `path` given a list of selected paths."""
    if not included:
        return 'full'
    for sel in included:
        if path == sel or path.startswith(sel + '/'):
            return 'full'
        if sel.startswith(path + '/'):
            return 'partial'
    return 'none'


def _build_status_group_filtered(node: dict, latest_batch: dict, paused_set: set, included: list) -> dict:
    """Like _build_status_group but restricts to paths in `included` (at any depth)."""
    inclusion = _node_included(node['path'], included)
    if inclusion == 'none':
        return None
    if inclusion == 'full' or node.get('host'):
        return _build_status_group(node, latest_batch, paused_set)
    # Partial match: recurse into children and filter
    children = [
        _build_status_group_filtered(c, latest_batch, paused_set, included)
        for c in node.get('children', [])
    ]
    children = [c for c in children if c]
    if not children:
        return None
    hc = sum(c['host_count'] for c in children)
    uc = sum(c['up_count']   for c in children)
    return {
        'name':       node['name'],
        'path':       node['path'],
        'is_leaf':    False,
        'children':   children,
        'host_count': hc,
        'up_count':   uc,
        'down_count': hc - uc,
    }


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = _client_ip()
    if request.method == 'POST':
        if _is_locked(ip):
            return render_template_string(LOGIN_HTML,
                error='Too many failed attempts. Try again in 24 hours.')
        if request.form.get('password') == config['password']:
            _clear_failures(ip)
            session.permanent = True
            session['authenticated'] = True
            session['csrf_token'] = secrets.token_hex(32)
            return redirect(url_for('index'))
        _record_failure(ip)
        remaining = _LOCKOUT_ATTEMPTS - _login_attempts.get(ip, {}).get('count', 0)
        if remaining <= 0:
            return render_template_string(LOGIN_HTML,
                error='Too many failed attempts. Account locked for 24 hours.')
        return render_template_string(LOGIN_HTML,
            error=f'Incorrect password. {remaining} attempt(s) remaining.')
    if _is_locked(ip):
        return render_template_string(LOGIN_HTML,
            error='Too many failed attempts. Try again in 24 hours.')
    return render_template_string(LOGIN_HTML, error=None)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Routes — Main UI
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return app.send_static_file('index.html')


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

def _node_stats(node: dict, latest_batch: dict, paused_set: set = None, leaves: list = None) -> dict:
    """Build the stats dict for a single node (leaf or group). Uptime excluded — use /api/node/uptime."""
    if paused_set is None:
        paused_set = set()

    if node['host']:
        is_paused  = node['path'] in paused_set
        row        = latest_batch.get(node['path'])
        is_up      = bool(row['is_up']) if (row and not is_paused) else None
        return {
            'name':         node['name'],
            'path':         node['path'],
            'is_leaf':      True,
            'host':         node['host'],
            'ping_interval':node['ping_interval'],
            'is_up':        is_up,
            'is_paused':    is_paused,
            'latency_ms':   row['latency_ms'] if row else None,
            'last_check':   row['timestamp']  if row else None,
            'host_count':   0 if is_paused else 1,
            'up_count':     (1 if is_up else 0) if is_up is not None else 0,
            'down_count':   (0 if is_up else 1) if is_up is not None else 0,
            'paused_count': 1 if is_paused else 0,
        }
    else:
        if leaves is None:
            leaves = tree_mgr.get_all_leaves(node['children'])
        active_leaves = [l for l in leaves if l['path'] not in paused_set]
        paused_count  = len(leaves) - len(active_leaves)
        active_paths  = [l['path'] for l in active_leaves]
        host_count    = len(active_leaves)
        up_count      = sum(1 for p in active_paths if latest_batch.get(p) and latest_batch[p]['is_up'])
        return {
            'name':         node['name'],
            'path':         node['path'],
            'is_leaf':      False,
            'host_count':   host_count,
            'up_count':     up_count,
            'down_count':   host_count - up_count,
            'paused_count': paused_count,
        }


@app.route('/api/node')
@login_required
def api_node():
    path = request.args.get('path', '').strip('/')

    children = tree_mgr.get_children(path)
    if children is None and path:
        return jsonify({'error': 'Not found'}), 404

    # Pre-fetch all latest ping results for leaves in this subtree
    all_leaves = tree_mgr.get_leaves_under(path) if path else tree_mgr.get_all_leaves()
    leaf_paths = [l['path'] for l in all_leaves]
    latest_batch = database.get_latest_results_batch(leaf_paths)
    paused_set = database.get_all_paused()

    items = []
    for child in (children or []):
        child_leaves = tree_mgr.get_all_leaves(child['children']) if not child['host'] else [child]
        items.append(_node_stats(child, latest_batch, paused_set, child_leaves if not child['host'] else None))

    return jsonify({
        'breadcrumb': tree_mgr.build_breadcrumb(path),
        'current_path': path,
        'items': items,
    })


@app.route('/api/csrf-token')
@login_required
def api_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({'csrf_token': session['csrf_token']})


@app.route('/api/node/uptime')
@login_required
def api_node_uptime():
    """
    Returns uptime percentages for all children of `path`.
    Separated from /api/node so the tile view can render status instantly
    and fill in uptime badges asynchronously.
    """
    path      = request.args.get('path', '').strip('/')
    children  = tree_mgr.get_children(path)
    paused_set = database.get_all_paused()

    result = {}
    for child in (children or []):
        if child['host']:
            result[child['path']] = {
                'uptime_24h': database.get_uptime(child['path'], 24),
                'uptime_7d':  database.get_uptime(child['path'], 168),
                'uptime_30d': database.get_uptime(child['path'], 720),
            }
        else:
            leaves = tree_mgr.get_all_leaves(child['children'])
            active = [l['path'] for l in leaves if l['path'] not in paused_set]
            result[child['path']] = {
                'uptime_24h': database.get_uptime_multi(active, 24)  if active else None,
                'uptime_7d':  database.get_uptime_multi(active, 168) if active else None,
                'uptime_30d': database.get_uptime_multi(active, 720) if active else None,
            }

    return jsonify({'uptime': result})


@app.route('/api/reload', methods=['POST'])
@login_required
@csrf_required
def api_reload():
    try:
        tree_mgr.load_tree()
        return jsonify({'status': 'ok', 'message': 'Hosts reloaded successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/summary')
@login_required
def api_summary():
    all_leaves = tree_mgr.get_all_leaves()
    leaf_paths = [l['path'] for l in all_leaves]
    paused_set = database.get_all_paused()
    latest = database.get_latest_results_batch(leaf_paths)
    active_paths = [p for p in leaf_paths if p not in paused_set]
    paused_count = len(leaf_paths) - len(active_paths)
    up = sum(1 for p in active_paths if latest.get(p) and latest[p]['is_up'])
    return jsonify({
        'total': len(all_leaves),
        'up': up,
        'down': len(active_paths) - up,
        'paused': paused_count,
        'uptime_24h': database.get_uptime_multi(active_paths, 24) if active_paths else None,
        'site_name': config.get('site_name', 'BBnet Uptime Monitor'),
    })


# ---------------------------------------------------------------------------
# Routes — Host detail
# ---------------------------------------------------------------------------

@app.route('/api/host')
@login_required
def api_host():
    try:
        path = request.args.get('path', '').strip('/')
        print(f"[api/host] Requested path: '{path}'")
        node = tree_mgr.find_node(path)
        if not node:
            print(f"[api/host] Node not found for path: '{path}'")
            return jsonify({'error': f'Host path not found: {path}'}), 404
        if not node['host']:
            print(f"[api/host] Node is a group (no host) for path: '{path}'")
            return jsonify({'error': f'Path is a group, not a host: {path}'}), 404

        latest = database.get_latest_result(path)
        is_up = bool(latest['is_up']) if latest else None
        stats = database.get_latency_stats(path, 24)

        return jsonify({
            'name': node['name'],
            'host': node['host'],
            'path': path,
            'ping_interval': node['ping_interval'],
            'is_up': is_up,
            'latency_ms': latest['latency_ms'] if latest else None,
            'last_check': latest['timestamp'] if latest else None,
            'uptime_1h':  database.get_uptime(path, 1),
            'uptime_24h': database.get_uptime(path, 24),
            'uptime_7d':  database.get_uptime(path, 168),
            'uptime_30d': database.get_uptime(path, 720),
            'uptime_1y':  database.get_uptime(path, 8760),
            'latency_avg_24h': stats['avg_ms'],
            'latency_min_24h': stats['min_ms'],
            'latency_max_24h': stats['max_ms'],
            'outages_30d': database.get_outage_count(path, 720),
            'breadcrumb': tree_mgr.build_breadcrumb(path),
        })
    except Exception as e:
        import traceback
        print(f"[api/host] Exception: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/host/graph')
@login_required
def api_host_graph():
    path = request.args.get('path', '').strip('/')
    hours = min(int(request.args.get('hours', 24)), 8760)
    since = int(time.time()) - hours * 3600

    points = database.get_latency_history(path, hours)
    down_periods = database.get_down_periods(path, since)

    return jsonify({
        'points': points,
        'down_periods': down_periods,
        'since': since,
        'now': int(time.time()),
    })


@app.route('/api/host/events')
@login_required
def api_host_events():
    path = request.args.get('path', '').strip('/')
    limit = min(int(request.args.get('limit', 100)), 500)
    events = database.get_event_history(path, limit)
    return jsonify({'events': events})


@app.route('/api/outages')
@login_required
def api_outages():
    days  = min(int(request.args.get('days', 30)), 90)
    now   = int(time.time())
    since = now - days * 86400

    paused_set = database.get_all_paused()
    top_pages  = tree_mgr.get_children('') or []

    # Build path → {name, host, site} lookup
    path_info: dict = {}
    for page in top_pages:
        leaves = tree_mgr.get_leaves_under(page['path']) or []
        for leaf in leaves:
            path_info[leaf['path']] = {
                'name': leaf['name'],
                'host': leaf['host'],
                'site': page['name'],
            }

    # Query outages for all active (non-paused) hosts
    active_paths = [p for p in path_info if p not in paused_set]
    raw = database.get_outages_in_period(active_paths, since, now)

    outages = []
    for o in raw:
        info = path_info.get(o['host_path'], {})
        outages.append({
            'host_path':        o['host_path'],
            'name':             info.get('name', o['host_path']),
            'host':             info.get('host', '—'),
            'site':             info.get('site', '—'),
            'start':            o['start'],
            'end':              o['end'],
            'duration_seconds': o['duration_seconds'],
            'ongoing':          o['ongoing'],
        })

    # Most recent outages first
    outages.sort(key=lambda x: x['start'], reverse=True)
    return jsonify({'outages': outages, 'days': days, 'since': since, 'now': now})


@app.route('/api/hosts/list')
@login_required
def api_hosts_list():
    status = request.args.get('status', 'all')  # 'up', 'down', 'paused', 'all'
    all_leaves = tree_mgr.get_all_leaves()
    leaf_paths = [l['path'] for l in all_leaves]
    paused_set = database.get_all_paused()
    latest = database.get_latest_results_batch(leaf_paths)

    result = []
    for leaf in all_leaves:
        is_paused = leaf['path'] in paused_set
        row = latest.get(leaf['path'])
        is_up = bool(row['is_up']) if (row and not is_paused) else None
        if status == 'up'     and (is_paused or is_up is not True):
            continue
        if status == 'down'   and (is_paused or is_up is not False):
            continue
        if status == 'paused' and not is_paused:
            continue
        result.append({
            'name': leaf['name'],
            'path': leaf['path'],
            'host': leaf['host'],
            'is_up': is_up,
            'is_paused': is_paused,
            'latency_ms': row['latency_ms'] if row else None,
            'last_check': row['timestamp'] if row else None,
        })

    # Sort: down first for 'all', alphabetical for filtered
    if status == 'all':
        result.sort(key=lambda x: (x['is_up'] is not False, x['name']))
    else:
        result.sort(key=lambda x: x['name'])

    return jsonify({'hosts': result, 'count': len(result)})


# ---------------------------------------------------------------------------
# Routes — Pause / Resume
# ---------------------------------------------------------------------------

@app.route('/api/host/pause', methods=['POST'])
@login_required
@csrf_required
def api_host_pause():
    path = request.args.get('path', '').strip('/')
    node = tree_mgr.find_node(path)
    if not node or not node['host']:
        return jsonify({'error': 'Host not found'}), 404
    database.pause_host(path)
    return jsonify({'status': 'paused', 'path': path})


@app.route('/api/host/resume', methods=['POST'])
@login_required
@csrf_required
def api_host_resume():
    path = request.args.get('path', '').strip('/')
    node = tree_mgr.find_node(path)
    if not node or not node['host']:
        return jsonify({'error': 'Host not found'}), 404
    database.resume_host(path)
    return jsonify({'status': 'active', 'path': path})


@app.route('/api/host/paused-list')
@login_required
def api_host_paused_list():
    paused = database.get_all_paused()
    return jsonify({'paused': list(paused)})


# ---------------------------------------------------------------------------
# Routes — Status Pages (admin CRUD)
# ---------------------------------------------------------------------------

@app.route('/api/status-pages', methods=['GET'])
@login_required
def api_list_status_pages():
    return jsonify({'pages': database.get_status_pages()})


@app.route('/api/status-pages', methods=['POST'])
@login_required
@csrf_required
def api_create_status_page():
    data = request.get_json(force=True) or {}
    slug  = data.get('slug', '').strip().lower()
    title = data.get('title', '').strip()
    layout         = data.get('layout', 'banner-list')
    included_pages = data.get('included_pages', [])
    password       = data.get('password', '').strip()

    if not slug or not title:
        return jsonify({'error': 'slug and title are required'}), 400
    if not re.match(r'^[a-z0-9-]+$', slug):
        return jsonify({'error': 'slug must contain only lowercase letters, numbers, and hyphens'}), 400
    if database.get_status_page(slug):
        return jsonify({'error': f'Slug "{slug}" is already in use'}), 409

    pw_hash = generate_password_hash(password) if password else None
    database.create_status_page(slug, title, layout, included_pages, pw_hash)
    return jsonify({'status': 'ok', 'slug': slug}), 201


@app.route('/api/status-pages/<slug>', methods=['PUT'])
@login_required
@csrf_required
def api_update_status_page(slug):
    page = database.get_status_page(slug)
    if not page:
        return jsonify({'error': 'Not found'}), 404

    data  = request.get_json(force=True) or {}
    title          = data.get('title', page['title']).strip()
    layout         = data.get('layout', page['layout'])
    included_pages = data.get('included_pages', page['included_pages'])

    # 'password' key present → update (empty string clears it); absent → keep existing hash
    if 'password' in data:
        pw = data['password'].strip()
        pw_hash = generate_password_hash(pw) if pw else None
    else:
        pw_hash = page['password_hash']

    database.update_status_page(slug, title, layout, included_pages, pw_hash)
    return jsonify({'status': 'ok'})


@app.route('/api/status-pages/<slug>', methods=['DELETE'])
@login_required
@csrf_required
def api_delete_status_page(slug):
    if not database.get_status_page(slug):
        return jsonify({'error': 'Not found'}), 404
    database.delete_status_page(slug)
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# Routes — Status Pages (public)
# ---------------------------------------------------------------------------

@app.route('/status/<slug>', methods=['GET', 'POST'])
def public_status_page(slug):
    page = database.get_status_page(slug)
    if not page:
        return 'Status page not found', 404

    if page['password_hash']:
        session_key = f'sp_{slug}'
        if request.method == 'POST':
            if check_password_hash(page['password_hash'], request.form.get('password', '')):
                session[session_key] = True
                return redirect(f'/status/{slug}')
            return render_template_string(STATUS_PASSWORD_HTML,
                                          title=page['title'], error='Incorrect password')
        if not session.get(session_key):
            return render_template_string(STATUS_PASSWORD_HTML, title=page['title'], error=None)

    return app.send_static_file('status_page.html')


@app.route('/api/status-page/<slug>/data')
def api_status_page_data(slug):
    page = database.get_status_page(slug)
    if not page:
        return jsonify({'error': 'Not found'}), 404

    # Password-protected pages require session auth (or admin session)
    if page['password_hash']:
        if not session.get(f'sp_{slug}') and not session.get('authenticated'):
            return jsonify({'error': 'Unauthorized'}), 401

    included  = page['included_pages']   # list of paths at any depth
    all_pages = tree_mgr.get_children('') or []

    # Determine which top-level pages have any selected descendant-or-self
    walk_from = all_pages if not included else [
        p for p in all_pages if _node_included(p['path'], included) != 'none'
    ]

    # Collect leaves for a single batch DB query
    all_leaves = []
    for p in walk_from:
        all_leaves.extend(tree_mgr.get_leaves_under(p['path']) or [])
    leaf_paths   = [l['path'] for l in all_leaves]
    latest_batch = database.get_latest_results_batch(leaf_paths)
    paused_set   = database.get_all_paused()

    if not included:
        groups = [_build_status_group(p, latest_batch, paused_set) for p in all_pages]
    else:
        groups = [
            _build_status_group_filtered(p, latest_batch, paused_set, included)
            for p in walk_from
        ]
        groups = [g for g in groups if g]

    total = sum(g['host_count'] for g in groups)
    up    = sum(g['up_count']   for g in groups)

    return jsonify({
        'title':   page['title'],
        'layout':  page['layout'],
        'groups':  groups,
        'summary': {'total': total, 'up': up, 'down': total - up},
        'now':     int(time.time()),
    })


@app.route('/api/kuma-probe')
@login_required
def api_kuma_probe():
    """Probe multiple Kuma endpoint + auth combinations to find what works."""
    if kuma_poller is None:
        return jsonify({'error': 'Kuma integration not configured'}), 503
    try:
        results = kuma_poller.probe()
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/api/kuma-test')
@login_required
def api_kuma_test():
    """Diagnostic: dump the raw Kuma /api/monitors response to verify connectivity."""
    if kuma_poller is None:
        return jsonify({'error': 'Kuma integration not configured — add kuma_url and kuma_api_key to config.yml'}), 503
    try:
        status_code, body_text, data = kuma_poller.fetch_raw_debug()
        return jsonify({
            'ok':          data is not None,
            'http_status': status_code,
            'body_preview': body_text[:500] if body_text else '',
            'data':        data,
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502


@app.route('/api/tree')
@login_required
def api_tree():
    """Return a simplified host tree for the status page host selector."""
    def simplify(node):
        if node.get('host'):
            return {'name': node['name'], 'path': node['path'], 'is_leaf': True}
        kids = [simplify(c) for c in node.get('children', [])]
        return {'name': node['name'], 'path': node['path'], 'is_leaf': False, 'children': kids}

    pages = tree_mgr.get_children('') or []
    return jsonify({'tree': [simplify(p) for p in pages]})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    database.init_db()
    app.secret_key = get_secret_key()

    # Load host tree
    tree_mgr.load_tree()

    # Start alerter
    alerter.init(config)

    # Start Kuma poller (if configured)
    if config.get('kuma_url') and config.get('kuma_api_key'):
        kuma_poller = kuma_module.KumaPoller(
            url=config['kuma_url'],
            api_key=config['kuma_api_key'],
            poll_interval=config.get('kuma_poll_interval', 60),
        )
        kuma_poller.start()

    # Start background pinger
    scheduler = pinger_module.PingScheduler(
        max_workers=config.get('max_ping_workers', 50),
        ping_count=config.get('ping_count', 5),
        ping_timeout=config.get('ping_timeout', 1),
        rapid_retry_interval=config.get('rapid_retry_interval', 20),
        recovery_pings=config.get('recovery_pings', 3),
    )
    scheduler.start()

    print(f"[uptime-monitor] Starting on port {config.get('port', 6000)}")
    app.run(
        host='0.0.0.0',
        port=config.get('port', 6000),
        debug=False,
        use_reloader=False,
    )
