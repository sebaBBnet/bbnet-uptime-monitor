"""
Uptime Monitor — Flask web application.
"""
import os
import secrets
import time
from functools import wraps
from pathlib import Path

import yaml
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for

import alerter
import database
import pinger as pinger_module
import tree as tree_mgr

CONFIG_FILE = Path('/app/config.yml')

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

config = load_config()

# ---------------------------------------------------------------------------
# Flask app setup
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder='static', static_url_path='/static')

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

# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == config['password']:
            session['authenticated'] = True
            return redirect(url_for('index'))
        return render_template_string(LOGIN_HTML, error='Incorrect password')
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

def _node_stats(node: dict, latest_batch: dict, leaves: list = None) -> dict:
    """Build the stats dict for a single node (leaf or group)."""
    if node['host']:
        # Leaf node
        row = latest_batch.get(node['path'])
        is_up = bool(row['is_up']) if row else None
        latency = row['latency_ms'] if row else None
        last_check = row['timestamp'] if row else None
        return {
            'name': node['name'],
            'path': node['path'],
            'is_leaf': True,
            'host': node['host'],
            'ping_interval': node['ping_interval'],
            'is_up': is_up,
            'latency_ms': latency,
            'last_check': last_check,
            'host_count': 1,
            'up_count': (1 if is_up else 0) if is_up is not None else 0,
            'down_count': (0 if is_up else 1) if is_up is not None else 0,
            'uptime_24h': database.get_uptime(node['path'], 24),
            'uptime_7d': database.get_uptime(node['path'], 168),
            'uptime_30d': database.get_uptime(node['path'], 720),
        }
    else:
        # Group node — aggregate from descendant leaves
        if leaves is None:
            leaves = tree_mgr.get_all_leaves(node['children'])
        leaf_paths = [l['path'] for l in leaves]
        host_count = len(leaves)
        up_count = sum(1 for p in leaf_paths if latest_batch.get(p) and latest_batch[p]['is_up'])
        return {
            'name': node['name'],
            'path': node['path'],
            'is_leaf': False,
            'host_count': host_count,
            'up_count': up_count,
            'down_count': host_count - up_count,
            'uptime_24h': database.get_uptime_multi(leaf_paths, 24),
            'uptime_7d': database.get_uptime_multi(leaf_paths, 168),
            'uptime_30d': database.get_uptime_multi(leaf_paths, 720),
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

    items = []
    for child in (children or []):
        child_leaves = tree_mgr.get_all_leaves(child['children']) if not child['host'] else [child]
        items.append(_node_stats(child, latest_batch, child_leaves if not child['host'] else None))

    return jsonify({
        'breadcrumb': tree_mgr.build_breadcrumb(path),
        'current_path': path,
        'items': items,
    })


@app.route('/api/reload', methods=['POST'])
@login_required
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
    latest = database.get_latest_results_batch(leaf_paths)
    total = len(all_leaves)
    up = sum(1 for p in leaf_paths if latest.get(p) and latest[p]['is_up'])
    return jsonify({
        'total': total,
        'up': up,
        'down': total - up,
        'uptime_24h': database.get_uptime_multi(leaf_paths, 24),
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


@app.route('/api/hosts/list')
@login_required
def api_hosts_list():
    status = request.args.get('status', 'all')  # 'up', 'down', 'all'
    all_leaves = tree_mgr.get_all_leaves()
    leaf_paths = [l['path'] for l in all_leaves]
    latest = database.get_latest_results_batch(leaf_paths)

    result = []
    for leaf in all_leaves:
        row = latest.get(leaf['path'])
        is_up = bool(row['is_up']) if row else None
        if status == 'up' and is_up is not True:
            continue
        if status == 'down' and is_up is not False:
            continue
        result.append({
            'name': leaf['name'],
            'path': leaf['path'],
            'host': leaf['host'],
            'is_up': is_up,
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
def api_host_pause():
    path = request.args.get('path', '').strip('/')
    node = tree_mgr.find_node(path)
    if not node or not node['host']:
        return jsonify({'error': 'Host not found'}), 404
    database.pause_host(path)
    return jsonify({'status': 'paused', 'path': path})


@app.route('/api/host/resume', methods=['POST'])
@login_required
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
# Startup
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    database.init_db()
    app.secret_key = get_secret_key()

    # Load host tree
    tree_mgr.load_tree()

    # Start alerter
    alerter.init(config)

    # Start background pinger
    scheduler = pinger_module.PingScheduler(
        max_workers=config.get('max_ping_workers', 50),
        ping_count=config.get('ping_count', 5),
        ping_timeout=config.get('ping_timeout', 1),
    )
    scheduler.start()

    print(f"[uptime-monitor] Starting on port {config.get('port', 6000)}")
    app.run(
        host='0.0.0.0',
        port=config.get('port', 6000),
        debug=False,
        use_reloader=False,
    )
