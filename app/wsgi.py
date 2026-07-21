"""
WSGI entry point for Gunicorn.

Gunicorn imports this module and serves `app`. We run the same startup
sequence as main.py __main__ block so the pinger and alerter threads
start exactly once before the first request arrives.
"""
import threading
import time
from pathlib import Path
import yaml

import alerter
import database
import kuma_poller as kuma_module
import pinger as pinger_module
import tree as tree_mgr
import main as main_module
from main import app

CONFIG_FILE = Path('/app/config.yml')

with open(CONFIG_FILE) as f:
    config = yaml.safe_load(f)

# Initialise DB, secret key, tree, alerter, pinger — same as main.py
database.init_db()
app.secret_key = config.get('secret_key') or __import__('secrets').token_hex(32)

# Persist secret key so sessions survive restarts
_stored = database.get_kv('secret_key')
if not _stored:
    database.set_kv('secret_key', app.secret_key)
else:
    app.secret_key = _stored

tree_mgr.load_tree()
alerter.init(config)

# Start Kuma poller (if configured)
if config.get('kuma_url') and config.get('kuma_api_key'):
    main_module.kuma_poller = kuma_module.KumaPoller(
        url=config['kuma_url'],
        api_key=config['kuma_api_key'],
        poll_interval=config.get('kuma_poll_interval', 60),
    )
    main_module.kuma_poller.start()

scheduler = pinger_module.PingScheduler(
    max_workers=config.get('max_ping_workers', 50),
    ping_count=config.get('ping_count', 5),
    ping_timeout=config.get('ping_timeout', 1),
    rapid_retry_interval=config.get('rapid_retry_interval', 20),
    recovery_pings=config.get('recovery_pings', 3),
)
scheduler.start()

def _cleanup_loop():
    """Delete records older than 2 years once per day."""
    while True:
        time.sleep(86400)
        try:
            database.cleanup_old_records()
            print("[wsgi] Ran cleanup_old_records")
        except Exception as e:
            print(f"[wsgi] cleanup error: {e}")

_t = threading.Thread(target=_cleanup_loop, daemon=True, name="cleanup")
_t.start()

print(f"[wsgi] App ready — Gunicorn serving on port {config.get('port', 9000)}")
