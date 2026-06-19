"""
WSGI entry point for Gunicorn.

Gunicorn imports this module and serves `app`. We run the same startup
sequence as main.py __main__ block so the pinger and alerter threads
start exactly once before the first request arrives.
"""
from pathlib import Path
import yaml

import alerter
import database
import pinger as pinger_module
import tree as tree_mgr
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

scheduler = pinger_module.PingScheduler(
    max_workers=config.get('max_ping_workers', 50),
    ping_count=config.get('ping_count', 5),
    ping_timeout=config.get('ping_timeout', 1),
)
scheduler.start()

print(f"[wsgi] App ready — Gunicorn serving on port {config.get('port', 9000)}")
