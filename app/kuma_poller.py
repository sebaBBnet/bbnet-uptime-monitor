"""
Kuma poller — fetches monitor status from an Uptime Kuma instance via REST API
and writes results into the local database so Kuma monitors appear in the dashboard
alongside regular ping hosts.

Kuma REST API (v2.x):
  GET /api/monitors
  Authorization: Bearer <api-key>

Status values: 1=up, 0=down, 2=pending, 3=maintenance
"""
import threading
import time

import requests

import database
import tree as tree_mgr


class KumaPoller:
    def __init__(self, url: str, api_key: str, poll_interval: int = 60):
        self.url           = url.rstrip('/')
        self.api_key       = api_key
        self.poll_interval = poll_interval
        self._stop         = threading.Event()
        self._thread       = None

        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'X-API-Key':     api_key,       # Kuma 2.x alternative header
            'Accept':        'application/json',
        })

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name='kuma-poller')
        self._thread.start()
        print(f"[kuma] Poller started — {self.url}, interval={self.poll_interval}s")

    def stop(self):
        self._stop.set()

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    def _run(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                print(f"[kuma] Poll error: {e}")
            self._stop.wait(self.poll_interval)

    def _poll(self):
        # Build kuma_id -> tree node map from current tree
        kuma_nodes = {
            leaf['kuma_id']: leaf
            for leaf in tree_mgr.get_all_leaves()
            if leaf.get('kuma_id')
        }
        if not kuma_nodes:
            return

        monitors = self._fetch_monitors()
        updated = 0

        for mon in monitors:
            mon_id = mon.get('id')
            if mon_id not in kuma_nodes:
                continue

            node    = kuma_nodes[mon_id]
            is_up, latency_ms = self._extract_status(mon)

            if is_up is None:
                continue  # no data yet (pending / no heartbeat)

            database.store_result(node['path'], is_up, latency_ms)
            updated += 1

        if updated:
            print(f"[kuma] Updated {updated} monitor(s)")

    def _fetch_monitors(self) -> list:
        """Fetch monitor list from Kuma API. Returns a list of monitor dicts."""
        resp = self._session.get(f"{self.url}/api/monitors", timeout=15)
        resp.raise_for_status()
        data = resp.json()

        monitors = data.get('monitors', data)

        # Some Kuma versions return a dict keyed by id rather than a list
        if isinstance(monitors, dict):
            monitors = list(monitors.values())

        return monitors if isinstance(monitors, list) else []

    @staticmethod
    def _extract_status(mon: dict):
        """
        Return (is_up: bool | None, latency_ms: float | None) from a monitor dict.
        Handles different Kuma response shapes across versions.
        """
        # Try embedded heartbeat objects (various field names used across versions)
        for key in ('heartbeat', 'lastHeartbeat', 'last_heartbeat'):
            hb = mon.get(key)
            if isinstance(hb, dict):
                status  = hb.get('status')
                latency = hb.get('latency') or hb.get('ping')
                if status is not None:
                    return _kuma_status(status), _to_float(latency)

        # Fall back to top-level status field
        status = mon.get('status')
        if status is not None:
            return _kuma_status(status), None

        return None, None

    # -----------------------------------------------------------------------
    # Diagnostic
    # -----------------------------------------------------------------------

    def fetch_raw(self) -> dict:
        """Return the raw /api/monitors response — used internally."""
        resp = self._session.get(f"{self.url}/api/monitors", timeout=15)
        resp.raise_for_status()
        return resp.json()

    def fetch_raw_debug(self) -> tuple:
        """Return (http_status, body_text, parsed_json_or_None) for the diagnostic endpoint."""
        resp = self._session.get(f"{self.url}/api/monitors", timeout=15)
        body = resp.text
        try:
            data = resp.json()
        except Exception:
            data = None
        return resp.status_code, body, data

    def probe(self) -> list:
        """
        Try several endpoint + auth combinations and return a result list.
        Each entry: {endpoint, auth, http_status, content_type, is_json, preview}
        """
        endpoints = [
            '/api/monitors',
            '/api/monitor',
            '/api/v1/monitors',
        ]
        auth_variants = [
            ('Bearer',  {'Authorization': f'Bearer {self.api_key}'}),
            ('apikey',  {'Authorization': f'apikey {self.api_key}'}),
            ('X-API-Key', {'X-API-Key': self.api_key}),
            ('query',   {}),   # api key as query param
        ]

        results = []
        base_session = requests.Session()
        base_session.headers.update({'Accept': 'application/json'})

        for path in endpoints:
            for auth_name, headers in auth_variants:
                url = f"{self.url}{path}"
                params = {'apikey': self.api_key} if auth_name == 'query' else {}
                try:
                    resp = base_session.get(url, headers=headers, params=params,
                                            timeout=10, allow_redirects=True)
                    ct = resp.headers.get('Content-Type', '')
                    try:
                        resp.json()
                        is_json = True
                    except Exception:
                        is_json = False
                    results.append({
                        'endpoint':     path,
                        'auth':         auth_name,
                        'http_status':  resp.status_code,
                        'content_type': ct,
                        'is_json':      is_json,
                        'preview':      resp.text[:200],
                    })
                except Exception as e:
                    results.append({
                        'endpoint':    path,
                        'auth':        auth_name,
                        'error':       str(e),
                    })

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kuma_status(status) -> bool:
    """Kuma status: 1=up, 0=down, 2=pending, 3=maintenance → True/False/None."""
    try:
        s = int(status)
    except (TypeError, ValueError):
        return None
    if s == 1:
        return True
    if s == 0:
        return False
    return None   # pending / maintenance — don't store


def _to_float(val) -> float:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None
