"""
Kuma poller — fetches monitor status from Uptime Kuma's public status page
heartbeat API and writes results into the local database so Kuma monitors
appear in the dashboard alongside regular ping hosts.

API endpoints used (no auth required):
  GET /api/status-page/<slug>
    Returns publicGroupList containing monitor IDs and names.
  GET /api/status-page/heartbeat/<slug>
    Returns heartbeatList keyed by monitor ID with status + latency.
    Status values: 1=up, 0=down, 2=pending, 3=maintenance

hosts.cfg format:
  page kuma "Kuma External"
  kuma-import my-status-page-slug

  Multiple slugs on the same page are fine:
  kuma-import slug-one
  kuma-import slug-two
"""
import re
import threading

import requests

import database
import tree as tree_mgr


class KumaPoller:
    def __init__(self, url: str, poll_interval: int = 60):
        self.url           = url.rstrip('/')
        self.poll_interval = poll_interval
        self._stop         = threading.Event()
        self._thread       = None
        self._session      = requests.Session()
        self._session.headers.update({'Accept': 'application/json'})

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
        imports = tree_mgr.get_kuma_imports()
        if not imports:
            return

        updated = 0
        for parent_path, slug in imports:
            try:
                monitors   = self._fetch_monitors(slug)
                heartbeats = self._fetch_heartbeats(slug)

                leaf_nodes = []
                for mon in monitors:
                    mon_id   = mon.get('id')
                    mon_name = mon.get('name', f'Monitor {mon_id}')
                    if mon_id is None:
                        continue

                    mon_slug  = _slugify(mon_name)
                    mon_path  = f"{parent_path}/{mon_slug}"

                    node = {
                        'name':              mon_name,
                        'slug':              mon_slug,
                        'path':              mon_path,
                        'host':              'kuma',
                        'ping_interval':     self.poll_interval,
                        'children':          [],
                        'kuma_id':           mon_id,
                        'kuma_slug':         slug,
                        'kuma_import_slugs': [],
                    }
                    leaf_nodes.append(node)

                    # Store current status in DB
                    hb_list = heartbeats.get(str(mon_id), [])
                    if hb_list:
                        is_up, latency_ms = _extract_status(hb_list[-1])
                        if is_up is not None:
                            database.store_result(mon_path, is_up, latency_ms)
                            updated += 1

                tree_mgr.inject_kuma_nodes(parent_path, slug, leaf_nodes)
                print(f"[kuma] '{slug}': {len(leaf_nodes)} monitor(s) injected")

            except Exception as e:
                print(f"[kuma] Error for slug '{slug}': {e}")

        if updated:
            print(f"[kuma] Updated status for {updated} monitor(s)")

    def _fetch_monitors(self, slug: str) -> list:
        """
        Fetch monitor list from /api/status-page/<slug>.
        Returns a flat list of {id, name} dicts from all groups on the page.
        """
        resp = self._session.get(f"{self.url}/api/status-page/{slug}", timeout=15)
        resp.raise_for_status()
        data = resp.json()

        monitors = []
        for group in data.get('publicGroupList', []):
            for mon in group.get('monitorList', []):
                monitors.append(mon)
        return monitors

    def _fetch_heartbeats(self, slug: str) -> dict:
        """
        Fetch heartbeatList from /api/status-page/heartbeat/<slug>.
        Returns dict keyed by monitor ID (as string).
        """
        resp = self._session.get(
            f"{self.url}/api/status-page/heartbeat/{slug}", timeout=15
        )
        resp.raise_for_status()
        return resp.json().get('heartbeatList', {})

    # -----------------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------------

    def get_slugs_from_tree(self) -> list:
        """Return unique slugs declared via kuma-import in the current tree."""
        return sorted({slug for _, slug in tree_mgr.get_kuma_imports()})

    def fetch_raw_debug(self, slug: str) -> tuple:
        """
        Return (http_status, body_text, parsed_json_or_None) for the heartbeat
        endpoint of a given slug — used by /api/kuma-test.
        """
        resp = self._session.get(
            f"{self.url}/api/status-page/heartbeat/{slug}", timeout=15
        )
        body = resp.text
        try:
            data = resp.json()
        except Exception:
            data = None
        return resp.status_code, body, data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    return slug.strip('-')


def _extract_status(hb: dict):
    """Return (is_up: bool | None, latency_ms: float | None) from a heartbeat dict."""
    status  = hb.get('status')
    latency = hb.get('latency') or hb.get('ping')
    return _kuma_status(status), _to_float(latency)


def _kuma_status(status):
    """1=up, 0=down, 2=pending, 3=maintenance → True/False/None."""
    try:
        s = int(status)
    except (TypeError, ValueError):
        return None
    if s == 1:
        return True
    if s == 0:
        return False
    return None


def _to_float(val):
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None
