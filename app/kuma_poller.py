"""
Kuma poller — fetches monitor status from Uptime Kuma's public status page
heartbeat API and writes results into the local database so Kuma monitors
appear in the dashboard alongside regular ping hosts.

API endpoints used (no auth required):
  GET /api/status-page/heartbeat/<slug>
    Returns heartbeatList keyed by monitor ID, each entry has status + latency.
    Status values: 1=up, 0=down, 2=pending, 3=maintenance

Hosts in hosts.cfg declare which Kuma status page they belong to:
  kuma My-Website  # kuma-id=3 kuma-slug=bbnet-status
"""
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
        # Group kuma nodes by status page slug
        slug_map: dict[str, list] = {}   # slug -> [leaf_node, ...]
        for leaf in tree_mgr.get_all_leaves():
            if leaf.get('kuma_id') and leaf.get('kuma_slug'):
                slug = leaf['kuma_slug']
                slug_map.setdefault(slug, []).append(leaf)

        if not slug_map:
            return

        updated = 0
        for slug, nodes in slug_map.items():
            try:
                heartbeats = self._fetch_heartbeats(slug)
            except Exception as e:
                print(f"[kuma] Failed to fetch slug '{slug}': {e}")
                continue

            # Build id -> node map for this slug
            id_map = {node['kuma_id']: node for node in nodes}

            for mon_id, hb_list in heartbeats.items():
                try:
                    node_id = int(mon_id)
                except ValueError:
                    continue
                if node_id not in id_map:
                    continue
                if not hb_list:
                    continue

                # Most recent heartbeat is the last item in the list
                latest  = hb_list[-1]
                is_up, latency_ms = _extract_status(latest)

                if is_up is None:
                    continue

                node = id_map[node_id]
                database.store_result(node['path'], is_up, latency_ms)
                updated += 1

        if updated:
            print(f"[kuma] Updated {updated} monitor(s)")

    def _fetch_heartbeats(self, slug: str) -> dict:
        """Fetch and return the heartbeatList dict for a status page slug."""
        resp = self._session.get(
            f"{self.url}/api/status-page/heartbeat/{slug}",
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get('heartbeatList', {})

    # -----------------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------------

    def fetch_raw_debug(self, slug: str) -> tuple:
        """Return (http_status, body_text, parsed_json_or_None) for a given slug."""
        resp = self._session.get(
            f"{self.url}/api/status-page/heartbeat/{slug}",
            timeout=15,
        )
        body = resp.text
        try:
            data = resp.json()
        except Exception:
            data = None
        return resp.status_code, body, data

    def get_slugs_from_tree(self) -> list:
        """Return the unique kuma-slugs declared in the current host tree."""
        slugs = set()
        for leaf in tree_mgr.get_all_leaves():
            if leaf.get('kuma_slug'):
                slugs.add(leaf['kuma_slug'])
        return sorted(slugs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_status(hb: dict):
    """Return (is_up: bool | None, latency_ms: float | None) from a heartbeat dict."""
    status  = hb.get('status')
    latency = hb.get('latency') or hb.get('ping')
    return _kuma_status(status), _to_float(latency)


def _kuma_status(status) -> bool:
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


def _to_float(val) -> float:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None
