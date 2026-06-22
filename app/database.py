"""
SQLite database operations for uptime monitoring.
"""
import hashlib
import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path('/data/uptime.db')
RETENTION_DAYS = 730  # 2 years

# ---------------------------------------------------------------------------
# TTL cache for expensive queries
# ---------------------------------------------------------------------------
_UPTIME_TTL  = 60    # uptime %s — 60s is fine (rolling averages over hours/days)
_LATEST_TTL  = 5     # latest ping results — 5s prevents hammering on rapid refreshes

_cache: dict      = {}   # key -> (value, expires_at)
_cache_lock       = threading.Lock()


def _cache_get(key):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and entry[1] > time.time():
            return entry[0], True
        return None, False


def _cache_set(key, value, ttl: int):
    with _cache_lock:
        _cache[key] = (value, time.time() + ttl)


def _paths_hash(host_paths: list) -> str:
    """Stable short key for a list of paths — avoids huge cache keys."""
    return hashlib.md5('|'.join(sorted(host_paths)).encode()).hexdigest()


def get_conn():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=500")   # 2MB per conn — short-lived conns don't need 40MB
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ping_results (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_path  TEXT    NOT NULL,
                timestamp  INTEGER NOT NULL,
                is_up      INTEGER NOT NULL,
                latency_ms REAL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_host_path_ts
            ON ping_results(host_path, timestamp)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kv_store (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS paused_hosts (
                host_path TEXT PRIMARY KEY,
                paused_at INTEGER NOT NULL
            )
        """)


def store_result(host_path: str, is_up: bool, latency_ms: float = None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO ping_results (host_path, timestamp, is_up, latency_ms) VALUES (?, ?, ?, ?)",
            (host_path, int(time.time()), 1 if is_up else 0, latency_ms)
        )


def get_latest_result(host_path: str):
    with get_conn() as conn:
        return conn.execute("""
            SELECT is_up, latency_ms, timestamp
            FROM ping_results
            WHERE host_path = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (host_path,)).fetchone()


def get_latest_results_batch(host_paths: list) -> dict:
    if not host_paths:
        return {}
    cache_key = f"lb:{_paths_hash(host_paths)}"
    val, hit = _cache_get(cache_key)
    if hit:
        return val
    placeholders = ','.join('?' * len(host_paths))
    with get_conn() as conn:
        rows = conn.execute(f"""
            WITH ranked AS (
                SELECT host_path, is_up, latency_ms, timestamp,
                       ROW_NUMBER() OVER (PARTITION BY host_path ORDER BY timestamp DESC) AS rn
                FROM ping_results
                WHERE host_path IN ({placeholders})
            )
            SELECT host_path, is_up, latency_ms, timestamp
            FROM ranked WHERE rn = 1
        """, host_paths).fetchall()
    result = {row['host_path']: row for row in rows}
    _cache_set(cache_key, result, _LATEST_TTL)
    return result


def get_uptime(host_path: str, hours: int):
    cache_key = f"u1:{host_path}:{hours}"
    val, hit = _cache_get(cache_key)
    if hit:
        return val
    since = int(time.time()) - hours * 3600
    with get_conn() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS total, COALESCE(SUM(is_up), 0) AS up_count
            FROM ping_results
            WHERE host_path = ? AND timestamp >= ?
        """, (host_path, since)).fetchone()
    result = None if (not row or row['total'] == 0) else round((row['up_count'] / row['total']) * 100, 2)
    _cache_set(cache_key, result, _UPTIME_TTL)
    return result


def get_uptime_multi(host_paths: list, hours: int):
    if not host_paths:
        return None
    cache_key = f"um:{_paths_hash(host_paths)}:{hours}"
    val, hit = _cache_get(cache_key)
    if hit:
        return val
    since = int(time.time()) - hours * 3600
    placeholders = ','.join('?' * len(host_paths))
    with get_conn() as conn:
        row = conn.execute(f"""
            SELECT COUNT(*) AS total, COALESCE(SUM(is_up), 0) AS up_count
            FROM ping_results
            WHERE host_path IN ({placeholders}) AND timestamp >= ?
        """, host_paths + [since]).fetchone()
    result = None if (not row or row['total'] == 0) else round((row['up_count'] / row['total']) * 100, 2)
    _cache_set(cache_key, result, _UPTIME_TTL)
    return result


def get_latency_stats(host_path: str, hours: int) -> dict:
    """Average, min, max latency over the period (up pings only)."""
    since = int(time.time()) - hours * 3600
    with get_conn() as conn:
        row = conn.execute("""
            SELECT AVG(latency_ms) AS avg_ms,
                   MIN(latency_ms) AS min_ms,
                   MAX(latency_ms) AS max_ms,
                   COUNT(latency_ms) AS count
            FROM ping_results
            WHERE host_path = ? AND timestamp >= ? AND is_up = 1 AND latency_ms IS NOT NULL
        """, (host_path, since)).fetchone()
    if not row or not row['count']:
        return {'avg_ms': None, 'min_ms': None, 'max_ms': None}
    return {
        'avg_ms': round(row['avg_ms'], 2),
        'min_ms': round(row['min_ms'], 2),
        'max_ms': round(row['max_ms'], 2),
    }


def get_latency_history(host_path: str, hours: int, max_points: int = 300) -> list:
    """
    Bucketed latency data for graphing.
    Returns list of {bucket, avg_latency, min_latency, max_latency, up_count, total_count}.
    """
    since = int(time.time()) - hours * 3600
    total_seconds = hours * 3600
    bucket_size = max(60, total_seconds // max_points)

    with get_conn() as conn:
        rows = conn.execute("""
            SELECT
                (timestamp / ?) * ? AS bucket,
                AVG(CASE WHEN is_up = 1 THEN latency_ms END)  AS avg_latency,
                MIN(CASE WHEN is_up = 1 THEN latency_ms END)  AS min_latency,
                MAX(CASE WHEN is_up = 1 THEN latency_ms END)  AS max_latency,
                SUM(is_up)   AS up_count,
                COUNT(*)     AS total_count
            FROM ping_results
            WHERE host_path = ? AND timestamp >= ?
            GROUP BY bucket
            ORDER BY bucket
        """, (bucket_size, bucket_size, host_path, since)).fetchall()

    return [dict(r) for r in rows]


def get_down_periods(host_path: str, since: int) -> list:
    """
    Returns [{start, end}] for each down period within the given time window.
    Open-ended period (end=None) means currently down.
    """
    with get_conn() as conn:
        rows = conn.execute("""
            WITH transitions AS (
                SELECT timestamp, is_up,
                       LAG(is_up) OVER (ORDER BY timestamp) AS prev_is_up
                FROM ping_results
                WHERE host_path = ? AND timestamp >= ?
            )
            SELECT timestamp, is_up
            FROM transitions
            WHERE prev_is_up IS NULL OR is_up != prev_is_up
            ORDER BY timestamp
        """, (host_path, since)).fetchall()

    periods = []
    down_start = None
    now = int(time.time())

    for row in rows:
        if not row['is_up'] and down_start is None:
            down_start = row['timestamp']
        elif row['is_up'] and down_start is not None:
            periods.append({'start': down_start, 'end': row['timestamp']})
            down_start = None

    if down_start is not None:
        periods.append({'start': down_start, 'end': now})

    return periods


def get_event_history(host_path: str, limit: int = 100) -> list:
    """
    Returns the most recent state-change events (up/down transitions).
    Each event: {is_up, timestamp, end_timestamp} where end_timestamp is when
    the state changed again (None = current state).
    """
    with get_conn() as conn:
        rows = conn.execute("""
            WITH transitions AS (
                SELECT timestamp, is_up,
                       LAG(is_up) OVER (ORDER BY timestamp) AS prev_is_up
                FROM ping_results
                WHERE host_path = ?
            ),
            state_changes AS (
                SELECT timestamp, is_up
                FROM transitions
                WHERE prev_is_up IS NULL OR is_up != prev_is_up
            ),
            with_end AS (
                SELECT timestamp, is_up,
                       LEAD(timestamp) OVER (ORDER BY timestamp) AS end_timestamp
                FROM state_changes
            )
            SELECT timestamp, is_up, end_timestamp
            FROM with_end
            ORDER BY timestamp DESC
            LIMIT ?
        """, (host_path, limit)).fetchall()

    return [
        {
            'is_up': bool(row['is_up']),
            'timestamp': row['timestamp'],
            'end_timestamp': row['end_timestamp'],
            'duration_seconds': (row['end_timestamp'] - row['timestamp']) if row['end_timestamp'] else None,
        }
        for row in rows
    ]


def get_outage_count(host_path: str, hours: int) -> int:
    """Number of distinct down events in the period."""
    since = int(time.time()) - hours * 3600
    with get_conn() as conn:
        row = conn.execute("""
            WITH transitions AS (
                SELECT timestamp, is_up,
                       LAG(is_up) OVER (ORDER BY timestamp) AS prev_is_up
                FROM ping_results
                WHERE host_path = ? AND timestamp >= ?
            )
            SELECT COUNT(*) AS cnt
            FROM transitions
            WHERE is_up = 0 AND (prev_is_up = 1 OR prev_is_up IS NULL)
        """, (host_path, since)).fetchone()
    return row['cnt'] if row else 0


def get_kv(key: str) -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
        return row['value'] if row else None


def set_kv(key: str, value: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value) VALUES (?, ?)",
            (key, value)
        )


def pause_host(host_path: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO paused_hosts (host_path, paused_at) VALUES (?, ?)",
            (host_path, int(time.time()))
        )


def resume_host(host_path: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM paused_hosts WHERE host_path = ?", (host_path,))


def is_paused(host_path: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM paused_hosts WHERE host_path = ?", (host_path,)
        ).fetchone()
        return row is not None


def get_all_paused() -> set:
    with get_conn() as conn:
        rows = conn.execute("SELECT host_path FROM paused_hosts").fetchall()
        return {row['host_path'] for row in rows}


def get_outages_in_period(host_paths: list, since: int, until: int = None) -> list:
    """
    Returns all down-periods for the given hosts that overlap with [since, until].
    Looks back up to 7 days before `since` to catch outages that started earlier.
    Each item: {host_path, start, end, duration_seconds, ongoing}
    """
    if not host_paths:
        return []
    if until is None:
        until = int(time.time())

    extended_since = since - 7 * 86400
    placeholders = ','.join('?' * len(host_paths))

    with get_conn() as conn:
        rows = conn.execute(f"""
            WITH ordered AS (
                SELECT host_path, timestamp, is_up,
                       LAG(is_up) OVER (PARTITION BY host_path ORDER BY timestamp) AS prev_is_up
                FROM ping_results
                WHERE host_path IN ({placeholders}) AND timestamp >= ?
            ),
            changes AS (
                SELECT host_path, timestamp, is_up
                FROM ordered
                WHERE prev_is_up IS NULL OR is_up != prev_is_up
            ),
            with_next AS (
                SELECT host_path, timestamp AS t_start, is_up,
                       LEAD(timestamp) OVER (PARTITION BY host_path ORDER BY timestamp) AS t_end
                FROM changes
            )
            SELECT host_path, t_start, t_end
            FROM with_next
            WHERE is_up = 0
              AND t_start < ?
              AND (t_end IS NULL OR t_end > ?)
            ORDER BY t_start
        """, host_paths + [extended_since, until, since]).fetchall()

    result = []
    for row in rows:
        end = row['t_end']
        result.append({
            'host_path':        row['host_path'],
            'start':            row['t_start'],
            'end':              end,
            'duration_seconds': (end - row['t_start']) if end else (until - row['t_start']),
            'ongoing':          end is None or end >= until,
        })
    return result


def cleanup_old_records():
    """Delete records older than 2 years."""
    cutoff = int(time.time()) - RETENTION_DAYS * 24 * 3600
    with get_conn() as conn:
        conn.execute("DELETE FROM ping_results WHERE timestamp < ?", (cutoff,))
