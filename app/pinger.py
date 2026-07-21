"""
Background ping service — schedules and executes pings for all hosts.

Down criteria: every `interval` seconds a burst of ping_count pings is sent.
If ALL pings in the burst fail, the host is declared DOWN and switched to
rapid-retry mode — it is re-pinged every `rapid_retry_interval` seconds.
To recover, the host must produce `recovery_pings` consecutive successful
bursts. This gives accurate outage end-times (±rapid_retry_interval)
without increasing load for healthy hosts.

Paused hosts are skipped entirely and generate no ping results.
"""
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import alerter
import database
import tree as tree_mgr


def ping_host(host: str, count: int = 5, timeout: int = 1):
    """
    Send `count` pings to host, each with `timeout` seconds deadline.
    Returns (is_up: bool, avg_latency_ms: float or None).
    Up if at least one ping succeeds; down only if all fail.
    """
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', str(timeout), host],
            capture_output=True,
            text=True,
            timeout=count * timeout + 3,
        )
        if result.returncode == 0:
            match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', result.stdout)
            latency = float(match.group(1)) if match else None
            return True, latency
        return False, None
    except Exception:
        return False, None


class PingScheduler:
    def __init__(self, max_workers: int = 50, ping_count: int = 5,
                 ping_timeout: int = 1, rapid_retry_interval: int = 20,
                 recovery_pings: int = 3):
        """
        ping_count:           pings per burst (all must fail to declare down)
        ping_timeout:         per-ping timeout in seconds
        rapid_retry_interval: seconds between retries while a host is down
        recovery_pings:       consecutive successful bursts required to recover
        """
        self.max_workers          = max_workers
        self.ping_count           = ping_count
        self.ping_timeout         = ping_timeout
        self.rapid_retry_interval = rapid_retry_interval
        self.recovery_pings       = recovery_pings

        self._executor    = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='pinger')
        self._last_ping:  dict = {}   # path -> timestamp of last completed burst
        self._in_flight:  set  = set()   # paths currently being pinged
        self._confirmed_down: set = set()  # paths currently in down state
        self._down_since: dict = {}   # path -> timestamp when first went down
        self._rapid_hosts: set = set()   # paths in rapid-retry mode
        self._recovery_streak: dict = {}  # path -> consecutive successes so far
        self._lock        = threading.Lock()
        self._stop_event  = threading.Event()
        self._thread      = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name='ping-scheduler')
        self._thread.start()
        print(
            f"[pinger] Started — {self.ping_count} pings/burst, {self.ping_timeout}s timeout, "
            f"rapid retry every {self.rapid_retry_interval}s, "
            f"{self.recovery_pings} consecutive successes to recover"
        )

    def stop(self):
        self._stop_event.set()

    def _run(self):
        last_cleanup = 0
        while not self._stop_event.is_set():
            now = time.time()

            # Hourly DB cleanup
            if now - last_cleanup > 3600:
                try:
                    database.cleanup_old_records()
                except Exception:
                    pass
                last_cleanup = now

            paused = database.get_all_paused()
            leaves = tree_mgr.get_all_leaves()

            for leaf in leaves:
                path     = leaf['path']
                interval = leaf['ping_interval']

                # Kuma-managed hosts — status comes from kuma_poller, not pinger
                if leaf.get('kuma_id'):
                    continue

                if path in paused:
                    continue

                with self._lock:
                    if path in self._in_flight:
                        continue
                    # Use rapid interval for down hosts, normal interval otherwise
                    effective_interval = (
                        self.rapid_retry_interval
                        if path in self._rapid_hosts
                        else interval
                    )
                    if now - self._last_ping.get(path, 0) < effective_interval:
                        continue
                    self._in_flight.add(path)

                self._executor.submit(self._ping_and_store, leaf)

            time.sleep(1)

    def _ping_and_store(self, leaf: dict):
        host = leaf['host']
        path = leaf['path']
        name = leaf['name']
        try:
            is_up, latency = ping_host(host, self.ping_count, self.ping_timeout)

            with self._lock:
                if is_up:
                    if path in self._rapid_hosts:
                        # Accumulate consecutive successes toward recovery
                        streak = self._recovery_streak.get(path, 0) + 1
                        self._recovery_streak[path] = streak
                        database.store_result(path, True, latency)

                        if streak >= self.recovery_pings:
                            # Fully recovered
                            self._rapid_hosts.discard(path)
                            self._recovery_streak.pop(path, None)
                            was_confirmed_down = path in self._confirmed_down
                            down_since = self._down_since.pop(path, None)
                            self._confirmed_down.discard(path)

                            if was_confirmed_down:
                                print(f"[pinger] {host} ({path}): recovered after {self.recovery_pings} successes")
                                threading.Thread(
                                    target=alerter.notify_up,
                                    args=(path, name, host, down_since),
                                    daemon=True
                                ).start()
                        # else: still in rapid mode, waiting for more successes
                    else:
                        # Normal up — clear any down state
                        was_confirmed_down = path in self._confirmed_down
                        down_since = self._down_since.pop(path, None)
                        self._confirmed_down.discard(path)
                        database.store_result(path, True, latency)

                        if was_confirmed_down:
                            threading.Thread(
                                target=alerter.notify_up,
                                args=(path, name, host, down_since),
                                daemon=True
                            ).start()
                else:
                    # Ping burst failed
                    if path in self._rapid_hosts:
                        # Reset recovery streak on failure during rapid mode
                        self._recovery_streak[path] = 0
                    else:
                        # First failure — enter rapid-retry mode
                        first_time_down = path not in self._confirmed_down
                        self._confirmed_down.add(path)
                        self._rapid_hosts.add(path)
                        self._recovery_streak[path] = 0
                        if first_time_down:
                            self._down_since[path] = int(time.time())
                            print(f"[pinger] {host} ({path}): all {self.ping_count} pings failed — rapid retry every {self.rapid_retry_interval}s")
                            threading.Thread(
                                target=alerter.notify_down,
                                args=(path, name, host),
                                daemon=True
                            ).start()
                    database.store_result(path, False, None)

        except Exception as e:
            print(f"[pinger] Error pinging {host}: {e}")
        finally:
            with self._lock:
                self._in_flight.discard(path)
                self._last_ping[path] = time.time()
