"""
Email alerting for BBnet Uptime Monitor.

Sends:
  - Down alert when a host is confirmed down (after consecutive failure threshold)
  - Recovery alert when a host comes back up
  - Daily summary at configured time
"""
import smtplib
import threading
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import database
import tree as tree_mgr

_config = {}
_lock = threading.Lock()
# Tracks hosts currently in alerted-down state to avoid repeat down alerts
_alerted_down: set = set()


def init(config: dict):
    global _config
    _config = config.get('alerts', {})
    if _config.get('enabled'):
        t = threading.Thread(target=_daily_summary_loop, daemon=True, name='alerter-daily')
        t.start()
        print(f"[alerter] Enabled — daily summary at {_config.get('daily_summary_time', '08:00')}")
    else:
        print("[alerter] Disabled (set alerts.enabled: true in config.yml to enable)")


def _send_email(subject: str, body_html: str, body_text: str):
    """Send an email via SMTP. Returns True on success."""
    cfg = _config
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = cfg.get('from_address', cfg.get('smtp_user', ''))
        msg['To']      = ', '.join(cfg.get('to_addresses', []))

        msg.attach(MIMEText(body_text, 'plain'))
        msg.attach(MIMEText(body_html, 'html'))

        with smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port'], timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(cfg['smtp_user'], cfg['smtp_password'])
            smtp.sendmail(msg['From'], cfg.get('to_addresses', []), msg.as_string())

        print(f"[alerter] Email sent: {subject}")
        return True
    except Exception as e:
        print(f"[alerter] Failed to send email: {e}")
        return False


def _fmt_time(ts):
    if ts is None:
        return '—'
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def notify_down(host_path: str, host_name: str, host_ip: str):
    """Called by pinger when a host is confirmed down."""
    if not _config.get('enabled'):
        return
    with _lock:
        if host_path in _alerted_down:
            return  # Already sent down alert
        _alerted_down.add(host_path)

    now = int(time.time())
    subject = f"🔴 DOWN: {host_name} ({host_ip})"

    body_html = f"""
<html><body style="font-family:sans-serif;color:#1a1a1a">
<h2 style="color:#c53030">🔴 Host Down</h2>
<table style="border-collapse:collapse;width:100%;max-width:500px">
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Host</td>
      <td style="padding:6px 12px">{host_name}</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">IP Address</td>
      <td style="padding:6px 12px">{host_ip}</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Path</td>
      <td style="padding:6px 12px">{host_path}</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Time</td>
      <td style="padding:6px 12px">{_fmt_time(now)}</td></tr>
</table>
<p style="color:#718096;font-size:12px;margin-top:24px">BBnet Uptime Monitor</p>
</body></html>"""

    body_text = f"HOST DOWN\n\nHost: {host_name}\nIP: {host_ip}\nPath: {host_path}\nTime: {_fmt_time(now)}"
    threading.Thread(target=_send_email, args=(subject, body_html, body_text), daemon=True).start()


def notify_up(host_path: str, host_name: str, host_ip: str, down_since: int = None):
    """Called by pinger when a host recovers."""
    if not _config.get('enabled'):
        return
    with _lock:
        was_alerted = host_path in _alerted_down
        _alerted_down.discard(host_path)

    if not was_alerted:
        return  # No down alert was sent, skip recovery

    now = int(time.time())
    duration = ''
    if down_since:
        secs = now - down_since
        h, m = divmod(secs // 60, 60)
        duration = f"{h}h {m}m" if h else f"{m}m"

    subject = f"🟢 RECOVERED: {host_name} ({host_ip})"

    body_html = f"""
<html><body style="font-family:sans-serif;color:#1a1a1a">
<h2 style="color:#276749">🟢 Host Recovered</h2>
<table style="border-collapse:collapse;width:100%;max-width:500px">
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Host</td>
      <td style="padding:6px 12px">{host_name}</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">IP Address</td>
      <td style="padding:6px 12px">{host_ip}</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Path</td>
      <td style="padding:6px 12px">{host_path}</td></tr>
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Recovered at</td>
      <td style="padding:6px 12px">{_fmt_time(now)}</td></tr>
  {f'<tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Outage duration</td><td style="padding:6px 12px">{duration}</td></tr>' if duration else ''}
</table>
<p style="color:#718096;font-size:12px;margin-top:24px">BBnet Uptime Monitor</p>
</body></html>"""

    body_text = f"HOST RECOVERED\n\nHost: {host_name}\nIP: {host_ip}\nPath: {host_path}\nRecovered: {_fmt_time(now)}" + (f"\nDowntime: {duration}" if duration else "")
    threading.Thread(target=_send_email, args=(subject, body_html, body_text), daemon=True).start()


def send_daily_summary():
    """Build and send the daily summary email."""
    if not _config.get('enabled'):
        return

    leaves = tree_mgr.get_all_leaves()
    if not leaves:
        return

    leaf_paths = [l['path'] for l in leaves]
    latest = database.get_latest_results_batch(leaf_paths)
    paused = database.get_all_paused()

    up_hosts, down_hosts, paused_hosts, unknown_hosts = [], [], [], []
    for leaf in leaves:
        p = leaf['path']
        if p in paused:
            paused_hosts.append(leaf)
            continue
        row = latest.get(p)
        if row is None:
            unknown_hosts.append(leaf)
        elif row['is_up']:
            up_hosts.append((leaf, row))
        else:
            down_hosts.append((leaf, row))

    total = len(leaves)
    now = datetime.now().strftime('%Y-%m-%d')
    subject = f"📊 Daily Summary — {now} — {len(up_hosts)}/{total} hosts up"

    def host_rows(items, show_latency=False):
        rows = ''
        for item in items:
            leaf = item[0] if isinstance(item, tuple) else item
            row  = item[1] if isinstance(item, tuple) else None
            lat  = f"{row['latency_ms']:.1f} ms" if (row and row['latency_ms']) else '—'
            rows += f"<tr><td style='padding:4px 8px'>{leaf['name']}</td><td style='padding:4px 8px;color:#718096'>{leaf['host']}</td>"
            if show_latency:
                rows += f"<td style='padding:4px 8px'>{lat}</td>"
            rows += "</tr>"
        return rows

    def section(title, color, items, show_latency=False):
        if not items:
            return ''
        extra_col = '<th style="padding:4px 8px">Latency</th>' if show_latency else ''
        return f"""
<h3 style="color:{color};margin-top:24px">{title} ({len(items)})</h3>
<table style="border-collapse:collapse;width:100%;max-width:600px;font-size:13px">
<thead><tr style="background:#f0f0f0">
  <th style="padding:4px 8px;text-align:left">Host</th>
  <th style="padding:4px 8px;text-align:left">IP</th>
  {extra_col}
</tr></thead>
<tbody>{host_rows(items, show_latency)}</tbody>
</table>"""

    body_html = f"""
<html><body style="font-family:sans-serif;color:#1a1a1a">
<h2>📊 Daily Uptime Summary — {now}</h2>
<p><strong>{len(up_hosts)}</strong> up &nbsp;|&nbsp; <strong style="color:#c53030">{len(down_hosts)}</strong> down &nbsp;|&nbsp; {len(paused_hosts)} paused &nbsp;|&nbsp; {len(unknown_hosts)} unknown &nbsp;|&nbsp; {total} total</p>
{section('🔴 Down', '#c53030', down_hosts)}
{section('🟡 Paused', '#b7791f', paused_hosts)}
{section('🟢 Up', '#276749', up_hosts, show_latency=True)}
<p style="color:#718096;font-size:12px;margin-top:32px">BBnet Uptime Monitor — daily summary</p>
</body></html>"""

    body_text = f"Daily Uptime Summary — {now}\n{len(up_hosts)} up | {len(down_hosts)} down | {len(paused_hosts)} paused | {total} total"
    _send_email(subject, body_html, body_text)


def _daily_summary_loop():
    """Background thread — fires daily summary at configured time."""
    summary_time = _config.get('daily_summary_time', '08:00')
    try:
        h, m = map(int, summary_time.split(':'))
    except Exception:
        h, m = 8, 0

    print(f"[alerter] Daily summary scheduled at {h:02d}:{m:02d}")
    last_sent_day = -1

    while True:
        now = datetime.now()
        if now.hour == h and now.minute == m and now.day != last_sent_day:
            try:
                send_daily_summary()
                last_sent_day = now.day
            except Exception as e:
                print(f"[alerter] Daily summary error: {e}")
        time.sleep(30)
