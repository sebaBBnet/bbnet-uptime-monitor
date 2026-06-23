"""
Email alerting for BBnet Uptime Monitor.

Sends:
  - Down alert when a host is confirmed down (after consecutive failure threshold)
  - Recovery alert when a host comes back up
  - Daily report   every day at configured time  — outages last 24h + uptime per site
  - Weekly report  every Monday (same time)       — uptime per site, 7-day window
  - Monthly report 1st of each month (same time)  — uptime per site, 30-day window
"""
import smtplib
import threading
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import database
import tree as tree_mgr

_config: dict = {}
_lock = threading.Lock()

# Tracks hosts for which the DOWN email has been sent
_alerted_down: set = set()
# Pending timers: host_path -> threading.Timer (down email not yet sent)
_pending_timers: dict = {}

_DOWN_ALERT_DELAY = 300  # seconds before sending a down alert (5 minutes)

# Rate limit: max 10 alert emails per minute
_alert_timestamps: list = []
_MAX_ALERTS_PER_MINUTE = 10

# Startup grace period — suppress down alerts for this many seconds after init
_STARTUP_GRACE = 300   # 5 minutes
_start_time: float = time.time()


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

def init(config: dict):
    global _config
    _config = config.get('alerts', {})
    if _config.get('enabled'):
        t = threading.Thread(target=_report_loop, daemon=True, name='alerter-reports')
        t.start()
        report_time = _config.get('daily_summary_time', '08:00')
        print(f"[alerter] Enabled — daily/weekly/monthly reports at {report_time}")
    else:
        print("[alerter] Disabled (set alerts.enabled: true in config.yml to enable)")


# ---------------------------------------------------------------------------
# Core email sender
# ---------------------------------------------------------------------------

def _send_email(subject: str, body_html: str, body_text: str, bypass_rate_limit: bool = False):
    """Send an email via SMTP TLS. Returns True on success."""
    cfg = _config

    # Rate-limit real-time alerts: max 10 per minute (reports bypass this)
    if not bypass_rate_limit:
        now = time.time()
        with _lock:
            # Drop timestamps older than 60s
            _alert_timestamps[:] = [t for t in _alert_timestamps if now - t < 60]
            if len(_alert_timestamps) >= _MAX_ALERTS_PER_MINUTE:
                print(f"[alerter] Rate-limited ({len(_alert_timestamps)}/min) — skipping: {subject}")
                return False
            _alert_timestamps.append(now)

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = cfg.get('from_address', cfg.get('smtp_user', ''))
        msg['To']      = ', '.join(cfg.get('to_addresses', []))

        msg.attach(MIMEText(body_text, 'plain'))
        msg.attach(MIMEText(body_html, 'html'))

        with smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port'], timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(cfg['smtp_user'], cfg['smtp_password'])
            smtp.sendmail(msg['From'], cfg.get('to_addresses', []), msg.as_string())

        print(f"[alerter] Email sent: {subject}")
        return True
    except Exception as e:
        print(f"[alerter] Failed to send email: {e}")
        return False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _fmt_time(ts):
    if ts is None:
        return '—'
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')


def _fmt_duration(seconds: int) -> str:
    if seconds is None or seconds < 0:
        return '—'
    if seconds < 60:
        return f"{seconds}s"
    m = seconds // 60
    h = m // 60
    m = m % 60
    if h:
        return f"{h}h {m}m" if m else f"{h}h"
    return f"{m}m"


def _uptime_color(pct) -> str:
    """Return a hex color based on uptime percentage."""
    if pct is None:
        return '#718096'
    if pct >= 99.9:
        return '#276749'   # dark green
    if pct >= 99.0:
        return '#38a169'   # green
    if pct >= 95.0:
        return '#d97706'   # amber
    if pct >= 90.0:
        return '#dd6b20'   # orange
    return '#c53030'       # red


def _uptime_badge(pct) -> str:
    """Return an HTML span with coloured uptime percentage."""
    if pct is None:
        return '<span style="color:#718096">N/A</span>'
    color = _uptime_color(pct)
    return f'<span style="color:{color};font-weight:bold">{pct:.2f}%</span>'


# ---------------------------------------------------------------------------
# Real-time down / recovery alerts
# ---------------------------------------------------------------------------

def notify_down(host_path: str, host_name: str, host_ip: str):
    """Called by pinger when a host is confirmed down.
    Email is delayed by _DOWN_ALERT_DELAY seconds — cancelled if host recovers first."""
    if not _config.get('enabled'):
        return
    if time.time() - _start_time < _STARTUP_GRACE:
        return  # Suppress alerts during startup grace period
    with _lock:
        if host_path in _alerted_down or host_path in _pending_timers:
            return  # Already alerted or timer already running

    detected_at = int(time.time())

    def _fire():
        with _lock:
            _pending_timers.pop(host_path, None)
            if host_path in _alerted_down:
                return  # notify_up already ran and cleared this
            _alerted_down.add(host_path)

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
  <tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Detected</td>
      <td style="padding:6px 12px">{_fmt_time(detected_at)}</td></tr>
</table>
<p style="color:#718096;font-size:12px;margin-top:24px">BBnet Uptime Monitor</p>
</body></html>"""
        body_text = (
            f"HOST DOWN\n\nHost: {host_name}\nIP: {host_ip}\n"
            f"Path: {host_path}\nDetected: {_fmt_time(detected_at)}"
        )
        _send_email(subject, body_html, body_text)

    timer = threading.Timer(_DOWN_ALERT_DELAY, _fire)
    timer.daemon = True
    with _lock:
        _pending_timers[host_path] = timer
    timer.start()


def notify_up(host_path: str, host_name: str, host_ip: str, down_since: int = None):
    """Called by pinger when a host recovers."""
    if not _config.get('enabled'):
        return
    with _lock:
        # Cancel pending timer if host recovered before the delay fired
        timer = _pending_timers.pop(host_path, None)
        was_alerted = host_path in _alerted_down
        _alerted_down.discard(host_path)

    if timer:
        timer.cancel()
        return  # Never sent the down email, so no recovery email needed

    if not was_alerted:
        return

    now = int(time.time())
    duration = ''
    if down_since:
        duration = _fmt_duration(now - down_since)

    subject = f"🟢 RECOVERED: {host_name} ({host_ip})"

    dur_row = (
        f'<tr><td style="padding:6px 12px;font-weight:bold;background:#f7f7f7">Outage duration</td>'
        f'<td style="padding:6px 12px">{duration}</td></tr>'
        if duration else ''
    )

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
  {dur_row}
</table>
<p style="color:#718096;font-size:12px;margin-top:24px">BBnet Uptime Monitor</p>
</body></html>"""

    body_text = (
        f"HOST RECOVERED\n\nHost: {host_name}\nIP: {host_ip}\n"
        f"Path: {host_path}\nRecovered: {_fmt_time(now)}"
        + (f"\nDowntime: {duration}" if duration else "")
    )
    threading.Thread(target=_send_email, args=(subject, body_html, body_text), daemon=True).start()


# ---------------------------------------------------------------------------
# Shared report data builder
# ---------------------------------------------------------------------------

def _build_report_data(hours: int) -> dict:
    """
    Collect per-top-level-page uptime data for the given time window.

    Returns:
      top_pages       — list of page dicts with name, active_leaves, uptime
      total_uptime    — aggregate uptime across all active hosts
      all_paused      — all paused leaf dicts across all pages
      all_active_paths— flat list of all active (non-paused) host paths
    """
    paused_set  = database.get_all_paused()
    top_pages   = tree_mgr.get_children('') or []

    report_pages     = []
    all_active_paths = []
    all_paused       = []

    for page in top_pages:
        leaves = tree_mgr.get_leaves_under(page['path']) or []
        active = [l for l in leaves if l['path'] not in paused_set]
        paused = [l for l in leaves if l['path'] in paused_set]
        paths  = [l['path'] for l in active]
        uptime = database.get_uptime_multi(paths, hours) if paths else None

        report_pages.append({
            'name':          page['name'],
            'path':          page['path'],
            'active_leaves': active,
            'active_paths':  paths,
            'paused_leaves': paused,
            'uptime':        uptime,
        })
        all_active_paths.extend(paths)
        all_paused.extend(paused)

    total_uptime = database.get_uptime_multi(all_active_paths, hours) if all_active_paths else None

    return {
        'top_pages':        report_pages,
        'total_uptime':     total_uptime,
        'all_paused':       all_paused,
        'all_active_paths': all_active_paths,
    }


# ---------------------------------------------------------------------------
# HTML building helpers
# ---------------------------------------------------------------------------

_EMAIL_STYLE = """
  body { font-family: Arial, Helvetica, sans-serif; background: #f0f2f5;
         margin: 0; padding: 20px; color: #1a1a1a; }
  .wrap { max-width: 680px; margin: 0 auto; background: #fff;
          border-radius: 8px; overflow: hidden;
          box-shadow: 0 2px 12px rgba(0,0,0,0.12); }
  .hdr  { padding: 28px 32px; }
  .hdr h1 { margin: 0 0 6px; font-size: 20px; color: #fff; }
  .hdr p  { margin: 0; font-size: 13px; color: rgba(255,255,255,0.75); }
  .hero { text-align: center; padding: 28px 32px;
          border-bottom: 1px solid #e8e8e8; }
  .hero .pct { font-size: 52px; font-weight: bold; margin: 0; }
  .hero .lbl { font-size: 13px; color: #718096; margin: 4px 0 0; }
  .section { padding: 24px 32px; }
  .section h2 { font-size: 15px; margin: 0 0 14px; color: #2d3748; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #f7f8fa; padding: 8px 12px; text-align: left;
       font-weight: 600; color: #4a5568; border-bottom: 2px solid #e2e8f0; }
  td { padding: 7px 12px; border-bottom: 1px solid #edf2f7; }
  tr:last-child td { border-bottom: none; }
  .ongoing { color: #c53030; font-style: italic; }
  .ftr { padding: 16px 32px; background: #f7f8fa;
         border-top: 1px solid #e8e8e8;
         font-size: 11px; color: #a0aec0; }
"""


def _email_wrap(header_color: str, icon: str, title: str, subtitle: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<style>{_EMAIL_STYLE}</style>
</head>
<body>
<div class="wrap">
  <div class="hdr" style="background:{header_color}">
    <h1>{icon} {title}</h1>
    <p>{subtitle}</p>
  </div>
  {body}
  <div class="ftr">BBnet Uptime Monitor &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
</div>
</body></html>"""


def _uptime_table(top_pages: list) -> str:
    rows = ''
    for p in top_pages:
        uptime_html = _uptime_badge(p['uptime'])
        rows += (
            f"<tr><td><strong>{p['name']}</strong></td>"
            f"<td style='text-align:right'>{uptime_html}</td>"
            f"<td style='text-align:right;color:#718096'>{len(p['active_leaves'])} hosts</td></tr>\n"
        )
    return f"""
<table>
  <thead><tr>
    <th>Site</th>
    <th style="text-align:right">Uptime</th>
    <th style="text-align:right">Active hosts</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def _paused_section(all_paused: list) -> str:
    if not all_paused:
        return ''
    rows = ''.join(
        f"<tr><td>⏸ {l['name']}</td><td style='color:#718096'>{l['host']}</td></tr>\n"
        for l in sorted(all_paused, key=lambda x: x['name'])
    )
    return f"""
<div class="section" style="border-top:1px solid #e8e8e8">
  <h2>⏸ Paused Hosts ({len(all_paused)})</h2>
  <table>
    <thead><tr><th>Host</th><th>IP Address</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""


# ---------------------------------------------------------------------------
# Outage section (daily only)
# ---------------------------------------------------------------------------

def _outage_section(top_pages: list, since: int, until: int) -> str:
    """
    Build the outages HTML section for the daily report.
    Groups outages by top-level page. Shows name, IP, start time, duration.
    """
    # Build a path → leaf lookup for name and IP
    path_to_leaf: dict = {}
    for page in top_pages:
        for leaf in page['active_leaves']:
            path_to_leaf[leaf['path']] = leaf

    total_outages = 0
    section_html  = ''

    for page in top_pages:
        if not page['active_paths']:
            continue
        outages = database.get_outages_in_period(page['active_paths'], since, until)
        if not outages:
            continue

        total_outages += len(outages)
        rows = ''
        for o in sorted(outages, key=lambda x: x['start']):
            leaf      = path_to_leaf.get(o['host_path'], {})
            name      = leaf.get('name', o['host_path'])
            ip        = leaf.get('host', '—')
            started   = _fmt_time(o['start'])
            if o['ongoing']:
                duration = f'<span class="ongoing">ongoing ({_fmt_duration(o["duration_seconds"])} so far)</span>'
            else:
                duration = _fmt_duration(o['duration_seconds'])
            rows += (
                f"<tr><td>{name}</td>"
                f"<td style='color:#718096'>{ip}</td>"
                f"<td>{started}</td>"
                f"<td>{duration}</td></tr>\n"
            )

        section_html += f"""
<div style="margin-bottom:20px">
  <h3 style="font-size:14px;margin:0 0 8px;color:#c53030">{page['name']}</h3>
  <table>
    <thead><tr>
      <th>Host</th><th>IP Address</th><th>Started</th><th>Duration</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    if not section_html:
        return """
<div class="section" style="border-top:1px solid #e8e8e8">
  <h2>🔴 Outages (last 24 hours)</h2>
  <p style="color:#276749;font-size:13px">✅ No outages recorded in the last 24 hours.</p>
</div>"""

    return f"""
<div class="section" style="border-top:1px solid #e8e8e8">
  <h2>🔴 Outages — last 24 hours ({total_outages} total)</h2>
  {section_html}
</div>"""


# ---------------------------------------------------------------------------
# Report senders
# ---------------------------------------------------------------------------

def send_daily_report():
    """Build and send the daily report (outages + uptime per site)."""
    if not _config.get('enabled'):
        return

    now   = int(time.time())
    since = now - 86400  # last 24 hours
    data  = _build_report_data(hours=24)

    if not data['all_active_paths'] and not data['all_paused']:
        print("[alerter] No hosts found; skipping daily report")
        return

    date_str     = datetime.now().strftime('%Y-%m-%d')
    total_uptime = data['total_uptime']
    pct_str      = f"{total_uptime:.2f}%" if total_uptime is not None else "N/A"
    pct_color    = _uptime_color(total_uptime)
    subject      = f"📊 Daily Report — {date_str} — Overall: {pct_str}"

    hero = f"""
<div class="hero">
  <p class="pct" style="color:{pct_color}">{pct_str}</p>
  <p class="lbl">Overall uptime — last 24 hours</p>
</div>"""

    site_section = f"""
<div class="section" style="border-top:1px solid #e8e8e8">
  <h2>📍 Uptime by Site — last 24 hours</h2>
  {_uptime_table(data['top_pages'])}
</div>"""

    outage_section = _outage_section(data['top_pages'], since, now)
    paused_section = _paused_section(data['all_paused'])

    body = hero + site_section + outage_section + paused_section

    body_html = _email_wrap(
        header_color='#1e40af',
        icon='📊',
        title='Daily Report',
        subtitle=date_str,
        body=body,
    )
    body_text = (
        f"Daily Report — {date_str}\n"
        f"Overall uptime (24h): {pct_str}\n\n"
        + "\n".join(
            f"  {p['name']}: {p['uptime']:.2f}% ({len(p['active_leaves'])} hosts)"
            if p['uptime'] is not None else f"  {p['name']}: N/A"
            for p in data['top_pages']
        )
        + (f"\n\n{len(data['all_paused'])} paused host(s)" if data['all_paused'] else '')
    )
    _send_email(subject, body_html, body_text, bypass_rate_limit=True)


def send_weekly_report():
    """Build and send the Monday weekly report (uptime per site, 7-day window)."""
    if not _config.get('enabled'):
        return

    data     = _build_report_data(hours=168)
    date_str = datetime.now().strftime('%Y-%m-%d')

    if not data['all_active_paths'] and not data['all_paused']:
        return

    total_uptime = data['total_uptime']
    pct_str      = f"{total_uptime:.2f}%" if total_uptime is not None else "N/A"
    pct_color    = _uptime_color(total_uptime)
    subject      = f"📅 Weekly Report — w/e {date_str} — Overall: {pct_str}"

    hero = f"""
<div class="hero">
  <p class="pct" style="color:{pct_color}">{pct_str}</p>
  <p class="lbl">Overall uptime — last 7 days</p>
</div>"""

    site_section = f"""
<div class="section" style="border-top:1px solid #e8e8e8">
  <h2>📍 Uptime by Site — last 7 days</h2>
  {_uptime_table(data['top_pages'])}
</div>"""

    paused_section = _paused_section(data['all_paused'])

    body_html = _email_wrap(
        header_color='#2f855a',
        icon='📅',
        title='Weekly Report',
        subtitle=f"Week ending {date_str}",
        body=hero + site_section + paused_section,
    )
    body_text = (
        f"Weekly Report — week ending {date_str}\n"
        f"Overall uptime (7d): {pct_str}\n\n"
        + "\n".join(
            f"  {p['name']}: {p['uptime']:.2f}%" if p['uptime'] is not None else f"  {p['name']}: N/A"
            for p in data['top_pages']
        )
    )
    _send_email(subject, body_html, body_text)


def send_monthly_report():
    """Build and send the 1st-of-month report (uptime per site, 30-day window)."""
    if not _config.get('enabled'):
        return

    data     = _build_report_data(hours=720)
    now_dt   = datetime.now()
    # Report covers the previous calendar month
    month_str = now_dt.strftime('%B %Y')
    date_str  = now_dt.strftime('%Y-%m-%d')

    if not data['all_active_paths'] and not data['all_paused']:
        return

    total_uptime = data['total_uptime']
    pct_str      = f"{total_uptime:.2f}%" if total_uptime is not None else "N/A"
    pct_color    = _uptime_color(total_uptime)
    subject      = f"🗓 Monthly Report — {month_str} — Overall: {pct_str}"

    hero = f"""
<div class="hero">
  <p class="pct" style="color:{pct_color}">{pct_str}</p>
  <p class="lbl">Overall uptime — last 30 days</p>
</div>"""

    site_section = f"""
<div class="section" style="border-top:1px solid #e8e8e8">
  <h2>📍 Uptime by Site — last 30 days</h2>
  {_uptime_table(data['top_pages'])}
</div>"""

    paused_section = _paused_section(data['all_paused'])

    body_html = _email_wrap(
        header_color='#6b21a8',
        icon='🗓',
        title='Monthly Report',
        subtitle=month_str,
        body=hero + site_section + paused_section,
    )
    body_text = (
        f"Monthly Report — {month_str}\n"
        f"Overall uptime (30d): {pct_str}\n\n"
        + "\n".join(
            f"  {p['name']}: {p['uptime']:.2f}%" if p['uptime'] is not None else f"  {p['name']}: N/A"
            for p in data['top_pages']
        )
    )
    _send_email(subject, body_html, body_text)


# ---------------------------------------------------------------------------
# Scheduler loop
# ---------------------------------------------------------------------------

def _report_loop():
    """
    Background thread. Fires at configured time daily.
    Also sends weekly report on Monday and monthly report on the 1st.
    """
    summary_time = _config.get('daily_summary_time', '08:00')
    try:
        fire_h, fire_m = map(int, summary_time.split(':'))
    except Exception:
        fire_h, fire_m = 8, 0

    print(f"[alerter] Reports scheduled at {fire_h:02d}:{fire_m:02d} "
          f"(weekly=Monday, monthly=1st of month)")

    last_daily_day   = -1
    last_weekly_week = -1
    last_monthly_mon = -1

    while True:
        now = datetime.now()

        if now.hour == fire_h and now.minute == fire_m:
            # --- Daily (every day) ---
            if now.day != last_daily_day:
                try:
                    send_daily_report()
                    last_daily_day = now.day
                except Exception as e:
                    print(f"[alerter] Daily report error: {e}")

            # --- Weekly (Monday only) ---
            iso_week = now.isocalendar()[1]
            if now.weekday() == 0 and iso_week != last_weekly_week:
                try:
                    send_weekly_report()
                    last_weekly_week = iso_week
                except Exception as e:
                    print(f"[alerter] Weekly report error: {e}")

            # --- Monthly (1st of month only) ---
            month_key = now.year * 100 + now.month
            if now.day == 1 and month_key != last_monthly_mon:
                try:
                    send_monthly_report()
                    last_monthly_mon = month_key
                except Exception as e:
                    print(f"[alerter] Monthly report error: {e}")

        time.sleep(30)
