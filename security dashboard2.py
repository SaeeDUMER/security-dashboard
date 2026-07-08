import calendar as cal_module
import ipaddress
import json
import platform
import queue
import random
import re
import socket
import subprocess
import threading
import uuid
import getpass
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

# ---------------------------------------------------------------------------
# Palette — dark purple base with neon accents
# ---------------------------------------------------------------------------

BG_MAIN = "#150821"
BG_SIDEBAR = "#1b0d30"
BG_CARD = "#211141"
BG_CARD_ALT = "#291752"
BG_TRACK = "#3a2568"
TEXT_PRIMARY = "#f2edfb"
TEXT_MUTED = "#9483b5"
BORDER = "#3a2568"

CYAN = "#22d3ee"
MAGENTA = "#ec4899"
YELLOW = "#facc15"
GREEN = "#34d399"
PURPLE = "#a78bfa"
ORANGE = "#fb923c"

SEVERITY_COLORS = {"Critical": MAGENTA, "High": ORANGE, "Medium": YELLOW, "Low": CYAN}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}
MAX_SCAN_HOSTS = 256
COVERAGE_DOMAINS = ["Network", "Endpoint", "Cloud", "Identity", "Data"]

# ---------------------------------------------------------------------------
# Real-time update cadence — everything on the dashboard streams on these
# timers instead of requiring a manual refresh.
# ---------------------------------------------------------------------------
LIVE_TICK_SECONDS = 2          # trend chart / gauges / coverage / system chips
LIVE_ALERT_CHANCE = 0.35       # probability a new alert streams in each tick
LIVE_PROCESS_INTERVAL_MS = 3000  # process monitor refresh cadence

# ---------------------------------------------------------------------------
# Config persistence — API keys, scan timeout, theme preference
# ---------------------------------------------------------------------------

CONFIG_PATH = Path.home() / ".sentinel_config.json"
DEFAULT_CONFIG = {
    "abuseipdb_key": "",
    "virustotal_key": "",
    "scan_timeout": 0.4,
    "theme": "dark",
}


def load_config():
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            merged = dict(DEFAULT_CONFIG)
            merged.update(data)
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Real system info (psutil / socket / platform) — no mock data here
# ---------------------------------------------------------------------------

def get_mac_address():
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -8, -8))


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "Unavailable"


def get_public_ip():
    if requests is None:
        return "requests not installed"
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=3)
        return resp.json().get("ip", "Unavailable")
    except Exception:
        return "Unavailable (offline?)"


def get_system_snapshot():
    """Real, live system info. Returns a dict of label -> value strings."""
    info = {
        "Hostname": socket.gethostname(),
        "OS": f"{platform.system()} {platform.release()}",
        "User": getpass.getuser(),
        "Local IP": get_local_ip(),
        "MAC": get_mac_address(),
    }
    if psutil:
        info["CPU"] = f"{psutil.cpu_percent(interval=0.2)}%"
        info["RAM"] = f"{psutil.virtual_memory().percent}%"
        try:
            info["Disk"] = f"{psutil.disk_usage('/').percent}%"
        except Exception:
            info["Disk"] = "N/A"
        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot
        info["Uptime"] = f"{uptime.days}d {uptime.seconds // 3600}h"
        info["Processes"] = str(len(psutil.pids()))
    else:
        for k in ("CPU", "RAM", "Disk", "Uptime", "Processes"):
            info[k] = "psutil not installed"
    return info


# ---------------------------------------------------------------------------
# Process monitor (real, via psutil)
# ---------------------------------------------------------------------------

def list_processes():
    if psutil is None:
        return []
    rows = []
    for proc in psutil.process_iter(["pid", "name", "username", "memory_percent", "status"]):
        try:
            info = proc.info
            rows.append({
                "pid": info["pid"],
                "name": info["name"] or "?",
                "user": (info["username"] or "?")[:20],
                "cpu": round(proc.cpu_percent(interval=None), 1),
                "mem": round(info["memory_percent"] or 0, 1),
                "status": info["status"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rows


# ---------------------------------------------------------------------------
# Threat intelligence lookups (real API calls — need your own key + internet)
# ---------------------------------------------------------------------------

def lookup_abuseipdb(ip, api_key):
    if requests is None:
        return {"error": "The 'requests' library isn't installed (pip install requests)."}
    if not api_key:
        return {"error": "No AbuseIPDB API key set. Add one in Settings."}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=8,
        )
        if resp.status_code != 200:
            return {"error": f"AbuseIPDB returned HTTP {resp.status_code}: {resp.text[:200]}"}
        data = resp.json().get("data", {})
        return {
            "IP": data.get("ipAddress", ip),
            "Abuse confidence score": f"{data.get('abuseConfidenceScore', '?')}%",
            "Country": data.get("countryCode", "?"),
            "ISP": data.get("isp", "?"),
            "Total reports": data.get("totalReports", "?"),
            "Is public": data.get("isPublic", "?"),
        }
    except Exception as exc:
        return {"error": f"Request failed: {exc}"}


def lookup_virustotal(indicator, api_key):
    if requests is None:
        return {"error": "The 'requests' library isn't installed (pip install requests)."}
    if not api_key:
        return {"error": "No VirusTotal API key set. Add one in Settings."}
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator))
    endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}" if is_ip \
        else f"https://www.virustotal.com/api/v3/files/{indicator}"
    try:
        resp = requests.get(endpoint, headers={"x-apikey": api_key}, timeout=8)
        if resp.status_code != 200:
            return {"error": f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}"}
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "Indicator": indicator,
            "Malicious": stats.get("malicious", "?"),
            "Suspicious": stats.get("suspicious", "?"),
            "Harmless": stats.get("harmless", "?"),
            "Undetected": stats.get("undetected", "?"),
            "Reputation": attrs.get("reputation", "?"),
        }
    except Exception as exc:
        return {"error": f"Request failed: {exc}"}


# ---------------------------------------------------------------------------
# Mock data layer — security alerts / trend / coverage.
# Clearly sample data: there's no real SIEM/EDR feed wired in here.
# ---------------------------------------------------------------------------

ALERT_TEMPLATES = [
    ("Critical", "Brute-force login attempt", "auth-gateway-{n}"),
    ("Critical", "Malware signature detected", "WKS-{n}"),
    ("High", "Unpatched CVE-2026-{n}", "payments-api"),
    ("High", "Unusual outbound traffic", "db-cluster-{n}"),
    ("High", "Suspicious lateral movement", "srv-internal-{n}"),
    ("Medium", "Privilege escalation attempt", "svc-account-{n}"),
    ("Medium", "Repeated failed MFA challenge", "vpn-node-{n}"),
    ("Low", "TLS certificate expiring soon", "api.internal.example.com"),
    ("Low", "Outdated software version detected", "host-{n}"),
]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate_alert():
    severity, desc_template, source_template = random.choice(ALERT_TEMPLATES)
    n = random.randint(1, 200)
    desc = desc_template.format(n=n)
    source = source_template.format(n=n)
    minutes_ago = random.randint(0, 240)
    timestamp = datetime.now() - timedelta(minutes=minutes_ago)
    return {"severity": severity, "description": desc,
            "source": f"{source} ({random_ip()})", "time": timestamp}


def generate_initial_alerts(count=9):
    alerts = [generate_alert() for _ in range(count)]
    alerts.sort(key=lambda a: a["time"], reverse=True)
    return alerts


TREND_WINDOW = 24  # number of points kept on screen for the live trend chart
TREND_IS_REAL_DATA = psutil is not None  # True unless psutil isn't installed


def sample_network_kbps(prev_bytes, elapsed_seconds):
    """One real, live sample of this machine's network throughput in KB/s.

    Reads psutil's cumulative bytes-sent + bytes-received counter and turns
    the delta since the last call into a rate. This is genuine measured
    activity from the OS, not a simulation — a spike in this line means
    real traffic actually left or arrived on this machine.

    Returns (kbps, new_prev_bytes). On the first call (prev_bytes is None)
    there's no delta yet, so it returns 0.0 as the baseline.
    """
    counters = psutil.net_io_counters()
    total_bytes = counters.bytes_sent + counters.bytes_recv
    if prev_bytes is None:
        return 0.0, total_bytes
    delta_bytes = max(0, total_bytes - prev_bytes)
    kbps = (delta_bytes / 1024) / max(elapsed_seconds, 0.001)
    return round(kbps, 1), total_bytes


def sample_network_kbps_fallback(prev_value):
    """Used only when psutil isn't installed and no real network counters
    are available. Clearly a simulated wobble, not real traffic — the UI
    labels this state explicitly so it's never mistaken for live data."""
    base = prev_value if prev_value is not None else 40
    return max(0, round(base + random.uniform(-8, 10), 1))


def generate_coverage():
    return [(domain, random.randint(58, 99)) for domain in COVERAGE_DOMAINS]


def step_coverage(previous):
    """Small live jitter around the previous reading instead of a full
    re-roll, so the coverage rings drift realistically tick to tick."""
    stepped = []
    for domain, pct in previous:
        pct = max(40, min(100, pct + random.randint(-3, 3)))
        stepped.append((domain, pct))
    return stepped


def compute_kpis(alerts, prev_kpis=None):
    active_threats = sum(1 for a in alerts if a["severity"] in ("Critical", "High"))
    if prev_kpis is None:
        blocked = random.randint(1100, 1400)
        vulns = random.randint(15, 30)
    else:
        blocked = max(0, prev_kpis["blocked_24h"] + random.randint(-4, 12))
        vulns = max(0, prev_kpis["open_vulns"] + random.choice([-1, 0, 0, 0, 1]))
    return {
        "active_threats": active_threats,
        "blocked_24h": blocked,
        "open_vulns": vulns,
        "uptime": round(random.uniform(99.90, 99.99), 2),
    }


# ---------------------------------------------------------------------------
# IP scanner — real ping sweep + common TCP port check (stdlib only)
# ---------------------------------------------------------------------------

def parse_targets(target_str):
    target_str = target_str.strip()
    if "/" in target_str:
        network = ipaddress.ip_network(target_str, strict=False)
        hosts = list(network.hosts()) or list(network)
        return [str(h) for h in hosts]
    if "-" in target_str and target_str.count(".") == 3:
        base, _, end = target_str.rpartition(".")
        start_last, _, end_last = end.partition("-")
        start_last, end_last = int(start_last), int(end_last)
        if start_last > end_last:
            raise ValueError("Range start must be less than range end.")
        return [f"{base}.{i}" for i in range(start_last, end_last + 1)]
    try:
        resolved = socket.gethostbyname(target_str)
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {target_str}")
    return [resolved]


def ping_host(ip, timeout=1):
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    timeout_value = str(int(timeout * 1000)) if is_windows else str(timeout)
    cmd = ["ping", count_flag, "1", timeout_flag, timeout_value, ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def scan_ports(ip, ports=COMMON_PORTS, timeout=0.4):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports


def scan_host(ip, timeout=0.4):
    up = ping_host(ip)
    open_ports = scan_ports(ip, timeout=timeout) if up else []
    return {"ip": ip, "up": up, "open_ports": open_ports}


IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def extract_ip(text):
    match = IP_PATTERN.search(text or "")
    return match.group(1) if match else None


def build_block_command(ip):
    system = platform.system().lower()
    if system == "windows":
        return (f'netsh advfirewall firewall add rule name="Block {ip}" '
                f'dir=in action=block remoteip={ip}')
    if system == "darwin":
        return f"echo 'block drop from {ip} to any' | sudo pfctl -ef -"
    return f"sudo iptables -A INPUT -s {ip} -j DROP"


# ---------------------------------------------------------------------------
# Reusable canvas widgets
# ---------------------------------------------------------------------------

class DonutGauge(tk.Canvas):
    def __init__(self, parent, size=104, thickness=10, **kwargs):
        super().__init__(parent, width=size, height=size + 20, bg=BG_CARD,
                          highlightthickness=0, **kwargs)
        self.size, self.thickness = size, thickness

    def draw(self, fraction, color, big_text, label_text):
        self.delete("all")
        pad = self.thickness
        x0, y0, x1, y1 = pad, pad, self.size - pad, self.size - pad
        self.create_oval(x0, y0, x1, y1, outline=BG_TRACK, width=self.thickness)
        fraction = max(0.0, min(1.0, fraction))
        if fraction > 0:
            self.create_arc(x0, y0, x1, y1, start=90, extent=-360 * fraction,
                             style="arc", outline=color, width=self.thickness)
        self.create_text(self.size / 2, self.size / 2, text=big_text,
                          font=("Helvetica", 15, "bold"), fill=TEXT_PRIMARY)
        self.create_text(self.size / 2, self.size + 8, text=label_text,
                          font=("Helvetica", 9), fill=TEXT_MUTED)


class SmallRing(tk.Canvas):
    def __init__(self, parent, size=64, thickness=7, **kwargs):
        super().__init__(parent, width=size, height=size + 18, bg=BG_CARD,
                          highlightthickness=0, **kwargs)
        self.size, self.thickness = size, thickness

    def draw(self, percent, color, label_text):
        self.delete("all")
        pad = self.thickness
        x0, y0, x1, y1 = pad, pad, self.size - pad, self.size - pad
        self.create_oval(x0, y0, x1, y1, outline=BG_TRACK, width=self.thickness)
        fraction = max(0.0, min(1.0, percent / 100))
        if fraction > 0:
            self.create_arc(x0, y0, x1, y1, start=90, extent=-360 * fraction,
                             style="arc", outline=color, width=self.thickness)
        self.create_text(self.size / 2, self.size / 2, text=f"{percent}%",
                          font=("Helvetica", 10, "bold"), fill=TEXT_PRIMARY)
        self.create_text(self.size / 2, self.size + 8, text=label_text,
                          font=("Helvetica", 8), fill=TEXT_MUTED)


class TrendChart(tk.Canvas):
    def __init__(self, parent, width=460, height=190, **kwargs):
        super().__init__(parent, width=width, height=height, bg=BG_CARD,
                          highlightthickness=0, **kwargs)
        self.width, self.height = width, height

    def draw(self, values, labels=None):
        """labels: optional list of x-axis strings (e.g. HH:MM:SS timestamps)
        matching values 1:1. Falls back to plain indices if omitted."""
        self.delete("all")
        pad_left, pad_bottom, pad_top, pad_right = 34, 22, 14, 12
        chart_w = self.width - pad_left - pad_right
        chart_h = self.height - pad_bottom - pad_top
        max_val = max(values) * 1.2 if values and max(values) > 0 else 1
        n = len(values)
        if not labels or len(labels) != n:
            labels = [str(i + 1) for i in range(n)]

        for i in range(4):
            y = pad_top + chart_h * i / 3
            self.create_line(pad_left, y, self.width - pad_right, y, fill=BORDER)
            val = round(max_val * (3 - i) / 3)
            self.create_text(pad_left - 6, y, text=str(val), anchor="e",
                              font=("Helvetica", 8), fill=TEXT_MUTED)

        points = []
        for i, v in enumerate(values):
            x = pad_left + (chart_w * i / (n - 1) if n > 1 else 0)
            y = pad_top + chart_h - (v / max_val) * chart_h
            points.append((x, y))

        fill_poly = [pad_left, pad_top + chart_h]
        for x, y in points:
            fill_poly.extend([x, y])
        fill_poly.extend([points[-1][0], pad_top + chart_h])
        self.create_polygon(fill_poly, fill="#123a52", outline="")

        for i in range(len(points) - 1):
            self.create_line(*points[i], *points[i + 1], fill=CYAN, width=2, smooth=True)
        # Thin out x-axis labels so they don't overlap on a wide live window.
        label_stride = max(1, n // 6)
        for i, (x, y) in enumerate(points):
            dot_r = 3 if i == len(points) - 1 else 2
            self.create_oval(x - dot_r, y - dot_r, x + dot_r, y + dot_r,
                              fill=CYAN, outline=BG_CARD)
            if i == len(points) - 1 or i % label_stride == 0:
                self.create_text(x, pad_top + chart_h + 12, text=labels[i],
                                  font=("Helvetica", 8), fill=TEXT_MUTED)


class Equalizer(tk.Canvas):
    def __init__(self, parent, width=280, height=190, **kwargs):
        super().__init__(parent, width=width, height=height, bg=BG_CARD,
                          highlightthickness=0, **kwargs)
        self.width, self.height = width, height

    def draw(self, items):
        self.delete("all")
        pad_bottom, pad_top = 24, 16
        chart_h = self.height - pad_bottom - pad_top
        max_val = max((v for _, v, _ in items), default=1) or 1
        n = len(items)
        slot = self.width / n
        bar_w = slot * 0.4

        for i, (label, value, color) in enumerate(items):
            bar_h = (value / max_val) * chart_h
            x0 = i * slot + (slot - bar_w) / 2
            x1 = x0 + bar_w
            y1 = pad_top + chart_h
            y0 = y1 - bar_h
            self.create_rectangle(x0, y0, x1, y1, fill=color, outline="")
            self.create_text((x0 + x1) / 2, y0 - 10, text=str(value),
                              font=("Helvetica", 9, "bold"), fill=TEXT_PRIMARY)
            self.create_text((x0 + x1) / 2, y1 + 12, text=label,
                              font=("Helvetica", 8), fill=TEXT_MUTED)


class MiniCalendar(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG_CARD, **kwargs)
        self._build()

    def _build(self):
        today = datetime.now()
        tk.Label(self, text=today.strftime("%B %Y"), font=("Helvetica", 11, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).grid(row=0, column=0, columnspan=7, pady=(0, 8))
        for col, day in enumerate(["M", "T", "W", "T", "F", "S", "S"]):
            tk.Label(self, text=day, font=("Helvetica", 9, "bold"), bg=BG_CARD,
                     fg=TEXT_MUTED, width=3).grid(row=1, column=col)
        weeks = cal_module.monthcalendar(today.year, today.month)
        for r, week in enumerate(weeks, start=2):
            for c, day in enumerate(week):
                if day == 0:
                    continue
                is_today = day == today.day
                tk.Label(
                    self, text=str(day), font=("Helvetica", 9, "bold" if is_today else "normal"),
                    width=3, pady=3, bg=CYAN if is_today else BG_CARD,
                    fg=BG_MAIN if is_today else TEXT_PRIMARY,
                ).grid(row=r, column=c)


def card(parent, **kwargs):
    return tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1, **kwargs)


def flat_button(parent, text, command, bg=BG_CARD_ALT, fg=TEXT_PRIMARY):
    return tk.Button(parent, text=text, command=command, relief="flat", bg=bg, fg=fg,
                      activebackground=BG_TRACK, activeforeground=TEXT_PRIMARY,
                      padx=12, pady=6, font=("Helvetica", 9), bd=0, cursor="hand2")


def stat_chip(parent, label, value):
    chip = tk.Frame(parent, bg=BG_CARD_ALT, padx=10, pady=6)
    tk.Label(chip, text=label, font=("Helvetica", 8), bg=BG_CARD_ALT, fg=TEXT_MUTED).pack(anchor="w")
    val_label = tk.Label(chip, text=value, font=("Helvetica", 10, "bold"), bg=BG_CARD_ALT, fg=TEXT_PRIMARY)
    val_label.pack(anchor="w")
    chip.value_label = val_label
    return chip


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class SecurityDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sentinel — Security Operations Console")
        self.geometry("1220x800")
        self.configure(bg=BG_MAIN)
        self.minsize(1040, 700)

        self.config_data = load_config()
        self.alerts = generate_initial_alerts()
        # The trend chart now tracks real, live network throughput (KB/s)
        # read from psutil. There's no history before the app started, so
        # it seeds with a single baseline reading and fills in for real as
        # ticks arrive — no fabricated past data points.
        self._net_prev_bytes = None
        if TREND_IS_REAL_DATA:
            first_kbps, self._net_prev_bytes = sample_network_kbps(None, LIVE_TICK_SECONDS)
        else:
            first_kbps = sample_network_kbps_fallback(None)
        self.trend = [first_kbps]
        self.trend_times = [datetime.now()]
        self.coverage = generate_coverage()
        self.kpis = None
        self.blocked_ips = {}
        self._alert_row_map = {}
        self._process_row_map = {}
        self.search_var = tk.StringVar()
        self.process_search_var = tk.StringVar()
        self.public_ip = "Looking up…"

        self._configure_ttk_style()
        self._build_menu()

        body = tk.Frame(self, bg=BG_MAIN)
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)

        main_area = tk.Frame(body, bg=BG_MAIN)
        main_area.pack(side="left", fill="both", expand=True)
        self._build_topbar(main_area)

        self.pages_container = tk.Frame(main_area, bg=BG_MAIN)
        self.pages_container.pack(fill="both", expand=True)

        page_keys = ("dashboard", "scanner", "process", "response", "intel", "reports", "settings")
        self.pages = {}
        for key in page_keys:
            page = tk.Frame(self.pages_container, bg=BG_MAIN)
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[key] = page

        self._build_dashboard_page(self.pages["dashboard"])
        self._build_scanner_page(self.pages["scanner"])
        self._build_process_page(self.pages["process"])
        self._build_response_page(self.pages["response"])
        self._build_intel_page(self.pages["intel"])
        self._build_reports_page(self.pages["reports"])
        self._build_settings_page(self.pages["settings"])

        self.show_page("dashboard")
        self.refresh_data()
        self.refresh_processes()
        threading.Thread(target=self._fetch_public_ip_async, daemon=True).start()

        # Kick off the real-time update loops. Everything below streams on
        # its own timer instead of waiting for a manual "Refresh" click.
        self._live_tick()
        self._live_process_tick()

    # -- chrome --------------------------------------------------------------

    def _configure_ttk_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=BG_CARD_ALT, fieldbackground=BG_CARD_ALT,
                         foreground=TEXT_PRIMARY, rowheight=26, font=("Helvetica", 10), borderwidth=0)
        style.configure("Treeview.Heading", background=BG_CARD, foreground=TEXT_MUTED,
                         font=("Helvetica", 9, "bold"), borderwidth=0)
        style.map("Treeview", background=[("selected", BG_TRACK)], foreground=[("selected", TEXT_PRIMARY)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export alerts to CSV", command=self.export_csv)
        file_menu.add_command(label="Export blocked IPs to CSV", command=self.export_blocked_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        actions_menu = tk.Menu(menubar, tearoff=0)
        actions_menu.add_command(label="Refresh data", command=self.refresh_data)
        actions_menu.add_command(label="Simulate new alert", command=self.simulate_alert)
        menubar.add_cascade(label="Actions", menu=actions_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About Sentinel", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def _show_about(self):
        messagebox.showinfo(
            "About Sentinel",
            "Sentinel — Security Operations Console\n\n"
            "Real: system stats, network scanner, process monitor, threat-intel "
            "lookups (with your own API key), firewall blocking, and the network "
            "throughput chart (live from psutil).\n"
            "Live-streaming synthetic data: security alerts, coverage rings, and "
            "KPI gauges update every couple of seconds on their own — there's no "
            "real SIEM/EDR feed behind those numbers, but the motion is real.\n\n"
            "Built with Python and Tkinter.",
        )

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=BG_SIDEBAR, width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="SENTINEL", font=("Consolas", 15, "bold"),
                 bg=BG_SIDEBAR, fg=CYAN).pack(anchor="w", padx=20, pady=(22, 2))
        tk.Label(sidebar, text="Security console", font=("Helvetica", 9),
                 bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(anchor="w", padx=20, pady=(0, 24))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "Dashboard"),
            ("scanner", "Network scanner"),
            ("process", "Process monitor"),
            ("response", "Firewall manager"),
            ("intel", "Threat intelligence"),
            ("reports", "Reports"),
            ("settings", "Settings"),
        ]
        for key, label in nav_items:
            btn = tk.Label(sidebar, text="  " + label, font=("Helvetica", 10),
                            bg=BG_SIDEBAR, fg=TEXT_MUTED, anchor="w", padx=20, pady=10, cursor="hand2")
            btn.pack(fill="x")
            btn.bind("<Button-1>", lambda e, k=key: self.show_page(k))
            self.nav_buttons[key] = btn

        tk.Frame(sidebar, bg=BG_SIDEBAR).pack(fill="both", expand=True)
        tk.Label(sidebar, text=f"{platform.system()} · {platform.machine()}",
                 font=("Helvetica", 8), bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(anchor="w", padx=20, pady=(0, 16))

    def show_page(self, key):
        for page in self.pages.values():
            page.lower()
        self.pages[key].lift()
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.config(bg=BG_CARD_ALT, fg=CYAN, font=("Helvetica", 10, "bold"))
            else:
                btn.config(bg=BG_SIDEBAR, fg=TEXT_MUTED, font=("Helvetica", 10))
        if key == "process":
            self.refresh_processes()

    def _build_topbar(self, parent):
        bar = tk.Frame(parent, bg=BG_MAIN, height=56)
        bar.pack(fill="x", padx=24, pady=(18, 6))

        left = tk.Frame(bar, bg=BG_MAIN)
        left.pack(side="left")
        tk.Label(left, text="Dashboard", font=("Helvetica", 15, "bold"),
                 bg=BG_MAIN, fg=CYAN).pack(anchor="w")
        tk.Label(left, text="SENTINEL / HOME", font=("Helvetica", 8),
                 bg=BG_MAIN, fg=TEXT_MUTED).pack(anchor="w")

        right = tk.Frame(bar, bg=BG_MAIN)
        right.pack(side="right")
        self.clock_label = tk.Label(right, text="", font=("Consolas", 10), bg=BG_MAIN, fg=TEXT_MUTED)
        self.clock_label.pack(side="right", padx=(16, 0))
        self._tick_clock()

        search_wrap = tk.Frame(bar, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        search_wrap.pack(side="right", padx=16)
        search_entry = tk.Entry(search_wrap, textvariable=self.search_var, width=26,
                                 font=("Helvetica", 10), bg=BG_CARD, fg=TEXT_PRIMARY,
                                 insertbackground=TEXT_PRIMARY, relief="flat", bd=6)
        search_entry.pack(side="left")
        tk.Label(search_wrap, text="Search alerts", font=("Helvetica", 8),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(side="left", padx=(0, 8))
        self.search_var.trace_add("write", lambda *a: self._render_alerts())

    def _tick_clock(self):
        self.clock_label.config(text=datetime.now().strftime("%a %d %b %Y, %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _fetch_public_ip_async(self):
        self.public_ip = get_public_ip()
        try:
            self.system_chips["Public IP"].value_label.config(text=self.public_ip)
        except Exception:
            pass

    # -- dashboard page -----------------------------------------------------

    def _build_dashboard_page(self, parent):
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        self.status_banner = tk.Frame(wrap, bg=BG_CARD_ALT, padx=14, pady=8)
        self.status_banner.pack(fill="x", pady=(0, 10))
        self.status_label = tk.Label(self.status_banner, text="", font=("Helvetica", 10, "bold"),
                                      bg=BG_CARD_ALT, fg=TEXT_PRIMARY)
        self.status_label.pack(side="left")

        sys_card = card(wrap, padx=14, pady=10)
        sys_card.pack(fill="x", pady=(0, 14))
        tk.Label(sys_card, text="System status (live)", font=("Helvetica", 10, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w", pady=(0, 8))
        chips_row = tk.Frame(sys_card, bg=BG_CARD)
        chips_row.pack(fill="x")
        snapshot = get_system_snapshot()
        snapshot["Public IP"] = self.public_ip
        self.system_chips = {}
        for i, (label, value) in enumerate(snapshot.items()):
            chip = stat_chip(chips_row, label, value)
            chip.grid(row=0, column=i, padx=(0 if i == 0 else 6, 0))
            self.system_chips[label] = chip

        gauges_row = tk.Frame(wrap, bg=BG_MAIN)
        gauges_row.pack(fill="x", pady=(0, 14))
        for i in range(5):
            gauges_row.columnconfigure(i, weight=1)
        gauge_specs = [
            ("threats", MAGENTA, "Active threats"), ("blocked", CYAN, "Blocked (24h)"),
            ("vulns", YELLOW, "Open vulnerabilities"), ("uptime", GREEN, "Uptime (30d)"),
            ("ips", PURPLE, "IPs blocked"),
        ]
        self.gauges = {}
        for i, (key, color, label) in enumerate(gauge_specs):
            c = card(gauges_row, padx=8, pady=10)
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            gauge = DonutGauge(c)
            gauge.pack()
            self.gauges[key] = (gauge, color, label)

        mid_row = tk.Frame(wrap, bg=BG_MAIN)
        mid_row.pack(fill="x", pady=(0, 14))
        chart_card = card(mid_row, padx=14, pady=12)
        chart_card.pack(side="left", fill="both", expand=True)
        chart_title = ("Network throughput (KB/s) — live, real data from this machine"
                        if TREND_IS_REAL_DATA else
                        "Network throughput (KB/s) — simulated (install psutil for real data)")
        tk.Label(chart_card, text=chart_title, font=("Helvetica", 10, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w", pady=(0, 6))
        self.chart = TrendChart(chart_card, width=520, height=180)
        self.chart.pack()

        eq_card = card(mid_row, padx=14, pady=12)
        eq_card.pack(side="left", fill="both", padx=(14, 0))
        tk.Label(eq_card, text="Alerts by severity", font=("Helvetica", 10, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w", pady=(0, 6))
        self.equalizer = Equalizer(eq_card, width=250, height=180)
        self.equalizer.pack()

        bottom_row = tk.Frame(wrap, bg=BG_MAIN)
        bottom_row.pack(fill="both", expand=True, pady=(0, 14))

        activity_card = card(bottom_row, padx=14, pady=12)
        activity_card.pack(side="left", fill="both", expand=True)
        tk.Label(activity_card, text="Recent alerts — live feed (synthetic data)", font=("Helvetica", 10, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w")

        columns = ("severity", "description", "source", "time")
        self.tree = ttk.Treeview(activity_card, columns=columns, show="headings", height=9)
        for col, txt, w in [("severity", "Severity", 80), ("description", "Description", 220),
                            ("source", "Source", 190), ("time", "Time", 90)]:
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor="center" if col in ("severity", "time") else "w")
        self.tree.pack(fill="both", expand=True, pady=(8, 0))
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)
        self.tree.bind("<Double-1>", self._on_alert_double_click)
        self.tree.bind("<Button-3>", self._on_alert_right_click)
        self.tree.bind("<Button-2>", self._on_alert_right_click)

        footer = tk.Frame(activity_card, bg=BG_CARD)
        footer.pack(fill="x", pady=(10, 0))
        flat_button(footer, "Refresh now", self.refresh_data, bg=CYAN, fg=BG_MAIN).pack(side="left")
        flat_button(footer, "Inject test alert", self.simulate_alert).pack(side="left", padx=(8, 0))
        flat_button(footer, "Export CSV", self.export_csv).pack(side="left", padx=(8, 0))
        self.auto_var = tk.BooleanVar(value=True)
        tk.Checkbutton(footer, text="Live updates", variable=self.auto_var, bg=BG_CARD, fg=TEXT_MUTED,
                        selectcolor=BG_CARD, activebackground=BG_CARD, font=("Helvetica", 9)).pack(side="right")
        self.live_dot = tk.Label(footer, text="●", font=("Helvetica", 10), bg=BG_CARD, fg=GREEN)
        self.live_dot.pack(side="right", padx=(0, 6))

        calendar_card = card(bottom_row, padx=14, pady=12)
        calendar_card.pack(side="left", fill="y", padx=(14, 0))
        MiniCalendar(calendar_card).pack()

        coverage_card = card(wrap, padx=14, pady=12)
        coverage_card.pack(fill="x")
        tk.Label(coverage_card, text="Security coverage by domain — live (synthetic data)", font=("Helvetica", 10, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w", pady=(0, 8))
        rings_row = tk.Frame(coverage_card, bg=BG_CARD)
        rings_row.pack()
        self.coverage_rings = []
        ring_colors = [CYAN, MAGENTA, YELLOW, GREEN, PURPLE]
        for i, domain in enumerate(COVERAGE_DOMAINS):
            ring = SmallRing(rings_row)
            ring.grid(row=0, column=i, padx=14)
            self.coverage_rings.append((ring, ring_colors[i % len(ring_colors)]))

    # -- network scanner page ------------------------------------------------

    def _build_scanner_page(self, parent):
        self._scan_queue = queue.Queue()
        self._scanning = False
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        c = card(wrap, padx=18, pady=16)
        c.pack(fill="both", expand=True)

        tk.Label(c, text="Network scanner", font=("Helvetica", 13, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(c, text="Real ping sweep + common-port check. Only scan networks and "
                         "hosts you own or are authorized to test.",
                 font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED, wraplength=800, justify="left"
                 ).pack(anchor="w", pady=(2, 14))

        form = tk.Frame(c, bg=BG_CARD)
        form.pack(fill="x")
        tk.Label(form, text="Target", font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.target_entry = tk.Entry(form, width=26, font=("Helvetica", 10), bg=BG_CARD_ALT,
                                      fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat")
        self.target_entry.insert(0, "192.168.1.1-20")
        self.target_entry.pack(side="left", padx=(6, 6), ipady=4)
        tk.Label(form, text="(IP, hostname, 192.168.1.1-20, or 192.168.1.0/28)",
                 font=("Helvetica", 8), bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.scan_button = flat_button(form, "Scan", self.start_scan, bg=CYAN, fg=BG_MAIN)
        self.scan_button.pack(side="right")

        self.scan_status_label = tk.Label(c, text="Ready.", font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED)
        self.scan_status_label.pack(anchor="w", pady=(10, 6))

        columns = ("ip", "status", "ports")
        self.scan_tree = ttk.Treeview(c, columns=columns, show="headings", height=16)
        self.scan_tree.heading("ip", text="IP address")
        self.scan_tree.heading("status", text="Status")
        self.scan_tree.heading("ports", text="Open ports")
        self.scan_tree.column("ip", width=160, anchor="w")
        self.scan_tree.column("status", width=100, anchor="center")
        self.scan_tree.column("ports", width=460, anchor="w")
        self.scan_tree.pack(fill="both", expand=True)
        self.scan_tree.tag_configure("up", foreground=GREEN)
        self.scan_tree.tag_configure("down", foreground=TEXT_MUTED)
        self.scan_tree.tag_configure("open", foreground=MAGENTA)
        self.scan_tree.bind("<Button-3>", self._on_scan_right_click)
        self.scan_tree.bind("<Button-2>", self._on_scan_right_click)

    # -- process monitor page (real, via psutil) -----------------------------

    def _build_process_page(self, parent):
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        c = card(wrap, padx=18, pady=16)
        c.pack(fill="both", expand=True)

        tk.Label(c, text="Process monitor", font=("Helvetica", 13, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w")
        if psutil is None:
            tk.Label(c, text="psutil isn't installed — run: pip install psutil",
                      font=("Helvetica", 9), bg=BG_CARD, fg=YELLOW).pack(anchor="w", pady=(4, 10))
        else:
            tk.Label(c, text="Live process list from this machine. Killing or suspending a "
                             "process affects your system immediately — use with care.",
                      font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED, wraplength=800, justify="left"
                      ).pack(anchor="w", pady=(2, 12))

        form = tk.Frame(c, bg=BG_CARD)
        form.pack(fill="x", pady=(0, 8))
        tk.Label(form, text="Filter", font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        filter_entry = tk.Entry(form, textvariable=self.process_search_var, width=24, font=("Helvetica", 10),
                                 bg=BG_CARD_ALT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat")
        filter_entry.pack(side="left", padx=(6, 10), ipady=4)
        self.process_search_var.trace_add("write", lambda *a: self._render_processes())
        flat_button(form, "Refresh", self.refresh_processes, bg=CYAN, fg=BG_MAIN).pack(side="right")

        columns = ("pid", "name", "user", "cpu", "mem", "status")
        self.process_tree = ttk.Treeview(c, columns=columns, show="headings", height=16)
        headers = [("pid", "PID", 70), ("name", "Name", 220), ("user", "User", 140),
                   ("cpu", "CPU %", 80), ("mem", "Mem %", 80), ("status", "Status", 100)]
        for col, txt, w in headers:
            self.process_tree.heading(col, text=txt, command=lambda c=col: self._sort_processes(c))
            self.process_tree.column(col, width=w, anchor="center" if col != "name" else "w")
        self.process_tree.pack(fill="both", expand=True, pady=(4, 0))

        proc_footer = tk.Frame(c, bg=BG_CARD)
        proc_footer.pack(fill="x", pady=(10, 0))
        flat_button(proc_footer, "Kill selected", self.kill_selected_process, bg=MAGENTA, fg=BG_MAIN).pack(side="left")
        flat_button(proc_footer, "Suspend selected", self.suspend_selected_process).pack(side="left", padx=(8, 0))
        flat_button(proc_footer, "Resume selected", self.resume_selected_process).pack(side="left", padx=(8, 0))

        self._process_sort_col = "cpu"
        self._process_sort_reverse = True
        self._process_cache = []

    # -- firewall manager page (blocking) ------------------------------------

    def _build_response_page(self, parent):
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        c = card(wrap, padx=18, pady=16)
        c.pack(fill="both", expand=True)

        tk.Label(c, text="Firewall manager", font=("Helvetica", 13, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(c, text="Right-click a row in Dashboard or Network scanner to block its "
                         "source IP, or add one manually below. Blocks are simulated by "
                         "default so nothing changes on this machine unless you opt in.",
                 font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED, wraplength=820, justify="left"
                 ).pack(anchor="w", pady=(2, 14))

        form = tk.Frame(c, bg=BG_CARD)
        form.pack(fill="x", pady=(0, 8))
        tk.Label(form, text="IP address", font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.block_entry = tk.Entry(form, width=20, font=("Helvetica", 10), bg=BG_CARD_ALT,
                                     fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat")
        self.block_entry.pack(side="left", padx=(6, 10), ipady=4)
        flat_button(form, "Block", lambda: self.block_ip(self.block_entry.get().strip(), "Manually blocked"),
                    bg=MAGENTA, fg=BG_MAIN).pack(side="left")

        self.apply_real_var = tk.BooleanVar(value=False)
        tk.Checkbutton(c, text="Actually apply blocks to this machine's firewall (requires "
                               "admin/root — off by default, simulated only)",
                       variable=self.apply_real_var, bg=BG_CARD, fg=TEXT_MUTED, selectcolor=BG_CARD,
                       activebackground=BG_CARD, font=("Helvetica", 8)).pack(anchor="w", pady=(0, 12))

        columns = ("ip", "reason", "time", "state")
        self.blocked_tree = ttk.Treeview(c, columns=columns, show="headings", height=12)
        for col, txt, w in [("ip", "IP address", 140), ("reason", "Reason", 320),
                            ("time", "Blocked at", 120), ("state", "Firewall rule", 140)]:
            self.blocked_tree.heading(col, text=txt)
            self.blocked_tree.column(col, width=w, anchor="center" if col in ("time", "state") else "w")
        self.blocked_tree.pack(fill="both", expand=True)
        self.blocked_tree.tag_configure("applied", foreground=MAGENTA)
        self.blocked_tree.tag_configure("simulated", foreground=TEXT_MUTED)

        response_footer = tk.Frame(c, bg=BG_CARD)
        response_footer.pack(fill="x", pady=(10, 0))
        flat_button(response_footer, "Unblock selected", self.unblock_selected).pack(side="left")
        flat_button(response_footer, "Export blocked IPs", self.export_blocked_csv).pack(side="left", padx=(8, 0))

    # -- threat intelligence page (real API calls) ---------------------------

    def _build_intel_page(self, parent):
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        c = card(wrap, padx=18, pady=16)
        c.pack(fill="both", expand=True)

        tk.Label(c, text="Threat intelligence", font=("Helvetica", 13, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(c, text="Real lookups against AbuseIPDB (IP reputation) or VirusTotal "
                         "(IP or file hash). Add your own free API key in Settings first.",
                 font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED, wraplength=820, justify="left"
                 ).pack(anchor="w", pady=(2, 14))

        form = tk.Frame(c, bg=BG_CARD)
        form.pack(fill="x")
        tk.Label(form, text="Indicator", font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.intel_entry = tk.Entry(form, width=32, font=("Helvetica", 10), bg=BG_CARD_ALT,
                                     fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat")
        self.intel_entry.pack(side="left", padx=(6, 10), ipady=4)
        tk.Label(form, text="(IP address or file hash)", font=("Helvetica", 8),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")

        self.intel_provider = tk.StringVar(value="AbuseIPDB")
        provider_menu = ttk.Combobox(form, textvariable=self.intel_provider,
                                     values=["AbuseIPDB", "VirusTotal"], width=12, state="readonly")
        provider_menu.pack(side="right", padx=(8, 0))
        flat_button(form, "Look up", self.run_intel_lookup, bg=CYAN, fg=BG_MAIN).pack(side="right")

        self.intel_status_label = tk.Label(c, text="Ready.", font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED)
        self.intel_status_label.pack(anchor="w", pady=(10, 6))

        self.intel_results = tk.Frame(c, bg=BG_CARD_ALT, padx=14, pady=14)
        self.intel_results.pack(fill="both", expand=True)

    def run_intel_lookup(self):
        indicator = self.intel_entry.get().strip()
        if not indicator:
            messagebox.showwarning("Threat intelligence", "Enter an IP address or file hash.")
            return
        provider = self.intel_provider.get()
        self.intel_status_label.config(text=f"Querying {provider}…")
        for w in self.intel_results.winfo_children():
            w.destroy()

        def worker():
            if provider == "AbuseIPDB":
                result = lookup_abuseipdb(indicator, self.config_data.get("abuseipdb_key", ""))
            else:
                result = lookup_virustotal(indicator, self.config_data.get("virustotal_key", ""))
            self.after(0, lambda: self._show_intel_result(provider, result))

        threading.Thread(target=worker, daemon=True).start()

    def _show_intel_result(self, provider, result):
        self.intel_status_label.config(text=f"{provider} result for your last query.")
        for w in self.intel_results.winfo_children():
            w.destroy()
        if "error" in result:
            tk.Label(self.intel_results, text=result["error"], font=("Helvetica", 10),
                     bg=BG_CARD_ALT, fg=YELLOW, wraplength=760, justify="left").pack(anchor="w")
            return
        for key, value in result.items():
            row = tk.Frame(self.intel_results, bg=BG_CARD_ALT)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=key, font=("Helvetica", 9), bg=BG_CARD_ALT, fg=TEXT_MUTED,
                     width=24, anchor="w").pack(side="left")
            tk.Label(row, text=str(value), font=("Helvetica", 10, "bold"), bg=BG_CARD_ALT,
                     fg=TEXT_PRIMARY, anchor="w").pack(side="left")

    # -- reports page ---------------------------------------------------------

    def _build_reports_page(self, parent):
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        c = card(wrap, padx=18, pady=16)
        c.pack(fill="both", expand=True)

        tk.Label(c, text="Reports", font=("Helvetica", 13, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(c, text="Export current data to a file you can share or archive.",
                 font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w", pady=(2, 16))

        for label, command in [
            ("Export alerts (CSV)", self.export_csv),
            ("Export blocked IPs (CSV)", self.export_blocked_csv),
            ("Export process snapshot (CSV)", self.export_process_csv),
            ("Export full summary (JSON)", self.export_summary_json),
        ]:
            row = card(c, padx=14, pady=12)
            row.pack(fill="x", pady=6)
            tk.Label(row, text=label, font=("Helvetica", 10), bg=BG_CARD, fg=TEXT_PRIMARY).pack(side="left")
            flat_button(row, "Export", command, bg=CYAN, fg=BG_MAIN).pack(side="right")

    def export_process_csv(self):
        rows = list_processes()
        if not rows:
            messagebox.showinfo("Reports", "No process data available (is psutil installed?).")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files", "*.csv")],
                                             initialfile="process_snapshot.csv")
        if not path:
            return
        import csv
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Name", "User", "CPU %", "Mem %", "Status"])
            for p in rows:
                writer.writerow([p["pid"], p["name"], p["user"], p["cpu"], p["mem"], p["status"]])
        messagebox.showinfo("Export complete", f"Process snapshot exported to:\n{path}")

    def export_summary_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON files", "*.json")],
                                             initialfile="sentinel_summary.json")
        if not path:
            return
        summary = {
            "generated_at": datetime.now().isoformat(),
            "system": get_system_snapshot(),
            "public_ip": self.public_ip,
            "alerts": [
                {"severity": a["severity"], "description": a["description"],
                 "source": a["source"], "time": a["time"].isoformat()}
                for a in self.alerts
            ],
            "blocked_ips": [
                {"ip": ip, "reason": info["reason"], "time": info["time"].isoformat(),
                 "applied": info["applied"]}
                for ip, info in self.blocked_ips.items()
            ],
        }
        try:
            Path(path).write_text(json.dumps(summary, indent=2))
            messagebox.showinfo("Export complete", f"Summary exported to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Reports", f"Couldn't write file:\n{exc}")

    # -- settings page ----------------------------------------------------------

    def _build_settings_page(self, parent):
        wrap = tk.Frame(parent, bg=BG_MAIN)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        c = card(wrap, padx=18, pady=16)
        c.pack(fill="both", expand=True)

        tk.Label(c, text="Settings", font=("Helvetica", 13, "bold"),
                 bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w", pady=(0, 14))

        def labeled_entry(label_text, value, show=None):
            row = tk.Frame(c, bg=BG_CARD)
            row.pack(fill="x", pady=6)
            tk.Label(row, text=label_text, font=("Helvetica", 9), bg=BG_CARD, fg=TEXT_MUTED,
                     width=22, anchor="w").pack(side="left")
            entry = tk.Entry(row, font=("Helvetica", 10), bg=BG_CARD_ALT, fg=TEXT_PRIMARY,
                              insertbackground=TEXT_PRIMARY, relief="flat", show=show or "")
            entry.insert(0, str(value))
            entry.pack(side="left", fill="x", expand=True, ipady=4)
            return entry

        self.settings_abuseipdb_entry = labeled_entry("AbuseIPDB API key", self.config_data.get("abuseipdb_key", ""), show="*")
        self.settings_vt_entry = labeled_entry("VirusTotal API key", self.config_data.get("virustotal_key", ""), show="*")
        self.settings_timeout_entry = labeled_entry("Scan port timeout (seconds)", self.config_data.get("scan_timeout", 0.4))

        theme_row = tk.Frame(c, bg=BG_CARD)
        theme_row.pack(fill="x", pady=6)
        tk.Label(theme_row, text="Theme (applies on restart)", font=("Helvetica", 9), bg=BG_CARD,
                 fg=TEXT_MUTED, width=22, anchor="w").pack(side="left")
        self.settings_theme_var = tk.StringVar(value=self.config_data.get("theme", "dark"))
        ttk.Combobox(theme_row, textvariable=self.settings_theme_var, values=["dark", "light"],
                     width=10, state="readonly").pack(side="left")

        tk.Label(c, text=f"Config file: {CONFIG_PATH}", font=("Helvetica", 8),
                 bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w", pady=(16, 6))

        flat_button(c, "Save settings", self.save_settings, bg=CYAN, fg=BG_MAIN).pack(anchor="w", pady=(6, 0))

    def save_settings(self):
        try:
            timeout = float(self.settings_timeout_entry.get())
        except ValueError:
            messagebox.showerror("Settings", "Scan timeout must be a number.")
            return
        self.config_data.update({
            "abuseipdb_key": self.settings_abuseipdb_entry.get().strip(),
            "virustotal_key": self.settings_vt_entry.get().strip(),
            "scan_timeout": timeout,
            "theme": self.settings_theme_var.get(),
        })
        if save_config(self.config_data):
            messagebox.showinfo("Settings", "Settings saved. Restart Sentinel for theme changes to apply.")
        else:
            messagebox.showerror("Settings", f"Couldn't write config file at:\n{CONFIG_PATH}")

    # -- behaviour: dashboard -------------------------------------------------

    def refresh_data(self):
        """Full manual repaint of every dashboard widget from current state.
        Also called once at startup; after that the live tick loop keeps
        everything moving on its own."""
        self.kpis = compute_kpis(self.alerts, self.kpis)
        self._redraw_gauges(self.kpis)
        self.chart.draw(self.trend, [t.strftime("%H:%M:%S") for t in self.trend_times])
        self._redraw_equalizer()
        self._redraw_coverage()
        self._render_alerts()
        self._update_status_banner(self.kpis["active_threats"])

    def _redraw_gauges(self, kpis):
        gauge, color, label = self.gauges["threats"]
        gauge.draw(min(kpis["active_threats"] / 15, 1), color, str(kpis["active_threats"]), label)
        gauge, color, label = self.gauges["blocked"]
        gauge.draw(min(kpis["blocked_24h"] / 2000, 1), color, f"{kpis['blocked_24h']:,}", label)
        gauge, color, label = self.gauges["vulns"]
        gauge.draw(min(kpis["open_vulns"] / 50, 1), color, str(kpis["open_vulns"]), label)
        gauge, color, label = self.gauges["uptime"]
        gauge.draw(kpis["uptime"] / 100, color, f"{kpis['uptime']}%", label)
        gauge, color, label = self.gauges["ips"]
        gauge.draw(min(len(self.blocked_ips) / 20, 1), color, str(len(self.blocked_ips)), label)

    def _redraw_equalizer(self):
        severity_order = ["Critical", "High", "Medium", "Low"]
        counts = {sev: 0 for sev in severity_order}
        for alert in self.alerts:
            counts[alert["severity"]] += 1
        self.equalizer.draw([(sev[:4], counts[sev], SEVERITY_COLORS[sev]) for sev in severity_order])

    def _redraw_coverage(self):
        for (ring, color), (domain, pct) in zip(self.coverage_rings, self.coverage):
            ring.draw(pct, color, domain)

    def _update_status_banner(self, active_threats):
        if active_threats == 0:
            color, text = GREEN, "Security posture: normal — no active critical/high threats"
        elif active_threats <= 3:
            color, text = YELLOW, f"Security posture: elevated — {active_threats} active threats need review"
        else:
            color, text = MAGENTA, f"Security posture: critical — {active_threats} active threats need immediate review"
        self.status_label.config(fg=color, text=text)

    def _render_alerts(self):
        self.tree.delete(*self.tree.get_children())
        self._alert_row_map = {}
        query = self.search_var.get().strip().lower()
        for alert in sorted(self.alerts, key=lambda a: a["time"], reverse=True):
            haystack = f"{alert['severity']} {alert['description']} {alert['source']}".lower()
            if query and query not in haystack:
                continue
            time_str = alert["time"].strftime("%H:%M:%S")
            iid = self.tree.insert("", "end",
                                    values=(alert["severity"], alert["description"], alert["source"], time_str),
                                    tags=(alert["severity"],))
            self._alert_row_map[iid] = alert

    def simulate_alert(self):
        self.alerts.append(generate_alert())
        if len(self.alerts) > 30:
            self.alerts = self.alerts[-30:]
        self.refresh_data()

    # -- behaviour: real-time engine -------------------------------------------
    #
    # A single ticking loop (self.after) drives every "live" element of the
    # dashboard: the trend chart streams a new sample, the gauges/equalizer/
    # coverage rings redraw from the latest state, system chips repaint with
    # fresh psutil readings, and alerts occasionally stream in — all without
    # any manual refresh. Blocking work (psutil snapshot) runs on a
    # background thread so the UI never freezes while it waits.

    def _live_tick(self):
        if self.auto_var.get():
            self.live_dot.config(fg=GREEN)
            # New streaming point for the trend chart — a real reading of
            # this machine's network throughput (net_io_counters() is a
            # cheap, non-blocking call, so it's safe to sample right here
            # on the UI thread).
            if TREND_IS_REAL_DATA:
                next_value, self._net_prev_bytes = sample_network_kbps(
                    self._net_prev_bytes, LIVE_TICK_SECONDS)
            else:
                next_value = sample_network_kbps_fallback(self.trend[-1] if self.trend else None)
            self.trend.append(next_value)
            self.trend_times.append(datetime.now())
            if len(self.trend) > TREND_WINDOW:
                self.trend = self.trend[-TREND_WINDOW:]
                self.trend_times = self.trend_times[-TREND_WINDOW:]
            self.chart.draw(self.trend, [t.strftime("%H:%M:%S") for t in self.trend_times])

            # Coverage rings drift slightly instead of jumping every tick.
            self.coverage = step_coverage(self.coverage)
            self._redraw_coverage()

            # KPIs / gauges refresh from the latest alert set.
            self.kpis = compute_kpis(self.alerts, self.kpis)
            self._redraw_gauges(self.kpis)
            self._update_status_banner(self.kpis["active_threats"])

            # Occasionally stream in a new alert, like a live feed would.
            if random.random() < LIVE_ALERT_CHANCE:
                self.alerts.append(generate_alert())
                if len(self.alerts) > 30:
                    self.alerts = self.alerts[-30:]
                self._redraw_equalizer()
                self._render_alerts()

            # Real system stats (CPU/RAM/etc.) are fetched off the UI thread
            # since psutil.cpu_percent(interval=...) blocks briefly.
            threading.Thread(target=self._live_system_snapshot, daemon=True).start()
        else:
            self.live_dot.config(fg=TEXT_MUTED)

        self.after(LIVE_TICK_SECONDS * 1000, self._live_tick)

    def _live_system_snapshot(self):
        snapshot = get_system_snapshot()
        snapshot["Public IP"] = self.public_ip
        self.after(0, lambda: self._apply_system_snapshot(snapshot))

    def _apply_system_snapshot(self, snapshot):
        for label, value in snapshot.items():
            chip = self.system_chips.get(label)
            if chip is not None:
                try:
                    chip.value_label.config(text=value)
                except Exception:
                    pass

    def _live_process_tick(self):
        if self.auto_var.get():
            threading.Thread(target=self._live_process_snapshot, daemon=True).start()
        self.after(LIVE_PROCESS_INTERVAL_MS, self._live_process_tick)

    def _live_process_snapshot(self):
        rows = list_processes()
        self.after(0, lambda: self._apply_process_snapshot(rows))

    def _apply_process_snapshot(self, rows):
        self._process_cache = rows
        self._render_processes()

    def _on_alert_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        severity, description, source, time_str = values
        messagebox.showinfo(f"{severity} alert",
                             f"Description: {description}\nSource: {source}\nTime: {time_str}")

    def _on_alert_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        alert = self._alert_row_map.get(iid)
        if not alert:
            return
        ip = extract_ip(alert["source"])
        menu = tk.Menu(self, tearoff=0)
        if ip:
            menu.add_command(label=f"Block source IP ({ip})",
                              command=lambda: self.block_ip(ip, f"Alert: {alert['description']}"))
        menu.add_command(label="Mark as resolved", command=lambda: self._resolve_alert(iid))
        menu.tk_popup(event.x_root, event.y_root)

    def _resolve_alert(self, iid):
        alert = self._alert_row_map.get(iid)
        if alert in self.alerts:
            self.alerts.remove(alert)
        self.refresh_data()

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
                                             initialfile="security_alerts.csv")
        if not path:
            return
        import csv
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Description", "Source", "Time"])
            for alert in sorted(self.alerts, key=lambda a: a["time"], reverse=True):
                writer.writerow([alert["severity"], alert["description"], alert["source"],
                                  alert["time"].strftime("%Y-%m-%d %H:%M:%S")])
        messagebox.showinfo("Export complete", f"Alerts exported to:\n{path}")

    # -- behaviour: network scanner -------------------------------------------

    def start_scan(self):
        if self._scanning:
            return
        raw_target = self.target_entry.get().strip()
        if not raw_target:
            messagebox.showwarning("Network scanner", "Enter a target IP, range, or hostname.")
            return
        try:
            targets = parse_targets(raw_target)
        except (ValueError, ipaddress.AddressValueError) as exc:
            messagebox.showerror("Network scanner", str(exc))
            return
        if len(targets) > MAX_SCAN_HOSTS:
            messagebox.showwarning("Network scanner",
                                    f"That range covers {len(targets)} hosts. Please scan "
                                    f"{MAX_SCAN_HOSTS} hosts or fewer at a time.")
            return

        self.scan_tree.delete(*self.scan_tree.get_children())
        self._scanning = True
        self.scan_button.config(state="disabled", text="Scanning…")
        self.scan_status_label.config(text=f"Scanning {len(targets)} host(s)…")

        timeout = self.config_data.get("scan_timeout", 0.4)
        thread = threading.Thread(target=self._run_scan, args=(targets, timeout), daemon=True)
        thread.start()
        self.after(100, self._poll_scan_queue)

    def _run_scan(self, targets, timeout):
        with ThreadPoolExecutor(max_workers=32) as executor:
            for result in executor.map(lambda ip: scan_host(ip, timeout), targets):
                self._scan_queue.put(result)
        self._scan_queue.put(None)

    def _poll_scan_queue(self):
        finished = False
        try:
            while True:
                item = self._scan_queue.get_nowait()
                if item is None:
                    finished = True
                    break
                self._add_scan_result(item)
        except queue.Empty:
            pass

        if finished:
            self._scanning = False
            self.scan_button.config(state="normal", text="Scan")
            responded = sum(1 for iid in self.scan_tree.get_children()
                            if "up" in self.scan_tree.item(iid, "tags")
                            or "open" in self.scan_tree.item(iid, "tags"))
            total = len(self.scan_tree.get_children())
            self.scan_status_label.config(text=f"Done — {responded} of {total} host(s) responded.")
        else:
            self.after(100, self._poll_scan_queue)

    def _add_scan_result(self, result):
        ip, up, ports = result["ip"], result["up"], result["open_ports"]
        status = "Up" if up else "No response"
        if ports:
            port_str = ", ".join(f"{p}/{PORT_NAMES.get(p, 'tcp')}" for p in ports)
            tag = "open"
        elif up:
            port_str, tag = "None found", "up"
        else:
            port_str, tag = "—", "down"
        self.scan_tree.insert("", "end", values=(ip, status, port_str), tags=(tag,))

    def _on_scan_right_click(self, event):
        iid = self.scan_tree.identify_row(event.y)
        if not iid:
            return
        self.scan_tree.selection_set(iid)
        values = self.scan_tree.item(iid, "values")
        if not values:
            return
        ip = values[0]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label=f"Block {ip}", command=lambda: self.block_ip(ip, "Flagged from network scan"))
        menu.tk_popup(event.x_root, event.y_root)

    # -- behaviour: process monitor -------------------------------------------

    def refresh_processes(self):
        self._process_cache = list_processes()
        self._render_processes()

    def _render_processes(self):
        self.process_tree.delete(*self.process_tree.get_children())
        self._process_row_map = {}
        query = self.process_search_var.get().strip().lower()
        rows = self._process_cache
        rows = sorted(rows, key=lambda r: r.get(self._process_sort_col, 0),
                       reverse=self._process_sort_reverse)
        for row in rows:
            haystack = f"{row['name']} {row['user']} {row['pid']}".lower()
            if query and query not in haystack:
                continue
            iid = self.process_tree.insert("", "end", values=(
                row["pid"], row["name"], row["user"], row["cpu"], row["mem"], row["status"]))
            self._process_row_map[iid] = row["pid"]

    def _sort_processes(self, col):
        if self._process_sort_col == col:
            self._process_sort_reverse = not self._process_sort_reverse
        else:
            self._process_sort_col = col
            self._process_sort_reverse = True
        self._render_processes()

    def _get_selected_pid(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showinfo("Process monitor", "Select a process first.")
            return None
        return self._process_row_map.get(selected[0])

    def kill_selected_process(self):
        if psutil is None:
            return
        pid = self._get_selected_pid()
        if pid is None:
            return
        if not messagebox.askyesno("Kill process", f"Terminate PID {pid}? This can't be undone."):
            return
        try:
            psutil.Process(pid).terminate()
            self.refresh_processes()
        except Exception as exc:
            messagebox.showerror("Process monitor", f"Couldn't terminate PID {pid}:\n{exc}")

    def suspend_selected_process(self):
        if psutil is None:
            return
        pid = self._get_selected_pid()
        if pid is None:
            return
        try:
            psutil.Process(pid).suspend()
            self.refresh_processes()
        except Exception as exc:
            messagebox.showerror("Process monitor", f"Couldn't suspend PID {pid}:\n{exc}")

    def resume_selected_process(self):
        if psutil is None:
            return
        pid = self._get_selected_pid()
        if pid is None:
            return
        try:
            psutil.Process(pid).resume()
            self.refresh_processes()
        except Exception as exc:
            messagebox.showerror("Process monitor", f"Couldn't resume PID {pid}:\n{exc}")

    # -- behaviour: firewall / threat response --------------------------------

    def block_ip(self, ip, reason):
        ip = (ip or "").strip()
        if not ip:
            messagebox.showwarning("Firewall manager", "Enter an IP address to block.")
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Firewall manager", f"'{ip}' isn't a valid IP address.")
            return
        if ip in self.blocked_ips:
            messagebox.showinfo("Firewall manager", f"{ip} is already blocked.")
            return

        command = build_block_command(ip)
        applied = False
        if self.apply_real_var.get():
            confirmed = messagebox.askyesno(
                "Confirm firewall change",
                f"This will run the following command on this machine:\n\n{command}\n\n"
                "It needs admin/root privileges and will actually block traffic from this IP. Continue?",
            )
            if confirmed:
                try:
                    subprocess.run(command, shell=True, check=True)
                    applied = True
                except Exception as exc:
                    messagebox.showerror("Firewall manager", f"Failed to apply firewall rule:\n{exc}")

        self.blocked_ips[ip] = {"reason": reason, "time": datetime.now(), "applied": applied, "command": command}
        self._render_blocked_ips()
        gauge, color, label = self.gauges["ips"]
        gauge.draw(min(len(self.blocked_ips) / 20, 1), color, str(len(self.blocked_ips)), label)

    def unblock_selected(self):
        selected = self.blocked_tree.selection()
        if not selected:
            return
        for iid in selected:
            ip = self.blocked_tree.item(iid, "values")[0]
            self.blocked_ips.pop(ip, None)
        self._render_blocked_ips()
        gauge, color, label = self.gauges["ips"]
        gauge.draw(min(len(self.blocked_ips) / 20, 1), color, str(len(self.blocked_ips)), label)

    def _render_blocked_ips(self):
        self.blocked_tree.delete(*self.blocked_tree.get_children())
        for ip, info in sorted(self.blocked_ips.items(), key=lambda kv: kv[1]["time"], reverse=True):
            state = "Applied" if info["applied"] else "Simulated"
            tag = "applied" if info["applied"] else "simulated"
            self.blocked_tree.insert("", "end",
                                      values=(ip, info["reason"], info["time"].strftime("%H:%M:%S"), state),
                                      tags=(tag,))

    def export_blocked_csv(self):
        if not self.blocked_ips:
            messagebox.showinfo("Firewall manager", "No blocked IPs to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
                                             initialfile="blocked_ips.csv")
        if not path:
            return
        import csv
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP address", "Reason", "Time", "Firewall rule", "Command"])
            for ip, info in sorted(self.blocked_ips.items(), key=lambda kv: kv[1]["time"], reverse=True):
                writer.writerow([ip, info["reason"], info["time"].strftime("%Y-%m-%d %H:%M:%S"),
                                  "Applied" if info["applied"] else "Simulated", info["command"]])
        messagebox.showinfo("Export complete", f"Blocked IP list exported to:\n{path}")


if __name__ == "__main__":
    app = SecurityDashboard()
    app.mainloop()