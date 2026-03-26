import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, Menu
import os, threading, subprocess, zipfile, shutil, psutil, re, time, hashlib, queue, json
import platform, webbrowser
import xml.etree.ElementTree as ET

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# --- FORENSIC ENGINE IMPORT ---
try:
    from androguard.core.bytecodes.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ── UI colour palette (dark-navy sidebar / light-lavender content) ─────────
SIDEBAR_BG    = "#1B2642"   # dark navy sidebar background
SIDEBAR_HOVER = "#243352"   # nav-button hover / active tint
MAIN_BG       = "#EEF0F6"   # light lavender main background
CARD_BG       = "#FFFFFF"   # card / panel white
ACCENT        = "#E8604C"   # coral orange-red accent
ACCENT2       = "#38C9B3"   # teal accent
TEXT_LIGHT    = "#FFFFFF"
TEXT_MUTED    = "#8E9BB3"
TEXT_DARK     = "#1B2642"
BORDER        = "#E2E6F0"


class APKMasterV59(ctk.CTk):

    # --- ABBREVIATION MAPPING FOR READABLE IMAGE NAMES ---
    ABBR_MAP = [
        ("btn_",  "Button_"),
        ("img_",  "Image_"),
        ("ic_",   "Icon_"),
        ("bg_",   "Background_"),
        ("fg_",   "Foreground_"),
        ("txt_",  "Text_"),
        ("iv_",   "ImageView_"),
        ("tv_",   "TextView_"),
    ]

    # --- CATEGORY FOLDER MAPPING (prefix → folder name) ---
    CATEGORY_PREFIXES = {
        "Button":     "Buttons",
        "Icon":       "Icons",
        "Image":      "Images",
        "Background": "Backgrounds",
        "Foreground": "Foregrounds",
        "ImageView":  "ImageViews",
        "TextView":   "TextViews",
    }

    # --- PERMISSION CLASSIFICATION ---
    PERMISSIONS_CRITICAL = {
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "WRITE_SMS",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        "RECORD_AUDIO", "CAMERA",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
        "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
        "WRITE_SECURE_SETTINGS", "CHANGE_COMPONENT_ENABLED_STATE",
        "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW",
    }
    PERMISSIONS_NOTABLE = {
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "MANAGE_EXTERNAL_STORAGE",
        "BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT",
        "NFC", "CHANGE_NETWORK_STATE", "CHANGE_WIFI_STATE", "ACCESS_WIFI_STATE",
        "VIBRATE", "RECEIVE_BOOT_COMPLETED", "USE_BIOMETRIC", "USE_FINGERPRINT",
        "PACKAGE_USAGE_STATS", "QUERY_ALL_PACKAGES",
        "FOREGROUND_SERVICE", "BIND_ACCESSIBILITY_SERVICE",
    }

    # --- KNOWN AD / TRACKING DOMAINS ---
    AD_DOMAINS = {
        "ads.facebook.com", "googlesyndication.com", "doubleclick.net",
        "admob.com", "moatads.com", "applovin.com", "ironsrc.com",
        "unity3d.com", "mopub.com", "adcolony.com", "vungle.com",
        "appsflyer.com", "adjust.com", "branch.io", "flurry.com",
        "onesignal.com", "tapjoy.com", "mbridge.com",
    }

    def __init__(self):
        super().__init__()
        self.title("APK Master V59")
        self.geometry("1600x1000")

        # --- PATHS & PERSISTENCE ---
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.join(self.script_dir, "sources.txt")
        self.patterns_file = os.path.join(self.script_dir, "exclude_patterns.txt")
        self.library_dir = os.path.join(self.script_dir, "MY_APP_LIBRARY")

        # --- STATE ---
        self.include_paths = []
        self.exclude_paths = []
        self.global_patterns = []
        self.apk_registry = []
        self.pipeline_queue = []
        self.is_running = False
        self.current_pid = None
        self.log_text = None  # Safety-Init: must exist before load_all_configs

        self.sort_states = {
            "?": True, "Status": True, "App-Name": True,
            "ID": True, "Version": True, "Größe": True, "Pfad": True,
        }

        # --- THREAT DATABASE ---
        self.THREATS = self._load_threats()
        self._log_queue = queue.Queue()   # thread-safe log queue

        # --- SDK SIGNATURES ---
        self.SDK_PATTERNS = [
            "com/google", "com/facebook", "com/appsflyer", "com/unity3d",
            "com/adjust", "com/firebase", "com/amazon", "com/mbridge",
            "io/fabric", "com/applovin", "com/ironsource", "com/vungle",
            "com/flurry", "com/tapjoy", "com/yandex/metrica", "com/onesignal",
        ]

        self.setup_ui()
        self.init_system()
        self.load_all_configs()
        self._drain_log()

    # =========================================================================
    # INIT
    # =========================================================================

    def init_system(self):
        if not os.path.exists(self.library_dir):
            os.makedirs(self.library_dir)
        for f in [self.config_file, self.patterns_file]:
            if not os.path.exists(f):
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write("# APK Master Configuration\n")

    def _load_threats(self):
        """Load threat signatures from threats.yaml; fall back to built-in defaults."""
        threats_path = os.path.join(self.script_dir, "threats.yaml")
        if YAML_AVAILABLE and os.path.exists(threats_path):
            try:
                with open(threats_path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if isinstance(data, dict):
                    return {k: list(v) for k, v in data.items()}
            except Exception:
                pass
        return self._default_threats()

    @staticmethod
    def _default_threats():
        """Built-in threat signatures used when threats.yaml is absent or unreadable."""
        return {
            "IDENTITY": [
                "getDeviceId", "getSimSerialNumber", "getSubscriberId",
                "getLine1Number", "INSTALL_REFERRER", "getImei", "getMeid",
                "getSerial", "getAccounts", "getAccountsByType",
            ],
            "SPY": [
                "MediaRecorder;->start", "Camera;->takePicture", "AudioSource;->MIC",
                "getLastKnownLocation", "requestLocationUpdates", "onLocationChanged",
                "getLatitude", "getLongitude", "getAccuracy", "CellInfo",
            ],
            "SHELL": [
                "Runtime;->exec", "ProcessBuilder;->start", "chmod ", "su -c",
                "mount -o remount", "/system/bin/sh", "/system/xbin/su",
                "LD_PRELOAD", "libspy", "insmod", "rmmod",
            ],
            "SMS": [
                "SMS_RECEIVED", "pdus", "SEND_SMS", "RECEIVE_WAP_PUSH",
                "SMS_SEND_ACTION", "android.provider.Telephony.SMS_RECEIVED",
                "SMS_BODY", "READ_SMS", "WRITE_SMS",
            ],
            "NETWORK": [
                "HttpURLConnection", "DefaultHttpClient", "Socket;->connect",
                "getServerSocket", "isNetworkConnected", "getWifiState",
                "getScanResults", "Proxy;->getAddress",
            ],
            "SYSTEM": [
                "getRunningAppProcesses", "getRecentTasks", "killBackgroundProcesses",
                "reboot", "ACTION_SHUTDOWN", "WRITE_SECURE_SETTINGS", "INSTALL_PACKAGES",
            ],
            "CRYPTO": [
                "AES/CBC/PKCS5Padding", "SecretKeySpec", "IvParameterSpec",
                "MessageDigest;->getInstance", "MD5", "SHA-1",
            ],
            "PERSISTENCE": [
                "RECEIVE_BOOT_COMPLETED", "ACTION_EXTERNAL_APPLICATIONS_AVAILABLE",
                "QUICKBOOT_POWERON", "AlarmManager;->setRepeating",
            ],
        }

    @staticmethod
    def _apk_sha256(path):
        """Compute SHA-256 hash of a file for reliable duplicate detection."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except OSError:
            pass
        return h.hexdigest()

    # =========================================================================
    # UI SETUP
    # =========================================================================

    def setup_ui(self):
        """Two-panel desktop layout: dark navy sidebar (left) + light main area (right)."""
        self.configure(fg_color=MAIN_BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Log console at bottom (must exist before any self.log() call)
        log_frame = ctk.CTkFrame(self, fg_color="#111827", corner_radius=0)
        log_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        log_frame.grid_columnconfigure(0, weight=1)
        self.log_text = ctk.CTkTextbox(
            log_frame, height=130, font=("Consolas", 11),
            fg_color="#111827", text_color="#00FF90", corner_radius=0,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        ctk.CTkButton(
            log_frame, text="Log speichern", width=110, height=28,
            font=("Segoe UI", 11), fg_color="#374151", hover_color="#4B5563",
            corner_radius=6, command=self._export_log,
        ).grid(row=0, column=1, padx=6, pady=4, sticky="ne")

        # 2. Left sidebar
        self._build_sidebar()

        # 3. Main area (top bar + content views + status bar)
        main = ctk.CTkFrame(self, fg_color=MAIN_BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        self._main = main

        self._build_topbar(main)
        content = ctk.CTkFrame(main, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self._content_area = content
        self._build_statusbar(main)

        # 4. Build individual view frames inside _content_area
        self._views: dict = {}
        self.setup_view_config()
        self.setup_view_dashboard()
        self.setup_view_pipeline()

        # 5. Show dashboard by default
        self._switch_view("dashboard")

    # ── SIDEBAR ───────────────────────────────────────────────────────────────

    def _build_sidebar(self):
        """Dark navy left panel: title, donut-chart stats, navigation, scan button."""
        sb = ctk.CTkFrame(self, width=280, fg_color=SIDEBAR_BG, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)
        sb.grid_rowconfigure(4, weight=1)   # spacer row above scan button
        self._sidebar = sb

        # Title
        hdr = ctk.CTkFrame(sb, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(32, 0))
        ctk.CTkLabel(hdr, text="Welcome to",
                     font=("Segoe UI", 12), text_color=TEXT_MUTED).pack(anchor="w")
        ctk.CTkLabel(hdr, text="APK Master",
                     font=("Segoe UI", 24, "bold"),
                     text_color=TEXT_LIGHT).pack(anchor="w")

        # Storage card with donut chart
        card = ctk.CTkFrame(sb, fg_color=SIDEBAR_HOVER, corner_radius=16)
        card.grid(row=1, column=0, sticky="ew", padx=16, pady=(22, 0))
        self._chart_canvas = tk.Canvas(
            card, width=110, height=110,
            bg=SIDEBAR_HOVER, highlightthickness=0,
        )
        self._chart_canvas.pack(side="left", padx=(14, 4), pady=14)
        info = ctk.CTkFrame(card, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self._stat_size_var  = ctk.StringVar(value="0 GB")
        self._stat_count_var = ctk.StringVar(value="Total: 0 APKs")
        ctk.CTkLabel(info, textvariable=self._stat_size_var,
                     font=("Segoe UI", 20, "bold"),
                     text_color=TEXT_LIGHT).pack(anchor="w", pady=(16, 0))
        ctk.CTkLabel(info, textvariable=self._stat_count_var,
                     font=("Segoe UI", 11),
                     text_color=TEXT_MUTED).pack(anchor="w")
        leg = ctk.CTkFrame(info, fg_color="transparent")
        leg.pack(anchor="w", pady=(8, 16))
        self._legend_dot(leg, ACCENT,  "Genutzt")
        self._legend_dot(leg, ACCENT2, "Verfügbar")
        self._draw_donut(0, 1)

        # Separator
        ctk.CTkFrame(sb, height=1, fg_color=SIDEBAR_HOVER).grid(
            row=2, column=0, sticky="ew", padx=16, pady=(20, 6))

        # Navigation buttons
        nav = ctk.CTkFrame(sb, fg_color="transparent")
        nav.grid(row=3, column=0, sticky="ew")
        self._nav_btns = {}
        for view_id, icon, label in [
            ("dashboard", "📊", "Dashboard"),
            ("config",    "⚙",  "Konfiguration"),
            ("pipeline",  "▶",  "Pipeline"),
        ]:
            btn = ctk.CTkButton(
                nav, text=f"  {icon}   {label}", anchor="w",
                font=("Segoe UI", 14), height=46,
                fg_color="transparent", hover_color=SIDEBAR_HOVER,
                text_color=TEXT_MUTED, corner_radius=12,
                command=lambda v=view_id: self._switch_view(v),
            )
            btn.pack(fill="x", padx=14, pady=2)
            self._nav_btns[view_id] = btn

        # Spacer
        ctk.CTkFrame(sb, fg_color="transparent").grid(row=4, column=0, sticky="nsew")

        # Scan button
        ctk.CTkButton(
            sb, text="SYSTEM-SCAN STARTEN", height=50,
            font=("Segoe UI", 13, "bold"),
            fg_color=ACCENT, hover_color="#C94A38", corner_radius=14,
            command=self.start_deep_scan,
        ).grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 24))

    def _legend_dot(self, parent, color, label):
        """Coloured circle + text legend entry."""
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(anchor="w", pady=1)
        dot = tk.Canvas(row, width=10, height=10, bg=SIDEBAR_HOVER, highlightthickness=0)
        dot.create_oval(1, 1, 9, 9, fill=color, outline="")
        dot.pack(side="left")
        ctk.CTkLabel(row, text=f"  {label}", font=("Segoe UI", 11),
                     text_color=TEXT_MUTED).pack(side="left")

    def _draw_donut(self, used: float, total: float):
        """Redraw the donut ring chart on the sidebar canvas."""
        c = self._chart_canvas
        c.delete("all")
        cx, cy, r, th = 55, 55, 42, 13
        pct = (used / total * 100) if total > 0 else 0
        # tkinter Canvas requires a non-zero extent; use a tiny value for 0% or 100%
        _MIN = -0.001
        ext_used = -(360 * pct / 100) if pct > 0 else _MIN
        ext_free = -(360 * (1 - pct / 100)) if pct < 100 else _MIN
        start_free = 90 + 360 * pct / 100
        # Available ring (teal)
        c.create_arc(cx - r, cy - r, cx + r, cy + r,
                     start=start_free, extent=ext_free,
                     style="arc", outline=ACCENT2, width=th)
        # Used ring (coral)
        c.create_arc(cx - r, cy - r, cx + r, cy + r,
                     start=90, extent=ext_used,
                     style="arc", outline=ACCENT, width=th)
        label = f"{pct:.0f}%" if total > 0 else "–"
        c.create_text(cx, cy, text=label, fill=TEXT_LIGHT,
                      font=("Segoe UI", 12, "bold"))

    def _update_sidebar_stats(self):
        """Refresh sidebar donut chart and counters after a scan."""
        total_apks = len(self.apk_registry)
        total_gb   = sum(x["size_mb"] for x in self.apk_registry) / 1024
        try:
            disk       = psutil.disk_usage(self.script_dir)
            disk_total = disk.total / (1024 ** 3)
            disk_used  = disk.used  / (1024 ** 3)
        except Exception:
            disk_total = max(total_gb * 10, 1)
            disk_used  = total_gb
        self._stat_size_var.set(f"{total_gb:.1f} GB")
        self._stat_count_var.set(f"Total: {total_apks} APKs")
        self._draw_donut(disk_used, disk_total)

    # ── TOP BAR ───────────────────────────────────────────────────────────────

    def _build_topbar(self, parent):
        """White bar at top of main area: search + action buttons + status."""
        bar = ctk.CTkFrame(parent, fg_color=CARD_BG, height=70, corner_radius=0)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(1, weight=1)

        # Search entry
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.filter_table())
        ctk.CTkEntry(
            bar,
            placeholder_text="🔍  Filter: Name, Package-ID oder Pfad …",
            textvariable=self.search_var, height=42, width=420,
            font=("Segoe UI", 13), corner_radius=21,
            fg_color=MAIN_BG, border_color=BORDER, border_width=1,
        ).grid(row=0, column=0, padx=(22, 10), pady=14)

        # Action buttons
        bf = ctk.CTkFrame(bar, fg_color="transparent")
        bf.grid(row=0, column=1, sticky="e", padx=18)

        def _btn(text, fg, ho, cmd):
            ctk.CTkButton(bf, text=text, height=38, font=("Segoe UI", 12),
                          fg_color=fg, hover_color=ho, corner_radius=10,
                          command=cmd).pack(side="left", padx=4)

        _btn("Alle wählen",  SIDEBAR_BG, SIDEBAR_HOVER,
             lambda: self.select_all_monolith(True))
        _btn("Aufheben",     "#95a5a6",  "#7f8c8d",
             lambda: self.select_all_monolith(False))
        _btn("Dubletten",    ACCENT,     "#C94A38",
             self.select_all_duplicates_monolith)
        _btn("Löschen",      "#c0392b",  "#922b21",
             self.delete_physically_monolith)
        _btn("→ Pipeline",   "#27ae60",  "#1e8449",
             self.move_to_pipeline_monolith)

        self.status_var = ctk.StringVar(value="Bereit.")
        ctk.CTkLabel(bar, textvariable=self.status_var,
                     font=("Segoe UI", 12), text_color=TEXT_MUTED).grid(
            row=0, column=2, padx=(0, 18))

    def _build_statusbar(self, parent):
        """Thin white bar at bottom of main area showing APK statistics."""
        bar = ctk.CTkFrame(parent, fg_color=CARD_BG, height=34, corner_radius=0)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)
        self.stats_var = ctk.StringVar(value="0 APKs | 0 ausgewählt | 0.00 GB total")
        ctk.CTkLabel(bar, textvariable=self.stats_var,
                     font=("Segoe UI", 11), text_color=TEXT_MUTED).pack(
            side="left", padx=20)

    def _switch_view(self, view_id: str):
        """Show the requested view frame; highlight the matching nav button."""
        for name, frame in self._views.items():
            if name == view_id:
                frame.grid()
            else:
                frame.grid_remove()
        for name, btn in self._nav_btns.items():
            if name == view_id:
                btn.configure(fg_color=SIDEBAR_HOVER, text_color=TEXT_LIGHT)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_MUTED)
        self._current_view = view_id

    # ── VIEWS ─────────────────────────────────────────────────────────────────

    def setup_view_config(self):
        """Build the Konfiguration view (source paths, exclude paths, patterns)."""
        view = ctk.CTkFrame(self._content_area, fg_color=MAIN_BG, corner_radius=0)
        view.grid(row=0, column=0, sticky="nsew")
        view.grid_remove()
        view.grid_columnconfigure(0, weight=3)
        view.grid_columnconfigure(1, weight=1)
        view.grid_rowconfigure(0, weight=1)
        view.grid_rowconfigure(1, weight=1)
        self._views["config"] = view

        # Left: path lists
        path_f = ctk.CTkFrame(view, fg_color="transparent")
        path_f.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(20, 8), pady=15)

        # Include paths
        ctk.CTkLabel(path_f, text="Quell-Verzeichnisse (Include +)",
                     font=("Segoe UI", 17, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", pady=(8, 4))
        inc_row = ctk.CTkFrame(path_f, fg_color="transparent")
        inc_row.pack(fill="both", expand=True)
        inc_box = ctk.CTkFrame(inc_row, fg_color=CARD_BG, corner_radius=10,
                               border_width=1, border_color=BORDER)
        inc_box.pack(side="left", fill="both", expand=True)
        self.inc_list = ttk.Treeview(inc_box, columns=("Status", "Path"),
                                     show="headings", height=8)
        self.inc_list.heading("Status", text="S")
        self.inc_list.column("Status", width=50, anchor="center")
        self.inc_list.heading("Path", text="Pfad")
        self.inc_list.column("Path", width=800)
        inc_vsb = ttk.Scrollbar(inc_box, orient="vertical", command=self.inc_list.yview)
        self.inc_list.configure(yscrollcommand=inc_vsb.set)
        self.inc_list.pack(side="left", fill="both", expand=True)
        inc_vsb.pack(side="right", fill="y")
        inc_btns = ctk.CTkFrame(inc_row, fg_color="transparent")
        inc_btns.pack(side="right", fill="y", padx=16)
        for txt, cmd, fg in [
            ("Neu",  lambda: self.smart_path_action("INC", "ADD"),  ACCENT2),
            ("Edit", lambda: self.smart_path_action("INC", "EDIT"), "#95a5a6"),
            ("Del",  lambda: self.delete_entry("INC"),              ACCENT),
        ]:
            ctk.CTkButton(inc_btns, text=txt, width=96, height=36,
                          fg_color=fg, corner_radius=10,
                          command=cmd).pack(pady=4)

        # Exclude paths
        ctk.CTkLabel(path_f, text="Pfad-Chirurgie (Exclude -)",
                     font=("Segoe UI", 17, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", pady=(18, 4))
        exc_row = ctk.CTkFrame(path_f, fg_color="transparent")
        exc_row.pack(fill="both", expand=True)
        exc_box = ctk.CTkFrame(exc_row, fg_color=CARD_BG, corner_radius=10,
                               border_width=1, border_color=BORDER)
        exc_box.pack(side="left", fill="both", expand=True)
        self.exc_list = ttk.Treeview(exc_box, columns=("Status", "Path"),
                                     show="headings", height=8)
        self.exc_list.heading("Status", text="S")
        self.exc_list.column("Status", width=50, anchor="center")
        self.exc_list.heading("Path", text="Pfad")
        self.exc_list.column("Path", width=800)
        exc_vsb = ttk.Scrollbar(exc_box, orient="vertical", command=self.exc_list.yview)
        self.exc_list.configure(yscrollcommand=exc_vsb.set)
        self.exc_list.pack(side="left", fill="both", expand=True)
        exc_vsb.pack(side="right", fill="y")
        exc_btns = ctk.CTkFrame(exc_row, fg_color="transparent")
        exc_btns.pack(side="right", fill="y", padx=16)
        for txt, cmd, fg in [
            ("Neu",  lambda: self.smart_path_action("EXC", "ADD"),  ACCENT2),
            ("Edit", lambda: self.smart_path_action("EXC", "EDIT"), "#95a5a6"),
            ("Del",  lambda: self.delete_entry("EXC"),              ACCENT),
        ]:
            ctk.CTkButton(exc_btns, text=txt, width=96, height=36,
                          fg_color=fg, corner_radius=10,
                          command=cmd).pack(pady=4)

        # Right: patterns + quick actions
        right = ctk.CTkFrame(view, fg_color="transparent")
        right.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(0, 20), pady=15)

        pat_card = ctk.CTkFrame(right, fg_color=CARD_BG, corner_radius=16,
                                border_width=1, border_color=BORDER)
        pat_card.pack(fill="both", expand=True, pady=(0, 10))
        ctk.CTkLabel(pat_card, text="Globale Muster",
                     font=("Segoe UI", 15, "bold"),
                     text_color=TEXT_DARK).pack(pady=(14, 0))
        self.pat_text = ctk.CTkTextbox(pat_card, width=240, height=200,
                                       font=("Consolas", 12),
                                       fg_color=MAIN_BG, border_width=0)
        self.pat_text.pack(padx=14, pady=6, fill="both", expand=True)
        ctk.CTkButton(pat_card, text="Muster speichern", height=34,
                      fg_color=ACCENT2, hover_color="#2aB09A",
                      corner_radius=10,
                      command=self.save_patterns).pack(pady=10)

        act_card = ctk.CTkFrame(right, fg_color=CARD_BG, corner_radius=16,
                                border_width=1, border_color=BORDER)
        act_card.pack(fill="x")
        ctk.CTkButton(act_card, text="LISTE NEU LADEN", height=46,
                      fg_color=SIDEBAR_BG, hover_color=SIDEBAR_HOVER,
                      corner_radius=12, font=("Segoe UI", 13, "bold"),
                      command=self.load_all_configs).pack(
            fill="x", padx=14, pady=(14, 6))
        ctk.CTkButton(act_card, text="SYSTEM-SCAN STARTEN", height=46,
                      fg_color=ACCENT, hover_color="#C94A38",
                      corner_radius=12, font=("Segoe UI", 13, "bold"),
                      command=self.start_deep_scan).pack(
            fill="x", padx=14, pady=(0, 14))

    def setup_view_dashboard(self):
        """Build the APK analysis grid (the main working view)."""
        view = ctk.CTkFrame(self._content_area, fg_color=MAIN_BG, corner_radius=0)
        view.grid(row=0, column=0, sticky="nsew")
        view.grid_remove()
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(0, weight=1)
        self._views["dashboard"] = view

        container = ctk.CTkFrame(view, fg_color=CARD_BG, corner_radius=14,
                                 border_width=1, border_color=BORDER)
        container.pack(fill="both", expand=True, padx=20, pady=15)
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        style.configure("APK.Treeview",
                        rowheight=52, font=("Segoe UI", 12),
                        background=CARD_BG, fieldbackground=CARD_BG,
                        foreground=TEXT_DARK)
        style.configure("APK.Treeview.Heading",
                        font=("Segoe UI", 12, "bold"),
                        background=MAIN_BG, foreground=TEXT_DARK)
        style.map("APK.Treeview",
                  background=[("selected", "#DDEEFF")],
                  foreground=[("selected", TEXT_DARK)])

        cols = ("?", "Status", "App-Name", "ID", "Version", "Größe", "Pfad")
        self.sel_tree = ttk.Treeview(container, columns=cols,
                                     show="headings", selectmode="none",
                                     style="APK.Treeview")
        col_cfg = {
            "?":       (60,  "center"),
            "Status":  (150, "w"),
            "App-Name":(260, "w"),
            "ID":      (270, "w"),
            "Version": (120, "center"),
            "Größe":   (120, "center"),
            "Pfad":    (680, "w"),
        }
        for col in cols:
            w, anch = col_cfg[col]
            self.sel_tree.heading(col, text=col,
                                  command=lambda c=col: self.sort_column_monolith(c))
            self.sel_tree.column(col, width=w, anchor=anch)

        vsb = ttk.Scrollbar(container, orient="vertical", command=self.sel_tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self.sel_tree.xview)
        self.sel_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.sel_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.sel_tree.bind("<ButtonRelease-1>", self.on_tree_click_monolith)
        self.sel_tree.bind("<Button-3>", self.show_context_menu_monolith)

    def setup_view_pipeline(self):
        """Build the Pipeline control view (strategy, queue, run/kill)."""
        view = ctk.CTkFrame(self._content_area, fg_color=MAIN_BG, corner_radius=0)
        view.grid(row=0, column=0, sticky="nsew")
        view.grid_remove()
        self._views["pipeline"] = view

        main = ctk.CTkFrame(view, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=40, pady=30)

        # Strategy card
        strat = ctk.CTkFrame(main, fg_color=CARD_BG, corner_radius=16,
                             border_width=1, border_color=BORDER)
        strat.pack(fill="x", pady=(0, 14))
        ctk.CTkLabel(strat, text="Archivierungs-Strategie",
                     font=("Segoe UI", 16, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=20, pady=(14, 6))
        strat_row = ctk.CTkFrame(strat, fg_color="transparent")
        strat_row.pack(fill="x", padx=20, pady=(0, 14))
        self.mode_var = ctk.StringVar(value="FULL")
        for text, val in [
            ("Vollständig (Logic+UX+Rebuild)", "FULL"),
            ("Nur Design-Ernte",               "UI"),
            ("Nur Code & Forensik",            "CODE"),
            ("Raw (Originalstruktur)",         "RAW"),
        ]:
            ctk.CTkRadioButton(strat_row, text=text, variable=self.mode_var,
                               value=val, font=("Segoe UI", 13),
                               text_color=TEXT_DARK,
                               fg_color=ACCENT).pack(side="left", padx=16)

        # Queue card
        queue_card = ctk.CTkFrame(main, fg_color=CARD_BG, corner_radius=16,
                                  border_width=1, border_color=BORDER)
        queue_card.pack(fill="both", expand=True, pady=(0, 14))
        ctk.CTkLabel(queue_card, text="Aktive Warteschlange",
                     font=("Segoe UI", 16, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=20, pady=(14, 6))
        self.pipe_scroll = ctk.CTkScrollableFrame(
            queue_card, fg_color="transparent", height=280)
        self.pipe_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        # Control card
        ctrl_card = ctk.CTkFrame(main, fg_color=CARD_BG, corner_radius=16,
                                 border_width=1, border_color=BORDER)
        ctrl_card.pack(fill="x")
        ctrl_row = ctk.CTkFrame(ctrl_card, fg_color="transparent")
        ctrl_row.pack(pady=18, padx=20)
        self.start_btn = ctk.CTkButton(
            ctrl_row, text="PIPELINE STARTEN", width=340, height=64,
            font=("Segoe UI", 19, "bold"),
            fg_color="#27ae60", hover_color="#1e8449", corner_radius=14,
            command=self.run_pipeline_monolith,
        )
        self.start_btn.pack(side="left", padx=10)
        ctk.CTkButton(
            ctrl_row, text="ABBRUCH / KILL", width=190, height=64,
            fg_color=ACCENT, hover_color="#C94A38",
            font=("Segoe UI", 15), corner_radius=14,
            command=self.kill_current,
        ).pack(side="left", padx=10)

    # =========================================================================
    # APK METADATA
    # =========================================================================

    def get_apk_metadata(self, apk_path):
        """Extracts identity via Androguard with byte-level fallback."""
        try:
            if ANDROGUARD_AVAILABLE:
                a = APK(apk_path)
                return (a.get_app_name(), a.get_package(),
                        a.get_version_name(), str(a.get_version_code()))
        except Exception:
            pass
        try:
            with zipfile.ZipFile(apk_path) as z:
                with z.open("AndroidManifest.xml") as f:
                    data = f.read()
                    matches = re.findall(rb'[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]+', data)
                    if matches:
                        return "Unbenannt", matches[0].decode(), "v?", "0"
        except Exception:
            pass
        return "Unidentifiziert", "err.apk", "ERR", "0"

    def get_apk_extended_metadata(self, apk_path):
        """Extract certificate signer and SDK versions (Androguard only).

        Returns a dict with 'signer', 'min_sdk', 'target_sdk' keys.
        Values are ``None`` when the information cannot be extracted.
        """
        info = {"signer": None, "min_sdk": None, "target_sdk": None}
        if not ANDROGUARD_AVAILABLE:
            return info
        try:
            a = APK(apk_path)
            info["min_sdk"] = a.get_min_sdk_version()
            info["target_sdk"] = a.get_target_sdk_version()
            certs = a.get_certificates()
            if certs:
                cert = certs[0]
                subject = cert.subject
                parts = []
                for attr in subject:
                    parts.append(f"{attr.oid._name}={attr.value}")
                info["signer"] = ", ".join(parts) if parts else str(subject)
        except Exception:
            pass
        return info

    # =========================================================================
    # SCAN
    # =========================================================================

    def start_deep_scan(self):
        if not self.include_paths:
            messagebox.showwarning("Fehler", "Keine Quellen definiert.")
            return
        self.status_var.set("Deep Scan läuft...")
        self.log("Starte systemweite Forensik-Analyse...")
        threading.Thread(target=self.logic_deep_scan_monolith, daemon=True).start()

    def logic_deep_scan_monolith(self):
        self.apk_registry = []
        id_map = {}
        norm_exc = [p.lower() for p in self.exclude_paths]
        patterns = [p.strip().lower()
                    for p in self.pat_text.get("1.0", "end").split("\n") if p.strip()]

        for src in self.include_paths:
            if not os.path.exists(src):
                self.log(f"Offline: {src}")
                continue
            for root, dirs, files in os.walk(src):
                dirs[:] = [
                    d for d in dirs
                    if os.path.normpath(os.path.join(root, d)).lower() not in norm_exc
                ]
                dirs[:] = [d for d in dirs
                           if not any(p in d.lower() for p in patterns)]
                for f in files:
                    if f.lower().endswith(".apk"):
                        fp = os.path.normpath(os.path.join(root, f))
                        app, pid, ver, code = self.get_apk_metadata(fp)
                        sz = os.path.getsize(fp)
                        sz_mb = sz / (1024 * 1024)
                        sha = self._apk_sha256(fp)
                        status, tag = "ORIGINAL", ""
                        if pid != "err.apk":
                            if pid in id_map:
                                if sha in id_map[pid]:
                                    status, tag = "DUBLETTE", "duplicate"
                                else:
                                    status, tag = "ANDERE VER.", "version"
                                    id_map[pid].append(sha)  # only add truly new hashes
                            else:
                                id_map[pid] = [sha]
                        else:
                            status, tag = "UNBEKANNT", "unknown"
                        self.apk_registry.append({
                            "checked": False, "status": status,
                            "app": app, "id": pid, "ver": ver,
                            "code": code, "size_mb": sz_mb,
                            "path": fp, "tag": tag, "sha256": sha,
                        })
        self.after(0, self.update_selection_table_monolith)

    # =========================================================================
    # PIPELINE
    # =========================================================================

    def run_pipeline_monolith(self):
        if not self.pipeline_queue:
            return
        self.is_running = True
        self.start_btn.configure(state="disabled")
        threading.Thread(target=self.pipeline_thread_monolith, daemon=True).start()

    def pipeline_thread_monolith(self):
        strat = self.mode_var.get()
        total = len(self.pipeline_queue)
        processed = 0
        while self.pipeline_queue:
            if not self.is_running:
                break
            apk_p = self.pipeline_queue.pop(0)
            processed += 1
            app_n, pkg, ver, code = self.get_apk_metadata(apk_p)
            pct = int(processed / total * 100) if total else 0
            self.log(f"\n--- [{processed}/{total} · {pct}%] HARVESTING: {app_n} ---")
            self.after(0, lambda p=pct, n=app_n:
                       self.status_var.set(f"Pipeline {p}% – {n}"))

            ext_meta = self.get_apk_extended_metadata(apk_p)

            target_dir = os.path.join(self.library_dir,
                                      f"{pkg.replace('.', '_')}_v{ver}")
            os.makedirs(target_dir, exist_ok=True)
            workspace = os.path.join(target_dir, "_TEMP_WS")
            apktool_jar = os.path.join(self.script_dir, "apktool.jar")

            if self.run_cmd(
                ["java", "-Xmx4G", "-jar", apktool_jar, "d", apk_p,
                 "-o", workspace, "-f"]) == 0:
                relevant_classes = []
                threat_details = {}
                if strat == "RAW":
                    self.security_only_scan_monolith(workspace, target_dir)
                else:
                    if strat in ("FULL", "CODE"):
                        relevant_classes, threat_details = (
                            self.harvest_code_monolith(workspace, target_dir, pkg))
                    if strat in ("FULL", "UI"):
                        self.harvest_ux_monolith(workspace, target_dir)
                    if strat == "FULL":
                        self.run_cmd([
                            "java", "-Xmx4G", "-jar", apktool_jar, "b", workspace,
                            "-o", os.path.join(target_dir, f"rebuilt_v{ver}.apk"),
                        ])

                permissions = self._extract_permissions_from_manifest(workspace)
                domains = self._extract_network_domains(workspace)
                self.generate_monolithic_report(
                    target_dir, app_n, pkg, ver, code, apk_p,
                    relevant_classes, permissions, domains,
                    threat_details=threat_details,
                    ext_meta=ext_meta,
                )
                if strat != "RAW":
                    shutil.rmtree(workspace, ignore_errors=True)
                self.log(f"Archivierung beendet: {app_n}")

            self.after(0, self.refresh_pipeline_ui)

        self.is_running = False
        self.after(0, lambda: [
            self.start_btn.configure(state="normal"),
            self.status_var.set("Pipeline beendet."),
        ])

    # =========================================================================
    # IMAGE HARVEST: readable names + semantic grouping
    # =========================================================================

    def _readable_name(self, filename):
        """Expand filename abbreviations and capitalize path segments.

        Examples:
            btn_ok.png  -> (Button_Ok, .png)
            ic_launcher -> (Icon_Launcher, .png)
            my_screen   -> (My_Screen, .png)
        """
        base, ext = os.path.splitext(filename)
        base_lower = base.lower()
        for abbr, full in self.ABBR_MAP:
            if base_lower.startswith(abbr.lower()):
                remainder = base[len(abbr):]
                parts = re.split(r'[_\-]+', remainder)
                remainder = "_".join(p.capitalize() for p in parts if p)
                return full + remainder, ext
        # No abbreviation matched – just capitalise segments
        parts = re.split(r'[_\-]+', base)
        return "_".join(p.capitalize() for p in parts if p), ext

    def harvest_ux_monolith(self, ws, target):
        """Extract images into COMPARE_IMAGES/Category/BaseName/density.ext.

        Grouping rules:
        * Category is derived from the readable filename prefix (Button, Icon…)
        * Files with the same base name (different densities) share one folder
        * density is the suffix after 'drawable-' (hdpi, xhdpi, …)
        * Duplicate density files are not overwritten
        """
        compare_p = os.path.join(target, "COMPARE_IMAGES")
        os.makedirs(compare_p, exist_ok=True)
        res_p = os.path.join(ws, "res")
        if not os.path.exists(res_p):
            return

        density_re = re.compile(r'drawable-(\w+)', re.IGNORECASE)

        for root, _, files in os.walk(res_p):
            dir_name = os.path.basename(root)
            m = density_re.search(dir_name)
            density = m.group(1) if m else "default"

            for f in files:
                if not f.lower().endswith((".png", ".jpg", ".webp", ".xml")):
                    continue

                readable_base, ext = self._readable_name(f)

                # Determine category folder from prefix
                category = "Other"
                for prefix, cat in self.CATEGORY_PREFIXES.items():
                    if readable_base.startswith(prefix):
                        category = cat
                        break

                dest_dir = os.path.join(compare_p, category, readable_base)
                os.makedirs(dest_dir, exist_ok=True)

                dest_file = os.path.join(dest_dir, f"{density}{ext}")
                if not os.path.exists(dest_file):  # skip duplicate densities
                    shutil.copy2(os.path.join(root, f), dest_file)

    # =========================================================================
    # CODE HARVEST: returns relevant entry-point classes
    # =========================================================================

    def harvest_code_monolith(self, ws, target, pkg_id):
        """Harvest smali; return (relevant_classes, threat_details) for Overview.md.

        *threat_details* maps category → list of flagged filenames so the report
        can show exactly which threat categories were triggered.
        """
        p_core = os.path.join(target, "_CODE")
        p_sdk  = os.path.join(target, "_SDK")
        p_sec  = os.path.join(target, "_THREATS")
        for d in (p_core, p_sdk, p_sec):
            os.makedirs(d, exist_ok=True)

        pkg_sl = pkg_id.replace(".", "/")
        relevant_classes = []
        threat_details: dict[str, list[str]] = {}
        ENTRY_KEYWORDS = (
            "mainactivity", "service", "manager", "handler",
            "receiver", "provider", "worker",
        )

        for i in range(1, 15):
            s_dir = os.path.join(ws, "smali" if i == 1 else f"smali_classes{i}")
            if not os.path.exists(s_dir):
                continue
            for root, _, files in os.walk(s_dir):
                rel = os.path.relpath(root, s_dir)
                rel_fwd = rel.replace("\\", "/")
                is_sdk  = any(s in rel_fwd for s in self.SDK_PATTERNS)
                is_core = pkg_sl in rel_fwd and not is_sdk
                dest = p_core if is_core else p_sdk

                for f in files:
                    if not f.endswith(".smali"):
                        continue
                    src = os.path.join(root, f)
                    try:
                        with open(src, "r", errors="ignore") as c:
                            content = c.read()
                    except Exception:
                        continue

                    # Categorised threat scan
                    flagged = False
                    for cat, sigs in self.THREATS.items():
                        if any(sig in content for sig in sigs):
                            flagged = True
                            threat_details.setdefault(cat, []).append(f)
                    if flagged:
                        shutil.copy2(src, os.path.join(
                            p_sec, f"{rel.replace(os.sep, '_')}_{f}"))

                    # Relevance detection (only for core app code)
                    if is_core:
                        cls_m = re.search(r'\.class\s+\S+\s+L([^;]+);', content)
                        if cls_m:
                            class_name = cls_m.group(1).replace("/", ".")
                            method_count = content.count(".method ")
                            has_oncreate = "onCreate(" in content
                            is_entry = any(kw in class_name.lower()
                                          for kw in ENTRY_KEYWORDS)
                            if has_oncreate or is_entry or method_count > 15:
                                relevant_classes.append(class_name)

                    df = os.path.join(dest, rel)
                    os.makedirs(df, exist_ok=True)
                    shutil.copy2(src, os.path.join(df, f))

        return relevant_classes, threat_details

    def security_only_scan_monolith(self, ws, target):
        sec_p = os.path.join(target, "_SECURITY_RAW")
        os.makedirs(sec_p, exist_ok=True)
        for root, _, files in os.walk(ws):
            for f in files:
                if f.endswith(".smali"):
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, "r", errors="ignore") as c:
                            if any(sig in c.read()
                                   for sub in self.THREATS.values() for sig in sub):
                                shutil.copy2(fp, os.path.join(sec_p, f))
                    except Exception:
                        pass

    # =========================================================================
    # PERMISSION EXTRACTION (reads decoded AndroidManifest.xml from workspace)
    # =========================================================================

    def _extract_permissions_from_manifest(self, workspace):
        """Parse the apktool-decoded AndroidManifest.xml and return short permission names."""
        manifest = os.path.join(workspace, "AndroidManifest.xml")
        permissions = []
        if not os.path.exists(manifest):
            return permissions
        try:
            tree = ET.parse(manifest)
            root = tree.getroot()
            ns = "http://schemas.android.com/apk/res/android"
            for elem in root.iter("uses-permission"):
                name = elem.get(f"{{{ns}}}name") or elem.get("android:name", "")
                if name:
                    short = (name
                             .replace("android.permission.", "")
                             .replace("com.android.browser.permission.", ""))
                    permissions.append(short)
        except Exception:
            pass
        return permissions

    # =========================================================================
    # NETWORK DOMAIN EXTRACTION
    # =========================================================================

    def _extract_network_domains(self, workspace):
        """Scan smali files for http/https URLs; return a deduplicated sorted domain list."""
        domains = set()
        url_re = re.compile(r'https?://([a-zA-Z0-9._\-]+)', re.IGNORECASE)
        for root, _, files in os.walk(workspace):
            for f in files:
                if not f.endswith(".smali"):
                    continue
                fp = os.path.join(root, f)
                try:
                    with open(fp, "r", errors="ignore") as c:
                        for m in url_re.finditer(c.read()):
                            host = m.group(1).lower().rstrip(".")
                            if "." in host and len(host) > 4:
                                domains.add(host)
                except Exception:
                    pass
        return sorted(domains)

    # =========================================================================
    # OVERVIEW.MD GENERATION
    # =========================================================================

    def generate_monolithic_report(self, target, name, pkg, ver, code, origin,
                                   relevant_classes=None, permissions=None,
                                   domains=None, *, threat_details=None,
                                   ext_meta=None):
        """Write Overview.md + Overview.json with categorised threat details."""
        if relevant_classes is None:
            relevant_classes = []
        if permissions is None:
            permissions = []
        if domains is None:
            domains = []
        if threat_details is None:
            threat_details = {}
        if ext_meta is None:
            ext_meta = {}

        # Classify permissions
        critical = sorted(p for p in permissions if p in self.PERMISSIONS_CRITICAL)
        notable  = sorted(p for p in permissions if p in self.PERMISSIONS_NOTABLE)
        normal   = sorted(p for p in permissions
                          if p not in self.PERMISSIONS_CRITICAL
                          and p not in self.PERMISSIONS_NOTABLE)

        # Split domains into ad/tracking and regular
        ad_domains    = [d for d in domains
                         if any(ad in d for ad in self.AD_DOMAINS)]
        clean_domains = [d for d in domains if d not in ad_domains]

        timestamp = time.ctime()

        lines = [
            f"# Overview: {name}",
            "",
            f"* **Package:** `{pkg}`",
            f"* **Version:** `{ver}` (Code: {code})",
            f"* **Source:** `{origin}`",
            f"* **Date:** {timestamp}",
        ]

        # Extended metadata (signer, SDK versions)
        signer = ext_meta.get("signer")
        min_sdk = ext_meta.get("min_sdk")
        target_sdk = ext_meta.get("target_sdk")
        if min_sdk or target_sdk:
            lines.append(
                f"* **SDK:** min {min_sdk or '?'} / target {target_sdk or '?'}")
        if signer:
            lines.append(f"* **Signiert von:** `{signer}`")
        lines.append("")

        # --- Entry points ---
        lines += ["## Einstieg (vermutlich relevant)", ""]
        if relevant_classes:
            for cls in relevant_classes[:20]:
                lines.append(f"* `{cls}`")
        else:
            lines.append("* *(keine Kern-Klassen gefunden – ggf. obfuskiert)*")
        lines.append("")

        # --- Permissions ---
        lines += ["## Berechtigungen", ""]
        if critical:
            lines += ["### ⚠️ Auffällig:", ""]
            for p in critical:
                lines.append(f"* `{p}` -- ungewöhnlich / potenziell kritisch")
            lines.append("")
        if notable:
            lines += ["### ℹ️ Beachtenswert:", ""]
            for p in notable:
                lines.append(f"* `{p}`")
            lines.append("")
        if normal:
            lines += ["### ✅ Unkritisch:", ""]
            for p in normal:
                lines.append(f"* `{p}`")
            lines.append("")
        if not permissions:
            lines += ["*(keine Berechtigungen erkannt)*", ""]

        # --- Network ---
        lines += ["## Netzwerk", ""]
        if clean_domains:
            for d in clean_domains[:30]:
                lines.append(f"* `{d}`")
            lines.append("")
        if ad_domains:
            lines += ["### 📢 Werbe-/Tracking-Domains:", ""]
            for d in ad_domains:
                lines.append(f"* `{d}` *(Ads/Tracking)*")
            lines.append("")
        if not domains:
            lines += ["*(keine URLs gefunden)*", ""]

        # --- Categorised threat summary ---
        lines += ["## Threat-Hinweise", ""]
        threat_dir = os.path.join(target, "_THREATS")
        if threat_details:
            total_threat_files = sum(len(v) for v in threat_details.values())
            lines.append(
                f"* **{total_threat_files}** verdächtige Datei(en) in "
                f"**{len(threat_details)}** Kategorie(n):")
            lines.append("")
            for cat in sorted(threat_details):
                lines.append(f"  * **{cat}**: {len(threat_details[cat])} Treffer")
            lines.append("")
        elif os.path.exists(threat_dir):
            threat_files = os.listdir(threat_dir)
            if threat_files:
                lines.append(
                    f"* {len(threat_files)} verdächtige Smali-Datei(en) in `_THREATS/`")
            else:
                lines.append("* Keine auffälligen Muster gefunden")
        else:
            lines.append("* *(Threat-Scan nicht ausgeführt)*")
        lines.append("")

        # --- Write Markdown report ---
        out_md = os.path.join(target, "Overview.md")
        with open(out_md, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        self.log(f"Overview.md erstellt: {out_md}")

        # --- Write JSON report (machine-readable, enables CI/automation) ---
        report_data = {
            "package": pkg,
            "app_name": name,
            "version": ver,
            "version_code": code,
            "source": origin,
            "date": timestamp,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "signer": signer,
            "entry_points": relevant_classes[:20],
            "permissions": {
                "critical": critical,
                "notable": notable,
                "normal": normal,
            },
            "network": {
                "domains": clean_domains,
                "ad_tracking": ad_domains,
            },
            "threats": {cat: len(files) for cat, files in threat_details.items()},
        }
        out_json = os.path.join(target, "Overview.json")
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, ensure_ascii=False)
        self.log(f"Overview.json erstellt: {out_json}")

    # =========================================================================
    # TABLE / GRID
    # =========================================================================

    def update_selection_table_monolith(self):
        for i in self.sel_tree.get_children():
            self.sel_tree.delete(i)
        for it in self.apk_registry:
            m = "[x]" if it["checked"] else "[  ]"
            self.sel_tree.insert(
                "", "end",
                values=(m, it["status"], it["app"], it["id"],
                        it["ver"], f"{it['size_mb']:.1f} MB", it["path"]),
                tags=(it["tag"],),
            )
        self.sel_tree.tag_configure("duplicate", background="#ffdada")
        self.sel_tree.tag_configure("version",   background="#fff4d1")
        self._switch_view("dashboard")
        self._update_sidebar_stats()
        self.update_stats_monolith()

    def on_tree_click_monolith(self, event):
        item = self.sel_tree.identify_row(event.y)
        col  = self.sel_tree.identify_column(event.x)
        if item and col == "#1":
            idx = self.sel_tree.index(item)
            self.apk_registry[idx]["checked"] = not self.apk_registry[idx]["checked"]
            self.sel_tree.set(
                item, column="?",
                value="[x]" if self.apk_registry[idx]["checked"] else "[  ]",
            )
            self.update_stats_monolith()

    def select_all_monolith(self, state):
        for it in self.apk_registry:
            it["checked"] = state
        self.update_selection_table_monolith()

    def select_all_duplicates_monolith(self):
        for it in self.apk_registry:
            if it["tag"] == "duplicate":
                it["checked"] = True
        self.update_selection_table_monolith()

    def delete_physically_monolith(self):
        sel = [it for it in self.apk_registry if it["checked"]]
        if sel and messagebox.askyesno("Löschen?",
                                       f"{len(sel)} Dateien wirklich löschen?"):
            for it in sel:
                try:
                    os.remove(it["path"])
                    self.apk_registry = [
                        x for x in self.apk_registry if x["path"] != it["path"]
                    ]
                except Exception:
                    pass
            self.update_selection_table_monolith()

    def update_stats_monolith(self):
        total = len(self.apk_registry)
        sel   = sum(1 for x in self.apk_registry if x["checked"])
        gb    = sum(x["size_mb"] for x in self.apk_registry) / 1024
        self.stats_var.set(f"{total} APKs | {sel} ausgewählt | {gb:.2f} GB total")

    def sort_column_monolith(self, col):
        data = [(self.sel_tree.set(k, col), k) for k in self.sel_tree.get_children("")]
        rev  = not self.sort_states[col]
        if col == "Größe":
            data.sort(key=lambda x: float(x[0].split()[0]), reverse=rev)
        else:
            data.sort(key=lambda x: str(x[0]).lower(), reverse=rev)
        for i, (_, k) in enumerate(data):
            self.sel_tree.move(k, "", i)
        self.sort_states[col] = rev

    @staticmethod
    def _open_folder(path):
        """Open *path* in the platform's file manager (cross-platform)."""
        folder = os.path.dirname(str(path))
        system = platform.system()
        if system == "Windows":
            os.startfile(folder)
        elif system == "Darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder])

    def show_context_menu_monolith(self, event):
        item = self.sel_tree.identify_row(event.y)
        if item:
            self.sel_tree.selection_set(item)
            m = Menu(self, tearoff=0)
            p = self.sel_tree.item(item)["values"][6]
            m.add_command(label="Im Explorer öffnen",
                          command=lambda: self._open_folder(p))
            m.post(event.x_root, event.y_root)

    def filter_table(self):
        val = self.search_var.get().lower()
        for i in self.sel_tree.get_children():
            row_text = "".join(map(str, self.sel_tree.item(i)["values"])).lower()
            if val in row_text:
                self.sel_tree.reattach(i, "", "end")
            else:
                self.sel_tree.detach(i)

    # =========================================================================
    # PROCESS RUNNER
    # =========================================================================

    def run_cmd(self, args):
        """Run a subprocess; args must be a list (shell=False prevents injection)."""
        p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        self.current_pid = p.pid
        for line in p.stdout:
            self.log(f"  {line.strip()}")
        return p.wait()

    def kill_current(self):
        if self.current_pid:
            try:
                pa = psutil.Process(self.current_pid)
                for c in pa.children(recursive=True):
                    c.kill()
                pa.kill()
            except Exception:
                pass
        self.is_running = False

    # =========================================================================
    # PIPELINE UI
    # =========================================================================

    def move_to_pipeline_monolith(self):
        self.pipeline_queue.extend(
            [x["path"] for x in self.apk_registry if x["checked"]])
        self.refresh_pipeline_ui()
        self._switch_view("pipeline")

    def refresh_pipeline_ui(self):
        for w in self.pipe_scroll.winfo_children():
            w.destroy()
        for p in self.pipeline_queue:
            ctk.CTkLabel(self.pipe_scroll,
                         text=f"- {os.path.basename(p)}").pack(anchor="w", padx=25)

    # =========================================================================
    # CONFIG PERSISTENCE
    # =========================================================================

    def save_all_to_txt(self):
        try:
            with open(self.config_file, "w", encoding="utf-8") as fh:
                fh.write("# APK Master Sources\n")
                for p in self.include_paths:
                    fh.write(f"INC:{p}\n")
                for p in self.exclude_paths:
                    fh.write(f"EXC:{p}\n")
        except Exception as e:
            self.log(f"Fehler beim Speichern: {e}")

    def save_patterns(self):
        try:
            with open(self.patterns_file, "w", encoding="utf-8") as fh:
                fh.write(self.pat_text.get("1.0", "end"))
            self.log("Muster gespeichert.")
        except Exception as e:
            self.log(f"Fehler: {e}")

    def load_all_configs(self):
        self.include_paths = []
        self.exclude_paths = []
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith("INC:"):
                            self.include_paths.append(line[4:])
                        elif line.startswith("EXC:"):
                            self.exclude_paths.append(line[4:])
            except Exception:
                pass
        if os.path.exists(self.patterns_file):
            try:
                with open(self.patterns_file, "r", encoding="utf-8") as fh:
                    content = fh.read()
                if hasattr(self, "pat_text") and self.pat_text:
                    self.pat_text.delete("1.0", "end")
                    self.pat_text.insert("1.0", content)
            except Exception:
                pass
        self.refresh_config_ui()
        self.log("Konfiguration geladen.")

    def refresh_config_ui(self):
        for tree, paths in [(self.inc_list, self.include_paths),
                            (self.exc_list, self.exclude_paths)]:
            for i in tree.get_children():
                tree.delete(i)
            for p in paths:
                status = "✓" if os.path.exists(p) else "✗"
                tree.insert("", "end", values=(status, p))

    # =========================================================================
    # LOG
    # =========================================================================

    def log(self, msg):
        """Thread-safe: puts message on queue; drained into the widget by _drain_log."""
        self._log_queue.put(msg)

    def _drain_log(self):
        """Consume queued log messages in the main thread (called via after())."""
        while not self._log_queue.empty():
            try:
                msg = self._log_queue.get_nowait()
                if self.log_text:
                    self.log_text.insert("end", f"> {msg}\n")
                    self.log_text.see("end")
            except queue.Empty:
                break
        self.after(100, self._drain_log)

    def _export_log(self):
        """Save the current log console content to a text file."""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Log", "*.log")],
            initialfile=f"apk_master_log_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self.log_text.get("1.0", "end"))
                self.log(f"Log exportiert: {path}")
            except Exception as e:
                self.log(f"Fehler beim Log-Export: {e}")

    # =========================================================================
    # PATH MANAGEMENT
    # =========================================================================

    def smart_path_action(self, t_type, mode):
        t_list = self.include_paths if t_type == "INC" else self.exclude_paths
        initial = "/"
        sel = None
        if mode == "EDIT":
            tree = self.inc_list if t_type == "INC" else self.exc_list
            sel = tree.selection()
            if sel:
                initial = tree.item(sel[0])["values"][1]
        new_p = filedialog.askdirectory(initialdir=initial)
        if new_p:
            cp = os.path.normpath(new_p)
            if mode == "EDIT" and sel:
                tree = self.inc_list if t_type == "INC" else self.exc_list
                old_v = tree.item(sel[0])["values"][1]
                if old_v in t_list:
                    t_list[t_list.index(old_v)] = cp
            elif cp not in t_list:
                t_list.append(cp)
            self.save_all_to_txt()
            self.refresh_config_ui()

    def delete_entry(self, t_type):
        tree = self.inc_list if t_type == "INC" else self.exc_list
        sel = tree.selection()
        if sel:
            v = tree.item(sel[0])["values"][1]
            lst = self.include_paths if t_type == "INC" else self.exclude_paths
            if v in lst:
                lst.remove(v)
            self.save_all_to_txt()
            self.refresh_config_ui()


if __name__ == "__main__":
    app = APKMasterV59()
    app.mainloop()
