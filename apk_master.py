import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk, Menu
import os, threading, subprocess, zipfile, shutil, psutil, re, time
import xml.etree.ElementTree as ET

# --- FORENSIC ENGINE IMPORT ---
try:
    from androguard.core.bytecodes.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


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
        self.geometry("1800x1100")

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
        self.THREATS = {
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

    # =========================================================================
    # UI SETUP
    # =========================================================================

    def setup_ui(self):
        """Log widget is built first so it exists before load_all_configs is called."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(3, weight=0)

        # 1. LOG (must come before everything that calls self.log())
        self.log_text = ctk.CTkTextbox(
            self, height=150, font=("Consolas", 11),
            fg_color="#1a1a1a", text_color="#00ff00",
        )
        self.log_text.grid(row=3, column=0, sticky="ew", padx=25, pady=(0, 20))

        # 2. HEADER
        header = ctk.CTkFrame(self, height=90, fg_color="#ffffff", corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        title_f = ctk.CTkFrame(header, fg_color="transparent")
        title_f.pack(side="left", padx=40)
        ctk.CTkLabel(title_f, text="APK Master V59",
                     font=("Segoe UI", 34, "bold")).pack(anchor="w")
        ctk.CTkLabel(title_f, text="APK Analysis Tool",
                     font=("Segoe UI", 13), text_color="gray").pack(anchor="w")
        self.status_var = ctk.StringVar(value="Bereit.")
        ctk.CTkLabel(header, textvariable=self.status_var,
                     font=("Segoe UI", 16, "bold"),
                     text_color="#2980b9").pack(side="right", padx=50)

        # 3. TABS
        self.tabs = ctk.CTkTabview(self, fg_color="white", border_width=1, corner_radius=20)
        self.tabs.grid(row=1, column=0, padx=30, pady=(10, 5), sticky="nsew")
        self.tab_cfg  = self.tabs.add(" 1. KONFIGURATION ")
        self.tab_sel  = self.tabs.add(" 2. ANALYSE-GRID ")
        self.tab_pipe = self.tabs.add(" 3. PIPELINE-STEUERUNG ")

        self.setup_tab_config_monolith()
        self.setup_tab_selection_monolith()
        self.setup_tab_pipeline_monolith()

    def setup_tab_config_monolith(self):
        self.tab_cfg.grid_columnconfigure(0, weight=3)
        self.tab_cfg.grid_columnconfigure(1, weight=1)
        self.tab_cfg.grid_rowconfigure(0, weight=1)
        self.tab_cfg.grid_rowconfigure(1, weight=1)

        path_frame = ctk.CTkFrame(self.tab_cfg, fg_color="transparent")
        path_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=25, pady=15)

        # -- SOURCES --
        ctk.CTkLabel(path_frame, text="Quell-Verzeichnisse (Include +)",
                     font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(10, 5))
        inc_c = ctk.CTkFrame(path_frame, fg_color="transparent")
        inc_c.pack(fill="both", expand=True)
        inc_tf = ctk.CTkFrame(inc_c, fg_color="white", border_width=1)
        inc_tf.pack(side="left", fill="both", expand=True)
        self.inc_list = ttk.Treeview(inc_tf, columns=("Status", "Path"),
                                     show="headings", height=8)
        self.inc_list.heading("Status", text="S")
        self.inc_list.column("Status", width=50, anchor="center")
        self.inc_list.heading("Path", text="Pfad")
        self.inc_list.column("Path", width=850)
        inc_vsb = ttk.Scrollbar(inc_tf, orient="vertical", command=self.inc_list.yview)
        self.inc_list.configure(yscrollcommand=inc_vsb.set)
        self.inc_list.pack(side="left", fill="both", expand=True)
        inc_vsb.pack(side="right", fill="y")
        inc_btn_f = ctk.CTkFrame(inc_c, fg_color="transparent")
        inc_btn_f.pack(side="right", fill="y", padx=20)
        ctk.CTkButton(inc_btn_f, text="Neu", width=110, height=40,
                      command=lambda: self.smart_path_action("INC", "ADD")).pack(pady=5)
        ctk.CTkButton(inc_btn_f, text="Edit", width=110, height=40, fg_color="#95a5a6",
                      command=lambda: self.smart_path_action("INC", "EDIT")).pack(pady=5)
        ctk.CTkButton(inc_btn_f, text="Del", width=110, height=40, fg_color="#e74c3c",
                      command=lambda: self.delete_entry("INC")).pack(pady=5)

        # -- EXCLUDE --
        ctk.CTkLabel(path_frame, text="Pfad-Chirurgie (Exclude -)",
                     font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(20, 5))
        exc_c = ctk.CTkFrame(path_frame, fg_color="transparent")
        exc_c.pack(fill="both", expand=True)
        exc_tf = ctk.CTkFrame(exc_c, fg_color="white", border_width=1)
        exc_tf.pack(side="left", fill="both", expand=True)
        self.exc_list = ttk.Treeview(exc_tf, columns=("Status", "Path"),
                                     show="headings", height=8)
        self.exc_list.heading("Status", text="S")
        self.exc_list.column("Status", width=50, anchor="center")
        self.exc_list.heading("Path", text="Pfad")
        self.exc_list.column("Path", width=850)
        exc_vsb = ttk.Scrollbar(exc_tf, orient="vertical", command=self.exc_list.yview)
        self.exc_list.configure(yscrollcommand=exc_vsb.set)
        self.exc_list.pack(side="left", fill="both", expand=True)
        exc_vsb.pack(side="right", fill="y")
        exc_btn_f = ctk.CTkFrame(exc_c, fg_color="transparent")
        exc_btn_f.pack(side="right", fill="y", padx=20)
        ctk.CTkButton(exc_btn_f, text="Neu", width=110, height=40,
                      command=lambda: self.smart_path_action("EXC", "ADD")).pack(pady=5)
        ctk.CTkButton(exc_btn_f, text="Edit", width=110, height=40, fg_color="#95a5a6",
                      command=lambda: self.smart_path_action("EXC", "EDIT")).pack(pady=5)
        ctk.CTkButton(exc_btn_f, text="Del", width=110, height=40, fg_color="#e74c3c",
                      command=lambda: self.delete_entry("EXC")).pack(pady=5)

        # -- PATTERNS & ACTIONS --
        pat_f = ctk.CTkFrame(self.tab_cfg, fg_color="#f9f9f9", corner_radius=20, border_width=1)
        pat_f.grid(row=0, column=1, sticky="nsew", padx=(0, 30), pady=(45, 15))
        ctk.CTkLabel(pat_f, text="Globale Muster",
                     font=("Segoe UI", 18, "bold")).pack(pady=10)
        self.pat_text = ctk.CTkTextbox(pat_f, width=280, height=250, font=("Consolas", 12))
        self.pat_text.pack(padx=15, pady=5, fill="both", expand=True)
        ctk.CTkButton(pat_f, text="Muster speichern", height=35,
                      command=self.save_patterns).pack(pady=15)

        act_f = ctk.CTkFrame(self.tab_cfg, fg_color="transparent")
        act_f.grid(row=1, column=1, sticky="nsew", padx=(0, 30), pady=15)
        ctk.CTkButton(act_f, text="LISTE NEU LADEN", width=250, height=70,
                      fg_color="#95a5a6", font=("Segoe UI", 15, "bold"),
                      command=self.load_all_configs).pack(pady=10, fill="x")
        ctk.CTkButton(act_f, text="SYSTEM-SCAN STARTEN", width=250, height=110,
                      font=("Segoe UI", 22, "bold"), fg_color="#27ae60",
                      command=self.start_deep_scan).pack(pady=10, fill="x")

        # -- FOOTER STATISTICS --
        self.footer = ctk.CTkFrame(self, height=40, fg_color="#f2f2f2", corner_radius=0)
        self.footer.grid(row=2, column=0, sticky="ew")
        self.stats_var = ctk.StringVar(value="0 APKs | 0 ausgewählt | 0.00 GB total")
        ctk.CTkLabel(self.footer, textvariable=self.stats_var,
                     font=("Segoe UI", 13)).pack(side="left", padx=25)

    def setup_tab_selection_monolith(self):
        tools = ctk.CTkFrame(self.tab_sel, fg_color="transparent")
        tools.pack(fill="x", padx=35, pady=25)

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.filter_table())
        search_entry = ctk.CTkEntry(
            tools, placeholder_text="Live-Filter: Name, Package-ID oder Pfad...",
            textvariable=self.search_var, width=600, height=50, font=("Segoe UI", 14),
        )
        search_entry.pack(side="left")

        btn_f = ctk.CTkFrame(tools, fg_color="transparent")
        btn_f.pack(side="right")
        ctk.CTkButton(btn_f, text="Alle wählen", width=140, height=50,
                      fg_color="#34495e",
                      command=lambda: self.select_all_monolith(True)).pack(side="left", padx=10)
        ctk.CTkButton(btn_f, text="Auswahl aufheben", width=140, height=50,
                      fg_color="#95a5a6",
                      command=lambda: self.select_all_monolith(False)).pack(side="left", padx=10)
        ctk.CTkButton(btn_f, text="DUBLETTEN MARKIEREN", height=50,
                      fg_color="#e67e22", font=("Segoe UI", 13, "bold"),
                      command=self.select_all_duplicates_monolith).pack(side="left", padx=10)

        grid_container = ctk.CTkFrame(self.tab_sel, fg_color="white",
                                      border_width=1, corner_radius=10)
        grid_container.pack(fill="both", expand=True, padx=35, pady=5)

        style = ttk.Style()
        style.configure("Treeview", rowheight=55, font=("Segoe UI", 13))
        style.configure("Treeview.Heading", font=("Segoe UI", 14, "bold"))

        cols = ("?", "Status", "App-Name", "ID", "Version", "Größe", "Pfad")
        self.sel_tree = ttk.Treeview(grid_container, columns=cols,
                                     show="headings", selectmode="none")
        for col in cols:
            self.sel_tree.heading(col, text=col,
                                  command=lambda c=col: self.sort_column_monolith(c))
            w = {"?": 70, "Status": 160, "App-Name": 280, "ID": 280,
                 "Version": 130, "Größe": 130, "Pfad": 700}
            self.sel_tree.column(
                col, width=w.get(col, 100),
                anchor="center" if col in ["?", "Größe", "Version"] else "w",
            )

        vsb = ttk.Scrollbar(grid_container, orient="vertical", command=self.sel_tree.yview)
        hsb = ttk.Scrollbar(grid_container, orient="horizontal", command=self.sel_tree.xview)
        self.sel_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.sel_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        grid_container.grid_columnconfigure(0, weight=1)
        grid_container.grid_rowconfigure(0, weight=1)

        self.sel_tree.bind("<ButtonRelease-1>", self.on_tree_click_monolith)
        self.sel_tree.bind("<Button-3>", self.show_context_menu_monolith)

        action_bar = ctk.CTkFrame(self.tab_sel, fg_color="transparent")
        action_bar.pack(fill="x", padx=35, pady=30)
        ctk.CTkButton(action_bar, text="MARKIERTE DATEIEN PHYSISCH LÖSCHEN",
                      height=70, fg_color="#c0392b", font=("Segoe UI", 16, "bold"),
                      command=self.delete_physically_monolith).pack(side="left")
        ctk.CTkButton(action_bar, text="GEWÄHLTE IN PIPELINE ÜBERNEHMEN",
                      height=70, fg_color="#2ecc71", font=("Segoe UI", 20, "bold"),
                      command=self.move_to_pipeline_monolith).pack(side="right")

    def setup_tab_pipeline_monolith(self):
        main = ctk.CTkFrame(self.tab_pipe, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=45, pady=35)

        ctk.CTkLabel(main, text="Archivierungs-Strategie wählen:",
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")
        strat_frame = ctk.CTkFrame(main, fg_color="#f2f2f2", corner_radius=20, border_width=1)
        strat_frame.pack(fill="x", pady=20)
        self.mode_var = ctk.StringVar(value="FULL")
        strats = [
            ("Vollständig (Logic+UX+Rebuild)", "FULL"),
            ("Nur Design-Ernte",               "UI"),
            ("Nur Code & Forensik",            "CODE"),
            ("Raw (Originalstruktur)",         "RAW"),
        ]
        for text, val in strats:
            ctk.CTkRadioButton(strat_frame, text=text, variable=self.mode_var, value=val,
                               font=("Segoe UI", 15, "bold")).pack(side="left",
                                                                   padx=35, pady=30)

        self.pipe_scroll = ctk.CTkScrollableFrame(
            main, label_text="Aktive Warteschlange", height=450,
            label_font=("Segoe UI", 14, "bold"),
        )
        self.pipe_scroll.pack(fill="both", expand=True, pady=10)

        ctrl_frame = ctk.CTkFrame(main, fg_color="transparent")
        ctrl_frame.pack(pady=40)
        self.start_btn = ctk.CTkButton(
            ctrl_frame, text="PIPELINE STARTEN", width=450, height=90,
            font=("Segoe UI", 24, "bold"), fg_color="#27ae60",
            command=self.run_pipeline_monolith,
        )
        self.start_btn.pack(side="left", padx=20)
        ctk.CTkButton(ctrl_frame, text="ABBRUCH / KILL", width=220, height=90,
                      fg_color="#e74c3c", font=("Segoe UI", 18),
                      command=self.kill_current).pack(side="left", padx=20)

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
                        status, tag = "ORIGINAL", ""
                        if pid != "err.apk":
                            if pid in id_map:
                                if sz in id_map[pid]:
                                    status, tag = "DUBLETTE", "duplicate"
                                else:
                                    status, tag = "ANDERE VER.", "version"
                                id_map[pid].append(sz)
                            else:
                                id_map[pid] = [sz]
                        else:
                            status, tag = "UNBEKANNT", "unknown"
                        self.apk_registry.append({
                            "checked": False, "status": status,
                            "app": app, "id": pid, "ver": ver,
                            "code": code, "size_mb": sz_mb,
                            "path": fp, "tag": tag,
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
        while self.pipeline_queue:
            if not self.is_running:
                break
            apk_p = self.pipeline_queue.pop(0)
            app_n, pkg, ver, code = self.get_apk_metadata(apk_p)
            self.log(f"\n--- HARVESTING: {app_n} ---")

            target_dir = os.path.join(self.library_dir,
                                      f"{pkg.replace('.', '_')}_v{ver}")
            os.makedirs(target_dir, exist_ok=True)
            workspace = os.path.join(target_dir, "_TEMP_WS")

            if self.run_cmd(
                f'java -Xmx4G -jar apktool.jar d "{apk_p}" -o "{workspace}" -f'
            ) == 0:
                relevant_classes = []
                if strat == "RAW":
                    self.security_only_scan_monolith(workspace, target_dir)
                else:
                    if strat in ("FULL", "CODE"):
                        relevant_classes = self.harvest_code_monolith(
                            workspace, target_dir, pkg)
                    if strat in ("FULL", "UI"):
                        self.harvest_ux_monolith(workspace, target_dir)
                    if strat == "FULL":
                        self.run_cmd(
                            f'java -Xmx4G -jar apktool.jar b "{workspace}"'
                            f' -o "{target_dir}/rebuilt_v{ver}.apk"'
                        )

                permissions = self._extract_permissions_from_manifest(workspace)
                domains = self._extract_network_domains(workspace)
                self.generate_monolithic_report(
                    target_dir, app_n, pkg, ver, code, apk_p,
                    relevant_classes, permissions, domains,
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
        """Harvest smali; return list of relevant class names for Overview.md."""
        p_core = os.path.join(target, "_CODE")
        p_sdk  = os.path.join(target, "_SDK")
        p_sec  = os.path.join(target, "_THREATS")
        for d in (p_core, p_sdk, p_sec):
            os.makedirs(d, exist_ok=True)

        pkg_sl = pkg_id.replace(".", "/")
        relevant_classes = []
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

                    # Threat scan
                    if any(sig in content
                           for sub in self.THREATS.values() for sig in sub):
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

        return relevant_classes

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
                                   domains=None):
        """Write Overview.md with permission classification and domain deduplication."""
        if relevant_classes is None:
            relevant_classes = []
        if permissions is None:
            permissions = []
        if domains is None:
            domains = []

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

        lines = [
            f"# Overview: {name}",
            "",
            f"* **Package:** `{pkg}`",
            f"* **Version:** `{ver}` (Code: {code})",
            f"* **Source:** `{origin}`",
            f"* **Date:** {time.ctime()}",
            "",
        ]

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

        # --- Threat summary ---
        lines += ["## Threat-Hinweise", ""]
        threat_dir = os.path.join(target, "_THREATS")
        if os.path.exists(threat_dir):
            threat_files = os.listdir(threat_dir)
            if threat_files:
                lines.append(
                    f"* {len(threat_files)} verdächtige Smali-Datei(en) in `_THREATS/`")
            else:
                lines.append("* Keine auffälligen Muster gefunden")
        else:
            lines.append("* *(Threat-Scan nicht ausgeführt)*")
        lines.append("")

        out_path = os.path.join(target, "Overview.md")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        self.log(f"Overview.md erstellt: {out_path}")

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
        self.tabs.set(" 2. ANALYSE-GRID ")
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

    def show_context_menu_monolith(self, event):
        item = self.sel_tree.identify_row(event.y)
        if item:
            self.sel_tree.selection_set(item)
            m = Menu(self, tearoff=0)
            p = self.sel_tree.item(item)["values"][6]
            m.add_command(label="Im Explorer öffnen",
                          command=lambda: os.startfile(os.path.dirname(p)))
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

    def run_cmd(self, cmd):
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
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
        self.tabs.set(" 3. PIPELINE-STEUERUNG ")

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
        if self.log_text:
            self.log_text.insert("end", f"> {msg}\n")
            self.log_text.see("end")

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
