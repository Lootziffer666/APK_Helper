"""APK Forensic Knowledge Base (AFKB)

Frontend and query system for the MY_APP_LIBRARY produced by APK Master.
Indexes metadata.json / Overview.json sidecar files, provides full-text code
search across all extracted Smali files, SDK auditing, threat filtering, and
a three-column desktop UI.

Usage:
    python afkb.py                         # opens the GUI
    python afkb.py --library /path/to/lib  # opens with library pre-selected

Tech stack:
    * customtkinter  – modern desktop GUI
    * sqlite3        – metadata index & fast queries
    * threading      – non-blocking code search
"""

from __future__ import annotations

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, ttk
import sqlite3
import json
import os
import re
import hashlib
import threading
import subprocess
import platform
import sys
import time
from pathlib import Path
from collections import defaultdict

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ── Colour palette (matches APK Master) ─────────────────────────────────────
SIDEBAR_BG    = "#1B2642"
SIDEBAR_HOVER = "#243352"
MAIN_BG       = "#EEF0F6"
CARD_BG       = "#FFFFFF"
ACCENT        = "#E8604C"
ACCENT2       = "#38C9B3"
TEXT_LIGHT    = "#FFFFFF"
TEXT_MUTED    = "#8E9BB3"
TEXT_DARK     = "#1B2642"
BORDER        = "#E2E6F0"


# ═══════════════════════════════════════════════════════════════════════════════
# INDEXER  –  crawls MY_APP_LIBRARY, builds / updates a SQLite index
# ═══════════════════════════════════════════════════════════════════════════════

class AFKBIndexer:
    """Background engine that crawls MY_APP_LIBRARY and maintains a SQLite
    index over every *metadata.json* (preferred) or *Overview.json* sidecar."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS apps (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id   TEXT    NOT NULL,
        app_name     TEXT    DEFAULT '',
        version_name TEXT    DEFAULT '',
        version_code INTEGER DEFAULT 0,
        sha256       TEXT    DEFAULT '',
        threat_score REAL    DEFAULT 0.0,
        folder_path  TEXT    UNIQUE NOT NULL,
        source_apk   TEXT    DEFAULT '',
        min_sdk      INTEGER,
        target_sdk   INTEGER,
        signer       TEXT    DEFAULT '',
        date_analyzed TEXT   DEFAULT '',
        core_files   INTEGER DEFAULT 0,
        sdk_files    INTEGER DEFAULT 0,
        layout_count INTEGER DEFAULT 0,
        indexed_at   TEXT    DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sdks (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        sdk_name   TEXT    NOT NULL,
        file_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS threats (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id    INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        category  TEXT    NOT NULL,
        hit_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS permissions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        permission TEXT    NOT NULL,
        severity   TEXT    DEFAULT 'normal'
    );
    CREATE TABLE IF NOT EXISTS components (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id    INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
        comp_type TEXT    NOT NULL,
        comp_name TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_apps_pkg    ON apps(package_id);
    CREATE INDEX IF NOT EXISTS idx_sdks_app    ON sdks(app_id);
    CREATE INDEX IF NOT EXISTS idx_threats_app ON threats(app_id);
    CREATE INDEX IF NOT EXISTS idx_perms_app   ON permissions(app_id);
    CREATE INDEX IF NOT EXISTS idx_comps_app   ON components(app_id);
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()

    # ── indexing ─────────────────────────────────────────────────────────────

    def index_library(self, library_path: str, progress_cb=None) -> int:
        """Walk *library_path* and (re-)index every app folder.

        *progress_cb(current, total, folder_name)* is called for UI updates.
        Returns the number of successfully indexed entries.
        """
        if not os.path.isdir(library_path):
            return 0
        entries = sorted(os.listdir(library_path))
        total = len(entries)
        indexed = 0
        for i, folder in enumerate(entries):
            folder_path = os.path.join(library_path, folder)
            if not os.path.isdir(folder_path):
                continue
            # prefer metadata.json, fall back to Overview.json
            meta_path = os.path.join(folder_path, "metadata.json")
            if not os.path.exists(meta_path):
                meta_path = os.path.join(folder_path, "Overview.json")
            if not os.path.exists(meta_path):
                continue
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                self._upsert_app(folder_path, data, meta_path)
                indexed += 1
            except Exception:
                pass
            if progress_cb:
                progress_cb(i + 1, total, folder)
        self.conn.commit()
        return indexed

    def _upsert_app(self, folder_path: str, data: dict, meta_path: str):
        """Insert or update a single app entry from its JSON sidecar."""
        cur = self.conn.cursor()
        is_meta = meta_path.endswith("metadata.json")

        if is_meta:
            pkg       = data.get("package_id", "")
            name      = data.get("app_name", "")
            ver       = data.get("version_name", "")
            ver_code  = _int(data.get("version_code", 0))
            sha       = data.get("sha256", "")
            tscore    = float(data.get("threat_score", 0))
            source    = ""
            min_sdk   = None
            target_sdk = None
            signer    = ""
            date      = ""
            core      = 0
            sdk_n     = 0
            layouts   = 0
            sdk_list  = data.get("found_sdk", [])
            sdk_inv   = {s: 0 for s in sdk_list} if isinstance(sdk_list, list) else {}
            hits      = data.get("heuristic_hits", {})
            perms     = {}
            comps     = {}
        else:  # Overview.json
            pkg        = data.get("package", "")
            name       = data.get("app_name", "")
            ver        = data.get("version", "")
            ver_code   = _int(data.get("version_code", 0))
            sha        = data.get("sha256", "")
            source     = data.get("source", "")
            min_sdk    = data.get("min_sdk")
            target_sdk = data.get("target_sdk")
            signer     = data.get("signer") or ""
            date       = data.get("date", "")
            cs         = data.get("code_stats") or {}
            core       = cs.get("core_files", 0) if isinstance(cs, dict) else 0
            sdk_n      = cs.get("sdk_files", 0)  if isinstance(cs, dict) else 0
            layouts    = data.get("layout_count", 0)
            sdk_inv    = data.get("sdk_inventory") or {}
            hits       = data.get("threats") or {}
            perms      = data.get("permissions") or {}
            comps      = data.get("components") or {}

            total_hits = sum(
                v if isinstance(v, (int, float)) else len(v)
                for v in hits.values())
            crit_perms = len(perms.get("critical", []))
            tscore = min(10.0, round(total_hits / 5 + crit_perms * 0.5, 1))

        cur.execute("""
            INSERT INTO apps
                (package_id, app_name, version_name, version_code, sha256,
                 threat_score, folder_path, source_apk, min_sdk, target_sdk,
                 signer, date_analyzed, core_files, sdk_files, layout_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(folder_path) DO UPDATE SET
                package_id=excluded.package_id, app_name=excluded.app_name,
                version_name=excluded.version_name, version_code=excluded.version_code,
                sha256=excluded.sha256, threat_score=excluded.threat_score,
                source_apk=excluded.source_apk, min_sdk=excluded.min_sdk,
                target_sdk=excluded.target_sdk, signer=excluded.signer,
                date_analyzed=excluded.date_analyzed, core_files=excluded.core_files,
                sdk_files=excluded.sdk_files, layout_count=excluded.layout_count,
                indexed_at=datetime('now')
        """, (pkg, name, ver, ver_code, sha, tscore, folder_path, source,
              min_sdk, target_sdk, signer, date, core, sdk_n, layouts))

        app_id = cur.execute(
            "SELECT id FROM apps WHERE folder_path=?",
            (folder_path,)).fetchone()[0]

        # Clear stale relations
        for tbl in ("sdks", "threats", "permissions", "components"):
            cur.execute(f"DELETE FROM {tbl} WHERE app_id=?", (app_id,))

        # SDKs
        if isinstance(sdk_inv, dict):
            for sdk, cnt in sdk_inv.items():
                cur.execute(
                    "INSERT INTO sdks (app_id,sdk_name,file_count) VALUES (?,?,?)",
                    (app_id, sdk, _int(cnt)))

        # Threats
        if isinstance(hits, dict):
            for cat, val in hits.items():
                cnt = len(val) if isinstance(val, list) else _int(val)
                cur.execute(
                    "INSERT INTO threats (app_id,category,hit_count) VALUES (?,?,?)",
                    (app_id, cat, cnt))

        # Permissions
        if isinstance(perms, dict):
            for severity, plist in perms.items():
                if isinstance(plist, list):
                    for p in plist:
                        cur.execute(
                            "INSERT INTO permissions (app_id,permission,severity) "
                            "VALUES (?,?,?)", (app_id, p, severity))

        # Components
        if isinstance(comps, dict):
            for comp_type, names in comps.items():
                if isinstance(names, list):
                    for n in names:
                        cur.execute(
                            "INSERT INTO components (app_id,comp_type,comp_name) "
                            "VALUES (?,?,?)", (app_id, comp_type, n))

    # ── queries ──────────────────────────────────────────────────────────────

    def get_all_packages(self) -> dict[str, list[dict]]:
        """Return ``{package_id: [row_dict, …]}`` ordered by version_code."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT package_id, app_name, version_name, version_code,
                   threat_score, folder_path, id
            FROM apps ORDER BY package_id, version_code DESC
        """)
        pkgs: dict[str, list[dict]] = defaultdict(list)
        for row in cur.fetchall():
            pkgs[row["package_id"]].append(dict(row))
        return dict(pkgs)

    def get_app_details(self, app_id: int) -> dict:
        row = self.conn.execute(
            "SELECT * FROM apps WHERE id=?", (app_id,)).fetchone()
        if row is None:
            return {}
        app = dict(row)
        app["sdks"] = [dict(r) for r in self.conn.execute(
            "SELECT sdk_name, file_count FROM sdks "
            "WHERE app_id=? ORDER BY file_count DESC", (app_id,))]
        app["threats"] = [dict(r) for r in self.conn.execute(
            "SELECT category, hit_count FROM threats "
            "WHERE app_id=? ORDER BY hit_count DESC", (app_id,))]
        app["permissions"] = [dict(r) for r in self.conn.execute(
            "SELECT permission, severity FROM permissions WHERE app_id=?",
            (app_id,))]
        app["components"] = [dict(r) for r in self.conn.execute(
            "SELECT comp_type, comp_name FROM components WHERE app_id=?",
            (app_id,))]
        return app

    def search_by_sdk(self, query: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute("""
            SELECT DISTINCT a.id, a.package_id, a.app_name, a.version_name,
                   a.threat_score, s.sdk_name, s.file_count
            FROM apps a JOIN sdks s ON a.id=s.app_id
            WHERE s.sdk_name LIKE ? ORDER BY s.file_count DESC
        """, (f"%{query}%",))]

    def search_by_threat(self, category: str | None = None) -> list[dict]:
        if category:
            return [dict(r) for r in self.conn.execute("""
                SELECT a.id, a.package_id, a.app_name, a.version_name,
                       a.threat_score, t.category, t.hit_count
                FROM apps a JOIN threats t ON a.id=t.app_id
                WHERE t.category LIKE ? AND t.hit_count>0
                ORDER BY t.hit_count DESC
            """, (f"%{category}%",))]
        return [dict(r) for r in self.conn.execute("""
            SELECT a.id, a.package_id, a.app_name, a.version_name,
                   a.threat_score, t.category, t.hit_count
            FROM apps a JOIN threats t ON a.id=t.app_id
            WHERE t.hit_count>0 ORDER BY a.threat_score DESC, t.hit_count DESC
        """)]

    def search_by_permission(self, perm: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute("""
            SELECT DISTINCT a.id, a.package_id, a.app_name, a.version_name,
                   a.threat_score, p.permission, p.severity
            FROM apps a JOIN permissions p ON a.id=p.app_id
            WHERE p.permission LIKE ? ORDER BY a.package_id
        """, (f"%{perm}%",))]

    def get_versions(self, package_id: str) -> list[dict]:
        """Multi-version timeline for a single package."""
        return [dict(r) for r in self.conn.execute("""
            SELECT * FROM apps WHERE package_id=? ORDER BY version_code
        """, (package_id,))]

    def get_stats(self, library_path: str | None = None) -> dict:
        c = self.conn
        stats: dict = {}
        stats["total_apps"]     = c.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
        stats["total_packages"] = c.execute(
            "SELECT COUNT(DISTINCT package_id) FROM apps").fetchone()[0]
        stats["total_sdks"]     = c.execute(
            "SELECT COUNT(DISTINCT sdk_name) FROM sdks").fetchone()[0]
        avg = c.execute(
            "SELECT ROUND(AVG(threat_score),1) FROM apps").fetchone()[0]
        stats["avg_threat_score"] = avg or 0.0
        if library_path and os.path.isdir(library_path):
            total = 0
            for dp, _, fns in os.walk(library_path):
                for fn in fns:
                    try:
                        total += os.path.getsize(os.path.join(dp, fn))
                    except OSError:
                        pass
            stats["total_size_gb"] = round(total / (1024 ** 3), 2)
        else:
            stats["total_size_gb"] = 0.0
        return stats

    def close(self):
        if self.conn:
            self.conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# CODE SEARCHER  –  live grep through Smali files
# ═══════════════════════════════════════════════════════════════════════════════

class CodeSearcher:
    """Performs live regular-expression grep across .smali files."""

    @staticmethod
    def search_smali(library_path: str, query: str, *,
                     max_results: int = 500) -> list[dict]:
        """Return up to *max_results* matching lines from all .smali files."""
        results: list[dict] = []
        try:
            pattern = re.compile(re.escape(query), re.IGNORECASE)
        except re.error:
            return results
        for root, _, files in os.walk(library_path):
            for fname in files:
                if not fname.endswith(".smali"):
                    continue
                fp = os.path.join(root, fname)
                try:
                    with open(fp, "r", errors="ignore") as fh:
                        for line_no, line in enumerate(fh, 1):
                            if pattern.search(line):
                                results.append({
                                    "file": os.path.relpath(fp, library_path),
                                    "line": line_no,
                                    "text": line.strip()[:200],
                                    "full_path": fp,
                                })
                                if len(results) >= max_results:
                                    return results
                except Exception:
                    continue
        return results

    @staticmethod
    def content_hash(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            return ""
        return h.hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# AFKB  –  main application (three-column customtkinter UI)
# ═══════════════════════════════════════════════════════════════════════════════

class AFKB(ctk.CTk):
    """APK Forensic Knowledge Base – desktop application."""

    def __init__(self, library_path: str | None = None):
        super().__init__()
        self.title("APK Forensic Knowledge Base (AFKB)")
        self.geometry("1400x850")
        self.minsize(1000, 600)

        self.library_path: str = library_path or ""
        self.indexer: AFKBIndexer | None = None
        self.current_app_id: int | None = None
        self._search_thread: threading.Thread | None = None

        self._build_ui()

        # auto-open if path supplied via CLI
        if self.library_path:
            self.after(200, self._load_library)

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        # ── top bar ──────────────────────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color=SIDEBAR_BG, height=48,
                           corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)

        ctk.CTkLabel(
            top, text="\U0001f50d APK Forensic Knowledge Base",
            text_color=TEXT_LIGHT, font=("", 16, "bold"),
        ).pack(side="left", padx=16)

        self.lib_label = ctk.CTkLabel(
            top, text="Kein Archiv geladen",
            text_color=TEXT_MUTED, font=("", 12))
        self.lib_label.pack(side="left", padx=16)

        ctk.CTkButton(
            top, text="\U0001f4c1 Archiv \u00f6ffnen", width=140,
            fg_color=ACCENT2, hover_color="#2eb8a3", text_color=TEXT_LIGHT,
            command=self._open_library,
        ).pack(side="right", padx=8, pady=8)

        ctk.CTkButton(
            top, text="\U0001f504 Neu indizieren", width=140,
            fg_color=ACCENT, hover_color="#d45540", text_color=TEXT_LIGHT,
            command=self._reindex,
        ).pack(side="right", padx=8, pady=8)

        # ── status bar ───────────────────────────────────────────────────────
        status = ctk.CTkFrame(self, fg_color=BORDER, height=28,
                              corner_radius=0)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        self.status_var = tk.StringVar(value="Bereit.")
        ctk.CTkLabel(status, textvariable=self.status_var,
                     text_color=TEXT_MUTED, font=("", 11)
                     ).pack(side="left", padx=12)

        # ── three-column body ────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color=MAIN_BG, corner_radius=0)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1, minsize=260)
        body.grid_columnconfigure(1, weight=3, minsize=400)
        body.grid_columnconfigure(2, weight=2, minsize=300)
        body.grid_rowconfigure(0, weight=1)

        self._build_left(body)
        self._build_middle(body)
        self._build_right(body)

    # ── LEFT column – library tree ───────────────────────────────────────────

    def _build_left(self, parent):
        left = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)

        ctk.CTkLabel(left, text="\U0001f4e6 Bibliothek",
                     font=("", 14, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=12,
                                                pady=(12, 4))

        self.tree_filter = ctk.CTkEntry(
            left, placeholder_text="Filter (Package-ID)\u2026", height=30)
        self.tree_filter.pack(fill="x", padx=8, pady=4)
        self.tree_filter.bind("<KeyRelease>", lambda _: self._filter_tree())

        tree_frame = ctk.CTkFrame(left, fg_color=CARD_BG, corner_radius=0)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=4)

        style = ttk.Style()
        style.configure("AFKB.Treeview", background=CARD_BG,
                        fieldbackground=CARD_BG, font=("", 11),
                        rowheight=26)

        self.lib_tree = ttk.Treeview(tree_frame, show="tree",
                                     selectmode="browse",
                                     style="AFKB.Treeview")
        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           command=self.lib_tree.yview)
        self.lib_tree.configure(yscrollcommand=sb.set)
        self.lib_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.lib_tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    # ── MIDDLE column – content / wiki ───────────────────────────────────────

    def _build_middle(self, parent):
        mid = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=8)
        mid.grid(row=0, column=1, sticky="nsew", padx=4, pady=8)

        ctk.CTkLabel(mid, text="\U0001f4cb Details", font=("", 14, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=12,
                                                pady=(12, 4))

        self.detail_frame = ctk.CTkScrollableFrame(
            mid, fg_color=CARD_BG, corner_radius=0)
        self.detail_frame.pack(fill="both", expand=True, padx=4, pady=4)

        self.detail_placeholder = ctk.CTkLabel(
            self.detail_frame,
            text="App in der Bibliothek ausw\u00e4hlen\u2026",
            text_color=TEXT_MUTED, font=("", 13))
        self.detail_placeholder.pack(pady=40)

    # ── RIGHT column – inspector / search ────────────────────────────────────

    def _build_right(self, parent):
        right = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=8)
        right.grid(row=0, column=2, sticky="nsew", padx=(4, 8), pady=8)

        ctk.CTkLabel(right, text="\U0001f50e Suche & Inspektor",
                     font=("", 14, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=12,
                                                pady=(12, 4))

        # search type selector
        sf = ctk.CTkFrame(right, fg_color=CARD_BG)
        sf.pack(fill="x", padx=8, pady=4)
        self.search_type = ctk.CTkSegmentedButton(
            sf, values=["Code", "SDK", "Threat", "Permission"],
            command=self._on_search_type)
        self.search_type.set("Code")
        self.search_type.pack(fill="x")

        # search entry + button
        ef = ctk.CTkFrame(right, fg_color=CARD_BG)
        ef.pack(fill="x", padx=8, pady=4)
        self.search_entry = ctk.CTkEntry(
            ef, placeholder_text="Smali-Code durchsuchen\u2026", height=32)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.search_entry.bind("<Return>", lambda _: self._run_search())
        ctk.CTkButton(ef, text="Suchen", width=70, fg_color=ACCENT2,
                      hover_color="#2eb8a3", text_color=TEXT_LIGHT,
                      command=self._run_search).pack(side="right")

        # results text area
        rf = ctk.CTkFrame(right, fg_color=CARD_BG, corner_radius=0)
        rf.pack(fill="both", expand=True, padx=4, pady=4)

        self.result_text = tk.Text(
            rf, wrap="word", font=("Consolas", 10), bg=CARD_BG,
            fg=TEXT_DARK, relief="flat", state="disabled", padx=8, pady=8)
        rsb = ttk.Scrollbar(rf, orient="vertical",
                            command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=rsb.set)
        self.result_text.pack(side="left", fill="both", expand=True)
        rsb.pack(side="right", fill="y")

        self.result_text.tag_configure("heading", font=("", 11, "bold"),
                                       foreground=TEXT_DARK)
        self.result_text.tag_configure("match", foreground=ACCENT)
        self.result_text.tag_configure("path", foreground=TEXT_MUTED)
        self.result_text.tag_configure("stat_label",
                                       font=("", 11, "bold"))

        # stats panel
        sp = ctk.CTkFrame(right, fg_color="#F8F9FC", corner_radius=6)
        sp.pack(fill="x", padx=8, pady=(4, 8))
        ctk.CTkLabel(sp, text="\U0001f4ca Statistiken",
                     font=("", 12, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=8,
                                                pady=(8, 2))
        self.stats_label = ctk.CTkLabel(
            sp, text="\u2014", text_color=TEXT_MUTED,
            font=("", 11), justify="left")
        self.stats_label.pack(anchor="w", padx=8, pady=(0, 8))

    # ── library management ───────────────────────────────────────────────────

    def _open_library(self):
        path = filedialog.askdirectory(
            title="MY_APP_LIBRARY Ordner w\u00e4hlen")
        if not path:
            return
        self.library_path = path
        self._load_library()

    def _load_library(self):
        """Open / create index for current *library_path*."""
        self.lib_label.configure(text=os.path.basename(self.library_path))
        db_path = os.path.join(self.library_path, "afkb_index.db")
        if self.indexer:
            self.indexer.close()
        self.indexer = AFKBIndexer(db_path)
        if not os.path.exists(db_path) or os.path.getsize(db_path) < 4096:
            self._reindex()
        else:
            self._refresh_tree()
            self._update_stats()

    def _reindex(self):
        if not self.library_path or not self.indexer:
            return
        self.status_var.set("Indizierung l\u00e4uft\u2026")
        self.update_idletasks()

        def _worker():
            count = self.indexer.index_library(
                self.library_path,
                progress_cb=lambda i, t, n: self.after(
                    0, lambda: self.status_var.set(
                        f"Indiziere {i}/{t}: {n}")))
            self.after(0, lambda: [
                self.status_var.set(
                    f"Indizierung abgeschlossen: {count} App(s)"),
                self._refresh_tree(),
                self._update_stats(),
            ])

        threading.Thread(target=_worker, daemon=True).start()

    # ── tree ─────────────────────────────────────────────────────────────────

    def _refresh_tree(self):
        self.lib_tree.delete(*self.lib_tree.get_children())
        if not self.indexer:
            return
        packages = self.indexer.get_all_packages()
        self._populate_tree(packages)

    def _populate_tree(self, packages: dict[str, list[dict]],
                       expand: bool = False):
        for pkg, versions in sorted(packages.items()):
            worst = max((v.get("threat_score", 0) for v in versions),
                        default=0)
            ind = _threat_dot(worst)
            node = self.lib_tree.insert("", "end",
                                        text=f"{ind} {pkg}", open=expand)
            for v in versions:
                vi = _threat_dot(v.get("threat_score", 0))
                label = f"{vi} v{v['version_name']}"
                aname = v.get("app_name")
                if aname:
                    label += f"  ({aname})"
                self.lib_tree.insert(node, "end", text=label,
                                     values=(v["id"],))

    def _filter_tree(self):
        q = self.tree_filter.get().lower().strip()
        self.lib_tree.delete(*self.lib_tree.get_children())
        if not self.indexer:
            return
        packages = self.indexer.get_all_packages()
        if not q:
            self._populate_tree(packages)
            return
        filtered = {
            pkg: vers for pkg, vers in packages.items()
            if q in pkg.lower()
            or any(q in (v.get("app_name") or "").lower() for v in vers)
        }
        self._populate_tree(filtered, expand=True)

    def _on_tree_select(self, _event):
        sel = self.lib_tree.selection()
        if not sel:
            return
        vals = self.lib_tree.item(sel[0], "values")
        if not vals:
            return  # package-level node
        self.current_app_id = int(vals[0])
        self._show_details(self.current_app_id)

    # ── detail view ──────────────────────────────────────────────────────────

    def _show_details(self, app_id: int):
        if not self.indexer:
            return
        app = self.indexer.get_app_details(app_id)
        if not app:
            return

        # clear
        for w in self.detail_frame.winfo_children():
            w.destroy()
        fr = self.detail_frame

        # --- header ---
        display_name = app.get("app_name") or app.get("package_id") or "?"
        ctk.CTkLabel(fr, text=display_name, font=("", 18, "bold"),
                     text_color=TEXT_DARK).pack(anchor="w", padx=8,
                                                pady=(8, 2))

        # --- metadata table ---
        mf = ctk.CTkFrame(fr, fg_color="#F8F9FC", corner_radius=6)
        mf.pack(fill="x", padx=8, pady=4)
        fields = [
            ("Package",      app.get("package_id", "")),
            ("Version",
             f"{app.get('version_name','?')} "
             f"(Code: {app.get('version_code','?')})"),
            ("SHA-256",      (app.get("sha256") or "\u2014")[:64]),
            ("SDK",
             f"min {app.get('min_sdk') or '?'} / "
             f"target {app.get('target_sdk') or '?'}"),
            ("Signiert",     app.get("signer") or "\u2014"),
            ("Analysiert",   app.get("date_analyzed") or "\u2014"),
            ("Threat-Score", f"{app.get('threat_score',0):.1f} / 10"),
        ]
        for lbl, val in fields:
            row = ctk.CTkFrame(mf, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)
            ctk.CTkLabel(row, text=f"{lbl}:", font=("", 11, "bold"),
                         text_color=TEXT_DARK, width=100,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(val)[:100], font=("", 11),
                         text_color=TEXT_MUTED,
                         anchor="w").pack(side="left", fill="x",
                                          expand=True)

        # --- code structure ---
        core = app.get("core_files", 0)
        sdk_n = app.get("sdk_files", 0)
        if core or sdk_n:
            _section(fr, "\U0001f4e6 Code-Struktur")
            total = core + sdk_n
            pct = int(core / total * 100) if total else 0
            ctk.CTkLabel(
                fr,
                text=f"Kern: {core} ({pct}%)  |  "
                     f"SDK/Libs: {sdk_n} ({100-pct}%)",
                font=("", 11), text_color=TEXT_MUTED,
            ).pack(anchor="w", padx=16)
            if app.get("layout_count"):
                ctk.CTkLabel(
                    fr, text=f"Layouts: {app['layout_count']} XML",
                    font=("", 11), text_color=TEXT_MUTED,
                ).pack(anchor="w", padx=16)

        # --- components ---
        comps = app.get("components", [])
        if comps:
            _section(fr, "\U0001f3d7 Architektur")
            by_type: dict[str, list[str]] = defaultdict(list)
            for c in comps:
                by_type[c["comp_type"]].append(c["comp_name"])
            for ct, names in sorted(by_type.items()):
                txt = f"{ct}: {', '.join(names[:10])}"
                if len(names) > 10:
                    txt += f" (+{len(names)-10})"
                ctk.CTkLabel(fr, text=txt, font=("", 11),
                             text_color=TEXT_MUTED,
                             wraplength=500).pack(anchor="w", padx=16)

        # --- SDKs ---
        sdks = app.get("sdks", [])
        if sdks:
            _section(fr, "\U0001f50c Erkannte SDKs")
            for s in sdks[:20]:
                ctk.CTkLabel(
                    fr,
                    text=f"\u2022 {s['sdk_name']} \u2014 "
                         f"{s['file_count']} Dateien",
                    font=("", 11), text_color=TEXT_MUTED,
                ).pack(anchor="w", padx=16)
            if len(sdks) > 20:
                ctk.CTkLabel(
                    fr, text=f"(+{len(sdks)-20} weitere)",
                    font=("", 10), text_color=TEXT_MUTED,
                ).pack(anchor="w", padx=16)

        # --- threats ---
        threats = [t for t in app.get("threats", []) if t["hit_count"] > 0]
        if threats:
            _section(fr, "\u26a0\ufe0f Threat-Hinweise")
            for t in threats:
                ctk.CTkLabel(
                    fr,
                    text=f"\u2022 {t['category']}: "
                         f"{t['hit_count']} Treffer",
                    font=("", 11), text_color=ACCENT,
                ).pack(anchor="w", padx=16)

        # --- permissions ---
        perms = app.get("permissions", [])
        if perms:
            _section(fr, "\U0001f510 Berechtigungen")
            by_sev: dict[str, list[str]] = defaultdict(list)
            for p in perms:
                by_sev[p["severity"]].append(p["permission"])
            for key, label in [("critical", "\u26a0\ufe0f Kritisch"),
                               ("notable", "\u2139\ufe0f Beachtenswert"),
                               ("normal", "\u2705 Normal")]:
                pl = by_sev.get(key, [])
                if pl:
                    ctk.CTkLabel(fr, text=f"{label}:",
                                 font=("", 11, "bold"),
                                 text_color=TEXT_DARK,
                                 ).pack(anchor="w", padx=16, pady=(4, 0))
                    ctk.CTkLabel(fr, text=", ".join(pl),
                                 font=("", 10), text_color=TEXT_MUTED,
                                 wraplength=500,
                                 ).pack(anchor="w", padx=24)

        # --- folder quick-links ---
        folder = app.get("folder_path", "")
        if folder and os.path.isdir(folder):
            _section(fr, "\U0001f4c1 Ordner")
            bf = ctk.CTkFrame(fr, fg_color="transparent")
            bf.pack(fill="x", padx=8, pady=4)
            for sub in ("_CODE", "_SDK", "_THREATS", "_LAYOUTS",
                        "COMPARE_IMAGES"):
                sp = os.path.join(folder, sub)
                if os.path.isdir(sp):
                    ctk.CTkButton(
                        bf, text=sub, width=110, height=28,
                        fg_color=SIDEBAR_BG, hover_color=SIDEBAR_HOVER,
                        text_color=TEXT_LIGHT, font=("", 10),
                        command=lambda p=sp: _open_path(p),
                    ).pack(side="left", padx=2, pady=2)

        # --- Overview.md preview ---
        md_path = os.path.join(folder, "Overview.md") if folder else ""
        if md_path and os.path.isfile(md_path):
            _section(fr, "\U0001f4c4 Overview.md")
            try:
                with open(md_path, "r", encoding="utf-8") as fh:
                    md = fh.read()[:3000]
                tw = tk.Text(fr, wrap="word", font=("Consolas", 10),
                             bg="#F8F9FC", fg=TEXT_DARK, relief="flat",
                             height=15, padx=8, pady=8)
                tw.insert("1.0", md)
                tw.configure(state="disabled")
                tw.pack(fill="x", padx=8, pady=4)
            except Exception:
                pass

    # ── search ───────────────────────────────────────────────────────────────

    def _on_search_type(self, value):
        hints = {
            "Code":       "Smali-Code durchsuchen (z.B. getDeviceId)\u2026",
            "SDK":        "SDK-Name (z.B. facebook, okhttp)\u2026",
            "Threat":     "Kategorie (z.B. IDENTITY, SPY)\u2026",
            "Permission": "Berechtigung (z.B. CAMERA, SMS)\u2026",
        }
        self.search_entry.configure(
            placeholder_text=hints.get(value, "Suchen\u2026"))

    def _run_search(self):
        query = self.search_entry.get().strip()
        if not query:
            return
        stype = self.search_type.get()
        self._clear_results()
        {"Code": self._search_code,
         "SDK": self._search_sdk,
         "Threat": self._search_threat,
         "Permission": self._search_perm}[stype](query)

    def _search_code(self, query: str):
        if not self.library_path:
            self._write_result("Kein Archiv geladen.\n")
            return
        self._write_result(
            f"Suche nach \u2018{query}\u2019 in .smali-Dateien\u2026\n\n",
            "heading")
        self.status_var.set("Code-Suche l\u00e4uft\u2026")
        self.update_idletasks()

        def _worker():
            results = CodeSearcher.search_smali(
                self.library_path, query, max_results=200)
            self.after(0, lambda: self._show_code_results(results, query))

        if self._search_thread and self._search_thread.is_alive():
            return
        self._search_thread = threading.Thread(target=_worker, daemon=True)
        self._search_thread.start()

    def _show_code_results(self, results: list[dict], query: str):
        self._clear_results()
        if not results:
            self._write_result(f"Keine Treffer f\u00fcr \u2018{query}\u2019.\n")
        else:
            self._write_result(
                f"{len(results)} Treffer f\u00fcr \u2018{query}\u2019:\n\n",
                "heading")
            cur_file = ""
            for r in results:
                if r["file"] != cur_file:
                    cur_file = r["file"]
                    self._write_result(f"\n\U0001f4c4 {cur_file}\n", "path")
                self._write_result(f"  L{r['line']}: ", "stat_label")
                self._write_result(f"{r['text']}\n")
        self.result_text.configure(state="disabled")
        self.status_var.set(f"Code-Suche: {len(results)} Treffer")

    def _search_sdk(self, query: str):
        if not self.indexer:
            self._write_result("Kein Index geladen.\n")
            return
        results = self.indexer.search_by_sdk(query)
        if not results:
            self._write_result(
                f"Kein SDK mit \u2018{query}\u2019 gefunden.\n")
        else:
            self._write_result(
                f"SDK-Audit: \u2018{query}\u2019 \u2014 "
                f"{len(results)} Treffer:\n\n", "heading")
            for r in results:
                self._write_result(
                    f"\u2022 {r['package_id']} v{r['version_name']}",
                    "stat_label")
                self._write_result(
                    f"  [{r['sdk_name']}: {r['file_count']} Dateien]\n",
                    "path")
        self.result_text.configure(state="disabled")
        self.status_var.set(f"SDK-Audit: {len(results)} Treffer")

    def _search_threat(self, query: str):
        if not self.indexer:
            self._write_result("Kein Index geladen.\n")
            return
        results = self.indexer.search_by_threat(query or None)
        if not results:
            self._write_result(
                f"Keine Threats f\u00fcr \u2018{query}\u2019 gefunden.\n")
        else:
            self._write_result(
                f"Threat-Filter: \u2018{query}\u2019 \u2014 "
                f"{len(results)} Treffer:\n\n", "heading")
            for r in results:
                dot = _threat_dot(r.get("threat_score", 0))
                self._write_result(
                    f"{dot} {r['package_id']} v{r['version_name']}",
                    "stat_label")
                self._write_result(
                    f"  [{r['category']}: {r['hit_count']} Hits]\n", "match")
        self.result_text.configure(state="disabled")
        self.status_var.set(f"Threat-Filter: {len(results)} Treffer")

    def _search_perm(self, query: str):
        if not self.indexer:
            self._write_result("Kein Index geladen.\n")
            return
        results = self.indexer.search_by_permission(query)
        if not results:
            self._write_result(
                f"Keine Apps mit Berechtigung "
                f"\u2018{query}\u2019 gefunden.\n")
        else:
            self._write_result(
                f"Permission-Suche: \u2018{query}\u2019 \u2014 "
                f"{len(results)} Treffer:\n\n", "heading")
            for r in results:
                self._write_result(
                    f"\u2022 {r['package_id']} v{r['version_name']}",
                    "stat_label")
                self._write_result(
                    f"  [{r['permission']} \u2014 {r['severity']}]\n", "path")
        self.result_text.configure(state="disabled")
        self.status_var.set(f"Permission-Suche: {len(results)} Treffer")

    # ── result helpers ───────────────────────────────────────────────────────

    def _clear_results(self):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")

    def _write_result(self, text: str, tag: str | None = None):
        self.result_text.configure(state="normal")
        if tag:
            self.result_text.insert("end", text, tag)
        else:
            self.result_text.insert("end", text)

    # ── statistics ───────────────────────────────────────────────────────────

    def _update_stats(self):
        if not self.indexer:
            return
        stats = self.indexer.get_stats(self.library_path)
        self.stats_label.configure(text=(
            f"Apps: {stats['total_apps']}\n"
            f"Packages: {stats['total_packages']}\n"
            f"SDKs erkannt: {stats['total_sdks']}\n"
            f"\u00d8 Threat-Score: {stats['avg_threat_score']}\n"
            f"Archiv-Gr\u00f6\u00dfe: {stats['total_size_gb']} GB"))


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _int(v) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return 0


def _threat_dot(score: float) -> str:
    if score >= 7:
        return "\U0001f534"   # red
    if score >= 3:
        return "\U0001f7e1"   # yellow
    return "\U0001f7e2"       # green


def _section(parent, title: str):
    ctk.CTkLabel(parent, text=title, font=("", 13, "bold"),
                 text_color=TEXT_DARK).pack(anchor="w", padx=8, pady=(12, 2))


def _open_path(path: str):
    try:
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


def main():
    library = None
    if "--library" in sys.argv:
        idx = sys.argv.index("--library")
        if idx + 1 < len(sys.argv):
            library = sys.argv[idx + 1]
    app = AFKB(library_path=library)
    app.mainloop()


if __name__ == "__main__":
    main()
