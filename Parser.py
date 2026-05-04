from __future__ import annotations

import csv
import json
import os
import re
import tkinter as tk
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import webview
except ImportError:
    webview = None


@dataclass
class SetupApiEvent:
    line_no: int
    timestamp: str
    severity: str
    category: str
    action: str
    status: str
    device: str
    session_id: str
    phase: str
    error_code: str
    risk_score: int
    tags: str
    message: str
    raw: str


class SetupApiParser:
    """
    Parser for Windows SetupAPI logs with DFIR-focused event extraction.
    """

    timestamp_regex = re.compile(
        r"(?P<ts>\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
    )
    device_regex = re.compile(
        r"(?P<dev>(?:USB|PCI|HID|SWD|ROOT|BTH|ACPI)\\[^\s\]\)]+)", re.IGNORECASE
    )
    category_regex = re.compile(r"^(?P<cat>[a-z]{2,5})\s*:\s*(?P<rest>.*)$", re.IGNORECASE)
    marker_regex = re.compile(r"^\s*(?P<marker>(?:>>>|<<<|!!!|!|#|@))\s*(?P<text>.*)$")
    error_code_regex = re.compile(r"(0x[0-9a-fA-F]{8}|\berror\s+\d+\b|\bcode\s+\d+\b)")

    severity_map = {
        "!!!": "Critical",
        "!": "Warning",
        "#": "Debug",
        "@": "Info",
        ">>>": "Section",
        "<<<": "Section",
    }

    def parse(self, text: str) -> tuple[list[SetupApiEvent], dict]:
        events: list[SetupApiEvent] = []
        current_timestamp = ""
        current_device = "Unknown"
        current_session = "S0000"
        session_counter = 0
        file_lines = text.splitlines()

        for index, line in enumerate(file_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            ts_match = self.timestamp_regex.search(stripped)
            if ts_match:
                current_timestamp = self._normalize_timestamp(ts_match.group("ts"))

            dev_match = self.device_regex.search(stripped)
            if dev_match:
                current_device = dev_match.group("dev")

            marker_match = self.marker_regex.match(stripped)
            if marker_match:
                marker = marker_match.group("marker")
                payload = marker_match.group("text")
                severity = self.severity_map.get(marker, "Info")
                category, message = self._extract_category_and_message(payload)
                action = self._classify_action(payload)
                status = self._classify_status(payload, severity)
            else:
                category, message = self._extract_category_and_message(stripped)
                severity = self._classify_severity(stripped)
                action = self._classify_action(stripped)
                status = self._classify_status(stripped, severity)

            if self._is_session_start(stripped, action):
                session_counter += 1
                current_session = f"S{session_counter:04d}"
            phase = self._classify_phase(stripped)
            error_code = self._extract_error_code(stripped)
            tags = self._extract_tags(stripped, action, status, severity)
            risk_score = self._risk_score(severity, status, tags, action)

            event = SetupApiEvent(
                line_no=index,
                timestamp=current_timestamp or "Unknown",
                severity=severity,
                category=category,
                action=action,
                status=status,
                device=current_device,
                session_id=current_session,
                phase=phase,
                error_code=error_code,
                risk_score=risk_score,
                tags=", ".join(tags),
                message=message,
                raw=line,
            )
            events.append(event)

        metadata = self._build_metadata(events, len(file_lines))
        return events, metadata

    def _normalize_timestamp(self, timestamp: str) -> str:
        for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(timestamp, fmt)
                return parsed.isoformat(sep=" ")
            except ValueError:
                continue
        return timestamp

    def _extract_category_and_message(self, payload: str) -> tuple[str, str]:
        match = self.category_regex.match(payload)
        if match:
            return match.group("cat").lower(), match.group("rest").strip()
        return "general", payload.strip()

    def _classify_action(self, payload: str) -> str:
        low = payload.lower()
        if any(word in low for word in ("rank", "select best driver", "driver node")):
            return "DriverRanking"
        if "install" in low:
            return "Install"
        if "remove" in low or "uninstall" in low:
            return "Remove"
        if "driver" in low:
            return "Driver"
        if "catalog" in low or "signature" in low or "sign" in low:
            return "Signature"
        if "service" in low:
            return "Service"
        if any(word in low for word in ("copy", "copying", "copied", "file queue")):
            return "FileOperation"
        if any(word in low for word in ("registry", "regopenkey", "regsetvalue", "software\\")):
            return "Registry"
        if "policy" in low:
            return "Policy"
        if any(word in low for word in ("co-installer", "class installer")):
            return "Installer"
        if "device" in low:
            return "Device"
        if "section start" in low:
            return "SectionStart"
        if "section end" in low:
            return "SectionEnd"
        return "Other"

    def _classify_status(self, payload: str, severity: str) -> str:
        low = payload.lower()
        if any(word in low for word in ("reboot required", "restart required", "pending reboot")):
            return "RebootRequired"
        if any(word in low for word in ("fail", "failed", "error", "denied", "blocked", "invalid", "timed out", "timeout")):
            return "Failed"
        if any(word in low for word in ("success", "succeeded", "completed", "ok", "exit status: 0x0")):
            return "Success"
        if severity in ("Critical", "Warning"):
            return "Attention"
        return "Unknown"

    def _classify_severity(self, payload: str) -> str:
        low = payload.lower()
        if any(word in low for word in ("fatal", "critical", "panic", "!!!", "access is denied")):
            return "Critical"
        if any(word in low for word in ("error", "failed", "denied", "warning", "timeout")):
            return "Warning"
        if any(word in low for word in ("debug", "trace", "verbose")):
            return "Debug"
        return "Info"

    def _is_session_start(self, payload: str, action: str) -> bool:
        low = payload.lower()
        return (
            action in {"SectionStart", "Install"}
            or ">>>  [device install" in low
            or "section start" in low
        )

    def _classify_phase(self, payload: str) -> str:
        low = payload.lower()
        if any(word in low for word in ("class installer", "co-installer")):
            return "Installer"
        if any(word in low for word in ("copy", "file queue", "inf")):
            return "FileOps"
        if any(word in low for word in ("service", "start service", "create service")):
            return "Service"
        if any(word in low for word in ("policy", "signature", "catalog", "certificate")):
            return "Trust"
        if any(word in low for word in ("remove", "uninstall")):
            return "Removal"
        if any(word in low for word in ("install", "device install")):
            return "Install"
        return "General"

    def _extract_error_code(self, payload: str) -> str:
        match = self.error_code_regex.search(payload)
        if not match:
            return "None"
        value = match.group(1).strip()
        return value.upper()

    def _extract_tags(self, payload: str, action: str, status: str, severity: str) -> list[str]:
        low = payload.lower()
        tags: list[str] = []
        if "usb" in low:
            tags.append("usb")
        if "driver" in low:
            tags.append("driver")
        if "signature" in low or "catalog" in low:
            tags.append("signature")
        if "policy" in low:
            tags.append("policy")
        if "service" in low:
            tags.append("service")
        if "registry" in low:
            tags.append("registry")
        if status == "Failed":
            tags.append("failure")
        if status == "RebootRequired":
            tags.append("reboot")
        if severity == "Critical":
            tags.append("critical")
        if action == "DriverRanking":
            tags.append("ranking")
        if not tags:
            tags.append("general")
        return tags

    def _risk_score(self, severity: str, status: str, tags: list[str], action: str) -> int:
        score = 10
        severity_weight = {"Info": 5, "Debug": 2, "Section": 8, "Warning": 28, "Critical": 45}
        status_weight = {"Success": -8, "Unknown": 0, "Attention": 12, "RebootRequired": 20, "Failed": 35}
        tag_bonus = {"signature": 12, "policy": 10, "failure": 15, "critical": 20, "registry": 8}

        score += severity_weight.get(severity, 6)
        score += status_weight.get(status, 0)
        score += sum(tag_bonus.get(tag, 0) for tag in tags)
        if action in {"Signature", "Policy", "DriverRanking"}:
            score += 6
        return max(0, min(score, 100))

    def _build_metadata(self, events: list[SetupApiEvent], total_lines: int) -> dict:
        severities = Counter(event.severity for event in events)
        statuses = Counter(event.status for event in events)
        actions = Counter(event.action for event in events)
        phases = Counter(event.phase for event in events)
        sessions = Counter(event.session_id for event in events)
        devices = Counter(event.device for event in events if event.device != "Unknown")
        errors = Counter(event.error_code for event in events if event.error_code != "None")

        indicators = [
            event for event in events
            if event.severity in ("Critical", "Warning")
            or event.status == "Failed"
            or event.risk_score >= 65
        ]
        top_risk_events = sorted(events, key=lambda e: e.risk_score, reverse=True)[:20]
        avg_risk = round(sum(event.risk_score for event in events) / len(events), 2) if events else 0
        detections = self._generate_sans_detections(events)

        return {
            "total_lines": total_lines,
            "parsed_events": len(events),
            "avg_risk_score": avg_risk,
            "severity_counts": dict(severities),
            "status_counts": dict(statuses),
            "action_counts": dict(actions),
            "phase_counts": dict(phases),
            "session_count": len(sessions),
            "top_error_codes": errors.most_common(8),
            "top_devices": devices.most_common(10),
            "high_risk_events": len(indicators),
            "top_risk_events": [asdict(event) for event in top_risk_events],
            "detections": detections,
        }

    def _generate_sans_detections(self, events: list[SetupApiEvent]) -> list[dict]:
        """
        Lightweight SANS-style detection summaries for triage.
        """
        detections: list[dict] = []

        def collect(name: str, predicate) -> None:
            matches = [event for event in events if predicate(event)]
            if not matches:
                return
            detections.append(
                {
                    "name": name,
                    "count": len(matches),
                    "max_risk": max(event.risk_score for event in matches),
                    "latest_timestamp": next((event.timestamp for event in reversed(matches) if event.timestamp != "Unknown"), "Unknown"),
                }
            )

        collect(
            "Driver install failures",
            lambda e: e.action in {"Install", "Driver"} and e.status == "Failed",
        )
        collect(
            "Signature or trust anomalies",
            lambda e: ("signature" in e.tags or e.action == "Signature") and e.status in {"Failed", "Attention"},
        )
        collect(
            "Policy enforcement blocks",
            lambda e: e.action == "Policy" and e.status in {"Failed", "Attention"},
        )
        collect(
            "Critical SetupAPI events",
            lambda e: e.severity == "Critical",
        )
        collect(
            "Reboot-required install chains",
            lambda e: e.status == "RebootRequired",
        )

        return sorted(detections, key=lambda item: (item["max_risk"], item["count"]), reverse=True)


class DFIRParserApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DFIR SetupAPI Log Parser")
        self.geometry("1400x860")
        self.minsize(1150, 700)

        self.parser = SetupApiParser()
        self.current_file: Path | None = None
        self.all_events: list[SetupApiEvent] = []
        self.filtered_events: list[SetupApiEvent] = []
        self.metadata: dict = {}
        self.default_log_candidates = [
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.dev.log",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.app.log",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.offline.log",
        ]

        self._configure_style()
        self._build_ui()

    def _configure_style(self) -> None:
        self.bg = "#090b10"
        self.panel = "#11151f"
        self.accent = "#2f80ff"
        self.text = "#dbe6ff"
        self.muted = "#7f93b5"
        self.critical = "#ff6b6b"
        self.warning = "#ffbf69"
        self.ok = "#4fd1a5"
        self.border = "#1f2b45"

        self.configure(bg=self.bg)

        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=self.panel, foreground=self.text, fieldbackground=self.panel)
        style.configure("Card.TFrame", background=self.panel)
        style.configure("Root.TFrame", background=self.bg)
        style.configure("Toolbar.TFrame", background="#0b1019")
        style.configure("CardBorder.TFrame", background=self.border)
        style.configure("Header.TLabel", background=self.bg, foreground=self.text, font=("Segoe UI Semibold", 20))
        style.configure("MetricTitle.TLabel", background=self.panel, foreground=self.muted, font=("Segoe UI Semibold", 8))
        style.configure("MetricValue.TLabel", background=self.panel, foreground=self.text, font=("Segoe UI Semibold", 18))
        style.configure("Muted.TLabel", background=self.panel, foreground=self.muted, font=("Segoe UI", 10))
        style.configure("Toolbar.TLabel", background=self.bg, foreground=self.muted, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background="#0b1019", foreground="#9ab2dd", font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI", 9), padding=8, borderwidth=0)
        style.map("TButton", background=[("active", "#1f4ea5"), ("!active", self.accent)])
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 9), padding=(11, 9))
        style.map("Accent.TButton", background=[("active", "#3a89ff"), ("!active", self.accent)])
        style.configure("Ghost.TButton", font=("Segoe UI", 9), padding=(10, 8))
        style.map("Ghost.TButton", background=[("active", "#1f2838"), ("!active", "#141b27")], foreground=[("!active", "#cfe0ff")])
        style.configure("TEntry", foreground=self.text, fieldbackground="#0f141d", insertcolor=self.text)
        style.configure("TCombobox", foreground=self.text, fieldbackground="#0f141d")
        style.configure("TNotebook", background=self.bg, borderwidth=0)
        style.configure("TNotebook.Tab", background="#141b28", foreground="#b8c9e9", padding=(14, 9), font=("Segoe UI Semibold", 9))
        style.map("TNotebook.Tab", background=[("selected", "#243452")], foreground=[("selected", "#ecf4ff")])
        style.configure(
            "Treeview",
            background="#0d131d",
            foreground=self.text,
            fieldbackground="#0d131d",
            rowheight=23,
            bordercolor=self.border,
            lightcolor=self.border,
            darkcolor=self.border,
        )
        style.configure("Treeview.Heading", background="#151f30", foreground="#bdd1f5", font=("Segoe UI Semibold", 9))
        style.map("Treeview", background=[("selected", "#1e3358")], foreground=[("selected", "#f1f6ff")])

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        header = ttk.Frame(self, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="DFIR SetupAPI Workbench", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.file_label = ttk.Label(header, text="Ready for parsing", style="Muted.TLabel")
        self.file_label.grid(row=1, column=0, sticky="w")

        actions = ttk.Frame(header, style="Root.TFrame")
        actions.grid(row=0, column=1, rowspan=2, sticky="e")
        ttk.Button(actions, text="Auto Parse SetupAPI", style="Accent.TButton", command=self.auto_parse_setupapi).grid(row=0, column=0, padx=4)
        ttk.Button(actions, text="Open Log", style="Ghost.TButton", command=self.open_file).grid(row=0, column=1, padx=4)
        ttk.Button(actions, text="Export CSV", style="Ghost.TButton", command=self.export_csv).grid(row=0, column=2, padx=4)
        ttk.Button(actions, text="Export JSON", style="Ghost.TButton", command=self.export_json).grid(row=0, column=3, padx=4)
        ttk.Button(actions, text="Clear", style="Ghost.TButton", command=self.clear).grid(row=0, column=4, padx=4)

        metrics = ttk.Frame(self, style="Root.TFrame")
        metrics.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        for idx in range(4):
            metrics.columnconfigure(idx, weight=1)

        self.metric_events = self._build_metric_card(metrics, "EVENTS", "0")
        self.metric_risk = self._build_metric_card(metrics, "HIGH RISK", "0", column=1)
        self.metric_devices = self._build_metric_card(metrics, "DEVICES", "0", column=2)
        self.metric_failures = self._build_metric_card(metrics, "FAILURES", "0", column=3)

        filters = ttk.Frame(self, style="Toolbar.TFrame")
        filters.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))
        for c in range(8):
            filters.columnconfigure(c, weight=1 if c in (1, 3, 5, 7) else 0)

        ttk.Label(filters, text="Search", style="Toolbar.TLabel").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filters, textvariable=self.search_var)
        search_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        search_entry.bind("<KeyRelease>", lambda _: self.apply_filters())

        ttk.Label(filters, text="Severity", style="Toolbar.TLabel").grid(row=0, column=2, sticky="w", padx=8, pady=8)
        self.severity_var = tk.StringVar(value="All")
        self.severity_combo = ttk.Combobox(filters, textvariable=self.severity_var, state="readonly", values=["All"])
        self.severity_combo.grid(row=0, column=3, sticky="ew", padx=8, pady=8)
        self.severity_combo.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())

        ttk.Label(filters, text="Status", style="Toolbar.TLabel").grid(row=0, column=4, sticky="w", padx=8, pady=8)
        self.status_filter_var = tk.StringVar(value="All")
        self.status_combo = ttk.Combobox(filters, textvariable=self.status_filter_var, state="readonly", values=["All"])
        self.status_combo.grid(row=0, column=5, sticky="ew", padx=8, pady=8)
        self.status_combo.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())

        ttk.Label(filters, text="Action", style="Toolbar.TLabel").grid(row=0, column=6, sticky="w", padx=8, pady=8)
        self.action_var = tk.StringVar(value="All")
        self.action_combo = ttk.Combobox(filters, textvariable=self.action_var, state="readonly", values=["All"])
        self.action_combo.grid(row=0, column=7, sticky="ew", padx=8, pady=8)
        self.action_combo.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())

        workspace = ttk.Frame(self, style="Root.TFrame")
        workspace.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 10))
        workspace.columnconfigure(0, weight=0)
        workspace.columnconfigure(1, weight=1)
        workspace.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(workspace, style="Toolbar.TFrame")
        sidebar.grid(row=0, column=0, sticky="nsw", padx=(0, 8))
        sidebar.columnconfigure(0, weight=1)
        self._build_sidebar(sidebar)

        self.notebook = ttk.Notebook(workspace)
        self.notebook.grid(row=0, column=1, sticky="nsew")

        events_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        indicators_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        stats_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        self.notebook.add(events_tab, text="Events")
        self.notebook.add(indicators_tab, text="High Risk Indicators")
        self.notebook.add(stats_tab, text="Statistics")

        self._build_events_tab(events_tab)
        self._build_indicators_tab(indicators_tab)
        self._build_stats_tab(stats_tab)

        self.status_text_var = tk.StringVar(value="Waiting: click Auto Parse SetupAPI for one-click triage.")
        status_bar = ttk.Frame(self, style="Toolbar.TFrame")
        status_bar.grid(row=4, column=0, sticky="ew")
        status_bar.columnconfigure(0, weight=1)
        ttk.Label(status_bar, textvariable=self.status_text_var, style="Status.TLabel").grid(
            row=0, column=0, sticky="w", padx=12, pady=7
        )

    def _build_sidebar(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="NAVIGATION", style="Toolbar.TLabel").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 6))
        ttk.Button(parent, text="Events", style="Ghost.TButton", command=lambda: self.notebook.select(0)).grid(
            row=1, column=0, sticky="ew", padx=8, pady=3
        )
        ttk.Button(parent, text="Indicators", style="Ghost.TButton", command=lambda: self.notebook.select(1)).grid(
            row=2, column=0, sticky="ew", padx=8, pady=3
        )
        ttk.Button(parent, text="Statistics", style="Ghost.TButton", command=lambda: self.notebook.select(2)).grid(
            row=3, column=0, sticky="ew", padx=8, pady=3
        )

        ttk.Separator(parent, orient="horizontal").grid(row=4, column=0, sticky="ew", padx=8, pady=10)
        ttk.Label(parent, text="QUICK ACTIONS", style="Toolbar.TLabel").grid(row=5, column=0, sticky="w", padx=10, pady=(2, 6))
        ttk.Button(parent, text="Auto Parse", style="Accent.TButton", command=self.auto_parse_setupapi).grid(
            row=6, column=0, sticky="ew", padx=8, pady=3
        )
        ttk.Button(parent, text="Open Custom Log", style="Ghost.TButton", command=self.open_file).grid(
            row=7, column=0, sticky="ew", padx=8, pady=3
        )

    def _build_metric_card(self, parent: ttk.Frame, title: str, value: str, column: int = 0) -> ttk.Label:
        border = ttk.Frame(parent, style="CardBorder.TFrame")
        border.grid(row=0, column=column, sticky="ew", padx=5)
        inner = ttk.Frame(border, style="Card.TFrame")
        inner.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)
        inner.columnconfigure(0, weight=1)
        ttk.Label(inner, text=title, style="MetricTitle.TLabel").grid(row=0, column=0, sticky="w", padx=12, pady=(8, 2))
        value_label = ttk.Label(inner, text=value, style="MetricValue.TLabel")
        value_label.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))
        return value_label

    def _build_events_tab(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=3)
        parent.rowconfigure(1, weight=2)
        parent.columnconfigure(0, weight=1)

        columns = ("time", "severity", "category", "action", "status", "device", "message", "line")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        self.tree.grid(row=0, column=0, sticky="nsew")

        widths = {
            "time": 170,
            "severity": 90,
            "category": 90,
            "action": 110,
            "status": 90,
            "device": 310,
            "message": 480,
            "line": 70,
        }
        for col in columns:
            self.tree.heading(col, text=col.title(), command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=widths[col], minwidth=60, anchor="w")

        scrollbar_y = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar_y.set)
        scrollbar_y.grid(row=0, column=1, sticky="ns")

        detail_frame = ttk.Frame(parent, style="Card.TFrame")
        detail_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        detail_frame.rowconfigure(1, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        ttk.Label(detail_frame, text="Event Details", style="Muted.TLabel").grid(row=0, column=0, sticky="w")

        self.detail_text = tk.Text(
            detail_frame,
            bg="#0d131d",
            fg=self.text,
            insertbackground=self.text,
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
        )
        self.detail_text.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self.detail_text.config(state="disabled")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_event)

    def _build_indicators_tab(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        columns = ("severity", "status", "action", "device", "message", "line")
        self.indicator_tree = ttk.Treeview(parent, columns=columns, show="headings")
        self.indicator_tree.grid(row=0, column=0, sticky="nsew")
        for col in columns:
            self.indicator_tree.heading(col, text=col.title())
            self.indicator_tree.column(col, width=180 if col in ("device", "message") else 100, anchor="w")

        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.indicator_tree.yview)
        self.indicator_tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

    def _build_stats_tab(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=0)
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)

        self.meta_label = ttk.Label(parent, text="Load a SetupAPI log to view statistics.", style="Muted.TLabel")
        self.meta_label.grid(row=0, column=0, sticky="w", padx=12, pady=12)

        self.stats_text = tk.Text(
            parent,
            bg="#0d131d",
            fg=self.text,
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
        )
        self.stats_text.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.stats_text.insert("1.0", "No data loaded.")
        self.stats_text.config(state="disabled")

    def open_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Open SetupAPI Log",
            filetypes=[
                ("Log files", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return

        self._parse_and_render(Path(file_path))

    def auto_parse_setupapi(self) -> None:
        for candidate in self.default_log_candidates:
            if candidate.exists():
                self._parse_and_render(candidate)
                return

        messagebox.showwarning(
            "SetupAPI Log Not Found",
            "No default SetupAPI log was found.\nExpected one of:\n"
            + "\n".join(str(path) for path in self.default_log_candidates),
        )
        self.status_text_var.set("Auto parse failed: default SetupAPI log not found.")

    def _parse_and_render(self, path: Path) -> None:
        self.status_text_var.set(f"Parsing: {path}")
        self.update_idletasks()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            messagebox.showerror("Read Error", f"Unable to read file:\n{exc}")
            self.status_text_var.set("Read error: unable to open selected file.")
            return

        self.current_file = path
        self.file_label.config(text=f"Source: {path}")
        self.all_events, self.metadata = self.parser.parse(text)
        self.apply_filters()
        self.refresh_stats()
        self.status_text_var.set(
            f"Parsed {self.metadata.get('parsed_events', 0)} events from {path.name}."
        )

    def clear(self) -> None:
        self.current_file = None
        self.file_label.config(text="Ready for parsing")
        self.all_events = []
        self.filtered_events = []
        self.metadata = {}
        self._refresh_event_tree()
        self._refresh_indicator_tree()
        self._set_text(self.detail_text, "")
        self.meta_label.config(text="Load a SetupAPI log to view statistics.")
        self._set_text(self.stats_text, "No data loaded.")
        self._refresh_combos()
        self._refresh_metrics()
        self.status_text_var.set("Cleared. Waiting for next parse.")

    def apply_filters(self) -> None:
        search = self.search_var.get().strip().lower()
        selected_severity = self.severity_var.get()
        selected_status = self.status_filter_var.get()
        selected_action = self.action_var.get()

        filtered = []
        for event in self.all_events:
            if selected_severity != "All" and event.severity != selected_severity:
                continue
            if selected_status != "All" and event.status != selected_status:
                continue
            if selected_action != "All" and event.action != selected_action:
                continue
            if search:
                haystack = f"{event.message} {event.device} {event.category} {event.raw}".lower()
                if search not in haystack:
                    continue
            filtered.append(event)

        self.filtered_events = filtered
        self._refresh_event_tree()
        self._refresh_indicator_tree()
        self._refresh_combos()
        self._refresh_metrics()

    def _refresh_event_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, event in enumerate(self.filtered_events):
            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    event.timestamp,
                    event.severity,
                    event.category,
                    event.action,
                    event.status,
                    event.device,
                    event.message,
                    event.line_no,
                ),
            )

    def _refresh_indicator_tree(self) -> None:
        self.indicator_tree.delete(*self.indicator_tree.get_children())
        indicators = [
            event for event in self.filtered_events
            if event.severity in ("Critical", "Warning") or event.status == "Failed"
        ]
        for event in indicators:
            self.indicator_tree.insert(
                "",
                "end",
                values=(event.severity, event.status, event.action, event.device, event.message, event.line_no),
            )

    def _refresh_combos(self) -> None:
        severities = sorted({event.severity for event in self.all_events})
        statuses = sorted({event.status for event in self.all_events})
        actions = sorted({event.action for event in self.all_events})

        self.severity_combo["values"] = ["All", *severities]
        self.status_combo["values"] = ["All", *statuses]
        self.action_combo["values"] = ["All", *actions]

        if self.severity_var.get() not in self.severity_combo["values"]:
            self.severity_var.set("All")
        if self.status_filter_var.get() not in self.status_combo["values"]:
            self.status_filter_var.set("All")
        if self.action_var.get() not in self.action_combo["values"]:
            self.action_var.set("All")

    def show_selected_event(self, _: tk.Event) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        if index >= len(self.filtered_events):
            return
        event = self.filtered_events[index]
        content = (
            f"Line: {event.line_no}\n"
            f"Timestamp: {event.timestamp}\n"
            f"Severity: {event.severity}\n"
            f"Category: {event.category}\n"
            f"Action: {event.action}\n"
            f"Status: {event.status}\n"
            f"Device: {event.device}\n\n"
            f"Message:\n{event.message}\n\n"
            f"Raw:\n{event.raw}\n"
        )
        self._set_text(self.detail_text, content)

    def refresh_stats(self) -> None:
        if not self.metadata:
            self.meta_label.config(text="No metadata available.")
            self._set_text(self.stats_text, "No data loaded.")
            self._refresh_metrics()
            return

        summary = (
            f"File: {self.current_file.name if self.current_file else 'Unknown'} | "
            f"Lines: {self.metadata.get('total_lines', 0)} | "
            f"Events: {self.metadata.get('parsed_events', 0)} | "
            f"High Risk: {self.metadata.get('high_risk_events', 0)}"
        )
        self.meta_label.config(text=summary)

        sev = self.metadata.get("severity_counts", {})
        st = self.metadata.get("status_counts", {})
        act = self.metadata.get("action_counts", {})
        top_devices = self.metadata.get("top_devices", [])

        lines = [
            "=== Severity Distribution ===",
            *[f"{k:>10}: {v}" for k, v in sorted(sev.items())],
            "",
            "=== Status Distribution ===",
            *[f"{k:>10}: {v}" for k, v in sorted(st.items())],
            "",
            "=== Action Distribution (Top 12) ===",
            *[f"{k:>12}: {v}" for k, v in Counter(act).most_common(12)],
            "",
            "=== Most Referenced Device IDs (Top 10) ===",
            *(
                [f"{device} -> {count}" for device, count in top_devices]
                if top_devices
                else ["No device IDs extracted."]
            ),
            "",
            "DFIR note: review 'Critical', 'Warning', and 'Failed' events first for triage.",
        ]
        self._set_text(self.stats_text, "\n".join(lines))
        self._refresh_metrics()

    def export_csv(self) -> None:
        if not self.filtered_events:
            messagebox.showinfo("No Data", "There are no filtered events to export.")
            return

        out = filedialog.asksaveasfilename(
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not out:
            return

        try:
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["line_no", "timestamp", "severity", "category", "action", "status", "device", "message", "raw"])
                for event in self.filtered_events:
                    writer.writerow([
                        event.line_no, event.timestamp, event.severity, event.category,
                        event.action, event.status, event.device, event.message, event.raw
                    ])
        except OSError as exc:
            messagebox.showerror("Export Error", f"Failed to write CSV:\n{exc}")
            return

        messagebox.showinfo("Export Complete", f"CSV exported:\n{out}")
        self.status_text_var.set(f"Export complete: CSV saved to {out}")

    def export_json(self) -> None:
        if not self.filtered_events:
            messagebox.showinfo("No Data", "There are no filtered events to export.")
            return

        out = filedialog.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not out:
            return

        payload = {
            "source_file": str(self.current_file) if self.current_file else None,
            "exported_at": datetime.now().isoformat(),
            "metadata": self.metadata,
            "events": [asdict(event) for event in self.filtered_events],
        }
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except OSError as exc:
            messagebox.showerror("Export Error", f"Failed to write JSON:\n{exc}")
            return

        messagebox.showinfo("Export Complete", f"JSON exported:\n{out}")
        self.status_text_var.set(f"Export complete: JSON saved to {out}")

    def sort_tree(self, column: str) -> None:
        rows = [(self.tree.set(item, column), item) for item in self.tree.get_children("")]

        if column == "line":
            rows.sort(key=lambda pair: int(pair[0]) if str(pair[0]).isdigit() else -1)
        else:
            rows.sort(key=lambda pair: str(pair[0]).lower())

        for idx, (_, item) in enumerate(rows):
            self.tree.move(item, "", idx)

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")

    def _refresh_metrics(self) -> None:
        events = self.metadata.get("parsed_events", 0) if self.metadata else 0
        high_risk = self.metadata.get("high_risk_events", 0) if self.metadata else 0
        top_devices = self.metadata.get("top_devices", []) if self.metadata else []
        status_counts = self.metadata.get("status_counts", {}) if self.metadata else {}
        failures = status_counts.get("Failed", 0)

        self.metric_events.config(text=str(events))
        self.metric_risk.config(text=str(high_risk))
        self.metric_devices.config(text=str(len(top_devices)))
        self.metric_failures.config(text=str(failures))


class WebBridge:
    def __init__(self) -> None:
        self.parser = SetupApiParser()
        self.current_file: Path | None = None
        self.events: list[SetupApiEvent] = []
        self.metadata: dict = {}
        self.window = None
        self.default_log_candidates = [
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.dev.log",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.app.log",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF" / "setupapi.offline.log",
        ]

    def attach_window(self, window) -> None:
        self.window = window

    def auto_parse(self) -> dict:
        for path in self.default_log_candidates:
            if path.exists():
                return self._parse_path(path)
        return {"ok": False, "error": "Default SetupAPI log not found in C:\\Windows\\INF."}

    def open_custom_log(self) -> dict:
        if self.window is None:
            return {"ok": False, "error": "Window is not initialized yet."}
        selected = self.window.create_file_dialog(
            webview.OPEN_DIALOG,
            allow_multiple=False,
            file_types=("Log files (*.log;*.txt)", "All files (*.*)"),
        )
        if not selected:
            return {"ok": False, "error": "No file selected."}
        return self._parse_path(Path(selected[0]))

    def get_snapshot(self) -> dict:
        return self._build_payload(self.events, "Ready.")

    def filter_events(self, search: str, severity: str, status: str, action: str) -> dict:
        search = (search or "").strip().lower()
        severity = severity or "All"
        status = status or "All"
        action = action or "All"

        filtered: list[SetupApiEvent] = []
        for event in self.events:
            if severity != "All" and event.severity != severity:
                continue
            if status != "All" and event.status != status:
                continue
            if action != "All" and event.action != action:
                continue
            if search:
                haystack = f"{event.message} {event.device} {event.category} {event.raw}".lower()
                if search not in haystack:
                    continue
            filtered.append(event)
        return self._build_payload(filtered, f"Filtered {len(filtered)} events.")

    def export_json(self, search: str, severity: str, status: str, action: str) -> dict:
        filtered_data = self.filter_events(search, severity, status, action)
        if not filtered_data["events"]:
            return {"ok": False, "error": "No events to export."}
        if self.window is None:
            return {"ok": False, "error": "Window is not initialized yet."}

        out = self.window.create_file_dialog(
            webview.SAVE_DIALOG, save_filename="setupapi_events.json"
        )
        if not out:
            return {"ok": False, "error": "Export cancelled."}
        out_path = Path(out)

        payload = {
            "source_file": str(self.current_file) if self.current_file else None,
            "exported_at": datetime.now().isoformat(),
            "metadata": self.metadata,
            "events": filtered_data["events"],
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {"ok": True, "message": f"JSON exported to {out_path}"}

    def export_csv(self, search: str, severity: str, status: str, action: str) -> dict:
        filtered_data = self.filter_events(search, severity, status, action)
        if not filtered_data["events"]:
            return {"ok": False, "error": "No events to export."}
        if self.window is None:
            return {"ok": False, "error": "Window is not initialized yet."}

        out = self.window.create_file_dialog(
            webview.SAVE_DIALOG, save_filename="setupapi_events.csv"
        )
        if not out:
            return {"ok": False, "error": "Export cancelled."}
        out_path = Path(out)

        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "line_no", "timestamp", "severity", "category", "action",
                    "status", "device", "session_id", "phase", "error_code",
                    "risk_score", "tags", "message", "raw",
                ]
            )
            for event in filtered_data["events"]:
                writer.writerow(
                    [
                        event["line_no"], event["timestamp"], event["severity"], event["category"],
                        event["action"], event["status"], event["device"], event["session_id"],
                        event["phase"], event["error_code"], event["risk_score"], event["tags"],
                        event["message"], event["raw"],
                    ]
                )
        return {"ok": True, "message": f"CSV exported to {out_path}"}

    def _parse_path(self, path: Path) -> dict:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"ok": False, "error": f"Failed to read file: {exc}"}

        self.current_file = path
        self.events, self.metadata = self.parser.parse(text)
        return self._build_payload(self.events, f"Parsed {len(self.events)} events from {path.name}.")

    def _build_payload(self, events: list[SetupApiEvent], message: str) -> dict:
        severities = sorted({event.severity for event in self.events})
        statuses = sorted({event.status for event in self.events})
        actions = sorted({event.action for event in self.events})
        indicators = [
            asdict(event) for event in events
            if event.severity in ("Critical", "Warning") or event.status == "Failed" or event.risk_score >= 65
        ]
        top_risk = sorted((asdict(event) for event in events), key=lambda item: item["risk_score"], reverse=True)[:12]
        return {
            "ok": True,
            "message": message,
            "source_file": str(self.current_file) if self.current_file else "No file loaded",
            "metadata": self.metadata,
            "events": [asdict(event) for event in events],
            "indicators": indicators,
            "top_risk": top_risk,
            "filter_options": {
                "severities": ["All", *severities],
                "statuses": ["All", *statuses],
                "actions": ["All", *actions],
            },
        }


def build_web_ui_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DFIR SetupAPI Workbench</title>
  <style>
    :root{
      --bg:#090d14; --panel:#101725; --panel2:#0b1220; --line:#1d2c48;
      --text:#e8f0ff; --muted:#93a7cc; --accent:#4a8dff; --bad:#ff7777; --warn:#ffbf6a; --good:#56d4aa;
    }
    *{box-sizing:border-box;font-family:"Inter","Segoe UI",Arial,sans-serif}
    body{margin:0;background:var(--bg);color:var(--text)}
    .app{height:100vh;display:grid;grid-template-rows:auto auto auto 1fr auto;gap:10px;padding:14px}
    .top{display:flex;justify-content:space-between;align-items:flex-start}
    h1{margin:0;font-size:23px;font-weight:700;letter-spacing:.02em}
    .source{margin-top:4px;color:var(--muted);font-size:12px}
    .actions{display:flex;gap:8px;flex-wrap:wrap}
    button{border:1px solid var(--line);background:#152239;color:var(--text);padding:8px 12px;border-radius:10px;cursor:pointer;font-size:12px}
    button:hover{filter:brightness(1.08)}
    .primary{background:var(--accent);border-color:#6ea7ff;color:#fff;font-weight:600}
    .kpi{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 12px}
    .label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
    .value{font-size:24px;font-weight:700;margin-top:2px}
    .filters{display:grid;grid-template-columns:2fr 1fr 1fr 1fr auto;gap:8px}
    input,select{width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--text);padding:9px;border-radius:10px}
    .mode{display:flex;gap:6px}
    .mode button{padding:9px 10px}
    .mode .active{background:#223458;border-color:#3e5d92}
    .workspace{display:grid;grid-template-columns:1fr 340px;gap:10px;min-height:0}
    .tableWrap,.side{background:var(--panel);border:1px solid var(--line);border-radius:12px;min-height:0}
    .tableWrap{overflow:auto}
    table{width:100%;border-collapse:collapse;font-size:12px}
    thead{position:sticky;top:0;background:#121e31;z-index:2}
    th,td{padding:8px;border-bottom:1px solid #1a2841;text-align:left;white-space:nowrap}
    tbody tr:hover{background:#162742;cursor:pointer}
    .sev-Critical{color:var(--bad);font-weight:700}
    .sev-Warning{color:var(--warn);font-weight:700}
    .sev-Info{color:#aac8ff}
    .sev-Debug{color:#7ec0ff}
    .sev-Section{color:var(--good)}
    .riskHigh{color:var(--bad);font-weight:700}
    .riskMed{color:var(--warn);font-weight:700}
    .side{display:grid;grid-template-rows:auto 1fr 1fr auto;gap:8px;padding:10px}
    .sideTitle{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
    .detail{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px;overflow:auto;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px}
    .riskList{display:flex;flex-direction:column;gap:6px;overflow:auto}
    .riskItem{padding:8px;border:1px solid var(--line);border-radius:9px;background:var(--panel2);font-size:12px}
    .status{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:9px 11px;color:var(--muted);font-size:12px}
  </style>
</head>
<body>
<div class="app">
  <div class="top">
    <div>
      <h1>DFIR SetupAPI Workbench</h1>
      <div class="source" id="sourceText">No file loaded</div>
    </div>
    <div class="actions">
      <button class="primary" onclick="autoParse()">Auto Parse SetupAPI</button>
      <button onclick="openCustom()">Open Log</button>
      <button onclick="exportCsv()">Export CSV</button>
      <button onclick="exportJson()">Export JSON</button>
    </div>
  </div>

  <div class="kpi">
    <div class="card"><div class="label">Events</div><div class="value" id="kpiEvents">0</div></div>
    <div class="card"><div class="label">High Risk</div><div class="value" id="kpiRisk">0</div></div>
    <div class="card"><div class="label">Failures</div><div class="value" id="kpiFailures">0</div></div>
    <div class="card"><div class="label">Sessions</div><div class="value" id="kpiSessions">0</div></div>
    <div class="card"><div class="label">Avg Risk</div><div class="value" id="kpiAvgRisk">0</div></div>
    <div class="card"><div class="label">Devices</div><div class="value" id="kpiDevices">0</div></div>
  </div>

  <div class="filters">
    <input id="search" placeholder="Search message, tags, error code, device..." oninput="applyFilters()" />
    <select id="severity" onchange="applyFilters()"><option>All</option></select>
    <select id="status" onchange="applyFilters()"><option>All</option></select>
    <select id="action" onchange="applyFilters()"><option>All</option></select>
    <div class="mode">
      <button id="eventsBtn" class="active" onclick="setView('events')">Events</button>
      <button id="indBtn" onclick="setView('indicators')">Alerts</button>
    </div>
  </div>

  <div class="workspace">
    <div class="tableWrap">
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Risk</th><th>Severity</th><th>Status</th><th>Action</th><th>Device</th><th>Session</th><th>Error</th><th>Message</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div class="side">
      <div>
        <div class="sideTitle">Event Details</div>
        <div class="detail" id="details">Select an event for full parsed details.</div>
      </div>
      <div>
        <div class="sideTitle">Top Risk Queue</div>
        <div class="riskList" id="riskList"></div>
      </div>
      <div>
        <div class="sideTitle">SANS-style Detections</div>
        <div class="riskList" id="detectionList"></div>
      </div>
      <div class="sideTitle" id="quickMeta">No metadata loaded</div>
    </div>
  </div>

  <div class="status" id="statusText">Waiting: click Auto Parse SetupAPI for one-click triage.</div>
</div>

<script>
  let current = { events: [], indicators: [], top_risk: [], filter_options: { severities:["All"], statuses:["All"], actions:["All"] } };
  let activeView = "events";

  function setStatus(text){ document.getElementById("statusText").textContent = text; }
  function severityClass(sev){ return `sev-${sev || "Info"}`; }
  function riskClass(score){ return score >= 75 ? "riskHigh" : (score >= 55 ? "riskMed" : ""); }
  function optionHTML(values){ return values.map(v => `<option>${v}</option>`).join(""); }

  function setView(view){
    activeView = view;
    document.getElementById("eventsBtn").classList.toggle("active", view === "events");
    document.getElementById("indBtn").classList.toggle("active", view === "indicators");
    renderRows();
  }

  function syncFilterOptions(){
    document.getElementById("severity").innerHTML = optionHTML(current.filter_options.severities || ["All"]);
    document.getElementById("status").innerHTML = optionHTML(current.filter_options.statuses || ["All"]);
    document.getElementById("action").innerHTML = optionHTML(current.filter_options.actions || ["All"]);
  }

  function updateKpis(data){
    const md = data.metadata || {};
    const statuses = md.status_counts || {};
    document.getElementById("kpiEvents").textContent = md.parsed_events || 0;
    document.getElementById("kpiRisk").textContent = md.high_risk_events || 0;
    document.getElementById("kpiFailures").textContent = statuses.Failed || 0;
    document.getElementById("kpiSessions").textContent = md.session_count || 0;
    document.getElementById("kpiAvgRisk").textContent = md.avg_risk_score || 0;
    document.getElementById("kpiDevices").textContent = (md.top_devices || []).length;
    document.getElementById("sourceText").textContent = `Source: ${data.source_file || "No file loaded"}`;
    document.getElementById("quickMeta").textContent = `Top error codes: ${(md.top_error_codes || []).map(i => i[0]).join(", ") || "none"}`;
  }

  function renderRows(){
    const rows = document.getElementById("rows");
    const data = activeView === "indicators" ? current.indicators : current.events;
    rows.innerHTML = data.map((e, i) => `
      <tr onclick="showDetails(${i})">
        <td>${e.timestamp || ""}</td>
        <td class="${riskClass(e.risk_score || 0)}">${e.risk_score || 0}</td>
        <td class="${severityClass(e.severity)}">${e.severity || ""}</td>
        <td>${e.status || ""}</td>
        <td>${e.action || ""}</td>
        <td>${e.device || ""}</td>
        <td>${e.session_id || ""}</td>
        <td>${e.error_code || ""}</td>
        <td>${e.message || ""}</td>
      </tr>
    `).join("");
    renderRiskQueue();
  }

  function renderRiskQueue(){
    const node = document.getElementById("riskList");
    const list = current.top_risk || [];
    node.innerHTML = list.map(e => `
      <div class="riskItem">
        <div><strong>${e.risk_score}</strong> - ${e.action} - ${e.status}</div>
        <div style="color:#9fb3d8;margin-top:4px">${e.device}</div>
      </div>
    `).join("");
    renderDetections();
  }

  function renderDetections(){
    const node = document.getElementById("detectionList");
    const detections = (current.metadata && current.metadata.detections) ? current.metadata.detections : [];
    node.innerHTML = detections.slice(0, 8).map(d => `
      <div class="riskItem">
        <div><strong>${d.name}</strong></div>
        <div style="color:#9fb3d8;margin-top:4px">Count: ${d.count} | Max Risk: ${d.max_risk}</div>
      </div>
    `).join("") || `<div class="riskItem">No detections triggered.</div>`;
  }

  function showDetails(index){
    const data = activeView === "indicators" ? current.indicators : current.events;
    const e = data[index];
    if (!e) return;
    document.getElementById("details").textContent =
`Line: ${e.line_no}
Timestamp: ${e.timestamp}
Severity: ${e.severity}
Status: ${e.status}
Action: ${e.action}
Phase: ${e.phase}
Session: ${e.session_id}
Error: ${e.error_code}
Risk Score: ${e.risk_score}
Tags: ${e.tags}
Device: ${e.device}

Message:
${e.message}

Raw:
${e.raw}`;
  }

  async function applyFilters(){
    const payload = await window.pywebview.api.filter_events(
      document.getElementById("search").value,
      document.getElementById("severity").value,
      document.getElementById("status").value,
      document.getElementById("action").value
    );
    if (!payload.ok) return setStatus(payload.error || "Filter failed.");
    current = payload;
    renderRows();
    setStatus(payload.message || "Filters applied.");
  }

  async function autoParse(){
    const result = await window.pywebview.api.auto_parse();
    if (!result.ok) return setStatus(result.error || "Auto parse failed.");
    current = result;
    syncFilterOptions();
    updateKpis(result);
    renderRows();
    setStatus(result.message);
  }

  async function openCustom(){
    const result = await window.pywebview.api.open_custom_log();
    if (!result.ok) return setStatus(result.error || "Open failed.");
    current = result;
    syncFilterOptions();
    updateKpis(result);
    renderRows();
    setStatus(result.message);
  }

  async function exportCsv(){
    const result = await window.pywebview.api.export_csv(
      document.getElementById("search").value,
      document.getElementById("severity").value,
      document.getElementById("status").value,
      document.getElementById("action").value
    );
    setStatus(result.ok ? result.message : (result.error || "CSV export failed."));
  }

  async function exportJson(){
    const result = await window.pywebview.api.export_json(
      document.getElementById("search").value,
      document.getElementById("severity").value,
      document.getElementById("status").value,
      document.getElementById("action").value
    );
    setStatus(result.ok ? result.message : (result.error || "JSON export failed."));
  }

  window.addEventListener("pywebviewready", async () => {
    const snap = await window.pywebview.api.get_snapshot();
    current = snap;
    syncFilterOptions();
    updateKpis(snap);
    renderRows();
  });
</script>
</body>
</html>"""


def run_pyweb_app() -> None:
    if webview is None:
        raise RuntimeError(
            "pywebview is not installed. Install with: pip install pywebview"
        )
    bridge = WebBridge()
    window = webview.create_window(
        "DFIR SetupAPI Workbench",
        html=build_web_ui_html(),
        js_api=bridge,
        width=1440,
        height=920,
        min_size=(1100, 700),
    )
    bridge.attach_window(window)
    webview.start()


def main() -> None:
    run_pyweb_app()


if __name__ == "__main__":
    main()
