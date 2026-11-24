"""Tkinter GUI for sysguard.

A thin, honest front-end over the same engine the CLI uses. The scan runs
on a background thread so the window stays responsive, and results are
posted back to the Tk main loop via a queue.
"""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .detectors import ALL_DETECTORS
from .engine import ScanResult, run_scan
from .findings import Finding, Severity
from . import procinfo

_SEV_COLOR = {
    "HIGH": "#c0392b",
    "MEDIUM": "#d35400",
    "LOW": "#2980b9",
    "INFO": "#7f8c8d",
}

_DISCLAIMER = (
    "sysguard is an educational, read-only scanner. It reports behaviour that "
    "CAN indicate a threat (such as a process reading your keyboard); it does "
    "not prove infection and is not a substitute for maintained anti-malware. "
    "Run it only on computers you own or are authorised to inspect."
)


class App(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=10)
        self.master = master
        self.grid(sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        self._queue: queue.Queue = queue.Queue()
        self._scanning = False
        self._findings: list[Finding] = []

        self._build_header()
        self._build_controls()
        self._build_table()
        self._build_detail()
        self._build_statusbar()

        self.after(100, self._drain_queue)

    # -- layout ----------------------------------------------------------
    def _build_header(self) -> None:
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(
            header, text="sysguard", font=("TkDefaultFont", 16, "bold")
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Local threat scanner — keyloggers, suspicious processes, "
                 "persistence, network & privilege issues",
            foreground="#555",
        ).grid(row=1, column=0, sticky="w")
        disclaimer = ttk.Label(
            header, text=_DISCLAIMER, wraplength=720, foreground="#7f3b00",
            font=("TkDefaultFont", 9, "italic"),
        )
        disclaimer.grid(row=2, column=0, sticky="w", pady=(6, 0))

    def _build_controls(self) -> None:
        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.scan_btn = ttk.Button(bar, text="Scan now", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.export_btn = ttk.Button(
            bar, text="Export JSON…", command=self.export_json, state="disabled"
        )
        self.export_btn.pack(side="left", padx=(8, 0))

        self.sev_var = tk.StringVar(value="INFO")
        ttk.Label(bar, text="Min severity:").pack(side="left", padx=(16, 4))
        ttk.Combobox(
            bar, textvariable=self.sev_var, width=8, state="readonly",
            values=[s.label for s in Severity],
        ).pack(side="left")
        self.sev_var.trace_add("write", lambda *_: self._refresh_table())

        self.progress = ttk.Progressbar(bar, mode="determinate", length=200)
        self.progress.pack(side="right")

    def _build_table(self) -> None:
        wrap = ttk.Frame(self)
        wrap.grid(row=3, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        cols = ("severity", "category", "title")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=12)
        self.tree.heading("severity", text="Severity")
        self.tree.heading("category", text="Category")
        self.tree.heading("title", text="Finding")
        self.tree.column("severity", width=90, anchor="center", stretch=False)
        self.tree.column("category", width=150, stretch=False)
        self.tree.column("title", width=460)
        self.tree.grid(row=0, column=0, sticky="nsew")

        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)

        for sev, color in _SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _build_detail(self) -> None:
        box = ttk.LabelFrame(self, text="Details", padding=6)
        box.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        box.columnconfigure(0, weight=1)
        self.detail = tk.Text(box, height=8, wrap="word", state="disabled")
        self.detail.grid(row=0, column=0, sticky="ew")

    def _build_statusbar(self) -> None:
        self.status = ttk.Label(self, text="Ready.", relief="sunken", anchor="w")
        self.status.grid(row=5, column=0, sticky="ew", pady=(8, 0))

    # -- scanning --------------------------------------------------------
    def start_scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…")
        self.export_btn.configure(state="disabled")
        self.progress.configure(value=0, maximum=len(ALL_DETECTORS))
        self._set_status("Scanning… this is read-only and changes nothing.")

        def worker() -> None:
            def progress(name: str, i: int, total: int) -> None:
                self._queue.put(("progress", (name, i, total)))
            try:
                result = run_scan(progress=progress)
                self._queue.put(("done", result))
            except Exception as exc:  # noqa: BLE001
                self._queue.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    name, i, _ = payload
                    self.progress.configure(value=i)
                    self._set_status(f"Running: {name}")
                elif kind == "done":
                    self._on_scan_done(payload)
                elif kind == "error":
                    self._scanning = False
                    self.scan_btn.configure(state="normal", text="Scan now")
                    messagebox.showerror("Scan failed", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _on_scan_done(self, result: ScanResult) -> None:
        self._scanning = False
        self._result = result
        self._findings = result.sorted_findings()
        self.progress.configure(value=self.progress["maximum"])
        self.scan_btn.configure(state="normal", text="Scan now")
        self.export_btn.configure(state="normal")
        self._refresh_table()

        counts = result.counts()
        root_note = "" if result.ran_as_root else "  (limited: not root — re-run with sudo)"
        self._set_status(
            f"Done in {result.duration:.2f}s — "
            f"HIGH {counts['HIGH']}, MEDIUM {counts['MEDIUM']}, "
            f"LOW {counts['LOW']}, INFO {counts['INFO']}{root_note}"
        )
        if not result.ran_as_root:
            messagebox.showinfo(
                "Limited visibility",
                "sysguard is not running as root, so processes, sockets and files "
                "owned by other users are invisible to it. For a complete scan, "
                "run it with sudo.",
            )

    # -- table / detail --------------------------------------------------
    def _refresh_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        min_sev = Severity[self.sev_var.get()]
        self._visible: list[Finding] = [
            f for f in self._findings if f.severity >= min_sev
        ]
        for idx, f in enumerate(self._visible):
            self.tree.insert(
                "", "end", iid=str(idx),
                values=(f.severity.label, f.category, f.title),
                tags=(f.severity.label,),
            )

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        f = self._visible[int(sel[0])]
        text = [f"{f.title}", "", f"Severity: {f.severity.label}",
                f"Category: {f.category}", "", f.detail]
        if f.remediation:
            text += ["", "What to do:", f.remediation]
        if f.evidence:
            text += ["", "Evidence:", json.dumps(f.evidence, indent=2)]
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", "\n".join(text))
        self.detail.configure(state="disabled")

    def export_json(self) -> None:
        if not getattr(self, "_result", None):
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            initialfile="sysguard-report.json",
        )
        if not path:
            return
        try:
            with open(path, "w") as fh:
                json.dump(self._result.to_dict(), fh, indent=2)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self._set_status(f"Report written to {path}")

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)


def main() -> int:
    root = tk.Tk()
    root.title("sysguard — local threat scanner")
    root.minsize(760, 640)
    App(root)
    if not procinfo.running_as_root():
        root.after(
            400,
            lambda: messagebox.showwarning(
                "Heads up",
                "Running without root. The scan will still work but cannot see "
                "everything on the system. Re-launch with sudo for full coverage.",
            ),
        )
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
