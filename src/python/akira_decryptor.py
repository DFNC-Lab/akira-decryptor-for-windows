#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Donghwoo Cho
# SPDX-License-Identifier: Apache-2.0
"""Akira Ransomware Decryptor — GUI v7

Professional forensic tool UI.
3-tab layout: Estimate QPC / Seed Search (GPU) / Decrypt Files
"""

import csv
import glob
import os
import re
import subprocess
import sys
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk

import customtkinter as ctk

# Force UTF-8 for subprocess I/O on Windows (avoids cp949 encoding issues)
if sys.platform == 'win32':
    os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

# Step3_FileDecryptor.exe (C port) is used via subprocess for 160x faster decryption

# Hide console window when launching subprocesses on Windows
_SUBPROCESS_FLAGS = (
    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent.parent

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
C_BG          = "#f7f8fa"      # Light gray background
C_SURFACE     = "#ffffff"      # White cards
C_SURFACE_ALT = "#f0f2f5"      # Subtle gray for alternating/inactive
C_BORDER      = "#d9dde3"      # Neutral border
C_BORDER_FOCUS = "#0a4173"     # Dark blue on focus

C_TEXT        = "#2c3e50"      # Dark blue-gray text
C_TEXT_DIM    = "#7f8c9b"      # Muted text
C_TEXT_BRIGHT = "#1a1a2e"      # Near-black for emphasis

C_PRIMARY     = "#0a4173"      # Dark blue (header, buttons, accents)
C_PRIMARY_HOVER = "#083561"    # Darker on hover
C_PRIMARY_DIM = "#a8c4de"      # Light blue for selections

C_DANGER      = "#c0392b"      # Muted red (errors)
C_SUCCESS     = "#27ae60"      # Green (success)
C_INFO        = "#2980b9"      # Info blue

C_INPUT_BG    = "#fafafa"
C_TAB_ACTIVE  = "#0a4173"

C_LOG_BG      = "#1a2332"      # Dark blue-gray log background
C_LOG_TEXT    = "#c8d6e5"      # Light text on dark log

C_HEADER_BG   = "#0a4173"      # Dark blue header
C_HEADER_TEXT = "#ffffff"       # White text on header

# ---------------------------------------------------------------------------
# Font: Pretendard (bundled in assets/fonts/) with Segoe UI fallback
# ---------------------------------------------------------------------------
import ctypes
_FONT_LOADED = False
def _load_pretendard():
    global _FONT_LOADED
    if _FONT_LOADED:
        return
    _FONT_LOADED = True
    try:
        font_dir = SCRIPT_DIR.parent.parent / "assets" / "fonts"
        if not font_dir.exists():
            font_dir = BASE_DIR / "assets" / "fonts"
        for otf in font_dir.glob("Pretendard-*.otf"):
            # FR_PRIVATE = 0x10: font available only to this process
            ctypes.windll.gdi32.AddFontResourceExW(str(otf), 0x10, 0)
    except Exception:
        pass  # Fallback to Segoe UI

_load_pretendard()
_FONT = "Pretendard"  # Falls back to Segoe UI if not loaded

FONT_TITLE   = (_FONT, 20, "bold")
FONT_H2      = (_FONT, 18, "bold")
FONT_BODY    = (_FONT, 16)
FONT_MONO    = ("Cascadia Mono", 14)
FONT_SMALL   = (_FONT, 14)
FONT_BTN     = (_FONT, 16, "bold")
FONT_TAB     = (_FONT, 15, "bold")
FONT_BADGE   = (_FONT, 13, "bold")


def find_exe(name: str) -> str | None:
    candidates = [
        PROJECT_DIR / "release" / name,
        PROJECT_DIR / "build_cuda" / "Release" / name,
        PROJECT_DIR / "build" / "Release" / name,
        PROJECT_DIR / "build_decrypt" / "Release" / name,
        PROJECT_DIR / name,
        BASE_DIR / name,
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def find_latest_file(pattern: str, directory: str = ".") -> str | None:
    files = glob.glob(os.path.join(directory, pattern))
    return max(files, key=os.path.getmtime) if files else None


# ---------------------------------------------------------------------------
# ANSI escape code stripper
# ---------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


# ---------------------------------------------------------------------------
# Process runner
# ---------------------------------------------------------------------------
class ProcessRunner:
    def __init__(self, cmd, on_done=None):
        self.cmd = cmd
        self.on_done = on_done
        self.q: queue.Queue[str | None] = queue.Queue()
        self.proc = None
        self.returncode = None

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            self.proc = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, encoding="utf-8", errors="replace",
                creationflags=_SUBPROCESS_FLAGS)
            for line in self.proc.stdout:
                line = strip_ansi(line)
                if "\r" in line:
                    line = line.rsplit("\r", 1)[-1]
                if not line or line == "\n":
                    continue
                self.q.put(line)
            self.proc.wait()
            self.returncode = self.proc.returncode
        except Exception as e:
            self.q.put(f"[ERROR] {e}\n")
            self.returncode = -1
        finally:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
            self.q.put(None)
            if self.on_done:
                self.on_done(self.returncode)

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------
class AkiraGUI(ctk.CTk):

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.title("AKIRA DECRYPTOR")
        self.geometry("960x720")
        self.minsize(800, 600)
        self.configure(fg_color=C_BG)

        # Resolve asset paths (PyInstaller _MEIPASS takes priority)
        def _find_asset(name):
            candidates = [
                Path(getattr(sys, '_MEIPASS', '')) / "assets" / name,
                BASE_DIR / "assets" / name,
                SCRIPT_DIR.parent.parent / "assets" / name,
                SCRIPT_DIR / "assets" / name,
            ]
            for c in candidates:
                if c.exists():
                    return c
            return None

        # Window icon (ICO for taskbar + title bar)
        try:
            ico = _find_asset("dfnc_logo.ico")
            if ico:
                self.iconbitmap(str(ico))
                # Also set for after() to ensure it sticks on some Windows versions
                self.after(100, lambda: self.iconbitmap(str(ico)))
        except Exception:
            pass

        self._runner: ProcessRunner | None = None
        self._current_stage = 1
        self._pages = {}
        self._cancel_event = threading.Event()
        self._log_visible = True
        self._qpc_file_map = {}

        self._build_layout()
        self._on_tab_change("Step 1. Estimate QPC")
        self.after(80, self._poll_queue)

    # == Layout =============================================================

    def _build_layout(self):
        # -- Header Bar --
        header = ctk.CTkFrame(self, height=52, fg_color=C_HEADER_BG,
                               corner_radius=0, border_width=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Left: title
        title_f = ctk.CTkFrame(header, fg_color="transparent")
        title_f.pack(side="left", padx=20)
        ctk.CTkLabel(title_f, text="AKIRA DECRYPTOR", font=FONT_TITLE,
                      text_color=C_HEADER_TEXT).pack(side="left")

        # Right: status
        status_f = ctk.CTkFrame(header, fg_color="transparent")
        status_f.pack(side="right", padx=20)
        self._status_dot = ctk.CTkLabel(status_f, text="\u25cf",
                                         font=("Segoe UI", 10),
                                         text_color=C_SUCCESS)
        self._status_dot.pack(side="left", padx=(0, 6))
        self.status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(status_f, textvariable=self.status_var,
                      font=FONT_SMALL, text_color="#a8c4de").pack(side="left")

        # Separator
        ctk.CTkFrame(self, height=1, fg_color=C_BORDER,
                      corner_radius=0).pack(fill="x")

        # -- Custom Tab Bar (dark theme, underline indicator) --
        tab_bar = ctk.CTkFrame(self, height=40, fg_color=C_SURFACE_ALT, corner_radius=0)
        tab_bar.pack(fill="x")
        tab_bar.pack_propagate(False)

        self._tab_names = ["Step 1. Estimate QPC", "Step 2. Seed Search", "Step 3. Decrypt Files"]
        self._tab_buttons = {}
        self._tab_indicators = {}

        tab_inner = ctk.CTkFrame(tab_bar, fg_color="transparent")
        tab_inner.pack(side="left", padx=16)

        for name in self._tab_names:
            tab_frame = ctk.CTkFrame(tab_inner, fg_color="transparent")
            tab_frame.pack(side="left", padx=(0, 4))

            btn = ctk.CTkButton(
                tab_frame, text=name, font=FONT_TAB, height=34,
                fg_color="transparent", hover_color=C_BORDER,
                text_color=C_TEXT_DIM, corner_radius=6, width=0,
                command=lambda n=name: self._on_tab_click(n))
            btn.pack(padx=4, pady=(3, 0))

            indicator = ctk.CTkFrame(tab_frame, height=3,
                                      fg_color="transparent", corner_radius=1)
            indicator.pack(fill="x", padx=8)

            self._tab_buttons[name] = btn
            self._tab_indicators[name] = indicator

        # -- Main Content --
        self.main = ctk.CTkFrame(self, fg_color=C_BG, corner_radius=0)
        self.main.pack(fill="both", expand=True)

        # Page container (scrollable to handle overflow)
        self.page_container = ctk.CTkScrollableFrame(
            self.main, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=C_BORDER, scrollbar_button_hover_color=C_TEXT_DIM)
        self.page_container.pack(fill="both", expand=True, padx=20, pady=(8, 4))

        self._build_step1()    # Step 1 page (index 0)
        self._build_step2()   # Step 2 page (index 1)
        self._build_step3()   # Step 3 page (index 2)

        # -- Log Section --
        self._build_log_section(self.main)

    # == Tab Navigation =====================================================

    def _on_tab_click(self, name):
        """Handle custom tab bar click."""
        self._on_tab_change(name)

    def _on_tab_change(self, value):
        if "Step 1" in value:
            stage = 0
        elif "Step 2" in value:
            stage = 1
        elif "Step 3" in value:
            stage = 2
        else:
            stage = 1
        self._current_stage = stage
        for s, frame in self._pages.items():
            frame.pack_forget()
        self._pages[stage].pack(fill="x")
        if stage == 2:
            self._refresh_seed_list()

        # Update custom tab bar: active = bold + underline, inactive = dim
        for name, btn in self._tab_buttons.items():
            if name == value:
                btn.configure(text_color=C_PRIMARY, font=FONT_TAB)
                self._tab_indicators[name].configure(fg_color=C_PRIMARY)
            else:
                btn.configure(text_color=C_TEXT_DIM, font=FONT_BODY)
                self._tab_indicators[name].configure(fg_color="transparent")

    # == Field Helper =======================================================

    def _field(self, parent, label, row, placeholder="", browse_cmd=None,
               validator=None):
        ctk.CTkLabel(parent, text=label, font=FONT_BODY,
                      text_color=C_TEXT_DIM).grid(
            row=row, column=0, sticky="w", padx=(0, 12), pady=6)
        entry = ctk.CTkEntry(
            parent, font=FONT_BODY, height=34,
            fg_color=C_INPUT_BG, border_color=C_BORDER, border_width=1,
            text_color=C_TEXT, corner_radius=6, placeholder_text=placeholder)
        entry.grid(row=row, column=1, sticky="ew", pady=6)
        if browse_cmd:
            ctk.CTkButton(
                parent, text="Browse", width=68, height=34, font=FONT_SMALL,
                fg_color=C_SURFACE_ALT, hover_color=C_BORDER, corner_radius=6,
                text_color=C_TEXT, border_width=1, border_color=C_BORDER,
                command=lambda: browse_cmd(entry)
            ).grid(row=row, column=2, padx=(8, 0), pady=6)
        if validator:
            self._attach_validator(entry, validator)
        return entry

    def _attach_validator(self, entry, validator_fn):
        def on_change(*_):
            value = entry.get().strip()
            if not value:
                entry.configure(border_color=C_BORDER)
                return
            if validator_fn(value):
                entry.configure(border_color=C_SUCCESS)
            else:
                entry.configure(border_color=C_DANGER)
        entry.bind("<FocusOut>", on_change)
        entry.bind("<KeyRelease>", on_change)

    # == Step 1: Estimate QPC ===============================================

    def _build_step1(self):
        page = ctk.CTkFrame(self.page_container, fg_color="transparent")
        self._pages[0] = page  # page 0 = Step 1

        # Parameters Card
        card = ctk.CTkFrame(page, fg_color=C_SURFACE, corner_radius=10,
                             border_width=1, border_color=C_BORDER)
        card.pack(fill="x")

        # Card header
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(16, 4))
        ctk.CTkLabel(hdr, text="QPC Estimation", font=FONT_H2,
                      text_color=C_TEXT).pack(side="left")
        ctk.CTkLabel(hdr, text="Estimate the reference QPC value from the ransomware log.",
                      font=FONT_SMALL, text_color=C_TEXT_DIM).pack(
            side="left", padx=(10, 0))

        # Info banner
        info = ctk.CTkFrame(card, fg_color="#e8f0fe", corner_radius=6,
                             border_width=1, border_color="#b8d4f0")
        info.pack(fill="x", padx=20, pady=(8, 4))
        ctk.CTkLabel(info, text="\u2139", font=(_FONT, 11), text_color=C_INFO).pack(side="left", padx=(10, 6), pady=8)
        ctk.CTkLabel(info, text="Run this on the infected PC. It automatically calculates the reference value from the ransomware log.",
                      font=FONT_SMALL, text_color="#1a56a0").pack(side="left", pady=8)

        # Log file path field
        fields = ctk.CTkFrame(card, fg_color="transparent")
        fields.pack(fill="x", padx=20, pady=(4, 4))
        fields.grid_columnconfigure(1, weight=1)
        self.s0_log = self._field(fields, "Akira Log File", 0,
                                   "Log-MM-DD-YYYY-HH-MM-SS.txt",
                                   self._browse_file)

        # Buttons + Progress
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(8, 4))
        self.s0_run = ctk.CTkButton(btn_row, text="Run Estimation", font=FONT_BTN, height=36,
                                      fg_color=C_PRIMARY, hover_color=C_PRIMARY_HOVER,
                                      corner_radius=6, command=self._run_step1)
        self.s0_run.pack(side="left")

        self.s0_stop = ctk.CTkButton(
            btn_row, text="Stop", font=FONT_BTN, height=36, width=60,
            fg_color=C_DANGER, hover_color="#a93226", corner_radius=6,
            command=self._stop_process, state="disabled")
        self.s0_stop.pack(side="left", padx=(8, 0))

        # Progress bar
        self.s0_progress = ctk.CTkProgressBar(
            card, fg_color=C_BORDER, progress_color=C_PRIMARY,
            height=3, corner_radius=1)
        self.s0_progress.pack(fill="x", padx=20, pady=(8, 4))
        self.s0_progress.set(0)

        self.s0_progress_label = ctk.CTkLabel(
            card, text="", font=FONT_SMALL, text_color=C_TEXT_DIM)
        self.s0_progress_label.pack(fill="x", padx=20, pady=(0, 16))

        # Results Card
        res_card = ctk.CTkFrame(page, fg_color=C_SURFACE, corner_radius=10,
                                 border_width=1, border_color=C_BORDER)
        res_card.pack(fill="x", pady=(8, 0))

        res_hdr = ctk.CTkFrame(res_card, fg_color="transparent")
        res_hdr.pack(fill="x", padx=20, pady=(12, 4))
        ctk.CTkLabel(res_hdr, text="Results", font=FONT_H2, text_color=C_TEXT).pack(side="left")

        res_fields = ctk.CTkFrame(res_card, fg_color="transparent")
        res_fields.pack(fill="x", padx=20, pady=(4, 16))
        res_fields.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(res_fields, text="ref_time:", font=FONT_BODY, text_color=C_TEXT_DIM).grid(row=0, column=0, sticky="w", padx=(0, 12), pady=4)
        self.s0_ref_time = ctk.CTkEntry(res_fields, font=FONT_MONO, height=34, fg_color=C_INPUT_BG, border_color=C_BORDER, border_width=1, text_color=C_TEXT, corner_radius=6, state="readonly")
        self.s0_ref_time.grid(row=0, column=1, sticky="ew", pady=4)

        ctk.CTkLabel(res_fields, text="ref_qpc:", font=FONT_BODY, text_color=C_TEXT_DIM).grid(row=1, column=0, sticky="w", padx=(0, 12), pady=4)
        self.s0_ref_qpc = ctk.CTkEntry(res_fields, font=FONT_MONO, height=34, fg_color=C_INPUT_BG, border_color=C_BORDER, border_width=1, text_color=C_TEXT, corner_radius=6, state="readonly")
        self.s0_ref_qpc.grid(row=1, column=1, sticky="ew", pady=4)

        # Auto-fill Step 2 is triggered in _step1_done() after success

    def _browse_file(self, entry):
        path = filedialog.askopenfilename(filetypes=[("Akira Log", "Log-*.txt"), ("All", "*.*")])
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _run_step1(self):
        exe = find_exe("Step1_QPCEstimator.exe")
        if not exe:
            messagebox.showerror("Error", "Step1_QPCEstimator.exe not found.")
            return

        log_path = self.s0_log.get().strip()
        cmd = [exe]
        if log_path:
            cmd.extend(["--log", log_path])

        self._clear_log()
        self._append_log(f"$ {' '.join(cmd)}\n\n")
        self._set_status("Running Step 1...", "running")
        self.s0_run.configure(state="disabled")
        self.s0_stop.configure(state="normal")
        self.s0_progress.configure(mode="indeterminate")
        self.s0_progress.start()
        self.s0_progress_label.configure(text="Estimating QPC value...")

        def on_done(rc):
            self.after(0, lambda: self._step1_done(rc))

        runner = ProcessRunner(cmd, on_done=on_done)
        self._runner = runner
        runner.start()

    def _step1_done(self, rc):
        self.s0_run.configure(state="normal")
        self.s0_stop.configure(state="disabled")
        self.s0_progress.stop()
        self.s0_progress.configure(mode="determinate")
        self.s0_progress.set(1.0 if rc == 0 else 0)
        self.s0_progress_label.configure(
            text="Estimation complete." if rc == 0 else "Estimation failed.")
        self._set_status("Step 1 complete" if rc == 0 else "Step 1 failed", "done" if rc == 0 else "error")
        # Parse log text for ref_time and ref_qpc
        log_text = self.log_text.get("1.0", "end")
        m_time = re.search(r'ref_time:\s*"([^"]+)"', log_text)
        m_qpc = re.search(r'ref_qpc:\s*(\d+)', log_text)
        if m_time:
            self.s0_ref_time.configure(state="normal")
            self.s0_ref_time.delete(0, "end")
            self.s0_ref_time.insert(0, m_time.group(1))
            self.s0_ref_time.configure(state="readonly")
        if m_qpc:
            self.s0_ref_qpc.configure(state="normal")
            self.s0_ref_qpc.delete(0, "end")
            self.s0_ref_qpc.insert(0, m_qpc.group(1))
            self.s0_ref_qpc.configure(state="readonly")
        # Auto-fill Step 2 and switch tab on success
        if rc == 0 and m_time and m_qpc:
            self.s1_time.delete(0, "end")
            self.s1_time.insert(0, m_time.group(1))
            self.s1_qpc.delete(0, "end")
            self.s1_qpc.insert(0, m_qpc.group(1))
            self._on_tab_change("Step 2. Seed Search")

    # == Step 2: Seed Search ===============================================

    def _build_step2(self):
        page = ctk.CTkFrame(self.page_container, fg_color="transparent")
        self._pages[1] = page

        # Parameters Card
        card = ctk.CTkFrame(page, fg_color=C_SURFACE, corner_radius=10,
                             border_width=1, border_color=C_BORDER)
        card.pack(fill="x")

        # Card header
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(16, 4))
        ctk.CTkLabel(hdr, text="Search Parameters", font=FONT_H2,
                      text_color=C_TEXT).pack(side="left")
        ctk.CTkLabel(hdr, text="GPU-accelerated brute-force seed search.",
                      font=FONT_SMALL, text_color=C_TEXT_DIM).pack(
            side="left", padx=(10, 0))

        # Info banner
        info = ctk.CTkFrame(card, fg_color="#e8f0fe", corner_radius=6,
                             border_width=1, border_color="#b8d4f0")
        info.pack(fill="x", padx=20, pady=(8, 4))
        ctk.CTkLabel(info, text="\u2139", font=(_FONT, 11), text_color=C_INFO).pack(side="left", padx=(10, 6), pady=8)
        ctk.CTkLabel(info, text="Searches for encryption seeds using GPU acceleration.",
                      font=FONT_SMALL, text_color="#1a56a0", justify="left", wraplength=700).pack(side="left", pady=8)

        # Fields
        fields = ctk.CTkFrame(card, fg_color="transparent")
        fields.pack(fill="x", padx=20, pady=(4, 4))
        fields.grid_columnconfigure(1, weight=1)

        self.s1_root = self._field(fields, "Infected Path", 0,
                                    "Folder containing .akira files",
                                    self._browse_dir,
                                    lambda v: os.path.isdir(v))
        self.s1_time = self._field(fields, "Infection Time", 1,
                                    "YYYY-MM-DD HH:MM:SS.mmm",
                                    validator=lambda v: bool(re.match(
                                        r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}$", v)))
        self.s1_qpc = self._field(fields, "Reference QPC", 2,
                                   "QPC value from Step 1",
                                   validator=lambda v: v.isdigit() and len(v) >= 5)

        # Buttons + Progress
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(8, 4))

        self.s1_run = ctk.CTkButton(
            btn_row, text="Start Search", font=FONT_BTN, height=36,
            fg_color=C_PRIMARY, hover_color=C_PRIMARY_HOVER, corner_radius=6,
            command=self._run_step2)
        self.s1_run.pack(side="left")

        self.s1_stop = ctk.CTkButton(
            btn_row, text="Stop", font=FONT_BTN, height=36, width=60,
            fg_color=C_DANGER, hover_color="#a93226", corner_radius=6,
            command=self._stop_process, state="disabled")
        self.s1_stop.pack(side="left", padx=(8, 0))

        # Progress bar
        self.s1_progress = ctk.CTkProgressBar(
            card, fg_color=C_BORDER, progress_color=C_PRIMARY,
            height=3, corner_radius=1)
        self.s1_progress.pack(fill="x", padx=20, pady=(8, 4))
        self.s1_progress.set(0)

        self.s1_progress_label = ctk.CTkLabel(
            card, text="", font=FONT_SMALL, text_color=C_TEXT_DIM)
        self.s1_progress_label.pack(fill="x", padx=20, pady=(0, 16))

        # Results Card (tk.Frame to avoid CTkFrame centering)
        res_card = tk.Frame(page._parent_frame if hasattr(page, '_parent_frame') else page,
                            bg=C_SURFACE, highlightthickness=1, highlightbackground=C_BORDER)
        res_card.pack(fill="x", pady=(8, 0))

        # Results header
        res_hdr = tk.Frame(res_card, bg=C_SURFACE)
        res_hdr.pack(fill="x", padx=20, pady=(12, 4), anchor="w")
        tk.Label(res_hdr, text="Search Results", font=FONT_H2,
                 fg=C_TEXT, bg=C_SURFACE).pack(side="left")

        self._s1_badge_frame = tk.Frame(res_hdr, bg=C_SURFACE)
        self._s1_badge_frame.pack(side="left", padx=(10, 0))

        # Treeview container
        self._s1_res_frame = tk.Frame(res_card, bg=C_SURFACE)
        self._s1_res_frame.pack(fill="x", padx=16, pady=(4, 16), anchor="nw")

        style = tk.ttk.Style()
        style.theme_use("clam")
        style.configure("Clean.Treeview",
                         background=C_SURFACE, foreground=C_TEXT,
                         fieldbackground=C_SURFACE, borderwidth=0,
                         font=("Cascadia Mono", 10), rowheight=28)
        style.configure("Clean.Treeview.Heading",
                         background=C_SURFACE_ALT, foreground=C_TEXT_DIM,
                         font=("Segoe UI Semibold", 9), borderwidth=0,
                         relief="flat")
        style.map("Clean.Treeview",
                   background=[("selected", C_PRIMARY_DIM)],
                   foreground=[("selected", C_TEXT_BRIGHT)])

        cols = ("file", "qpc3", "qpc4", "qpc1", "qpc2", "time")
        self.s1_tree = tk.ttk.Treeview(
            self._s1_res_frame, columns=cols, show="headings",
            style="Clean.Treeview", height=8)
        for c, w, txt in [("file", 180, "File"),
                           ("qpc3", 120, "QPC3 (KCipher-2 Key)"),
                           ("qpc4", 120, "QPC4 (KCipher-2 IV)"),
                           ("qpc1", 120, "QPC1 (ChaCha8 Key)"),
                           ("qpc2", 120, "QPC2 (ChaCha8 Nonce)"),
                           ("time", 60, "Time(s)")]:
            self.s1_tree.heading(c, text=txt)
            self.s1_tree.column(c, width=w,
                                 anchor="center" if c != "file" else "w")
        self.s1_tree.pack(fill="x", padx=2, pady=2)


    # == Step 3: Decrypt Files =============================================

    def _build_step3(self):
        page = ctk.CTkFrame(self.page_container, fg_color="transparent")
        self._pages[2] = page

        # Input Card
        card = ctk.CTkFrame(page, fg_color=C_SURFACE, corner_radius=10,
                             border_width=1, border_color=C_BORDER)
        card.pack(fill="x")

        # Header
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(16, 4))
        ctk.CTkLabel(hdr, text="File Decryption", font=FONT_H2,
                      text_color=C_TEXT).pack(side="left")
        ctk.CTkLabel(hdr, text="Decrypt all .akira files using discovered seeds.",
                      font=FONT_SMALL, text_color=C_TEXT_DIM).pack(
            side="left", padx=(10, 0))

        # Info banner
        info = ctk.CTkFrame(card, fg_color="#e8f0fe", corner_radius=6,
                             border_width=1, border_color="#b8d4f0")
        info.pack(fill="x", padx=20, pady=(8, 4))
        ctk.CTkLabel(info, text="\u2139", font=(_FONT, 11),
                      text_color=C_INFO).pack(side="left", padx=(10, 6), pady=8)
        ctk.CTkLabel(info, text="After Step 2 completes, the found_seeds CSV is loaded automatically. Click 'Decrypt All' to derive keys and decrypt all files.",
                      font=FONT_SMALL, text_color="#1a56a0").pack(
            side="left", pady=8)

        # QPC List Selection
        sel_frame = ctk.CTkFrame(card, fg_color="transparent")
        sel_frame.pack(fill="x", padx=20, pady=(12, 4))

        ctk.CTkLabel(sel_frame, text="Seed File", font=FONT_BODY,
                      text_color=C_TEXT_DIM, width=80).pack(side="left")

        self.s2_qpc_dropdown = ctk.CTkOptionMenu(
            sel_frame, values=["(Scanning...)"], font=FONT_BODY,
            width=420, height=34, fg_color=C_INPUT_BG,
            button_color=C_BORDER, dropdown_fg_color=C_SURFACE,
            text_color=C_TEXT, button_hover_color=C_BORDER_FOCUS,
            command=self._on_qpc_selected)
        self.s2_qpc_dropdown.pack(side="left", padx=(8, 0))

        ctk.CTkButton(sel_frame, text="Browse", width=68, height=34,
                       font=FONT_SMALL, fg_color=C_SURFACE_ALT,
                       hover_color=C_BORDER, corner_radius=6,
                       text_color=C_TEXT, border_width=1,
                       border_color=C_BORDER,
                       command=self._browse_seed_file).pack(
            side="left", padx=(8, 0))

        ctk.CTkButton(sel_frame, text="\u21bb", width=34, height=34,
                       font=("Segoe UI", 13), fg_color=C_SURFACE_ALT,
                       hover_color=C_BORDER, corner_radius=6,
                       text_color=C_TEXT, border_width=1,
                       border_color=C_BORDER,
                       command=self._refresh_seed_list).pack(
            side="left", padx=(4, 0))

        # Buttons
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(8, 4))

        self.s2_run = ctk.CTkButton(
            btn_row, text="Decrypt All", font=FONT_BTN, height=36,
            fg_color=C_PRIMARY, hover_color=C_PRIMARY_HOVER, corner_radius=6,
            command=self._run_step3)
        self.s2_run.pack(side="left")

        self.s2_stop = ctk.CTkButton(
            btn_row, text="Cancel", font=FONT_BTN, height=36, width=60,
            fg_color=C_DANGER, hover_color="#a93226", corner_radius=6,
            command=self._cancel_decrypt, state="disabled")
        self.s2_stop.pack(side="left", padx=(8, 0))

        # Progress
        self.s2_progress = ctk.CTkProgressBar(
            card, fg_color=C_BORDER, progress_color=C_PRIMARY,
            height=3, corner_radius=1)
        self.s2_progress.pack(fill="x", padx=20, pady=(8, 4))
        self.s2_progress.set(0)

        self.s2_progress_label = ctk.CTkLabel(
            card, text="", font=FONT_SMALL, text_color=C_TEXT_DIM)
        self.s2_progress_label.pack(fill="x", padx=20, pady=(0, 16))

        # Results Card (tk.Frame to avoid CTkFrame centering)
        res_card = tk.Frame(page._parent_frame if hasattr(page, '_parent_frame') else page,
                            bg=C_SURFACE, highlightthickness=1, highlightbackground=C_BORDER)
        res_card.pack(fill="x", pady=(8, 0))

        res_hdr = tk.Frame(res_card, bg=C_SURFACE)
        res_hdr.pack(fill="x", padx=20, pady=(12, 4), anchor="w")
        tk.Label(res_hdr, text="Decryption Results", font=FONT_H2,
                 fg=C_TEXT, bg=C_SURFACE).pack(side="left")

        self._s2_badge_frame = tk.Frame(res_hdr, bg=C_SURFACE)
        self._s2_badge_frame.pack(side="left", padx=(10, 0))

        self._s2_res_frame = tk.Frame(res_card, bg=C_SURFACE)
        self._s2_res_frame.pack(fill="x", padx=16, pady=(4, 16), anchor="nw")

        cols2 = ("file", "mode", "kc2_key", "kc2_iv", "cc8_key", "cc8_iv", "status")
        self.s2_tree = tk.ttk.Treeview(
            self._s2_res_frame, columns=cols2, show="headings",
            style="Clean.Treeview", height=8)
        for c, w, txt in [("file", 180, "File"), ("mode", 50, "Mode"),
                           ("kc2_key", 110, "KCipher-2 Key"),
                           ("kc2_iv", 110, "KCipher-2 IV"),
                           ("cc8_key", 110, "ChaCha8 Key"),
                           ("cc8_iv", 110, "ChaCha8 Nonce"),
                           ("status", 60, "Status")]:
            self.s2_tree.heading(c, text=txt)
            self.s2_tree.column(c, width=w,
                                 anchor="center" if c != "file" else "w")
        self.s2_tree.pack(fill="x", padx=2, pady=2)


    # == QPC List Auto-detect ===============================================

    def _refresh_seed_list(self):
        search_dirs = [
            ".",
            str(PROJECT_DIR),
            str(PROJECT_DIR / "release"),
            str(BASE_DIR),
        ]
        found = {}
        for d in search_dirs:
            try:
                for f in glob.glob(os.path.join(d, "found_seeds_*.csv")):
                    abs_path = os.path.abspath(f)
                    if abs_path not in found:
                        mtime = os.path.getmtime(abs_path)
                        label = f"{os.path.basename(abs_path)}"
                        found[abs_path] = (label, mtime)
            except OSError:
                pass

        sorted_files = sorted(found.items(), key=lambda x: x[1][1],
                               reverse=True)

        self._qpc_file_map = {}
        labels = []
        for path, (label, _) in sorted_files:
            self._qpc_file_map[label] = path
            labels.append(label)

        if labels:
            self.s2_qpc_dropdown.configure(values=labels)
            self.s2_qpc_dropdown.set(labels[0])
        else:
            self.s2_qpc_dropdown.configure(
                values=["(No seed files found)"])
            self.s2_qpc_dropdown.set("(No seed files found)")

    def _on_qpc_selected(self, value):
        pass  # Selection stored in dropdown, read on run

    def _browse_seed_file(self):
        f = filedialog.askopenfilename(
            title="Select seed file",
            filetypes=[("Seed CSV", "found_seeds_*.csv"), ("Text", "*.txt"),
                       ("All", "*.*")])
        if f:
            label = os.path.basename(f)
            self._qpc_file_map[label] = f
            current_vals = list(self.s2_qpc_dropdown.cget("values") or [])
            if label not in current_vals:
                current_vals.insert(0, label)
                self.s2_qpc_dropdown.configure(values=current_vals)
            self.s2_qpc_dropdown.set(label)

    # == Log Section ========================================================

    def _build_log_section(self, parent):
        log_outer = ctk.CTkFrame(parent, fg_color="transparent")
        log_outer.pack(fill="both", expand=False, padx=20, pady=(4, 12))

        # Header (clickable)
        log_header = ctk.CTkFrame(log_outer, fg_color=C_SURFACE,
                                   corner_radius=8, height=34, cursor="hand2",
                                   border_width=1, border_color=C_BORDER)
        log_header.pack(fill="x")
        log_header.pack_propagate(False)

        self._log_arrow = ctk.CTkLabel(log_header, text="\u25be",
                                        font=FONT_BODY, text_color=C_TEXT_DIM)
        self._log_arrow.pack(side="left", padx=(12, 4))
        log_lbl = ctk.CTkLabel(log_header, text="Execution Log", font=FONT_H2,
                                text_color=C_TEXT)
        log_lbl.pack(side="left")

        ctk.CTkButton(log_header, text="Clear", width=56, height=24,
                       font=FONT_SMALL, fg_color=C_SURFACE_ALT,
                       hover_color=C_BORDER, text_color=C_TEXT_DIM,
                       corner_radius=4, border_width=1, border_color=C_BORDER,
                       command=self._clear_log).pack(side="right", padx=8)

        for w in [log_header, self._log_arrow, log_lbl]:
            w.bind("<Button-1>", lambda e: self._toggle_log())

        # Log content
        self._log_frame = ctk.CTkFrame(log_outer, fg_color=C_LOG_BG,
                                        corner_radius=8, border_width=1,
                                        border_color="#2a3a4a")
        self._log_frame.pack(fill="both", expand=True, pady=(2, 0))

        self.log_text = ctk.CTkTextbox(
            self._log_frame, font=("Cascadia Mono", 10), height=200,
            state="disabled",
            fg_color=C_LOG_BG, text_color=C_LOG_TEXT, corner_radius=6,
            wrap="word", border_width=0)
        self.log_text.pack(fill="both", expand=True, padx=12, pady=8)

    def _toggle_log(self):
        self._log_visible = not self._log_visible
        if self._log_visible:
            self._log_arrow.configure(text="\u25be")
            self._log_frame.pack(fill="both", expand=True, pady=(2, 0))
        else:
            self._log_arrow.configure(text="\u25b8")
            self._log_frame.pack_forget()

    # == Browse =============================================================

    def _browse_dir(self, entry):
        d = filedialog.askdirectory(title="Select directory with .akira files")
        if d:
            entry.delete(0, "end")
            entry.insert(0, d)
            entry.event_generate("<FocusOut>")

    # == Log ================================================================

    def _append_log(self, text):
        if isinstance(text, bytes):
            text = text.decode('utf-8', errors='replace')
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _log_safe(self, text):
        self.after(0, lambda: self._append_log(text))

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _poll_queue(self):
        if self._runner:
            try:
                while True:
                    line = self._runner.q.get_nowait()
                    if line is None:
                        break
                    self._append_log(line)
            except queue.Empty:
                pass
        self.after(80, self._poll_queue)

    # == Status =============================================================

    def _set_status(self, text, state="ready"):
        colors = {
            "ready": C_SUCCESS,
            "running": C_PRIMARY,
            "error": C_DANGER,
            "done": C_SUCCESS,
        }
        self._status_dot.configure(text_color=colors.get(state, C_TEXT_DIM))
        self.status_var.set(text)

    # == Process Control ====================================================

    def _stop_process(self):
        if self._runner:
            self._runner.kill()
            self._append_log("\n[STOPPED] Process terminated.\n")
            self._set_status("Stopped", "error")
            self._set_running(False, stage=self._current_stage)

    def _cancel_decrypt(self):
        self._cancel_event.set()
        self._stop_process()

    def _set_running(self, running, stage=None):
        """Enable/disable UI controls during execution.

        Args:
            running: True to lock UI, False to unlock.
            stage: 0=Step1, 1=Step2, 2=Step3. If None, affects all.
        """
        state = "disabled" if running else "normal"
        self.s0_run.configure(state=state)
        self.s1_run.configure(state=state)
        self.s2_run.configure(state=state)

        stop_state = "normal" if running else "disabled"
        if stage is None or stage == 0:
            self.s0_stop.configure(state=stop_state)
        if stage is None or stage == 1:
            self.s1_stop.configure(state=stop_state)
        if stage is None or stage == 2:
            self.s2_stop.configure(state=stop_state)

        # Only toggle progress bar for the active stage
        progress_map = {0: self.s0_progress, 1: self.s1_progress}
        bar = progress_map.get(stage)
        if bar:
            if running:
                bar.configure(mode="indeterminate")
                bar.start()
            else:
                bar.stop()
                bar.configure(mode="determinate")
                bar.set(0)

    # == Badges =============================================================

    def _update_badges(self, frame, badges):
        for w in frame.winfo_children():
            w.destroy()
        for text, color in badges:
            ctk.CTkLabel(frame, text=text, font=FONT_BADGE,
                          text_color=color, fg_color=C_SURFACE_ALT,
                          corner_radius=4).pack(side="left", padx=(4, 0))

    # == Step 2 Logic ======================================================

    def _run_step2(self):
        exe = find_exe("Step2_SeedScanner.exe")
        if not exe:
            messagebox.showerror("Error",
                "Step2_SeedScanner.exe not found.\nBuild the project first.")
            return

        root = self.s1_root.get().strip()
        ref_time = self.s1_time.get().strip()
        ref_qpc = self.s1_qpc.get().strip()
        if not all([root, ref_time, ref_qpc]):
            messagebox.showwarning("Missing",
                "Please fill in all required fields.")
            return

        cmd = [exe, root, ref_time, ref_qpc]

        self._clear_log()
        self._append_log(f"$ {' '.join(cmd)}\n\n")
        self._set_status("Searching seeds...", "running")
        self._set_running(True, stage=1)
        self._update_badges(self._s1_badge_frame, [])

        for item in self.s1_tree.get_children():
            self.s1_tree.delete(item)
        # Clear tree for new run

        def on_done(rc):
            self.after(0, lambda: self._step2_done(rc))
        self._runner = ProcessRunner(cmd, on_done=on_done)
        self._runner.start()

    def _step2_done(self, rc):
        self._set_running(False, stage=1)
        if rc == 0:
            self._parse_step2_results()
        else:
            self._set_status(f"Step 2 failed (exit {rc})", "error")

    def _parse_step2_results(self):
        f = None
        for d in [".", str(PROJECT_DIR), str(PROJECT_DIR / "release")]:
            f = find_latest_file("found_seeds_*.csv", d)
            if f:
                break
        if not f:
            self._set_status("No seed file found.", "error")
            return

        rows = []
        try:
            with open(f, "r", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    rows.append(row)
        except Exception as e:
            self._append_log(f"[ERROR] {e}\n")
            return

        # Show treeview, hide placeholder
        for item in self.s1_tree.get_children():
            self.s1_tree.delete(item)
        for r in rows:
            self.s1_tree.insert("", "end", values=(
                r.get("file_name", ""),
                r.get("qpc3", ""), r.get("qpc4", ""),
                r.get("qpc1", ""), r.get("qpc2", ""),
                r.get("elapsed_seconds", "")))

        elapsed = rows[-1].get("elapsed_seconds", "?") if rows else "?"
        self._update_badges(self._s1_badge_frame, [
            (f"{len(rows)} seeds found", C_SUCCESS),
            (f"{elapsed}s", C_TEXT_DIM),
        ])
        self._set_status(
            f"Found {len(rows)} seed pair(s). Output: {os.path.basename(f)}",
            "done")

        # Auto-refresh Step 3 dropdown
        self._refresh_seed_list()

        # Prompt to proceed to Step 3
        if len(rows) > 0:
            if messagebox.askyesno("Seeds Found",
                    f"{len(rows)} seed(s) found.\nProceed to Step 3 (Decrypt)?"):
                self._on_tab_change("Step 3. Decrypt Files")

    # == Step 3 Logic (Parallel Decryption) ================================

    def _run_step3(self):
        keygen = find_exe("SeedToKey.exe")
        if not keygen:
            messagebox.showerror("Error",
                "SeedToKey.exe not found.\nBuild the project first.")
            return

        decrypt_exe = find_exe("Step3_FileDecryptor.exe")
        if not decrypt_exe:
            messagebox.showerror("Error",
                "Step3_FileDecryptor.exe not found.\nBuild the project first.")
            return

        selected = self.s2_qpc_dropdown.get()
        qpc_file = self._qpc_file_map.get(selected, selected)
        if not qpc_file or not os.path.exists(qpc_file):
            messagebox.showwarning("Missing",
                "Please select a valid seed file.")
            return

        # Parse seed file
        entries = []
        try:
            with open(qpc_file, "r", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    fp = row.get("file_path", "").strip()
                    q3 = row.get("qpc3", "").strip()
                    q4 = row.get("qpc4", "").strip()
                    q1 = row.get("qpc1", "").strip()
                    q2 = row.get("qpc2", "").strip()
                    mode = row.get("enc_mode", "half").strip() or "half"
                    if fp and q3 and q4:
                        entries.append((fp, q3, q4, q1, q2, mode))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse: {e}")
            return

        if not entries:
            messagebox.showinfo("Info", "No valid entries in seed file.")
            return

        # Populate table
        for item in self.s2_tree.get_children():
            self.s2_tree.delete(item)
        iids = []
        for fp, q3, q4, q1, q2, mode in entries:
            parent_dir = os.path.basename(os.path.dirname(fp))
            fname = os.path.join(parent_dir, os.path.basename(fp))
            iid = self.s2_tree.insert("", "end",
                                       values=(fname, mode, "...", "...",
                                               "...", "...", "Pending"))
            iids.append(iid)

        self._clear_log()
        self._append_log(f"[INFO] Processing {len(entries)} file(s)...\n\n")
        self._set_status(f"Decrypting {len(entries)} file(s)...", "running")
        self._set_running(True, stage=2)
        self._cancel_event.clear()
        self.s2_progress.set(0)
        self.s2_progress.configure(mode="determinate")

        def process_all():
            # Phase 1: Batch key derivation (all unique seeds at once)
            # Collect seeds with their required output sizes
            # KCipher-2: key=16B, IV=16B. ChaCha8: key=16B, nonce=8B.
            seed_sizes = {}  # seed_str -> size_in_bytes
            for fp, q3, q4, q1, q2, mode in entries:
                seed_sizes[q3] = 16  # KCipher-2 key
                seed_sizes[q4] = 16  # KCipher-2 IV
                if q1: seed_sizes[q1] = 16  # ChaCha8 key
                if q2: seed_sizes[q2] = 8   # ChaCha8 nonce

            seed_cache = {}  # seed_str -> hex_key
            self._log_safe(f"[Phase 1] Deriving keys for {len(seed_sizes)} unique seeds...\n")
            for seed, size in seed_sizes.items():
                if self._cancel_event.is_set():
                    self._log_safe("\n[CANCELLED] Key derivation aborted.\n")
                    self.after(0, lambda: self._step3_done(ok_count[0], len(entries)))
                    return
                seed_cache[seed] = self._run_keygen(keygen, seed, size)
            self._log_safe(f"[Phase 1] Done.\n\n")

            # Phase 2: Parallel decryption
            max_workers = min(os.cpu_count() or 4, 8, len(entries))
            completed = [0]  # mutable counter
            ok_count = [0]
            lock = threading.Lock()

            def decrypt_one(idx, fp, q3, q4, q1, q2, mode, iid):
                if self._cancel_event.is_set():
                    return False

                key_hex = seed_cache.get(q3, "")
                iv_hex = seed_cache.get(q4, "")
                cc8_key_hex = seed_cache.get(q1, "") if q1 else ""
                cc8_iv_hex = seed_cache.get(q2, "") if q2 else ""

                if not key_hex or not iv_hex:
                    self.after(0, lambda _iid=iid: self.s2_tree.set(_iid, "status", "FAILED"))
                    with lock:
                        completed[0] += 1
                        progress = completed[0] / len(entries)
                        c = completed[0]
                        self.after(0, lambda p=progress, _c=c: (
                            self.s2_progress.set(p),
                            self.s2_progress_label.configure(
                                text=f"{_c}/{len(entries)} files")))
                    return False

                self.after(0, lambda _iid=iid, k=key_hex, v=iv_hex,
                           ck=cc8_key_hex, cv=cc8_iv_hex: (
                    self.s2_tree.set(_iid, "kc2_key", k),
                    self.s2_tree.set(_iid, "kc2_iv", v),
                    self.s2_tree.set(_iid, "cc8_key", ck or "-"),
                    self.s2_tree.set(_iid, "cc8_iv", cv or "-"),
                    self.s2_tree.set(_iid, "status", "Decrypting...")))

                out_path = fp[:-len(".akira")] if fp.endswith(".akira") else fp + ".decrypted"

                # Build command with optional ChaCha8 keys
                cmd = [decrypt_exe, "--key", key_hex, "--iv", iv_hex,
                       "--input", fp, "--output", out_path, "--mode", mode]
                if cc8_key_hex and cc8_iv_hex:
                    cmd += ["--chacha-key", cc8_key_hex, "--chacha-iv", cc8_iv_hex]

                try:
                    r = subprocess.run(
                        cmd,
                        capture_output=True, text=True, timeout=120,
                        encoding="utf-8", errors="replace",
                        creationflags=_SUBPROCESS_FLAGS)

                    success = r.returncode == 0
                    status = "OK" if success else "FAILED"
                    self.after(0, lambda _iid=iid, s=status: self.s2_tree.set(_iid, "status", s))

                    if not success:
                        err_msg = r.stderr.strip() or r.stdout.strip()
                        if err_msg:
                            self._log_safe(f"  [{os.path.basename(fp)}] ERROR: {err_msg}\n")

                    with lock:
                        completed[0] += 1
                        if success:
                            ok_count[0] += 1
                        progress = completed[0] / len(entries)
                        c = completed[0]
                        self.after(0, lambda p=progress, _c=c: (
                            self.s2_progress.set(p),
                            self.s2_progress_label.configure(
                                text=f"{_c}/{len(entries)} files")))

                    return success
                except subprocess.TimeoutExpired:
                    try:
                        r.kill()
                        r.communicate(timeout=5)
                    except Exception:
                        pass
                    self.after(0, lambda _iid=iid: self.s2_tree.set(_iid, "status", "TIMEOUT"))
                    with lock:
                        completed[0] += 1
                    return False
                except Exception as e:
                    self._log_safe(f"  [{os.path.basename(fp)}] ERROR: {e}\n")
                    self.after(0, lambda _iid=iid: self.s2_tree.set(_iid, "status", "FAILED"))
                    with lock:
                        completed[0] += 1
                    return False

            self._log_safe(f"[Phase 2] Decrypting {len(entries)} files ({max_workers} parallel)...\n")

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = []
                for i, (fp, q3, q4, q1, q2, mode) in enumerate(entries):
                    if self._cancel_event.is_set():
                        break
                    f = pool.submit(decrypt_one, i, fp, q3, q4, q1, q2, mode, iids[i])
                    futures.append(f)

                for f in as_completed(futures, timeout=300):
                    pass  # Results already handled in decrypt_one

            self._log_safe(f"\n[DONE] {ok_count[0]}/{len(entries)} files decrypted.\n")
            self.after(0, lambda: self._step3_done(ok_count[0], len(entries)))

        threading.Thread(target=process_all, daemon=True).start()

    def _run_keygen(self, exe, seed, size=16):
        try:
            r = subprocess.run([exe, seed, str(size), "--format", "hex"],
                                capture_output=True,
                                text=True, timeout=30, encoding="utf-8",
                                errors="replace",
                                creationflags=_SUBPROCESS_FLAGS)
            if r.returncode == 0:
                # Extract hex from output (may have labels like "Key (hex): ...")
                out = r.stdout.strip()
                for line in out.splitlines():
                    line = line.strip()
                    if ":" in line:
                        line = line.split(":", 1)[1].strip()
                    expected_len = size * 2  # 16B=32hex, 8B=16hex
                    if len(line) == expected_len and all(c in "0123456789ABCDEFabcdef" for c in line):
                        return line
                self._log_safe(f"  [WARN] Unexpected SeedToKey output: {out[:80]}\n")
                return ""
            self._log_safe(f"  [ERROR] SeedToKey failed: {r.stderr}\n")
        except Exception as e:
            self._log_safe(f"  [ERROR] {e}\n")
        return ""

    def _step3_done(self, ok, total):
        self._set_running(False, stage=2)
        self._update_badges(self._s2_badge_frame, [
            (f"{ok}/{total} decrypted", C_SUCCESS if ok == total else C_DANGER),
        ])
        self._set_status(f"Complete: {ok}/{total} files decrypted.", "done")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        app = AkiraGUI()
        app.mainloop()
    except Exception:
        import traceback
        crash_log = os.path.join(
            os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
            else os.path.dirname(__file__), "crash.log")
        with open(crash_log, "w", encoding="utf-8") as f:
            traceback.print_exc(file=f)
        raise
