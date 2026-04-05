"""
Win2K NT Internals Analyzer — Professional GUI
================================================
Full graphical interface for analyzing, comparing, decompiling,
patching, and building NT kernel-mode and user-mode binaries.

Features:
  - 13 analysis tabs covering every aspect of NT internals
  - Dark / Light / Midnight themes with live switching
  - Smart defaults and examples (ntdll.dll, ntoskrnl.exe, etc.)
  - Professional status bar, tooltips, and visual hierarchy

Launch:  python win2k_gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import json
import importlib


# ══════════════════════════════════════════════════════════════════════════
#  Lazy Imports — backend modules loaded on first use for fast startup
# ══════════════════════════════════════════════════════════════════════════

_module_cache = {}


def _lazy(module_name):
    """Import and cache a module on first access."""
    if module_name not in _module_cache:
        _module_cache[module_name] = importlib.import_module(module_name)
    return _module_cache[module_name]


def _pe_analyzer():     return _lazy('nt_analyzer.pe_analyzer')
def _syscall_ext():     return _lazy('nt_analyzer.syscall_extractor')
def _comparator():      return _lazy('nt_analyzer.comparator')
def _struct_analyzer(): return _lazy('nt_analyzer.struct_analyzer')
def _def_generator():   return _lazy('nt_analyzer.def_generator')
def _sc_patcher():      return _lazy('nt_analyzer.syscall_patcher')
def _ros_patcher():     return _lazy('nt_analyzer.ros_patcher')
def _build_gen():       return _lazy('nt_analyzer.build_generator')
def _behavior():        return _lazy('nt_analyzer.behavior_analyzer')
def _decompiler():      return _lazy('nt_analyzer.decompiler')
def _compat():          return _lazy('nt_analyzer.compat_analyzer')
def _pe_patcher():      return _lazy('nt_analyzer.pe_patcher')


# ══════════════════════════════════════════════════════════════════════════
#  Theme System — Three professional color schemes
# ══════════════════════════════════════════════════════════════════════════

THEMES = {
    "Dark": {
        "bg":         "#1e1e2e",
        "bg_dark":    "#181825",
        "bg_light":   "#313244",
        "fg":         "#cdd6f4",
        "fg_dim":     "#6c7086",
        "accent":     "#89b4fa",
        "accent_hover": "#74c7ec",
        "green":      "#a6e3a1",
        "red":        "#f38ba8",
        "yellow":     "#f9e2af",
        "peach":      "#fab387",
        "tab_bg":     "#11111b",
        "entry_bg":   "#45475a",
        "btn_bg":     "#585b70",
        "btn_active": "#7f849c",
        "border":     "#313244",
        "header_bg":  "#11111b",
        "card_bg":    "#1e1e2e",
        "separator":  "#45475a",
        "placeholder":"#6c7086",
    },
    "Light": {
        "bg":         "#eff1f5",
        "bg_dark":    "#e6e9ef",
        "bg_light":   "#ccd0da",
        "fg":         "#4c4f69",
        "fg_dim":     "#8c8fa1",
        "accent":     "#1e66f5",
        "accent_hover": "#2a7bf5",
        "green":      "#40a02b",
        "red":        "#d20f39",
        "yellow":     "#df8e1d",
        "peach":      "#fe640b",
        "tab_bg":     "#dce0e8",
        "entry_bg":   "#ffffff",
        "btn_bg":     "#ccd0da",
        "btn_active": "#bcc0cc",
        "border":     "#bcc0cc",
        "header_bg":  "#dce0e8",
        "card_bg":    "#e6e9ef",
        "separator":  "#ccd0da",
        "placeholder":"#9ca0b0",
    },
    "Midnight": {
        "bg":         "#0d1117",
        "bg_dark":    "#010409",
        "bg_light":   "#161b22",
        "fg":         "#e6edf3",
        "fg_dim":     "#7d8590",
        "accent":     "#58a6ff",
        "accent_hover": "#79c0ff",
        "green":      "#3fb950",
        "red":        "#f85149",
        "yellow":     "#d29922",
        "peach":      "#f0883e",
        "tab_bg":     "#010409",
        "entry_bg":   "#21262d",
        "btn_bg":     "#30363d",
        "btn_active": "#484f58",
        "border":     "#30363d",
        "header_bg":  "#010409",
        "card_bg":    "#0d1117",
        "separator":  "#21262d",
        "placeholder":"#484f58",
    },
}

# Current theme — mutable global dict so all code can read T['key']
T = {}
_current_theme_name = "Dark"


def set_theme(name):
    global _current_theme_name
    _current_theme_name = name
    T.clear()
    T.update(THEMES[name])


set_theme("Dark")  # default


# ══════════════════════════════════════════════════════════════════════════
#  Smart Defaults — example paths for file pickers
# ══════════════════════════════════════════════════════════════════════════

EXAMPLES = {
    "dll":       "e.g.  C:\\Windows\\System32\\ntdll.dll",
    "ntdll":     "e.g.  C:\\WINNT\\System32\\ntdll.dll",
    "kernel":    "e.g.  C:\\WINNT\\System32\\ntoskrnl.exe",
    "pe":        "e.g.  ntdll.dll, kernel32.dll, hal.dll, win32k.sys",
    "win2k_dll": "e.g.  C:\\WINNT\\System32\\kernel32.dll",
    "ros_dll":   "e.g.  C:\\reactos\\dll\\win32\\kernel32\\kernel32.dll",
    "ros_dir":   "e.g.  C:\\reactos",
    "scan_dir":  "e.g.  C:\\WINNT\\System32",
    "def_file":  "e.g.  kernel32.def",
    "pe_patch":  "e.g.  ntdll.dll, hal.dll, win32k.sys, ACPI.sys",
}


# ══════════════════════════════════════════════════════════════════════════
#  PlaceholderEntry — Entry widget with grey hint text
# ══════════════════════════════════════════════════════════════════════════

class PlaceholderEntry(tk.Entry):
    """Entry with placeholder hint text that disappears on focus."""

    def __init__(self, master=None, placeholder="", textvariable=None, **kw):
        self._ph = placeholder
        self._var = textvariable or tk.StringVar()
        self._showing_ph = False
        super().__init__(master, textvariable=self._var, **kw)
        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)
        self._on_focus_out()  # show placeholder initially

    def _on_focus_in(self, event=None):
        if self._showing_ph:
            self._var.set("")
            self.configure(fg=T["fg"])
            self._showing_ph = False

    def _on_focus_out(self, event=None):
        if not self._var.get():
            self._var.set(self._ph)
            self.configure(fg=T["placeholder"])
            self._showing_ph = True

    def get_value(self):
        """Return actual value (empty string if placeholder is showing)."""
        if self._showing_ph:
            return ""
        return self._var.get()

    def set_value(self, val):
        self._var.set(val)
        self._showing_ph = False
        self.configure(fg=T["fg"])

    def refresh_theme(self):
        if self._showing_ph:
            self.configure(fg=T["placeholder"], bg=T["entry_bg"], insertbackground=T["fg"])
        else:
            self.configure(fg=T["fg"], bg=T["entry_bg"], insertbackground=T["fg"])


# ══════════════════════════════════════════════════════════════════════════
#  Main Application
# ══════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Win2K NT Internals Analyzer")
        self.geometry("1300x850")
        self.minsize(1000, 650)
        self.configure(bg=T["bg"])

        # Track PlaceholderEntry widgets for theme refresh
        self._placeholder_entries = []

        self._configure_styles()
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

    # ── Style engine ──────────────────────────────────────────────────────
    def _configure_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        s = self.style
        s.configure(".", background=T["bg"], foreground=T["fg"], fieldbackground=T["entry_bg"])

        # Notebook
        s.configure("TNotebook", background=T["tab_bg"], borderwidth=0,
                     tabmargins=[8, 6, 8, 4])
        s.configure("TNotebook.Tab", background=T["bg_light"], foreground=T["fg"],
                     padding=[14, 7], font=("Segoe UI", 9, "bold"))
        s.map("TNotebook.Tab",
              background=[("selected", T["accent"])],
              foreground=[("selected", T["bg_dark"])])

        # Frames
        s.configure("TFrame", background=T["bg"])
        s.configure("Card.TFrame", background=T["card_bg"], relief="flat")

        # Labels
        s.configure("TLabel", background=T["bg"], foreground=T["fg"], font=("Segoe UI", 10))
        s.configure("Header.TLabel", background=T["header_bg"], foreground=T["accent"],
                     font=("Segoe UI", 18, "bold"))
        s.configure("SubHeader.TLabel", background=T["header_bg"], foreground=T["fg_dim"],
                     font=("Segoe UI", 10))
        s.configure("Section.TLabel", background=T["bg"], foreground=T["accent"],
                     font=("Segoe UI", 11, "bold"))
        s.configure("Status.TLabel", background=T["header_bg"], foreground=T["fg_dim"],
                     font=("Segoe UI", 9))
        s.configure("Version.TLabel", background=T["header_bg"], foreground=T["fg_dim"],
                     font=("Segoe UI", 9, "italic"))

        # Buttons
        s.configure("TButton", background=T["btn_bg"], foreground=T["fg"],
                     font=("Segoe UI", 10, "bold"), padding=[12, 5])
        s.map("TButton",
              background=[("active", T["btn_active"])],
              foreground=[("active", T["fg"])])

        s.configure("Accent.TButton", background=T["accent"], foreground=T["bg_dark"],
                     font=("Segoe UI", 10, "bold"), padding=[14, 6])
        s.map("Accent.TButton",
              background=[("active", T["accent_hover"])])

        s.configure("Theme.TButton", background=T["bg_light"], foreground=T["fg"],
                     font=("Segoe UI", 9), padding=[10, 4])
        s.map("Theme.TButton",
              background=[("active", T["btn_active"])])

        # Treeview
        s.configure("Treeview", background=T["bg_dark"], foreground=T["fg"],
                     fieldbackground=T["bg_dark"], font=("Consolas", 9), rowheight=24)
        s.configure("Treeview.Heading", background=T["bg_light"], foreground=T["accent"],
                     font=("Segoe UI", 9, "bold"))
        s.map("Treeview",
              background=[("selected", T["bg_light"])],
              foreground=[("selected", T["accent"])])

        # Separator
        s.configure("TSeparator", background=T["separator"])

        # Radiobutton / Checkbutton
        s.configure("TRadiobutton", background=T["bg"], foreground=T["fg"],
                     font=("Segoe UI", 10))
        s.configure("TCheckbutton", background=T["bg"], foreground=T["fg"],
                     font=("Segoe UI", 10))

    # ── Header bar ────────────────────────────────────────────────────────
    def _build_header(self):
        self.hdr = tk.Frame(self, bg=T["header_bg"], height=64)
        self.hdr.pack(fill="x")
        self.hdr.pack_propagate(False)

        # Left: Title + subtitle
        left = tk.Frame(self.hdr, bg=T["header_bg"])
        left.pack(side="left", padx=20, pady=6)

        self.hdr_title = ttk.Label(left, text="\u2588\u2588 Win2K NT Internals Analyzer",
                                   style="Header.TLabel")
        self.hdr_title.pack(side="left")

        self.hdr_sub = ttk.Label(left,
            text="    Analyze \u2022 Compare \u2022 Decompile \u2022 Patch \u2022 Build   |   NT 5.0 \u2192 Windows 2000 SP4",
            style="SubHeader.TLabel")
        self.hdr_sub.pack(side="left", padx=(8, 0))

        # Right: Theme selector
        right = tk.Frame(self.hdr, bg=T["header_bg"])
        right.pack(side="right", padx=20, pady=6)

        self.hdr_version = ttk.Label(right, text="v3.0", style="Version.TLabel")
        self.hdr_version.pack(side="left", padx=(0, 16))

        ttk.Label(right, text="Theme:", style="SubHeader.TLabel").pack(side="left", padx=(0, 6))

        self.theme_var = tk.StringVar(value=_current_theme_name)
        self.theme_combo = ttk.Combobox(right, textvariable=self.theme_var,
                                         values=list(THEMES.keys()), state="readonly",
                                         width=10, font=("Segoe UI", 9))
        self.theme_combo.pack(side="left")
        self.theme_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_theme(self.theme_var.get()))

    # ── Notebook / Tabs ──────────────────────────────────────────────────
    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(6, 0))

        self.tab_exports    = ExportImportTab(self.nb, self)
        self.tab_syscalls   = SyscallTab(self.nb, self)
        self.tab_compare    = CompareTab(self.nb, self)
        self.tab_structs    = StructTab(self.nb, self)
        self.tab_pe         = PEHeaderTab(self.nb, self)
        self.tab_defgen     = DefGenTab(self.nb, self)
        self.tab_scpatch    = SyscallPatchTab(self.nb, self)
        self.tab_rospatch   = ROSPatchTab(self.nb, self)
        self.tab_build      = BuildGenTab(self.nb, self)
        self.tab_behavior   = BehaviorTab(self.nb, self)
        self.tab_decompiler = DecompilerTab(self.nb, self)
        self.tab_compat     = CompatAnalyzerTab(self.nb, self)
        self.tab_patcher    = PEPatcherTab(self.nb, self)

        tabs = [
            (self.tab_exports,    " Exports "),
            (self.tab_syscalls,   " Syscalls "),
            (self.tab_compare,    " Compare "),
            (self.tab_structs,    " Structs "),
            (self.tab_pe,         " PE Header "),
            (self.tab_defgen,     " DEF Gen "),
            (self.tab_scpatch,    " SC Patch "),
            (self.tab_rospatch,   " ROS Patch "),
            (self.tab_build,      " Build "),
            (self.tab_behavior,   " Behavior "),
            (self.tab_decompiler, " Decompile "),
            (self.tab_compat,     " Compat "),
            (self.tab_patcher,    " PE Patch "),
        ]
        for tab, text in tabs:
            self.nb.add(tab, text=text)

    # ── Status bar ────────────────────────────────────────────────────────
    def _build_statusbar(self):
        self.statusbar = tk.Frame(self, bg=T["header_bg"], height=28)
        self.statusbar.pack(fill="x", side="bottom")
        self.statusbar.pack_propagate(False)

        self.status_lbl = ttk.Label(self.statusbar,
            text="  Ready  \u2022  13 analysis modules loaded  \u2022  All PE types supported: .dll .sys .exe .cpl .drv .ocx .scr",
            style="Status.TLabel")
        self.status_lbl.pack(side="left", padx=10, pady=4)

        self.theme_lbl = ttk.Label(self.statusbar,
            text=f"Theme: {_current_theme_name}  ",
            style="Status.TLabel")
        self.theme_lbl.pack(side="right", padx=10, pady=4)

    # ── Theme switching ───────────────────────────────────────────────────
    def _apply_theme(self, name):
        set_theme(name)
        self._configure_styles()

        # Update root window
        self.configure(bg=T["bg"])

        # Walk ALL widgets and recolor
        self._recolor_tree(self)

        # Update status bar label
        self.theme_lbl.configure(text=f"Theme: {name}  ")

        # Update PlaceholderEntry widgets
        for entry in self._placeholder_entries:
            try:
                entry.refresh_theme()
            except tk.TclError:
                pass

    def _recolor_tree(self, widget):
        """Iteratively recolor all tk (non-ttk) widgets."""
        hdr_ids = {id(self.hdr), id(self.statusbar)}
        stack = list(widget.winfo_children())
        # Pre-collect header-zone widget ids for O(1) lookup
        hdr_zone = set()
        for root_w in (self.hdr, self.statusbar):
            sub = [root_w]
            while sub:
                w = sub.pop()
                hdr_zone.add(id(w))
                sub.extend(w.winfo_children())

        while stack:
            child = stack.pop()
            cls_name = type(child).__name__
            try:
                if cls_name == "Frame":
                    bg = T["header_bg"] if id(child) in hdr_zone else T["bg"]
                    child.configure(bg=bg)
                elif cls_name == "Entry" and not isinstance(child, PlaceholderEntry):
                    child.configure(bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"])
                elif cls_name == "ScrolledText":
                    child.configure(bg=T["bg_dark"], fg=T["fg"], insertbackground=T["fg"])
                    child.tag_configure("title",   foreground=T["accent"], font=("Consolas", 11, "bold"))
                    child.tag_configure("ok",      foreground=T["green"])
                    child.tag_configure("warn",    foreground=T["yellow"])
                    child.tag_configure("error",   foreground=T["red"])
                    child.tag_configure("dim",     foreground=T["fg_dim"])
                    child.tag_configure("peach",   foreground=T["peach"])
                    child.tag_configure("heading", foreground=T["accent"], font=("Consolas", 10, "bold"))
                elif cls_name == "Checkbutton":
                    child.configure(bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"],
                                    activebackground=T["bg"], activeforeground=T["fg"])
                elif cls_name == "Text":
                    child.configure(bg=T["bg_dark"], fg=T["fg"], insertbackground=T["fg"])
            except (tk.TclError, AttributeError):
                pass
            stack.extend(child.winfo_children())

    def register_placeholder(self, entry):
        self._placeholder_entries.append(entry)

    def set_status(self, text):
        self.status_lbl.configure(text=f"  {text}")


# ══════════════════════════════════════════════════════════════════════════
#  Helper Functions
# ══════════════════════════════════════════════════════════════════════════

def make_file_picker(parent, label_text, row=0, placeholder="", app=None):
    """Create a label + entry + browse button row. Returns (frame, var_getter)."""
    frm = tk.Frame(parent, bg=T["bg"])
    frm.grid(row=row, column=0, sticky="ew", padx=12, pady=5)
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text=label_text, width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))

    var = tk.StringVar()
    if placeholder:
        ent = PlaceholderEntry(frm, placeholder=placeholder, textvariable=var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        if app:
            app.register_placeholder(ent)
    else:
        ent = tk.Entry(frm, textvariable=var, bg=T["entry_bg"], fg=T["fg"],
                       insertbackground=T["fg"], font=("Consolas", 10), relief="flat", bd=5)
    ent.grid(row=0, column=1, sticky="ew")

    def browse():
        path = filedialog.askopenfilename(
            filetypes=[("PE Files", "*.dll;*.sys;*.exe;*.cpl;*.drv;*.ocx;*.scr"),
                       ("All Files", "*.*")])
        if path:
            if isinstance(ent, PlaceholderEntry):
                ent.set_value(path)
            else:
                var.set(path)

    ttk.Button(frm, text="Browse \u2026", command=browse).grid(row=0, column=2, padx=(8, 0))

    # Return a getter that handles placeholder entries correctly
    def get_value():
        if isinstance(ent, PlaceholderEntry):
            return ent.get_value()
        return var.get()

    return frm, get_value, var


def make_dir_picker(parent, label_text, row=0, placeholder="", app=None):
    """Create a label + entry + browse button for directories."""
    frm = tk.Frame(parent, bg=T["bg"])
    frm.grid(row=row, column=0, sticky="ew", padx=12, pady=5)
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text=label_text, width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))

    var = tk.StringVar()
    if placeholder:
        ent = PlaceholderEntry(frm, placeholder=placeholder, textvariable=var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        if app:
            app.register_placeholder(ent)
    else:
        ent = tk.Entry(frm, textvariable=var, bg=T["entry_bg"], fg=T["fg"],
                       insertbackground=T["fg"], font=("Consolas", 10), relief="flat", bd=5)
    ent.grid(row=0, column=1, sticky="ew")

    def browse():
        path = filedialog.askdirectory()
        if path:
            if isinstance(ent, PlaceholderEntry):
                ent.set_value(path)
            else:
                var.set(path)

    ttk.Button(frm, text="Browse \u2026", command=browse).grid(row=0, column=2, padx=(8, 0))

    def get_value():
        if isinstance(ent, PlaceholderEntry):
            return ent.get_value()
        return var.get()

    return frm, get_value, var


def make_output(parent):
    """Create a themed scrolled text output area with colored tags."""
    txt = scrolledtext.ScrolledText(parent, bg=T["bg_dark"], fg=T["fg"], insertbackground=T["fg"],
                                     font=("Consolas", 10), relief="flat", bd=8,
                                     wrap="none", state="disabled")
    txt.tag_configure("title",   foreground=T["accent"], font=("Consolas", 11, "bold"))
    txt.tag_configure("ok",      foreground=T["green"])
    txt.tag_configure("warn",    foreground=T["yellow"])
    txt.tag_configure("error",   foreground=T["red"])
    txt.tag_configure("dim",     foreground=T["fg_dim"])
    txt.tag_configure("peach",   foreground=T["peach"])
    txt.tag_configure("heading", foreground=T["accent"], font=("Consolas", 10, "bold"))
    return txt


def output_write(txt_widget, content, tag=None):
    """Append text to a read-only ScrolledText."""
    txt_widget.configure(state="normal")
    if tag:
        txt_widget.insert("end", content, tag)
    else:
        txt_widget.insert("end", content)
    txt_widget.configure(state="disabled")
    txt_widget.see("end")


def output_clear(txt_widget):
    txt_widget.configure(state="normal")
    txt_widget.delete("1.0", "end")
    txt_widget.configure(state="disabled")


def run_async(func, callback=None):
    """Run func in a background thread, call callback(result) on completion."""
    def wrapper():
        try:
            result = func()
            if callback:
                callback(result)
        except Exception as e:
            if callback:
                callback(e)
    t = threading.Thread(target=wrapper, daemon=True)
    t.start()


def make_section_label(parent, text, row=0):
    """Create a styled section divider label."""
    lbl = ttk.Label(parent, text=f"  \u2500\u2500  {text}  \u2500\u2500", style="Section.TLabel")
    lbl.grid(row=row, column=0, sticky="w", padx=12, pady=(10, 4))
    return lbl


def make_button_bar(parent, row=0):
    """Create a button container frame."""
    frm = tk.Frame(parent, bg=T["bg"])
    frm.grid(row=row, column=0, sticky="ew", padx=12, pady=6)
    return frm


# ══════════════════════════════════════════════════════════════════════════
#  Tab 1: Export / Import Analyzer
# ══════════════════════════════════════════════════════════════════════════

class ExportImportTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        _, self._get_dll, self.dll_var = make_file_picker(
            self, "PE File:", row=0,
            placeholder=EXAMPLES["dll"], app=app)

        btn_frm = make_button_bar(self, row=1)
        ttk.Button(btn_frm, text="\U0001F4E4  Analyze Exports", style="Accent.TButton",
                   command=self._run_exports).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4E5  Analyze Imports", style="Accent.TButton",
                   command=self._run_imports).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save JSON",
                   command=self._save_json).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Select a PE file (ntdll.dll, kernel32.dll, hal.dll, win32k.sys, ...)")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=2, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_data = None

    def _run_exports(self):
        path = self._get_dll()
        if not path:
            messagebox.showwarning("No file", "Please select a PE file first.\n\nExample: ntdll.dll, kernel32.dll")
            return
        self.status_var.set("\u23F3 Analyzing exports...")
        output_clear(self.output)

        def work():
            return _pe_analyzer().analyze_exports(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_data = result
            output_write(self.output, f"  EXPORTS: {result['dll_name']}\n", "title")
            output_write(self.output, f"  Total: {result['total_exports']} exports\n\n", "ok")
            output_write(self.output,
                f"  {'Ord':<8} {'Name':<50} {'RVA':<12} {'Forwarded To'}\n", "heading")
            output_write(self.output, f"  {'\u2500'*8} {'\u2500'*50} {'\u2500'*12} {'\u2500'*30}\n", "dim")
            for exp in result['exports']:
                name = exp['name'] or "(ordinal only)"
                fwd = exp['forwarded_to'] or ''
                line = f"  {exp['ordinal']:<8} {name:<50} {hex(exp['rva']):<12} {fwd}\n"
                if fwd:
                    output_write(self.output, line, "peach")
                elif not exp['name']:
                    output_write(self.output, line, "dim")
                else:
                    output_write(self.output, line)
            self.status_var.set(f"\u2705 Done \u2014 {result['total_exports']} exports found")
            self.app.set_status(f"Exports: {result['dll_name']} \u2014 {result['total_exports']} exports")

        run_async(work, lambda r: self.after(0, done, r))

    def _run_imports(self):
        path = self._get_dll()
        if not path:
            messagebox.showwarning("No file", "Please select a PE file first.\n\nExample: ntdll.dll, kernel32.dll")
            return
        self.status_var.set("\u23F3 Analyzing imports...")
        output_clear(self.output)

        def work():
            return _pe_analyzer().analyze_imports(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_data = result
            total = sum(len(v) for v in result.values())
            output_write(self.output, f"  IMPORTS\n", "title")
            output_write(self.output, f"  {len(result)} DLLs, {total} functions\n\n", "ok")
            for dll_name, funcs in sorted(result.items()):
                output_write(self.output, f"  [{dll_name}]", "heading")
                output_write(self.output, f"  ({len(funcs)} functions)\n", "dim")
                for f in funcs:
                    name = f['name'] or f"ordinal #{f['ordinal']}"
                    output_write(self.output, f"    {name}\n")
                output_write(self.output, "\n")
            self.status_var.set(f"\u2705 Done \u2014 {len(result)} DLLs, {total} imports")
            self.app.set_status(f"Imports: {len(result)} DLLs, {total} functions")

        run_async(work, lambda r: self.after(0, done, r))

    def _save_json(self):
        if not self._last_data:
            messagebox.showinfo("No data", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self._last_data, f, indent=2)
            self.status_var.set(f"\U0001F4BE Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 2: Syscall Extractor
# ══════════════════════════════════════════════════════════════════════════

class SyscallTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        _, self._get_ntdll, self.ntdll_var = make_file_picker(
            self, "ntdll.dll:", row=0,
            placeholder=EXAMPLES["ntdll"], app=app)

        btn_frm = make_button_bar(self, row=1)
        ttk.Button(btn_frm, text="\U0001F50D  Extract Syscalls", style="Accent.TButton",
                   command=self._run).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save JSON",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Select ntdll.dll to extract syscall numbers and mechanisms")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=2, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_data = None

    def _run(self):
        path = self._get_ntdll()
        if not path:
            messagebox.showwarning("No file", "Select ntdll.dll first.\n\nThis is the NT user\u2192kernel transition DLL that contains all syscall stubs.")
            return
        self.status_var.set("\u23F3 Extracting syscalls...")
        output_clear(self.output)

        def work():
            return _syscall_ext().extract_syscalls(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_data = result
            output_write(self.output, f"  SYSCALL TABLE: {os.path.basename(path)}\n", "title")
            output_write(self.output, f"  {len(result)} syscalls extracted\n\n", "ok")
            output_write(self.output,
                f"  {'#':<8} {'Hex':<10} {'Name':<48} {'Mechanism':<20} {'Raw Bytes'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*8} {'\u2500'*10} {'\u2500'*48} {'\u2500'*20} {'\u2500'*30}\n", "dim")
            for sc in result:
                mech = sc['mechanism']
                tag = None
                if 'int 0x2E' in mech:
                    tag = "ok"
                elif 'sysenter' in mech or 'KiFast' in mech:
                    tag = "peach"
                elif 'syscall' in mech:
                    tag = "warn"
                line = (f"  {sc['syscall_number']:<8} {sc['syscall_hex']:<10} "
                        f"{sc['name']:<48} {mech:<20} {sc['raw_bytes_hex']}\n")
                output_write(self.output, line, tag)
            self.status_var.set(f"\u2705 Done \u2014 {len(result)} syscalls")
            self.app.set_status(f"Syscalls: {len(result)} extracted from {os.path.basename(path)}")

        run_async(work, lambda r: self.after(0, done, r))

    def _save(self):
        if not self._last_data:
            messagebox.showinfo("No data", "Run extraction first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self._last_data, f, indent=2)
            self.status_var.set(f"\U0001F4BE Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 3: DLL Comparison
# ══════════════════════════════════════════════════════════════════════════

class CompareTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self._get_dll1, self.dll1_var = make_file_picker(
            self, "Win2000 DLL:", row=0,
            placeholder=EXAMPLES["win2k_dll"], app=app)
        _, self._get_dll2, self.dll2_var = make_file_picker(
            self, "ReactOS DLL:", row=1,
            placeholder=EXAMPLES["ros_dll"], app=app)

        # Labels
        lbl_frm = tk.Frame(self, bg=T["bg"])
        lbl_frm.grid(row=2, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(lbl_frm, text="Label A:").pack(side="left", padx=5)
        self.label1_var = tk.StringVar(value="Win2000")
        tk.Entry(lbl_frm, textvariable=self.label1_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=15).pack(side="left", padx=5)
        ttk.Label(lbl_frm, text="Label B:").pack(side="left", padx=(15, 5))
        self.label2_var = tk.StringVar(value="ReactOS")
        tk.Entry(lbl_frm, textvariable=self.label2_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=15).pack(side="left", padx=5)

        btn_frm = make_button_bar(self, row=3)
        ttk.Button(btn_frm, text="\u2194  Compare DLLs", style="Accent.TButton",
                   command=self._run).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save Report",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Compare a Win2000 DLL with its ReactOS equivalent")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_report = None

    def _run(self):
        p1, p2 = self._get_dll1(), self._get_dll2()
        if not p1 or not p2:
            messagebox.showwarning("Missing files", "Select both DLLs.\n\nExample:\n  A: C:\\WINNT\\System32\\ntdll.dll\n  B: C:\\reactos\\ntdll.dll")
            return
        l1, l2 = self.label1_var.get() or "Win2000", self.label2_var.get() or "ReactOS"
        self.status_var.set("\u23F3 Comparing...")
        output_clear(self.output)

        def work():
            is_ntdll = 'ntdll' in os.path.basename(p1).lower()
            return _comparator().full_comparison(p1, p2, l1, l2, is_ntdll=is_ntdll)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_report = result
            self._render_report(result)
            self.status_var.set("\u2705 Comparison complete")

        run_async(work, lambda r: self.after(0, done, r))

    def _render_report(self, rpt):
        l1, l2 = rpt['label1'], rpt['label2']
        output_write(self.output, f"  COMPARISON: {rpt['file1']} ({l1}) vs {rpt['file2']} ({l2})\n\n", "title")

        exp = rpt.get('export_comparison', {})
        output_write(self.output, "  \u2500\u2500 EXPORTS \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n", "heading")
        output_write(self.output, f"    {l1}: {exp.get('total_1',0)} exports\n")
        output_write(self.output, f"    {l2}: {exp.get('total_2',0)} exports\n")
        output_write(self.output, f"    Common: {exp.get('common_by_name',0)}\n", "ok")

        compat = exp.get('compatibility_pct', 0)
        tag = "ok" if compat >= 80 else ("warn" if compat >= 50 else "error")
        output_write(self.output, f"    Compatibility: {compat}%\n", tag)

        mismatches = exp.get('ordinal_mismatches', [])
        if mismatches:
            output_write(self.output, f"    Ordinal mismatches: {len(mismatches)}\n\n", "warn")
            for m in mismatches[:30]:
                ov1 = m.get(f'ordinal_{l1}', '?')
                ov2 = m.get(f'ordinal_{l2}', '?')
                output_write(self.output, f"      {m['name']}: {ov1} \u2192 {ov2}\n", "warn")
            if len(mismatches) > 30:
                output_write(self.output, f"      ... +{len(mismatches)-30} more\n", "dim")

        only1 = exp.get(f'only_in_{l1}', [])
        only2 = exp.get(f'only_in_{l2}', [])
        if only1:
            output_write(self.output, f"\n    Only in {l1} ({len(only1)} \u2014 MUST be added to {l2}):\n", "error")
            for name in only1[:40]:
                output_write(self.output, f"      \u2717 {name}\n", "error")
            if len(only1) > 40:
                output_write(self.output, f"      ... +{len(only1)-40} more\n", "dim")
        if only2:
            output_write(self.output, f"\n    Only in {l2} ({len(only2)} \u2014 extra, safe):\n", "dim")
            for name in only2[:20]:
                output_write(self.output, f"      + {name}\n", "dim")
            if len(only2) > 20:
                output_write(self.output, f"      ... +{len(only2)-20} more\n", "dim")

        imp = rpt.get('import_comparison', {})
        output_write(self.output, "\n\n  \u2500\u2500 IMPORTS \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n", "heading")
        output_write(self.output, f"    Common DLLs: {len(imp.get('common_dlls',[]))}\n", "ok")
        d1 = imp.get(f'dlls_only_in_{l1}', [])
        d2 = imp.get(f'dlls_only_in_{l2}', [])
        if d1:
            output_write(self.output, f"    DLLs only in {l1}: {', '.join(d1)}\n", "warn")
        if d2:
            output_write(self.output, f"    DLLs only in {l2}: {', '.join(d2)}\n", "dim")

        pe = rpt.get('pe_header_comparison', {})
        diffs = pe.get('differing_fields', {})
        if diffs:
            output_write(self.output, "\n\n  \u2500\u2500 PE HEADER DIFFERENCES \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n", "heading")
            for field, vals in diffs.items():
                output_write(self.output, f"    {field}: ", "warn")
                output_write(self.output, f"{vals.get(l1)} \u2192 {vals.get(l2)}\n")

        sc = rpt.get('syscall_comparison')
        if sc:
            output_write(self.output, "\n\n  \u2500\u2500 SYSCALL TABLE \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n", "heading")
            output_write(self.output, f"    Matching: {sc['matching_count']}\n", "ok")
            if sc['mismatched_count']:
                output_write(self.output, f"    Mismatched: {sc['mismatched_count']}  \u2190 NEED PATCHING\n", "error")
            output_write(self.output, f"    Only in {l1}: {sc['only_in_first_count']}\n")
            output_write(self.output, f"    Only in {l2}: {sc['only_in_second_count']}\n")
            if sc['mismatched']:
                output_write(self.output, "\n    MISMATCHED SYSCALLS:\n", "error")
                for m in sc['mismatched'][:40]:
                    output_write(self.output,
                        f"      {m['name']:<45} {m['number_first']:>4} \u2192 {m['number_second']:<4}  "
                        f"(delta: {m['delta']:+d})\n", "error")
        output_write(self.output, "\n")

    def _save(self):
        if not self._last_report:
            messagebox.showinfo("No data", "Run a comparison first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
        if path:
            _comparator().save_comparison_report(self._last_report, path)
            self.status_var.set(f"\U0001F4BE Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 4: NT Structure Viewer
# ══════════════════════════════════════════════════════════════════════════

class StructTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top = tk.Frame(self, bg=T["bg"])
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=8)

        ttk.Label(top, text="Structure:").pack(side="left", padx=5)
        self.struct_var = tk.StringVar()
        cb = ttk.Combobox(top, textvariable=self.struct_var,
                          values=_struct_analyzer().list_known_structures(), state="readonly",
                          width=32, font=("Consolas", 10))
        cb.pack(side="left", padx=5)
        if _struct_analyzer().list_known_structures():
            cb.current(0)

        ttk.Button(top, text="\U0001F9E9  View Layout", style="Accent.TButton",
                   command=self._show).pack(side="left", padx=5)
        ttk.Button(top, text="\U0001F4C4  Generate C Header",
                   command=self._gen_header).pack(side="left", padx=5)
        ttk.Button(top, text="\U0001F4E6  Export All Headers",
                   command=self._export_all).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Select an NT kernel/user structure to inspect")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _show(self):
        name = self.struct_var.get()
        if not name:
            return
        s = _struct_analyzer().get_known_structure(name)
        if not s:
            return
        output_clear(self.output)
        output_write(self.output, f"  {s['name']}  ({s['os']})\n", "title")
        output_write(self.output, f"  Size: 0x{s['size']:X} ({s['size']} bytes)\n\n", "ok")
        output_write(self.output,
            f"  {'Offset':<10} {'Size':<8} {'Name':<42} {'Type'}\n", "heading")
        output_write(self.output,
            f"  {'\u2500'*10} {'\u2500'*8} {'\u2500'*42} {'\u2500'*30}\n", "dim")
        for f in s['fields']:
            line = f"  0x{f['offset']:03X}     0x{f['size']:<5X} {f['name']:<42} {f['type']}\n"
            output_write(self.output, line)
        self.status_var.set(f"\u2705 {s['name']}: {len(s['fields'])} fields, 0x{s['size']:X} bytes")

    def _gen_header(self):
        name = self.struct_var.get()
        if not name:
            return
        s = _struct_analyzer().get_known_structure(name)
        if not s:
            return
        output_clear(self.output)
        header = _struct_analyzer().generate_c_header(s)
        output_write(self.output, header)
        self.status_var.set(f"\u2705 Generated C header for {name}")

    def _export_all(self):
        d = filedialog.askdirectory(title="Select output directory for .h files")
        if d:
            files = _struct_analyzer().save_all_headers(d)
            self.status_var.set(f"\U0001F4BE Exported {len(files)} header files to {d}")
            messagebox.showinfo("Done", f"Generated {len(files)} header files:\n" +
                                "\n".join(os.path.basename(f) for f in files))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 5: PE Header / Directory Scanner
# ══════════════════════════════════════════════════════════════════════════

class PEHeaderTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        _, self._get_file, self.file_var = make_file_picker(
            self, "PE File:", row=0,
            placeholder=EXAMPLES["pe"], app=app)
        _, self._get_dir, self.dir_var = make_dir_picker(
            self, "Scan Directory:", row=1,
            placeholder=EXAMPLES["scan_dir"], app=app)

        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F4CB  Analyze PE Header", style="Accent.TButton",
                   command=self._run_header).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F50D  Scan Directory", style="Accent.TButton",
                   command=self._run_scan).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Analyze any PE file header or scan a System32 directory")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=3, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _run_header(self):
        path = self._get_file()
        if not path:
            messagebox.showwarning("No file", "Select a PE file.\n\nSupported: .dll .sys .exe .cpl .drv .ocx .scr")
            return
        self.status_var.set("\u23F3 Analyzing...")
        output_clear(self.output)

        def work():
            return _pe_analyzer().analyze_pe_header(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, f"  PE HEADER: {os.path.basename(path)}\n\n", "title")
            for key, val in result.items():
                if key == 'sections':
                    continue
                output_write(self.output, f"  {key:<36} ", "dim")
                output_write(self.output, f"{val}\n")
            output_write(self.output, "\n  SECTIONS:\n", "heading")
            output_write(self.output,
                f"  {'Name':<10} {'VAddr':<12} {'VSize':<12} {'RawSize':<12} {'Characteristics'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*10} {'\u2500'*12} {'\u2500'*12} {'\u2500'*12} {'\u2500'*16}\n", "dim")
            for sec in result.get('sections', []):
                output_write(self.output,
                    f"  {sec['name']:<10} {sec['virtual_address']:<12} "
                    f"{sec['virtual_size']:<12} {sec['raw_size']:<12} "
                    f"{sec['characteristics']}\n")
            self.status_var.set("\u2705 Done")

        run_async(work, lambda r: self.after(0, done, r))

    def _run_scan(self):
        d = self._get_dir()
        if not d:
            messagebox.showwarning("No directory", "Select a directory to scan.\n\nExample: C:\\WINNT\\System32")
            return
        self.status_var.set("\u23F3 Scanning...")
        output_clear(self.output)

        import glob as gl

        def work():
            files = []
            for ext in ('*.dll', '*.sys', '*.exe'):
                files.extend(gl.glob(os.path.join(d, ext)))
            return files

        def done(files):
            if isinstance(files, Exception):
                self.status_var.set(f"\u274C Error: {files}")
                return
            output_write(self.output, f"  SCAN: {d}  ({len(files)} PE files)\n\n", "title")
            key_files = {'ntdll.dll', 'kernel32.dll', 'shell32.dll', 'user32.dll',
                         'gdi32.dll', 'advapi32.dll', 'ntoskrnl.exe', 'win32k.sys',
                         'ole32.dll', 'rpcrt4.dll', 'msvcrt.dll'}
            output_write(self.output,
                f"  {'File':<28} {'Exports':<10} {'Import DLLs':<14} {'ImageBase':<16} {'Sections'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*28} {'\u2500'*10} {'\u2500'*14} {'\u2500'*16} {'\u2500'*8}\n", "dim")
            count = 0
            for fp in sorted(files):
                bn = os.path.basename(fp).lower()
                if bn not in key_files:
                    continue
                try:
                    exp = _pe_analyzer().analyze_exports(fp)
                    imp = _pe_analyzer().analyze_imports(fp)
                    hdr = _pe_analyzer().analyze_pe_header(fp)
                    line = (f"  {bn:<28} {exp['total_exports']:<10} {len(imp):<14} "
                            f"{hdr['image_base']:<16} {hdr['number_of_sections']}\n")
                    tag = "ok" if bn in ('ntdll.dll', 'kernel32.dll', 'win32k.sys') else None
                    output_write(self.output, line, tag)
                    count += 1
                except Exception as e:
                    output_write(self.output, f"  {bn:<28} ERROR: {e}\n", "error")
            self.status_var.set(f"\u2705 Scanned {count} key files out of {len(files)} total")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 6: DEF File Generator
# ══════════════════════════════════════════════════════════════════════════

class DefGenTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        _, self._get_dll, self.dll_var = make_file_picker(
            self, "Win2000 DLL:", row=0,
            placeholder=EXAMPLES["win2k_dll"], app=app)
        _, self._get_ros, self.ros_def_var = make_file_picker(
            self, "ReactOS .def:", row=1,
            placeholder=EXAMPLES["def_file"], app=app)

        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F4C4  Generate .def", style="Accent.TButton",
                   command=self._gen_def).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2194  Compare with ReactOS .def",
                   command=self._compare_def).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save .def",
                   command=self._save_def).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Generate .def files from Win2000 DLLs for ReactOS builds")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=3, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_def = None

    def _gen_def(self):
        path = self._get_dll()
        if not path:
            messagebox.showwarning("No file", "Select a Win2000 DLL first.\n\nExample: kernel32.dll, ntdll.dll")
            return
        self.status_var.set("\u23F3 Generating .def...")
        output_clear(self.output)

        def work():
            return _def_generator().generate_def_file(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_def = result
            lines = result.split('\n')
            for line in lines:
                if line.startswith(';') or line.startswith('LIBRARY') or line.startswith('EXPORTS'):
                    output_write(self.output, line + '\n', "heading")
                elif '@' in line:
                    output_write(self.output, line + '\n', "ok")
                else:
                    output_write(self.output, line + '\n')
            export_count = sum(1 for l in lines if l.strip() and not l.startswith(';')
                               and not l.startswith('LIBRARY') and not l.startswith('EXPORTS'))
            self.status_var.set(f"\u2705 Generated .def with {export_count} entries")

        run_async(work, lambda r: self.after(0, done, r))

    def _compare_def(self):
        dll_path = self._get_dll()
        ros_path = self._get_ros()
        if not dll_path or not ros_path:
            messagebox.showwarning("Missing", "Select both Win2000 DLL and ReactOS .def file.")
            return
        self.status_var.set("\u23F3 Comparing...")
        output_clear(self.output)

        def work():
            return _def_generator().compare_def_with_reactos(dll_path, ros_path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  DEF COMPARISON\n\n", "title")
            output_write(self.output, f"  Missing from ReactOS ({len(result['missing_in_reactos'])}):\n", "error")
            for name in result['missing_in_reactos'][:50]:
                output_write(self.output, f"    - {name}\n", "error")
            output_write(self.output, f"\n  Extra in ReactOS ({len(result['extra_in_reactos'])}):\n", "dim")
            for name in result['extra_in_reactos'][:50]:
                output_write(self.output, f"    + {name}\n", "dim")
            output_write(self.output, f"\n  Ordinal mismatches ({len(result['ordinal_mismatches'])}):\n", "warn")
            for m in result['ordinal_mismatches'][:30]:
                output_write(self.output, f"    {m['name']}: Win2K={m['win2k_ordinal']} ROS={m['reactos_ordinal']}\n", "warn")
            self.status_var.set("\u2705 Comparison done")

        run_async(work, lambda r: self.after(0, done, r))

    def _save_def(self):
        if not self._last_def:
            messagebox.showinfo("No data", "Generate a .def first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".def",
                                             filetypes=[("DEF Files", "*.def"), ("All", "*.*")])
        if path:
            with open(path, 'w') as f:
                f.write(self._last_def)
            self.status_var.set(f"\U0001F4BE Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 7: Syscall Patcher
# ══════════════════════════════════════════════════════════════════════════

class SyscallPatchTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        _, self._get_ntdll, self.ntdll_var = make_file_picker(
            self, "ntdll.dll:", row=0,
            placeholder=EXAMPLES["ntdll"], app=app)

        opt_frm = tk.Frame(self, bg=T["bg"])
        opt_frm.grid(row=1, column=0, sticky="w", padx=12, pady=5)
        ttk.Label(opt_frm, text="Header Style:").pack(side="left", padx=5)
        self.style_var = tk.StringVar(value="napi")
        for val, text in [("napi", "NAPI (#define)"), ("define", "SYS_ defines"),
                          ("asm", "MASM .asm"), ("table", "C Array")]:
            ttk.Radiobutton(opt_frm, text=text, variable=self.style_var, value=val).pack(side="left", padx=8)

        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F527  Generate Header", style="Accent.TButton",
                   command=self._gen).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save Header",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Generate syscall number headers from ntdll.dll for use in drivers/tools")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=3, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_header = None

    def _gen(self):
        path = self._get_ntdll()
        if not path:
            messagebox.showwarning("No file", "Select ntdll.dll first.\n\nThis extracts syscall numbers to generate C/ASM headers.")
            return
        style = self.style_var.get()
        self.status_var.set(f"\u23F3 Generating {style} header...")
        output_clear(self.output)

        def work():
            return _sc_patcher().generate_syscall_header(path, style=style)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_header = result
            for line in result.split('\n'):
                if line.startswith('//') or line.startswith(';') or line.startswith('#ifndef'):
                    output_write(self.output, line + '\n', "dim")
                elif '#define' in line:
                    output_write(self.output, line + '\n', "ok")
                elif line.strip().startswith('{'):
                    output_write(self.output, line + '\n', "peach")
                else:
                    output_write(self.output, line + '\n')
            self.status_var.set("\u2705 Header generated")

        run_async(work, lambda r: self.after(0, done, r))

    def _save(self):
        if not self._last_header:
            messagebox.showinfo("No data", "Generate a header first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".h",
                                             filetypes=[("Header Files", "*.h;*.inc;*.asm"), ("All", "*.*")])
        if path:
            with open(path, 'w') as f:
                f.write(self._last_header)
            self.status_var.set(f"\U0001F4BE Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 8: ReactOS Source Patcher
# ══════════════════════════════════════════════════════════════════════════

class ROSPatchTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self._get_ros, self.ros_dir = make_dir_picker(
            self, "ReactOS Source:", row=0,
            placeholder=EXAMPLES["ros_dir"], app=app)
        _, self._get_ntdll, self.ntdll_var = make_file_picker(
            self, "Win2K ntdll:", row=1,
            placeholder=EXAMPLES["ntdll"], app=app)

        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F50D  Scan Issues", style="Accent.TButton",
                   command=self._scan).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F3AF  Patch WinVer Target",
                   command=lambda: self._run_patch('winver')).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F527  Patch Syscall Mechanism",
                   command=lambda: self._run_patch('syscall')).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2699  Patch All",
                   command=lambda: self._run_patch('all')).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        chk_frm = tk.Frame(self, bg=T["bg"])
        chk_frm.grid(row=3, column=0, sticky="w", padx=12, pady=3)
        self.dryrun_var = tk.BooleanVar(value=True)
        tk.Checkbutton(chk_frm, text="  Dry run (preview only, don't modify files)",
                        variable=self.dryrun_var,
                        bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"],
                        activebackground=T["bg"], activeforeground=T["fg"],
                        font=("Segoe UI", 10)).pack(side="left")

        self.status_var = tk.StringVar(value="\u2022 Patch ReactOS C source for Win2000 compatibility")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _scan(self):
        ros_path = self._get_ros()
        if not ros_path:
            messagebox.showwarning("Missing", "Select ReactOS source directory.\n\nExample: C:\\reactos")
            return
        self.status_var.set("\u23F3 Scanning for Win2K compatibility issues...")
        output_clear(self.output)

        def work():
            patcher = _ros_patcher().ReactOSPatcher(ros_path)
            return patcher.scan_issues()

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  REACTOS WIN2K COMPATIBILITY SCAN\n\n", "title")
            total = 0
            for category, issues in result.items():
                if issues:
                    output_write(self.output, f"  [{category}] ({len(issues)} issues)\n", "heading")
                    for issue in issues[:30]:
                        output_write(self.output, f"    {issue}\n", "warn")
                    if len(issues) > 30:
                        output_write(self.output, f"    ... +{len(issues)-30} more\n", "dim")
                    output_write(self.output, "\n")
                    total += len(issues)
            if total == 0:
                output_write(self.output, "  No issues found!\n", "ok")
            self.status_var.set(f"\u2705 Scan complete: {total} issues found")

        run_async(work, lambda r: self.after(0, done, r))

    def _run_patch(self, mode):
        ros_path = self._get_ros()
        if not ros_path:
            messagebox.showwarning("Missing", "Select ReactOS source directory.")
            return
        ntdll_path = self._get_ntdll() or None
        dry = self.dryrun_var.get()
        self.status_var.set(f"\u23F3 Patching ({mode}){'  [DRY RUN]' if dry else ''}...")
        output_clear(self.output)

        def work():
            patcher = _ros_patcher().ReactOSPatcher(ros_path, ntdll_path)
            if mode == 'winver':
                return patcher.patch_winver_target(dry_run=dry)
            elif mode == 'syscall':
                return patcher.patch_syscall_mechanism(dry_run=dry)
            elif mode == 'all':
                return patcher.run_all_patches(dry_run=dry)
            return {}

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            dry_label = " [DRY RUN]" if dry else ""
            output_write(self.output, f"  PATCH RESULTS{dry_label}\n\n", "title")
            if isinstance(result, dict):
                for step, details in result.items():
                    output_write(self.output, f"  [{step}]\n", "heading")
                    if isinstance(details, list):
                        for d in details[:50]:
                            output_write(self.output, f"    {d}\n", "ok")
                    elif isinstance(details, dict):
                        for k, v in details.items():
                            output_write(self.output, f"    {k}: {v}\n")
                    else:
                        output_write(self.output, f"    {details}\n")
                    output_write(self.output, "\n")
            else:
                output_write(self.output, f"  {result}\n")
            self.status_var.set(f"\u2705 Patch complete{dry_label}")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 9: Build Script Generator
# ══════════════════════════════════════════════════════════════════════════

class BuildGenTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self._get_ros, self.ros_dir = make_dir_picker(
            self, "ReactOS Source:", row=0,
            placeholder=EXAMPLES["ros_dir"], app=app)

        tgt_frm = tk.Frame(self, bg=T["bg"])
        tgt_frm.grid(row=1, column=0, sticky="ew", padx=12, pady=5)
        ttk.Label(tgt_frm, text="Targets:").pack(side="left", padx=5)
        self.target_vars = {}
        for name in _build_gen().BUILD_TARGETS:
            var = tk.BooleanVar(value=(name in ('ntdll.dll', 'kernel32.dll', 'shell32.dll', 'win32k.sys')))
            ttk.Checkbutton(tgt_frm, text=name.replace('.dll','').replace('.sys','').replace('.exe',''),
                            variable=var).pack(side="left", padx=4)
            self.target_vars[name] = var

        bld_frm = tk.Frame(self, bg=T["bg"])
        bld_frm.grid(row=2, column=0, sticky="w", padx=12, pady=5)
        ttk.Label(bld_frm, text="Build System:").pack(side="left", padx=5)
        self.build_var = tk.StringVar(value="rosbe")
        for val, text in [("rosbe", "RosBE + Ninja"), ("msvc", "MSVC + NMake"), ("cmake", "Standalone CMake")]:
            ttk.Radiobutton(bld_frm, text=text, variable=self.build_var, value=val).pack(side="left", padx=8)

        btn_frm = make_button_bar(self, row=3)
        ttk.Button(btn_frm, text="\u2699  Generate Script", style="Accent.TButton",
                   command=self._gen).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save Script",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Generate build scripts for compiling ReactOS DLLs targeting Win2000")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_script = None

    def _get_targets(self):
        return [name for name, var in self.target_vars.items() if var.get()]

    def _gen(self):
        ros = self._get_ros()
        if not ros:
            messagebox.showwarning("Missing", "Select ReactOS source directory.")
            return
        targets = self._get_targets()
        if not targets:
            messagebox.showwarning("No targets", "Select at least one build target.")
            return
        build = self.build_var.get()
        output_clear(self.output)

        if build == 'rosbe':
            script = _build_gen().generate_rosbe_script(ros, targets)
        elif build == 'msvc':
            script = _build_gen().generate_msvc_script(ros, targets)
        else:
            script = _build_gen().generate_individual_dll_cmake(targets[0], ros)

        self._last_script = script
        for line in script.split('\n'):
            if line.strip().startswith('REM') or line.strip().startswith('#') or line.strip().startswith(';'):
                output_write(self.output, line + '\n', "dim")
            elif 'echo' in line.lower() or 'cmake' in line.lower():
                output_write(self.output, line + '\n', "heading")
            elif 'ERROR' in line or 'failed' in line:
                output_write(self.output, line + '\n', "error")
            elif 'ninja' in line.lower() or 'nmake' in line.lower():
                output_write(self.output, line + '\n', "ok")
            else:
                output_write(self.output, line + '\n')
        self.status_var.set(f"\u2705 Generated {build} script for {len(targets)} targets")

    def _save(self):
        if not self._last_script:
            messagebox.showinfo("No data", "Generate a script first.")
            return
        ext = ".bat" if self.build_var.get() in ('rosbe', 'msvc') else ".cmake"
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("Batch Files", "*.bat"), ("CMake", "*.cmake;CMakeLists.txt"), ("All", "*.*")])
        if path:
            with open(path, 'w') as f:
                f.write(self._last_script)
            self.status_var.set(f"\U0001F4BE Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 10: Function Behavior Analyzer
# ══════════════════════════════════════════════════════════════════════════

class BehaviorTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(6, weight=1)

        _, self._get_a, self.dll_a_var = make_file_picker(
            self, "DLL A (Win2K):", row=0,
            placeholder=EXAMPLES["win2k_dll"], app=app)
        _, self._get_b, self.dll_b_var = make_file_picker(
            self, "DLL B (ReactOS):", row=1,
            placeholder=EXAMPLES["ros_dll"], app=app)

        func_frm = tk.Frame(self, bg=T["bg"])
        func_frm.grid(row=2, column=0, sticky="ew", padx=12, pady=5)
        func_frm.columnconfigure(1, weight=1)
        ttk.Label(func_frm, text="Function:", width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))
        self.func_var = tk.StringVar()
        ent = PlaceholderEntry(func_frm, placeholder="e.g.  NtCreateFile, RtlInitUnicodeString",
                               textvariable=self.func_var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        ent.grid(row=0, column=1, sticky="ew")
        app.register_placeholder(ent)
        self._func_entry = ent

        btn_frm = make_button_bar(self, row=3)
        ttk.Button(btn_frm, text="\U0001F4BB  Disassemble", style="Accent.TButton",
                   command=self._disasm).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2194  Compare Function",
                   command=self._compare_one).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CA  Batch Compare",
                   command=self._batch).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F9EC  Detect Patterns",
                   command=self._patterns).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F50D  Scan All",
                   command=self._scan_all).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        lim_frm = tk.Frame(self, bg=T["bg"])
        lim_frm.grid(row=4, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(lim_frm, text="Max functions (batch):").pack(side="left", padx=5)
        self.max_var = tk.StringVar(value="100")
        tk.Entry(lim_frm, textvariable=self.max_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=8).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Compare function behavior between Win2000 and ReactOS binaries")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=5, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=6, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _get_func(self):
        return self._func_entry.get_value()

    def _disasm(self):
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.\n\nExample: NtCreateFile")
            return
        self.status_var.set(f"\u23F3 Disassembling {func}...")
        output_clear(self.output)

        def work():
            return _behavior().disassemble_function(path, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found in the DLL exports.\n", "error")
                self.status_var.set("\u274C Function not found")
                return
            for line in result.split('\n'):
                if line.startswith(';'):
                    output_write(self.output, line + '\n', "dim")
                elif '; \u2192' in line:
                    output_write(self.output, line + '\n', "peach")
                elif 'call' in line or 'int' in line:
                    output_write(self.output, line + '\n', "ok")
                elif 'ret' in line or 'retn' in line:
                    output_write(self.output, line + '\n', "warn")
                else:
                    output_write(self.output, line + '\n')
            self.status_var.set(f"\u2705 Disassembly of {func} complete")

        run_async(work, lambda r: self.after(0, done, r))

    def _compare_one(self):
        pa = self._get_a()
        pb = self._get_b()
        func = self._get_func()
        if not pa or not pb or not func:
            messagebox.showwarning("Missing", "Select both DLLs and enter a function name.")
            return
        self.status_var.set(f"\u23F3 Comparing {func}...")
        output_clear(self.output)

        def work():
            return _behavior().compare_functions(pa, pb, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  FUNCTION COMPARISON\n\n", "title")
            for line in result.summary().split('\n'):
                if 'Similarity' in line:
                    pct = result.similarity
                    tag = "ok" if pct >= 80 else ("warn" if pct >= 50 else "error")
                    output_write(self.output, f"  {line}\n", tag)
                elif 'MISMATCH' in line:
                    output_write(self.output, f"  {line}\n", "error")
                elif 'MATCH' in line:
                    output_write(self.output, f"  {line}\n", "ok")
                elif 'only in' in line.lower():
                    output_write(self.output, f"  {line}\n", "warn")
                else:
                    output_write(self.output, f"  {line}\n")
            self.status_var.set(f"\u2705 Comparison: {result.similarity:.1f}% similar")

        run_async(work, lambda r: self.after(0, done, r))

    def _batch(self):
        pa = self._get_a()
        pb = self._get_b()
        if not pa or not pb:
            messagebox.showwarning("Missing", "Select both DLLs.")
            return
        try:
            max_funcs = int(self.max_var.get())
        except ValueError:
            max_funcs = 100
        self.status_var.set("\u23F3 Batch comparing all shared exports...")
        output_clear(self.output)

        def work():
            results = _behavior().batch_compare(pa, pb)
            return results[:max_funcs]

        def done(results):
            if isinstance(results, Exception):
                self.status_var.set(f"\u274C Error: {results}")
                output_write(self.output, f"ERROR: {results}\n", "error")
                return
            output_write(self.output, "  BATCH FUNCTION COMPARISON\n\n", "title")
            output_write(self.output,
                f"  {'Function':<48} {'Sim%':<8} {'Blocks A':<10} {'Blocks B':<10} {'Notes'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*48} {'\u2500'*8} {'\u2500'*10} {'\u2500'*10} {'\u2500'*20}\n", "dim")
            for r in results:
                pct = r.similarity
                tag = "ok" if pct >= 80 else ("warn" if pct >= 50 else "error")
                ba = r.fp_a.block_count if r.fp_a else 0
                bb = r.fp_b.block_count if r.fp_b else 0
                notes = ""
                if r.syscall_match is True:
                    notes = "syscall OK"
                elif r.syscall_match is False:
                    notes = "SYSCALL MISMATCH"
                elif r.fp_a and r.fp_a.syscall_number is not None:
                    notes = f"stub 0x{r.fp_a.syscall_number:X}"
                line = f"  {r.func_name:<48} {pct:>6.1f}% {ba:<10} {bb:<10} {notes}\n"
                output_write(self.output, line, tag)
            self.status_var.set(f"\u2705 Compared {len(results)} functions")

        run_async(work, lambda r: self.after(0, done, r))

    def _patterns(self):
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return
        self.status_var.set(f"\u23F3 Detecting patterns for {func}...")
        output_clear(self.output)

        def work():
            return _behavior().detect_api_patterns(path, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("\u274C Not found")
                return
            output_write(self.output, f"  BEHAVIOR PATTERNS: {func}\n\n", "title")
            fp = result['fingerprint']
            output_write(self.output, f"  Instructions: {fp.total_insns}\n")
            output_write(self.output, f"  Basic blocks: {fp.block_count}\n")
            if fp.syscall_number is not None:
                output_write(self.output, f"  Syscall: 0x{fp.syscall_number:X}\n", "ok")
            output_write(self.output, f"\n  Detected patterns:\n\n", "heading")
            for ptype, pdesc in result['patterns']:
                color = {"syscall_stub": "ok", "forwarder": "peach", "api_wrapper": "peach",
                         "complex": "warn", "memory_allocator": "warn", "registry": "warn",
                         "file_io": "warn", "process_thread": "error"}.get(ptype, None)
                output_write(self.output, f"    [{ptype}] ", "heading")
                output_write(self.output, f"{pdesc}\n", color)
            if fp.api_calls:
                output_write(self.output, f"\n  API calls ({len(fp.api_calls)}):\n", "heading")
                for call in fp.api_calls:
                    output_write(self.output, f"    \u2192 {call}\n", "peach")
            self.status_var.set(f"\u2705 Pattern analysis complete for {func}")

        run_async(work, lambda r: self.after(0, done, r))

    def _scan_all(self):
        path = self._get_a()
        if not path:
            messagebox.showwarning("Missing", "Select DLL A.")
            return
        try:
            max_funcs = int(self.max_var.get())
        except ValueError:
            max_funcs = 100
        self.status_var.set("\u23F3 Scanning all exports for behavior patterns...")
        output_clear(self.output)

        def work():
            return _behavior().scan_all_exports(path, max_funcs)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  EXPORT BEHAVIOR SCAN\n\n", "title")
            total = 0
            for category, funcs in sorted(result.items(), key=lambda x: -len(x[1])):
                output_write(self.output, f"  [{category}] \u2014 {len(funcs)} functions\n", "heading")
                for fname, fdesc in funcs[:20]:
                    output_write(self.output, f"    {fname:<48} {fdesc}\n")
                if len(funcs) > 20:
                    output_write(self.output, f"    ... +{len(funcs)-20} more\n", "dim")
                output_write(self.output, "\n")
                total += len(funcs)
            self.status_var.set(f"\u2705 Scanned: {total} functions in {len(result)} categories")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 11: Decompiler
# ══════════════════════════════════════════════════════════════════════════

class DecompilerTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self._get_pe, self.pe_var = make_file_picker(
            self, "PE File:", row=0,
            placeholder=EXAMPLES["pe"], app=app)

        func_frm = tk.Frame(self, bg=T["bg"])
        func_frm.grid(row=1, column=0, sticky="ew", padx=12, pady=5)
        func_frm.columnconfigure(1, weight=1)
        ttk.Label(func_frm, text="Function/RVA:", width=16, anchor="e").grid(
            row=0, column=0, padx=(0, 8))
        self.func_var = tk.StringVar()
        ent = PlaceholderEntry(func_frm, placeholder="e.g.  NtCreateFile  or  0x0004AE10",
                               textvariable=self.func_var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        ent.grid(row=0, column=1, sticky="ew")
        app.register_placeholder(ent)
        self._func_entry = ent

        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F4BB  Decompile Export", style="Accent.TButton",
                   command=self._decompile_one).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F50D  Discover Functions",
                   command=self._discover).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CA  Batch Decompile",
                   command=self._batch).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save Output",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        lim_frm = tk.Frame(self, bg=T["bg"])
        lim_frm.grid(row=3, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(lim_frm, text="Max functions:").pack(side="left", padx=5)
        self.max_var = tk.StringVar(value="50")
        tk.Entry(lim_frm, textvariable=self.max_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=8).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Decompile PE exports to C pseudocode \u2014 recognizes kernel APIs, NTSTATUS, IRP codes")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _get_func(self):
        return self._func_entry.get_value()

    def _decompile_one(self):
        path = self._get_pe()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select a PE file and enter a function name or RVA.\n\nExamples:\n  NtCreateFile\n  0x0004AE10")
            return
        self.status_var.set(f"\u23F3 Decompiling {func}...")
        output_clear(self.output)

        if func.startswith('0x') or func.startswith('0X'):
            func_val = int(func, 16)
        else:
            func_val = func

        def work():
            return _decompiler().decompile(path, func_val)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("\u274C Not found")
                return
            self._colorize(result)
            self.status_var.set(f"\u2705 Decompiled {func}")

        run_async(work, lambda r: self.after(0, done, r))

    def _discover(self):
        path = self._get_pe()
        if not path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        try:
            mx = int(self.max_var.get())
        except ValueError:
            mx = 50
        self.status_var.set(f"\u23F3 Discovering functions (max {mx})...")
        output_clear(self.output)

        def work():
            return _decompiler().decompile_no_symbols(path, max_funcs=mx)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            for name, code in result.items():
                output_write(self.output, f"{'='*70}\n", "dim")
                self._colorize(code)
                output_write(self.output, "\n")
            self.status_var.set(f"\u2705 Discovered {len(result)} functions")

        run_async(work, lambda r: self.after(0, done, r))

    def _batch(self):
        path = self._get_pe()
        if not path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        try:
            mx = int(self.max_var.get())
        except ValueError:
            mx = 100
        self.status_var.set(f"\u23F3 Batch decompiling exports (max {mx})...")
        output_clear(self.output)

        def work():
            return _decompiler().batch_decompile(path, max_funcs=mx)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            for name, code in result.items():
                output_write(self.output, f"{'='*70}\n", "dim")
                self._colorize(code)
                output_write(self.output, "\n")
            self.status_var.set(f"\u2705 Decompiled {len(result)} exports")

        run_async(work, lambda r: self.after(0, done, r))

    def _save(self):
        content = self.output.get("1.0", "end-1c")
        if not content.strip():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".c",
            filetypes=[("C Source", "*.c"), ("Text", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, 'w') as f:
                f.write(content)
            self.status_var.set(f"\U0001F4BE Saved to {path}")

    def _colorize(self, code):
        for line in code.split('\n'):
            stripped = line.lstrip()
            if stripped.startswith('/*') or stripped.startswith(' *') or stripped.startswith('*/'):
                output_write(self.output, line + '\n', "dim")
            elif stripped.startswith('//'):
                output_write(self.output, line + '\n', "dim")
            elif stripped.startswith('if ') or stripped.startswith('while ') or stripped.startswith('goto ') or stripped == 'continue;':
                output_write(self.output, line + '\n', "peach")
            elif 'return ' in stripped:
                output_write(self.output, line + '\n', "warn")
            elif '= ' in stripped and ('(' in stripped or 'sub_' in stripped or 'loc_' in stripped):
                output_write(self.output, line + '\n', "ok")
            elif stripped.startswith('loc_') and stripped.endswith(':'):
                output_write(self.output, line + '\n', "heading")
            elif stripped.startswith('NTSTATUS') or stripped.startswith('PVOID') or stripped.startswith('VOID'):
                output_write(self.output, line + '\n', "ok")
            else:
                output_write(self.output, line + '\n')


# ══════════════════════════════════════════════════════════════════════════
#  Tab 12: Compat Analyzer
# ══════════════════════════════════════════════════════════════════════════

class CompatAnalyzerTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self._get_a, self.pe_a_var = make_file_picker(
            self, "PE File A:", row=0,
            placeholder="e.g.  C:\\WINNT\\System32\\ntdll.dll  (Win2000 original)", app=app)
        _, self._get_b, self.pe_b_var = make_file_picker(
            self, "PE File B:", row=1,
            placeholder="e.g.  C:\\reactos\\ntdll.dll  (ReactOS / XP replacement)", app=app)

        label_frm = tk.Frame(self, bg=T["bg"])
        label_frm.grid(row=2, column=0, sticky="ew", padx=12, pady=5)
        label_frm.columnconfigure(1, weight=1)
        label_frm.columnconfigure(3, weight=1)
        ttk.Label(label_frm, text="Label A:", width=10, anchor="e").grid(row=0, column=0, padx=(0, 5))
        self.label_a_var = tk.StringVar(value="Win2000")
        tk.Entry(label_frm, textvariable=self.label_a_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat", bd=5).grid(
            row=0, column=1, sticky="ew", padx=(0, 15))
        ttk.Label(label_frm, text="Label B:", width=10, anchor="e").grid(row=0, column=2, padx=(0, 5))
        self.label_b_var = tk.StringVar(value="ReactOS/XP")
        tk.Entry(label_frm, textvariable=self.label_b_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat", bd=5).grid(
            row=0, column=3, sticky="ew")

        btn_frm = make_button_bar(self, row=3)
        ttk.Button(btn_frm, text="\u26A0  Full Compat Analysis", style="Accent.TButton",
                   command=self._analyze_both).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F50D  Analyze Single PE",
                   command=self._analyze_single).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4D6  Known Differences",
                   command=self._show_known).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F6A8  Bugcheck Lookup",
                   command=self._bugcheck).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save Report",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 Deep NT version compatibility analysis \u2014 detects syscall, calling convention, and structure differences")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _analyze_both(self):
        pa, pb = self._get_a(), self._get_b()
        if not pa or not pb:
            messagebox.showwarning("Missing", "Select both PE files.\n\nExample:\n  A: ntdll.dll (Win2000)\n  B: ntdll.dll (ReactOS)")
            return
        la, lb = self.label_a_var.get(), self.label_b_var.get()
        self.status_var.set("\u23F3 Analyzing compatibility...")
        output_clear(self.output)

        def work():
            return _compat().compare_compat(pa, pb, la, lb)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            report = result
            self._colorize_report(report.summary())
            critical = sum(1 for i in report.issues if i.severity == "critical")
            warnings = sum(1 for i in report.issues if i.severity == "warning")
            self.status_var.set(f"\u2705 Done: {critical} critical, {warnings} warnings")

        run_async(work, lambda r: self.after(0, done, r))

    def _analyze_single(self):
        pa = self._get_a()
        if not pa:
            messagebox.showwarning("Missing", "Select PE File A.")
            return
        la = self.label_a_var.get()
        self.status_var.set("\u23F3 Analyzing single PE...")
        output_clear(self.output)

        def work():
            return _compat().analyze_single_pe(pa, la)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            r = result
            output_write(self.output, f"PE: {os.path.basename(pa)}\n", "title")
            output_write(self.output, f"Type: {r['type']}\n")
            output_write(self.output, f"Machine: 0x{r['machine']:04X}\n")
            output_write(self.output, f"Image Base: 0x{r['image_base']:08X}\n")
            sc = r.get('syscall', {})
            if sc:
                output_write(self.output, f"Syscall: {sc.get('mechanism', 'N/A')}\n", "ok")
                output_write(self.output, f"  int 0x2E: {sc.get('int_2e', 0)}, sysenter: {sc.get('sysenter', 0)}\n")
            convs = r.get('conventions', {})
            if convs:
                fc = sum(1 for c in convs.values() if c.convention == 'fastcall')
                sc_cnt = sum(1 for c in convs.values() if c.convention == 'stdcall')
                output_write(self.output, f"Conventions: {sc_cnt} stdcall, {fc} fastcall\n", "ok")
                for name, c in sorted(convs.items()):
                    if c.convention == 'fastcall':
                        output_write(self.output, f"  FASTCALL: {name} ({c.param_count} params)\n", "warn")
            output_write(self.output, f"\nSections:\n", "heading")
            for s in r.get('sections', []):
                output_write(self.output, f"  {s['name']:<10} vsize=0x{s['vsize']:X}  raw=0x{s['rsize']:X}\n")
            self.status_var.set("\u2705 Done")

        run_async(work, lambda r: self.after(0, done, r))

    def _show_known(self):
        output_clear(self.output)
        diffs = _compat().get_known_differences()
        output_write(self.output, "KNOWN NT 5.0 \u2192 5.1 DIFFERENCES\n", "title")
        output_write(self.output, "\n\u2500\u2500 Calling Convention Changes \u2500\u2500\n", "heading")
        for name, info in diffs['calling_convention_changes'].items():
            output_write(self.output, f"  {name}: {info['from']} \u2192 {info['to']}\n", "warn")
        output_write(self.output, "\n\u2500\u2500 HAL Dispatch Removed Defines \u2500\u2500\n", "heading")
        for name, routing in diffs['hal_dispatch_removed_defines'].items():
            output_write(self.output, f"  {name}: routed through {routing}\n", "error")
        output_write(self.output, "\n\u2500\u2500 Macro Differences \u2500\u2500\n", "heading")
        for name, info in diffs['macro_differences'].items():
            output_write(self.output, f"  {name}: {info['desc']}\n", "peach")
        output_write(self.output, "\n\u2500\u2500 HAL Functions Removed in XP \u2500\u2500\n", "heading")
        for name in diffs['hal_functions_removed']:
            output_write(self.output, f"  {name}\n", "error")
        output_write(self.output, "\n\u2500\u2500 Bugcheck Codes \u2500\u2500\n", "heading")
        for code, info in diffs['compat_bugchecks'].items():
            output_write(self.output, f"  0x{code:08X} {info['name']}\n", "warn")
            output_write(self.output, f"    {info['compat_hint']}\n", "dim")
        self.status_var.set("\u2705 Showing known differences")

    def _bugcheck(self):
        from tkinter.simpledialog import askstring
        code = askstring("Bugcheck Lookup", "Enter bugcheck code (hex):\n\nExample: 0xA5, 0x7F, 0x0A", parent=self)
        if not code:
            return
        output_clear(self.output)
        result = _compat().diagnose_bugcheck(code)
        output_write(self.output, f"Bugcheck: {result['code']}\n", "title")
        output_write(self.output, f"Name: {result.get('name', 'Unknown')}\n", "warn")
        if 'description' in result:
            output_write(self.output, f"Description: {result['description']}\n")
        output_write(self.output, f"Compat hint: {result['compat_hint']}\n", "ok")
        if 'known_causes' in result:
            output_write(self.output, "\nKnown causes:\n", "heading")
            for cause in result['known_causes']:
                output_write(self.output, f"  - {cause}\n")
        self.status_var.set(f"\u2705 Bugcheck {result['code']} lookup done")

    def _save(self):
        content = self.output.get("1.0", "end-1c")
        if not content.strip():
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, 'w') as f:
                f.write(content)
            self.status_var.set(f"\U0001F4BE Saved to {path}")

    def _colorize_report(self, text):
        for line in text.split('\n'):
            stripped = line.strip()
            if stripped.startswith('[CRITICAL]'):
                output_write(self.output, line + '\n', "error")
            elif stripped.startswith('[WARNING]'):
                output_write(self.output, line + '\n', "warn")
            elif stripped.startswith('[info]'):
                output_write(self.output, line + '\n', "dim")
            elif stripped.startswith('Fix:') or stripped.startswith('Fix '):
                output_write(self.output, line + '\n', "ok")
            elif '=' * 10 in stripped:
                output_write(self.output, line + '\n', "heading")
            elif stripped.startswith('\u2500\u2500'):
                output_write(self.output, line + '\n', "heading")
            elif '\u2190 DIFFERENT' in stripped:
                output_write(self.output, line + '\n', "warn")
            elif stripped.startswith('+') or stripped.startswith('-'):
                output_write(self.output, line + '\n', "peach")
            else:
                output_write(self.output, line + '\n')


# ══════════════════════════════════════════════════════════════════════════
#  Tab 13: PE Patcher (KernelEx Ultimate Edition)
# ══════════════════════════════════════════════════════════════════════════

class PEPatcherTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(6, weight=1)

        _, self._get_pe, self.pe_var = make_file_picker(
            self, "PE File:", row=0,
            placeholder=EXAMPLES["pe_patch"], app=app)

        # Output path
        out_frm = tk.Frame(self, bg=T["bg"])
        out_frm.grid(row=1, column=0, sticky="ew", padx=12, pady=5)
        out_frm.columnconfigure(1, weight=1)
        ttk.Label(out_frm, text="Output Path:", width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))
        self.out_var = tk.StringVar()
        ent = PlaceholderEntry(out_frm, placeholder="e.g.  ntdll_patched.dll  (leave empty for auto)",
                               textvariable=self.out_var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        ent.grid(row=0, column=1, sticky="ew")
        app.register_placeholder(ent)
        self._out_entry = ent
        ttk.Button(out_frm, text="Browse \u2026", command=self._browse_out).grid(row=0, column=2, padx=(8, 0))

        # Options row 1
        opt_frm = tk.Frame(self, bg=T["bg"])
        opt_frm.grid(row=2, column=0, sticky="ew", padx=12, pady=5)

        self.chk_version = tk.BooleanVar(value=True)
        self.chk_syscalls = tk.BooleanVar(value=True)
        self.chk_strip_debug = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frm, text="  Patch version to 5.0 (NT 2000)", variable=self.chk_version,
                       bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"], activebackground=T["bg"],
                       activeforeground=T["fg"], font=("Segoe UI", 10)).pack(side="left", padx=10)
        tk.Checkbutton(opt_frm, text="  Patch sysenter \u2192 int 0x2E", variable=self.chk_syscalls,
                       bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"], activebackground=T["bg"],
                       activeforeground=T["fg"], font=("Segoe UI", 10)).pack(side="left", padx=10)
        tk.Checkbutton(opt_frm, text="  Strip debug info", variable=self.chk_strip_debug,
                       bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"], activebackground=T["bg"],
                       activeforeground=T["fg"], font=("Segoe UI", 10)).pack(side="left", padx=10)

        # Options row 2: shim + rebase
        shim_frm = tk.Frame(self, bg=T["bg"])
        shim_frm.grid(row=3, column=0, sticky="ew", padx=12, pady=5)
        ttk.Label(shim_frm, text="Convention shim:").pack(side="left", padx=5)
        self.shim_var = tk.StringVar()
        shim_ent = PlaceholderEntry(shim_frm,
                                     placeholder="e.g.  IoReadPartitionTable,fastcall,stdcall,4",
                                     textvariable=self.shim_var,
                                     bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                                     font=("Consolas", 10), relief="flat", bd=5, width=38)
        shim_ent.pack(side="left", padx=5)
        app.register_placeholder(shim_ent)
        self._shim_entry = shim_ent

        ttk.Label(shim_frm, text="    Rebase addr:").pack(side="left", padx=(15, 5))
        self.rebase_var = tk.StringVar()
        rebase_ent = PlaceholderEntry(shim_frm,
                                       placeholder="e.g.  0x80400000",
                                       textvariable=self.rebase_var,
                                       bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                                       font=("Consolas", 10), relief="flat", bd=5, width=14)
        rebase_ent.pack(side="left", padx=5)
        app.register_placeholder(rebase_ent)
        self._rebase_entry = rebase_ent

        # Buttons
        btn_frm = make_button_bar(self, row=4)
        ttk.Button(btn_frm, text="\u26A1  Quick Win2000 Patch", style="Accent.TButton",
                   command=self._quick_patch).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F527  Custom Patch",
                   command=self._custom_patch).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F529  Patch Syscalls Only",
                   command=self._patch_syscalls).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CB  Inspect Tables",
                   command=self._inspect_tables).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CD  Rebase",
                   command=self._rebase).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="\u2022 KernelEx-inspired PE patcher \u2014 version stamp, syscall, shim, rebase, blob inject")
        ttk.Label(self, textvariable=self.status_var, foreground=T["fg_dim"]).grid(
            row=5, column=0, sticky="w", padx=16, pady=(0, 2))

        self.output = make_output(self)
        self.output.grid(row=6, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _browse_out(self):
        path = filedialog.asksaveasfilename(
            filetypes=[("PE Files", "*.dll;*.sys;*.exe"), ("All", "*.*")])
        if path:
            self._out_entry.set_value(path)

    def _get_out(self):
        return self._out_entry.get_value() or None

    def _get_shim(self):
        return self._shim_entry.get_value()

    def _get_rebase(self):
        return self._rebase_entry.get_value()

    def _quick_patch(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file to patch.\n\nSupported: ntdll.dll, hal.dll, win32k.sys, ACPI.sys, any .dll/.sys/.exe")
            return
        output = self._get_out()
        self.status_var.set("\u23F3 Applying Win2000 quick patch...")
        output_clear(self.output)

        def work():
            return _pe_patcher().patch_pe_for_win2000(pe_path, output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\n\u2705 Patched file saved to: {result.output_path}\n", "ok")
                self.status_var.set(f"\u2705 Patch successful: {result.output_path}")
                self.app.set_status(f"Patched: {os.path.basename(pe_path)} \u2192 {result.output_path}")
            else:
                output_write(self.output, "\n\u274C Patch had errors!\n", "error")
                self.status_var.set("\u274C Patch failed")

        run_async(work, lambda r: self.after(0, done, r))

    def _custom_patch(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file to patch.")
            return
        output = self._get_out()
        self.status_var.set("\u23F3 Applying custom patches...")
        output_clear(self.output)

        chk_ver = self.chk_version.get()
        chk_sys = self.chk_syscalls.get()
        chk_dbg = self.chk_strip_debug.get()
        shim = self._get_shim()
        rebase = self._get_rebase()

        def work():
            patcher = _pe_patcher().PEPatcher(pe_path)
            if chk_ver:
                patcher.patch_os_version(5, 0)
                patcher.patch_subsystem_version(5, 0)
            if chk_sys:
                count = patcher.patch_syscall_stubs()
                patcher._record("info", f"Patched {count} syscall stubs")
            if chk_dbg:
                patcher.remove_debug_directory()
            if shim:
                parts = shim.split(',')
                if len(parts) == 4:
                    patcher.apply_convention_shim(parts[0].strip(), parts[1].strip(),
                                                  parts[2].strip(), int(parts[3].strip()))
            if rebase:
                patcher.rebase_image(int(rebase, 16))
            return patcher.save(output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\n\u2705 Patched file saved to: {result.output_path}\n", "ok")
                self.status_var.set(f"\u2705 Patch successful: {result.output_path}")
            else:
                output_write(self.output, "\n\u274C Patch had errors!\n", "error")
                for e in result.errors:
                    output_write(self.output, f"  {e}\n", "error")
                self.status_var.set("\u274C Patch failed")

        run_async(work, lambda r: self.after(0, done, r))

    def _patch_syscalls(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        output = self._get_out()
        self.status_var.set("\u23F3 Patching syscall stubs...")
        output_clear(self.output)

        def work():
            return _pe_patcher().patch_syscall_stubs(pe_path, output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\n\u2705 Saved to: {result.output_path}\n", "ok")
            self.status_var.set("\u2705 Done")

        run_async(work, lambda r: self.after(0, done, r))

    def _inspect_tables(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        self.status_var.set("\u23F3 Inspecting PE tables...")
        output_clear(self.output)

        def work():
            return _pe_patcher().inspect_pe_tables(pe_path)

        def done(tables):
            if isinstance(tables, Exception):
                self.status_var.set(f"\u274C Error: {tables}")
                output_write(self.output, f"ERROR: {tables}\n", "error")
                return

            output_write(self.output, "=== SECTIONS ===\n", "heading")
            for s in tables['sections']:
                flags = []
                if s['executable']: flags.append('X')
                if s['writable']: flags.append('W')
                output_write(self.output,
                    f"  {s['name']:<10s} RVA=0x{s['rva']:08X} "
                    f"VSize=0x{s['virtual_size']:08X} "
                    f"Raw=0x{s['raw_offset']:08X} "
                    f"RSize=0x{s['raw_size']:08X} [{','.join(flags)}]\n")

            output_write(self.output, f"\n=== EXPORTS ({len(tables['exports'])}) ===\n", "heading")
            for e in tables['exports'][:200]:
                fwd = f" -> {e['forwarder']}" if e['forwarder'] else ""
                name = e['name'] or f"@{e['ordinal']}"
                output_write(self.output,
                    f"  [{e['ordinal']:4d}] 0x{e['rva']:08X} {name}{fwd}\n")

            output_write(self.output, f"\n=== IMPORTS ({len(tables['imports'])}) ===\n", "heading")
            cur_dll = None
            for i in tables['imports'][:200]:
                if i['dll'] != cur_dll:
                    cur_dll = i['dll']
                    output_write(self.output, f"\n  {cur_dll}:\n", "ok")
                name = i['name'] or f"@{i['ordinal']}"
                output_write(self.output, f"    0x{i['iat_rva']:08X} {name}\n")

            relocs = tables['relocations']
            output_write(self.output, f"\n=== RELOCATIONS ({len(relocs)}) ===\n", "heading")
            for r in relocs[:100]:
                output_write(self.output, f"  0x{r['rva']:08X} {r['type_name']}\n")
            if len(relocs) > 100:
                output_write(self.output, f"  ... and {len(relocs) - 100} more\n", "dim")

            self.status_var.set(f"\u2705 Inspection: {len(tables['exports'])} exports, "
                              f"{len(tables['imports'])} imports, {len(relocs)} relocs")

        run_async(work, lambda r: self.after(0, done, r))

    def _rebase(self):
        pe_path = self._get_pe()
        rebase = self._get_rebase()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        if not rebase:
            messagebox.showwarning("Missing", "Enter a hex address in the Rebase field.\n\nExample: 0x80400000 (ntoskrnl), 0x80010000 (hal)")
            return
        output = self._get_out()
        self.status_var.set("\u23F3 Rebasing...")
        output_clear(self.output)

        def work():
            return _pe_patcher().rebase_pe(pe_path, int(rebase, 16), output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\n\u2705 Rebased file saved to: {result.output_path}\n", "ok")
            self.status_var.set("\u2705 Done")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Launch
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app = App()
    app.mainloop()
