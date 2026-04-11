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
import re
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
def _kdbg():            return _lazy('nt_analyzer.kernel_debugger')
def _sym_loader():      return _lazy('nt_analyzer.symbol_loader')
def _deep_analyzer():   return _lazy('nt_analyzer.deep_analyzer')
def _emulator():        return _lazy('nt_analyzer.emulator')


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
        self.tab_deep       = DeepAnalyzerTab(self.nb, self)
        self.tab_xref       = XRefScannerTab(self.nb, self)
        self.tab_patcher    = PEPatcherTab(self.nb, self)
        self.tab_kdbg       = KernelDebuggerTab(self.nb, self)

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
            (self.tab_deep,       " Deep "),
            (self.tab_xref,       " XRefs "),
            (self.tab_patcher,    " PE Patch "),
            (self.tab_kdbg,       " \U0001F41E KDebug "),
        ]
        for tab, text in tabs:
            self.nb.add(tab, text=text)

    # ── Status bar ────────────────────────────────────────────────────────
    def _build_statusbar(self):
        self.statusbar = tk.Frame(self, bg=T["header_bg"], height=28)
        self.statusbar.pack(fill="x", side="bottom")
        self.statusbar.pack_propagate(False)

        self.status_lbl = ttk.Label(self.statusbar,
            text="  Ready  \u2022  16 analysis modules loaded  \u2022  Live kernel debugger  \u2022  Deep function analysis  \u2022  System-wide XRef scanning  \u2022  Symbol loading (.map/.pdb/.dbg)",
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


def _configure_output_tags(txt):
    """Apply standard color tags to a ScrolledText widget."""
    txt.tag_configure("title",   foreground=T["accent"], font=("Consolas", 11, "bold"))
    txt.tag_configure("ok",      foreground=T["green"])
    txt.tag_configure("warn",    foreground=T["yellow"])
    txt.tag_configure("error",   foreground=T["red"])
    txt.tag_configure("dim",     foreground=T["fg_dim"])
    txt.tag_configure("peach",   foreground=T["peach"])
    txt.tag_configure("heading", foreground=T["accent"], font=("Consolas", 10, "bold"))


class TabbedOutput(ttk.Frame):
    """Notebook-based output area with closeable result tabs.

    Acts as a drop-in replacement for a ScrolledText widget by proxying
    methods to the currently active tab.  Call ``new_tab(title)`` to create
    a fresh output tab (instead of clearing the single output).
    """

    def __init__(self, parent, **kw):
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._nb = ttk.Notebook(self)
        self._nb.grid(row=0, column=0, sticky="nsew")
        self._tabs = {}          # frame_str -> ScrolledText
        self._extra_tags = {}    # tag_name -> (args, kwargs)
        self._extra_binds = []   # (tag, sequence, callback)
        self._current = None     # active ScrolledText
        self._counter = 0
        # Close tabs: middle-click or right-click
        self._nb.bind("<Button-2>", self._close_clicked)
        self._nb.bind("<Button-3>", self._show_context)
        self._ctx = tk.Menu(self._nb, tearoff=0)
        self._ctx.add_command(label="Close Tab", command=self._close_ctx_tab)
        self._ctx.add_command(label="Close All Others", command=self._close_others)
        self._ctx.add_separator()
        self._ctx.add_command(label="Close All", command=self.close_all)

    # ── public API ────────────────────────────────────────────
    def new_tab(self, title="Result"):
        """Create a new output tab and make it active.  Returns the ScrolledText."""
        self._counter += 1
        frm = ttk.Frame(self._nb)
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(0, weight=1)
        txt = scrolledtext.ScrolledText(
            frm, bg=T["bg_dark"], fg=T["fg"], insertbackground=T["fg"],
            font=("Consolas", 10), relief="flat", bd=8,
            wrap="none", state="disabled")
        txt.grid(row=0, column=0, sticky="nsew")
        _configure_output_tags(txt)
        # Apply any extra tags / binds registered by the owning tab
        for tag, kw in self._extra_tags.items():
            txt.tag_configure(tag, **kw)
        for tag, seq, cb in self._extra_binds:
            txt.tag_bind(tag, seq, cb)
        # Limit number of tabs (auto-close oldest beyond 20)
        tab_ids = self._nb.tabs()
        if len(tab_ids) >= 20:
            oldest = tab_ids[0]
            self._nb.forget(oldest)
            self._tabs.pop(oldest, None)
        self._nb.add(frm, text=f"  {title}  ")
        self._nb.select(frm)
        self._tabs[str(frm)] = txt
        self._current = txt
        return txt

    def new_tab_hidden(self, title):
        """Create a new output tab WITHOUT switching to it. Returns the title."""
        # If already exists, keep it as-is
        for tab_id in self._nb.tabs():
            if self._nb.tab(tab_id, "text").strip() == title:
                return title
        # Save current selection
        cur_sel = self._nb.select()
        self.new_tab(title)
        # Restore previous tab
        if cur_sel:
            try:
                self._nb.select(cur_sel)
                self._current = self._tabs.get(cur_sel)
            except Exception:
                pass
        return title

    def get_or_create_tab(self, title):
        """Find existing tab by *title*; select it and return its ScrolledText.
        If no tab with that title exists, create a new one."""
        for tab_id in self._nb.tabs():
            if self._nb.tab(tab_id, "text").strip() == title:
                self._nb.select(tab_id)
                txt = self._tabs.get(tab_id)
                if txt:
                    self._current = txt
                    return txt
        return self.new_tab(title)

    def write_to_tab(self, title, content, tag=None):
        """Write *content* to the tab named *title* WITHOUT switching to it.
        Creates the tab (hidden) if it doesn't exist yet."""
        target = None
        for tab_id in self._nb.tabs():
            if self._nb.tab(tab_id, "text").strip() == title:
                target = self._tabs.get(tab_id)
                break
        if target is None:
            # Tab doesn't exist — create it but stay on current tab
            cur_sel = self._nb.select()
            target = self.new_tab(title)
            if cur_sel:
                self._nb.select(cur_sel)
        # Write to the target tab directly
        target.configure(state="normal")
        target.insert("end", content, (tag,) if tag else ())
        target.see("end")
        target.configure(state="disabled")

    def find_tab(self, title):
        """Return (tab_id, widget) for a tab with given title, or (None, None)."""
        for tab_id in self._nb.tabs():
            if self._nb.tab(tab_id, "text").strip() == title:
                return tab_id, self._tabs.get(tab_id)
        return None, None

    def clear_current(self):
        """Clear the currently active tab's text."""
        c = self._cur()
        if c:
            c.configure(state="normal")
            c.delete("1.0", "end")
            c.configure(state="disabled")

    def close_all(self):
        for t in list(self._nb.tabs()):
            self._nb.forget(t)
        self._tabs.clear()
        self._current = None

    # ── extra tag registration (called once in tab __init__) ──
    def tag_configure(self, tag, **kw):
        self._extra_tags[tag] = kw
        if self._current:
            self._current.tag_configure(tag, **kw)

    def tag_bind(self, tag, sequence, callback):
        self._extra_binds.append((tag, sequence, callback))
        if self._current:
            self._current.tag_bind(tag, sequence, callback)

    # ── ScrolledText proxy (so output_write / output_clear work) ─
    def _cur(self):
        sel = self._nb.select()
        if sel:
            t = self._tabs.get(sel)
            if t:
                self._current = t
                return t
        return self._current

    def configure(self, **kw):
        c = self._cur()
        if c:
            c.configure(**kw)

    def config(self, **kw):
        return self.configure(**kw)

    def insert(self, *a, **kw):
        c = self._cur()
        if c:
            c.insert(*a, **kw)

    def delete(self, *a, **kw):
        c = self._cur()
        if c:
            c.delete(*a, **kw)

    def get(self, *a, **kw):
        c = self._cur()
        return c.get(*a, **kw) if c else ""

    def index(self, *a, **kw):
        c = self._cur()
        return c.index(*a, **kw) if c else "1.0"

    def tag_ranges(self, *a, **kw):
        c = self._cur()
        return c.tag_ranges(*a, **kw) if c else ()

    def see(self, *a):
        c = self._cur()
        if c:
            c.see(*a)

    # ── internal ──────────────────────────────────────────────
    def _close_clicked(self, event):
        try:
            idx = self._nb.index(f"@{event.x},{event.y}")
            tab_id = self._nb.tabs()[idx]
            self._nb.forget(tab_id)
            self._tabs.pop(tab_id, None)
        except Exception:
            pass

    def _show_context(self, event):
        try:
            self._ctx_idx = self._nb.index(f"@{event.x},{event.y}")
            self._ctx.tk_popup(event.x_root, event.y_root)
        except Exception:
            pass

    def _close_ctx_tab(self):
        try:
            tab_id = self._nb.tabs()[self._ctx_idx]
            self._nb.forget(tab_id)
            self._tabs.pop(tab_id, None)
        except Exception:
            pass

    def _close_others(self):
        try:
            keep = self._nb.tabs()[self._ctx_idx]
            for t in list(self._nb.tabs()):
                if t != keep:
                    self._nb.forget(t)
                    self._tabs.pop(t, None)
        except Exception:
            pass


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


def _extract_func_from_click(event, output_widget):
    """Extract the function name under a func_link or func_link_b tag click.
    Works with both TabbedOutput and plain ScrolledText.
    Returns the stripped function name or None."""
    try:
        if isinstance(output_widget, TabbedOutput):
            txt = output_widget._cur()
        else:
            txt = output_widget
        if not txt:
            return None
        idx = txt.index(f"@{event.x},{event.y}")
        tags = txt.tag_names(idx)
        # Check for either func_link or func_link_b
        tag_name = None
        if "func_link" in tags:
            tag_name = "func_link"
        elif "func_link_b" in tags:
            tag_name = "func_link_b"
        if not tag_name:
            return None
        r = txt.tag_prevrange(tag_name, f"{idx}+1c")
        if not r:
            return None
        return txt.get(r[0], r[1]).strip()
    except Exception:
        return None


def setup_func_link(output_widget, pe_path_getter, app_ref, sym_getter=None, mode_var=None, symbols_getter=None,
                    pe_path_getter_b=None, sym_getter_b=None, symbols_getter_b=None):
    """Register func_link tag on a TabbedOutput so clicking a function name
    opens a new tab with the decompilation mode selected in mode_var.

    pe_path_getter: callable returning the PE file path (DLL A)
    app_ref: the main Win2KAnalyzerApp for after() and target tab lookup
    symbols_getter: optional callable returning a symbols dict {va: name} for DLL A
    sym_getter: optional callable returning (use_sym:bool, sym_path:str|None) for DLL A
    mode_var: optional StringVar ('Assembly'|'Pseudo-C'|'Hex Dump'); defaults to Assembly
    pe_path_getter_b: optional callable returning the PE file path (DLL B / ReactOS)
    sym_getter_b: optional callable returning (use_sym:bool, sym_path:str|None) for DLL B
    symbols_getter_b: optional callable returning a symbols dict {va: name} for DLL B
    """
    output_widget.tag_configure("func_link", foreground="#89b4fa", underline=True)
    output_widget.tag_configure("func_link_b", foreground="#a6e3a1", underline=True)

    def _pick_sym(is_b=False):
        """Return (sym_getter_fn, symbols_getter_fn, pe_getter_fn) for the right side."""
        if is_b and pe_path_getter_b:
            return (sym_getter_b, symbols_getter_b, pe_path_getter_b)
        return (sym_getter, symbols_getter, pe_path_getter)

    def _colorize_asm(result, func_name):
        output_write(output_widget, f"  DISASSEMBLY: {func_name}\n\n", "title")
        for line in result.splitlines():
            stripped = line.lstrip()
            if stripped.startswith(';'):
                output_write(output_widget, line + "\n", "dim")
            elif '; \u2192' in line:
                output_write(output_widget, line + "\n", "peach")
            elif '; arg' in line:
                output_write(output_widget, line + "\n", "ok")
            elif '; local_' in line:
                output_write(output_widget, line + "\n", "warn")
            elif 'call' in line.lower() or 'int' in line:
                output_write(output_widget, line + "\n", "ok")
            elif stripped.startswith(('ret', 'retn')):
                output_write(output_widget, line + "\n", "warn")
            elif stripped.startswith('j'):
                output_write(output_widget, line + "\n", "peach")
            else:
                output_write(output_widget, line + "\n")

    def _colorize_pseudoc(code, func_name):
        output_write(output_widget, f"  PSEUDO-C: {func_name}\n\n", "title")
        for line in code.split('\n'):
            stripped = line.lstrip()
            if stripped.startswith('/*') or stripped.startswith(' *') or stripped.startswith('*/'):
                output_write(output_widget, line + '\n', "dim")
            elif stripped.startswith('//'):
                output_write(output_widget, line + '\n', "dim")
            elif any(kw in stripped for kw in ('if ', 'else', 'while', 'for ', 'switch', 'case ', 'return')):
                output_write(output_widget, line + '\n', "warn")
            elif stripped.startswith(('void ', 'int ', 'NTSTATUS', 'DWORD', 'BOOL')):
                output_write(output_widget, line + '\n', "ok")
            elif '(' in stripped and ')' in stripped and not stripped.startswith('//'):
                output_write(output_widget, line + '\n', "peach")
            else:
                output_write(output_widget, line + '\n')

    def _do_asm(func_name, pe_path, is_b=False):
        sg, _, _ = _pick_sym(is_b)
        use_sym = False
        sym_path = None
        if sg:
            use_sym, sym_path = sg()
        side_tag = " [B]" if is_b else ""
        sym_tag = " +sym" if (use_sym and sym_path) else ""
        output_widget.new_tab(f"Disasm{sym_tag}{side_tag}: {func_name}")
        def work():
            if use_sym and sym_path:
                syms = _sym_loader().load_symbols(sym_path, pe_path=pe_path)
                fm = _deep_analyzer().PEFunctionMap(pe_path)
                fm.discover_all_functions()
                fm.analyze_all_functions()
                if isinstance(syms, tuple):
                    sym_list, _ = syms
                else:
                    sym_list = syms
                if isinstance(sym_list, dict):
                    for va, name in sym_list.items():
                        if va in fm.functions and name:
                            fm.functions[va].name = name
                elif isinstance(sym_list, list):
                    for sym in sym_list:
                        va = sym.get('address', 0)
                        name = sym.get('name', '')
                        if va in fm.functions and name:
                            fm.functions[va].name = name
                code = _deep_analyzer().disassemble_function_full(fm, func_name)
                fm.close()
                return code
            # Pass symbols for non-exported function lookup
            _, syms_g_fn, _ = _pick_sym(is_b)
            click_syms = syms_g_fn() if syms_g_fn else None
            return _behavior().disassemble_function(pe_path, func_name, symbols=click_syms)
        def done(result):
            if isinstance(result, Exception):
                output_write(output_widget, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(output_widget, f"  Function '{func_name}' not found.\n", "error")
                return
            _colorize_asm(result, func_name)
        def callback(result):
            app_ref.after(0, done, result)
        run_async(work, callback)

    def _do_pseudoc(func_name, pe_path, is_b=False):
        sg, syms_g, _ = _pick_sym(is_b)
        sym_tag = ""
        syms = None
        if syms_g:
            syms = syms_g()
            if syms:
                sym_tag = " +sym"
        elif sg:
            use_sym, sym_path = sg()
            if use_sym and sym_path:
                sym_tag = " +sym"
        side_tag = " [B]" if is_b else ""
        output_widget.new_tab(f"Pseudo-C{sym_tag}{side_tag}: {func_name}")
        def work():
            return _decompiler().decompile(pe_path, func_name, symbols=syms)
        def done(result):
            if isinstance(result, Exception):
                output_write(output_widget, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(output_widget, f"  Function '{func_name}' not found.\n", "error")
                return
            _colorize_pseudoc(result, func_name)
        def callback(result):
            app_ref.after(0, done, result)
        run_async(work, callback)

    def _do_hex(func_name, pe_path, is_b=False):
        sg, _, _ = _pick_sym(is_b)
        sym_tag = ""
        if sg:
            use_sym, sym_path = sg()
            if use_sym and sym_path:
                sym_tag = " +sym"
        side_tag = " [B]" if is_b else ""
        output_widget.new_tab(f"HEX{sym_tag}{side_tag}: {func_name}")
        def work():
            import pefile
            pe = pefile.PE(pe_path, fast_load=False)
            rva = None
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
                        rva = exp.address
                        break
            if rva is None:
                pe.close()
                return None
            img_base = pe.OPTIONAL_HEADER.ImageBase
            va = img_base + rva
            offset = pe.get_offset_from_rva(rva)
            data = pe.get_data(rva, min(4096, len(pe.__data__) - offset))
            pe.close()
            return (data, va, rva)
        def done(result):
            if isinstance(result, Exception):
                output_write(output_widget, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(output_widget, f"  Function '{func_name}' not found.\n", "error")
                return
            data, va, rva = result
            output_write(output_widget, f"  HEX DUMP: {func_name}\n", "title")
            output_write(output_widget, f"  RVA: 0x{rva:08X}  VA: 0x{va:08X}  Size: {len(data)} bytes\n\n", "dim")
            for i in range(0, min(len(data), 2048), 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02X}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                addr = va + i
                tag = None
                if b'\xC3' in chunk:
                    tag = "warn"
                elif b'\xE8' in chunk:
                    tag = "ok"
                elif b'\xCC' in chunk:
                    tag = "error"
                output_write(output_widget, f"  {addr:08X}     {hex_str:<50s} {ascii_str}\n", tag)
                if b'\xC3' in chunk or b'\xCC' in chunk:
                    if i > 32:
                        break
        def callback(result):
            app_ref.after(0, done, result)
        run_async(work, callback)

    def _on_click_side(event, is_b=False):
        func_name = _extract_func_from_click(event, output_widget)
        if not func_name:
            return
        _, _, pg = _pick_sym(is_b)
        pe_path = pg()
        if not pe_path:
            return
        mode = mode_var.get() if mode_var else "Assembly"
        if mode == "Pseudo-C":
            _do_pseudoc(func_name, pe_path, is_b=is_b)
        elif mode == "Hex Dump":
            _do_hex(func_name, pe_path, is_b=is_b)
        else:
            _do_asm(func_name, pe_path, is_b=is_b)

    def on_click(event):
        _on_click_side(event, is_b=False)

    def on_click_b(event):
        _on_click_side(event, is_b=True)

    output_widget.tag_bind("func_link", "<Button-1>", on_click)
    output_widget.tag_bind("func_link", "<Enter>",
                           lambda e: output_widget.configure(cursor="hand2"))
    output_widget.tag_bind("func_link", "<Leave>",
                           lambda e: output_widget.configure(cursor=""))
    output_widget.tag_bind("func_link_b", "<Button-1>", on_click_b)
    output_widget.tag_bind("func_link_b", "<Enter>",
                           lambda e: output_widget.configure(cursor="hand2"))
    output_widget.tag_bind("func_link_b", "<Leave>",
                           lambda e: output_widget.configure(cursor=""))


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


def make_progress_bar(parent, row):
    """Create a themed progress bar with start/stop helpers.
    Returns (frame, progress_bar, start_fn, stop_fn)."""
    frm = tk.Frame(parent, bg=T["bg"], height=8)
    frm.grid(row=row, column=0, sticky="ew", padx=12, pady=(0, 2))
    frm.columnconfigure(0, weight=1)

    bar = ttk.Progressbar(frm, mode='indeterminate', length=200)
    bar.grid(row=0, column=0, sticky="ew")
    bar.grid_remove()  # hidden by default

    def start():
        bar.grid()
        bar.start(12)

    def stop():
        bar.stop()
        bar.grid_remove()

    return frm, bar, start, stop


def run_with_progress(tab, func, callback):
    """Run an async operation with the tab's progress bar animated."""
    if hasattr(tab, '_prog_start'):
        tab._prog_start()

    def wrapped_callback(result):
        def finish(r):
            if hasattr(tab, '_prog_stop'):
                tab._prog_stop()
            callback(r)
        tab.after(0, finish, result)

    run_async(func, wrapped_callback)


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


def make_status_with_progress(parent, default_text, row):
    """Create status label with an inline indeterminate progress bar.
    Returns (status_var, start_fn, stop_fn)."""
    status_var = tk.StringVar(value=default_text)
    sf = tk.Frame(parent, bg=T["bg"])
    sf.grid(row=row, column=0, sticky="ew", padx=12, pady=(0, 2))
    sf.columnconfigure(0, weight=1)
    ttk.Label(sf, textvariable=status_var, foreground=T["fg_dim"]).pack(side="left", padx=4)
    prog = ttk.Progressbar(sf, mode='indeterminate', length=200)

    def start():
        prog.pack(side="right", padx=8)
        prog.start(12)

    def stop():
        prog.stop()
        prog.pack_forget()

    return status_var, start, stop


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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)
        ttk.Separator(btn_frm, orient="vertical").pack(side="left", padx=8, fill="y", pady=2)
        ttk.Label(btn_frm, text="Click mode:").pack(side="left", padx=(0, 3))
        self._click_mode_var = tk.StringVar(value="Assembly")
        ttk.Combobox(btn_frm, textvariable=self._click_mode_var, width=10,
                     values=["Assembly", "Pseudo-C", "Hex Dump"],
                     state="readonly").pack(side="left", padx=2)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Select a PE file (ntdll.dll, kernel32.dll, hal.dll, win32k.sys, ...)", row=2)

        self.output = TabbedOutput(self)
        self.output.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        setup_func_link(self.output, self._get_dll, app, mode_var=self._click_mode_var)
        self._last_data = None

    def _run_exports(self):
        path = self._get_dll()
        if not path:
            messagebox.showwarning("No file", "Please select a PE file first.\n\nExample: ntdll.dll, kernel32.dll")
            return
        self.status_var.set("\u23F3 Analyzing exports...")
        self.output.new_tab("Exports")

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
                ord_s = f"  {exp['ordinal']:<8} "
                rva_s = f" {hex(exp['rva']):<12} {fwd}\n"
                if fwd:
                    output_write(self.output, ord_s)
                    output_write(self.output, f"{name:<50}", "peach")
                    output_write(self.output, rva_s, "peach")
                elif not exp['name']:
                    output_write(self.output, ord_s)
                    output_write(self.output, f"{name:<50}", "dim")
                    output_write(self.output, rva_s, "dim")
                else:
                    output_write(self.output, ord_s)
                    output_write(self.output, f"{name:<50}", "func_link")
                    output_write(self.output, rva_s)
            self.status_var.set(f"\u2705 Done \u2014 {result['total_exports']} exports found")
            self.app.set_status(f"Exports: {result['dll_name']} \u2014 {result['total_exports']} exports")

        run_with_progress(self, work, done)

    def _run_imports(self):
        path = self._get_dll()
        if not path:
            messagebox.showwarning("No file", "Please select a PE file first.\n\nExample: ntdll.dll, kernel32.dll")
            return
        self.status_var.set("\u23F3 Analyzing imports...")
        self.output.new_tab("Imports")

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

        run_with_progress(self, work, done)

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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Select ntdll.dll to extract syscall numbers and mechanisms", row=2)

        self.output = TabbedOutput(self)
        self.output.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_data = None

    def _run(self):
        path = self._get_ntdll()
        if not path:
            messagebox.showwarning("No file", "Select ntdll.dll first.\n\nThis is the NT user\u2192kernel transition DLL that contains all syscall stubs.")
            return
        self.status_var.set("\u23F3 Extracting syscalls...")
        self.output.new_tab("Analysis")

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

        run_with_progress(self, work, done)

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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Compare a Win2000 DLL with its ReactOS equivalent", row=4)

        self.output = TabbedOutput(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_report = None

    def _run(self):
        p1, p2 = self._get_dll1(), self._get_dll2()
        if not p1 or not p2:
            messagebox.showwarning("Missing files", "Select both DLLs.\n\nExample:\n  A: C:\\WINNT\\System32\\ntdll.dll\n  B: C:\\reactos\\ntdll.dll")
            return
        l1, l2 = self.label1_var.get() or "Win2000", self.label2_var.get() or "ReactOS"
        self.status_var.set("\u23F3 Comparing...")
        self.output.new_tab("Analysis")

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

        run_with_progress(self, work, done)

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
                output_write(self.output, "      ")
                output_write(self.output, m['name'], "func_link")
                output_write(self.output, f": {ov1} \u2192 {ov2}\n", "warn")
            if len(mismatches) > 30:
                output_write(self.output, f"      ... +{len(mismatches)-30} more\n", "dim")

        only1 = exp.get(f'only_in_{l1}', [])
        only2 = exp.get(f'only_in_{l2}', [])
        if only1:
            output_write(self.output, f"\n    Only in {l1} ({len(only1)} \u2014 MUST be added to {l2}):\n", "error")
            for name in only1[:40]:
                output_write(self.output, "      \u2717 ")
                output_write(self.output, name, "func_link")
                output_write(self.output, "\n")
            if len(only1) > 40:
                output_write(self.output, f"      ... +{len(only1)-40} more\n", "dim")
        if only2:
            output_write(self.output, f"\n    Only in {l2} ({len(only2)} \u2014 extra, safe):\n", "dim")
            for name in only2[:20]:
                output_write(self.output, "      + ")
                output_write(self.output, name, "func_link")
                output_write(self.output, "\n")
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

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Select an NT kernel/user structure to inspect", row=1)

        self.output = TabbedOutput(self)
        self.output.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _show(self):
        name = self.struct_var.get()
        if not name:
            return
        s = _struct_analyzer().get_known_structure(name)
        if not s:
            return
        self.output.new_tab("Structures")
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
        self.output.new_tab("Header Gen")
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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Analyze any PE file header or scan a System32 directory", row=3)

        self.output = TabbedOutput(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _run_header(self):
        path = self._get_file()
        if not path:
            messagebox.showwarning("No file", "Select a PE file.\n\nSupported: .dll .sys .exe .cpl .drv .ocx .scr")
            return
        self.status_var.set("\u23F3 Analyzing...")
        self.output.new_tab("PE Header")

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

        run_with_progress(self, work, done)

    def _run_scan(self):
        d = self._get_dir()
        if not d:
            messagebox.showwarning("No directory", "Select a directory to scan.\n\nExample: C:\\WINNT\\System32")
            return
        self.status_var.set("\u23F3 Scanning...")
        self.output.new_tab("PE Scan")

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

        run_with_progress(self, work, done)


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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Generate .def files from Win2000 DLLs for ReactOS builds", row=3)

        self.output = TabbedOutput(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_def = None

    def _gen_def(self):
        path = self._get_dll()
        if not path:
            messagebox.showwarning("No file", "Select a Win2000 DLL first.\n\nExample: kernel32.dll, ntdll.dll")
            return
        self.status_var.set("\u23F3 Generating .def...")
        self.output.new_tab("DEF File")

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

        run_with_progress(self, work, done)

    def _compare_def(self):
        dll_path = self._get_dll()
        ros_path = self._get_ros()
        if not dll_path or not ros_path:
            messagebox.showwarning("Missing", "Select both Win2000 DLL and ReactOS .def file.")
            return
        self.status_var.set("\u23F3 Comparing...")
        self.output.new_tab("DEF Compare")

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

        run_with_progress(self, work, done)

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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Generate syscall number headers from ntdll.dll for use in drivers/tools", row=3)

        self.output = TabbedOutput(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._last_header = None

    def _gen(self):
        path = self._get_ntdll()
        if not path:
            messagebox.showwarning("No file", "Select ntdll.dll first.\n\nThis extracts syscall numbers to generate C/ASM headers.")
            return
        style = self.style_var.get()
        self.status_var.set(f"\u23F3 Generating {style} header...")
        self.output.new_tab("Generate")

        def work():
            return _sc_patcher().generate_syscall_header(path, header_style=style)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_header = result['content']
            for line in result['content'].split('\n'):
                if line.startswith('//') or line.startswith(';') or line.startswith('#ifndef'):
                    output_write(self.output, line + '\n', "dim")
                elif '#define' in line:
                    output_write(self.output, line + '\n', "ok")
                elif line.strip().startswith('{'):
                    output_write(self.output, line + '\n', "peach")
                else:
                    output_write(self.output, line + '\n')
            self.status_var.set("\u2705 Header generated")

        run_with_progress(self, work, done)

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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        chk_frm = tk.Frame(self, bg=T["bg"])
        chk_frm.grid(row=3, column=0, sticky="w", padx=12, pady=3)
        self.dryrun_var = tk.BooleanVar(value=True)
        tk.Checkbutton(chk_frm, text="  Dry run (preview only, don't modify files)",
                        variable=self.dryrun_var,
                        bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"],
                        activebackground=T["bg"], activeforeground=T["fg"],
                        font=("Segoe UI", 10)).pack(side="left")

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Patch ReactOS C source for Win2000 compatibility", row=4)

        self.output = TabbedOutput(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _scan(self):
        ros_path = self._get_ros()
        if not ros_path:
            messagebox.showwarning("Missing", "Select ReactOS source directory.\n\nExample: C:\\reactos")
            return
        self.status_var.set("\u23F3 Scanning for Win2K compatibility issues...")
        self.output.new_tab("Scan")

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

        run_with_progress(self, work, done)

    def _run_patch(self, mode):
        ros_path = self._get_ros()
        if not ros_path:
            messagebox.showwarning("Missing", "Select ReactOS source directory.")
            return
        ntdll_path = self._get_ntdll() or None
        dry = self.dryrun_var.get()
        self.status_var.set(f"\u23F3 Patching ({mode}){'  [DRY RUN]' if dry else ''}...")
        self.output.new_tab("Patch")

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

        run_with_progress(self, work, done)


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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Generate build scripts for compiling ReactOS DLLs targeting Win2000", row=4)

        self.output = TabbedOutput(self)
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
        self.output.new_tab("Generate")

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
        self.rowconfigure(9, weight=1)

        # ── History state ──
        self._history = []
        self._history_idx = -1

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
        ttk.Button(btn_frm, text="\U0001F500  Control Flow",
                   command=self._control_flow).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F517  Resolve Unknown",
                   command=self._resolve_unknown).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F3AE  Simulate",
                   command=self._simulate).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u25C0 Back",
                   command=self._history_back).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="Forward \u25B6",
                   command=self._history_forward).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        lim_frm = tk.Frame(self, bg=T["bg"])
        lim_frm.grid(row=4, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(lim_frm, text="Max functions (batch):").pack(side="left", padx=5)
        self.max_var = tk.StringVar(value="100")
        tk.Entry(lim_frm, textvariable=self.max_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=8).pack(side="left", padx=5)
        ttk.Label(lim_frm, text="   DLL search dir:").pack(side="left", padx=5)
        self.dll_dir_var = tk.StringVar()
        dll_dir_ent = PlaceholderEntry(lim_frm, placeholder="e.g. C:\\WINNT\\System32",
                                       textvariable=self.dll_dir_var,
                                       bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                                       font=("Consolas", 10), relief="flat", bd=5, width=25)
        dll_dir_ent.pack(side="left", padx=5)
        app.register_placeholder(dll_dir_ent)
        self._dll_dir_entry = dll_dir_ent
        # Windows version selector for struct field analysis
        ttk.Label(lim_frm, text="   Target OS:").pack(side="left", padx=5)
        self._version_var = tk.StringVar(value="win2k")
        ver_combo = ttk.Combobox(lim_frm, textvariable=self._version_var, width=18,
                                 values=["win2k", "winxp", "win2k3", "vista", "win7", "win10", "win11"],
                                 state="readonly")
        ver_combo.pack(side="left", padx=5)
        # Struct display mode
        ttk.Label(lim_frm, text="   Structs:").pack(side="left", padx=5)
        self._struct_mode_var = tk.StringVar(value="Database")
        ttk.Combobox(lim_frm, textvariable=self._struct_mode_var, width=12,
                     values=["Raw Offsets", "Database", "Symbols"],
                     state="readonly").pack(side="left", padx=2)

        # ── Symbols A (Win2K) row ──
        sym_a_frm = tk.Frame(self, bg=T["bg"])
        sym_a_frm.grid(row=5, column=0, sticky="ew", padx=12, pady=2)
        ttk.Label(sym_a_frm, text="Symbols A:").pack(side="left", padx=5)
        self._sym_a_var = tk.StringVar()
        sym_a_ent = PlaceholderEntry(sym_a_frm, placeholder="Win2K symbols: .map / .pdb / .dbg",
                                     textvariable=self._sym_a_var,
                                     bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                                     font=("Consolas", 10), relief="flat", bd=5, width=36)
        sym_a_ent.pack(side="left", padx=5)
        app.register_placeholder(sym_a_ent)
        self._sym_a_entry = sym_a_ent
        ttk.Button(sym_a_frm, text="Browse",
                   command=lambda: self._browse_symbols('a')).pack(side="left", padx=3)
        ttk.Button(sym_a_frm, text="\U0001F4E5  Load",
                   command=lambda: self._load_symbols('a')).pack(side="left", padx=3)
        ttk.Button(sym_a_frm, text="\U0001F4E4  Unload",
                   command=lambda: self._unload_symbols('a')).pack(side="left", padx=3)
        self._loaded_symbols_a = {}
        self._sym_meta_a = {}
        self._use_sym_a_var = tk.BooleanVar(value=False)
        self.sym_a_status_var = tk.StringVar(value="")
        ttk.Label(sym_a_frm, textvariable=self.sym_a_status_var, foreground=T["green"],
                  font=("Segoe UI", 9)).pack(side="left", padx=(8, 0))

        # ── Symbols B (ReactOS) row ──
        sym_b_frm = tk.Frame(self, bg=T["bg"])
        sym_b_frm.grid(row=6, column=0, sticky="ew", padx=12, pady=2)
        ttk.Label(sym_b_frm, text="Symbols B:").pack(side="left", padx=5)
        self._sym_b_var = tk.StringVar()
        sym_b_ent = PlaceholderEntry(sym_b_frm, placeholder="ReactOS symbols: .map / .pdb / .dbg",
                                     textvariable=self._sym_b_var,
                                     bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                                     font=("Consolas", 10), relief="flat", bd=5, width=36)
        sym_b_ent.pack(side="left", padx=5)
        app.register_placeholder(sym_b_ent)
        self._sym_b_entry = sym_b_ent
        ttk.Button(sym_b_frm, text="Browse",
                   command=lambda: self._browse_symbols('b')).pack(side="left", padx=3)
        ttk.Button(sym_b_frm, text="\U0001F4E5  Load",
                   command=lambda: self._load_symbols('b')).pack(side="left", padx=3)
        ttk.Button(sym_b_frm, text="\U0001F4E4  Unload",
                   command=lambda: self._unload_symbols('b')).pack(side="left", padx=3)
        self._loaded_symbols_b = {}
        self._sym_meta_b = {}
        self._use_sym_b_var = tk.BooleanVar(value=False)
        self.sym_b_status_var = tk.StringVar(value="")
        ttk.Label(sym_b_frm, textvariable=self.sym_b_status_var, foreground=T["green"],
                  font=("Segoe UI", 9)).pack(side="left", padx=(8, 0))
        self._hist_var = tk.StringVar(value="")
        ttk.Label(sym_b_frm, textvariable=self._hist_var).pack(side="right", padx=10)

        # Backward-compatible combined accessor
        self._loaded_symbols = {}  # merged view (A+B) for legacy code
        self._sym_meta = {}
        self._use_sym_var = self._use_sym_a_var  # alias
        self.sym_status_var = self.sym_a_status_var  # alias

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Compare function behavior between Win2000 and ReactOS binaries", row=7)

        # Click mode selector
        click_frm = tk.Frame(self, bg=T["bg"])
        click_frm.grid(row=8, column=0, sticky="w", padx=12, pady=0)
        ttk.Label(click_frm, text="Click mode:").pack(side="left", padx=(0, 3))
        self._click_mode_var = tk.StringVar(value="Assembly")
        ttk.Combobox(click_frm, textvariable=self._click_mode_var, width=10,
                     values=["Assembly", "Pseudo-C", "Hex Dump"],
                     state="readonly").pack(side="left", padx=2)

        # Execution trace toggle for Simulate
        self._show_trace_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(click_frm, text="Show execution trace",
                        variable=self._show_trace_var).pack(side="left", padx=(20, 0))

        self.output = TabbedOutput(self)
        self.output.grid(row=9, column=0, sticky="nsew", padx=10, pady=(0, 10))
        def _sym_getter():
            if self._loaded_symbols_a:
                return (True, self._sym_a_entry.get_value())
            return (False, None)
        def _sym_getter_b():
            if self._loaded_symbols_b:
                return (True, self._sym_b_entry.get_value())
            return (False, None)
        setup_func_link(self.output, self._get_a, self.app,
                        sym_getter=_sym_getter,
                        symbols_getter=lambda: self._loaded_symbols_a or None,
                        mode_var=self._click_mode_var,
                        pe_path_getter_b=self._get_b,
                        sym_getter_b=_sym_getter_b,
                        symbols_getter_b=lambda: self._loaded_symbols_b or None)

    # ── Symbol browsing ──
    def _browse_symbols(self, which='a'):
        path = filedialog.askopenfilename(
            filetypes=[("Symbol files", "*.map *.pdb *.dbg *.sym"), ("All", "*.*")])
        if path:
            entry = self._sym_a_entry if which == 'a' else self._sym_b_entry
            entry.set_value(path)

    def _load_symbols(self, which='a'):
        """Load a symbol file (.map, .pdb, .dbg, .sym) into persistent cache for DLL A or B."""
        entry = self._sym_a_entry if which == 'a' else self._sym_b_entry
        sym_path = entry.get_value()
        label = "A (Win2K)" if which == 'a' else "B (ReactOS)"
        if not sym_path:
            messagebox.showwarning("No file", f"Enter or browse for a symbol file for {label}.\n\n"
                                   "Supported: .map (MSVC/GCC/IDA), .pdb, .dbg, .sym")
            return
        if not os.path.isfile(sym_path):
            messagebox.showerror("Not found", f"File not found:\n{sym_path}")
            return

        pe_path = self._get_a() if which == 'a' else self._get_b()
        self.status_var.set(f"\u23F3 Loading {label} symbols from {os.path.basename(sym_path)}...")

        def work(progress_cb):
            progress_cb(f"Loading {label} symbols from {os.path.basename(sym_path)}...", 30)
            return _sym_loader().load_symbols(sym_path, pe_path=pe_path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                return
            symbols, meta = result
            if which == 'a':
                self._loaded_symbols_a = _sym_loader().merge_symbols(self._loaded_symbols_a, symbols)
                self._sym_meta_a = meta
                self._use_sym_a_var.set(True)
                status_var = self.sym_a_status_var
            else:
                self._loaded_symbols_b = _sym_loader().merge_symbols(self._loaded_symbols_b, symbols)
                self._sym_meta_b = meta
                self._use_sym_b_var.set(True)
                status_var = self.sym_b_status_var
            # Update merged view for legacy code
            self._loaded_symbols = _sym_loader().merge_symbols(
                self._loaded_symbols_a, self._loaded_symbols_b)
            n = meta.get('total_symbols', 0)
            fmt = meta.get('format', '?')
            err = meta.get('error', '')
            total = len(self._loaded_symbols_a) if which == 'a' else len(self._loaded_symbols_b)
            if err:
                status_var.set(f"\u26A0 {err}")
                self.status_var.set(f"\u26A0 {label}: {err}")
            else:
                status_var.set(f"\u2705 {n} symbols ({fmt})")
                self.status_var.set(
                    f"\u2705 {label}: Loaded {n} symbols from {os.path.basename(sym_path)} "
                    f"[{fmt}] \u2014 total: {total}")

        run_with_progress_dialog(self.app, f"Loading {label} symbols\u2026", work, done)

    def _unload_symbols(self, which='a'):
        """Clear loaded symbols for DLL A or B."""
        label = "A (Win2K)" if which == 'a' else "B (ReactOS)"
        if which == 'a':
            self._loaded_symbols_a = {}
            self._sym_meta_a = {}
            self._use_sym_a_var.set(False)
            self.sym_a_status_var.set("")
        else:
            self._loaded_symbols_b = {}
            self._sym_meta_b = {}
            self._use_sym_b_var.set(False)
            self.sym_b_status_var.set("")
        # Update merged view
        self._loaded_symbols = _sym_loader().merge_symbols(
            self._loaded_symbols_a, self._loaded_symbols_b)
        self.status_var.set(f"\U0001F4E4 {label} symbols unloaded")

    # ── History system ──
    def _save_to_history(self, title):
        self.output.configure(state="normal")
        text = self.output.get("1.0", "end-1c")
        self.output.configure(state="disabled")
        if self._history_idx < len(self._history) - 1:
            self._history = self._history[:self._history_idx + 1]
        self._history.append((title, text))
        self._history_idx = len(self._history) - 1
        self._update_hist_label()

    def _history_back(self):
        if self._history_idx > 0:
            self._history_idx -= 1
            title, text = self._history[self._history_idx]
            output_clear(self.output)
            output_write(self.output, text)
            self.status_var.set(f"\u25C0 {title}")
            self._update_hist_label()

    def _history_forward(self):
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            title, text = self._history[self._history_idx]
            output_clear(self.output)
            output_write(self.output, text)
            self.status_var.set(f"\u25B6 {title}")
            self._update_hist_label()

    def _update_hist_label(self):
        n = len(self._history)
        if n > 0:
            self._hist_var.set(f"History: {self._history_idx + 1}/{n}")
        else:
            self._hist_var.set("")

    def _get_func(self):
        return self._func_entry.get_value()

    def _disasm(self):
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.\n\nExample: NtCreateFile")
            return
        use_sym = self._use_sym_a_var.get() and self._loaded_symbols_a
        # Also pass symbols for non-exported function lookup even in basic mode
        all_syms_a = dict(self._loaded_symbols_a) if self._loaded_symbols_a else None
        self.output.new_tab(f"Disasm: {func}")

        loaded_syms = dict(self._loaded_symbols_a) if use_sym else None

        def work(progress_cb):
            progress_cb(f"Loading PE: {os.path.basename(path)}", 10)
            if loaded_syms:
                progress_cb(f"Building function map\u2026", 30)
                fm = _deep_analyzer().PEFunctionMap(path, progress_callback=progress_cb)
                fm.discover_all_functions()
                fm.analyze_all_functions()
                # Merge loaded symbols
                for va, name in loaded_syms.items():
                    if va in fm.functions and name:
                        fm.functions[va].name = name
                progress_cb(f"Disassembling {func} with symbols\u2026", 70)
                code = _deep_analyzer().disassemble_function_full(fm, func)
                fm.close()
                return ('deep', code)
            else:
                progress_cb(f"Disassembling {func}\u2026", 30)
                result = _behavior().disassemble_function(path, func, symbols=all_syms_a)
                progress_cb("Formatting output\u2026", 90)
                return ('basic', result)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            mode, code = result
            if code is None:
                output_write(self.output, f"  Function '{func}' not found.\n\n", "error")
                output_write(self.output,
                    f"  Searched: PE exports, Nt\u2194Zw alias, SSDT resolution", "dim")
                if self._loaded_symbols_a:
                    output_write(self.output, f", loaded symbols ({len(self._loaded_symbols_a)})", "dim")
                output_write(self.output, "\n", "dim")
                self.status_var.set("\u274C Function not found")
                return
            for line in code.split('\n'):
                if line.startswith(';'):
                    output_write(self.output, line + '\n', "dim")
                elif '; \u2192' in line:
                    output_write(self.output, line + '\n', "peach")
                elif '; arg' in line:
                    output_write(self.output, line + '\n', "ok")
                elif '; local_' in line:
                    output_write(self.output, line + '\n', "warn")
                elif 'call' in line.lower() or 'int' in line:
                    output_write(self.output, line + '\n', "ok")
                elif 'ret' in line or 'retn' in line:
                    output_write(self.output, line + '\n', "warn")
                else:
                    output_write(self.output, line + '\n')
            sym_note = " (with symbols)" if mode == 'deep' else ""
            self._save_to_history(f"Disasm: {func}")
            self.status_var.set(f"\u2705 Disassembly of {func} complete{sym_note}")

        run_with_progress_dialog(self.app, f"Disassembling {func}\u2026", work, done)

    def _compare_one(self):
        pa = self._get_a()
        pb = self._get_b()
        func = self._get_func()
        if not pa or not pb or not func:
            messagebox.showwarning("Missing", "Select both DLLs and enter a function name.")
            return
        self.output.new_tab(f"Compare: {func}")
        syms_a = dict(self._loaded_symbols_a) if self._loaded_symbols_a else None
        syms_b = dict(self._loaded_symbols_b) if self._loaded_symbols_b else None

        def work(progress_cb):
            progress_cb(f"Fingerprinting {func} in {os.path.basename(pa)}\u2026", 20)
            progress_cb(f"Fingerprinting {func} in {os.path.basename(pb)}\u2026", 50)
            result = _behavior().compare_functions(pa, pb, func,
                                                   symbols_a=syms_a, symbols_b=syms_b)
            progress_cb("Computing similarity\u2026", 90)
            return result

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  FUNCTION COMPARISON\n\n", "title")
            # Clickable links to decompile from either DLL
            output_write(self.output, "  \u25B6 View in DLL A (Win2K):  ")
            output_write(self.output, f"{result.func_name}", "func_link")
            output_write(self.output, "   |   \u25B6 View in DLL B (ReactOS):  ")
            output_write(self.output, f"{result.func_name}", "func_link_b")
            output_write(self.output, "\n\n")
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
            self._save_to_history(f"Compare: {func}")
            self.status_var.set(f"\u2705 Comparison: {result.similarity:.1f}% similar")

        run_with_progress_dialog(self.app, f"Comparing {func}\u2026", work, done)

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
        self.output.new_tab("Batch")

        def work(progress_cb):
            progress_cb("Enumerating shared exports\u2026", 5)
            results = _behavior().batch_compare(pa, pb, progress_callback=progress_cb)
            return results[:max_funcs]

        def done(results):
            if isinstance(results, Exception):
                self.status_var.set(f"\u274C Error: {results}")
                output_write(self.output, f"ERROR: {results}\n", "error")
                return
            output_write(self.output, "  BATCH FUNCTION COMPARISON\n", "title")
            output_write(self.output, "  Click function name: blue=DLL A (Win2K), green=DLL B (ReactOS)\n\n", "dim")
            output_write(self.output,
                f"  {'Function A':<26}{'Function B':<26}{'Sim%':<8} {'Blocks A':<10} {'Blocks B':<10} {'Notes'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*26}{'\u2500'*26}{'\u2500'*8} {'\u2500'*10} {'\u2500'*10} {'\u2500'*20}\n", "dim")
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
                output_write(self.output, "  ")
                output_write(self.output, f"{r.func_name}", "func_link")
                pad_a = max(1, 26 - len(r.func_name))
                output_write(self.output, " " * pad_a)
                output_write(self.output, f"{r.func_name}", "func_link_b")
                pad_b = max(1, 26 - len(r.func_name))
                rest = f"{pct:>6.1f}% {ba:<10} {bb:<10} {notes}\n"
                output_write(self.output, " " * pad_b + rest, tag)
            self._save_to_history("Batch Compare")
            self.status_var.set(f"\u2705 Compared {len(results)} functions")

        run_with_progress_dialog(self.app, "Batch comparing exports\u2026", work, done)

    def _patterns(self):
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return
        self.output.new_tab(f"Patterns: {func}")

        def work(progress_cb):
            progress_cb(f"Loading PE: {os.path.basename(path)}", 10)
            progress_cb(f"Fingerprinting {func}\u2026", 30)
            result = _behavior().detect_api_patterns(path, func)
            progress_cb("Analyzing patterns\u2026", 80)
            return result

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

            # Show basic blocks detail
            output_write(self.output, f"\n  {'='*65}\n", "dim")
            output_write(self.output, f"  BASIC BLOCKS ({fp.block_count} blocks, {fp.total_insns} instructions)\n\n", "heading")
            for idx, (addr, block) in enumerate(sorted(fp.blocks.items())):
                n_insns = len(block.instructions)
                succ_str = ""
                if block.successors:
                    succ_str = f"  \u2192 {', '.join(f'0x{s:08X}' for s in block.successors)}"
                output_write(self.output, f"  Block {idx} @ 0x{addr:08X} ({n_insns} insns){succ_str}\n", "heading")
                for mnem, op_norm in block.instructions:
                    output_write(self.output, f"      {mnem:<10} {op_norm}\n", "dim")
                if block.calls:
                    for c in block.calls:
                        cname = c if isinstance(c, str) else f"0x{c:08X}"
                        output_write(self.output, f"      \u21B3 calls {cname}\n", "peach")
                if block.normalized_hash:
                    output_write(self.output, f"      hash: {block.normalized_hash[:16]}\n", "dim")
                output_write(self.output, "\n")
            self._save_to_history(f"Patterns: {func}")
            self.status_var.set(f"\u2705 Pattern analysis complete for {func}")

        run_with_progress_dialog(self.app, f"Detecting patterns: {func}\u2026", work, done)

    def _scan_all(self):
        path = self._get_a()
        if not path:
            messagebox.showwarning("Missing", "Select DLL A.")
            return
        try:
            max_funcs = int(self.max_var.get())
        except ValueError:
            max_funcs = 100
        version = self._version_var.get() or 'win2k'
        self.output.new_tab("Scan All")

        def work(progress_cb):
            return _behavior().scan_all_exports(path, max_funcs, progress_callback=progress_cb, version=version)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  EXPORT BEHAVIOR SCAN\n\n", "title")
            output_write(self.output, "  Click any function name to disassemble it.\n\n", "dim")
            total = 0
            for category, funcs in sorted(result.items(), key=lambda x: -len(x[1])):
                output_write(self.output, f"  [{category}] \u2014 {len(funcs)} functions\n", "heading")
                for entry in funcs:
                    # Support both old (name, desc) and new (name, desc, info) format
                    if len(entry) >= 3:
                        fname, fdesc, info = entry[0], entry[1], entry[2]
                    else:
                        fname, fdesc = entry[0], entry[1]
                        info = {}
                    # Function name as clickable link
                    output_write(self.output, "    ")
                    output_write(self.output, f"{fname}", "func_link")
                    # Addresses
                    rva = info.get('rva')
                    va = info.get('va')
                    if rva is not None:
                        output_write(self.output, f"  RVA:0x{rva:08X}  VA:0x{va:08X}", "dim")
                    # Description (blocks, instructions)
                    output_write(self.output, f"\n        {fdesc}", "")
                    # Struct field accesses — display depends on struct mode
                    struct_fields = info.get('struct_fields', {})
                    struct_ofs = info.get('struct_offsets', [])
                    struct_mode = self._struct_mode_var.get()
                    if struct_mode == "Raw Offsets":
                        # Always show raw offsets only
                        if struct_ofs:
                            seen = []
                            for o in struct_ofs:
                                if o not in seen:
                                    seen.append(o)
                            try:
                                seen.sort(key=lambda x: int(x, 16) if x.startswith('0x') else int(x))
                            except Exception:
                                pass
                            output_write(self.output,
                                f"  structs:[{','.join(seen)}]", "peach")
                    elif struct_mode == "Symbols":
                        # Try symbol-based resolution first, fall back to database
                        sym_fields = info.get('sym_struct_fields', {})
                        if sym_fields:
                            for sname in sorted(sym_fields.keys()):
                                fields = sym_fields[sname]
                                field_strs = [f'+{o} {fn}' for o, fn in fields]
                                output_write(self.output,
                                    f"\n        {sname}: ", "ok")
                                output_write(self.output,
                                    f"{', '.join(field_strs)}", "peach")
                        elif struct_fields:
                            # Fall back to database
                            by_struct = {}
                            for ofs_key, field_list in struct_fields.items():
                                for sname, fname_f, ftype, cnt in field_list:
                                    if sname not in by_struct:
                                        by_struct[sname] = []
                                    by_struct[sname].append((ofs_key, fname_f, ftype, cnt))
                            for sname in sorted(by_struct.keys()):
                                fields = by_struct[sname]
                                field_strs = [f'+{o} {fn}' for o, fn, ft, c in fields]
                                output_write(self.output,
                                    f"\n        {sname} (db): ", "ok")
                                output_write(self.output,
                                    f"{', '.join(field_strs)}", "peach")
                        elif struct_ofs:
                            seen = []
                            for o in struct_ofs:
                                if o not in seen:
                                    seen.append(o)
                            try:
                                seen.sort(key=lambda x: int(x, 16) if x.startswith('0x') else int(x))
                            except Exception:
                                pass
                            output_write(self.output,
                                f"  structs:[{','.join(seen)}]", "peach")
                    else:
                        # Database mode (default)
                        if struct_fields:
                            by_struct = {}
                            for ofs_key, field_list in struct_fields.items():
                                for sname, fname_f, ftype, cnt in field_list:
                                    if sname not in by_struct:
                                        by_struct[sname] = []
                                    by_struct[sname].append((ofs_key, fname_f, ftype, cnt))
                            for sname in sorted(by_struct.keys()):
                                fields = by_struct[sname]
                                field_strs = [f'+{o} {fn}' for o, fn, ft, c in fields]
                                output_write(self.output,
                                    f"\n        {sname}: ", "ok")
                                output_write(self.output,
                                    f"{', '.join(field_strs)}", "peach")
                            identified_offsets = set(struct_fields.keys())
                            unknown = [o for o in struct_ofs if o not in identified_offsets]
                            if unknown:
                                try:
                                    unknown.sort(key=lambda x: int(x, 16) if x.startswith('0x') else int(x))
                                except Exception:
                                    pass
                                output_write(self.output,
                                    f"\n        unresolved offsets: [{','.join(unknown)}]", "dim")
                        elif struct_ofs:
                            seen = []
                            for o in struct_ofs:
                                if o not in seen:
                                    seen.append(o)
                            try:
                                seen.sort(key=lambda x: int(x, 16) if x.startswith('0x') else int(x))
                            except Exception:
                                pass
                            output_write(self.output,
                                f"  structs:[{','.join(seen)}]", "peach")
                    # API calls (deduplicated with counts)
                    apis = info.get('api_calls', [])
                    if apis:
                        from collections import Counter
                        counts = Counter(apis)
                        parts = []
                        for name, cnt in counts.items():
                            if cnt > 1:
                                parts.append(f"{name} (\u00d7{cnt})")
                            else:
                                parts.append(name)
                        output_write(self.output,
                            f"\n        calls: {', '.join(parts)}", "dim")
                    output_write(self.output, "\n")
                output_write(self.output, "\n")
                total += len(funcs)
            self._save_to_history("Scan All")
            self.status_var.set(f"\u2705 Scanned: {total} functions in {len(result)} categories")

        run_with_progress_dialog(self.app, "Scanning all exports\u2026", work, done)

    def _control_flow(self):
        """Full control flow structure analysis — loops, if/else, switches."""
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return
        self.output.new_tab(f"Flow: {func}")

        def work(progress_cb):
            progress_cb(f"Loading PE: {os.path.basename(path)}", 10)
            progress_cb(f"Building control flow graph for {func}\u2026", 30)
            result = _behavior().analyze_control_flow(path, func)
            progress_cb("Detecting loops, branches, switches\u2026", 80)
            return result

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("\u274C Not found")
                return
            report = _behavior().format_control_flow(result)
            for line in report.split('\n'):
                if line.strip().startswith('='):
                    output_write(self.output, line + '\n', "dim")
                elif 'CONTROL FLOW' in line or 'LOOPS' in line or 'BRANCHES' in line \
                        or 'SWITCH' in line or 'CALL TREE' in line or 'ANNOTATED' in line \
                        or 'UNKNOWN' in line:
                    output_write(self.output, line + '\n', "title")
                elif line.strip().startswith('\u2500'):
                    output_write(self.output, line + '\n', "dim")
                elif line.strip().startswith('Loop ') or line.strip().startswith('Branch ') \
                        or line.strip().startswith('Switch '):
                    output_write(self.output, line + '\n', "heading")
                elif line.strip().startswith('\u25C6'):
                    output_write(self.output, line + '\n', "warn")
                elif '\u21B3 calls' in line or '\u2192' in line:
                    output_write(self.output, line + '\n', "peach")
                elif 'Complexity' in line or 'Blocks' in line:
                    output_write(self.output, line + '\n', "ok")
                elif line.strip().startswith('Block 0x'):
                    output_write(self.output, line + '\n', "heading")
                elif line.strip().startswith('Condition:'):
                    output_write(self.output, line + '\n', "warn")
                else:
                    output_write(self.output, line + '\n')
            n_loops = len(result['loops'])
            n_ifs = len(result['if_else'])
            n_sws = len(result['switches'])
            self._save_to_history(f"ControlFlow: {func}")
            self.status_var.set(
                f"\u2705 {func}: complexity={result['complexity']}, "
                f"{n_loops} loops, {n_ifs} branches, {n_sws} switches, "
                f"{len(result['call_tree'])} API calls")

        run_with_progress_dialog(self.app, f"Control flow: {func}\u2026", work, done)

    # ── Kernel Function Emulator ──────────────────────────────────────

    def _simulate(self):
        """Run the kernel function emulator with auto-generated test scenarios."""
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return

        syms_a = dict(self._loaded_symbols_a) if self._loaded_symbols_a else None
        show_trace = self._show_trace_var.get()

        self.output.new_tab(f"Simulate: {func}")

        def work(progress_cb):
            emu_mod = _emulator()
            progress_cb(f"Running emulation scenarios for {func}\u2026", 10)
            # Let run_test_suite generate scenarios internally so
            # buffer addresses match the emulator's actual heap_base
            results = emu_mod.run_test_suite(
                path, func,
                symbols=syms_a,
                progress_cb=progress_cb,
            )
            report = emu_mod.format_report(func, results, show_trace=show_trace)
            return report, results

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Emulation error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                import traceback
                output_write(self.output, traceback.format_exc(), "dim")
                return

            report, suite = result
            output_write(self.output, report + "\n")

            # Summary status
            passed = sum(1 for sc, r in suite if not r.exception and
                         (sc.expected_status is None or r.return_value == sc.expected_status))
            failed = len(suite) - passed
            self._save_to_history(f"Simulate: {func}")
            self.status_var.set(
                f"\u2705 Emulation done: {passed} passed, {failed} failed "
                f"out of {len(suite)} scenarios")

        run_with_progress_dialog(self.app, f"Emulating {func}\u2026", work, done)

    def _resolve_unknown(self):
        """KernelEx-style: resolve unknown call targets by scanning nearby DLLs."""
        path = self._get_a()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return
        dll_dir = self._dll_dir_entry.get_value()
        if not dll_dir:
            # Default to same directory as the PE
            dll_dir = os.path.dirname(path)
        if not dll_dir or not os.path.isdir(dll_dir):
            messagebox.showwarning("Missing", "Enter a valid DLL search directory.\n\n"
                                   "This is used to resolve unknown call targets\n"
                                   "(like KernelEx's SearchPath approach).\n\n"
                                   "Example: C:\\WINNT\\System32")
            return
        self.output.new_tab(f"Resolve: {func}")

        def work(progress_cb):
            import pefile as _pf
            progress_cb(f"Analyzing control flow for {func}\u2026", 10)
            analysis = _behavior().analyze_control_flow(path, func)
            if analysis is None:
                return None
            unknown = analysis.get('unknown_calls', [])
            if not unknown:
                return {'analysis': analysis, 'resolved': {}, 'message': 'No unknown call targets found'}
            progress_cb(f"Found {len(unknown)} unknown targets, loading PE\u2026", 40)
            pe = _pf.PE(path, fast_load=True)
            img_base = pe.OPTIONAL_HEADER.ImageBase
            pe.close()
            progress_cb(f"Scanning DLLs in {os.path.basename(dll_dir)}\u2026", 60)
            resolved = _sym_loader().resolve_from_dlls(unknown, [dll_dir], img_base)
            progress_cb("Formatting results\u2026", 95)
            return {'analysis': analysis, 'resolved': resolved, 'unknown': unknown}

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("\u274C Not found")
                return

            resolved = result.get('resolved', {})
            unknown = result.get('unknown', [])
            analysis = result.get('analysis', {})

            output_write(self.output, "  UNKNOWN FUNCTION RESOLUTION\n", "title")
            output_write(self.output, f"  (KernelEx-style DLL export scanning)\n\n", "dim")
            output_write(self.output, f"  Function: {func}\n")
            output_write(self.output, f"  DLL search path: {dll_dir}\n")
            output_write(self.output, f"  Total call targets: {len(analysis.get('call_tree', []))}\n")
            output_write(self.output, f"  Unknown targets: {len(unknown)}\n")
            output_write(self.output, f"  Resolved: {len(resolved)}\n\n")

            if resolved:
                output_write(self.output, f"  RESOLVED ({len(resolved)})\n", "heading")
                output_write(self.output, f"  {'─'*60}\n", "dim")
                for addr in sorted(resolved.keys()):
                    name = resolved[addr]
                    output_write(self.output, f"    0x{addr:08X}  \u2192  ", "dim")
                    output_write(self.output, f"{name}\n", "ok")
                output_write(self.output, "\n")

            still_unknown = [a for a in unknown if a not in resolved]
            if still_unknown:
                output_write(self.output, f"  STILL UNKNOWN ({len(still_unknown)})\n", "heading")
                output_write(self.output, f"  {'─'*60}\n", "dim")
                for addr in sorted(still_unknown):
                    output_write(self.output, f"    0x{addr:08X}  (internal / not exported)\n", "warn")
                output_write(self.output, "\n")

            if analysis.get('call_tree'):
                output_write(self.output, f"  KNOWN API CALLS ({len(analysis['call_tree'])})\n", "heading")
                output_write(self.output, f"  {'─'*60}\n", "dim")
                seen = set()
                for call in analysis['call_tree']:
                    if call not in seen:
                        seen.add(call)
                        output_write(self.output, f"    \u2192 {call}\n", "peach")

            total_resolved = len(resolved)
            total_unknown = len(still_unknown)
            self._save_to_history(f"Resolve: {func}")
            self.status_var.set(
                f"\u2705 Resolved {total_resolved}/{len(unknown)} unknown targets "
                f"({total_unknown} still unknown)")

        run_with_progress_dialog(self.app, f"Resolving unknown calls in {func}\u2026", work, done)


# ══════════════════════════════════════════════════════════════════════════
#  Tab 11: Decompiler
# ══════════════════════════════════════════════════════════════════════════

class DecompilerTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(6, weight=1)

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
        ttk.Button(btn_frm, text="\U0001F5A5  Disassemble",
                   command=self._disasm_one).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="HEX  Hex Dump",
                   command=self._hexdump_one).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F50D  Discover Functions",
                   command=self._discover).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CA  Batch Decompile",
                   command=self._batch).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BE  Save Output",
                   command=self._save).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        lim_frm = tk.Frame(self, bg=T["bg"])
        lim_frm.grid(row=3, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(lim_frm, text="Max functions:").pack(side="left", padx=5)
        self.max_var = tk.StringVar(value="50")
        tk.Entry(lim_frm, textvariable=self.max_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=8).pack(side="left", padx=5)
        self.expand_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(lim_frm, text="Expand called functions (inline decompile)",
                        variable=self.expand_var).pack(side="left", padx=15)

        # Symbol loading row
        sym_frm = tk.Frame(self, bg=T["bg"])
        sym_frm.grid(row=4, column=0, sticky="ew", padx=12, pady=3)
        sym_frm.columnconfigure(1, weight=1)
        ttk.Label(sym_frm, text="Symbols:", width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))
        self._sym_var = tk.StringVar()
        self._sym_entry = PlaceholderEntry(
            sym_frm, placeholder="e.g.  ntdll.map, ntoskrnl.pdb, symbols.sym",
            textvariable=self._sym_var,
            bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
            font=("Consolas", 10), relief="flat", bd=5)
        self._sym_entry.grid(row=0, column=1, sticky="ew")
        app.register_placeholder(self._sym_entry)

        def _browse_sym():
            path = filedialog.askopenfilename(
                filetypes=[("Symbol files", "*.map;*.pdb;*.dbg;*.sym;*.txt"),
                           ("MAP files", "*.map"), ("PDB files", "*.pdb"),
                           ("DBG files", "*.dbg"), ("All", "*.*")])
            if path:
                self._sym_entry.set_value(path)
        ttk.Button(sym_frm, text="Browse \u2026", command=_browse_sym).grid(
            row=0, column=2, padx=(8, 0))
        ttk.Button(sym_frm, text="\U0001F4E5  Load Symbols", command=self._load_symbols).grid(
            row=0, column=3, padx=(8, 0))
        ttk.Button(sym_frm, text="\U0001F4E4  Unload Symbols", command=self._unload_symbols).grid(
            row=0, column=4, padx=(8, 0))

        self._loaded_symbols = {}
        self._sym_meta = {}
        self.sym_status_var = tk.StringVar(value="")
        ttk.Label(sym_frm, textvariable=self.sym_status_var, foreground=T["green"],
                  font=("Segoe UI", 9)).grid(row=0, column=5, padx=(8, 0))

        # Click mode in lim_frm
        ttk.Label(lim_frm, text="   Click mode:").pack(side="left", padx=5)
        self._click_mode_var = tk.StringVar(value="Assembly")
        ttk.Combobox(lim_frm, textvariable=self._click_mode_var, width=10,
                     values=["Assembly", "Pseudo-C", "Hex Dump"],
                     state="readonly").pack(side="left", padx=2)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Decompile PE exports to C pseudocode \u2014 recognizes kernel APIs, NTSTATUS, IRP codes", row=5)

        self.output = TabbedOutput(self)
        self.output.grid(row=6, column=0, sticky="nsew", padx=10, pady=(0, 10))
        setup_func_link(self.output, self._get_pe, app, mode_var=self._click_mode_var,
                        symbols_getter=lambda: self._loaded_symbols or None)

    def _get_func(self):
        return self._func_entry.get_value()

    def _load_symbols(self):
        """Load a symbol file (.map, .pdb, .dbg, .sym)."""
        sym_path = self._sym_entry.get_value()
        if not sym_path:
            messagebox.showwarning("No file", "Enter or browse for a symbol file.\n\n"
                                   "Supported: .map (MSVC/GCC/IDA), .pdb, .dbg, .sym")
            return
        if not os.path.isfile(sym_path):
            messagebox.showerror("Not found", f"File not found:\n{sym_path}")
            return

        self.status_var.set(f"\u23F3 Loading symbols from {os.path.basename(sym_path)}...")

        def work(progress_cb):
            progress_cb(f"Loading symbols from {os.path.basename(sym_path)}\u2026", 30)
            return _sym_loader().load_symbols(sym_path, pe_path=self._get_pe())

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                return
            symbols, meta = result
            self._loaded_symbols = _sym_loader().merge_symbols(self._loaded_symbols, symbols)
            self._sym_meta = meta
            n = meta.get('total_symbols', 0)
            fmt = meta.get('format', '?')
            err = meta.get('error', '')
            if err:
                self.sym_status_var.set(f"\u26A0 {err}")
                self.status_var.set(f"\u26A0 {err}")
            else:
                self.sym_status_var.set(f"\u2705 {n} symbols ({fmt})")
                self.status_var.set(
                    f"\u2705 Loaded {n} symbols from {os.path.basename(sym_path)} "
                    f"[{fmt}] — total: {len(self._loaded_symbols)}")

        run_with_progress_dialog(self.app, f"Loading symbols\u2026", work, done)

    def _unload_symbols(self):
        """Clear all loaded symbols."""
        self._loaded_symbols = {}
        self._sym_meta = {}
        self.sym_status_var.set("")
        self.status_var.set("\U0001F4E4 Symbols unloaded")

    def _decompile_one(self):
        path = self._get_pe()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select a PE file and enter a function name or RVA.\n\nExamples:\n  NtCreateFile\n  0x0004AE10")
            return

        if func.startswith('0x') or func.startswith('0X'):
            func_val = int(func, 16)
        else:
            func_val = func

        expand = self.expand_var.get()
        syms = self._loaded_symbols if self._loaded_symbols else None
        sym_tag = " +sym" if syms else ""
        self.output.new_tab(f"Pseudo-C{sym_tag}: {func}")

        def work(progress_cb):
            progress_cb(f"Loading PE: {os.path.basename(path)}", 10)
            if syms:
                progress_cb(f"Decompiling {func} with {len(syms)} symbols\u2026", 30)
            else:
                progress_cb(f"Decompiling {func}\u2026", 30)
            result = _decompiler().decompile(path, func_val, symbols=syms, expand_calls=expand)
            progress_cb("Formatting output\u2026", 90)
            return result

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

        run_with_progress_dialog(self.app, f"Decompiling {func}\u2026", work, done)

    def _disasm_one(self):
        """Disassemble a function showing annotated x86 assembly."""
        path = self._get_pe()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select PE and enter function name/RVA.")
            return
        syms = self._loaded_symbols if self._loaded_symbols else None
        self.output.new_tab(f"ASM: {func}")

        def work(progress_cb):
            progress_cb(f"Loading PE: {os.path.basename(path)}", 10)
            progress_cb(f"Disassembling {func}\u2026", 30)
            return _behavior().disassemble_function(path, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("\u274C Not found")
                return
            for line in result.split('\n'):
                if line.startswith(';'):
                    output_write(self.output, line + '\n', "dim")
                elif '; \u2192' in line:
                    output_write(self.output, line + '\n', "peach")
                elif 'call' in line.lower():
                    output_write(self.output, line + '\n', "ok")
                elif 'ret' in line or 'retn' in line:
                    output_write(self.output, line + '\n', "warn")
                elif 'jmp' in line or line.strip().startswith('j'):
                    output_write(self.output, line + '\n', "peach")
                else:
                    output_write(self.output, line + '\n')
            self.status_var.set(f"\u2705 Assembly: {func}")

        run_with_progress_dialog(self.app, f"Disassembling {func}\u2026", work, done)

    def _hexdump_one(self):
        """Show raw hex dump of a function's machine code."""
        path = self._get_pe()
        func = self._get_func()
        if not path or not func:
            messagebox.showwarning("Missing", "Select PE and enter function name/RVA.")
            return
        self.output.new_tab(f"HEX: {func}")

        def work(progress_cb):
            progress_cb(f"Reading {func}\u2026", 30)
            import pefile
            pe = pefile.PE(path, fast_load=False)
            rva = None
            if isinstance(func, str) and (func.startswith('0x') or func.startswith('0X')):
                rva = int(func, 16)
            elif hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name and exp.name.decode('ascii', errors='replace') == func:
                        rva = exp.address
                        break
            if rva is None:
                pe.close()
                return None
            img_base = pe.OPTIONAL_HEADER.ImageBase
            va = img_base + rva
            offset = pe.get_offset_from_rva(rva)
            data = pe.get_data(rva, min(4096, len(pe.__data__) - offset))
            pe.close()
            return (data, va, rva)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("\u274C Not found")
                return
            data, va, rva = result
            output_write(self.output, f"  HEX DUMP: {func}\n", "title")
            output_write(self.output, f"  RVA: 0x{rva:08X}  VA: 0x{va:08X}  Size: {len(data)} bytes\n\n", "dim")
            output_write(self.output, f"  {'Offset':<12} {'Hex':<50} {'ASCII'}\n", "heading")
            output_write(self.output, f"  {'\u2500'*12} {'\u2500'*50} {'\u2500'*16}\n", "dim")
            for i in range(0, min(len(data), 2048), 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02X}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                addr = va + i
                # Colorize: highlight CC (int3), C3 (ret), E8 (call)
                tag = None
                if b'\xC3' in chunk:
                    tag = "warn"
                elif b'\xE8' in chunk:
                    tag = "ok"
                elif b'\xCC' in chunk:
                    tag = "error"
                output_write(self.output, f"  {addr:08X}     {hex_str:<50s} {ascii_str}\n", tag)
                if b'\xC3' in chunk or b'\xCC' in chunk:
                    # Likely end of function
                    if i > 32:
                        break
            self.status_var.set(f"\u2705 Hex dump: {func} ({min(len(data), 2048)} bytes)")

        run_with_progress_dialog(self.app, f"Hex dump: {func}\u2026", work, done)

    def _discover(self):
        path = self._get_pe()
        if not path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        try:
            mx = int(self.max_var.get())
        except ValueError:
            mx = 50
        self.output.new_tab("Discover")

        def work(progress_cb):
            progress_cb(f"Discovering functions (max {mx})\u2026", 10)
            return _decompiler().decompile_no_symbols(path, max_funcs=mx)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            for name, code in result.items():
                output_write(self.output, f"{'='*70}\n", "dim")
                output_write(self.output, f"  {name}", "func_link")
                output_write(self.output, "\n", "dim")
                self._colorize(code)
                output_write(self.output, "\n")
            self.status_var.set(f"\u2705 Discovered {len(result)} functions")

        run_with_progress_dialog(self.app, f"Discovering functions\u2026", work, done)

    def _batch(self):
        path = self._get_pe()
        if not path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        try:
            mx = int(self.max_var.get())
        except ValueError:
            mx = 100
        self.output.new_tab("Batch")
        syms = self._loaded_symbols if self._loaded_symbols else None

        def work(progress_cb):
            progress_cb(f"Batch decompiling exports (max {mx})\u2026", 10)
            return _decompiler().batch_decompile(path, max_funcs=mx, symbols=syms)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            for name, code in result.items():
                output_write(self.output, f"{'='*70}\n", "dim")
                output_write(self.output, f"  {name}", "func_link")
                output_write(self.output, "\n", "dim")
                self._colorize(code)
                output_write(self.output, "\n")
            self.status_var.set(f"\u2705 Decompiled {len(result)} exports")

        run_with_progress_dialog(self.app, f"Batch decompiling {mx} exports\u2026", work, done)

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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)
        ttk.Separator(btn_frm, orient="vertical").pack(side="left", padx=8, fill="y", pady=2)
        ttk.Label(btn_frm, text="Click mode:").pack(side="left", padx=(0, 3))
        self._click_mode_var = tk.StringVar(value="Assembly")
        ttk.Combobox(btn_frm, textvariable=self._click_mode_var, width=10,
                     values=["Assembly", "Pseudo-C", "Hex Dump"],
                     state="readonly").pack(side="left", padx=2)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Deep NT version compatibility analysis \u2014 detects syscall, calling convention, and structure differences", row=4)

        self.output = TabbedOutput(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))
        setup_func_link(self.output, self._get_a, app, mode_var=self._click_mode_var)

    def _analyze_both(self):
        pa, pb = self._get_a(), self._get_b()
        if not pa or not pb:
            messagebox.showwarning("Missing", "Select both PE files.\n\nExample:\n  A: ntdll.dll (Win2000)\n  B: ntdll.dll (ReactOS)")
            return
        la, lb = self.label_a_var.get(), self.label_b_var.get()
        self.status_var.set("\u23F3 Analyzing compatibility...")
        self.output.new_tab("Compat Analysis")

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

        run_with_progress(self, work, done)

    def _analyze_single(self):
        pa = self._get_a()
        if not pa:
            messagebox.showwarning("Missing", "Select PE File A.")
            return
        la = self.label_a_var.get()
        self.status_var.set("\u23F3 Analyzing single PE...")
        self.output.new_tab("Single Analysis")

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

        run_with_progress(self, work, done)

    def _show_known(self):
        self.output.new_tab("Known APIs")
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
        self.output.new_tab("Bugcheck")
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
#  Progress Dialog — Modal dialog with percentage and current-item display
# ══════════════════════════════════════════════════════════════════════════

class ProgressDialog(tk.Toplevel):
    """Modal progress dialog with percentage, current operation, and cancel."""

    def __init__(self, parent, title="Analyzing..."):
        super().__init__(parent)
        self.title(title)
        self.geometry("520x180")
        self.resizable(False, False)
        self.configure(bg=T["bg"])
        self.transient(parent)
        self.grab_set()
        self.cancelled = False

        # Center on parent
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - 260
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - 90
        self.geometry(f"+{px}+{py}")

        self.op_var = tk.StringVar(value="Initializing...")
        self.item_var = tk.StringVar(value="")
        self.pct_var = tk.IntVar(value=0)

        ttk.Label(self, textvariable=self.op_var,
                  font=("Segoe UI", 11, "bold")).pack(padx=20, pady=(18, 4), anchor="w")

        self.bar = ttk.Progressbar(self, mode='determinate',
                                    maximum=100, variable=self.pct_var, length=480)
        self.bar.pack(padx=20, pady=6)

        self.item_lbl = ttk.Label(self, textvariable=self.item_var,
                                   foreground=T["fg_dim"], font=("Consolas", 9))
        self.item_lbl.pack(padx=20, anchor="w")

        btn_frm = tk.Frame(self, bg=T["bg"])
        btn_frm.pack(pady=(8, 12))
        self.pct_lbl = ttk.Label(btn_frm, text="0%", font=("Segoe UI", 10, "bold"))
        self.pct_lbl.pack(side="left", padx=(0, 20))
        ttk.Button(btn_frm, text="Cancel", command=self._cancel).pack(side="left")

        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def update_progress(self, message, pct, item=""):
        """Thread-safe progress update. Call from any thread."""
        def _update():
            self.op_var.set(message)
            self.pct_var.set(min(int(pct), 100))
            self.pct_lbl.configure(text=f"{min(int(pct), 100)}%")
            if item:
                self.item_var.set(item)
        try:
            self.after(0, _update)
        except tk.TclError:
            pass

    def _cancel(self):
        self.cancelled = True
        try:
            self.destroy()
        except tk.TclError:
            pass

    def close(self):
        try:
            self.destroy()
        except tk.TclError:
            pass


def run_with_progress_dialog(parent, title, work_fn, done_fn):
    """Run work_fn(progress_callback) in a thread with a modal progress dialog.
    progress_callback(message, pct) updates the dialog.
    done_fn(result) is called on the main thread when done."""
    dlg = ProgressDialog(parent, title)

    def progress_cb(message, pct):
        if dlg.cancelled:
            return
        dlg.update_progress(message, pct)

    def runner():
        try:
            result = work_fn(progress_cb)
        except Exception as e:
            result = e
        def finish():
            dlg.close()
            done_fn(result)
        try:
            parent.after(0, finish)
        except tk.TclError:
            pass

    t = threading.Thread(target=runner, daemon=True)
    t.start()


# ══════════════════════════════════════════════════════════════════════════
#  Tab 13: Deep Function Analyzer
# ══════════════════════════════════════════════════════════════════════════

class DeepAnalyzerTab(ttk.Frame):
    """Deep analysis: discover ALL functions (exported + internal),
    profile each one, browse cross-references, view code, and port."""

    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(10, weight=1)
        self._func_map = None
        self._history = []       # list of (title, output_text) for back/forward
        self._history_idx = -1

        _, self._get_pe, self.pe_var = make_file_picker(
            self, "PE File:", row=0,
            placeholder=EXAMPLES["pe"], app=app)

        # Function filter / search
        func_frm = tk.Frame(self, bg=T["bg"])
        func_frm.grid(row=1, column=0, sticky="ew", padx=12, pady=5)
        func_frm.columnconfigure(1, weight=1)
        ttk.Label(func_frm, text="Function:", width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))
        self.func_var = tk.StringVar()
        ent = PlaceholderEntry(func_frm, placeholder="e.g.  NtCreateFile, sub_77F81234",
                               textvariable=self.func_var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        ent.grid(row=0, column=1, sticky="ew")
        app.register_placeholder(ent)
        self._func_entry = ent

        # Buttons row 1: Main actions
        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F50D  Discover All Functions", style="Accent.TButton",
                   command=self._discover).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CB  Profile",
                   command=self._profile).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F517  XRefs",
                   command=self._show_xrefs).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4BB  Code",
                   command=self._show_code).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4E6  Dependencies",
                   command=self._show_deps).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\U0001F4CA  Statistics",
                   command=self._statistics).pack(side="left", padx=5)

        # Buttons row 2: Compare + navigation
        btn_frm2 = make_button_bar(self, row=3)
        ttk.Button(btn_frm2, text="\u2194  Deep Compare",
                   command=self._deep_compare).pack(side="left", padx=5)
        ttk.Button(btn_frm2, text="\U0001F4CA  Batch Compare",
                   command=self._batch_deep).pack(side="left", padx=5)
        ttk.Button(btn_frm2, text="\u25C0 Back",
                   command=self._history_back).pack(side="left", padx=(20, 3))
        ttk.Button(btn_frm2, text="Forward \u25B6",
                   command=self._history_forward).pack(side="left", padx=3)
        ttk.Button(btn_frm2, text="\u2716  Clear",
                   command=lambda: self.output.close_all()).pack(side="left", padx=(20, 5))

        # Compare with file picker
        _, self._get_pe_b, self.pe_b_var = make_file_picker(
            self, "Compare with:", row=4,
            placeholder=EXAMPLES["ros_dll"], app=app)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Deep analysis: discover internal functions, profile, XRefs, code, dependencies", row=5)

        # Options row
        opt_frm = tk.Frame(self, bg=T["bg"])
        opt_frm.grid(row=6, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(opt_frm, text="Max functions:").pack(side="left", padx=5)
        self.max_var = tk.StringVar(value="3000")
        tk.Entry(opt_frm, textvariable=self.max_var, bg=T["entry_bg"], fg=T["fg"],
                 insertbackground=T["fg"], font=("Consolas", 10), relief="flat",
                 bd=5, width=8).pack(side="left", padx=5)
        self.show_internal_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frm, text="Show internal (private) functions",
                        variable=self.show_internal_var).pack(side="left", padx=15)
        self._hist_var = tk.StringVar(value="")
        ttk.Label(opt_frm, textvariable=self._hist_var, foreground=T["fg_dim"]).pack(side="right", padx=15)

        # Symbol file (optional)
        sym_frm = tk.Frame(self, bg=T["bg"])
        sym_frm.grid(row=7, column=0, sticky="ew", padx=12, pady=3)
        ttk.Label(sym_frm, text="Symbols:", foreground=T["fg_dim"]).pack(side="left", padx=5)
        self.sym_var = tk.StringVar()
        sym_ent = PlaceholderEntry(sym_frm, placeholder="optional \u2014 .map / .pdb / .dbg for better names",
                                   textvariable=self.sym_var,
                                   bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                                   font=("Consolas", 10), relief="flat", bd=5)
        sym_ent.pack(side="left", fill="x", expand=True, padx=5)
        app.register_placeholder(sym_ent)
        self._sym_entry = sym_ent
        ttk.Button(sym_frm, text="Browse\u2026", command=self._browse_symbols).pack(side="left", padx=5)
        ttk.Button(sym_frm, text="Load", command=self._load_symbols).pack(side="left", padx=3)

        # Click mode in opt_frm
        ttk.Label(opt_frm, text="   Click mode:").pack(side="left", padx=5)
        self._click_mode_var = tk.StringVar(value="Assembly")
        ttk.Combobox(opt_frm, textvariable=self._click_mode_var, width=10,
                     values=["Assembly", "Pseudo-C", "Hex Dump"],
                     state="readonly").pack(side="left", padx=2)

        self.output = TabbedOutput(self)
        self.output.grid(row=10, column=0, sticky="nsew", padx=10, pady=(0, 10))
        setup_func_link(self.output, self._get_pe, app, mode_var=self._click_mode_var)

        # Right-click context menu on output
        self._context_menu = tk.Menu(self.output, tearoff=0,
                                      bg=T["bg_light"], fg=T["fg"],
                                      activebackground=T["accent"],
                                      activeforeground=T["bg_dark"],
                                      font=("Segoe UI", 10))
        self.output.bind("<Button-3>", self._on_right_click)

    def _get_func(self):
        return self._func_entry.get_value()

    def _browse_symbols(self):
        path = filedialog.askopenfilename(
            filetypes=[("Symbol files", "*.map *.pdb *.dbg *.sym"), ("All", "*.*")])
        if path:
            self._sym_entry.set_value(path)

    def _load_symbols(self):
        sym_path = self._sym_entry.get_value()
        if not sym_path:
            messagebox.showwarning("Missing", "Browse to a symbol file first.")
            return
        if not self._func_map:
            messagebox.showwarning("Missing", "Run 'Discover All Functions' first.")
            return
        self.status_var.set("\u23F3 Loading symbols\u2026")
        def work():
            result = _sym_loader().load_symbols(sym_path, pe_path=self._get_pe())
            if isinstance(result, tuple):
                sym_dict, _ = result
            else:
                sym_dict = result
            if not isinstance(sym_dict, dict):
                return 0
            merged = 0
            for va, name in sym_dict.items():
                if va in self._func_map.functions and name:
                    self._func_map.functions[va].name = name
                    self._func_map._va_to_name[va] = name
                    merged += 1
            return merged
        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                return
            self.status_var.set(f"\u2705 Loaded symbols: {result} functions renamed")
        run_with_progress(self, work, done)

    # \u2500\u2500 History system \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    def _save_to_history(self, title):
        """Save current output to history."""
        self.output.configure(state="normal")
        text = self.output.get("1.0", "end-1c")
        self.output.configure(state="disabled")
        if self._history_idx < len(self._history) - 1:
            self._history = self._history[:self._history_idx + 1]
        self._history.append((title, text))
        self._history_idx = len(self._history) - 1
        self._update_hist_label()

    def _history_back(self):
        if self._history_idx > 0:
            self._history_idx -= 1
            title, text = self._history[self._history_idx]
            output_clear(self.output)
            output_write(self.output, text)
            self.status_var.set(f"\u25C0 {title}")
            self._update_hist_label()

    def _history_forward(self):
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            title, text = self._history[self._history_idx]
            output_clear(self.output)
            output_write(self.output, text)
            self.status_var.set(f"\u25B6 {title}")
            self._update_hist_label()

    def _update_hist_label(self):
        n = len(self._history)
        if n > 0:
            self._hist_var.set(f"History: {self._history_idx + 1}/{n}")
        else:
            self._hist_var.set("")

    # \u2500\u2500 Right-click context menu \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    def _on_right_click(self, event):
        try:
            idx = self.output.index(f"@{event.x},{event.y}")
            line = self.output.get(f"{idx} linestart", f"{idx} lineend").strip()
        except tk.TclError:
            line = ""
        func_name = self._extract_func_name(line)
        menu = self._context_menu
        menu.delete(0, "end")
        if func_name:
            menu.add_command(label=f"\u25B8 Select: {func_name}",
                             command=lambda fn=func_name: self._select_function(fn))
            menu.add_separator()
            menu.add_command(label="\U0001F4CB  Profile Function",
                             command=lambda fn=func_name: self._action_on(fn, 'profile'))
            menu.add_command(label="\U0001F4BB  View Code (Disassembly)",
                             command=lambda fn=func_name: self._action_on(fn, 'code'))
            menu.add_command(label="\U0001F517  Show Cross-References",
                             command=lambda fn=func_name: self._action_on(fn, 'xrefs'))
            menu.add_command(label="\U0001F4E6  Porting Dependencies",
                             command=lambda fn=func_name: self._action_on(fn, 'deps'))
            menu.add_separator()
            menu.add_command(label="\U0001F9EC  Analyze Behavior",
                             command=lambda fn=func_name: self._action_on(fn, 'behavior'))
            menu.add_command(label="\U0001F500  Control Flow Analysis",
                             command=lambda fn=func_name: self._action_on(fn, 'control_flow'))
            menu.add_command(label="\U0001F4DC  Decompile to C",
                             command=lambda fn=func_name: self._action_on(fn, 'decompile'))
            menu.add_separator()
            menu.add_command(label="\u2194  Deep Compare with File B",
                             command=lambda fn=func_name: self._action_on(fn, 'deep_compare'))
            menu.add_command(label="\U0001F50D  Scan System32 for Callers",
                             command=lambda fn=func_name: self._action_on(fn, 'system_xref'))
        else:
            menu.add_command(label="(no function detected)", state="disabled")
        menu.add_separator()
        menu.add_command(label="Copy Output", command=self._copy_output)
        menu.tk_popup(event.x_root, event.y_root)

    def _extract_func_name(self, line):
        """Extract a function name from a text line."""
        line = line.strip()
        if not line:
            return None
        m = re.match(r'^(\w+)\s+(EXPORT|internal|syscall|thunk)', line)
        if m:
            return m.group(1)
        m = re.match(r'^[\u2192\u2190\u25B8]\s*(\S+)', line)
        if m:
            name = m.group(1)
            return name.split('!')[-1] if '!' in name else name
        m = re.search(r'\b(sub_[0-9A-Fa-f]{6,8})\b', line)
        if m:
            return m.group(1)
        m = re.match(r'^([A-Z][a-zA-Z0-9_]+)', line)
        if m and len(m.group(1)) >= 3:
            return m.group(1)
        return None

    def _select_function(self, func_name):
        self._func_entry.set_value(func_name)

    def _action_on(self, func_name, action):
        self._func_entry.set_value(func_name)
        actions = {
            'profile': self._profile, 'code': self._show_code,
            'xrefs': self._show_xrefs, 'deps': self._show_deps,
            'behavior': lambda: self._cross_tab_behavior(func_name),
            'control_flow': lambda: self._cross_tab_control_flow(func_name),
            'decompile': lambda: self._cross_tab_decompile(func_name),
            'deep_compare': self._deep_compare,
            'system_xref': lambda: self._cross_tab_system_xref(func_name),
        }
        fn = actions.get(action)
        if fn:
            fn()

    def _copy_output(self):
        self.output.configure(state="normal")
        text = self.output.get("1.0", "end-1c")
        self.output.configure(state="disabled")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Copied to clipboard")

    # \u2500\u2500 Cross-tab actions \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    def _cross_tab_behavior(self, func_name):
        pe_path = self._get_pe()
        if not pe_path:
            return
        self.status_var.set(f"\u23F3 Analyzing behavior of {func_name}\u2026")
        self.output.new_tab("Behavior")
        def work():
            return _behavior().detect_api_patterns(pe_path, func_name)
        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func_name}' not found in exports.\n", "error")
                self.status_var.set("\u274C Not found (must be exported for behavior analysis)")
                return
            output_write(self.output, f"  BEHAVIOR PATTERNS: {func_name}\n\n", "title")
            fp = result['fingerprint']
            output_write(self.output, f"  Instructions: {fp.total_insns}  |  Blocks: {fp.block_count}\n")
            if fp.syscall_number is not None:
                output_write(self.output, f"  Syscall: 0x{fp.syscall_number:X}\n", "ok")
            for ptype, pdesc in result['patterns']:
                output_write(self.output, f"    [{ptype}] {pdesc}\n", "peach")
            if fp.api_calls:
                output_write(self.output, f"\n  API calls ({len(fp.api_calls)}):\n", "heading")
                for call in fp.api_calls:
                    output_write(self.output, f"    \u2192 {call}\n", "peach")
            self._save_to_history(f"Behavior: {func_name}")
            self.status_var.set(f"\u2705 Behavior: {func_name}")
        run_with_progress(self, work, done)

    def _cross_tab_control_flow(self, func_name):
        pe_path = self._get_pe()
        if not pe_path:
            return
        self.status_var.set(f"\u23F3 Control flow of {func_name}\u2026")
        self.output.new_tab("Control Flow")
        def work():
            return _behavior().analyze_control_flow(pe_path, func_name)
        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func_name}' not found.\n", "error")
                return
            report = _behavior().format_control_flow(result)
            for line in report.split('\n'):
                output_write(self.output, line + '\n')
            self._save_to_history(f"ControlFlow: {func_name}")
            self.status_var.set(f"\u2705 Control flow: {func_name}")
        run_with_progress(self, work, done)

    def _cross_tab_decompile(self, func_name):
        pe_path = self._get_pe()
        if not pe_path:
            return
        self.status_var.set(f"\u23F3 Decompiling {func_name}\u2026")
        self.output.new_tab(f"Pseudo-C: {func_name}")
        def work():
            dec = _decompiler().X86Decompiler(pe_path)
            return dec.decompile(func_name)
        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, f"  // Decompiled: {func_name}\n\n", "title")
            output_write(self.output, result + '\n')
            self._save_to_history(f"Decompile: {func_name}")
            self.status_var.set(f"\u2705 Decompiled: {func_name}")
        run_with_progress(self, work, done)

    def _cross_tab_system_xref(self, func_name):
        scan_dir = r"C:\WINNT\System32"
        if not os.path.isdir(scan_dir):
            scan_dir = r"C:\Windows\System32"
        if not os.path.isdir(scan_dir):
            messagebox.showwarning("Missing", "Cannot find System32 directory.")
            return
        self.output.new_tab("System XRef")
        pe_exts = {'.dll', '.sys', '.exe', '.drv', '.cpl', '.ocx', '.scr'}
        pe_files = [os.path.join(scan_dir, f) for f in os.listdir(scan_dir)
                    if os.path.splitext(f)[1].lower() in pe_exts]
        def work(progress_cb):
            return _deep_analyzer().scan_system_xrefs_detailed(
                func_name, pe_files, progress_callback=progress_cb)
        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, f"  SYSTEM-WIDE XREF: {func_name}\n", "title")
            output_write(self.output, f"  {len(result)} PE files reference {func_name}\n\n", "ok")
            hdr = f"  {'PE File':<40} {'Import From':<30} {'IAT Address':<16} {'Type'}\n"
            output_write(self.output, hdr, "heading")
            sep = f"  {'\u2500'*40} {'\u2500'*30} {'\u2500'*16} {'\u2500'*10}\n"
            output_write(self.output, sep, "dim")
            for xref in result:
                iat = f"0x{xref.caller_va:08X}" if xref.caller_va else "N/A"
                output_write(self.output,
                    f"  {xref.caller_name:<40} {xref.callee_name:<30} {iat:<16} {xref.xref_type}\n")
            self._save_to_history(f"SystemXRef: {func_name}")
            self.status_var.set(f"\u2705 Found {len(result)} references to {func_name}")
        run_with_progress_dialog(self.app, f"Scanning for {func_name}\u2026", work, done)

    # \u2500\u2500 New analysis methods \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    def _show_code(self):
        """Show full annotated disassembly of a function."""
        func_name = self._get_func()
        if not func_name:
            messagebox.showwarning("Missing", "Enter a function name.")
            return
        if not self._func_map:
            pe_path = self._get_pe()
            if not pe_path:
                messagebox.showwarning("Missing", "Run 'Discover All Functions' first, or select a PE file.")
                return
            self.status_var.set(f"\u23F3 Loading {func_name}\u2026")
            def work(progress_cb):
                fm = _deep_analyzer().PEFunctionMap(pe_path, progress_callback=progress_cb)
                fm.discover_all_functions()
                fm.analyze_all_functions()
                fm.build_xrefs()
                return fm
            def done(result):
                if isinstance(result, Exception):
                    self.status_var.set(f"\u274C Error: {result}")
                    return
                self._func_map = result
                self._show_code_impl(func_name)
            run_with_progress_dialog(self.app, "Loading PE\u2026", work, done)
            return
        self._show_code_impl(func_name)

    def _show_code_impl(self, func_name):
        self.output.new_tab("Code")
        code = _deep_analyzer().disassemble_function_full(self._func_map, func_name)
        if code is None:
            output_write(self.output, f"  Function '{func_name}' not found.\n", "error")
            self.status_var.set("\u274C Not found")
            return
        for line in code.split('\n'):
            if line.startswith(';'):
                output_write(self.output, line + '\n', "dim")
            elif '; \u2192' in line:
                output_write(self.output, line + '\n', "peach")
            elif '; arg' in line:
                output_write(self.output, line + '\n', "ok")
            elif '; local_' in line:
                output_write(self.output, line + '\n', "warn")
            elif 'call' in line.lower():
                output_write(self.output, line + '\n', "ok")
            elif line.split() and len(line.split()) > 1 and line.split()[1].startswith('ret'):
                output_write(self.output, line + '\n', "warn")
            else:
                output_write(self.output, line + '\n')
        self._save_to_history(f"Code: {func_name}")
        self.status_var.set(f"\u2705 Code: {func_name}")

    def _show_deps(self):
        """Show porting dependencies for a function."""
        func_name = self._get_func()
        if not func_name:
            messagebox.showwarning("Missing", "Enter a function name.")
            return
        if not self._func_map:
            messagebox.showwarning("Missing", "Run 'Discover All Functions' first.")
            return
        self.output.new_tab("Dependencies")
        deps = _deep_analyzer().get_function_dependencies(self._func_map, func_name)
        if not deps:
            output_write(self.output, f"  Function '{func_name}' not found.\n", "error")
            self.status_var.set("\u274C Not found")
            return
        report = _deep_analyzer().format_dependencies(deps)
        for line in report.split('\n'):
            if '\u26A0' in line:
                output_write(self.output, line + '\n', "warn")
            elif '\u2713' in line:
                output_write(self.output, line + '\n', "ok")
            elif 'PORTING' in line or 'SUMMARY' in line:
                output_write(self.output, line + '\n', "title")
            elif line.strip().startswith('\u2192'):
                output_write(self.output, line + '\n', "peach")
            elif line.strip().startswith('\u2190'):
                output_write(self.output, line + '\n', "warn")
            elif '\u2500' in line or '=' * 10 in line:
                output_write(self.output, line + '\n', "dim")
            elif any(h in line for h in ('API IMPORTS', 'INTERNAL CALLS', 'STRUCTURE',
                                          'DATA REF', 'STRING REF', 'CALLERS', 'SUB-DEP')):
                output_write(self.output, line + '\n', "heading")
            else:
                output_write(self.output, line + '\n')
        self._save_to_history(f"Dependencies: {func_name}")
        self.status_var.set(f"\u2705 Dependencies: {func_name}")

    # \u2500\u2500 Core operations \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    def _discover(self):
        """Discover ALL functions in the PE — exports + internal via prologue scan."""
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        self.output.new_tab("Discover")

        def work(progress_cb):
            fm = _deep_analyzer().PEFunctionMap(pe_path, progress_callback=progress_cb)
            fm.discover_all_functions()
            progress_cb("Analyzing all functions...", 30)
            try:
                max_f = int(self.max_var.get())
            except ValueError:
                max_f = 3000
            fm.analyze_all_functions(max_functions=max_f)
            progress_cb("Building cross-references...", 75)
            fm.build_xrefs()
            progress_cb("Done", 100)
            return fm

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._func_map = result
            fm = result
            funcs = fm.functions
            n_exp = sum(1 for f in funcs.values() if f.is_exported)
            n_int = sum(1 for f in funcs.values() if not f.is_exported)
            n_sys = sum(1 for f in funcs.values() if f.is_syscall_stub)
            n_thunk = sum(1 for f in funcs.values() if f.is_thunk)

            output_write(self.output, f"  DEEP FUNCTION DISCOVERY: {os.path.basename(pe_path)}\n", "title")
            output_write(self.output, f"  {'='*65}\n\n", "dim")
            output_write(self.output, f"  Total functions found: {len(funcs)}\n", "ok")
            output_write(self.output, f"    Exported (public):  {n_exp}\n", "ok")
            output_write(self.output, f"    Internal (private): {n_int}\n", "warn")
            output_write(self.output, f"    Syscall stubs:      {n_sys}\n")
            output_write(self.output, f"    Thunks/forwarders:  {n_thunk}\n")
            output_write(self.output, f"    Cross-references:   {len(fm.xrefs)}\n")
            output_write(self.output, f"\n  {'\u2500'*65}\n", "dim")
            output_write(self.output, "  Right-click any function for actions (profile, code, xrefs, decompile\u2026)\n\n", "dim")

            show_int = self.show_internal_var.get()
            output_write(self.output, f"\n  {'Name':<40} {'Type':<10} {'Conv':<10} "
                         f"{'Args':<6} {'Size':<8} {'Blocks':<8} {'Callers':<8} {'Calls'}\n", "heading")
            output_write(self.output, f"  {'\u2500'*40} {'\u2500'*10} {'\u2500'*10} "
                         f"{'\u2500'*6} {'\u2500'*8} {'\u2500'*8} {'\u2500'*8} {'\u2500'*8}\n", "dim")

            for va, func in funcs.items():
                if not show_int and not func.is_exported:
                    continue
                ftype = "EXPORT" if func.is_exported else "internal"
                if func.is_syscall_stub:
                    ftype = f"syscall"
                elif func.is_thunk:
                    ftype = "thunk"
                tag = "ok" if func.is_exported else "dim"
                output_write(self.output, f"  {func.name:<40}", "func_link")
                rest = (f" {ftype:<10} {func.calling_convention:<10} "
                        f"{func.n_args:<6} {func.size:<8} {func.n_basic_blocks:<8} "
                        f"{len(func.called_by):<8} {len(func.calls_out)}\n")
                output_write(self.output, rest, tag)

            self._save_to_history(f"Discover: {os.path.basename(pe_path)}")
            self.status_var.set(f"\u2705 Found {len(funcs)} functions "
                               f"({n_exp} exported, {n_int} internal, {len(fm.xrefs)} xrefs)")

        run_with_progress_dialog(self.app, f"Analyzing {os.path.basename(pe_path)}...", work, done)

    def _profile(self):
        """Show detailed profile of a single function."""
        func_name = self._get_func()
        if not func_name:
            messagebox.showwarning("Missing", "Enter a function name (e.g. NtCreateFile, sub_77F81234).")
            return

        if self._func_map:
            func = self._func_map.find_function_by_name(func_name)
            if func:
                self.output.new_tab("Profile")
                report = _deep_analyzer().format_function_profile_with_map(func, self._func_map)
                for line in report.split('\n'):
                    if line.strip().startswith('='):
                        output_write(self.output, line + '\n', "dim")
                    elif 'API IMPORTS' in line or 'INTERNAL CALLS' in line or 'CALLED BY' in line \
                            or 'STRING REF' in line or 'STRUCTURE' in line or 'DATA REF' in line:
                        output_write(self.output, line + '\n', "heading")
                    elif line.strip().startswith('\u2192'):
                        output_write(self.output, line + '\n', "peach")
                    elif line.strip().startswith('\u2190'):
                        output_write(self.output, line + '\n', "warn")
                    elif 'EXPORTED' in line or 'INTERNAL' in line:
                        output_write(self.output, line + '\n', "title")
                    else:
                        output_write(self.output, line + '\n')
                self._save_to_history(f"Profile: {func_name}")
                self.status_var.set(f"\u2705 Profile: {func_name}")
                return

        # No cached map — analyze just this function from PE
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Run 'Discover All Functions' first, or select a PE file.")
            return
        self.status_var.set(f"\u23F3 Profiling {func_name}...")
        self.output.new_tab(f"Profile: {func_name}")

        def work(progress_cb):
            fm = _deep_analyzer().PEFunctionMap(pe_path, progress_callback=progress_cb)
            fm.discover_all_functions()
            func = fm.find_function_by_name(func_name)
            if func:
                fm.analyze_function(func.va)
                fm.build_xrefs()
            return (fm, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            fm, func = result
            self._func_map = fm
            if not func:
                output_write(self.output, f"  Function '{func_name}' not found.\n", "error")
                self.status_var.set("\u274C Function not found")
                return
            report = _deep_analyzer().format_function_profile_with_map(func, fm)
            for line in report.split('\n'):
                output_write(self.output, line + '\n')
            self._save_to_history(f"Profile: {func_name}")
            self.status_var.set(f"\u2705 Profile: {func_name}")

        run_with_progress_dialog(self.app, f"Profiling {func_name}...", work, done)

    def _show_xrefs(self):
        """Show all cross-references for a function."""
        func_name = self._get_func()
        if not func_name:
            messagebox.showwarning("Missing", "Enter a function name.")
            return
        if not self._func_map:
            messagebox.showwarning("Missing", "Run 'Discover All Functions' first.")
            return

        func = self._func_map.find_function_by_name(func_name)
        if not func:
            self.output.new_tab("XRefs")
            output_write(self.output, f"  Function '{func_name}' not found.\n", "error")
            return

        self.output.new_tab("XRefs")
        output_write(self.output, f"  CROSS-REFERENCES: {func_name}\n", "title")
        output_write(self.output, f"  {'='*65}\n\n", "dim")

        # Inbound: who calls this function
        callers = self._func_map.get_callers_of(func.va)
        output_write(self.output, f"  CALLERS ({len(callers)})  \u2014  who calls {func_name}:\n", "heading")
        output_write(self.output, f"  {'\u2500'*60}\n", "dim")
        if callers:
            for xref in callers:
                output_write(self.output, f"    \u2190 {xref.caller_name}  ({xref.xref_type})\n", "warn")
        else:
            output_write(self.output, "    (no callers found in this PE)\n", "dim")

        # Outbound: what does this function call
        callees = self._func_map.get_callees_of(func.va)
        output_write(self.output, f"\n  CALLEES ({len(callees)})  \u2014  what {func_name} calls:\n", "heading")
        output_write(self.output, f"  {'\u2500'*60}\n", "dim")
        if callees:
            for xref in callees:
                output_write(self.output, f"    \u2192 {xref.callee_name}  ({xref.xref_type})\n", "peach")
        else:
            output_write(self.output, "    (no outbound calls)\n", "dim")

        # API imports
        if func.api_imports:
            output_write(self.output, f"\n  API IMPORTS ({len(func.api_imports)}):\n", "heading")
            output_write(self.output, f"  {'\u2500'*60}\n", "dim")
            for api in sorted(set(func.api_imports)):
                output_write(self.output, f"    \u2192 {api}\n", "ok")

        self._save_to_history(f"XRefs: {func_name}")
        self.status_var.set(f"\u2705 XRefs: {len(callers)} callers, {len(callees)} callees")

    def _statistics(self):
        """Show statistics about the analyzed PE."""
        if not self._func_map:
            messagebox.showwarning("Missing", "Run 'Discover All Functions' first.")
            return
        fm = self._func_map
        funcs = fm.functions

        self.output.new_tab("Statistics")
        output_write(self.output, f"  DEEP ANALYSIS STATISTICS\n", "title")
        output_write(self.output, f"  {'='*65}\n\n", "dim")

        # Basic counts
        n_exp = sum(1 for f in funcs.values() if f.is_exported)
        n_int = sum(1 for f in funcs.values() if not f.is_exported)
        n_sys = sum(1 for f in funcs.values() if f.is_syscall_stub)
        n_thunk = sum(1 for f in funcs.values() if f.is_thunk)
        output_write(self.output, f"  Functions: {len(funcs)} total  ({n_exp} exported, {n_int} internal)\n")
        output_write(self.output, f"  Syscall stubs: {n_sys}  |  Thunks: {n_thunk}\n")
        output_write(self.output, f"  Cross-references: {len(fm.xrefs)}\n\n")

        # Calling convention breakdown
        conv_counts = {}
        for f in funcs.values():
            c = f.calling_convention or "unknown"
            conv_counts[c] = conv_counts.get(c, 0) + 1
        output_write(self.output, f"  CALLING CONVENTIONS:\n", "heading")
        for conv, cnt in sorted(conv_counts.items(), key=lambda x: -x[1]):
            output_write(self.output, f"    {conv:<12} {cnt}\n")

        # Most-called functions (hotspots)
        output_write(self.output, f"\n  TOP 20 MOST-CALLED FUNCTIONS (hotspots):\n", "heading")
        output_write(self.output, f"  {'\u2500'*60}\n", "dim")
        by_callers = sorted(funcs.values(), key=lambda f: len(f.called_by), reverse=True)
        for f in by_callers[:20]:
            if not f.called_by:
                break
            tag = "ok" if f.is_exported else "warn"
            output_write(self.output, f"    {f.name:<45} {len(f.called_by)} callers\n", tag)

        # Largest functions
        output_write(self.output, f"\n  TOP 20 LARGEST FUNCTIONS (most complex):\n", "heading")
        output_write(self.output, f"  {'\u2500'*60}\n", "dim")
        by_size = sorted(funcs.values(), key=lambda f: f.n_instructions, reverse=True)
        for f in by_size[:20]:
            output_write(self.output, f"    {f.name:<45} {f.n_instructions} insns, "
                         f"{f.n_basic_blocks} blocks\n")

        # Functions with most API calls
        output_write(self.output, f"\n  TOP 20 MOST API-HEAVY FUNCTIONS:\n", "heading")
        output_write(self.output, f"  {'\u2500'*60}\n", "dim")
        by_api = sorted(funcs.values(), key=lambda f: len(f.api_imports), reverse=True)
        for f in by_api[:20]:
            if not f.api_imports:
                break
            output_write(self.output, f"    {f.name:<45} {len(f.api_imports)} API calls\n", "peach")

        self._save_to_history("Statistics")
        self.status_var.set(f"\u2705 Statistics for {len(funcs)} functions")

    def _deep_compare(self):
        """Deep compare a single function between two PEs."""
        func_name = self._get_func()
        pe_a = self._get_pe()
        pe_b = self._get_pe_b()
        if not func_name or not pe_a or not pe_b:
            messagebox.showwarning("Missing",
                                  "Select both PE files and enter a function name.")
            return
        self.output.new_tab("Deep Compare")

        def work(progress_cb):
            return _deep_analyzer().deep_compare_function(
                pe_a, pe_b, func_name, progress_callback=progress_cb)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            report = _deep_analyzer().format_deep_compare(result)
            for line in report.split('\n'):
                if 'MATCH' in line:
                    output_write(self.output, line + '\n', "ok")
                elif 'MISMATCH' in line or 'DIFFERENT' in line:
                    output_write(self.output, line + '\n', "error")
                elif line.strip().startswith('\u2796'):
                    output_write(self.output, line + '\n', "error")
                elif line.strip().startswith('\u2795'):
                    output_write(self.output, line + '\n', "ok")
                elif '\u2500' in line or '=' * 10 in line:
                    output_write(self.output, line + '\n', "dim")
                elif 'SIGNATURE' in line or 'CODE' in line or 'API CALL' in line \
                        or 'STRING' in line or 'STRUCTURE' in line or 'INTERNAL' in line:
                    output_write(self.output, line + '\n', "heading")
                else:
                    output_write(self.output, line + '\n')
            status = "\u2705 IDENTICAL" if result.hash_match else f"\u26A0 {result.block_similarity:.1f}% similar"
            self._save_to_history(f"Compare: {func_name}")
            self.status_var.set(f"{status} \u2014 {func_name}")

        run_with_progress_dialog(self.app,
                                 f"Deep comparing {func_name}...", work, done)

    def _batch_deep(self):
        """Batch deep compare all shared exports between two PEs."""
        pe_a = self._get_pe()
        pe_b = self._get_pe_b()
        if not pe_a or not pe_b:
            messagebox.showwarning("Missing", "Select both PE files.")
            return
        self.output.new_tab("Batch Deep")
        self._batch_results = None
        self._batch_fm_a = None
        self._batch_fm_b = None

        def work(progress_cb):
            progress_cb("Loading PE A...", 5)
            fm_a = _deep_analyzer().PEFunctionMap(pe_a, progress_callback=progress_cb)
            fm_a.discover_all_functions()
            fm_a.analyze_all_functions()
            fm_a.build_xrefs()

            progress_cb("Loading PE B...", 50)
            fm_b = _deep_analyzer().PEFunctionMap(pe_b, progress_callback=progress_cb)
            fm_b.discover_all_functions()
            fm_b.analyze_all_functions()
            fm_b.build_xrefs()

            exports_a = {f.name: f for f in fm_a.functions.values() if f.is_exported}
            exports_b = {f.name: f for f in fm_b.functions.values() if f.is_exported}
            shared = sorted(set(exports_a.keys()) & set(exports_b.keys()))

            results = []
            for idx, name in enumerate(shared):
                fa = exports_a[name]
                fb = exports_b[name]
                r = _deep_analyzer().DeepCompareResult(
                    func_name=name,
                    file_a=os.path.basename(pe_a),
                    file_b=os.path.basename(pe_b),
                )
                r.n_args_a = fa.n_args
                r.n_args_b = fb.n_args
                r.conv_a = fa.calling_convention
                r.conv_b = fb.calling_convention
                r.sig_match = (fa.n_args == fb.n_args and
                               fa.calling_convention == fb.calling_convention)
                r.hash_match = (fa.normalized_hash == fb.normalized_hash)
                r.insn_count_a = fa.n_instructions
                r.insn_count_b = fb.n_instructions
                max_i = max(fa.n_instructions, fb.n_instructions, 1)
                min_i = min(fa.n_instructions, fb.n_instructions)
                r.block_similarity = (min_i / max_i) * 100
                r.apis_only_a = sorted(set(fa.api_imports) - set(fb.api_imports))
                r.apis_only_b = sorted(set(fb.api_imports) - set(fa.api_imports))
                r.apis_common = sorted(set(fa.api_imports) & set(fb.api_imports))
                r.strings_only_a = sorted(set(s for _, s in fa.string_refs) - set(s for _, s in fb.string_refs))
                r.strings_only_b = sorted(set(s for _, s in fb.string_refs) - set(s for _, s in fa.string_refs))
                r.structs_only_a = sorted(set(fa.struct_accesses) - set(fb.struct_accesses))
                r.structs_only_b = sorted(set(fb.struct_accesses) - set(fa.struct_accesses))
                r.internal_calls_a = len(fa.calls_out)
                r.internal_calls_b = len(fb.calls_out)
                results.append(r)
                if idx % 20 == 0:
                    progress_cb(f"Comparing {name}...", 50 + int(50 * idx / max(len(shared), 1)))

            return (fm_a, fm_b, results)

        def done(payload):
            if isinstance(payload, Exception):
                self.status_var.set(f"\u274C Error: {payload}")
                output_write(self.output, f"ERROR: {payload}\n", "error")
                return
            fm_a, fm_b, results = payload
            self._batch_fm_a = fm_a
            self._batch_fm_b = fm_b
            self._batch_results = results

            ba = os.path.basename(pe_a)
            bb = os.path.basename(pe_b)
            output_write(self.output, f"  BATCH DEEP FUNCTION COMPARISON\n", "title")
            output_write(self.output, f"  A: {ba}   B: {bb}\n", "dim")
            output_write(self.output, f"  {'='*100}\n", "dim")
            output_write(self.output, "  Double-click any function to open side-by-side diff window\n\n", "dim")

            output_write(self.output,
                f"  {'Function':<40} {'Sig':<6} {'Sim%':<8} {'ArgsA':<7} {'ArgsB':<7} "
                f"{'APIsA':<7} {'APIsB':<7} {'CallsA':<8} {'CallsB':<8} {'Code'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*40} {'\u2500'*6} {'\u2500'*8} {'\u2500'*7} {'\u2500'*7} "
                f"{'\u2500'*7} {'\u2500'*7} {'\u2500'*8} {'\u2500'*8} {'\u2500'*6}\n", "dim")

            identical = 0
            sig_mismatch = 0
            for r in results:
                sig = "\u2705" if r.sig_match else "\u274C"
                code = "SAME" if r.hash_match else "DIFF"
                tag = "ok" if r.hash_match else ("warn" if r.block_similarity >= 50 else "error")
                if r.hash_match:
                    identical += 1
                if not r.sig_match:
                    sig_mismatch += 1
                total_apis_a = len(r.apis_only_a) + len(r.apis_common)
                total_apis_b = len(r.apis_only_b) + len(r.apis_common)
                line = (f"  {r.func_name:<40} {sig:<6} {r.block_similarity:>6.1f}% "
                        f"{r.n_args_a:<7} {r.n_args_b:<7} "
                        f"{total_apis_a:<7} {total_apis_b:<7} "
                        f"{r.internal_calls_a:<8} {r.internal_calls_b:<8} {code}\n")
                output_write(self.output, line, tag)

            output_write(self.output, f"\n  {'='*100}\n", "dim")
            output_write(self.output,
                f"  Total: {len(results)} functions  |  "
                f"Identical: {identical}  |  "
                f"Signature mismatches: {sig_mismatch}\n", "title")

            self._save_to_history("Batch Compare")
            self.status_var.set(f"\u2705 Compared {len(results)} functions "
                               f"({identical} identical, {sig_mismatch} sig mismatches)")

            # Bind double-click on the output
            self.output.bind("<Double-Button-1>", self._on_batch_dblclick)

        run_with_progress_dialog(self.app, "Batch deep comparison...", work, done)

    def _on_batch_dblclick(self, event):
        """Open side-by-side diff window for the double-clicked function."""
        if not self._batch_results:
            return
        try:
            idx = self.output.index(f"@{event.x},{event.y}")
            line = self.output.get(f"{idx} linestart", f"{idx} lineend").strip()
        except tk.TclError:
            return
        func_name = self._extract_func_name(line)
        if not func_name:
            return
        result = None
        for r in self._batch_results:
            if r.func_name == func_name:
                result = r
                break
        if not result:
            return
        self._open_diff_window(func_name, result)

    def _open_diff_window(self, func_name, result):
        """Open a Toplevel window showing side-by-side disassembly diff."""
        fm_a = self._batch_fm_a
        fm_b = self._batch_fm_b
        if not fm_a or not fm_b:
            return

        func_a = fm_a.find_function_by_name(func_name)
        func_b = fm_b.find_function_by_name(func_name)

        da = _deep_analyzer()
        lines_a = da.get_disassembly_lines(fm_a, func_a) if func_a else []
        lines_b = da.get_disassembly_lines(fm_b, func_b) if func_b else []

        win = tk.Toplevel(self.app)
        win.title(f"Deep Diff: {func_name}")
        win.geometry("1400x800")
        win.configure(bg=T["bg"])

        # Header
        hdr = tk.Frame(win, bg=T["bg_light"])
        hdr.pack(fill="x", padx=5, pady=5)
        sig_match = "\u2705 MATCH" if result.sig_match else "\u274C MISMATCH"
        code_match = "\u2705 IDENTICAL" if result.hash_match else f"\u26A0 {result.block_similarity:.1f}% similar"
        tk.Label(hdr, text=f"  {func_name}", font=("Consolas", 14, "bold"),
                 bg=T["bg_light"], fg=T["accent"]).pack(side="left", padx=10)
        tk.Label(hdr, text=f"Signature: {sig_match}   Code: {code_match}",
                 font=("Segoe UI", 10), bg=T["bg_light"], fg=T["fg"]).pack(side="left", padx=20)

        # Info panel
        info = tk.Frame(win, bg=T["bg"])
        info.pack(fill="x", padx=10, pady=3)
        total_a = len(result.apis_only_a) + len(result.apis_common)
        total_b = len(result.apis_only_b) + len(result.apis_common)
        info_text = (
            f"  A: {result.file_a}  ({result.conv_a}, {result.n_args_a} args, "
            f"{result.insn_count_a} insns, {result.internal_calls_a} calls, {total_a} APIs)\n"
            f"  B: {result.file_b}  ({result.conv_b}, {result.n_args_b} args, "
            f"{result.insn_count_b} insns, {result.internal_calls_b} calls, {total_b} APIs)"
        )
        tk.Label(info, text=info_text, font=("Consolas", 9), bg=T["bg"],
                 fg=T["fg_dim"], justify="left", anchor="w").pack(fill="x")

        # Paned window: left = File A, right = File B
        pw = tk.PanedWindow(win, orient="horizontal", bg=T["bg"],
                            sashwidth=4, sashrelief="flat")
        pw.pack(fill="both", expand=True, padx=5, pady=5)

        def make_code_panel(parent, title):
            frm = tk.Frame(parent, bg=T["bg"])
            tk.Label(frm, text=title, font=("Consolas", 10, "bold"),
                     bg=T["bg"], fg=T["accent"]).pack(anchor="w", padx=5)
            txt = tk.Text(frm, bg=T["bg"], fg=T["fg"],
                          font=("Consolas", 9), wrap="none",
                          insertbackground=T["fg"], relief="flat", bd=5,
                          selectbackground=T["accent"],
                          selectforeground=T["bg_dark"])
            sb_y = ttk.Scrollbar(frm, orient="vertical", command=txt.yview)
            sb_x = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
            txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
            sb_y.pack(side="right", fill="y")
            sb_x.pack(side="bottom", fill="x")
            txt.pack(fill="both", expand=True)
            txt.tag_configure("match", foreground=T.get("fg", "#cdd6f4"))
            txt.tag_configure("diff", foreground="#f38ba8", background="#302030")
            txt.tag_configure("call_match", foreground="#a6e3a1")
            txt.tag_configure("call_diff", foreground="#fab387", background="#302030")
            return frm, txt

        frm_a, txt_a = make_code_panel(pw, f"\u25C0  {result.file_a}")
        frm_b, txt_b = make_code_panel(pw, f"{result.file_b}  \u25B6")
        pw.add(frm_a, stretch="always")
        pw.add(frm_b, stretch="always")

        # Normalize instructions for diffing
        def normalize(mnemonic, op_str):
            return f"{mnemonic} {re.sub(r'0x[0-9a-fA-F]+', '<N>', op_str)}"

        norm_a = [normalize(m, o) for _, m, o, _ in lines_a]
        norm_b = [normalize(m, o) for _, m, o, _ in lines_b]
        norm_set_b = set(norm_b)
        norm_set_a = set(norm_a)

        def fill_panel(txt_widget, lines_list, norm_list, other_set):
            txt_widget.configure(state="normal")
            for i, (addr, mnemonic, op_str, annot) in enumerate(lines_list):
                norm = norm_list[i]
                is_call = mnemonic in ('call', 'jmp')
                if norm in other_set:
                    tag = "call_match" if is_call else "match"
                else:
                    tag = "call_diff" if is_call else "diff"
                annot_str = f"  ; {annot}" if annot else ""
                line = f"0x{addr:08X}:  {mnemonic:<10} {op_str:<40}{annot_str}\n"
                txt_widget.insert("end", line, tag)
            txt_widget.configure(state="disabled")

        fill_panel(txt_a, lines_a, norm_a, norm_set_b)
        fill_panel(txt_b, lines_b, norm_b, norm_set_a)

        # Synchronized scrolling via mousewheel
        def on_wheel_a(event):
            txt_b.yview_scroll(int(-1 * (event.delta / 120)), "units")
        def on_wheel_b(event):
            txt_a.yview_scroll(int(-1 * (event.delta / 120)), "units")
        txt_a.bind("<MouseWheel>", on_wheel_a)
        txt_b.bind("<MouseWheel>", on_wheel_b)

        # Bottom differences summary
        diff_frm = tk.Frame(win, bg=T["bg_light"])
        diff_frm.pack(fill="x", padx=5, pady=5)
        diff_parts = []
        if result.apis_only_a:
            diff_parts.append(f"APIs only in A: {', '.join(result.apis_only_a[:5])}")
        if result.apis_only_b:
            diff_parts.append(f"APIs only in B: {', '.join(result.apis_only_b[:5])}")
        if result.strings_only_a:
            diff_parts.append(f"Strings only in A: {', '.join(result.strings_only_a[:3])}")
        if result.strings_only_b:
            diff_parts.append(f"Strings only in B: {', '.join(result.strings_only_b[:3])}")
        if result.structs_only_a:
            diff_parts.append(f"Struct offsets only in A: {', '.join(f'+0x{o:03X}' for o in result.structs_only_a[:5])}")
        if result.structs_only_b:
            diff_parts.append(f"Struct offsets only in B: {', '.join(f'+0x{o:03X}' for o in result.structs_only_b[:5])}")
        if not diff_parts:
            diff_parts.append("No API/string/struct differences detected")
        diff_text = "  DIFFERENCES:  " + "  |  ".join(diff_parts)
        tk.Label(diff_frm, text=diff_text, font=("Consolas", 9),
                 bg=T["bg_light"], fg=T["fg"], wraplength=1350,
                 justify="left", anchor="w").pack(fill="x", padx=5, pady=3)


# ══════════════════════════════════════════════════════════════════════════
#  Tab 14: System-Wide XRef Scanner
# ══════════════════════════════════════════════════════════════════════════

class XRefScannerTab(ttk.Frame):
    """Scan all PE files in a directory (e.g. System32) for references to a function."""

    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        # Function name to search for
        func_frm = tk.Frame(self, bg=T["bg"])
        func_frm.grid(row=0, column=0, sticky="ew", padx=12, pady=5)
        func_frm.columnconfigure(1, weight=1)
        ttk.Label(func_frm, text="Function name:", width=16, anchor="e").grid(row=0, column=0, padx=(0, 8))
        self.func_var = tk.StringVar()
        ent = PlaceholderEntry(func_frm, placeholder="e.g.  CreateFileW, NtCreateFile, RtlInitUnicodeString",
                               textvariable=self.func_var,
                               bg=T["entry_bg"], fg=T["fg"], insertbackground=T["fg"],
                               font=("Consolas", 10), relief="flat", bd=5)
        ent.grid(row=0, column=1, sticky="ew")
        app.register_placeholder(ent)
        self._func_entry = ent

        # Directory to scan
        _, self._get_dir, self.dir_var = make_dir_picker(
            self, "Scan directory:", row=1,
            placeholder=EXAMPLES["scan_dir"], app=app)

        # Buttons
        btn_frm = make_button_bar(self, row=2)
        ttk.Button(btn_frm, text="\U0001F50D  Scan All PEs", style="Accent.TButton",
                   command=self._scan).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="\u2716  Clear",
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 Scan entire directories for all callers of a function", row=3)

        # Info label
        info_frm = tk.Frame(self, bg=T["bg"])
        info_frm.grid(row=4, column=0, sticky="w", padx=12, pady=3)
        ttk.Label(info_frm, text="Scans .dll .sys .exe .drv .cpl .ocx .scr files for import references",
                  foreground=T["fg_dim"]).pack(side="left")

        self.output = TabbedOutput(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _get_func(self):
        return self._func_entry.get_value()

    def _scan(self):
        func_name = self._get_func()
        scan_dir = self._get_dir()
        if not func_name:
            messagebox.showwarning("Missing", "Enter a function name to search for.")
            return
        if not scan_dir or not os.path.isdir(scan_dir):
            messagebox.showwarning("Missing", "Select a directory to scan (e.g. C:\\WINNT\\System32).")
            return
        self.output.new_tab("Scan")

        pe_exts = {'.dll', '.sys', '.exe', '.drv', '.cpl', '.ocx', '.scr'}
        pe_files = [os.path.join(scan_dir, f) for f in os.listdir(scan_dir)
                    if os.path.splitext(f)[1].lower() in pe_exts]

        def work(progress_cb):
            return _deep_analyzer().scan_system_xrefs_detailed(
                func_name, pe_files, progress_callback=progress_cb)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, f"  SYSTEM-WIDE XREF SCAN: {func_name}\n", "title")
            output_write(self.output, f"  Directory: {scan_dir}\n", "dim")
            output_write(self.output, f"  {'='*80}\n\n", "dim")
            output_write(self.output, f"  {len(result)} PE files reference {func_name}:\n\n", "ok")

            # Group by source file
            by_file = {}
            for xref in result:
                by_file.setdefault(xref.caller_name, []).append(xref)

            output_write(self.output,
                f"  {'PE File':<40} {'Import From':<30} {'IAT Address':<16} {'Type'}\n", "heading")
            output_write(self.output,
                f"  {'\u2500'*40} {'\u2500'*30} {'\u2500'*16} {'\u2500'*10}\n", "dim")

            for pe_name in sorted(by_file.keys()):
                xrefs = by_file[pe_name]
                for xref in xrefs:
                    iat = f"0x{xref.caller_va:08X}" if xref.caller_va else "N/A"
                    output_write(self.output,
                        f"  {pe_name:<40} {xref.callee_name:<30} {iat:<16} {xref.xref_type}\n")

            if not result:
                output_write(self.output, f"  No references to '{func_name}' found in {scan_dir}\n", "dim")

            self.status_var.set(f"\u2705 Found {len(result)} references to {func_name} "
                               f"in {len(by_file)} PE files")

        run_with_progress_dialog(self.app,
                                 f"Scanning for {func_name}...", work, done)


# ══════════════════════════════════════════════════════════════════════════
#  Tab 15: PE Patcher (KernelEx Ultimate Edition)
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
                   command=lambda: self.output.close_all()).pack(side="left", padx=5)

        self.status_var, self._prog_start, self._prog_stop = make_status_with_progress(
            self, "\u2022 KernelEx-inspired PE patcher \u2014 version stamp, syscall, shim, rebase, blob inject", row=5)

        self.output = TabbedOutput(self)
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
        self.output.new_tab("Quick Patch")

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

        run_with_progress(self, work, done)

    def _custom_patch(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file to patch.")
            return
        output = self._get_out()
        self.status_var.set("\u23F3 Applying custom patches...")
        self.output.new_tab("Custom Patch")

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

        run_with_progress(self, work, done)

    def _patch_syscalls(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        output = self._get_out()
        self.status_var.set("\u23F3 Patching syscall stubs...")
        self.output.new_tab("Syscall Patch")

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

        run_with_progress(self, work, done)

    def _inspect_tables(self):
        pe_path = self._get_pe()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        self.status_var.set("\u23F3 Inspecting PE tables...")
        self.output.new_tab("Tables")

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

        run_with_progress(self, work, done)

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
        self.output.new_tab("Result")

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

        run_with_progress(self, work, done)


# ══════════════════════════════════════════════════════════════════════════
#  Interactive Disassembly View (used by Kernel Debugger)
# ══════════════════════════════════════════════════════════════════════════

class DisassemblyView(tk.Frame):
    """Interactive disassembly view with clickable breakpoint gutter.

    Shows disassembled functions with:
    - Line numbers in the left margin
    - Red breakpoint dots (●) that can be toggled by clicking
    - Address, hex bytes, mnemonic, operands for each instruction
    - Call target annotations with function names
    - Current EIP indicator (yellow arrow ►)
    """

    # Breakpoint dot character and colors
    _BP_CHAR = "\u25CF"   # ● filled circle
    _BP_COLOR = "#E51400"  # red
    _EIP_CHAR = "\u25B6"  # ► arrow
    _EIP_COLOR = "#FFD700"  # gold

    def __init__(self, parent, debugger_tab):
        super().__init__(parent, bg=T["bg_dark"])
        self._dtab = debugger_tab
        self._functions = []    # list of dicts from disassemble_function
        self._addr_to_line = {} # address -> line number (1-based)
        self._line_to_addr = {} # line number -> address
        self._bp_lines = set()  # lines with breakpoints
        self._exec_lines = set() # lines that were actually executed
        self._eip_line = None   # line with current EIP

        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Gutter (breakpoints + line numbers)
        self._gutter = tk.Text(
            self, width=8, bg=T["bg"], fg="#888888",
            font=("Consolas", 10), relief="flat", bd=4,
            cursor="hand2", state="disabled",
            wrap="none", highlightthickness=0,
            selectbackground=T["bg"], selectforeground="#888888",
        )
        self._gutter.grid(row=0, column=0, sticky="ns")

        # Main disassembly text
        self._text = tk.Text(
            self, bg=T["bg_dark"], fg=T["fg"],
            font=("Consolas", 10), relief="flat", bd=8,
            wrap="none", state="disabled",
            insertbackground=T["fg"], highlightthickness=0,
        )
        self._text.grid(row=0, column=1, sticky="nsew")

        # Scrollbar
        self._sb = ttk.Scrollbar(self, command=self._on_scroll)
        self._sb.grid(row=0, column=2, sticky="ns")
        self._text.configure(yscrollcommand=self._sync_scroll)

        # Horizontal scrollbar
        self._hsb = ttk.Scrollbar(self, orient="horizontal",
                                   command=self._text.xview)
        self._hsb.grid(row=1, column=1, sticky="ew")
        self._text.configure(xscrollcommand=self._hsb.set)

        # Configure tags
        self._text.tag_configure("func_header", foreground="#569CD6",
                                  font=("Consolas", 10, "bold"))
        self._text.tag_configure("address", foreground="#DCDCAA")
        self._text.tag_configure("hexbytes", foreground="#666666")
        self._text.tag_configure("mnemonic", foreground="#C586C0")
        self._text.tag_configure("mnemonic_call", foreground="#4EC9B0",
                                  font=("Consolas", 10, "bold"))
        self._text.tag_configure("mnemonic_jmp", foreground="#CE9178")
        self._text.tag_configure("mnemonic_ret", foreground="#D16969",
                                  font=("Consolas", 10, "bold"))
        self._text.tag_configure("operand", foreground="#D4D4D4")
        self._text.tag_configure("call_target", foreground="#4EC9B0")
        self._text.tag_configure("separator", foreground="#444444")
        self._text.tag_configure("eip_line", background="#3A3A00")
        self._text.tag_configure("bp_line", background="#3A1010")
        self._text.tag_configure("exec_line", background="#1A2A1A")
        self._text.tag_configure("not_exec_line", foreground="#555555")

        self._gutter.tag_configure("bp_dot", foreground=self._BP_COLOR,
                                    font=("Consolas", 10, "bold"))
        self._gutter.tag_configure("eip_arrow", foreground=self._EIP_COLOR,
                                    font=("Consolas", 10, "bold"))
        self._gutter.tag_configure("linenum", foreground="#555555")
        self._gutter.tag_configure("exec_mark", foreground="#4EC9B0")

        # Bind click on gutter
        self._gutter.bind("<Button-1>", self._on_gutter_click)

        # Sync scrolling
        self._text.bind("<MouseWheel>", self._on_mousewheel)
        self._gutter.bind("<MouseWheel>", self._on_mousewheel)

    def _on_scroll(self, *args):
        self._text.yview(*args)
        self._gutter.yview(*args)

    def _sync_scroll(self, first, last):
        self._sb.set(first, last)
        self._gutter.yview_moveto(first)

    def _on_mousewheel(self, event):
        delta = -1 * (event.delta // 120)
        self._text.yview_scroll(delta, "units")
        self._gutter.yview_scroll(delta, "units")
        return "break"

    def load_functions(self, functions: list):
        """Load disassembled functions into the view."""
        self._functions = functions
        self._addr_to_line.clear()
        self._line_to_addr.clear()
        self._bp_lines.clear()
        self._eip_line = None

        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._gutter.configure(state="normal")
        self._gutter.delete("1.0", "end")

        line_num = 0

        for fi, func in enumerate(functions):
            if fi > 0:
                # Separator between functions
                line_num += 1
                self._text.insert("end",
                    "\u2500" * 80 + "\n", "separator")
                self._gutter.insert("end", "\n")

            # Function header
            line_num += 1
            header = f"  {func['module']}!{func['name']}  (0x{func['address']:08X})\n"
            self._text.insert("end", header, "func_header")
            self._gutter.insert("end", "\n")

            # Instructions
            for insn in func['instructions']:
                line_num += 1
                self._addr_to_line[insn['address']] = line_num
                self._line_to_addr[line_num] = insn['address']

                # Address column
                addr_str = f"  {insn['address']:08X}  "
                self._text.insert("end", addr_str, "address")

                # Hex bytes
                hex_str = insn['bytes'].hex().upper()
                hex_str = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                hex_col = f"{hex_str:24s} "
                self._text.insert("end", hex_col, "hexbytes")

                # Mnemonic
                mn = insn['mnemonic']
                if mn in ('call',):
                    mn_tag = "mnemonic_call"
                elif mn in ('jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb',
                            'jae', 'jbe', 'jg', 'jl', 'jge', 'jle',
                            'jna', 'jnb', 'jnae', 'jnbe', 'jng', 'jnl',
                            'jnge', 'jnle', 'jo', 'jno', 'js', 'jns',
                            'jp', 'jnp', 'jcxz', 'jecxz', 'loop',
                            'loope', 'loopne'):
                    mn_tag = "mnemonic_jmp"
                elif mn in ('ret', 'retn', 'retf'):
                    mn_tag = "mnemonic_ret"
                else:
                    mn_tag = "mnemonic"
                self._text.insert("end", f"{mn:8s}", mn_tag)

                # Operands
                op_str = insn['op_str']
                self._text.insert("end", f" {op_str}", "operand")

                # Call target annotation
                if insn.get('call_name'):
                    self._text.insert("end",
                        f"    ; {insn['call_name']}", "call_target")

                self._text.insert("end", "\n")

                # Gutter line number
                self._gutter.insert("end",
                    f" {line_num:5d} \n", "linenum")

        self._text.configure(state="disabled")
        self._gutter.configure(state="disabled")

        # Now mark existing breakpoints
        self._refresh_breakpoint_markers()

    def _on_gutter_click(self, event):
        """Toggle breakpoint on clicked line."""
        # Get line number from click position
        idx = self._gutter.index(f"@{event.x},{event.y}")
        line = int(idx.split('.')[0])

        addr = self._line_to_addr.get(line)
        if addr is None:
            return  # clicked on non-instruction line

        dbg = self._dtab._dbg
        if not dbg:
            dbg = self._dtab._make_session()

        if line in self._bp_lines:
            # Remove breakpoint
            for bp in dbg.list_breakpoints():
                if bp.address == addr:
                    dbg.remove_breakpoint(bp.id)
                    break
            self._bp_lines.discard(line)
        else:
            # Set breakpoint
            try:
                dbg.set_breakpoint(addr)
                self._bp_lines.add(line)
            except Exception as e:
                self._dtab.status_var.set(f"\u274C {e}")
                return

        self._refresh_breakpoint_markers()
        self._refresh_line_highlights()

        # Update status
        bp_count = len(self._bp_lines)
        self._dtab.status_var.set(
            f"\U0001F6D1 {bp_count} breakpoint{'s' if bp_count != 1 else ''} set")

    def _refresh_breakpoint_markers(self):
        """Refresh breakpoint dots in gutter and sync with debugger state."""
        dbg = self._dtab._dbg
        bp_addrs = set()
        if dbg:
            for bp in dbg.list_breakpoints():
                if bp.enabled:
                    bp_addrs.add(bp.address)

        self._bp_lines.clear()
        for addr in bp_addrs:
            if addr in self._addr_to_line:
                self._bp_lines.add(self._addr_to_line[addr])

        # Redraw gutter
        self._gutter.configure(state="normal")

        # Remove old bp_dot tags
        self._gutter.tag_remove("bp_dot", "1.0", "end")

        for line in self._bp_lines:
            # Replace the first char of the gutter line with a red dot
            line_start = f"{line}.0"
            line_end = f"{line}.1"
            self._gutter.delete(line_start, line_end)
            self._gutter.insert(line_start, self._BP_CHAR, "bp_dot")

        self._gutter.configure(state="disabled")
        self._refresh_line_highlights()

    def _refresh_line_highlights(self):
        """Highlight lines with breakpoints and EIP."""
        self._text.configure(state="normal")
        self._text.tag_remove("bp_line", "1.0", "end")
        self._text.tag_remove("eip_line", "1.0", "end")

        for line in self._bp_lines:
            self._text.tag_add("bp_line", f"{line}.0", f"{line}.end")

        if self._eip_line:
            self._text.tag_add("eip_line",
                f"{self._eip_line}.0", f"{self._eip_line}.end")

        self._text.configure(state="disabled")

    def update_eip(self, eip_addr: int):
        """Update the current EIP indicator."""
        # Restore old EIP line's gutter character (remove arrow, put back ● or space)
        if self._eip_line is not None:
            self._gutter.configure(state="normal")
            self._gutter.tag_remove("eip_arrow", "1.0", "end")
            line_start = f"{self._eip_line}.0"
            line_char  = f"{self._eip_line}.1"
            self._gutter.delete(line_start, line_char)
            if self._eip_line in self._bp_lines:
                self._gutter.insert(line_start, self._BP_CHAR, "bp_dot")
            else:
                self._gutter.insert(line_start, " ")
            self._gutter.configure(state="disabled")

        self._eip_line = self._addr_to_line.get(eip_addr)
        if self._eip_line is not None:
            self._gutter.configure(state="normal")
            # Always place the arrow (overrides ● if EIP is at a BP line)
            line_start = f"{self._eip_line}.0"
            line_char  = f"{self._eip_line}.1"
            self._gutter.delete(line_start, line_char)
            self._gutter.insert(line_start, self._EIP_CHAR, "eip_arrow")
            self._gutter.configure(state="disabled")

            # Scroll to make EIP visible
            self._text.see(f"{self._eip_line}.0")
            self._gutter.see(f"{self._eip_line}.0")

        self._refresh_line_highlights()

    def clear_eip(self):
        """Remove EIP indicator."""
        if self._eip_line:
            self._gutter.configure(state="normal")
            self._gutter.tag_remove("eip_arrow", "1.0", "end")
            # Restore line number char if no breakpoint
            if self._eip_line not in self._bp_lines:
                line_start = f"{self._eip_line}.0"
                line_char = f"{self._eip_line}.1"
                self._gutter.delete(line_start, line_char)
                self._gutter.insert(line_start, " ")
            self._gutter.configure(state="disabled")
            self._eip_line = None
            self._refresh_line_highlights()

    def mark_executed(self, addresses):
        """Mark lines that were executed (from trace) vs not executed.

        addresses: iterable of int addresses that were visited.
        """
        exec_addrs = set(addresses)
        self._exec_lines.clear()

        for addr, line in self._addr_to_line.items():
            if addr in exec_addrs:
                self._exec_lines.add(line)

        self._text.configure(state="normal")
        self._text.tag_remove("exec_line", "1.0", "end")
        self._text.tag_remove("not_exec_line", "1.0", "end")

        for line, addr in self._line_to_addr.items():
            if line in self._exec_lines:
                self._text.tag_add("exec_line", f"{line}.0", f"{line}.end")
            else:
                self._text.tag_add("not_exec_line", f"{line}.0", f"{line}.end")
        self._text.configure(state="disabled")

        # Mark executed lines in gutter with a tick
        self._gutter.configure(state="normal")
        self._gutter.tag_remove("exec_mark", "1.0", "end")
        for line in self._exec_lines:
            line_start = f"{line}.0"
            line_char = f"{line}.1"
            cur = self._gutter.get(line_start, line_char)
            if cur not in (self._BP_CHAR, self._EIP_CHAR):
                self._gutter.delete(line_start, line_char)
                self._gutter.insert(line_start, "\u2502", "exec_mark")
        self._gutter.configure(state="disabled")

    def clear_execution_marks(self):
        """Remove execution path highlighting."""
        self._exec_lines.clear()
        self._text.configure(state="normal")
        self._text.tag_remove("exec_line", "1.0", "end")
        self._text.tag_remove("not_exec_line", "1.0", "end")
        self._text.configure(state="disabled")
        self._gutter.configure(state="normal")
        self._gutter.tag_remove("exec_mark", "1.0", "end")
        self._gutter.configure(state="disabled")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 16: Kernel Debugger
# ══════════════════════════════════════════════════════════════════════════

class KernelDebuggerTab(ttk.Frame):
    """Live kernel‑state debugger — multi‑PE loader, breakpoints, stepping."""

    def __init__(self, parent, app):
        super().__init__(parent, style="TFrame")
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(8, weight=1)   # output area expands

        self._env = None           # KernelEnvironment
        self._dbg = None           # DebugSession
        self._insp = None          # ObjectInspector
        self._loaded = False
        self._disasm_view = None   # DisassemblyView (if open)
        self._trace_tab_title = None  # title of debug/trace tab

        # Row 0 — system32 folder picker
        _, self._get_sys32, self._sys32_var = make_dir_picker(
            self, "System32 folder:", row=0,
            placeholder=r"C:\Users\win2000\Desktop\2kDEBUG\system32",
            app=app)

        # Row 1 — load / unload / symbols
        bf1 = make_button_bar(self, row=1)
        ttk.Button(bf1, text="\u25B6 Load Core",
                   command=self._load_core).pack(side="left", padx=2)
        ttk.Button(bf1, text="\u2B07 Load Dependencies",
                   command=self._load_deps).pack(side="left", padx=2)
        ttk.Button(bf1, text="\U0001F50D Load Symbols \u2026",
                   command=self._load_symbols).pack(side="left", padx=2)
        ttk.Button(bf1, text="\u274C Unload",
                   command=self._unload).pack(side="left", padx=2)

        # Row 2 — function / args
        func_frm = tk.Frame(self, bg=T["bg"])
        func_frm.grid(row=2, column=0, sticky="ew", padx=12, pady=4)
        func_frm.columnconfigure(1, weight=1)
        ttk.Label(func_frm, text="Function:").grid(row=0, column=0, padx=(0, 6))
        self._func_var = tk.StringVar()
        self._func_ent = PlaceholderEntry(func_frm, textvariable=self._func_var,
                                          placeholder="NtPowerInformation")
        self._func_ent.grid(row=0, column=1, sticky="ew")
        app._placeholder_entries.append(self._func_ent)

        ttk.Label(func_frm, text="  Args:").grid(row=0, column=2, padx=(8, 6))
        self._args_var = tk.StringVar()
        self._args_ent = PlaceholderEntry(func_frm, textvariable=self._args_var,
                                          placeholder="0, 0, 0, 0x1000, 0x1000")
        self._args_ent.grid(row=0, column=3, sticky="ew")
        func_frm.columnconfigure(3, weight=1)
        app._placeholder_entries.append(self._args_ent)
        ttk.Button(func_frm, text="\u25BC Presets",
                   command=self._show_arg_presets, width=10).grid(
                       row=0, column=4, padx=(6, 0))

        # Row 3 — run / step / continue / breakpoints
        bf2 = make_button_bar(self, row=3)
        ttk.Button(bf2, text="\u25B6 Run",
                   command=self._run).pack(side="left", padx=2)
        ttk.Button(bf2, text="\u23F8 Run+Break at Entry",
                   command=self._run_break).pack(side="left", padx=2)
        ttk.Button(bf2, text="\u23ED Step",
                   command=self._step).pack(side="left", padx=2)
        ttk.Button(bf2, text="\u25B6\u25B6 Continue",
                   command=self._continue).pack(side="left", padx=2)
        ttk.Button(bf2, text="\u25B6 Run Until BP",
                   command=self._run_until_bp).pack(side="left", padx=2)
        ttk.Separator(bf2, orient="vertical").pack(side="left", padx=6, fill="y")
        ttk.Button(bf2, text="\U0001F6D1 Set Breakpoint",
                   command=self._add_breakpoint).pack(side="left", padx=2)
        ttk.Button(bf2, text="List BPs",
                   command=self._list_breakpoints).pack(side="left", padx=2)

        # Row 4 — options
        opt_frm = tk.Frame(self, bg=T["bg"])
        opt_frm.grid(row=4, column=0, sticky="w", padx=12, pady=2)
        self._show_trace_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frm, text="Show instruction trace",
                       variable=self._show_trace_var,
                       bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"],
                       activebackground=T["bg"], activeforeground=T["fg"]
                       ).pack(side="left", padx=4)
        self._user_mode_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frm, text="User mode (PreviousMode=1)",
                       variable=self._user_mode_var,
                       bg=T["bg"], fg=T["fg"], selectcolor=T["bg_dark"],
                       activebackground=T["bg"], activeforeground=T["fg"]
                       ).pack(side="left", padx=4)

        # Row 5 — breakpoint entry
        bp_frm = tk.Frame(self, bg=T["bg"])
        bp_frm.grid(row=5, column=0, sticky="ew", padx=12, pady=2)
        bp_frm.columnconfigure(1, weight=1)
        ttk.Label(bp_frm, text="Breakpoint:").grid(row=0, column=0, padx=(0, 6))
        self._bp_var = tk.StringVar()
        self._bp_ent = PlaceholderEntry(bp_frm, textvariable=self._bp_var,
                                        placeholder="NtClose or 0x004DC97E")
        self._bp_ent.grid(row=0, column=1, sticky="ew")
        app._placeholder_entries.append(self._bp_ent)

        # Row 6 — inspect buttons
        bf3 = make_button_bar(self, row=6)
        ttk.Button(bf3, text="Registers",
                   command=self._show_regs).pack(side="left", padx=2)
        ttk.Button(bf3, text="Call Stack",
                   command=self._show_callstack).pack(side="left", padx=2)
        ttk.Button(bf3, text="Stack Memory",
                   command=self._show_stack_mem).pack(side="left", padx=2)
        ttk.Button(bf3, text="Handle Table",
                   command=self._show_handles).pack(side="left", padx=2)
        ttk.Button(bf3, text="Env Info",
                   command=self._show_env).pack(side="left", padx=2)
        ttk.Separator(bf3, orient="vertical").pack(side="left", padx=6, fill="y")
        ttk.Button(bf3, text="\U0001F4CB Disassemble",
                   command=self._disassemble).pack(side="left", padx=2)
        ttk.Button(bf3, text="\U0001F50D Find Callers",
                   command=self._find_callers).pack(side="left", padx=2)
        ttk.Separator(bf3, orient="vertical").pack(side="left", padx=6, fill="y")
        ttk.Button(bf3, text="\u2B0C Split View",
                   command=self._toggle_split_view).pack(side="left", padx=2)
        ttk.Separator(bf3, orient="vertical").pack(side="left", padx=6, fill="y")
        ttk.Button(bf3, text="\U0001F9F9 Clear",
                   command=self._clear_output).pack(side="left", padx=2)

        # Row 7 — status + progress
        self.status_var, self._prog_start, self._prog_stop = \
            make_status_with_progress(self, "Kernel debugger ready", row=7)

        # Row 8 — output (supports tabbed and split view modes)
        self._split_mode = False
        self._split_pane = None
        self.output = TabbedOutput(self)
        self.output.grid(row=8, column=0, sticky="nsew", padx=10, pady=(4, 10))

    # ── helpers ───────────────────────────────────────────────────────────

    def _bp_not_hit_diagnostic(self, result, tab):
        """Show detailed diagnostic when breakpoints weren't hit."""
        if not self._dbg:
            return
        bps = self._dbg.list_breakpoints()
        if not bps:
            self.output.write_to_tab(tab,
                "\n  \u26A0 No breakpoints were set.\n", "warn")
            self.output.write_to_tab(tab,
                "  Tip: Set breakpoints before running, or use "
                "\"Run+Break at Entry\" to pause at function start.\n")
            return

        visited = result.get("visited_addresses", set()) if isinstance(result, dict) else set()
        insn_count = result.get("instructions", 0) if isinstance(result, dict) else 0

        # Gather BP hit counts and event info
        bp_events = {}
        if isinstance(result, dict):
            for ev in result.get("events", []):
                if ev.event_type == "breakpoint" and ev.details:
                    bp_events[ev.details.get("bp_id")] = ev.details.get("hit_count", 0)

        enabled_bps = [bp for bp in bps if bp.enabled]
        missed_bps = [bp for bp in enabled_bps if bp.address not in visited]

        self.output.write_to_tab(tab,
            f"\n  {'─' * 60}\n", "separator")
        self.output.write_to_tab(tab,
            "  BREAKPOINT DIAGNOSTIC\n\n", "title")
        self.output.write_to_tab(tab,
            f"  Instructions executed: {insn_count}\n")
        self.output.write_to_tab(tab,
            f"  Unique addresses visited: {len(visited)}\n")
        self.output.write_to_tab(tab,
            f"  Breakpoints: {len(enabled_bps)} enabled, "
            f"{len(missed_bps)} not reached\n\n")

        for bp in bps:
            addr = bp.address
            name = bp.name
            was_visited = addr in visited
            was_hit = bp.hit_count > 0 or bp.id in bp_events

            if not bp.enabled:
                self.output.write_to_tab(tab,
                    f"  \u26D4 BP #{bp.id}  0x{addr:08X}  {name}  "
                    f"[DISABLED]\n", "warn")
            elif was_hit:
                # BP was hit (previously or during this run) — already triggered
                self.output.write_to_tab(tab,
                    f"  \u2705 BP #{bp.id}  0x{addr:08X}  {name}  "
                    f"— hit {bp.hit_count}x (already triggered earlier)\n", "ok")
            elif was_visited:
                # Address was executed but BP didn't fire — conditional BP
                # or BP was added after the address was already passed
                self.output.write_to_tab(tab,
                    f"  \u26A0 BP #{bp.id}  0x{addr:08X}  {name}  "
                    f"— address visited but BP not triggered "
                    f"(set after passing? conditional?)\n", "warn")
            else:
                self.output.write_to_tab(tab,
                    f"  \u274C BP #{bp.id}  0x{addr:08X}  {name}  "
                    f"— NOT on executed code path\n", "error")

        # Suggest possible causes
        any_disabled = any(not bp.enabled for bp in bps)
        some_missed = len(missed_bps) > 0
        all_missed = len(missed_bps) == len(enabled_bps) and len(enabled_bps) > 0

        reasons = []
        if any_disabled:
            reasons.append(
                "Some breakpoints are disabled \u2014 enable them in List BPs")
        if all_missed:
            reasons.append(
                "The function arguments caused a code path that "
                "bypassed ALL breakpoint addresses")
            reasons.append(
                "Try different arguments, or set breakpoints closer "
                "to the function entry point")
            if insn_count < 50:
                reasons.append(
                    "Very few instructions executed \u2014 the function "
                    "may have returned early (check args / PreviousMode)")
        elif some_missed:
            reasons.append(
                "The function arguments caused a code path that "
                "bypassed some breakpoint addresses")
            reasons.append(
                "Try setting breakpoints on different branches, "
                "or use Disassemble to see the control flow")

        if reasons:
            self.output.write_to_tab(tab, "\n  Possible reasons:\n")
            for r in reasons:
                self.output.write_to_tab(tab, f"  \u2022 {r}\n")
        self.output.write_to_tab(tab, "\n")

    def _update_disasm_execution(self, result):
        """Update disassembly view with execution path highlighting."""
        if not self._disasm_view:
            return
        visited = None
        if isinstance(result, dict):
            visited = result.get("visited_addresses")
        if not visited and self._dbg:
            # Fallback: read directly from debug session
            visited = set(self._dbg._block_hits.keys()) if hasattr(self._dbg, '_block_hits') else None
        if visited:
            try:
                self._disasm_view.mark_executed(visited)
            except Exception:
                pass

    # ── arg presets ───────────────────────────────────────────────────────

    # Test argument presets for common NT kernel functions.
    # Format: { "FuncName": [ ("Description", "arg_string"), ... ] }
    _ARG_PRESETS = {
        "NtPowerInformation": [
            ("Level 0 \u2014 SystemPowerPolicyAc (default)", "0, 0, 0, 0x1000, 0x1000"),
            ("Level 1 \u2014 SystemPowerPolicyDc",           "1, 0, 0, 0x1000, 0x1000"),
            ("Level 2 \u2014 VerifySystemPolicies",          "2, 0, 0, 0x1000, 0x1000"),
            ("Level 3 \u2014 VerifyProcessorPowerPolicy",    "3, 0, 0, 0x1000, 0x1000"),
            ("Level 10 \u2014 SystemBatteryState",           "0xa, 0, 0, 0x1000, 0x1000"),
            ("Level 11 \u2014 SystemPowerStateHandler",      "0xb, 0, 0, 0x1000, 0x1000"),
            ("Level 12 \u2014 ProcessorStateHandler",        "0xc, 0, 0, 0x1000, 0x1000"),
            ("Level 41 \u2014 SystemPowerInformation",       "0x29, 0, 0, 0x1000, 0x1000"),
        ],
        "NtClose": [
            ("Valid handle",          "0x100"),
            ("Null handle",           "0"),
            ("Invalid handle (test)", "0xDEADBEEF"),
        ],
        "NtQuerySystemInformation": [
            ("Class 0 \u2014 SystemBasicInformation",        "0, 0x80000, 0x1000, 0x80004"),
            ("Class 2 \u2014 SystemPerformanceInformation",  "2, 0x80000, 0x1000, 0x80004"),
            ("Class 5 \u2014 SystemProcessInformation",      "5, 0x80000, 0x4000, 0x80004"),
            ("Class 8 \u2014 SystemProcessorInfo",           "8, 0x80000, 0x1000, 0x80004"),
            ("Class 11 \u2014 SystemModuleInformation",      "0xb, 0x80000, 0x4000, 0x80004"),
        ],
        "NtQueryInformationProcess": [
            ("Class 0 \u2014 ProcessBasicInformation",  "-1, 0, 0x80000, 0x18, 0x80018"),
            ("Class 7 \u2014 ProcessDebugPort",         "-1, 7, 0x80000, 4, 0x80004"),
            ("Class 30 \u2014 ProcessWow64Information", "-1, 30, 0x80000, 4, 0x80004"),
        ],
        "NtCreateFile": [
            ("Open null (exercise validation)", "0x80000, 0x80100000, 0, 0x80200, 0, 0, 1, 0, 0, 0, 0, 0"),
        ],
        "NtOpenFile": [
            ("Open null (exercise validation)", "0x80000, 0x80100000, 0, 0x80200, 0, 0"),
        ],
        "NtReadFile": [
            ("Handle + null buffer", "0x100, 0, 0, 0, 0x80200, 0x80300, 0x1000, 0, 0"),
        ],
        "NtWriteFile": [
            ("Handle + null buffer", "0x100, 0, 0, 0, 0x80200, 0x80300, 0x1000, 0, 0"),
        ],
        "NtAllocateVirtualMemory": [
            ("Commit 4KB private",  "-1, 0x80000, 0, 0x80004, 0x1000, 4"),
            ("Reserve 64KB",        "-1, 0x80000, 0, 0x80004, 0x2000, 4"),
        ],
        "NtFreeVirtualMemory": [
            ("Release at address", "-1, 0x80000, 0x80004, 0x8000"),
        ],
        "NtDeviceIoControlFile": [
            ("Null IOCTL", "0x100, 0, 0, 0, 0x80200, 0x80000, 0, 0, 0, 0"),
        ],
        "NtQueryInformationFile": [
            ("FileBasicInformation",    "0x100, 0x80200, 0x80300, 0x28, 4"),
            ("FileStandardInformation", "0x100, 0x80200, 0x80300, 0x18, 5"),
        ],
        "NtSetInformationFile": [
            ("FileBasicInformation",       "0x100, 0x80200, 0x80300, 0x28, 4"),
            ("FileDispositionInformation", "0x100, 0x80200, 0x80300, 1, 13"),
        ],
        "NtQueryInformationThread": [
            ("ThreadBasicInformation", "-2, 0, 0x80000, 0x1C, 0x80020"),
        ],
        "NtOpenKey": [
            ("Null attributes", "0x80000, 0x80100000, 0"),
        ],
        "NtQueryKey": [
            ("KeyBasicInformation", "0x100, 0, 0x80000, 0x100, 0x80100"),
            ("KeyFullInformation",  "0x100, 2, 0x80000, 0x200, 0x80200"),
        ],
        "NtQueryValueKey": [
            ("KeyValueBasicInformation", "0x100, 0x80200, 0, 0x80300, 0x100, 0x80400"),
        ],
    }

    def _show_arg_presets(self):
        """Show a dropdown menu of preset arguments for the current function."""
        func = self._get_func()

        menu = tk.Menu(self.app, tearoff=0, bg=T["bg_light"], fg=T["fg"],
                       activebackground=T["accent"], activeforeground="#000000",
                       font=("Consolas", 9))

        if func and func in self._ARG_PRESETS:
            menu.add_command(label=f"\u2500\u2500 {func} \u2500\u2500",
                             state="disabled")
            for desc, args in self._ARG_PRESETS[func]:
                menu.add_command(label=f"  {desc}",
                    command=lambda a=args: self._apply_preset_args(a))
            menu.add_separator()

        # Also try to get signature from KERNEL_API_SIGNATURES
        if func:
            try:
                from nt_analyzer.decompiler import KERNEL_API_SIGNATURES
                sig = KERNEL_API_SIGNATURES.get(func)
                if sig:
                    ret_type, params = sig
                    param_str = ", ".join(f"{t} {n}" for t, n in params)
                    menu.add_command(
                        label=f"Sig: {ret_type} {func}({param_str})",
                        state="disabled")
                    # Generate zero-filled args from signature
                    zero_args = ", ".join("0" for _ in params)
                    menu.add_command(
                        label=f"  All zeros ({len(params)} args)",
                        command=lambda a=zero_args: self._apply_preset_args(a))
            except Exception:
                pass

        # Show other functions that have presets
        others = [f for f in sorted(self._ARG_PRESETS) if f != func]
        if others:
            menu.add_separator()
            menu.add_command(label="\u2500\u2500 Other functions \u2500\u2500",
                             state="disabled")
            for fn in others:
                sub = tk.Menu(menu, tearoff=0, bg=T["bg_light"], fg=T["fg"],
                              activebackground=T["accent"],
                              activeforeground="#000000",
                              font=("Consolas", 9))
                for desc, args in self._ARG_PRESETS[fn]:
                    sub.add_command(label=f"  {desc}",
                        command=lambda f=fn, a=args:
                            self._apply_preset(f, a))
                menu.add_cascade(label=f"  {fn}", menu=sub)

        # Position below the Presets button
        try:
            x = self._args_ent.winfo_rootx() + self._args_ent.winfo_width()
            y = self._args_ent.winfo_rooty() + self._args_ent.winfo_height()
            menu.tk_popup(x, y)
        except Exception:
            menu.tk_popup(
                self.app.winfo_pointerx(), self.app.winfo_pointery())

    def _apply_preset_args(self, args_str):
        """Apply a preset args string to the args entry."""
        if isinstance(self._args_ent, PlaceholderEntry):
            self._args_ent.set_value(args_str)
        else:
            self._args_var.set(args_str)

    def _apply_preset(self, func_name, args_str):
        """Apply a preset: set function name and args."""
        if isinstance(self._func_ent, PlaceholderEntry):
            self._func_ent.set_value(func_name)
        else:
            self._func_var.set(func_name)
        self._apply_preset_args(args_str)

    # ── split view ────────────────────────────────────────────────────────

    def _toggle_split_view(self):
        """Toggle between tabbed mode and side-by-side (trace + disasm)."""
        if self._split_mode:
            self._restore_tabbed_view()
        else:
            self._enter_split_view()

    def _enter_split_view(self):
        """Switch to side-by-side: trace left, disasm right."""
        # Find the trace tab
        trace_tab_title = self._trace_tab_title
        if not trace_tab_title:
            for tab_id in reversed(self.output._nb.tabs()):
                title = self.output._nb.tab(tab_id, "text").strip()
                if any(title.startswith(p) for p in
                       ("Run:", "Debug:", "Run\u2192BP:")):
                    trace_tab_title = title
                    break

        if not trace_tab_title and not self._disasm_view:
            self.status_var.set(
                "\u26A0 Need a trace or disassembly tab for split view")
            return

        # Hide the normal output notebook
        self.output.grid_forget()

        # Create a PanedWindow for side-by-side
        pw = tk.PanedWindow(self, orient="horizontal", bg=T["separator"],
                            sashwidth=4, sashrelief="flat",
                            opaqueresize=True, bd=0)
        pw.grid(row=8, column=0, sticky="nsew", padx=10, pady=(4, 10))

        # ── Left pane: trace output ──
        left_frm = tk.Frame(pw, bg=T["bg_dark"])
        left_frm.columnconfigure(0, weight=1)
        left_frm.rowconfigure(1, weight=1)

        left_hdr = tk.Frame(left_frm, bg=T["bg"])
        left_hdr.grid(row=0, column=0, sticky="ew")
        tk.Label(left_hdr, text=f"  {trace_tab_title or 'Trace'}  ",
                 bg=T["bg"], fg=T["accent"],
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=4, pady=2)

        left_txt = scrolledtext.ScrolledText(
            left_frm, bg=T["bg_dark"], fg=T["fg"], insertbackground=T["fg"],
            font=("Consolas", 10), relief="flat", bd=8,
            wrap="none", state="disabled")
        left_txt.grid(row=1, column=0, sticky="nsew")
        _configure_output_tags(left_txt)

        # Copy trace content from the existing tab
        if trace_tab_title:
            _, src_widget = self.output.find_tab(trace_tab_title)
            if src_widget and hasattr(src_widget, 'get'):
                content = src_widget.get("1.0", "end-1c")
                left_txt.configure(state="normal")
                left_txt.insert("1.0", content)
                left_txt.see("end")
                left_txt.configure(state="disabled")

        pw.add(left_frm, stretch="always")

        # ── Right pane: disassembly ──
        right_frm = tk.Frame(pw, bg=T["bg_dark"])
        right_frm.columnconfigure(0, weight=1)
        right_frm.rowconfigure(1, weight=1)

        right_hdr = tk.Frame(right_frm, bg=T["bg"])
        right_hdr.grid(row=0, column=0, sticky="ew")

        func = self._get_func()
        disasm_title = f"Disasm: {func}" if func else "Disassembly"
        tk.Label(right_hdr, text=f"  {disasm_title}  ",
                 bg=T["bg"], fg=T["accent"],
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=4, pady=2)
        ttk.Button(right_hdr, text="\u2716 Restore Tabs",
                   command=self._restore_tabbed_view).pack(
                       side="right", padx=4, pady=2)

        if self._disasm_view:
            # Reparent disasm view into right pane
            self._disasm_view_original_parent = self._disasm_view.master
            self._disasm_view.grid_forget()
            self._disasm_view.grid(in_=right_frm, row=1, column=0,
                                   sticky="nsew")
        else:
            tk.Label(right_frm,
                     text="No disassembly loaded.\nClick Disassemble first.",
                     bg=T["bg_dark"], fg=T["fg_dim"],
                     font=("Consolas", 10)).grid(
                         row=1, column=0, sticky="nsew")

        pw.add(right_frm, stretch="always")

        self._split_pane = pw
        self._split_left_txt = left_txt
        self._split_left_title = trace_tab_title
        self._split_mode = True
        self.status_var.set(
            "\u2B0C Split view \u2014 click \u2716 Restore Tabs to go back")

    def _restore_tabbed_view(self):
        """Restore the normal tabbed output view."""
        if not self._split_mode:
            return

        # Reparent disasm view back to its original tab
        if (self._disasm_view and
                hasattr(self, '_disasm_view_original_parent')):
            orig = self._disasm_view_original_parent
            self._disasm_view.grid_forget()
            self._disasm_view.grid(in_=orig, row=0, column=0, sticky="nsew")

        # Destroy the split pane
        if self._split_pane:
            self._split_pane.grid_forget()
            self._split_pane.destroy()
            self._split_pane = None

        # Re-grid the normal output
        self.output.grid(row=8, column=0, sticky="nsew",
                         padx=10, pady=(4, 10))

        self._split_mode = False
        self.status_var.set("Kernel debugger ready")

    def _parse_args(self):
        """Parse the args entry into a list of ints."""
        raw = self._args_ent.get_value() if isinstance(
            self._args_ent, PlaceholderEntry) else self._args_var.get()
        if not raw.strip():
            return []
        parts = [p.strip() for p in raw.split(',')]
        result = []
        for p in parts:
            if not p:
                continue
            result.append(int(p, 0))  # supports 0x hex
        return result

    def _get_func(self):
        if isinstance(self._func_ent, PlaceholderEntry):
            return self._func_ent.get_value()
        return self._func_var.get()

    def _ensure_env(self):
        if self._env and self._loaded:
            return True
        self.status_var.set("\u26A0 Load core first (click Load Core)")
        return False

    def _update_disasm_eip(self):
        """Update EIP marker in disassembly view if one is open."""
        if self._disasm_view and self._dbg:
            try:
                regs = self._dbg.inspect_registers()
                self._disasm_view.update_eip(regs['eip'])
            except Exception:
                pass

    # ── load / unload ─────────────────────────────────────────────────────

    def _load_core(self):
        sys32 = self._get_sys32()
        if not sys32 or not os.path.isdir(sys32):
            messagebox.showwarning("Missing", "Select a valid System32 folder.")
            return
        self.output.new_tab("Load Core")

        def work(progress_cb):
            kdbg = _kdbg()
            env = kdbg.KernelEnvironment(sys32)
            env.load_core(progress_cb=progress_cb)
            progress_cb("Loading dependencies\u2026", 75)
            env.auto_load_dependencies(progress_cb=progress_cb)
            return env

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._env = result
            self._loaded = True
            self._dbg = None
            self._insp = _kdbg().ObjectInspector(self._env)
            info = self._env.get_info()
            output_write(self.output, "  KERNEL ENVIRONMENT LOADED\n\n", "title")
            output_write(self.output, f"  System Root: {info['system_root']}\n", "ok")
            output_write(self.output, f"  Modules: {info['modules_loaded']} (with dependencies)\n", "ok")
            output_write(self.output, f"  Available files: {info['available_files']}\n\n")
            for name, m in info.get('modules', {}).items():
                output_write(self.output,
                    f"  {name:24s}  base={m['base']}  "
                    f"exports={m['exports']:5d}  unresolved={m['unresolved']}\n")
            self.status_var.set(
                f"\u2705 Loaded: {info['modules_loaded']} modules, "
                f"{info['available_files']} files available")

        run_with_progress_dialog(self.app, "Loading kernel environment + dependencies\u2026", work, done)

    def _load_deps(self):
        if not self._ensure_env():
            return
        self.output.new_tab("Dependencies")

        def work(progress_cb):
            self._env.auto_load_dependencies(progress_cb=progress_cb)
            return self._env.get_info()

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  DEPENDENCY RESOLUTION\n\n", "title")
            for name, m in result.get('modules', {}).items():
                tag = "ok" if m['unresolved'] == 0 else "warn"
                output_write(self.output,
                    f"  {name:24s}  base={m['base']}  "
                    f"exports={m['exports']:5d}  unresolved={m['unresolved']}\n", tag)
            # Gather unresolved imports from modules
            any_unresolved = False
            for name, m in result.get('modules', {}).items():
                if m['unresolved'] > 0:
                    any_unresolved = True
            if any_unresolved:
                output_write(self.output, f"\n  Some imports remain unresolved "
                    f"(DLLs not found in system32 folder)\n", "warn")
            self.status_var.set(
                f"\u2705 {result['modules_loaded']} modules loaded")

        run_with_progress_dialog(self.app, "Loading dependencies\u2026", work, done)

    def _load_symbols(self):
        if not self._ensure_env():
            return
        path = filedialog.askopenfilename(
            filetypes=[("Symbol files", "*.map *.pdb *.dbg *.sym"),
                       ("All files", "*.*")])
        if not path:
            return

        # Auto-detect module name from symbol filename
        sym_base = os.path.splitext(os.path.basename(path))[0].lower()
        # Find matching module
        mod_name = None
        for name in self._env.modules:
            if os.path.splitext(name)[0].lower() == sym_base:
                mod_name = name
                break
        if not mod_name:
            mod_name = list(self._env.modules.keys())[0] if self._env.modules else sym_base

        def work(progress_cb):
            progress_cb(f"Loading symbols for {mod_name}\u2026", 30)
            count = self._env.load_symbols_from_file(mod_name, path)
            progress_cb("Done", 100)
            return count

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                return
            self.status_var.set(f"\u2705 Symbols loaded: {result} symbols for {mod_name}")

        run_with_progress_dialog(self.app, "Loading symbols\u2026", work, done)

    def _unload(self):
        if self._env:
            try:
                self._env.close()
            except Exception:
                pass
        self._env = None
        self._dbg = None
        self._insp = None
        self._loaded = False
        self.status_var.set("Environment unloaded")

    # ── run / step / continue ─────────────────────────────────────────────

    def _make_session(self):
        """Create or reuse a DebugSession, preserving breakpoints."""
        kdbg = _kdbg()
        if not self._dbg or self._dbg.state == kdbg.DebugState.STOPPED:
            old_bps = None
            if self._dbg:
                old_bps = self._dbg.list_breakpoints()
            self._dbg = kdbg.DebugSession(self._env)
            # Carry forward breakpoints from previous session
            if old_bps:
                for bp in old_bps:
                    try:
                        self._dbg.set_breakpoint(bp.address)
                    except Exception:
                        pass
        return self._dbg

    def _run(self):
        if not self._ensure_env():
            return
        func = self._get_func()
        if not func:
            messagebox.showwarning("Missing", "Enter a function name.")
            return
        args = self._parse_args()
        show_trace = self._show_trace_var.get()
        user_mode = self._user_mode_var.get()
        self.output.new_tab_hidden(f"Run: {func}")
        self._trace_tab_title = f"Run: {func}"

        def work(progress_cb):
            progress_cb(f"Resolving {func}\u2026", 10)
            dbg = self._make_session()
            progress_cb(f"Running {func}\u2026", 30)
            result = dbg.run(func, args=args, show_trace=show_trace,
                             user_mode=user_mode)
            if 'error' in result:
                return result  # pass error dict through
            progress_cb("Formatting results\u2026", 90)
            return dbg.format_result(result, show_trace=show_trace)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                self.output.write_to_tab(self._trace_tab_title or "Run",
                    f"ERROR: {result}\n", "error")
                return
            if isinstance(result, dict) and 'error' in result:
                self.status_var.set(f"\u274C {result['error']}")
                self.output.write_to_tab(self._trace_tab_title or "Run",
                    f"  \u274C {result['error']}\n", "error")
                return
            # Write report to trace tab without switching
            trace_tab = self._trace_tab_title or "Run"
            for line in result.split('\n'):
                self.output.write_to_tab(trace_tab, line + '\n')
            self._update_disasm_execution(None)
            self.status_var.set("\u2705 Run complete")

        run_with_progress_dialog(self.app, f"Running {func}\u2026", work, done)

    def _run_break(self):
        if not self._ensure_env():
            return
        func = self._get_func()
        if not func:
            messagebox.showwarning("Missing", "Enter a function name.")
            return
        args = self._parse_args()
        show_trace = self._show_trace_var.get()
        user_mode = self._user_mode_var.get()
        self.output.new_tab_hidden(f"Debug: {func}")
        self._trace_tab_title = f"Debug: {func}"

        def work(progress_cb):
            progress_cb(f"Resolving {func}\u2026", 10)
            dbg = self._make_session()
            progress_cb(f"Running {func} (break at entry)\u2026", 30)
            result = dbg.run(func, args=args, show_trace=show_trace,
                             user_mode=user_mode, stop_at_entry=True)
            progress_cb("Done", 100)
            return result

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                self.output.write_to_tab(self._trace_tab_title or "Debug",
                    f"ERROR: {result}\n", "error")
                return
            kdbg = _kdbg()
            trace_tab = self._trace_tab_title or "Debug"
            if self._dbg and self._dbg.state == kdbg.DebugState.PAUSED:
                regs = self._dbg.inspect_registers()
                eip = regs['eip']
                eip_name = regs.get('eip_name', f'0x{eip:08X}')
                self.output.write_to_tab(trace_tab,
                    f"  \u23F8 PAUSED at {eip_name}\n\n", "title")
                pairs = [
                    ("EAX", regs.get("eax", 0)), ("EBX", regs.get("ebx", 0)),
                    ("ECX", regs.get("ecx", 0)), ("EDX", regs.get("edx", 0)),
                    ("ESI", regs.get("esi", 0)), ("EDI", regs.get("edi", 0)),
                    ("EBP", regs.get("ebp", 0)), ("ESP", regs.get("esp", 0)),
                    ("EIP", regs.get("eip", 0)),
                ]
                reg_line = "".join(f"  {n}=0x{v:08X}" for n, v in pairs)
                self.output.write_to_tab(trace_tab, reg_line + "\n", "ok")
                self.status_var.set(
                    f"\u23F8 Paused at {eip_name} \u2014 use Step / Continue")
                self._update_disasm_eip()
                self._update_disasm_execution(result)
            else:
                report = self._dbg.format_result(result, show_trace=show_trace)
                for line in report.split('\n'):
                    self.output.write_to_tab(trace_tab, line + '\n')
                self._update_disasm_execution(result)
                self.status_var.set("\u2705 Run complete (no break)")

        run_with_progress_dialog(self.app, f"Debugging {func}\u2026", work, done)

    def _step(self):
        kdbg = _kdbg()
        if not self._dbg or self._dbg.state != kdbg.DebugState.PAUSED:
            self.status_var.set("\u26A0 Not paused — use Run+Break first")
            return
        result = self._dbg.step()
        if not result:
            return
        # Write trace to the debug tab WITHOUT switching away from current tab
        trace_tab = self._trace_tab_title or "Trace"
        if result.get("state") == "completed":
            retval = result.get("return_value", 0)
            self.output.write_to_tab(trace_tab,
                f"\n  \u2705 Function returned: 0x{retval:08X} "
                f"({kdbg.ntstatus_name(retval)})\n", "ok")
            self.status_var.set(
                f"\u2705 Completed: 0x{retval:08X} ({kdbg.ntstatus_name(retval)})")
            return
        if "error" in result:
            self.output.write_to_tab(trace_tab,
                f"\n  \u274C Error: {result['error']}\n", "error")
            return
        eip = result['eip']
        eip_name = result.get('eip_name', f'0x{eip:08X}')
        self.output.write_to_tab(trace_tab,
            f"  \u25B6 0x{eip:08X}  {eip_name}\n")
        self.status_var.set(f"\u23F8 Step: {eip_name}")
        self._update_disasm_eip()

    def _continue(self):
        kdbg = _kdbg()
        if not self._dbg or self._dbg.state != kdbg.DebugState.PAUSED:
            self.status_var.set("\u26A0 Not paused — nothing to continue")
            return

        def work(progress_cb):
            progress_cb("Continuing execution\u2026", 30)
            result = self._dbg.continue_run()
            progress_cb("Done", 100)
            return result

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                trace_tab = self._trace_tab_title or "Trace"
                self.output.write_to_tab(trace_tab,
                    f"ERROR: {result}\n", "error")
                return
            # Write continue output to trace tab WITHOUT switching
            trace_tab = self._trace_tab_title or "Trace"
            kdbg2 = _kdbg()
            if result.get("state") == "paused":
                regs = self._dbg.inspect_registers()
                eip = regs['eip']
                eip_name = regs.get('eip_name', f'0x{eip:08X}')
                self.output.write_to_tab(trace_tab,
                    f"\n  \u23F8 Breakpoint at {eip_name}\n", "title")
                # Write registers to trace tab
                pairs = [
                    ("EAX", regs.get("eax", 0)), ("EBX", regs.get("ebx", 0)),
                    ("ECX", regs.get("ecx", 0)), ("EDX", regs.get("edx", 0)),
                    ("ESI", regs.get("esi", 0)), ("EDI", regs.get("edi", 0)),
                    ("EBP", regs.get("ebp", 0)), ("ESP", regs.get("esp", 0)),
                    ("EIP", regs.get("eip", 0)),
                ]
                reg_line = "".join(f"  {n}=0x{v:08X}" for n, v in pairs)
                self.output.write_to_tab(trace_tab, reg_line + "\n", "ok")
                self.status_var.set(f"\u23F8 Paused at {eip_name}")
                self._update_disasm_eip()
                self._update_disasm_execution(result)
            else:
                retval = result.get("return_value", 0)
                show_trace = self._show_trace_var.get()
                report = self._dbg.format_result(result,
                                                  show_trace=show_trace)
                # Write completion report to trace tab
                for line in report.split('\n'):
                    self.output.write_to_tab(trace_tab, line + '\n')
                self._update_disasm_execution(result)
                self.status_var.set(
                    f"\u2705 Completed: 0x{retval:08X} "
                    f"({kdbg2.ntstatus_name(retval)})")

        run_with_progress_dialog(self.app, "Continuing execution\u2026", work, done)

    def _run_until_bp(self):
        """Run function until next breakpoint (like WinDbg 'g').
        If already paused, continues from current position to next BP."""
        if not self._ensure_env():
            return
        kdbg = _kdbg()

        # If already paused — just continue to next breakpoint (same as Continue)
        if self._dbg and self._dbg.state == kdbg.DebugState.PAUSED:
            trace_tab = self._trace_tab_title or "Trace"

            def work_cont(progress_cb):
                progress_cb("Continuing to next breakpoint\u2026", 30)
                result = self._dbg.continue_run()
                progress_cb("Done", 100)
                return result

            def done_cont(result):
                if isinstance(result, Exception):
                    self.status_var.set(f"\u274C {result}")
                    self.output.write_to_tab(trace_tab,
                        f"ERROR: {result}\n", "error")
                    return
                tab = self._trace_tab_title or "Trace"
                kdbg2 = _kdbg()
                # Use result dict state as primary truth (consistent with _continue)
                got_bp = (isinstance(result, dict) and
                          result.get("state") == "paused") or (
                          self._dbg and
                          self._dbg.state == kdbg2.DebugState.PAUSED)
                if got_bp and self._dbg:
                    regs = self._dbg.inspect_registers()
                    eip = regs['eip']
                    eip_name = regs.get('eip_name', f'0x{eip:08X}')
                    self.output.write_to_tab(tab,
                        f"  \u23F8 BREAKPOINT HIT at {eip_name}\n\n", "title")
                    pairs = [
                        ("EAX", regs.get("eax", 0)), ("EBX", regs.get("ebx", 0)),
                        ("ECX", regs.get("ecx", 0)), ("EDX", regs.get("edx", 0)),
                        ("ESI", regs.get("esi", 0)), ("EDI", regs.get("edi", 0)),
                        ("EBP", regs.get("ebp", 0)), ("ESP", regs.get("esp", 0)),
                        ("EIP", regs.get("eip", 0)),
                    ]
                    reg_line = "".join(f"  {n}=0x{v:08X}" for n, v in pairs)
                    self.output.write_to_tab(tab, reg_line + "\n", "ok")
                    self.status_var.set(
                        f"\u23F8 Paused at {eip_name} \u2014 use Step / Run Until BP")
                    self._update_disasm_eip()
                    self._update_disasm_execution(result)
                else:
                    # Function completed — clear EIP arrow in disassembly
                    if self._disasm_view:
                        try:
                            self._disasm_view.clear_eip()
                        except Exception:
                            pass
                    retval = result.get("return_value", 0) if isinstance(result, dict) else 0
                    show_trace = self._show_trace_var.get()
                    if isinstance(result, dict):
                        self._bp_not_hit_diagnostic(result, tab)
                        self.output.write_to_tab(tab, "\n")
                        report = self._dbg.format_result(result, show_trace=show_trace)
                        for line in report.split('\n'):
                            self.output.write_to_tab(tab, line + '\n')
                    self._update_disasm_execution(result)
                    self.status_var.set(
                        f"\u2705 Completed: 0x{retval:08X} "
                        f"({kdbg2.ntstatus_name(retval)})")

            run_with_progress_dialog(self.app,
                "Continuing to next breakpoint\u2026", work_cont, done_cont)
            return

        # Not paused — start fresh run until a breakpoint fires
        func = self._get_func()
        if not func:
            messagebox.showwarning("Missing", "Enter a function name.")
            return
        args = self._parse_args()
        show_trace = self._show_trace_var.get()
        user_mode = self._user_mode_var.get()
        tab_title = f"Run\u2192BP: {func}"
        self.output.new_tab_hidden(tab_title)
        self._trace_tab_title = tab_title

        def work(progress_cb):
            progress_cb(f"Resolving {func}\u2026", 10)
            dbg = self._make_session()
            progress_cb(f"Running {func} until breakpoint\u2026", 30)
            result = dbg.run(func, args=args, show_trace=show_trace,
                             user_mode=user_mode)
            progress_cb("Done", 100)
            return result

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                self.output.write_to_tab(self._trace_tab_title or "Run\u2192BP",
                    f"ERROR: {result}\n", "error")
                return
            if isinstance(result, dict) and 'error' in result:
                self.status_var.set(f"\u274C {result['error']}")
                self.output.write_to_tab(self._trace_tab_title or "Run\u2192BP",
                    f"  \u274C {result['error']}\n", "error")
                return
            kdbg = _kdbg()
            trace_tab = self._trace_tab_title or "Run\u2192BP"
            if self._dbg and self._dbg.state == kdbg.DebugState.PAUSED:
                regs = self._dbg.inspect_registers()
                eip = regs['eip']
                eip_name = regs.get('eip_name', f'0x{eip:08X}')
                self.output.write_to_tab(trace_tab,
                    f"  \u23F8 BREAKPOINT HIT at {eip_name}\n\n", "title")
                pairs = [
                    ("EAX", regs.get("eax", 0)), ("EBX", regs.get("ebx", 0)),
                    ("ECX", regs.get("ecx", 0)), ("EDX", regs.get("edx", 0)),
                    ("ESI", regs.get("esi", 0)), ("EDI", regs.get("edi", 0)),
                    ("EBP", regs.get("ebp", 0)), ("ESP", regs.get("esp", 0)),
                    ("EIP", regs.get("eip", 0)),
                ]
                reg_line = "".join(f"  {n}=0x{v:08X}" for n, v in pairs)
                self.output.write_to_tab(trace_tab, reg_line + "\n", "ok")
                self.status_var.set(
                    f"\u23F8 Paused at {eip_name} \u2014 use Step / Continue")
                self._update_disasm_eip()
                self._update_disasm_execution(result)
            else:
                self._bp_not_hit_diagnostic(result, trace_tab)
                self.output.write_to_tab(trace_tab, "\n")
                report = self._dbg.format_result(result,
                                                  show_trace=show_trace)
                for line in report.split('\n'):
                    self.output.write_to_tab(trace_tab, line + '\n')
                self._update_disasm_execution(result)
                self.status_var.set("\u2705 Run complete (no BP hit)")

        run_with_progress_dialog(self.app,
            f"Running {func} until breakpoint\u2026", work, done)

    # ── breakpoints ───────────────────────────────────────────────────────

    def _add_breakpoint(self):
        if not self._ensure_env():
            return
        raw = self._bp_ent.get_value() if isinstance(
            self._bp_ent, PlaceholderEntry) else self._bp_var.get()
        raw = raw.strip()
        if not raw:
            messagebox.showwarning("Missing", "Enter a breakpoint name or address.")
            return
        dbg = self._make_session()
        # Parse hex address if applicable
        target = raw
        if raw.startswith("0x") or raw.startswith("0X"):
            try:
                target = int(raw, 16)
            except ValueError:
                pass
        try:
            bp_id = dbg.set_breakpoint(target)
            self.status_var.set(f"\U0001F6D1 Breakpoint #{bp_id} set: {raw}")
            if self._disasm_view:
                self._disasm_view._refresh_breakpoint_markers()
        except ValueError as e:
            self.status_var.set(f"\u274C {e}")

    def _list_breakpoints(self):
        if not self._dbg:
            self.status_var.set("No debug session active")
            return
        bps = self._dbg.list_breakpoints()
        if not bps:
            self.status_var.set("No breakpoints set")
            return

        # Create interactive breakpoint tab
        self.output._counter += 1
        frm = ttk.Frame(self.output._nb)
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)

        # Toolbar
        tb = tk.Frame(frm, bg=T["bg"])
        tb.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        ttk.Button(tb, text="Delete All",
                   command=lambda: self._bp_delete_all(frm)).pack(side="right", padx=4)
        ttk.Button(tb, text="Refresh",
                   command=lambda: self._bp_refresh(frm, bp_list)).pack(side="right", padx=4)

        # Scrollable list
        canvas = tk.Canvas(frm, bg=T["bg_dark"], highlightthickness=0)
        vsb = ttk.Scrollbar(frm, orient="vertical", command=canvas.yview)
        bp_list = tk.Frame(canvas, bg=T["bg_dark"])
        bp_list.bind("<Configure>",
                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=bp_list, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        frm.columnconfigure(0, weight=1)

        # Auto-close oldest
        tab_ids = self.output._nb.tabs()
        if len(tab_ids) >= 20:
            oldest = tab_ids[0]
            self.output._nb.forget(oldest)
            self.output._tabs.pop(oldest, None)

        self.output._nb.add(frm, text="  Breakpoints  ")
        self.output._nb.select(frm)
        self.output._tabs[str(frm)] = canvas  # store for tab tracking

        self._bp_refresh(frm, bp_list)

    def _bp_refresh(self, frm, bp_list):
        """Refresh the interactive breakpoint list."""
        for w in bp_list.winfo_children():
            w.destroy()

        if not self._dbg:
            return
        bps = self._dbg.list_breakpoints()

        if not bps:
            lbl = tk.Label(bp_list, text="  No breakpoints set",
                           bg=T["bg_dark"], fg="#888888",
                           font=("Consolas", 10))
            lbl.pack(anchor="w", padx=8, pady=8)
            return

        # Header
        hdr = tk.Frame(bp_list, bg=T["bg"])
        hdr.pack(fill="x", padx=4, pady=(4, 2))
        for col, w in [("ID", 4), ("Address", 12), ("Name", 36),
                        ("Hits", 6), ("State", 8), ("", 14)]:
            tk.Label(hdr, text=col, bg=T["bg"], fg="#AAAAAA",
                     font=("Consolas", 9, "bold"), width=w,
                     anchor="w").pack(side="left")

        for bp in bps:
            row = tk.Frame(bp_list, bg=T["bg_dark"])
            row.pack(fill="x", padx=4, pady=1)

            fg = T["fg"] if bp.enabled else "#666666"
            tk.Label(row, text=f"#{bp.id}", bg=T["bg_dark"], fg=fg,
                     font=("Consolas", 10), width=4,
                     anchor="w").pack(side="left")
            tk.Label(row, text=f"0x{bp.address:08X}", bg=T["bg_dark"],
                     fg="#DCDCAA", font=("Consolas", 10), width=12,
                     anchor="w").pack(side="left")
            tk.Label(row, text=bp.name, bg=T["bg_dark"], fg=fg,
                     font=("Consolas", 10), width=36,
                     anchor="w").pack(side="left")
            tk.Label(row, text=str(bp.hit_count), bg=T["bg_dark"],
                     fg="#888888", font=("Consolas", 10), width=6,
                     anchor="w").pack(side="left")

            state_text = "enabled" if bp.enabled else "disabled"
            state_fg = "#4EC9B0" if bp.enabled else "#D16969"
            tk.Label(row, text=state_text, bg=T["bg_dark"], fg=state_fg,
                     font=("Consolas", 10), width=8,
                     anchor="w").pack(side="left")

            # Toggle button
            toggle_text = "Disable" if bp.enabled else "Enable"
            bp_id = bp.id
            ttk.Button(row, text=toggle_text, width=7,
                       command=lambda bid=bp_id: self._bp_toggle(bid, frm, bp_list)
                       ).pack(side="left", padx=2)

            # Delete button
            ttk.Button(row, text="\u2716", width=3,
                       command=lambda bid=bp_id: self._bp_delete(bid, frm, bp_list)
                       ).pack(side="left", padx=2)

    def _bp_toggle(self, bp_id, frm, bp_list):
        """Toggle a breakpoint enabled/disabled."""
        if not self._dbg:
            return
        for bp in self._dbg.list_breakpoints():
            if bp.id == bp_id:
                bp.enabled = not bp.enabled
                break
        if self._disasm_view:
            self._disasm_view._refresh_breakpoint_markers()
        self._bp_refresh(frm, bp_list)

    def _bp_delete(self, bp_id, frm, bp_list):
        """Delete a single breakpoint."""
        if not self._dbg:
            return
        self._dbg.remove_breakpoint(bp_id)
        if self._disasm_view:
            self._disasm_view._refresh_breakpoint_markers()
        self._bp_refresh(frm, bp_list)
        self.status_var.set(f"Breakpoint #{bp_id} deleted")

    def _bp_delete_all(self, frm):
        """Delete all breakpoints."""
        if not self._dbg:
            return
        for bp in list(self._dbg.list_breakpoints()):
            self._dbg.remove_breakpoint(bp.id)
        if self._disasm_view:
            self._disasm_view._refresh_breakpoint_markers()
        # Find bp_list frame inside frm
        for w in frm.winfo_children():
            if isinstance(w, tk.Canvas):
                for child_id in w.find_all():
                    widget = w.nametowidget(w.itemcget(child_id, 'window'))
                    if isinstance(widget, tk.Frame):
                        self._bp_refresh(frm, widget)
                        break
                break
        self.status_var.set("All breakpoints deleted")

    # ── inspection ────────────────────────────────────────────────────────

    def _clear_output(self):
        """Clear the currently active output tab."""
        self.output.clear_current()

    def _write_regs(self, regs):
        """Write register state to output."""
        pairs = [
            ("EAX", regs.get("eax", 0)), ("EBX", regs.get("ebx", 0)),
            ("ECX", regs.get("ecx", 0)), ("EDX", regs.get("edx", 0)),
            ("ESI", regs.get("esi", 0)), ("EDI", regs.get("edi", 0)),
            ("EBP", regs.get("ebp", 0)), ("ESP", regs.get("esp", 0)),
            ("EIP", regs.get("eip", 0)),
        ]
        for name, val in pairs:
            output_write(self.output, f"  {name}=0x{val:08X}", "ok")
        output_write(self.output, "\n")

    def _write_report(self, report_text):
        """Write a formatted report string to output."""
        for line in report_text.split('\n'):
            if '\u2550' in line or '\u2500' in line:
                output_write(self.output, line + '\n', "heading")
            elif line.strip().startswith('\U0001F534') or \
                 line.strip().startswith('\u26A0'):
                output_write(self.output, line + '\n', "warn")
            elif 'STATUS_SUCCESS' in line:
                output_write(self.output, line + '\n', "ok")
            elif 'ERROR' in line or '0xC' in line:
                output_write(self.output, line + '\n', "error")
            else:
                output_write(self.output, line + '\n')

    def _show_regs(self):
        kdbg = _kdbg()
        if not self._dbg or self._dbg.state not in (
                kdbg.DebugState.PAUSED, kdbg.DebugState.STOPPED):
            self.status_var.set("\u26A0 No active session")
            return
        regs = self._dbg.inspect_registers()
        self.output.get_or_create_tab("Registers")
        output_write(self.output, "\n  \u2500\u2500\u2500 CPU REGISTERS \u2500\u2500\u2500\n\n", "title")
        self._write_regs(regs)
        efl = regs.get("eflags", 0)
        output_write(self.output, f"\n  EFLAGS=0x{efl:08X}  ", "dim")
        flags = []
        if efl & 0x01: flags.append("CF")
        if efl & 0x04: flags.append("PF")
        if efl & 0x40: flags.append("ZF")
        if efl & 0x80: flags.append("SF")
        if efl & 0x800: flags.append("OF")
        output_write(self.output, " ".join(flags) + "\n", "dim")

    def _show_callstack(self):
        kdbg = _kdbg()
        if not self._dbg or self._dbg.state not in (
                kdbg.DebugState.PAUSED, kdbg.DebugState.STOPPED):
            self.status_var.set("\u26A0 No active session")
            return
        frames = self._dbg.get_call_stack()
        self.output.get_or_create_tab("Call Stack")
        output_write(self.output, "\n  \u2500\u2500\u2500 CALL STACK \u2500\u2500\u2500\n\n", "title")
        if not frames:
            output_write(self.output, "  (empty)\n", "dim")
            return
        for i, f in enumerate(frames):
            mod = f.module or ""
            func = f.function or self._env.describe_address(f.return_address)
            if mod:
                display = f"{mod}!{func}"
            else:
                display = func
            output_write(self.output,
                f"  #{i:2d}  {display}  "
                f"(FP=0x{f.frame_pointer:08X})\n", "ok")

    def _show_stack_mem(self):
        kdbg = _kdbg()
        if not self._dbg or self._dbg.state not in (
                kdbg.DebugState.PAUSED, kdbg.DebugState.STOPPED):
            self.status_var.set("\u26A0 No active session")
            return
        entries = self._dbg.inspect_stack()
        self.output.get_or_create_tab("Stack")
        output_write(self.output, "\n  \u2500\u2500\u2500 STACK MEMORY \u2500\u2500\u2500\n\n", "title")
        for e in entries:
            sym = e.get("symbol", "")
            sym_str = f"  {sym}" if sym else ""
            output_write(self.output,
                f"  +0x{e['offset']:04X}  [0x{e['address']:08X}]  "
                f"0x{e['value']:08X}{sym_str}\n")

    def _show_handles(self):
        if not self._insp:
            self.status_var.set("\u26A0 Load core first")
            return
        self.output.get_or_create_tab("Handles")
        output_write(self.output, "\n  \u2500\u2500\u2500 HANDLE TABLE \u2500\u2500\u2500\n\n", "title")
        rows = self._insp.walk_handle_table()
        for row in rows:
            output_write(self.output, f"  {row}\n")

    def _show_env(self):
        if not self._ensure_env():
            return
        dbg = self._make_session()
        info = dbg.format_environment_info()
        self.output.get_or_create_tab("Env Info")
        output_write(self.output, "\n  \u2500\u2500\u2500 ENVIRONMENT INFO \u2500\u2500\u2500\n", "title")
        self._write_report(info)
        self.status_var.set("\u2705 Environment info displayed")

    # ── interactive disassembly ───────────────────────────────────────────

    def _disassemble(self):
        if not self._ensure_env():
            return
        func = self._get_func()
        if not func:
            messagebox.showwarning("Missing", "Enter a function name.")
            return

        # If a disasm tab for this function already exists, just switch to it
        tab_title = f"Disasm: {func}"
        existing_id, existing_w = self.output.find_tab(tab_title)
        if existing_id and isinstance(existing_w, DisassemblyView):
            self.output._nb.select(existing_id)
            self._disasm_view = existing_w
            # Refresh EIP arrow if paused
            kdbg = _kdbg()
            if self._dbg and self._dbg.state == kdbg.DebugState.PAUSED:
                regs = self._dbg.inspect_registers()
                existing_w.update_eip(regs['eip'])
            total_insn = sum(len(f['instructions'])
                             for f in (existing_w._functions or []))
            self.status_var.set(
                f"\u2705 Disasm: {func}  ({total_insn} instructions) "
                f"\u2014 click gutter to set breakpoints")
            return

        def work(progress_cb):
            progress_cb(f"Disassembling {func}\u2026", 20)
            dbg = self._make_session()
            progress_cb(f"Resolving calls recursively\u2026", 40)
            functions = dbg.disassemble_function(func)
            progress_cb("Building view\u2026", 80)
            return functions

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return

            functions = result
            if not functions:
                self.status_var.set("\u26A0 No code found for function")
                return

            # Create a new tab with DisassemblyView
            self.output._counter += 1
            frm = ttk.Frame(self.output._nb)
            frm.columnconfigure(0, weight=1)
            frm.rowconfigure(0, weight=1)

            dv = DisassemblyView(frm, self)
            dv.grid(row=0, column=0, sticky="nsew")

            # Auto-close oldest if too many tabs
            tab_ids = self.output._nb.tabs()
            if len(tab_ids) >= 20:
                oldest = tab_ids[0]
                self.output._nb.forget(oldest)
                self.output._tabs.pop(oldest, None)

            self.output._nb.add(frm, text=f"  {tab_title}  ")
            self.output._nb.select(frm)
            self._disasm_view = dv
            self.output._tabs[str(frm)] = dv

            dv.load_functions(functions)

            # Show EIP if paused
            kdbg = _kdbg()
            if self._dbg and self._dbg.state == kdbg.DebugState.PAUSED:
                regs = self._dbg.inspect_registers()
                dv.update_eip(regs['eip'])

            total_insn = sum(len(f['instructions']) for f in functions)
            self.status_var.set(
                f"\u2705 Disassembled {len(functions)} function(s), "
                f"{total_insn} instructions \u2014 click gutter to set breakpoints")

        run_with_progress_dialog(self.app, f"Disassembling {func}\u2026", work, done)

    # ── cross-references ──────────────────────────────────────────────────

    def _find_callers(self):
        if not self._ensure_env():
            return
        func = self._get_func()
        if not func:
            messagebox.showwarning("Missing", "Enter a function name.")
            return

        def work(progress_cb):
            progress_cb(f"Scanning all modules for calls to {func}\u2026", 20)
            dbg = self._make_session()
            callers = dbg.find_callers(func)
            progress_cb("Done", 100)
            return callers

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"\u274C {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return

            callers = result
            self.output.new_tab(f"Callers: {func}")
            output_write(self.output,
                f"  CROSS-REFERENCES: calls to {func}\n", "title")

            # Separate by call type
            direct = [c for c in callers if c.get('call_type') == 'direct']
            ssdt = [c for c in callers if c.get('call_type') == 'ssdt']
            stubs = [c for c in callers if c.get('call_type') == 'syscall_stub']

            total = len(callers)
            output_write(self.output,
                f"  Found {total} caller(s): "
                f"{len(direct)} direct, {len(ssdt)} SSDT, {len(stubs)} syscall stub(s)\n\n", "ok")

            if not callers:
                output_write(self.output,
                    "  No callers found (direct or indirect).\n",
                    "dim")
                self.status_var.set(f"\u26A0 No callers found for {func}")
                return

            if direct:
                output_write(self.output,
                    f"  ── Direct CALL Instructions ({len(direct)}) ──\n\n",
                    "heading")
                output_write(self.output,
                    f"  {'Address':12s}  {'Module':16s}  {'Calling Function'}\n",
                    "heading")
                output_write(self.output,
                    f"  {'─'*12}  {'─'*16}  {'─'*40}\n", "dim")
                for c in direct:
                    addr_str = f"0x{c['caller_address']:08X}"
                    output_write(self.output,
                        f"  {addr_str:12s}  {c['caller_module']:16s}  "
                        f"{c['caller_function']}\n")
                output_write(self.output, "\n")

            if ssdt:
                sc_num = ssdt[0].get('syscall_num')
                output_write(self.output,
                    f"  ── SSDT Dispatch (syscall 0x{sc_num:X} / {sc_num}) ──\n\n",
                    "heading")
                output_write(self.output,
                    f"  {'Address':12s}  {'Module':16s}  {'Dispatch Path'}\n",
                    "heading")
                output_write(self.output,
                    f"  {'─'*12}  {'─'*16}  {'─'*50}\n", "dim")
                for c in ssdt:
                    addr_str = f"0x{c['caller_address']:08X}" if c['caller_address'] else "(indirect)"
                    output_write(self.output,
                        f"  {addr_str:12s}  {c['caller_module']:16s}  "
                        f"{c['caller_function']}\n", "warn")
                output_write(self.output,
                    f"\n  The kernel SSDT dispatches int 2e/sysenter calls to this function\n"
                    f"  via KeServiceDescriptorTable[{sc_num}].\n"
                    f"  Any user-mode NtXxx call with EAX={sc_num} reaches this function.\n\n", "dim")

            if stubs:
                sc_num = stubs[0].get('syscall_num')
                output_write(self.output,
                    f"  ── Syscall Stubs (mov eax, 0x{sc_num:X}; int 2e) ──\n\n",
                    "heading")
                output_write(self.output,
                    f"  {'Address':12s}  {'Module':16s}  {'Stub Function'}\n",
                    "heading")
                output_write(self.output,
                    f"  {'─'*12}  {'─'*16}  {'─'*50}\n", "dim")
                for c in stubs:
                    addr_str = f"0x{c['caller_address']:08X}"
                    output_write(self.output,
                        f"  {addr_str:12s}  {c['caller_module']:16s}  "
                        f"{c['caller_function']}\n", "peach")
                output_write(self.output, "\n")

            output_write(self.output,
                f"\n  Tip: Copy an address above into the Breakpoint field "
                f"to break when {func} is called from that site.\n", "dim")

            self.status_var.set(
                f"\U0001F50D {len(callers)} call site(s) found for {func}")

        run_with_progress_dialog(self.app,
            f"Scanning for callers of {func}\u2026", work, done)

if __name__ == '__main__':
    app = App()
    app.mainloop()
