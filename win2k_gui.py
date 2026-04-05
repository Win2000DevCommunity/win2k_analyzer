"""
Win2K NT Internals Analyzer - Graphical Interface
===================================================
Full GUI for analyzing Windows 2000 SP4 system DLLs
and comparing them with ReactOS builds.

Launch: python win2k_gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import json

from nt_analyzer.pe_analyzer import analyze_exports, analyze_imports, analyze_pe_header
from nt_analyzer.syscall_extractor import extract_syscalls, extract_syscall_table, compare_syscall_tables
from nt_analyzer.comparator import (
    compare_exports, compare_imports, compare_pe_headers,
    full_comparison, save_comparison_report, print_comparison_summary
)
from nt_analyzer.struct_analyzer import (
    get_known_structure, list_known_structures,
    generate_c_header, save_all_headers
)
from nt_analyzer.def_generator import generate_def_file, generate_def_for_directory, compare_def_with_reactos
from nt_analyzer.syscall_patcher import generate_syscall_header
from nt_analyzer.ros_patcher import ReactOSPatcher
from nt_analyzer.build_generator import generate_rosbe_script, generate_msvc_script, generate_individual_dll_cmake, BUILD_TARGETS
from nt_analyzer.behavior_analyzer import (
    fingerprint_function, compare_functions, batch_compare as behavior_batch_compare,
    detect_api_patterns, scan_all_exports, disassemble_function
)
from nt_analyzer.decompiler import (
    decompile, decompile_no_symbols, batch_decompile, X86Decompiler, FunctionFinder
)
from nt_analyzer.compat_analyzer import (
    compare_compat, analyze_single_pe, get_known_differences, diagnose_bugcheck
)
from nt_analyzer.pe_patcher import (
    PEPatcher, CodeBlob, patch_pe_for_win2000, patch_syscall_stubs as patch_sysenter,
    inject_convention_shim, inspect_pe_tables
)


# ── Color scheme ──────────────────────────────────────────────────────────
BG          = "#1e1e2e"
BG_DARKER   = "#181825"
BG_LIGHTER  = "#313244"
FG          = "#cdd6f4"
FG_DIM      = "#6c7086"
ACCENT      = "#89b4fa"
GREEN       = "#a6e3a1"
RED         = "#f38ba8"
YELLOW      = "#f9e2af"
PEACH       = "#fab387"
TAB_BG      = "#11111b"
ENTRY_BG    = "#45475a"
BTN_BG      = "#585b70"
BTN_ACTIVE  = "#7f849c"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Win2K NT Internals Analyzer")
        self.geometry("1200x800")
        self.minsize(900, 600)
        self.configure(bg=BG)

        self._configure_styles()
        self._build_header()
        self._build_notebook()

    # ── Styles ────────────────────────────────────────────────────────────
    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, fieldbackground=ENTRY_BG)
        style.configure("TNotebook", background=TAB_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_LIGHTER, foreground=FG,
                         padding=[14, 6], font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", BG_DARKER)])

        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("TButton", background=BTN_BG, foreground=FG,
                         font=("Segoe UI", 10, "bold"), padding=[10, 4])
        style.map("TButton",
                  background=[("active", BTN_ACTIVE)],
                  foreground=[("active", FG)])

        style.configure("Accent.TButton", background=ACCENT, foreground=BG_DARKER,
                         font=("Segoe UI", 10, "bold"), padding=[12, 5])
        style.map("Accent.TButton",
                  background=[("active", "#74c7ec")])

        style.configure("Header.TLabel", background=BG_DARKER, foreground=ACCENT,
                         font=("Segoe UI", 16, "bold"))
        style.configure("SubHeader.TLabel", background=BG_DARKER, foreground=FG_DIM,
                         font=("Segoe UI", 9))
        style.configure("Section.TLabel", background=BG, foreground=ACCENT,
                         font=("Segoe UI", 11, "bold"))

        style.configure("Treeview", background=BG_DARKER, foreground=FG,
                         fieldbackground=BG_DARKER, font=("Consolas", 9),
                         rowheight=22)
        style.configure("Treeview.Heading", background=BG_LIGHTER, foreground=ACCENT,
                         font=("Segoe UI", 9, "bold"))
        style.map("Treeview",
                  background=[("selected", BG_LIGHTER)],
                  foreground=[("selected", ACCENT)])

    # ── Header bar ────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_DARKER, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ttk.Label(hdr, text="Win2K NT Internals Analyzer", style="Header.TLabel").pack(
            side="left", padx=16, pady=8)
        ttk.Label(hdr, text="Analyze Windows 2000 SP4 DLLs  |  Compare with ReactOS",
                  style="SubHeader.TLabel").pack(side="left", padx=4, pady=8)

    # ── Notebook / Tabs ──────────────────────────────────────────────────
    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_exports  = ExportImportTab(self.nb)
        self.tab_syscalls = SyscallTab(self.nb)
        self.tab_compare  = CompareTab(self.nb)
        self.tab_structs  = StructTab(self.nb)
        self.tab_pe       = PEHeaderTab(self.nb)
        self.tab_defgen   = DefGenTab(self.nb)
        self.tab_scpatch  = SyscallPatchTab(self.nb)
        self.tab_rospatch = ROSPatchTab(self.nb)
        self.tab_build    = BuildGenTab(self.nb)
        self.tab_behavior = BehaviorTab(self.nb)
        self.tab_decompiler = DecompilerTab(self.nb)
        self.tab_compat = CompatAnalyzerTab(self.nb)
        self.tab_patcher = PEPatcherTab(self.nb)

        self.nb.add(self.tab_exports,  text="  Exports / Imports  ")
        self.nb.add(self.tab_syscalls, text="  Syscall Extractor  ")
        self.nb.add(self.tab_compare,  text="  DLL Comparison  ")
        self.nb.add(self.tab_structs,  text="  NT Structures  ")
        self.nb.add(self.tab_pe,       text="  PE Header / Scan  ")
        self.nb.add(self.tab_defgen,   text="  DEF Generator  ")
        self.nb.add(self.tab_scpatch,  text="  Syscall Patcher  ")
        self.nb.add(self.tab_rospatch, text="  ROS Patcher  ")
        self.nb.add(self.tab_build,    text="  Build Scripts  ")
        self.nb.add(self.tab_behavior, text="  Behavior Analyzer  ")
        self.nb.add(self.tab_decompiler, text="  Decompiler  ")
        self.nb.add(self.tab_compat,   text="  Compat Analyzer  ")
        self.nb.add(self.tab_patcher,  text="  PE Patcher  ")


# ══════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════

def make_file_picker(parent, label_text, row=0):
    """Create a label + entry + browse button row. Returns (frame, entry_var)."""
    frm = tk.Frame(parent, bg=BG)
    frm.grid(row=row, column=0, sticky="ew", padx=8, pady=4)
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text=label_text, width=14, anchor="e").grid(row=0, column=0, padx=(0, 6))

    var = tk.StringVar()
    ent = tk.Entry(frm, textvariable=var, bg=ENTRY_BG, fg=FG, insertbackground=FG,
                   font=("Consolas", 10), relief="flat", bd=4)
    ent.grid(row=0, column=1, sticky="ew")

    def browse():
        path = filedialog.askopenfilename(
            filetypes=[("PE Files", "*.dll;*.sys;*.exe"), ("All Files", "*.*")])
        if path:
            var.set(path)

    ttk.Button(frm, text="Browse...", command=browse).grid(row=0, column=2, padx=(6, 0))
    return frm, var


def make_dir_picker(parent, label_text, row=0):
    """Create a label + entry + browse button for directories."""
    frm = tk.Frame(parent, bg=BG)
    frm.grid(row=row, column=0, sticky="ew", padx=8, pady=4)
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text=label_text, width=14, anchor="e").grid(row=0, column=0, padx=(0, 6))

    var = tk.StringVar()
    ent = tk.Entry(frm, textvariable=var, bg=ENTRY_BG, fg=FG, insertbackground=FG,
                   font=("Consolas", 10), relief="flat", bd=4)
    ent.grid(row=0, column=1, sticky="ew")

    def browse():
        path = filedialog.askdirectory()
        if path:
            var.set(path)

    ttk.Button(frm, text="Browse...", command=browse).grid(row=0, column=2, padx=(6, 0))
    return frm, var


def make_output(parent):
    """Create a dark scrolled text output area."""
    txt = scrolledtext.ScrolledText(parent, bg=BG_DARKER, fg=FG, insertbackground=FG,
                                     font=("Consolas", 10), relief="flat", bd=6,
                                     wrap="none", state="disabled")
    # Configure tags for colored output
    txt.tag_configure("title",   foreground=ACCENT, font=("Consolas", 11, "bold"))
    txt.tag_configure("ok",      foreground=GREEN)
    txt.tag_configure("warn",    foreground=YELLOW)
    txt.tag_configure("error",   foreground=RED)
    txt.tag_configure("dim",     foreground=FG_DIM)
    txt.tag_configure("peach",   foreground=PEACH)
    txt.tag_configure("heading", foreground=ACCENT, font=("Consolas", 10, "bold"))
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


# ══════════════════════════════════════════════════════════════════════════
#  Tab 1: Export / Import Analyzer
# ══════════════════════════════════════════════════════════════════════════

class ExportImportTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        _, self.dll_var = make_file_picker(self, "DLL File:", row=0)

        # Buttons
        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=1, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Analyze Exports", style="Accent.TButton",
                   command=self._run_exports).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Analyze Imports", style="Accent.TButton",
                   command=self._run_imports).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save JSON...",
                   command=self._save_json).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=2, column=0, sticky="w", padx=12)

        # Output
        self.output = make_output(self)
        self.output.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))

        self._last_data = None

    def _run_exports(self):
        path = self.dll_var.get()
        if not path:
            messagebox.showwarning("No file", "Please select a DLL file first.")
            return
        self.status_var.set("Analyzing exports...")
        output_clear(self.output)

        def work():
            return analyze_exports(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_data = result
            output_write(self.output, f"  EXPORTS: {result['dll_name']}\n", "title")
            output_write(self.output, f"  Total: {result['total_exports']} exports\n\n", "ok")
            output_write(self.output,
                f"  {'Ord':<8} {'Name':<50} {'RVA':<12} {'Forwarded To'}\n", "heading")
            output_write(self.output, f"  {'─'*8} {'─'*50} {'─'*12} {'─'*30}\n", "dim")

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

            self.status_var.set(f"Done — {result['total_exports']} exports found")

        run_async(work, lambda r: self.after(0, done, r))

    def _run_imports(self):
        path = self.dll_var.get()
        if not path:
            messagebox.showwarning("No file", "Please select a DLL file first.")
            return
        self.status_var.set("Analyzing imports...")
        output_clear(self.output)

        def work():
            return analyze_imports(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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

            self.status_var.set(f"Done — {len(result)} DLLs, {total} imports")

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
            self.status_var.set(f"Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 2: Syscall Extractor
# ══════════════════════════════════════════════════════════════════════════

class SyscallTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        _, self.ntdll_var = make_file_picker(self, "ntdll.dll:", row=0)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=1, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Extract Syscalls", style="Accent.TButton",
                   command=self._run).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save JSON...",
                   command=self._save).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=2, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._last_data = None

    def _run(self):
        path = self.ntdll_var.get()
        if not path:
            messagebox.showwarning("No file", "Select ntdll.dll first.")
            return
        self.status_var.set("Extracting syscalls...")
        output_clear(self.output)

        def work():
            return extract_syscalls(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_data = result
            output_write(self.output, f"  SYSCALL TABLE: {os.path.basename(path)}\n", "title")
            output_write(self.output, f"  {len(result)} syscalls extracted\n\n", "ok")

            output_write(self.output,
                f"  {'#':<8} {'Hex':<10} {'Name':<48} {'Mechanism':<20} {'Raw Bytes'}\n", "heading")
            output_write(self.output,
                f"  {'─'*8} {'─'*10} {'─'*48} {'─'*20} {'─'*30}\n", "dim")

            for sc in result:
                mech = sc['mechanism']
                tag = None
                if 'int 0x2E' in mech:
                    tag = "ok"        # Win2000 native
                elif 'sysenter' in mech or 'KiFast' in mech:
                    tag = "peach"     # XP style
                elif 'syscall' in mech:
                    tag = "warn"      # x64

                line = (f"  {sc['syscall_number']:<8} {sc['syscall_hex']:<10} "
                        f"{sc['name']:<48} {mech:<20} {sc['raw_bytes_hex']}\n")
                output_write(self.output, line, tag)

            self.status_var.set(f"Done — {len(result)} syscalls")

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
            self.status_var.set(f"Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 3: DLL Comparison
# ══════════════════════════════════════════════════════════════════════════

class CompareTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self.dll1_var = make_file_picker(self, "Win2000 DLL:", row=0)
        _, self.dll2_var = make_file_picker(self, "ReactOS DLL:", row=1)

        # Labels
        lbl_frm = tk.Frame(self, bg=BG)
        lbl_frm.grid(row=2, column=0, sticky="w", padx=8, pady=2)
        ttk.Label(lbl_frm, text="Label 1:").pack(side="left", padx=4)
        self.label1_var = tk.StringVar(value="Win2000")
        tk.Entry(lbl_frm, textvariable=self.label1_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat",
                 bd=4, width=15).pack(side="left", padx=4)
        ttk.Label(lbl_frm, text="Label 2:").pack(side="left", padx=4)
        self.label2_var = tk.StringVar(value="ReactOS")
        tk.Entry(lbl_frm, textvariable=self.label2_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat",
                 bd=4, width=15).pack(side="left", padx=4)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=3, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Compare DLLs", style="Accent.TButton",
                   command=self._run).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save Report...",
                   command=self._save).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=4, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._last_report = None

    def _run(self):
        p1, p2 = self.dll1_var.get(), self.dll2_var.get()
        if not p1 or not p2:
            messagebox.showwarning("Missing files", "Select both DLLs.")
            return
        l1, l2 = self.label1_var.get() or "Win2000", self.label2_var.get() or "ReactOS"
        self.status_var.set("Comparing...")
        output_clear(self.output)

        def work():
            is_ntdll = 'ntdll' in os.path.basename(p1).lower()
            return full_comparison(p1, p2, l1, l2, is_ntdll=is_ntdll)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            self._last_report = result
            self._render_report(result)
            self.status_var.set("Comparison complete")

        run_async(work, lambda r: self.after(0, done, r))

    def _render_report(self, rpt):
        l1, l2 = rpt['label1'], rpt['label2']
        output_write(self.output, f"  COMPARISON: {rpt['file1']} ({l1}) vs {rpt['file2']} ({l2})\n\n", "title")

        # Exports
        exp = rpt.get('export_comparison', {})
        output_write(self.output, "  ── EXPORTS ─────────────────────────────────────\n", "heading")
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
                output_write(self.output, f"      {m['name']}: {ov1} → {ov2}\n", "warn")
            if len(mismatches) > 30:
                output_write(self.output, f"      ... +{len(mismatches)-30} more\n", "dim")

        only1 = exp.get(f'only_in_{l1}', [])
        only2 = exp.get(f'only_in_{l2}', [])
        if only1:
            output_write(self.output, f"\n    Only in {l1} ({len(only1)} — MUST be added to {l2}):\n", "error")
            for name in only1[:40]:
                output_write(self.output, f"      ✗ {name}\n", "error")
            if len(only1) > 40:
                output_write(self.output, f"      ... +{len(only1)-40} more\n", "dim")
        if only2:
            output_write(self.output, f"\n    Only in {l2} ({len(only2)} — extra, safe):\n", "dim")
            for name in only2[:20]:
                output_write(self.output, f"      + {name}\n", "dim")
            if len(only2) > 20:
                output_write(self.output, f"      ... +{len(only2)-20} more\n", "dim")

        # Imports
        imp = rpt.get('import_comparison', {})
        output_write(self.output, "\n\n  ── IMPORTS ─────────────────────────────────────\n", "heading")
        output_write(self.output, f"    Common DLLs: {len(imp.get('common_dlls',[]))}\n", "ok")
        d1 = imp.get(f'dlls_only_in_{l1}', [])
        d2 = imp.get(f'dlls_only_in_{l2}', [])
        if d1:
            output_write(self.output, f"    DLLs only in {l1}: {', '.join(d1)}\n", "warn")
        if d2:
            output_write(self.output, f"    DLLs only in {l2}: {', '.join(d2)}\n", "dim")

        # PE header diffs
        pe = rpt.get('pe_header_comparison', {})
        diffs = pe.get('differing_fields', {})
        if diffs:
            output_write(self.output, "\n\n  ── PE HEADER DIFFERENCES ───────────────────────\n", "heading")
            for field, vals in diffs.items():
                output_write(self.output, f"    {field}: ", "warn")
                output_write(self.output, f"{vals.get(l1)} → {vals.get(l2)}\n")

        # Syscalls
        sc = rpt.get('syscall_comparison')
        if sc:
            output_write(self.output, "\n\n  ── SYSCALL TABLE ───────────────────────────────\n", "heading")
            output_write(self.output, f"    Matching: {sc['matching_count']}\n", "ok")
            if sc['mismatched_count']:
                output_write(self.output, f"    Mismatched: {sc['mismatched_count']}  ← NEED PATCHING\n", "error")
            output_write(self.output, f"    Only in {l1}: {sc['only_in_first_count']}\n")
            output_write(self.output, f"    Only in {l2}: {sc['only_in_second_count']}\n")

            if sc['mismatched']:
                output_write(self.output, "\n    MISMATCHED SYSCALLS:\n", "error")
                for m in sc['mismatched'][:40]:
                    output_write(self.output,
                        f"      {m['name']:<45} {m['number_first']:>4} → {m['number_second']:<4}  "
                        f"(delta: {m['delta']:+d})\n", "error")

        output_write(self.output, "\n")

    def _save(self):
        if not self._last_report:
            messagebox.showinfo("No data", "Run a comparison first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")])
        if path:
            save_comparison_report(self._last_report, path)
            self.status_var.set(f"Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 4: NT Structure Viewer
# ══════════════════════════════════════════════════════════════════════════

class StructTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top = tk.Frame(self, bg=BG)
        top.grid(row=0, column=0, sticky="ew", padx=8, pady=6)

        ttk.Label(top, text="Structure:").pack(side="left", padx=4)
        self.struct_var = tk.StringVar()
        cb = ttk.Combobox(top, textvariable=self.struct_var,
                          values=list_known_structures(), state="readonly",
                          width=30, font=("Consolas", 10))
        cb.pack(side="left", padx=4)
        if list_known_structures():
            cb.current(0)

        ttk.Button(top, text="View Layout", style="Accent.TButton",
                   command=self._show).pack(side="left", padx=4)
        ttk.Button(top, text="Generate C Header",
                   command=self._gen_header).pack(side="left", padx=4)
        ttk.Button(top, text="Export All Headers...",
                   command=self._export_all).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Select a structure")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=1, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _show(self):
        name = self.struct_var.get()
        if not name:
            return
        s = get_known_structure(name)
        if not s:
            return
        output_clear(self.output)
        output_write(self.output, f"  {s['name']}  ({s['os']})\n", "title")
        output_write(self.output, f"  Size: 0x{s['size']:X} ({s['size']} bytes)\n\n", "ok")

        output_write(self.output,
            f"  {'Offset':<10} {'Size':<8} {'Name':<42} {'Type'}\n", "heading")
        output_write(self.output,
            f"  {'─'*10} {'─'*8} {'─'*42} {'─'*30}\n", "dim")

        for f in s['fields']:
            line = f"  0x{f['offset']:03X}     0x{f['size']:<5X} {f['name']:<42} {f['type']}\n"
            output_write(self.output, line)

        self.status_var.set(f"{s['name']}: {len(s['fields'])} fields, 0x{s['size']:X} bytes")

    def _gen_header(self):
        name = self.struct_var.get()
        if not name:
            return
        s = get_known_structure(name)
        if not s:
            return
        output_clear(self.output)
        header = generate_c_header(s)
        output_write(self.output, header)
        self.status_var.set(f"Generated C header for {name}")

    def _export_all(self):
        d = filedialog.askdirectory(title="Select output directory for .h files")
        if d:
            files = save_all_headers(d)
            self.status_var.set(f"Exported {len(files)} header files to {d}")
            messagebox.showinfo("Done", f"Generated {len(files)} header files:\n" +
                                "\n".join(os.path.basename(f) for f in files))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 5: PE Header / Directory Scanner
# ══════════════════════════════════════════════════════════════════════════

class PEHeaderTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        _, self.file_var = make_file_picker(self, "PE File:", row=0)
        _, self.dir_var  = make_dir_picker(self, "Scan Directory:", row=1)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Analyze PE Header", style="Accent.TButton",
                   command=self._run_header).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Scan Directory", style="Accent.TButton",
                   command=self._run_scan).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=3, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _run_header(self):
        path = self.file_var.get()
        if not path:
            messagebox.showwarning("No file", "Select a PE file.")
            return
        self.status_var.set("Analyzing...")
        output_clear(self.output)

        def work():
            return analyze_pe_header(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
                f"  {'─'*10} {'─'*12} {'─'*12} {'─'*12} {'─'*16}\n", "dim")
            for sec in result.get('sections', []):
                output_write(self.output,
                    f"  {sec['name']:<10} {sec['virtual_address']:<12} "
                    f"{sec['virtual_size']:<12} {sec['raw_size']:<12} "
                    f"{sec['characteristics']}\n")
            self.status_var.set("Done")

        run_async(work, lambda r: self.after(0, done, r))

    def _run_scan(self):
        d = self.dir_var.get()
        if not d:
            messagebox.showwarning("No directory", "Select a directory to scan.")
            return
        self.status_var.set("Scanning...")
        output_clear(self.output)

        import glob as gl

        def work():
            files = []
            for ext in ('*.dll', '*.sys', '*.exe'):
                files.extend(gl.glob(os.path.join(d, ext)))
            return files

        def done(files):
            if isinstance(files, Exception):
                self.status_var.set(f"Error: {files}")
                return

            output_write(self.output, f"  SCAN: {d}  ({len(files)} PE files)\n\n", "title")

            key_files = {'ntdll.dll', 'kernel32.dll', 'shell32.dll', 'user32.dll',
                         'gdi32.dll', 'advapi32.dll', 'ntoskrnl.exe', 'win32k.sys',
                         'ole32.dll', 'rpcrt4.dll', 'msvcrt.dll'}

            output_write(self.output,
                f"  {'File':<28} {'Exports':<10} {'Import DLLs':<14} {'ImageBase':<16} {'Sections'}\n",
                "heading")
            output_write(self.output,
                f"  {'─'*28} {'─'*10} {'─'*14} {'─'*16} {'─'*8}\n", "dim")

            count = 0
            for fp in sorted(files):
                bn = os.path.basename(fp).lower()
                if bn not in key_files:
                    continue
                try:
                    exp = analyze_exports(fp)
                    imp = analyze_imports(fp)
                    hdr = analyze_pe_header(fp)
                    line = (f"  {bn:<28} {exp['total_exports']:<10} {len(imp):<14} "
                            f"{hdr['image_base']:<16} {hdr['number_of_sections']}\n")
                    tag = "ok" if bn in ('ntdll.dll', 'kernel32.dll', 'win32k.sys') else None
                    output_write(self.output, line, tag)
                    count += 1
                except Exception as e:
                    output_write(self.output, f"  {bn:<28} ERROR: {e}\n", "error")

            self.status_var.set(f"Scanned {count} key files out of {len(files)} total")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 6: DEF File Generator
# ══════════════════════════════════════════════════════════════════════════

class DefGenTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        _, self.dll_var = make_file_picker(self, "Win2000 DLL:", row=0)
        _, self.ros_def_var = make_file_picker(self, "ReactOS .def:", row=1)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Generate .def", style="Accent.TButton",
                   command=self._gen_def).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Compare with ReactOS .def",
                   command=self._compare_def).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save .def...",
                   command=self._save_def).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=3, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._last_def = None

    def _gen_def(self):
        path = self.dll_var.get()
        if not path:
            messagebox.showwarning("No file", "Select a Win2000 DLL first.")
            return
        self.status_var.set("Generating .def...")
        output_clear(self.output)

        def work():
            return generate_def_file(path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set(f"Generated .def with {export_count} entries")

        run_async(work, lambda r: self.after(0, done, r))

    def _compare_def(self):
        dll_path = self.dll_var.get()
        ros_path = self.ros_def_var.get()
        if not dll_path or not ros_path:
            messagebox.showwarning("Missing", "Select both Win2000 DLL and ReactOS .def file.")
            return
        self.status_var.set("Comparing...")
        output_clear(self.output)

        def work():
            return compare_def_with_reactos(dll_path, ros_path)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set("Comparison done")

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
            self.status_var.set(f"Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 7: Syscall Patcher
# ══════════════════════════════════════════════════════════════════════════

class SyscallPatchTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        _, self.ntdll_var = make_file_picker(self, "ntdll.dll:", row=0)

        opt_frm = tk.Frame(self, bg=BG)
        opt_frm.grid(row=1, column=0, sticky="w", padx=8, pady=4)

        ttk.Label(opt_frm, text="Header Style:").pack(side="left", padx=4)
        self.style_var = tk.StringVar(value="napi")
        for val, text in [("napi", "NAPI (#define)"), ("define", "SYS_ defines"),
                          ("asm", "MASM .asm"), ("table", "C Array")]:
            ttk.Radiobutton(opt_frm, text=text, variable=self.style_var, value=val).pack(side="left", padx=6)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Generate Header", style="Accent.TButton",
                   command=self._gen).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save Header...",
                   command=self._save).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=3, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=4, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._last_header = None

    def _gen(self):
        path = self.ntdll_var.get()
        if not path:
            messagebox.showwarning("No file", "Select ntdll.dll first.")
            return
        style = self.style_var.get()
        self.status_var.set(f"Generating {style} header...")
        output_clear(self.output)

        def work():
            return generate_syscall_header(path, style=style)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set("Header generated")

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
            self.status_var.set(f"Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 8: ReactOS Source Patcher
# ══════════════════════════════════════════════════════════════════════════

class ROSPatchTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self.ros_dir = make_dir_picker(self, "ReactOS Source:", row=0)
        _, self.ntdll_var = make_file_picker(self, "Win2K ntdll:", row=1)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Scan Issues", style="Accent.TButton",
                   command=self._scan).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Patch WinVer Target",
                   command=lambda: self._run_patch('winver')).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Patch Syscall Mechanism",
                   command=lambda: self._run_patch('syscall')).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Patch All",
                   command=lambda: self._run_patch('all')).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        # Dry-run checkbox
        chk_frm = tk.Frame(self, bg=BG)
        chk_frm.grid(row=3, column=0, sticky="w", padx=8, pady=2)
        self.dryrun_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(chk_frm, text="Dry run (preview only, don't modify files)",
                        variable=self.dryrun_var).pack(side="left")

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=4, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _scan(self):
        ros_path = self.ros_dir.get()
        if not ros_path:
            messagebox.showwarning("Missing", "Select ReactOS source directory.")
            return
        self.status_var.set("Scanning for Win2K compatibility issues...")
        output_clear(self.output)

        def work():
            patcher = ReactOSPatcher(ros_path)
            return patcher.scan_issues()

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set(f"Scan complete: {total} issues found")

        run_async(work, lambda r: self.after(0, done, r))

    def _run_patch(self, mode):
        ros_path = self.ros_dir.get()
        if not ros_path:
            messagebox.showwarning("Missing", "Select ReactOS source directory.")
            return
        ntdll_path = self.ntdll_var.get() or None
        dry = self.dryrun_var.get()

        self.status_var.set(f"Patching ({mode}){'  [DRY RUN]' if dry else ''}...")
        output_clear(self.output)

        def work():
            patcher = ReactOSPatcher(ros_path, ntdll_path)
            if mode == 'winver':
                return patcher.patch_winver_target(dry_run=dry)
            elif mode == 'syscall':
                return patcher.patch_syscall_mechanism(dry_run=dry)
            elif mode == 'all':
                return patcher.run_all_patches(dry_run=dry)
            return {}

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set(f"Patch complete{dry_label}")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 9: Build Script Generator
# ══════════════════════════════════════════════════════════════════════════

class BuildGenTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self.ros_dir = make_dir_picker(self, "ReactOS Source:", row=0)

        # Target selection
        tgt_frm = tk.Frame(self, bg=BG)
        tgt_frm.grid(row=1, column=0, sticky="ew", padx=8, pady=4)

        ttk.Label(tgt_frm, text="Targets:").pack(side="left", padx=4)
        self.target_vars = {}
        for name in BUILD_TARGETS:
            var = tk.BooleanVar(value=(name in ('ntdll.dll', 'kernel32.dll', 'shell32.dll', 'win32k.sys')))
            ttk.Checkbutton(tgt_frm, text=name.replace('.dll','').replace('.sys','').replace('.exe',''),
                            variable=var).pack(side="left", padx=3)
            self.target_vars[name] = var

        # Build system selection
        bld_frm = tk.Frame(self, bg=BG)
        bld_frm.grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Label(bld_frm, text="Build System:").pack(side="left", padx=4)
        self.build_var = tk.StringVar(value="rosbe")
        for val, text in [("rosbe", "RosBE + Ninja"), ("msvc", "MSVC + NMake"), ("cmake", "Standalone CMake")]:
            ttk.Radiobutton(bld_frm, text=text, variable=self.build_var, value=val).pack(side="left", padx=6)

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=3, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Generate Script", style="Accent.TButton",
                   command=self._gen).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save Script...",
                   command=self._save).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=4, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._last_script = None

    def _get_targets(self):
        return [name for name, var in self.target_vars.items() if var.get()]

    def _gen(self):
        ros = self.ros_dir.get()
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
            script = generate_rosbe_script(ros, targets)
        elif build == 'msvc':
            script = generate_msvc_script(ros, targets)
        else:
            script = generate_individual_dll_cmake(targets[0], ros)

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
        self.status_var.set(f"Generated {build} script for {len(targets)} targets")

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
            self.status_var.set(f"Saved to {os.path.basename(path)}")


# ══════════════════════════════════════════════════════════════════════════
#  Tab 10: Function Behavior Analyzer
# ══════════════════════════════════════════════════════════════════════════

class BehaviorTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(6, weight=1)

        _, self.dll_a_var = make_file_picker(self, "DLL A (Win2K):", row=0)
        _, self.dll_b_var = make_file_picker(self, "DLL B (ReactOS):", row=1)

        func_frm = tk.Frame(self, bg=BG)
        func_frm.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        func_frm.columnconfigure(1, weight=1)

        ttk.Label(func_frm, text="Function:", width=14, anchor="e").grid(row=0, column=0, padx=(0, 6))
        self.func_var = tk.StringVar()
        tk.Entry(func_frm, textvariable=self.func_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat", bd=4).grid(
            row=0, column=1, sticky="ew")

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=3, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Disassemble", style="Accent.TButton",
                   command=self._disasm).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Compare Function",
                   command=self._compare_one).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Batch Compare All",
                   command=self._batch).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Detect Patterns",
                   command=self._patterns).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Scan All Exports",
                   command=self._scan_all).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        # Max functions for batch
        lim_frm = tk.Frame(self, bg=BG)
        lim_frm.grid(row=4, column=0, sticky="w", padx=8, pady=2)
        ttk.Label(lim_frm, text="Max functions (batch):").pack(side="left", padx=4)
        self.max_var = tk.StringVar(value="100")
        tk.Entry(lim_frm, textvariable=self.max_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat",
                 bd=4, width=8).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=5, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=6, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _disasm(self):
        path = self.dll_a_var.get()
        func = self.func_var.get().strip()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return
        self.status_var.set(f"Disassembling {func}...")
        output_clear(self.output)

        def work():
            return disassemble_function(path, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found in the DLL exports.\n", "error")
                self.status_var.set("Function not found")
                return
            for line in result.split('\n'):
                if line.startswith(';'):
                    output_write(self.output, line + '\n', "dim")
                elif '; →' in line:
                    output_write(self.output, line + '\n', "peach")
                elif 'call' in line or 'int' in line:
                    output_write(self.output, line + '\n', "ok")
                elif 'ret' in line or 'retn' in line:
                    output_write(self.output, line + '\n', "warn")
                else:
                    output_write(self.output, line + '\n')
            self.status_var.set(f"Disassembly of {func} complete")

        run_async(work, lambda r: self.after(0, done, r))

    def _compare_one(self):
        pa = self.dll_a_var.get()
        pb = self.dll_b_var.get()
        func = self.func_var.get().strip()
        if not pa or not pb or not func:
            messagebox.showwarning("Missing", "Select both DLLs and enter a function name.")
            return
        self.status_var.set(f"Comparing {func}...")
        output_clear(self.output)

        def work():
            return compare_functions(pa, pb, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set(f"Comparison: {result.similarity:.1f}% similar")

        run_async(work, lambda r: self.after(0, done, r))

    def _batch(self):
        pa = self.dll_a_var.get()
        pb = self.dll_b_var.get()
        if not pa or not pb:
            messagebox.showwarning("Missing", "Select both DLLs.")
            return

        try:
            max_funcs = int(self.max_var.get())
        except ValueError:
            max_funcs = 100

        self.status_var.set("Batch comparing all shared exports...")
        output_clear(self.output)

        def work():
            results = behavior_batch_compare(pa, pb)
            return results[:max_funcs]

        def done(results):
            if isinstance(results, Exception):
                self.status_var.set(f"Error: {results}")
                output_write(self.output, f"ERROR: {results}\n", "error")
                return
            output_write(self.output, "  BATCH FUNCTION COMPARISON\n\n", "title")
            output_write(self.output,
                f"  {'Function':<48} {'Sim%':<8} {'Blocks A':<10} {'Blocks B':<10} {'Notes'}\n", "heading")
            output_write(self.output,
                f"  {'─'*48} {'─'*8} {'─'*10} {'─'*10} {'─'*20}\n", "dim")

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

            self.status_var.set(f"Compared {len(results)} functions")

        run_async(work, lambda r: self.after(0, done, r))

    def _patterns(self):
        path = self.dll_a_var.get()
        func = self.func_var.get().strip()
        if not path or not func:
            messagebox.showwarning("Missing", "Select DLL A and enter a function name.")
            return
        self.status_var.set(f"Detecting patterns for {func}...")
        output_clear(self.output)

        def work():
            return detect_api_patterns(path, func)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("Not found")
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
                    output_write(self.output, f"    → {call}\n", "peach")
            self.status_var.set(f"Pattern analysis complete for {func}")

        run_async(work, lambda r: self.after(0, done, r))

    def _scan_all(self):
        path = self.dll_a_var.get()
        if not path:
            messagebox.showwarning("Missing", "Select DLL A.")
            return

        try:
            max_funcs = int(self.max_var.get())
        except ValueError:
            max_funcs = 100

        self.status_var.set("Scanning all exports for behavior patterns...")
        output_clear(self.output)

        def work():
            return scan_all_exports(path, max_funcs)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, "  EXPORT BEHAVIOR SCAN\n\n", "title")
            total = 0
            for category, funcs in sorted(result.items(), key=lambda x: -len(x[1])):
                output_write(self.output, f"  [{category}] — {len(funcs)} functions\n", "heading")
                for fname, fdesc in funcs[:20]:
                    output_write(self.output, f"    {fname:<48} {fdesc}\n")
                if len(funcs) > 20:
                    output_write(self.output, f"    ... +{len(funcs)-20} more\n", "dim")
                output_write(self.output, "\n")
                total += len(funcs)
            self.status_var.set(f"Scanned: {total} functions in {len(result)} categories")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Tab 11: Decompiler
# ══════════════════════════════════════════════════════════════════════════

class DecompilerTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self.pe_var = make_file_picker(self, "PE File:", row=0)

        func_frm = tk.Frame(self, bg=BG)
        func_frm.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        func_frm.columnconfigure(1, weight=1)

        ttk.Label(func_frm, text="Function/RVA:", width=14, anchor="e").grid(
            row=0, column=0, padx=(0, 6))
        self.func_var = tk.StringVar()
        tk.Entry(func_frm, textvariable=self.func_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat", bd=4).grid(
            row=0, column=1, sticky="ew")

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Decompile Export", style="Accent.TButton",
                   command=self._decompile_one).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Discover Functions (No Symbols)",
                   command=self._discover).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Batch Decompile Exports",
                   command=self._batch).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save Output",
                   command=self._save).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        lim_frm = tk.Frame(self, bg=BG)
        lim_frm.grid(row=3, column=0, sticky="w", padx=8, pady=2)
        ttk.Label(lim_frm, text="Max functions:").pack(side="left", padx=4)
        self.max_var = tk.StringVar(value="50")
        tk.Entry(lim_frm, textvariable=self.max_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat",
                 bd=4, width=8).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=4, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _decompile_one(self):
        path = self.pe_var.get()
        func = self.func_var.get().strip()
        if not path or not func:
            messagebox.showwarning("Missing", "Select a PE file and enter a function name or RVA (0x...).")
            return
        self.status_var.set(f"Decompiling {func}...")
        output_clear(self.output)

        if func.startswith('0x') or func.startswith('0X'):
            func_val = int(func, 16)
        else:
            func_val = func

        def work():
            return decompile(path, func_val)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            if result is None:
                output_write(self.output, f"  Function '{func}' not found.\n", "error")
                self.status_var.set("Not found")
                return
            self._colorize(result)
            self.status_var.set(f"Decompiled {func}")

        run_async(work, lambda r: self.after(0, done, r))

    def _discover(self):
        path = self.pe_var.get()
        if not path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        try:
            mx = int(self.max_var.get())
        except ValueError:
            mx = 50
        self.status_var.set(f"Discovering functions (max {mx})...")
        output_clear(self.output)

        def work():
            return decompile_no_symbols(path, max_funcs=mx)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            for name, code in result.items():
                output_write(self.output, f"{'='*70}\n", "dim")
                self._colorize(code)
                output_write(self.output, "\n")
            self.status_var.set(f"Discovered {len(result)} functions")

        run_async(work, lambda r: self.after(0, done, r))

    def _batch(self):
        path = self.pe_var.get()
        if not path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        try:
            mx = int(self.max_var.get())
        except ValueError:
            mx = 100
        self.status_var.set(f"Batch decompiling exports (max {mx})...")
        output_clear(self.output)

        def work():
            return batch_decompile(path, max_funcs=mx)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            for name, code in result.items():
                output_write(self.output, f"{'='*70}\n", "dim")
                self._colorize(code)
                output_write(self.output, "\n")
            self.status_var.set(f"Decompiled {len(result)} exports")

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
            self.status_var.set(f"Saved to {path}")

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
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self.pe_a_var = make_file_picker(self, "PE File A:", row=0)
        _, self.pe_b_var = make_file_picker(self, "PE File B:", row=1)

        label_frm = tk.Frame(self, bg=BG)
        label_frm.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        label_frm.columnconfigure(1, weight=1)
        label_frm.columnconfigure(3, weight=1)

        ttk.Label(label_frm, text="Label A:", width=10, anchor="e").grid(row=0, column=0, padx=(0, 4))
        self.label_a_var = tk.StringVar(value="Win2000")
        tk.Entry(label_frm, textvariable=self.label_a_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat", bd=4).grid(
            row=0, column=1, sticky="ew", padx=(0, 12))
        ttk.Label(label_frm, text="Label B:", width=10, anchor="e").grid(row=0, column=2, padx=(0, 4))
        self.label_b_var = tk.StringVar(value="ReactOS/XP")
        tk.Entry(label_frm, textvariable=self.label_b_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat", bd=4).grid(
            row=0, column=3, sticky="ew")

        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=3, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Full Compat Analysis", style="Accent.TButton",
                   command=self._analyze_both).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Analyze Single PE",
                   command=self._analyze_single).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Known Differences",
                   command=self._show_known).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Bugcheck Lookup",
                   command=self._bugcheck).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Save Report",
                   command=self._save).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=4, column=0, sticky="w", padx=12)

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _analyze_both(self):
        pa, pb = self.pe_a_var.get(), self.pe_b_var.get()
        if not pa or not pb:
            messagebox.showwarning("Missing", "Select both PE files.")
            return
        la, lb = self.label_a_var.get(), self.label_b_var.get()
        self.status_var.set("Analyzing compatibility...")
        output_clear(self.output)

        def work():
            return compare_compat(pa, pb, la, lb)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            report = result
            self._colorize_report(report.summary())
            critical = sum(1 for i in report.issues if i.severity == "critical")
            warnings = sum(1 for i in report.issues if i.severity == "warning")
            self.status_var.set(f"Done: {critical} critical, {warnings} warnings")

        run_async(work, lambda r: self.after(0, done, r))

    def _analyze_single(self):
        pa = self.pe_a_var.get()
        if not pa:
            messagebox.showwarning("Missing", "Select PE File A.")
            return
        la = self.label_a_var.get()
        self.status_var.set("Analyzing single PE...")
        output_clear(self.output)

        def work():
            return analyze_single_pe(pa, la)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
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
            self.status_var.set("Done")

        run_async(work, lambda r: self.after(0, done, r))

    def _show_known(self):
        output_clear(self.output)
        diffs = get_known_differences()
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
        self.status_var.set("Showing known differences")

    def _bugcheck(self):
        from tkinter.simpledialog import askstring
        code = askstring("Bugcheck", "Enter bugcheck code (e.g. 0xA5):", parent=self)
        if not code:
            return
        output_clear(self.output)
        result = diagnose_bugcheck(code)
        output_write(self.output, f"Bugcheck: {result['code']}\n", "title")
        output_write(self.output, f"Name: {result.get('name', 'Unknown')}\n", "warn")
        if 'description' in result:
            output_write(self.output, f"Description: {result['description']}\n")
        output_write(self.output, f"Compat hint: {result['compat_hint']}\n", "ok")
        if 'known_causes' in result:
            output_write(self.output, "\nKnown causes:\n", "heading")
            for cause in result['known_causes']:
                output_write(self.output, f"  - {cause}\n")
        self.status_var.set(f"Bugcheck {result['code']} lookup done")

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
            self.status_var.set(f"Saved to {path}")

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
#  Tab 13: PE Patcher
# ══════════════════════════════════════════════════════════════════════════

class PEPatcherTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        _, self.pe_var = make_file_picker(self, "PE File:", row=0)

        # Output path
        out_frm = tk.Frame(self, bg=BG)
        out_frm.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        out_frm.columnconfigure(1, weight=1)
        ttk.Label(out_frm, text="Output Path:", width=14, anchor="e").grid(row=0, column=0, padx=(0, 6))
        self.out_var = tk.StringVar()
        tk.Entry(out_frm, textvariable=self.out_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat", bd=4).grid(
            row=0, column=1, sticky="ew")
        ttk.Button(out_frm, text="Browse...", command=self._browse_out).grid(row=0, column=2, padx=(6, 0))

        # Options row 1
        opt_frm = tk.Frame(self, bg=BG)
        opt_frm.grid(row=2, column=0, sticky="ew", padx=8, pady=4)

        self.chk_version = tk.BooleanVar(value=True)
        self.chk_syscalls = tk.BooleanVar(value=True)
        self.chk_strip_debug = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frm, text="Patch version to 5.0", variable=self.chk_version,
                       bg=BG, fg=FG, selectcolor=BG_DARKER, activebackground=BG,
                       activeforeground=FG).pack(side="left", padx=8)
        tk.Checkbutton(opt_frm, text="Patch sysenter \u2192 int 0x2E", variable=self.chk_syscalls,
                       bg=BG, fg=FG, selectcolor=BG_DARKER, activebackground=BG,
                       activeforeground=FG).pack(side="left", padx=8)
        tk.Checkbutton(opt_frm, text="Strip debug info", variable=self.chk_strip_debug,
                       bg=BG, fg=FG, selectcolor=BG_DARKER, activebackground=BG,
                       activeforeground=FG).pack(side="left", padx=8)

        # Options row 2: shim + rebase
        shim_frm = tk.Frame(self, bg=BG)
        shim_frm.grid(row=3, column=0, sticky="ew", padx=8, pady=4)
        ttk.Label(shim_frm, text="Convention shim:").pack(side="left", padx=4)
        self.shim_var = tk.StringVar()
        tk.Entry(shim_frm, textvariable=self.shim_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat",
                 bd=4, width=35).pack(side="left", padx=4)
        ttk.Label(shim_frm, text="(func,from,to,nparams)", foreground=FG_DIM).pack(side="left", padx=4)

        ttk.Label(shim_frm, text="  Rebase:").pack(side="left", padx=(12, 4))
        self.rebase_var = tk.StringVar()
        tk.Entry(shim_frm, textvariable=self.rebase_var, bg=ENTRY_BG, fg=FG,
                 insertbackground=FG, font=("Consolas", 10), relief="flat",
                 bd=4, width=12).pack(side="left", padx=4)
        ttk.Label(shim_frm, text="(hex address)", foreground=FG_DIM).pack(side="left", padx=4)

        # Buttons row 1
        btn_frm = tk.Frame(self, bg=BG)
        btn_frm.grid(row=4, column=0, sticky="w", padx=8, pady=4)

        ttk.Button(btn_frm, text="Quick Win2000 Patch", style="Accent.TButton",
                   command=self._quick_patch).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Custom Patch",
                   command=self._custom_patch).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Patch Syscalls Only",
                   command=self._patch_syscalls).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Inspect Tables",
                   command=self._inspect_tables).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Rebase",
                   command=self._rebase).pack(side="left", padx=4)
        ttk.Button(btn_frm, text="Clear",
                   command=lambda: output_clear(self.output)).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground=FG_DIM).grid(
            row=5, column=0, sticky="sw", padx=12, pady=(0,4))

        self.output = make_output(self)
        self.output.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _browse_out(self):
        path = filedialog.asksaveasfilename(
            filetypes=[("PE Files", "*.dll;*.sys;*.exe"), ("All", "*.*")])
        if path:
            self.out_var.set(path)

    def _quick_patch(self):
        pe_path = self.pe_var.get()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file to patch.")
            return
        output = self.out_var.get() or None
        self.status_var.set("Applying Win2000 quick patch...")
        output_clear(self.output)

        def work():
            return patch_pe_for_win2000(pe_path, output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\nPatched file saved to: {result.output_path}\n", "ok")
                self.status_var.set(f"Patch successful: {result.output_path}")
            else:
                output_write(self.output, "\nPatch had errors!\n", "error")
                self.status_var.set("Patch failed")

        run_async(work, lambda r: self.after(0, done, r))

    def _custom_patch(self):
        pe_path = self.pe_var.get()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file to patch.")
            return
        output = self.out_var.get() or None
        self.status_var.set("Applying custom patches...")
        output_clear(self.output)

        chk_ver = self.chk_version.get()
        chk_sys = self.chk_syscalls.get()
        chk_dbg = self.chk_strip_debug.get()
        shim = self.shim_var.get().strip()
        rebase = self.rebase_var.get().strip()

        def work():
            patcher = PEPatcher(pe_path)
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
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\nPatched file saved to: {result.output_path}\n", "ok")
                self.status_var.set(f"Patch successful: {result.output_path}")
            else:
                output_write(self.output, "\nPatch had errors!\n", "error")
                for e in result.errors:
                    output_write(self.output, f"  {e}\n", "error")
                self.status_var.set("Patch failed")

        run_async(work, lambda r: self.after(0, done, r))

    def _patch_syscalls(self):
        pe_path = self.pe_var.get()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        output = self.out_var.get() or None
        self.status_var.set("Patching syscall stubs...")
        output_clear(self.output)

        def work():
            return patch_sysenter(pe_path, output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\nSaved to: {result.output_path}\n", "ok")
            self.status_var.set("Done")

        run_async(work, lambda r: self.after(0, done, r))

    def _inspect_tables(self):
        pe_path = self.pe_var.get()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        self.status_var.set("Inspecting PE tables...")
        output_clear(self.output)

        def work():
            return inspect_pe_tables(pe_path)

        def done(tables):
            if isinstance(tables, Exception):
                self.status_var.set(f"Error: {tables}")
                output_write(self.output, f"ERROR: {tables}\n", "error")
                return

            output_write(self.output, "=== SECTIONS ===\n")
            for s in tables['sections']:
                flags = []
                if s['executable']: flags.append('X')
                if s['writable']: flags.append('W')
                output_write(self.output,
                    f"  {s['name']:<10s} RVA=0x{s['rva']:08X} "
                    f"VSize=0x{s['virtual_size']:08X} "
                    f"Raw=0x{s['raw_offset']:08X} "
                    f"RSize=0x{s['raw_size']:08X} [{','.join(flags)}]\n")

            output_write(self.output, f"\n=== EXPORTS ({len(tables['exports'])}) ===\n")
            for e in tables['exports'][:200]:
                fwd = f" -> {e['forwarder']}" if e['forwarder'] else ""
                name = e['name'] or f"@{e['ordinal']}"
                output_write(self.output,
                    f"  [{e['ordinal']:4d}] 0x{e['rva']:08X} {name}{fwd}\n")

            output_write(self.output, f"\n=== IMPORTS ({len(tables['imports'])}) ===\n")
            cur_dll = None
            for i in tables['imports'][:200]:
                if i['dll'] != cur_dll:
                    cur_dll = i['dll']
                    output_write(self.output, f"\n  {cur_dll}:\n")
                name = i['name'] or f"@{i['ordinal']}"
                output_write(self.output, f"    0x{i['iat_rva']:08X} {name}\n")

            relocs = tables['relocations']
            output_write(self.output, f"\n=== RELOCATIONS ({len(relocs)}) ===\n")
            for r in relocs[:100]:
                output_write(self.output, f"  0x{r['rva']:08X} {r['type_name']}\n")
            if len(relocs) > 100:
                output_write(self.output, f"  ... and {len(relocs) - 100} more\n")

            self.status_var.set(f"Inspection complete: {len(tables['exports'])} exports, "
                              f"{len(tables['imports'])} imports, {len(relocs)} relocs")

        run_async(work, lambda r: self.after(0, done, r))

    def _rebase(self):
        pe_path = self.pe_var.get()
        rebase = self.rebase_var.get().strip()
        if not pe_path:
            messagebox.showwarning("Missing", "Select a PE file.")
            return
        if not rebase:
            messagebox.showwarning("Missing", "Enter a hex address in the Rebase field.")
            return
        output = self.out_var.get() or None
        self.status_var.set("Rebasing...")
        output_clear(self.output)

        def work():
            from nt_analyzer.pe_patcher import rebase_pe
            return rebase_pe(pe_path, int(rebase, 16), output)

        def done(result):
            if isinstance(result, Exception):
                self.status_var.set(f"Error: {result}")
                output_write(self.output, f"ERROR: {result}\n", "error")
                return
            output_write(self.output, result.summary() + '\n')
            if result.success:
                output_write(self.output, f"\nRebased file saved to: {result.output_path}\n", "ok")
            self.status_var.set("Done")

        run_async(work, lambda r: self.after(0, done, r))


# ══════════════════════════════════════════════════════════════════════════
#  Launch
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app = App()
    app.mainloop()
