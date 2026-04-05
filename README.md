# Win2K NT Internals Analyzer

**The ultimate reverse-engineering and binary compatibility toolkit for porting ReactOS components to Windows 2000 SP4.**

Analyze, compare, decompile, patch, and build NT kernel-mode and user-mode binaries — all from a single tool with both a **dark-themed GUI (13 tabs)** and a **full CLI (27 commands)**.

**NEW in v3.0 — KernelEx Ultimate PE Patcher:**  All patching techniques from KernelEx (Xeno86, 2006-2008) have been reverse-engineered and reimplemented in Python with modern 2026 capabilities: code blob injection with 4-table fixups, full export/import table rebuild, PE rebase, GenPatch-style C→binary compilation, 5-stage patch pipeline, symbol-aware patching, and more.

Works on **ALL PE file types**: `.dll`, `.sys`, `.exe`, `.cpl`, `.drv`, `.ocx`, `.scr`

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

---

## Table of Contents

- [What Does This Tool Do?](#what-does-this-tool-do)
- [Features Overview](#features-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Opening the GUI](#opening-the-gui)
- [Using the CLI](#using-the-cli)
- [CLI Command Reference (All 27 Commands)](#cli-command-reference-all-27-commands)
- [GUI Tab Reference (All 13 Tabs)](#gui-tab-reference-all-13-tabs)
- [Using with Visual Studio Code](#using-with-visual-studio-code)
- [Using with GitHub Copilot](#using-with-github-copilot)
- [Module Architecture](#module-architecture)
- [FAQ — Frequently Asked Questions](#faq--frequently-asked-questions)
- [Known NT 5.0 vs 5.1 Differences](#known-nt-50-vs-51-differences)
- [Contributing](#contributing)

---

## What Does This Tool Do?

If you want to **replace Windows 2000 SP4 system files (kernel32.dll, ntdll.dll, shell32.dll, win32k.sys, etc.) with open-source ReactOS equivalents**, you need to understand the deep binary-level differences between NT 5.0 (Windows 2000) and NT 5.1+ (XP/ReactOS target).

This tool gives you everything in one place:

1. **Analyze** — Extract exports, imports, syscalls, PE headers from any Windows binary
2. **Compare** — Side-by-side diff of Win2000 vs ReactOS DLLs (exports, imports, syscalls, PE headers)
3. **Decompile** — Convert x86 assembly to C pseudocode, even **without symbols**
4. **Detect** — Intelligently find calling convention changes, HAL dispatch differences, macro differences, structure layout changes between NT versions
5. **Patch** — KernelEx-inspired PE binary patcher with ALL KernelEx techniques: code blob injection with 4-table fixups (abs_ofs, abs_api, rel_api, hook_api), full export table rebuild with sorted merge, PE rebase with relocation fixups, GenPatch-style C/ASM compilation pipeline, calling convention shims, and the full 5-stage patch pipeline (prepare → api_entries → alter_sections → rebuild_tables → process)
6. **Inspect** — Deep PE table inspection: exports, imports, relocations, sections — with hex dump
7. **Build** — Generate build scripts (RosBE, MSVC, CMake) for compiling ReactOS DLLs for Win2000

---

## Features Overview

| Category | Feature | CLI | GUI |
|----------|---------|-----|-----|
| **PE Analysis** | Export table dump (names, ordinals, RVAs, forwarded) | `exports` | Tab 1 |
| | Import table dump (per-DLL function lists) | `imports` | Tab 1 |
| | PE header analysis (machine, subsystem, version, sections) | `header` | Tab 5 |
| | Scan directory for all PE files | `scan` | Tab 5 |
| **Syscalls** | Extract syscall numbers from ntdll.dll stubs | `syscalls` | Tab 2 |
| | Generate syscall headers (napi/define/asm/table styles) | `syscall-patch` | Tab 7 |
| **Comparison** | Full DLL comparison (exports + imports + headers + syscalls) | `compare` | Tab 3 |
| | Batch compare all matching DLLs in two directories | `batch-compare` | Tab 3 |
| **Structures** | 9 known Win2000 SP4 undocumented structure layouts | `structs` | Tab 4 |
| | Generate C header files (.h) for all structures | `gen-headers` | Tab 4 |
| **DEF Files** | Auto-generate .def files from DLL exports | `gen-def` | Tab 6 |
| **Decompiler** | Decompile exported functions to C pseudocode | `decompile` | Tab 11 |
| | Discover functions without symbols (prologue scanning) | `discover-functions` | Tab 11 |
| | Batch decompile all exports | `batch-decompile` | Tab 11 |
| **Behavior** | Function fingerprinting and API pattern detection | `behavior` | Tab 10 |
| | Disassemble exported functions | `disasm` | Tab 10 |
| **Compat Analysis** | Deep compatibility analysis between two PE binaries | `compat-analyze` | Tab 12 |
| | Single PE compatibility profile | `compat-single` | Tab 12 |
| | Show all known NT 5.0→5.1 differences | `compat-known` | Tab 12 |
| | Bugcheck code diagnosis with compat hints | `bugcheck` | Tab 12 |
| **PE Patching** | Quick Win2000 patch (version + syscalls) | `patch-pe --quick` | Tab 13 |
| | Patch sysenter stubs to int 0x2E | `patch-pe --syscalls` | Tab 13 |
| | Inject calling convention shims (stdcall↔fastcall) | `patch-pe --shim` | Tab 13 |
| | Rebase PE to new ImageBase with relocation fixups | `patch-pe --rebase` / `rebase` | Tab 13 |
| | Strip debug directory from PE | `patch-pe --strip-debug` | Tab 13 |
| | Grow section, add import, forward export | `patch-pe --grow-section/--add-import/--forward-export` | Tab 13 |
| | Inject raw code blob with 4-table fixups | `inject-blob` | — |
| | GenPatch: compile C source & inject into PE | `compile-inject` | — |
| | Full export table rebuild (add/forward/alias/hook) | Python API | — |
| | 5-stage KernelEx pipeline (PatchSet) | Python API | — |
| | Symbol map loading + symbol-aware patching | Python API | — |
| **PE Inspection** | Inspect all PE tables (EAT, IAT, relocs, sections) | `inspect-pe` | Tab 13 |
| | Hex dump at RVA | `hex-dump` | — |
| **Build** | Generate RosBE / MSVC / CMake build scripts | `build-script` | Tab 9 |
| | ReactOS source tree auto-patcher | — | Tab 8 |

---

## Installation

### Prerequisites

- **Python 3.10 or later** (tested on Python 3.14)
- **Windows** (the tool analyzes Windows PE binaries)
- **tkinter** (included with standard Python on Windows)

### Clone and Install

```bash
git clone https://github.com/Win2000DevCommunity/win2k_analyzer.git
cd win2k_analyzer
pip install -r requirements.txt
```

### Dependencies

```
pefile>=2023.2.7    # PE file parsing
capstone>=5.0.0     # x86 disassembly engine
tabulate>=0.9.0     # Table formatting for CLI output
colorama>=0.4.6     # Colored terminal output
```

All pure-Python except capstone (has native C backend for speed).

---

## Quick Start

**Analyze a DLL's exports:**
```bash
python win2k_analyzer.py exports C:\WINNT\system32\kernel32.dll
```

**Compare Win2000 vs ReactOS ntdll:**
```bash
python win2k_analyzer.py compare C:\win2k\ntdll.dll C:\reactos\ntdll.dll
```

**Deep compatibility analysis:**
```bash
python win2k_analyzer.py compat-analyze C:\win2k\ntoskrnl.exe C:\reactos\ntoskrnl.exe
```

**Quick-patch a ReactOS DLL for Win2000:**
```bash
python win2k_analyzer.py patch-pe --quick C:\reactos\ntdll.dll
```

**Open the GUI:**
```bash
python win2k_gui.py
```

---

## Opening the GUI

The GUI is a standalone Python/Tkinter application with a dark theme and 13 tabs.

### From the command line:

```bash
cd win2k_analyzer
python win2k_gui.py
```

### From Visual Studio Code:

1. Open the `win2k_analyzer` folder in VS Code
2. Open `win2k_gui.py`
3. Press `F5` or click **Run > Run Without Debugging**
4. Or open the VS Code terminal (`Ctrl+`` `) and type: `python win2k_gui.py`

### From File Explorer:

Double-click `win2k_gui.py` (if Python is associated with `.py` files).

### GUI Tabs at a Glance:

| Tab # | Name | What it does |
|-------|------|-------------|
| 1 | Exports / Imports | Browse any PE file's export and import tables |
| 2 | Syscall Extractor | Extract syscall numbers from ntdll.dll |
| 3 | DLL Comparison | Side-by-side comparison of two DLLs |
| 4 | NT Structures | View 9 known Win2000 undocumented structures, generate C headers |
| 5 | PE Header / Scan | Full PE header dump, scan directories for PE files |
| 6 | DEF Generator | Auto-generate .def files from DLL exports |
| 7 | Syscall Patcher | Generate syscall headers in 4 styles |
| 8 | ROS Patcher | Auto-patch ReactOS source tree for Win2000 |
| 9 | Build Scripts | Generate RosBE/MSVC/CMake build scripts |
| 10 | Behavior Analyzer | Function fingerprinting, API pattern detection |
| 11 | Decompiler | x86 → C pseudocode decompiler, works without symbols |
| 12 | Compat Analyzer | Deep NT version compatibility detection, bugcheck diagnosis |
| 13 | PE Patcher | Patch binaries: version, syscalls, calling conventions |

---

## Using the CLI

The CLI tool is `win2k_analyzer.py`. Every command has built-in help:

```bash
python win2k_analyzer.py -h                    # Show all commands
python win2k_analyzer.py exports -h            # Help for a specific command
python win2k_analyzer.py compat-analyze -h     # Help for compat analyzer
```

### CLI in Visual Studio Code

The CLI works perfectly inside the **VS Code integrated terminal**:

1. Open the `win2k_analyzer` folder in VS Code (`File > Open Folder`)
2. Open the terminal: `Ctrl+`` ` or `View > Terminal`
3. Run any command:
   ```bash
   python win2k_analyzer.py exports C:\WINNT\system32\kernel32.dll
   ```
4. VS Code will show the colored output directly in the terminal panel
5. You can have multiple terminals open — one for CLI commands, one running the GUI

### CLI with GitHub Copilot in VS Code

This tool is fully compatible with **GitHub Copilot** in VS Code:

- **Copilot Chat** can help you write commands — ask it: *"How do I compare two DLLs with win2k_analyzer?"*
- **Copilot Agent Mode** can run CLI commands for you directly, analyze the output, and suggest next steps
- Copilot can read the Python modules and help you extend them with new analysis features
- You can ask Copilot to analyze the output of `compat-analyze` and explain what each issue means
- Copilot can help you write patches based on the `compat-known` output

**Example Copilot workflow:**
1. Ask Copilot: *"Run compat-analyze on my Win2000 ntoskrnl.exe vs ReactOS one and explain the results"*
2. Copilot runs the command, reads the report, and explains each critical issue
3. Ask: *"Now patch the ReactOS binary to fix the syscall mechanism"*
4. Copilot runs `patch-pe --syscalls` for you

---

## CLI Command Reference (All 27 Commands)

### PE Analysis

#### `exports` — Dump Export Table
```bash
python win2k_analyzer.py exports <dll_path> [-o output.json]
```
Lists all exported functions with ordinals, RVAs, and forwarded targets.

#### `imports` — Dump Import Table
```bash
python win2k_analyzer.py imports <dll_path> [-o output.json]
```
Lists all imported DLLs and their functions.

#### `header` — PE Header Info
```bash
python win2k_analyzer.py header <dll_path>
```
Shows machine type, subsystem, image base, entry point, sections, data directories.

#### `scan` — Scan Directory for PE Files
```bash
python win2k_analyzer.py scan <directory> [--ext .dll .sys .exe]
```
Finds all PE files in a directory and shows basic info for each.

---

### Syscalls

#### `syscalls` — Extract Syscall Numbers
```bash
python win2k_analyzer.py syscalls <ntdll_path> [-o syscalls.json]
```
Extracts syscall numbers from ntdll.dll stubs (supports int 0x2E, sysenter, and syscall patterns).

#### `syscall-patch` — Generate Syscall Headers
```bash
python win2k_analyzer.py syscall-patch <ntdll_path> --style {napi,define,asm,table} [-o header.h]
```
Generates syscall number headers in 4 formats for use in ReactOS builds.

---

### Comparison

#### `compare` — Full DLL Comparison
```bash
python win2k_analyzer.py compare <win2k_dll> <reactos_dll> [-o report.json]
```
Complete comparison: exports, imports, PE headers, syscalls (if ntdll).

#### `batch-compare` — Batch Compare Directories
```bash
python win2k_analyzer.py batch-compare <win2k_dir> <reactos_dir> [--ext .dll] [-o report.json]
```
Compares all matching DLLs between two directories.

---

### Structures

#### `structs` — Show NT Structure Layouts
```bash
python win2k_analyzer.py structs [name] [--c-header]
```
Shows known Win2000 SP4 undocumented structure layouts. Available structures: `PEB`, `TEB`, `KUSER_SHARED_DATA`, `EPROCESS`, `ETHREAD`, `LDR_DATA_TABLE_ENTRY`, `HEAP`, `PEB_LDR_DATA`, `RTL_USER_PROCESS_PARAMETERS`.

```bash
python win2k_analyzer.py structs PEB --c-header   # Generate C header for PEB
python win2k_analyzer.py structs                   # List all known structures
```

#### `gen-headers` — Generate All C Headers
```bash
python win2k_analyzer.py gen-headers <output_dir>
```
Generates `.h` files for all 9 known structures.

---

### DEF Files

#### `gen-def` — Generate .def File
```bash
python win2k_analyzer.py gen-def <dll_path> [-o output.def]
```
Auto-generates a `.def` file from DLL exports, ready for use in ReactOS builds.

---

### Build Scripts

#### `build-script` — Generate Build Script
```bash
python win2k_analyzer.py build-script <reactos_dir> --type {rosbe,msvc,cmake} --dlls ntdll.dll kernel32.dll [-o build.cmd]
```
Generates build scripts for compiling ReactOS DLLs targeting Win2000.

---

### Disassembly & Decompilation

#### `disasm` — Disassemble Function
```bash
python win2k_analyzer.py disasm <pe_path> <function_name>
```
Disassembles an exported function to x86 assembly.

#### `behavior` — Analyze Function Behavior
```bash
python win2k_analyzer.py behavior <pe_path> <function_name> [--compare-with <other_pe>]
```
Fingerprints a function: instruction count, API calls, syscall usage, block structure.

#### `decompile` — Decompile to C Pseudocode
```bash
python win2k_analyzer.py decompile <pe_path> <function_or_rva> [-o output.c]
```
Decompiles an exported function (or RVA address like `0x1234`) to C pseudocode. Recognizes kernel APIs, NTSTATUS codes, IRP major codes, driver structures.

```bash
python win2k_analyzer.py decompile C:\win2k\ntoskrnl.exe NtCreateFile
python win2k_analyzer.py decompile C:\win2k\ntoskrnl.exe 0x0004AE10
```

#### `discover-functions` — Discover Functions Without Symbols
```bash
python win2k_analyzer.py discover-functions <pe_path> [--max 50] [-o output.c]
```
Scans for function prologues in code sections and decompiles discovered functions — **no symbols or exports needed**.

#### `batch-decompile` — Batch Decompile All Exports
```bash
python win2k_analyzer.py batch-decompile <pe_path> [--max 100] [-o output.c]
```
Decompiles all exported functions from a PE file.

---

### Compatibility Analysis

#### `compat-analyze` — Deep Binary Compatibility Analysis
```bash
python win2k_analyzer.py compat-analyze <pe_a> <pe_b> [--label-a Win2000] [--label-b ReactOS] [--max 500] [-o report.txt]
```
**The most powerful command.** Performs deep analysis between two PE binaries and finds ALL compatibility-breaking differences:

- Calling convention changes (stdcall ↔ fastcall) per export
- HAL dispatch table routing differences
- Bit-shift pattern differences (e.g., HalpVector `<<4` vs `<<8`)
- Syscall mechanism (int 0x2E vs sysenter)
- Missing/added/changed exports and ordinal mismatches
- Import dependency differences
- Section characteristic differences
- PE header version mismatches

```bash
# Compare Win2000 kernel with ReactOS kernel
python win2k_analyzer.py compat-analyze C:\win2k\ntoskrnl.exe C:\reactos\ntoskrnl.exe

# Compare HALs
python win2k_analyzer.py compat-analyze C:\win2k\hal.dll C:\reactos\hal.dll --label-a "Win2000 HAL" --label-b "ReactOS HAL"

# Compare ntdll with custom labels and save report
python win2k_analyzer.py compat-analyze C:\win2k\ntdll.dll C:\reactos\ntdll.dll -o compat_report.txt
```

#### `compat-single` — Single PE Compatibility Profile
```bash
python win2k_analyzer.py compat-single <pe_path> [--label Win2000]
```
Analyzes a single binary: type, machine, syscall mechanism, calling convention statistics, section layout.

#### `compat-known` — Known NT Version Differences
```bash
python win2k_analyzer.py compat-known
```
Displays the built-in knowledge base of all known NT 5.0 → 5.1 differences: calling convention changes, removed HAL defines, macro differences, IDT dispatch changes, bugcheck codes.

#### `bugcheck` — Bugcheck Code Diagnosis
```bash
python win2k_analyzer.py bugcheck <code>
```
Given a BSOD bugcheck code, returns compatibility-specific causes and fix hints.

```bash
python win2k_analyzer.py bugcheck 0xA5    # ACPI_BIOS_ERROR
python win2k_analyzer.py bugcheck 0x7F    # UNEXPECTED_KERNEL_MODE_TRAP
python win2k_analyzer.py bugcheck 0x1E    # KMODE_EXCEPTION_NOT_HANDLED
python win2k_analyzer.py bugcheck 0xCA    # PNP_DETECTED_FATAL_ERROR
```

---

### PE Patching

#### `patch-pe` — Patch PE Binary for Win2000 Compatibility
```bash
# Quick patch: sets version to 5.0 + patches sysenter→int 0x2E
python win2k_analyzer.py patch-pe --quick <pe_path> [-o output.dll]

# Custom: patch only version
python win2k_analyzer.py patch-pe <pe_path> --version 5.0

# Custom: patch only syscall stubs
python win2k_analyzer.py patch-pe <pe_path> --syscalls

# Custom: inject calling convention shim
python win2k_analyzer.py patch-pe <pe_path> --shim "IoReadPartitionTable,fastcall,stdcall,4"

# Rebase to new ImageBase (fixes all relocations automatically)
python win2k_analyzer.py patch-pe <pe_path> --rebase 0x10000000

# Strip debug info + add an import
python win2k_analyzer.py patch-pe <pe_path> --strip-debug --add-import "ntdll.dll!RtlInitUnicodeString"

# Forward an export and grow a section
python win2k_analyzer.py patch-pe <pe_path> --forward-export "OldFunc=newdll.NewFunc" --grow-section ".text,0x2000"

# Load a symbol map for named patching
python win2k_analyzer.py patch-pe <pe_path> --symbol-map symbols.map --version 5.0

# Combine everything
python win2k_analyzer.py patch-pe <pe_path> --version 5.0 --syscalls --shim "IoReadPartitionTable,fastcall,stdcall,4" --rebase 0x7C800000 --strip-debug -o patched.dll
```

The patcher creates a new file (`<name>_patched.<ext>` by default) — it never modifies the original binary in place.

#### `inspect-pe` — Inspect PE Internal Tables
```bash
# Show all tables (sections, exports, imports, relocations)
python win2k_analyzer.py inspect-pe <pe_path>

# Show only exports
python win2k_analyzer.py inspect-pe <pe_path> -t exports

# Show relocations with a limit
python win2k_analyzer.py inspect-pe <pe_path> -t relocations -n 100
```

#### `inject-blob` — Inject Raw Code Blob
```bash
# Inject a binary blob and hook an export to it
python win2k_analyzer.py inject-blob <pe_path> <blob.bin> --hook "FuncName=0x00"
```
Injects a raw machine code blob into a new `.patch` section and optionally redirects specified exports to entry points within the blob.

#### `compile-inject` — GenPatch: Compile C Source & Inject
```bash
# Compile a C file and inject the resulting code into a PE
python win2k_analyzer.py compile-inject <pe_path> <source.c> --hook "MyFunc=0x00"

# Use a specific compiler
python win2k_analyzer.py compile-inject <pe_path> <source.c> --compiler i686-w64-mingw32-gcc
```
GenPatch-style pipeline: compiles C/ASM source to a flat binary blob using gcc+objcopy, then injects it with full fixup support. Requires MinGW gcc on PATH.

#### `rebase` — Rebase PE ImageBase
```bash
python win2k_analyzer.py rebase <pe_path> 0x10000000 [-o output.dll]
```
Changes the PE ImageBase and walks all relocation entries to fix up absolute addresses. Like KernelEx's `ChangeImageBase`.

#### `hex-dump` — Hex Dump at RVA
```bash
python win2k_analyzer.py hex-dump <pe_path> 0x1000 -l 0x100
```
Dumps hex + ASCII at any RVA in a PE file. Useful for verifying patches.

---

## GUI Tab Reference (All 13 Tabs)

### Tab 1: Exports / Imports
- Browse to any PE file (.dll, .sys, .exe, .cpl)
- Click **Analyze Exports** or **Analyze Imports**
- Results shown in a scrollable table
- Save to JSON

### Tab 2: Syscall Extractor
- Load ntdll.dll (Win2000 or any version)
- Extracts all syscall numbers from stubs
- Supports int 0x2E (Win2000), sysenter (XP), syscall (x64)
- Save syscall table to JSON

### Tab 3: DLL Comparison
- Load two PE files (e.g., Win2000 ntdll.dll and ReactOS ntdll.dll)
- Click **Full Compare**
- Shows: exports only in A, only in B, common, ordinal mismatches, import differences, header differences

### Tab 4: NT Structures
- Select from 9 known Win2000 SP4 undocumented structures
- View field names, offsets, sizes, types
- Generate C header files (.h)
- Structures: PEB, TEB, KUSER_SHARED_DATA, EPROCESS, ETHREAD, LDR_DATA_TABLE_ENTRY, HEAP, PEB_LDR_DATA, RTL_USER_PROCESS_PARAMETERS

### Tab 5: PE Header / Scan
- Detailed PE header dump for any file
- Scan a directory for all PE files

### Tab 6: DEF Generator
- Generate .def files from any DLL
- Ready for use in ReactOS builds
- Scan entire directories

### Tab 7: Syscall Patcher
- Generate syscall number headers from ntdll.dll
- 4 output styles: napi, define, asm, table

### Tab 8: ROS Patcher
- Point to a ReactOS source tree
- Auto-patches: version targets, syscall mechanism, .def files, and more
- Dry-run mode available
- Creates `.orig_win2k` backups of all modified files

### Tab 9: Build Scripts
- Select ReactOS source directory
- Choose DLL targets (ntdll, kernel32, shell32, etc.)
- Generate RosBE, MSVC, or CMake build scripts

### Tab 10: Behavior Analyzer
- Fingerprint any exported function
- Detect API call patterns, syscall usage
- Compare function implementations between two DLLs

### Tab 11: Decompiler
- Decompile any exported function to C pseudocode
- Enter function name or RVA (e.g., `0x4AE10`)
- **Discover Functions** — finds functions without symbols by scanning for prologues
- **Batch Decompile** — decompile all exports at once
- Syntax highlighting in output
- Recognizes: NTSTATUS codes, IRP major codes, kernel APIs, driver structures, pool tags, IOCTL codes

### Tab 12: Compat Analyzer
- Load two PE files for deep compatibility analysis
- Set version labels (e.g., "Win2000" and "ReactOS")
- **Full Compat Analysis** — runs all detection engines
- **Analyze Single PE** — compatibility profile for one binary
- **Known Differences** — browse the built-in NT 5.0→5.1 knowledge base
- **Bugcheck Lookup** — enter a BSOD code, get compat-specific diagnosis
- Color-coded output: red for critical, yellow for warnings

### Tab 13: PE Patcher (KernelEx Ultimate Edition)
- Load a PE file to patch
- Checkboxes: Patch version to 5.0, Patch sysenter→int 0x2E, Strip debug info
- Convention shim entry field (e.g., `IoReadPartitionTable,fastcall,stdcall,4`)
- Rebase entry field (hex address, e.g., `0x7C800000`)
- **Quick Win2000 Patch** — one-click version + syscall fix
- **Custom Patch** — apply all selected patches (version, syscalls, debug strip, shim, rebase)
- **Patch Syscalls Only** — just the sysenter→int 0x2E replacement
- **Inspect Tables** — view all PE internal tables (exports, imports, relocations, sections)
- **Rebase** — change ImageBase and fix all relocations
- Output file saved as `<name>_patched.<ext>` (original never modified)

---

## Using with Visual Studio Code

This project works great as a **VS Code workspace**:

1. **Open the folder**: `File > Open Folder > win2k_analyzer`
2. **Run the GUI**: Open terminal (`Ctrl+`` `), type `python win2k_gui.py`
3. **Run CLI commands**: Use the integrated terminal for any CLI command
4. **Edit modules**: All 12 Python modules are in the `nt_analyzer/` package — fully documented and modular
5. **Debug**: Set breakpoints in any module, press F5 to debug
6. **IntelliSense**: VS Code provides autocomplete for all module functions

### Recommended VS Code Extensions

- **Python** (Microsoft) — IntelliSense, debugging, linting
- **GitHub Copilot** — AI-assisted coding and command suggestions
- **Hex Editor** — View patched PE binaries
- **x86 and x86-64 Assembly** — Syntax highlighting for disassembly output

---

## Using with GitHub Copilot

GitHub Copilot integrates seamlessly with this tool:

### In Copilot Chat:
- *"Show me the exports of kernel32.dll"* → Copilot runs `exports` command
- *"Compare these two ntoskrnl.exe files for compatibility"* → Copilot runs `compat-analyze`
- *"What does bugcheck 0xA5 mean?"* → Copilot runs `bugcheck 0xA5`
- *"Decompile NtCreateFile from this kernel"* → Copilot runs `decompile`
- *"Patch this DLL for Windows 2000"* → Copilot runs `patch-pe --quick`

### In Copilot Agent Mode:
Copilot can autonomously:
1. Run analysis commands and interpret results
2. Identify compatibility issues from reports
3. Suggest and apply patches
4. Extend the analyzer with new detection rules
5. Write custom scripts using the `nt_analyzer` Python API

### Using the Python API directly:
```python
from nt_analyzer.compat_analyzer import compare_compat, diagnose_bugcheck
from nt_analyzer.pe_patcher import (
    PEPatcher, CodeBlob, DiffEntry, PatchSet,
    patch_pe_for_win2000, inspect_pe_tables, rebase_pe
)
from nt_analyzer.decompiler import decompile, decompile_no_symbols

# Deep compatibility analysis
report = compare_compat("win2k_ntoskrnl.exe", "reactos_ntoskrnl.exe")
print(report.summary())

# Diagnose a BSOD
info = diagnose_bugcheck("0xA5")
print(info['known_causes'])

# Quick-patch a binary for Win2000
result = patch_pe_for_win2000("reactos_ntdll.dll")
print(result.summary())

# Inspect all PE tables
tables = inspect_pe_tables("kernel32.dll")
print(f"Exports: {len(tables['exports'])}, Imports: {len(tables['imports'])}")

# Rebase a PE
result = rebase_pe("my.dll", 0x10000000)
print(result.summary())

# Advanced: inject a code blob with KernelEx's 4-table fixup system
patcher = PEPatcher("target.dll")
blob = CodeBlob(
    code=my_compiled_x86_bytes,
    abs_ofs=[(0x10,)],                                # DWORDs needing +ImageBase+blob_rva
    abs_api=[(0x20, "kernel32.dll", "GetProcAddress")],  # absolute API address
    rel_api=[(0x30, "ntdll.dll", "RtlInitUnicodeString")],  # relative call to API
    hook_api=[("OldFunction", 0x00)],                   # redirect export to blob
    new_exports=[("NewFunction", 0x40)],               # register new exports
)
patcher.inject_code_blob(blob)
patcher.rebuild_exports()  # sorted merge into new .edata section
result = patcher.save()

# Use the 5-stage KernelEx pipeline
patch = PatchSet(
    name="Win2000 Compat",
    code_blobs=[blob],
    diff_patches=[DiffEntry(mode="rva", location=0x1234, new_bytes=b'\x90\x90')],
    version_patch=(5, 0),
    conditions=[lambda p: hasattr(p.pe, 'DIRECTORY_ENTRY_EXPORT')],
)
result = patcher.apply_patch_set(patch)

# Decompile without symbols
functions = decompile_no_symbols("ntoskrnl.exe", max_funcs=20)
for name, code in functions.items():
    print(code)
```

---

## Module Architecture

```
win2k_analyzer/
├── win2k_analyzer.py          # CLI frontend (27 commands)
├── win2k_gui.py               # GUI frontend (13 tabs, dark theme)
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── nt_analyzer/               # Core analysis package
│   ├── __init__.py            # Package init, version 2.0.0
│   ├── pe_analyzer.py         # PE export/import/header analysis
│   ├── syscall_extractor.py   # Syscall number extraction from ntdll stubs
│   ├── comparator.py          # Side-by-side DLL comparison
│   ├── struct_analyzer.py     # 9 known Win2000 SP4 structure layouts
│   ├── def_generator.py       # Auto .def file generation
│   ├── syscall_patcher.py     # Syscall header generation (4 styles)
│   ├── ros_patcher.py         # ReactOS source tree auto-patcher
│   ├── build_generator.py     # Build script generation (RosBE/MSVC/CMake)
│   ├── behavior_analyzer.py   # Function fingerprinting & API patterns
│   ├── decompiler.py          # x86→C decompiler (works without symbols)
│   ├── compat_analyzer.py     # Deep NT version compatibility detection
│   └── pe_patcher.py          # KernelEx-inspired PE binary patcher (1900+ lines, 46 methods)
│
└── generated_headers/         # Output: generated C header files
    ├── peb_win2k.h
    ├── teb_win2k.h
    └── kuser_shared_data_win2k.h
```

---

## FAQ — Frequently Asked Questions

### General

**Q: What Python version do I need?**
A: Python 3.10 or later. Tested on Python 3.14.

**Q: Does this work on Linux/Mac?**
A: The analysis and comparison features work anywhere. The GUI requires tkinter. PE patching is Windows-focused but the code runs cross-platform.

**Q: What file types does this support?**
A: ALL PE file types: `.dll`, `.sys`, `.exe`, `.cpl`, `.drv`, `.ocx`, `.scr` — anything with a valid PE header.

**Q: Do I need debug symbols (PDB files)?**
A: **No.** The decompiler and all analysis features work without symbols. The `discover-functions` command finds functions by scanning for prologues.

### Analysis

**Q: How do I see what functions a DLL exports?**
A: CLI: `python win2k_analyzer.py exports <file>` or GUI: Tab 1, browse to file, click "Analyze Exports".

**Q: How do I compare Win2000 and ReactOS versions of the same DLL?**
A: CLI: `python win2k_analyzer.py compare <win2k.dll> <reactos.dll>` for basic comparison, or `python win2k_analyzer.py compat-analyze <win2k.dll> <reactos.dll>` for deep compatibility analysis.

**Q: How do I see the undocumented PEB/TEB/EPROCESS structures?**
A: CLI: `python win2k_analyzer.py structs PEB` or GUI: Tab 4, select PEB from the list.

**Q: How do I extract syscall numbers?**
A: CLI: `python win2k_analyzer.py syscalls C:\WINNT\system32\ntdll.dll` or GUI: Tab 2.

**Q: How do I generate a .def file for building a DLL?**
A: CLI: `python win2k_analyzer.py gen-def <dll_path>` or GUI: Tab 6.

### Decompilation

**Q: How do I decompile a kernel function?**
A: CLI: `python win2k_analyzer.py decompile <pe_file> <function_name>` or GUI: Tab 11, enter function name, click "Decompile Export".

**Q: Can I decompile by address instead of name?**
A: Yes. Use an RVA: `python win2k_analyzer.py decompile ntoskrnl.exe 0x4AE10`

**Q: How do I find functions in a binary without symbols?**
A: CLI: `python win2k_analyzer.py discover-functions <pe_file> --max 100` or GUI: Tab 11, click "Discover Functions (No Symbols)".

**Q: What kernel APIs does the decompiler recognize?**
A: 80+ kernel APIs including IoCallDriver, KeWaitForSingleObject, ExAllocatePool, ObReferenceObject, RtlInitUnicodeString, MmProbeAndLockPages, and many more. Plus NTSTATUS codes, IRP major codes, pool types, IRQL levels, device types, and IOCTL decoding.

### Compatibility

**Q: What does `compat-analyze` detect?**
A: Calling convention changes (stdcall↔fastcall), HAL dispatch routing differences, bit-shift macro changes (HalpVector), syscall mechanism (int 0x2E vs sysenter), missing/added exports, import changes, section differences, version mismatches, ordinal shifts.

**Q: I got bugcheck 0xA5 (ACPI_BIOS_ERROR) — what's wrong?**
A: Run `python win2k_analyzer.py bugcheck 0xA5`. Common cause: HalpVector macro uses `<<8` (XP) instead of `<<4` (Win2000), or HAL/ACPI version mismatch.

**Q: I got bugcheck 0x7F (UNEXPECTED_KERNEL_MODE_TRAP) — what's wrong?**
A: Run `python win2k_analyzer.py bugcheck 0x7F`. Common cause: Calling convention mismatch — stdcall callee cleans N bytes from stack but fastcall only cleans N-8, causing stack corruption.

**Q: What are the known NT 5.0→5.1 calling convention changes?**
A: Run `python win2k_analyzer.py compat-known`. Key ones: IoAssignDriveLetters, IoReadPartitionTable, IoSetPartitionInformation, IoWritePartitionTable changed from stdcall to fastcall. Also IofCallDriver, IofCompleteRequest, KfAcquireSpinLock, KfReleaseSpinLock, KfRaiseIrql, KfLowerIrql.

**Q: What HAL defines were removed in XP?**
A: HalIoAssignDriveLetters, HalIoReadPartitionTable, HalIoSetPartitionInformation, HalIoWritePartitionTable — these macros routed through HalDispatchTable in Win2000 but were removed in XP (kernel handles them directly).

### Patching

**Q: How do I patch a ReactOS DLL to work on Win2000?**
A: Quick way: `python win2k_analyzer.py patch-pe --quick <file>`. This sets the version stamp to 5.0 and replaces all sysenter stubs with int 0x2E.

**Q: Does patching modify my original file?**
A: **No.** The patcher always creates a new file: `<name>_patched.<ext>`. Use `-o` to specify a custom output path.

**Q: How do I fix a calling convention mismatch?**
A: Use `--shim`: `python win2k_analyzer.py patch-pe <file> --shim "IoReadPartitionTable,fastcall,stdcall,4"`. This injects a wrapper that translates between conventions.

**Q: How do I inject custom code into a PE?**
A: Two ways: (1) Compile C code and inject in one step: `python win2k_analyzer.py compile-inject <pe> <source.c> --hook "FuncName=0x00"`. (2) Inject a pre-compiled blob: `python win2k_analyzer.py inject-blob <pe> <blob.bin> --hook "FuncName=0x00"`. Both create a `.patch` section and can redirect existing exports to your code.

**Q: How do I inspect PE tables without patching?**
A: CLI: `python win2k_analyzer.py inspect-pe <file>` or GUI: Tab 13, click "Inspect Tables". Shows sections, exports, imports, and relocations.

**Q: How do I rebase a PE to a different address?**
A: CLI: `python win2k_analyzer.py rebase <file> 0x10000000` or `python win2k_analyzer.py patch-pe <file> --rebase 0x10000000`. The rebase walks all relocation entries and fixes absolute addresses.

**Q: What is the 4-table fixup system?**
A: Inspired by KernelEx's `binary_api_patch`: when you inject a code blob, you specify 4 fixup tables that tell the patcher how to resolve addresses in your code: `abs_ofs` (add ImageBase+blob_rva), `abs_api` (absolute API address), `rel_api` (relative call/jmp to API), `hook_api` (redirect existing exports to blob entry points).

**Q: What is the 5-stage pipeline?**
A: Based on KernelEx's `apply_patches`: (1) Prepare — validate conditions, (2) API_entries — inject code blobs with fixups, (3) Alter_sections — apply binary diffs and shims, (4) Rebuild_tables — rebuild export/import tables, (5) Process — version patches, checksum, finalize. Use the `PatchSet` class for bundled patching.

**Q: How do I generate build scripts for ReactOS?**
A: CLI: `python win2k_analyzer.py build-script <reactos_dir> --type rosbe --dlls ntdll.dll kernel32.dll` or GUI: Tab 9.

### VS Code & Copilot

**Q: Can I use this from VS Code?**
A: Yes. Open the `win2k_analyzer` folder in VS Code. Use the integrated terminal for CLI commands, or press F5 to run the GUI. All modules support IntelliSense autocomplete.

**Q: Does this work with GitHub Copilot?**
A: Yes. Copilot can run CLI commands via Agent Mode, analyze output, suggest patches, and even extend the analyzer modules. Ask Copilot things like *"Run compat-analyze and explain the results"* or *"Patch this DLL for Windows 2000"*.

**Q: Can I extend the analyzer with new features?**
A: Yes. Each module in `nt_analyzer/` is standalone. Add new detection rules to `compat_analyzer.py`, new structure layouts to `struct_analyzer.py`, or new patch types to `pe_patcher.py`. The CLI and GUI will pick them up automatically.

---

## Known NT 5.0 vs 5.1 Differences

This knowledge base is built into the tool (see `compat-known` command):

| Category | NT 5.0 (Windows 2000) | NT 5.1 (Windows XP) |
|----------|----------------------|---------------------|
| Syscall mechanism | `int 0x2E` | `sysenter` |
| HalpVector macro | `Vector << 4` | `Vector << 8` |
| IDT entry calculation | Uses Vector directly | Uses `HalVectorToIDTEntry(Vector)` |
| IoReadPartitionTable | stdcall, routed through HalDispatchTable | fastcall, kernel-direct |
| IoWritePartitionTable | stdcall, routed through HalDispatchTable | fastcall, kernel-direct |
| IoAssignDriveLetters | stdcall, routed through HalDispatchTable | fastcall, kernel-direct |
| IoSetPartitionInformation | stdcall, routed through HalDispatchTable | fastcall, kernel-direct |
| HalIo* defines | Present in headers | Removed |
| IofCallDriver | stdcall | fastcall |
| IofCompleteRequest | stdcall | fastcall |
| KfAcquireSpinLock | stdcall | fastcall |
| KfReleaseSpinLock | stdcall | fastcall |
| Affinity calculation | Direct bitmask | NUMA-aware via HalpVectorToNode |
| drivesup.c includes | halp.h (kernel code) | nt.h (user-mode style) |

---

## Contributing

This is a community project for Windows 2000 preservation and ReactOS compatibility research.

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Areas that need help:
- More structure layouts (KPRCB, KTHREAD, OBJECT_HEADER, etc.)
- x86-64 decompiler support
- More calling convention detection heuristics
- Additional NT version difference rules
- Testing on more Win2000 system binaries
- Pre-built patch sets for common ReactOS DLLs
- PDB symbol loading integration
- Binary diff generation between PE versions

---

**Made with love for the Windows 2000 community.**
