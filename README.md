# Win2K NT Internals Analyzer

**The ultimate reverse-engineering and binary compatibility toolkit for porting ReactOS components to Windows 2000 SP4.**

Analyze, compare, decompile, emulate, debug, patch, rewrite, and build NT kernel-mode and user-mode binaries — all from a single tool with both a **dark-themed GUI (17 tabs)** and a **full CLI (27 commands)**.

**NEW in v3.5 — Universal Binary Rewriting Tool (UBRT) v7.2:**
- **Universal Binary Rewriter:** Insert, delete, or patch bytes anywhere in a PE, ELF, or Mach-O binary and have **every reference in the file automatically recalculated** — relocations, jump tables, export/import tables, exception tables, TLS, debug directories, resource directories, load configs, delay imports, bound imports, and more.
- **15 reference analysis passes** — discovers 109,000+ relocatable references in ntoskrnl.exe alone: direct relocations, export RVAs, import thunks, exception handler RVAs, TLS callbacks, debug directory entries, resource RVAs, load config pointers, delay import descriptors, bound import descriptors, indirect calls through memory, indirect jumps through memory, section-relative data, cross-section references, and QEMU dynamic trace targets.
- **Multi-format support:** PE (32/64-bit), ELF (with full section/program header updates, SHT_RELA addend correction), Mach-O (including fat/universal binaries with automatic arch offset shifting).
- **QEMU dynamic tracing:** Run any binary under QEMU with `-d exec` tracing, parse the execution log, and **automatically discover indirect call/jump targets** that static analysis misses — merged as first-class references for the shift engine.
- **compact():** Reclaim trailing zero padding from any section in PE, ELF, or Mach-O binaries — automatically updates all headers and re-parses the binary.
- **strip_signature():** Remove PE Authenticode signatures (zeroes Security directory, truncates certificate table, zeroes checksum) and Mach-O LC_CODE_SIGNATURE load commands — so modified binaries don't fail signature verification.
- **Resource directory protection:** Detects when a shift operation falls inside a `.rsrc` section and skips internal resource pointer rewriting to prevent corruption of the resource tree's relative offsets.
- **GUI Tab 17 (UBRT):** Full graphical interface with progress dialogs, tabbed results, format detection, reference analysis display, and interactive patch/insert/delete operations.

**Previously in v3.4 — Dynamic PDB Structure Extraction:**
- **Zero static data:** All Win2000 kernel structure layouts (PEB, TEB, EPROCESS, ETHREAD, KUSER_SHARED_DATA, etc.) are now extracted **live from real PDB debug symbols** — no hardcoded field tables, no stale offsets.
- **Native PDB 2.0 / 7.0 parser** — reads Microsoft PDB files (both JG/MSF 2.0 and DS/MSF 7.0 formats) directly in pure Python — no `pdbparse` or external dependency required.
- **Full TPI stream support** — resolves LF_STRUCTURE, LF_UNION, LF_ARRAY, LF_POINTER, LF_MODIFIER, LF_BITFIELD, LF_FIELDLIST and all CodeView leaf types. Handles forward-reference chains, nested types, and pointer qualifiers (PVOID, PULONG, PPEB_LDR_DATA, etc.).
- **GUI Load PDB button** — Tab 4 (NT Structures) gains a **Load PDB** button and a live filter box. Point it at `ntoskrnl.pdb` and instantly browse all 309+ structures extracted from the debug symbols.
- **CLI `--pdb` flag** — `structs --pdb ntoskrnl.pdb [NAME]` and `gen-headers --pdb ntoskrnl.pdb <dir>` now require a PDB path so layouts always come from the binary's own symbols.
- **Tested on Win2K SP4 retail debug symbols** — 309 structures, 10 unions, 2268 types extracted from `ntoskrnl.pdb` (PDB 2.0 format from the Windows 2000 SP4 DDK/debug package).

**Previously in v3.3 — Live Kernel Debugger:**
- **Live Kernel State Debugger:** Point it at a Win2K System32 folder and it builds a complete kernel environment in RAM — loads ntoskrnl.exe + hal.dll + dependencies, resolves cross-module IAT imports, builds KPCR/EPROCESS/ETHREAD/handle tables, then lets you run any kernel function with breakpoints, single-stepping, register inspection, call stack reconstruction, and object inspection. Like a portable WinDbg — no live kernel, no VM, no debug cables.
- **Multi-PE Loader:** Loads multiple PEs into a shared Unicorn x86 address space with real GDT/FS segment setup for kernel FS:[offset] access (KPCR at 0xFFDFF000).
- **Breakpoints + Stepping:** Set breakpoints by name or address, step instruction-by-instruction, continue from pause, inspect registers/stack/memory at any point.
- **Cross-Module Call Tracing:** Watch ntoskrnl call into HAL and back with real resolved import addresses — no stubs.
- **Missing Module Detection:** Auto-detects when a dependency can't be loaded (e.g., bootvid.dll) and reports exactly which imports are affected.

**Previously in v3.2 — Kernel Function Emulator, SSDT Intelligence, Dual Symbols:**
- **Kernel Function Emulator:** WinDbg-like x86 emulation engine powered by Unicorn. Load any Win2K PE (ntoskrnl.exe, hal.dll, ntdll.dll, ...), emulate any kernel function with controlled inputs, auto-generate 12 test scenarios, verify NTSTATUS return values and API call patterns — all **before** patching a live system.
- **SSDT Resolver (Zero-Symbol Kernel Intelligence):** Resolves ALL 248 private Nt* kernel functions (NtPowerInformation, NtQuerySystemInformation, NtClose, etc.) directly from the binary — no PDB/DBG symbols required. Scans KiServiceTable via Zw stub → syscall number → SSDT lookup.
- **Dual Symbol Loading:** Behavior Analyzer now supports separate symbol files for DLL A (Win2K) and DLL B (ReactOS) with color-coded clickable links — blue for Win2K, green for ReactOS.
- **67+ Kernel API Mocks:** ExAllocatePool, ProbeForRead/Write, ObReferenceObjectByHandle, KeGetCurrentIrql, spinlocks, MDL operations, registry, IO/IRP, power management — all mocked for accurate emulation.

**Previously in v3.1 — Deep Analyzer, Tabbed Output, Symbol Integration:**
- Tabbed Output (IDA Pro-style), Deep Analyzer (function discovery without symbols), Symbol Loader (.map/.pdb/.dbg/.sym), Decompiler Modes (Pseudo-C/ASM/Hex), XRef Scanner, Progress Dialogs.

**Previously in v3.0 — KernelEx Ultimate PE Patcher:**  All patching techniques from KernelEx (Xeno86, 2006-2008) have been reverse-engineered and reimplemented in Python with modern 2026 capabilities: code blob injection with 4-table fixups, full export/import table rebuild, PE rebase, GenPatch-style C→binary compilation, 5-stage patch pipeline, symbol-aware patching, and more.

Works on **ALL PE file types**: `.dll`, `.sys`, `.exe`, `.cpl`, `.drv`, `.ocx`, `.scr`

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

---

## Table of Contents

- [What Does This Tool Do?](#what-does-this-tool-do)
- [What's New in v3.5 — UBRT Engine](#whats-new-in-v35--ubrt-engine)
- [What's New in v3.4 — Dynamic PDB Structure Extraction](#whats-new-in-v34--dynamic-pdb-structure-extraction)
- [What's New in v3.2](#whats-new-in-v32)
- [Kernel Function Emulator](#kernel-function-emulator--pre-test-patches-before-deploying)
- [SSDT Resolver — Zero-Symbol Kernel Intelligence](#ssdt-resolver--zero-symbol-kernel-intelligence)
- [Features Overview](#features-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Opening the GUI](#opening-the-gui)
- [Tabbed Output System](#tabbed-output-system)
- [Using the CLI](#using-the-cli)
- [CLI Command Reference (All 27 Commands)](#cli-command-reference-all-27-commands)
- [Patching NT System Internals (.sys / Kernel-Mode Binaries)](#patching-nt-system-internals-sys--kernel-mode-binaries)
- [Kernel Debugger — Live Kernel State](#kernel-debugger--live-kernel-state)
- [UBRT Engine — Universal Binary Rewriting](#ubrt-engine--universal-binary-rewriting)
- [GUI Tab Reference (All 17 Tabs)](#gui-tab-reference-all-17-tabs)
- [Deep Analyzer — IDA Pro-Level Analysis Without Symbols](#deep-analyzer--ida-pro-level-analysis-without-symbols)
- [Symbol Loader — Enrich Disassembly With Debug Info](#symbol-loader--enrich-disassembly-with-debug-info)
- [Decompiler Modes — Pseudo-C, Assembly, Hex Dump](#decompiler-modes--pseudo-c-assembly-hex-dump)
- [XRef Scanner — Find All Callers Across System32](#xref-scanner--find-all-callers-across-system32)
- [Using with Visual Studio Code](#using-with-visual-studio-code)
- [Using with GitHub Copilot](#using-with-github-copilot)
- [Module Architecture](#module-architecture)
- [FAQ — Frequently Asked Questions](#faq--frequently-asked-questions)
- [Contributing](#contributing)

---

## What Does This Tool Do?

If you want to **replace Windows 2000 SP4 system files (kernel32.dll, ntdll.dll, shell32.dll, win32k.sys, etc.) with open-source ReactOS equivalents**, you need to understand the deep binary-level differences between NT 5.0 (Windows 2000) and NT 5.1+ (XP/ReactOS target).

This tool gives you everything in one place:

1. **Analyze** — Extract exports, imports, syscalls, PE headers from any Windows binary
2. **Compare** — Side-by-side diff of Win2000 vs ReactOS DLLs (exports, imports, syscalls, PE headers)
3. **Decompile** — Convert x86 assembly to C pseudocode, annotated assembly, or hex dump — even **without symbols**
4. **Deep Analyze** — IDA Pro-level function discovery, cross-reference maps, calling convention detection, dependency profiling — all without symbols
5. **Detect** — Intelligently find calling convention changes, HAL dispatch differences, macro differences, structure layout changes between NT versions
6. **Patch** — KernelEx-inspired PE binary patcher with ALL KernelEx techniques: code blob injection with 4-table fixups, full export table rebuild, PE rebase, GenPatch-style C/ASM compilation pipeline, calling convention shims, and the full 5-stage patch pipeline
7. **Inspect** — Deep PE table inspection: exports, imports, relocations, sections — with hex dump
8. **Scan** — System-wide cross-reference scanning: find every PE in a directory that imports or calls a given function
9. **Build** — Generate build scripts (RosBE, MSVC, CMake) for compiling ReactOS DLLs for Win2000

---

## What's New in v3.4 — Dynamic PDB Structure Extraction

### Native PDB Parser (NEW)

All NT kernel structure layouts are now extracted **live from real Win2K debug symbol files** using a built-in pure-Python PDB parser — no external libraries, no `pdbparse`, no hardcoded tables.

**Supported PDB formats:**
- **PDB 2.0** (magic `Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0`) — used by Windows 2000 SP4 DDK debug symbols
- **PDB 7.0** (magic `Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0`) — used by modern MSVC toolchains

**CodeView TPI leaf types fully supported:**

| Leaf Code | Type | Description |
|-----------|------|-------------|
| `0x1001` | `LF_MODIFIER` | const/volatile qualifier wrapper |
| `0x1002` | `LF_POINTER` | pointer type (→ PVOID, PULONG, PPEB, ...) |
| `0x1003` | `LF_ARRAY_ST` | fixed-size array (PDB 2.0 style) |
| `0x1005` | `LF_STRUCTURE` | struct type with named fields |
| `0x1006` | `LF_UNION` | union type |
| `0x1203` | `LF_FIELDLIST` | list of member fields for a struct/union |
| `0x1205` | `LF_BITFIELD` | bit-field member |
| `0x1405` | `LF_MEMBER_ST` | named struct member (name + offset + type) |
| `0x1503` | `LF_ARRAY` | fixed-size array (PDB 7.0 style) |

**Forward-reference resolution** — if a struct type has size=0 (forward reference), the parser automatically finds the full definition by scanning the TPI stream.

**Pointer name promotion** — `P` + `void` → `PVOID`, `P` + `ULONG` → `PULONG`, `P` + `_PEB_LDR_DATA` → `PPEB_LDR_DATA` (uses uppercase only when base type is all-caps).

**Last-field size inference** — the size of the final field in any struct is inferred from `struct_total_size − last_field_offset` rather than guessing from the type, eliminating zero-byte trailing fields.

### What Was Extracted from Win2K SP4 ntoskrnl.pdb

```
PDB format:  2.0 (JG/MSF)
TPI stream:  2268 types
Structures:  309
Unions:       10
```

**Example — PEB (Process Environment Block):**
```c
typedef struct _PEB {         // 488 bytes, 56 fields
    UCHAR  InheritedAddressSpace;          // +0x000  1 bytes
    UCHAR  ReadImageFileExecOptions;       // +0x001  1 bytes
    UCHAR  BeingDebugged;                  // +0x002  1 bytes
    UCHAR  SpareBool;                      // +0x003  1 bytes
    PVOID  Mutant;                         // +0x004  4 bytes
    PVOID  ImageBaseAddress;               // +0x008  4 bytes
    PPEB_LDR_DATA  Ldr;                    // +0x00c  4 bytes
    // ... 53 more fields
    ULONG  CSDVersion[2];                  // +0x1e8  8 bytes (last field from struct size)
} PEB;
```

### GUI Changes: Tab 4 (NT Structures)

The Structures tab is completely reworked:

- **Load PDB button** — opens a file dialog to select any `.pdb` file
- **Live filter box** — type to filter structure names in real time (e.g., type `PEB` to instantly find `_PEB`, `_PEB_LDR_DATA`, `_PEB_FREE_BLOCK`)
- **Dynamic combobox** — populated with all extracted structures after PDB load (309+ entries from ntoskrnl.pdb)
- **View Layout** — shows field table: name, offset (hex), size (bytes), type string
- **Generate C Header** — generates a proper C typedef struct block for the selected structure
- **Export All Headers** — generates `.h` files for every structure/union in the PDB into a chosen output directory

### CLI Changes

```bash
# List all structures from a PDB
python win2k_analyzer.py structs --pdb C:\Symbols\ntoskrnl.pdb

# View a specific structure
python win2k_analyzer.py structs --pdb C:\Symbols\ntoskrnl.pdb _PEB

# Generate C header for one structure
python win2k_analyzer.py structs --pdb C:\Symbols\ntoskrnl.pdb _EPROCESS --c-header

# Generate all C headers from a PDB
python win2k_analyzer.py gen-headers --pdb C:\Symbols\ntoskrnl.pdb .\generated_headers\
```

The `--pdb` flag is **required** for both commands — structures always come from the provided debug symbols, never from embedded static data.

### Python API

```python
from nt_analyzer.struct_analyzer import load_pdb, list_structures, get_structure, PDBTypeInfo

# Load a PDB file
info = load_pdb(r"C:\Symbols\ntoskrnl.pdb")

# List all available structure names
names = list_structures(info)   # ['_ACE', '_ACL', ..., '_PEB', ..., '_ZONE_HEADER']
print(f"{len(names)} structures found")

# Get one structure's fields
peb = get_structure(info, "_PEB")
# → PDBTypeInfo(name='_PEB', size=488, fields=[...56 fields...])
for field in peb.fields:
    print(f"  +0x{field.offset:03x}  {field.type_name:<30} {field.name}")

# Generate a C header string
from nt_analyzer.struct_analyzer import generate_c_header
header = generate_c_header(info, "_PEB")
print(header)

# Save all headers to disk
from nt_analyzer.struct_analyzer import save_all_headers
saved = save_all_headers(info, r".\generated_headers")
print(f"Saved {saved} header files")
```

---

## What's New in v3.2

### Kernel Function Emulator (NEW)

A **WinDbg-like x86 emulation engine** that lets you execute any kernel function virtually and verify its behavior before deploying patches to real hardware:

- **Works on any Win2K system PE** — ntoskrnl.exe, hal.dll, ntdll.dll, win32k.sys, any .sys driver
- **SSDT-powered** — finds private Nt* kernel functions automatically, no symbols needed
- **67+ kernel API mocks** — ExAllocatePool, ProbeForRead/Write, ObReferenceObjectByHandle, KeGetCurrentIrql, spinlocks, MDL, registry, IO/IRP, power, HAL stubs
- **Auto-generated test scenarios** — 12 scenarios per function: null args, valid/invalid classes, user/kernel mode, small buffers, privilege checks
- **Full execution trace** — every instruction, every branch, every API call logged
- **NTSTATUS verification** — compare return values against expected results
- **Dynamic memory layout** — stack/heap/stubs placed automatically to avoid PE image overlap

**Real example — NtPowerInformation from Win2K ntoskrnl.exe (all 12 scenarios):**

```
========================================================================
  KERNEL FUNCTION EMULATION REPORT
  Function: NtPowerInformation
  Scenarios tested: 12
========================================================================

────────────────────────────────────────────────────────────────────────
 ❌  Scenario 1: Null arguments
    All arguments zero / NULL - should fail gracefully
    Mode: User
    Args: [0x0, 0x0, 0x0, 0x0, 0x0]
    Return: 0x00000000 (STATUS_SUCCESS)
    Expected: 0xC000000D (STATUS_INVALID_PARAMETER)
    Match: NO
    Instructions: 140
    Time: 0.016s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 2: Class 0 - Kernel mode
    InformationClass=0, valid output buffer, kernel mode
    Mode: Kernel
    Args: [0x0, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x00000000 (STATUS_SUCCESS)
    Expected: 0x00000000 (STATUS_SUCCESS)
    Match: YES
    Instructions: 210
    Time: 0.011s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 3: Class 0 - User mode
    InformationClass=0, valid output buffer, user mode
    Mode: User
    Args: [0x0, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x00000000 (STATUS_SUCCESS)
    Instructions: 210
    Time: 0.013s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 4: Small buffer
    Output buffer too small
    Mode: Kernel
    Args: [0x0, 0x0, 0x0, 0x8C0000, 0x4]
    Return: 0xC0000023 (STATUS_BUFFER_TOO_SMALL)
    Expected: 0xC0000023 (STATUS_BUFFER_TOO_SMALL)
    Match: YES
    Instructions: 148
    Time: 0.018s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ❌  Scenario 5: Invalid class 0xFFFF
    Very large information class - should return INVALID_PARAMETER
    Mode: Kernel
    Args: [0xFFFF, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x01469780 (STATUS_OK(0x01469780))
    Expected: 0xC000000D (STATUS_INVALID_PARAMETER)
    Match: NO
    Instructions: 282428
    Time: 4.651s
    Exception: Unicorn error: Invalid instruction (UC_ERR_INSN_INVALID)
    API calls (3003):
      KeGetCurrentIrql (x3003)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 6: User mode - no privilege
    User mode call with privilege check disabled
    Mode: User
    Args: [0x0, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x00000000 (STATUS_SUCCESS)
    Instructions: 210
    Time: 0.012s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ❌  Scenario 7: Valid input buffer
    Both InputBuffer and OutputBuffer valid
    Mode: Kernel
    Args: [0x0, 0x8D0000, 0x100, 0x8C0000, 0x1000]
    Return: 0x00000045 (STATUS_OK(0x00000045))
    Expected: 0x00000000 (STATUS_SUCCESS)
    Match: NO
    Instructions: 500001
    Time: 9.811s
    Exception: Instruction limit (500000)
    API calls (3002):
      KeGetCurrentIrql (x3002)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 8: Class 1
    InformationClass=1, kernel mode
    Mode: Kernel
    Args: [0x1, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x00000000 (STATUS_SUCCESS)
    Instructions: 210
    Time: 0.007s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 9: Class 2
    InformationClass=2, kernel mode
    Mode: Kernel
    Args: [0x2, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0xC000000D (STATUS_INVALID_PARAMETER)
    Instructions: 135
    Time: 0.016s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 10: Class 3
    InformationClass=3, kernel mode
    Mode: Kernel
    Args: [0x3, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0xC000000D (STATUS_INVALID_PARAMETER)
    Instructions: 135
    Time: 0.006s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 11: Class 4
    InformationClass=4, kernel mode
    Mode: Kernel
    Args: [0x4, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x00000000 (STATUS_SUCCESS)
    Instructions: 267
    Time: 0.009s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

────────────────────────────────────────────────────────────────────────
 ✅  Scenario 12: Class 5
    InformationClass=5, kernel mode
    Mode: Kernel
    Args: [0x5, 0x0, 0x0, 0x8C0000, 0x1000]
    Return: 0x00000000 (STATUS_SUCCESS)
    Instructions: 198
    Time: 0.005s
    API calls (1):
      HalRequestSoftwareInterrupt (x1)

========================================================================
  SUMMARY: 9 passed, 3 failed out of 12 scenarios
========================================================================
```

**Detailed execution trace (NtYieldExecution — 11 instructions):**

```
  VA         | Instruction
  -----------+-------------------------------------------
  0x00432F1C | cmp dword ptr [0x473bdc], 0
  0x00432F23 | push ebx
  0x00432F24 | push esi
  0x00432F25 | push edi
  0x00432F26 | mov ebx, 0x40000024
  0x00432F2B | je 0x432fcb                          <-- BRANCH
  0x00432FCB | pop edi
  0x00432FCC | mov eax, ebx
  0x00432FCE | pop esi
  0x00432FCF | pop ebx
  0x00432FD0 | ret                                  <-- RETURN

  Return: 0x40000024 (STATUS_NO_YIELD_PERFORMED)
```

**Multi-function analysis on real Win2K ntoskrnl.exe:**

| Function | Args | Return | Status | Instructions | API Calls |
|---|---|---|---|---|---|
| NtClose | Handle=0x10 | 0xC0000008 | STATUS_INVALID_HANDLE | 121 | HalRequestSoftwareInterrupt |
| NtQuerySystemInformation | Class=0, Buf=NULL | 0xC0000004 | STATUS_INFO_LENGTH_MISMATCH | 50 | (none) |
| NtQueryInformationProcess | Handle=-1, Class=0 | 0xC0000004 | STATUS_INFO_LENGTH_MISMATCH | 41 | (none) |
| NtYieldExecution | (none) | 0x40000024 | STATUS_NO_YIELD_PERFORMED | 11 | (none) |
| NtPowerInformation | Class=0, Buf=valid | 0x00000000 | STATUS_SUCCESS | 210 | HalRequestSoftwareInterrupt |
| NtPowerInformation | Class=2 | 0xC000000D | STATUS_INVALID_PARAMETER | 135 | HalRequestSoftwareInterrupt |

**Use case — verify your patch before deploying:**

1. Run the **original** Win2K function → get return values + API call pattern
2. Run **your patched** version of the same function → compare results
3. If both return the **same NTSTATUS** for the same inputs and call the **same APIs**, your patch integrates correctly with the kernel

### SSDT Resolver — Zero-Symbol Kernel Intelligence (NEW)

In ntoskrnl.exe, `Nt*` functions (NtCreateFile, NtPowerInformation, etc.) are **private** — they don't appear in the PE export table. Only `Zw*` wrappers are exported. Previously, you needed PDB/DBG symbols to find them.

The SSDT resolver finds them automatically:

1. Find the `Zw*` export (e.g., `ZwPowerInformation`) → read the stub: `mov eax, N` → syscall number
2. Scan the binary for `mov [KeServiceDescriptorTable], offset KiServiceTable` (the kernel init code)
3. Read `KiServiceTable[N]` → the actual `Nt*` function VA

All **248 private Nt kernel syscalls** are now resolvable — zero symbols required.

### Dual Symbol Loading (NEW)

The Behavior Analyzer (Tab 10) now supports **two separate symbol files**:

- **Symbols A** (Win2K) — loaded with blue clickable links
- **Symbols B** (ReactOS) — loaded with green clickable links

When comparing functions, click the blue link to view in DLL A or the green link to view in DLL B. No more confusion about which symbol set is active.

### Tabbed Output (IDA Pro-style)

Every analysis action in every tab now opens results in a **new closeable tab** instead of overwriting the previous output. This means:

- **No more lost results** — click "Disassemble" five times and you get five tabs, all accessible
- **Side-by-side comparison** — switch between tabs to compare different function analyses
- **Close tabs freely** — right-click a tab for Close / Close All Others / Close All, or middle-click to close
- **Auto-cleanup** — tabs auto-prune when you exceed 20 open tabs (oldest closed first)
- **Smart tab titles** — tabs show the function name and operation (e.g., "Disasm: NtCreateFile", "HEX: RtlInitUnicodeString")

### Deep Analyzer (Tab 13)

A full IDA Pro / Ghidra-style analysis engine that works **entirely without debug symbols**:

- **Discover ALL functions** — finds exported + internal functions via prologue scanning (`push ebp; mov ebp, esp`)
- **Function profiling** — calling convention, argument count, stack frame size, API calls, string references
- **Cross-reference maps** — who calls this function, what does it call, what APIs does it import
- **Porting dependency analysis** — shows exactly what needs to be ported for a function to work
- **Deep comparison** — compare function implementations across two PEs (hash, signature, code blocks, API differences)
- **Batch deep compare** — compare all shared exports with double-click to open side-by-side diff window
- **Right-click context menu** — on any discovered function: Profile, View Code, XRefs, Dependencies, Compare, Scan System32

### Symbol Loader

Load debug symbols from **6 formats** to enrich disassembly and analysis:

| Format | Source | Example |
|--------|--------|---------|
| MSVC .map | `link.exe /MAP` | `ntdll.map` |
| GCC .map | `ld -Map` | `kernel32.map` |
| IDA .map | File → Produce → MAP | `hal.map` |
| Simple .sym | `address<tab>name` per line | `symbols.sym` |
| PDB | Microsoft debug symbols | `ntdll.pdb` |
| DBG | COFF debug symbols | `ntoskrnl.dbg` |

When symbols are loaded and the **"Use symbols"** checkbox is checked:
- Disassembly shows **real function names** instead of `sub_XXXXX`
- Arguments and local variables are annotated in the output
- Call targets are resolved to named functions
- Cross-references use symbol names

### Decompiler Modes (Tab 11)

Three distinct output modes, like IDA Pro and Ghidra:

| Mode | Button | What You See |
|------|--------|-------------|
| **Pseudo-C** | 📄 Decompile Export | C-like pseudocode with kernel API recognition, NTSTATUS codes, IRP codes |
| **Assembly** | 🖥 Disassemble | Annotated x86 assembly with colored `call`/`ret`/`jmp` highlighting |
| **Hex Dump** | HEX Hex Dump | Raw bytes with address + hex + ASCII columns, color-coded: `CC`(int3)=red, `C3`(ret)=yellow, `E8`(call)=green |

### XRef Scanner (Tab 14)

Scan an entire directory for every PE file that imports or calls a given function:

- Enter a function name (e.g., `NtCreateFile`, `CreateFileW`)
- Click "Scan All PEs" — scans all `.dll`, `.sys`, `.exe`, `.drv`, `.cpl`, `.ocx`, `.scr` files
- Results grouped by PE file, showing: import source DLL, IAT address, reference type
- Essential for understanding which system components depend on a function before patching it

### Progress Dialogs

All long-running operations now show a **real-time progress dialog** with:
- Operation name (e.g., "Fingerprinting NtCreateFile...")
- Percentage bar (0–100%)
- Current item being processed
- Cancel button for graceful abort

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
| **Structures** | Dynamic PDB extraction — 309+ structures from real Win2K debug symbols | `structs --pdb` | Tab 4 |
| | Generate C header files (.h) for all extracted structures | `gen-headers --pdb` | Tab 4 |
| **DEF Files** | Auto-generate .def files from DLL exports | `gen-def` | Tab 6 |
| **Decompiler** | Decompile exported functions to C pseudocode | `decompile` | Tab 11 |
| | **Annotated x86 disassembly with color highlighting** | — | Tab 11 |
| | **Raw hex dump with CC/C3/E8 color coding** | — | Tab 11 |
| | Discover functions without symbols (prologue scanning) | `discover-functions` | Tab 11 |
| | Batch decompile all exports | `batch-decompile` | Tab 11 |
| **Behavior** | Function fingerprinting and API pattern detection | `behavior` | Tab 10 |
| | Disassemble exported functions | `disasm` | Tab 10 |
| | **Symbol-enhanced disassembly** (args, locals, call targets) | — | Tab 10 |
| | **Dual symbol loading** (Symbols A + Symbols B with color-coded links) | — | Tab 10 |
| | **SSDT resolver** (find all 248 private Nt* functions, no symbols) | Python API | Tab 10 |
| | **Kernel function emulator** (Unicorn x86 emulation + test scenarios) | Python API | Tab 10 |
| | **Scan all exports with progress tracking** | — | Tab 10 |
| | **Batch compare with real-time progress** | — | Tab 10 |
| **Deep Analysis** | **Discover ALL functions (exported + internal)** | — | Tab 13 |
| | **Function profiling (convention, args, APIs, strings)** | — | Tab 13 |
| | **Cross-reference maps (callers, callees, API imports)** | — | Tab 13 |
| | **Porting dependency analysis** | — | Tab 13 |
| | **Deep function comparison (hash, signature, blocks)** | — | Tab 13 |
| | **Batch deep compare with side-by-side diff window** | — | Tab 13 |
| **XRef Scanning** | **Scan directory for all callers of a function** | — | Tab 14 |
| | **Grouped results by PE file with IAT addresses** | — | Tab 14 |
| **Symbol Loading** | **Load .map / .pdb / .dbg / .sym symbol files** | — | Tab 10, 11, 13 |
| | **Merge symbols into function discovery and disassembly** | — | Tab 10, 13 |
| **Compat Analysis** | Deep compatibility analysis between two PE binaries | `compat-analyze` | Tab 12 |
| | Single PE compatibility profile | `compat-single` | Tab 12 |
| | Bugcheck code diagnosis with compat hints | `bugcheck` | Tab 12 |
| **PE Patching** | Quick Win2000 patch (version + syscalls) | `patch-pe --quick` | Tab 15 |
| | Patch sysenter stubs to int 0x2E | `patch-pe --syscalls` | Tab 15 |
| | Inject calling convention shims (stdcall↔fastcall) | `patch-pe --shim` | Tab 15 |
| | Rebase PE to new ImageBase with relocation fixups | `patch-pe --rebase` / `rebase` | Tab 15 |
| | Strip debug directory from PE | `patch-pe --strip-debug` | Tab 15 |
| | Grow section, add import, forward export | `patch-pe --grow-section/--add-import/--forward-export` | Tab 15 |
| | Inject raw code blob with 4-table fixups | `inject-blob` | — |
| | GenPatch: compile C source & inject into PE | `compile-inject` | — |
| | Full export table rebuild (add/forward/alias/hook) | Python API | — |
| | 5-stage KernelEx pipeline (PatchSet) | Python API | — |
| | Symbol map loading + symbol-aware patching | Python API | — |
| **PE Inspection** | Inspect all PE tables (EAT, IAT, relocs, sections) | `inspect-pe` | Tab 15 |
| | Hex dump at RVA | `hex-dump` | — |
| **Build** | Generate RosBE / MSVC / CMake build scripts | `build-script` | Tab 9 |
| | ReactOS source tree auto-patcher | — | Tab 8 |
| **Kernel Debugger** | **Live kernel-state debugger (multi-PE, breakpoints, stepping)** | Python API | Tab 16 |
| | **Cross-module IAT resolution and call tracing** | Python API | Tab 16 |
| | **Object inspector (EPROCESS, DRIVER_OBJECT, handle table)** | Python API | Tab 16 |
| | **Missing module detection and dependency resolver** | Python API | Tab 16 |
| **UBRT Engine** | **Universal binary rewriter — insert/delete/patch with auto-reference fixups** | Python API | Tab 17 |
| | **15-pass reference analysis (relocations, exports, imports, exceptions, TLS, resources, ...)** | Python API | Tab 17 |
| | **Multi-format: PE (32/64), ELF (RELA), Mach-O (fat/universal)** | Python API | Tab 17 |
| | **QEMU dynamic tracing — discover indirect call/jump targets** | Python API | Tab 17 |
| | **compact() — reclaim section padding (PE, ELF, Mach-O)** | Python API | Tab 17 |
| | **strip_signature() — remove PE Authenticode / Mach-O LC_CODE_SIGNATURE** | Python API | Tab 17 |
| | **Resource directory protection (.rsrc conflict detection)** | Python API | Tab 17 |
| **UI Features** | **Tabbed output — each action opens new closeable tab** | — | All tabs |
| | **Right-click / middle-click to close tabs** | — | All tabs |
| | **Progress dialogs with operation names + percentage** | — | Tab 10, 13 |
| | **Dark theme with syntax highlighting** | — | All tabs |

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
unicorn>=2.0.0      # x86 CPU emulator (kernel function emulator)
pyelftools>=0.29    # ELF binary parsing (UBRT ELF support)
tabulate>=0.9.0     # Table formatting for CLI output
colorama>=0.4.6     # Colored terminal output
```

All pure-Python except capstone and unicorn (have native C backends for speed).

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

The GUI is a standalone Python/Tkinter application with a dark theme and 17 tabs.

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
| 4 | NT Structures | Load PDB, extract 309+ structures live, filter, C header generation |
| 5 | PE Header / Scan | Full PE header dump, scan directories for PE files |
| 6 | DEF Generator | Auto-generate .def files from DLL exports |
| 7 | Syscall Patcher | Generate syscall headers in 4 styles |
| 8 | ROS Patcher | Auto-patch ReactOS source tree for Win2000 |
| 9 | Build Scripts | Generate RosBE/MSVC/CMake build scripts |
| 10 | Behavior Analyzer | Function fingerprinting, API patterns, symbol-enhanced disassembly |
| 11 | Decompiler | 3 modes: Pseudo-C / Assembly / Hex Dump, batch decompile, symbol loading |
| 12 | Compat Analyzer | Deep NT version compatibility detection, bugcheck diagnosis |
| 13 | Deep Analyzer | IDA Pro-level function discovery, profiling, XRefs, deep compare |
| 14 | XRef Scanner | Scan directories for all callers of a function |
| 15 | PE Patcher | Patch binaries: version, syscalls, calling conventions, rebase |
| 16 | Kernel Debugger | Live kernel-state debugger with breakpoints, stepping, register inspection |
| 17 | UBRT Engine | Universal binary rewriter — insert/delete/patch with automatic reference recalculation |

---

## Tabbed Output System

Every GUI tab uses a **tabbed output** system instead of a single text area. This is the most significant UI change in v3.1:

### How It Works

1. **Click any analysis button** (Disassemble, Decompile, Compare, etc.) → a **new tab** opens with the results
2. The previous results remain in their own tab — nothing is lost
3. Tab title shows the operation and function name: `Disasm: NtCreateFile`, `HEX: RtlInitUnicodeString`, `Compare: IoCallDriver`

### Managing Tabs

| Action | How |
|--------|-----|
| **Close one tab** | Middle-click the tab, or right-click → Close Tab |
| **Close all except active** | Right-click → Close All Others |
| **Close all tabs** | Right-click → Close All, or click the Clear button |
| **Switch between tabs** | Click the tab header |

### Auto-Pruning

When you open more than **20 tabs**, the oldest tab is automatically closed to prevent memory buildup. You can always re-run any analysis to recreate a tab.

### Example Workflow

```
1. Load ntdll.dll in Behavior Analyzer (Tab 10)
2. Disassemble NtCreateFile     → Tab opens: "Disasm: NtCreateFile"
3. Disassemble NtOpenFile       → Tab opens: "Disasm: NtOpenFile"
4. Compare NtCreateFile         → Tab opens: "Compare: NtCreateFile"
5. Detect patterns NtCreateFile → Tab opens: "Patterns: NtCreateFile"
   Now you have 4 tabs visible — click any to review, middle-click to close
```

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
- Copilot can help you write patches based on the `compat-analyze` output

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
python win2k_analyzer.py structs --pdb <pdb_path> [name] [--c-header]
```
Extracts and displays Win2000 kernel structure layouts **directly from a PDB debug symbol file**. Pass the name of any structure to view its field list, or omit the name to list all available structures.

```bash
python win2k_analyzer.py structs --pdb ntoskrnl.pdb PEB --c-header   # C header for PEB
python win2k_analyzer.py structs --pdb ntoskrnl.pdb                   # List all 309+ structures
python win2k_analyzer.py structs --pdb ntoskrnl.pdb EPROCESS          # View EPROCESS layout
```

> **Required:** You need the Win2K SP4 debug symbols (`ntoskrnl.pdb`, available from the Windows 2000 SP4 DDK/debug package or Microsoft Symbol Server). PDB 2.0 (`JG`) and PDB 7.0 (`DS`) formats are both supported natively.

#### `gen-headers` — Generate All C Headers
```bash
python win2k_analyzer.py gen-headers --pdb <pdb_path> <output_dir>
```
Extracts every structure and union from the PDB file and generates a `.h` file for each one in `<output_dir>`.

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

## Patching NT System Internals (.sys / Kernel-Mode Binaries)

The Win2K Analyzer fully supports patching **kernel-mode system binaries** — the core NT executables and drivers that make up the Windows 2000 kernel. All PE Patcher commands and the GUI (Tab 13) work on `.sys`, `.exe`, `.dll` kernel files equally.

### Target System Files

| File | Role | Common Patching Scenarios |
|---|---|---|
| `ntoskrnl.exe` | NT kernel executive | Version stamp, syscall mechanism (`sysenter` → `int 0x2E`), structure layout fixes |
| `hal.dll` | Hardware Abstraction Layer | Calling convention shims (stdcall↔fastcall), HalpVector macro fix (`shl 8` → `shl 4`), HAL dispatch table entries |
| `win32k.sys` | Win32 kernel subsystem | Syscall stubs, version stamp, export forwarding |
| `ntdll.dll` | NT user→kernel transition layer | Syscall stub patching (`sysenter` → `int 0x2E`), version stamp |
| `ACPI.sys` / `pci.sys` | Bus / power drivers | Rebase, calling convention shims, version stamp |
| Any `.sys` driver | Third-party / ReactOS drivers | Full PE patching pipeline |

### Step-by-Step: Patching a ReactOS Kernel Binary for Win2000

#### 1. Analyze compatibility first

Before patching, run `compat-analyze` to see exactly what differs between your Win2000 original and the ReactOS replacement:

```bash
# Compare ntoskrnl.exe
python win2k_analyzer.py compat-analyze C:\win2k\ntoskrnl.exe C:\reactos\ntoskrnl.exe

# Compare HAL
python win2k_analyzer.py compat-analyze C:\win2k\hal.dll C:\reactos\hal.dll --label-a "Win2000 HAL" --label-b "ReactOS HAL"

# Compare win32k.sys
python win2k_analyzer.py compat-analyze C:\win2k\win32k.sys C:\reactos\win32k.sys
```

The report will flag:
- **Version mismatch** (NT 5.1 vs 5.0)
- **Syscall mechanism** (`sysenter`/`syscall` vs `int 0x2E`)
- **Calling convention changes** (functions that switched from stdcall to fastcall)
- **Missing/added exports**
- **HalpVector bit-shift differences** (`shl 4` on Win2000, `shl 8` on XP)
- **HAL dispatch table** entries removed in XP

#### 2. Inspect the PE structure

```bash
# View all internal tables
python win2k_analyzer.py inspect-pe C:\reactos\ntoskrnl.exe

# Check exports specifically
python win2k_analyzer.py inspect-pe C:\reactos\hal.dll -t exports

# Verify relocations (critical for kernel rebasing)
python win2k_analyzer.py inspect-pe C:\reactos\ACPI.sys -t relocations
```

#### 3. Quick-patch for version + syscalls

The `--quick` flag handles the two most common issues in one shot — sets PE version to 5.0 (NT 2000) and patches `sysenter` → `int 0x2E`:

```bash
python win2k_analyzer.py patch-pe --quick C:\reactos\ntoskrnl.exe -o ntoskrnl_w2k.exe
python win2k_analyzer.py patch-pe --quick C:\reactos\win32k.sys -o win32k_w2k.sys
python win2k_analyzer.py patch-pe --quick C:\reactos\ntdll.dll -o ntdll_w2k.dll
```

#### 4. Fix calling convention differences (HAL / kernel functions)

Several HAL I/O functions changed from `stdcall` (Win2000) to `fastcall` (XP/ReactOS). If a ReactOS driver calls these with the wrong convention, it will corrupt the stack and bugcheck. Apply shims:

```bash
# Fix IoReadPartitionTable: ReactOS uses fastcall, Win2000 expects stdcall
python win2k_analyzer.py patch-pe C:\reactos\hal.dll --shim "IoReadPartitionTable,fastcall,stdcall,4"

# Fix all four HAL I/O partition functions at once
python win2k_analyzer.py patch-pe C:\reactos\hal.dll \
  --shim "IoAssignDriveLetters,fastcall,stdcall,4" \
  --shim "IoReadPartitionTable,fastcall,stdcall,4" \
  --shim "IoSetPartitionInformation,fastcall,stdcall,4" \
  --shim "IoWritePartitionTable,fastcall,stdcall,4" \
  -o hal_w2k.dll

# Fix IRQL spinlock fastcall wrappers
python win2k_analyzer.py patch-pe C:\reactos\ntoskrnl.exe \
  --shim "KfAcquireSpinLock,fastcall,stdcall,1" \
  --shim "KfReleaseSpinLock,fastcall,stdcall,2" \
  -o ntoskrnl_w2k.exe
```

**Calling convention changes dynamically detected by our tool:**

| Function | Win2000 (5.0) | XP/ReactOS (5.1) |
|---|---|---|
| `IoAssignDriveLetters` | stdcall | fastcall |
| `IoReadPartitionTable` | stdcall | fastcall |
| `IoSetPartitionInformation` | stdcall | fastcall |
| `IoWritePartitionTable` | stdcall | fastcall |
| `IofCallDriver` | stdcall | fastcall |
| `IofCompleteRequest` | stdcall | fastcall |
| `KfAcquireSpinLock` | stdcall | fastcall |
| `KfReleaseSpinLock` | stdcall | fastcall |
| `KfRaiseIrql` | stdcall | fastcall |
| `KfLowerIrql` | stdcall | fastcall |

#### 5. Rebase kernel drivers

Windows 2000 loads kernel images at specific base addresses. If a ReactOS driver uses a different ImageBase, rebase it:

```bash
# Rebase ntoskrnl to Win2000's expected address
python win2k_analyzer.py rebase C:\reactos\ntoskrnl.exe 0x80400000 -o ntoskrnl_w2k.exe

# Rebase hal.dll
python win2k_analyzer.py rebase C:\reactos\hal.dll 0x80010000 -o hal_w2k.dll

# Rebase a .sys driver
python win2k_analyzer.py rebase C:\reactos\ACPI.sys 0x80000000 -o ACPI_w2k.sys
```

#### 6. Inject code blobs for kernel-mode hooks

For advanced fixes (HalpVector macro, IDT dispatch routing, custom shims), compile and inject machine code:

```bash
# Compile a C shim and inject into hal.dll
python win2k_analyzer.py compile-inject C:\reactos\hal.dll halpvector_fix.c --hook "HalpVectorToIRQL=0x00"

# Inject a pre-built binary blob into a .sys driver
python win2k_analyzer.py inject-blob C:\reactos\ACPI.sys acpi_shim.bin --hook "AcpiInitialize=0x00"
```

#### 7. Verify patches

```bash
# Hex dump to confirm int 0x2E bytes (CD 2E) replaced sysenter (0F 34)
python win2k_analyzer.py hex-dump ntoskrnl_w2k.exe 0x1000 -l 0x100

# Re-inspect the patched PE
python win2k_analyzer.py inspect-pe ntoskrnl_w2k.exe

# Run compat-analyze on patched vs original Win2000 binary
python win2k_analyzer.py compat-analyze C:\win2k\ntoskrnl.exe ntoskrnl_w2k.exe
```

#### Full pipeline example — patching ReactOS ntoskrnl.exe for Windows 2000

```bash
# All-in-one: version 5.0 + syscalls + spinlock shims + rebase + strip debug
python win2k_analyzer.py patch-pe C:\reactos\ntoskrnl.exe \
  --version 5.0 \
  --syscalls \
  --shim "KfAcquireSpinLock,fastcall,stdcall,1" \
  --shim "KfReleaseSpinLock,fastcall,stdcall,2" \
  --rebase 0x80400000 \
  --strip-debug \
  -o ntoskrnl_w2k.exe
```

### Known Kernel-Mode Differences Detected

Our compatibility analyzer automatically detects these NT 5.0 vs 5.1 kernel-mode issues:

| Category | What It Detects |
|---|---|
| **Syscall mechanism** | `sysenter`/`syscall` (XP) vs `int 0x2E` (Win2000) |
| **Calling conventions** | 10 HAL/kernel functions that changed stdcall → fastcall |
| **HalpVector macro** | Bit-shift `shl 4` (Win2000) vs `shl 8` (XP) for IDT vector calc |
| **HAL dispatch table** | Entries removed in XP (`HalIoAssignDriveLetters`, etc.) |
| **IDT dispatch routing** | Direct vector vs `HalVectorToIDTEntry()` translation |
| **Interrupt affinity** | Direct bitmask (2000) vs `HalpVectorToNode` NUMA table (XP) |
| **Structure layout** | `KINTERRUPT` size change (0x1E8 → 0x1F0), field offsets |
| **PE version stamp** | MajorOperatingSystemVersion / MajorSubsystemVersion |

> **⚠️ WARNING:** Patching kernel-mode binaries is inherently dangerous. Always keep backups of your original system files. Test patched drivers in a virtual machine before deploying to real hardware. A bad kernel patch will cause a blue screen (BSOD). Use the `bugcheck` command to decode any resulting stop codes:
> ```bash
> python win2k_analyzer.py bugcheck 0x7F    # UNEXPECTED_KERNEL_MODE_TRAP
> python win2k_analyzer.py bugcheck 0x0A    # IRQL_NOT_LESS_OR_EQUAL
> python win2k_analyzer.py bugcheck 0x1E    # KMODE_EXCEPTION_NOT_HANDLED
> ```

---

## Kernel Debugger — Live Kernel State

The kernel debugger builds a complete NT kernel environment from real Win2K System32 files:

```python
from nt_analyzer.kernel_debugger import *

# One-shot convenience
report = quick_debug(r"C:\2kDEBUG\system32", "NtPowerInformation",
                     args=[0, 0, 0, 0x1000, 0x1000])
print(report)
```

Output:
```
════════════════════════════════════════════════════════════════════════
  KERNEL ENVIRONMENT STATUS
════════════════════════════════════════════════════════════════════════
  System Root: C:\2kDEBUG\system32
  Modules Loaded: 2
  Available Files: 2142
  KPCR: 0xFFDFF000
  System EPROCESS: 0x81340000

  Loaded Modules:
  ntoskrnl.exe   base=0x00400000  exports=1258  unresolved=10
  hal.dll        base=0x80010000  exports=95    unresolved=0

════════════════════════════════════════════════════════════════════════
  LIVE KERNEL DEBUG REPORT
  Function: NtPowerInformation
  Return: 0x00000000 (STATUS_SUCCESS)
  Instructions: 276
  Time: 0.011s
════════════════════════════════════════════════════════════════════════
```

**Interactive debugging:**
```python
env = KernelEnvironment(r"C:\2kDEBUG\system32")
env.load_core()                        # ntoskrnl + hal
env.auto_load_dependencies()           # pull in what's needed

dbg = DebugSession(env)
dbg.set_breakpoint("NtClose")          # by name
dbg.set_breakpoint(0x004DC97E)         # by address

# Run with break at entry
result = dbg.run("NtPowerInformation", args=[0, 0, 0, 0x1000, 0x1000],
                 stop_at_entry=True)

# Step through
while dbg.state == DebugState.PAUSED:
    regs = dbg.inspect_registers()     # EIP, ESP, EAX, ...
    stack = dbg.get_call_stack()       # EBP chain walk
    print(f"EIP=0x{regs['eip']:08X} ({regs['eip_name']})")
    dbg.step()

# Or continue to next breakpoint
result = dbg.continue_run()
```

**What's built in memory:**
- KPCR + KPRCB at 0xFFDFF000 (GDT with FS segment for kernel FS:[offset] access)
- KUSER_SHARED_DATA at 0x7FFE0000 (NtMajorVersion=5, NtMinorVersion=0, 512MB RAM)
- System EPROCESS (PID 4, ImageFileName="System"), ETHREAD, idle thread
- Handle table with pseudo-handles (-1=process, -2=thread)
- Full GDT: null + CS + DS + FS→KPCR

### Comprehensive NtPowerInformation Debug Test

A full 13-scenario debug test is included in [`ntpower_debug_results.txt`](ntpower_debug_results.txt) — generated by [`test_ntpower_debug.py`](test_ntpower_debug.py). Excerpts:

**All 37 power information classes tested:**
```
  Class  Name                                     Return           Status                          Insns
  0      SystemPowerPolicyAc                      0x00000000      STATUS_SUCCESS                    276
  1      SystemPowerPolicyDc                      0x00000000      STATUS_SUCCESS                    276
  2      VerifySystemPolicies                     0xC000000D      STATUS_INVALID_PARAMETER          201
  4      SystemPowerStateHandler                  0x00000000      STATUS_SUCCESS                    333
  8      SystemBatteryState                       0x00000000      STATUS_SUCCESS                    173
  11     ProcessorPowerPolicyDc                   0x00000000      STATUS_SUCCESS                   3612
  6      SystemPowerPolicyOld                     0x0000009F      STATUS_POWER_STATE_INVALID      47591
  255    InvalidClass_0xFF                        0x0000009F      STATUS_POWER_STATE_INVALID      47586
```

**Buffer size boundary detection (class 0 needs ≥0x100):**
```
  BufSize      Return           Status
  1            0xC0000023      STATUS_BUFFER_TOO_SMALL
  0x80         0xC0000023      STATUS_BUFFER_TOO_SMALL
  0x100        0x00000000      STATUS_SUCCESS
  0x1000       0x00000000      STATUS_SUCCESS
```

**Breakpoint + stepping through kernel code:**
```
  Step  0: EIP=0x004E1536  ntoskrnl.exe!PoShutdownBugCheck+0x13E0
  Step  5: EIP=0x004152E6  ntoskrnl.exe!ExAcquireResourceExclusiveLite
  Step 16: EIP=0x800134F0  hal.dll!KfAcquireSpinLock
  Step 23: EIP=0x00415303  ntoskrnl.exe!ExAcquireResourceExclusiveLite+0x1D
```

**Cross-module call analysis (87.5% ntoskrnl, 12.5% hal):**
```
  ntoskrnl.exe --> hal.dll!KfAcquireSpinLock (0x800134F0)
  hal.dll --> ntoskrnl.exe!ExAcquireResourceExclusiveLite+0x1D (0x00415303)
  ntoskrnl.exe --> hal.dll!KfReleaseSpinLock (0x800135C0)
  hal.dll --> ntoskrnl.exe!ExReleaseResourceLite+0x21 (0x00415769)
```

**Error detection with spin loop events:**
```
  Test: Invalid class 0xFF
    Return: 0x0000009F (STATUS_POWER_STATE_INVALID)
    Instructions: 47586
    Events (1): spin_loop
      [spin_loop] Spin loop at 0x0046CF4C (501 hits)
```

---

## GUI Tab Reference (All 17 Tabs)

### Tab 1: Exports / Imports
- Browse to any PE file (.dll, .sys, .exe, .cpl)
- Click **Analyze Exports** or **Analyze Imports**
- Each analysis opens a **new output tab** with results
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
- Click **Load PDB** and browse to a Win2K debug symbol file (e.g., `ntoskrnl.pdb`)
- All structures and unions are extracted live from the PDB — 309+ structures from the Win2K SP4 ntoskrnl symbols
- Type in the **Filter** box to search by structure name in real time
- Select a structure from the dropdown to view its field names, offsets, sizes, and types
- **Generate C Header** — generate a `.h` file for the selected structure
- **Export All Headers** — generate `.h` files for every extracted structure into a chosen directory
- Supports both PDB 2.0 (JG/MSF, Win2K DDK format) and PDB 7.0 (DS/MSF, modern format)

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
- **Symbol-enhanced disassembly** — load .map/.pdb/.dbg/.sym files, check "Use symbols", and disassembly shows real function names, arguments, locals
- **7 analysis actions**, each opens a new tab:
  - **Disassemble** — x86 disassembly (symbol-enhanced when checkbox is checked)
  - **Compare Function** — compare same function between two PEs
  - **Batch Compare** — compare all shared exports with progress dialog
  - **Detect Patterns** — find API call sequences and syscall patterns
  - **Scan All Exports** — fingerprint every export with real-time progress
  - **Control Flow** — analyze branch structure and code blocks
  - **Resolve Unknown** — identify unknown call targets
- **Clickable function names** — click any function name in output to jump to its analysis
- **History navigation** — Back/Forward buttons to revisit previous analyses
- **Progress dialogs** — all operations show current function name and percentage

### Tab 11: Decompiler
- **Three output modes** for any exported function:
  - 📄 **Decompile Export** — C pseudocode with kernel API recognition, NTSTATUS codes, IRP major codes, pool tags, IOCTL decoding
  - 🖥 **Disassemble** — Annotated x86 assembly with color-coded `call` (green), `ret` (yellow), `jmp` (peach), comments (gray)
  - HEX **Hex Dump** — Raw bytes displayed as: virtual address | hex pairs | ASCII. Color-highlights: `CC`(int3)=red, `C3`(ret)=yellow, `E8`(call)=green. Stops at ret/int3 boundary.
- Enter function name or RVA (e.g., `0x4AE10`)
- **Discover Functions** — finds functions without symbols by scanning for prologues
- **Batch Decompile** — decompile all exports at once
- **Symbol file loading** — browse .map/.pdb/.dbg/.sym to enrich output
- Each operation opens a **new tab** with smart title (e.g., "ASM: NtCreateFile", "HEX: RtlInitUnicodeString")

### Tab 12: Compat Analyzer
- Load two PE files for deep compatibility analysis
- Set version labels (e.g., "Win2000" and "ReactOS")
- **Full Compat Analysis** — runs all detection engines
- **Analyze Single PE** — compatibility profile for one binary
- **Bugcheck Lookup** — enter a BSOD code, get compat-specific diagnosis
- Color-coded output: red for critical, yellow for warnings

### Tab 13: Deep Analyzer (NEW)
The most powerful analysis tab — combines IDA Pro-style function discovery with deep binary comparison:

- **Discover All Functions** — scans prologue patterns (`push ebp; mov ebp, esp`) to find ALL functions: exported AND internal. Lists them with addresses, sizes, calling conventions.
- **Profile** — detailed metadata for selected function: calling convention, argument count, stack frame size, API calls, string references, struct offset accesses
- **XRefs** — cross-reference map: inbound callers, outbound calls, API imports used
- **Code** — full annotated disassembly of selected function
- **Dependencies** — porting dependency analysis: what functions, APIs, and structures need to be available for this function to work
- **Statistics** — PE-wide stats: hottest functions (most called), largest functions, most API-heavy, calling convention breakdown
- **Deep Compare** — compare a single function between two PE files: hash match, signature similarity, code block differences, API differences, string differences
- **Batch Deep Compare** — compare ALL shared exports between two PEs. **Double-click any row** to open a side-by-side diff window
- **Right-click context menu** on any discovered function:
  - Select function, Profile, View Code, Show XRefs
  - Porting Dependencies, Analyze Behavior, Control Flow Analysis
  - Decompile to C, Deep Compare with File B
  - Scan System32 for Callers (finds all PEs that import this function)

### Tab 14: XRef Scanner (NEW)
System-wide cross-reference scanner:

- Enter a function name (e.g., `NtCreateFile`, `CreateFileW`, `ExAllocatePool`)
- Browse to a directory (e.g., `C:\WINNT\system32`)
- Click **Scan All PEs** — scans every `.dll`, `.sys`, `.exe`, `.drv`, `.cpl`, `.ocx`, `.scr` file in the directory
- Results grouped by PE file:
  ```
  ── kernel32.dll ──
    Import: ntdll.dll!NtCreateFile  IAT: 0x7C801234  Type: IAT_IMPORT
  ── advapi32.dll ──
    Import: ntdll.dll!NtCreateFile  IAT: 0x77DA5678  Type: IAT_IMPORT
  Total: 47 PE files reference NtCreateFile
  ```
- Essential before patching: know which system components depend on a function

### Tab 15: PE Patcher (KernelEx Ultimate Edition)
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

### Tab 16: 🐞 Kernel Debugger (NEW)
Live kernel-state debugger — a portable WinDbg built entirely in Python:

- **System32 folder picker** — point to any Win2K System32 directory
- **Load Core** — loads ntoskrnl.exe + hal.dll into shared Unicorn x86 address space
- **Load Dependencies** — auto-resolves imported DLLs across up to 3 dependency levels
- **Load Symbols** — browse .map/.pdb/.dbg/.sym files for enhanced function names
- **Function + Args** — enter function name and arguments (supports hex: `0x1000`)
- **Run** — execute function to completion, get NTSTATUS return + instruction count
- **Run+Break at Entry** — pause at first instruction, enables stepping
- **Step** — execute one instruction at a time, inspect state after each
- **Continue** — resume from breakpoint until next break or completion
- **Set Breakpoint** — by function name (`NtClose`) or address (`0x004DC97E`)
- **Registers** — view EAX/EBX/ECX/EDX/ESI/EDI/EBP/ESP/EIP/EFLAGS
- **Call Stack** — EBP chain walk with module!function annotation
- **Stack Memory** — hex dump of stack from ESP upward with symbol lookup
- **Handle Table** — walk kernel object handle table
- **Env Info** — full environment status (modules, exports, unresolved imports)
- **Instruction trace** — optional per-instruction log with address + disassembly
- **User/Kernel mode toggle** — set PreviousMode for testing different call paths

### Tab 17: UBRT Engine (NEW)
Universal Binary Rewriting Tool — treat any binary like a text file. Insert, delete, or patch bytes anywhere and have every reference in the file automatically recalculated:

- **Browse to any PE, ELF, or Mach-O binary** — format is auto-detected
- **Analyze References** — runs 15 analysis passes to discover all relocatable references (relocations, exports, imports, exception handlers, TLS callbacks, debug directories, resource RVAs, load config pointers, delay imports, bound imports, indirect calls/jumps, section-relative data, cross-section refs)
- **Results display** — shows reference count by type, broken down by analysis pass
- **Insert Bytes** — insert N bytes at any RVA/offset; all references after the insertion point are shifted forward automatically
- **Delete Bytes** — remove N bytes at any RVA/offset; all references shift backward
- **Patch Bytes** — overwrite bytes at any offset without shifting
- **compact()** — reclaim trailing zero padding from sections to shrink the binary
- **strip_signature()** — remove code signatures (PE Authenticode / Mach-O LC_CODE_SIGNATURE) so modified binaries don't trigger verification failures
- **QEMU Trace** — load a QEMU `-d exec` trace log to discover indirect call/jump targets; merged as first-class references
- **Mach-O fat binary support** — extract thin binaries from fat/universal Mach-O files; fat header offsets are automatically updated when an arch is modified
- **Resource protection** — warns when a shift operation falls inside `.rsrc` to prevent corruption of the resource tree's internal relative offsets
- **Progress dialogs** — all long-running operations show real-time progress with percentage and cancel button
- **Tabbed output** — each analysis opens in a new closeable tab

---

## UBRT Engine — Universal Binary Rewriting

The UBRT Engine (Tab 17, `nt_analyzer/ubrt_engine.py`) is a **universal binary shift engine** that lets you insert, delete, or patch bytes at arbitrary locations in PE, ELF, and Mach-O binaries while automatically recalculating every internal reference. Think of it as `sed` for compiled binaries.

### Why UBRT?

Traditional binary patching tools let you overwrite bytes in place, but they can't **insert** or **delete** — because adding even a single byte shifts every address after it, breaking hundreds of thousands of cross-references. UBRT solves this by:

1. **Analyzing** the entire binary to discover all relocatable references (15 analysis passes)
2. **Tracking** every reference's file offset and target
3. **Shifting** all affected references when bytes are inserted or deleted
4. **Updating** all format-specific headers (section tables, program headers, load commands, etc.)

### Supported Formats

| Format | Reference Passes | Shift Engine | compact() | strip_signature() |
|--------|-----------------|--------------|-----------|-------------------|
| **PE** (32/64-bit) | 15 passes — relocations, EAT, IAT, exceptions, TLS, debug, resources, load config, delay imports, bound imports, indirect calls/jumps, section-relative, cross-section, QEMU trace | Full header update (sections, data directories, Optional header sizes) | Section padding reclamation | Zeroes Security DD, truncates cert table, zeroes checksum |
| **ELF** | Section headers, program headers, RELA addend correction | Section/program header offset + size updates, SHT offset update | Section padding reclamation with alignment | — |
| **Mach-O** | Load commands, segments, sections | Segment/section size updates via load commands | Segment filesize/vmsize reclamation | Removes LC_CODE_SIGNATURE load command + blob |
| **Mach-O Fat** | Per-arch (delegates to thin Mach-O engine) | Fat header arch offset shifting for all subsequent architectures | Per-arch | Per-arch |

### 15 Reference Analysis Passes (PE)

| # | Pass | What it finds | Example |
|---|------|--------------|---------|
| 1 | Base relocations | `.reloc` entries — absolute address fixups | Every `IMAGE_BASE_RELOCATION` entry |
| 2 | Export address table | RVAs in the EAT pointing to function bodies | `NtCreateFile → RVA 0x4AE10` |
| 3 | Import thunks | IAT/ILT entries pointing to `IMAGE_IMPORT_BY_NAME` | `kernel32.dll!CreateFileW` |
| 4 | Exception handlers | `.pdata` function table entries (RVAs to handlers) | SEH unwind entries |
| 5 | TLS callbacks | TLS directory + callback array RVAs | Thread-local storage init |
| 6 | Debug directory | Debug data RVAs (CodeView, MISC) | PDB path pointer |
| 7 | Resource directory | Resource tree node RVAs (directories + data entries) | Icons, version info, manifests |
| 8 | Load config | Lock prefix table, SE handler table, guard CF table | Security cookie pointer |
| 9 | Delay imports | Delay-load IAT/ILT/DLL name RVAs | `delayimp:advapi32.dll` |
| 10 | Bound imports | Bound import descriptor offsets | Pre-resolved import bindings |
| 11 | Indirect calls | `call [mem]` through absolute memory addresses | `call [0x77F81234]` |
| 12 | Indirect jumps | `jmp [mem]` through absolute memory addresses | `jmp [0x77F81238]` |
| 13 | Section-relative | Data references relative to section bases | Static data pointers |
| 14 | Cross-section | References between different PE sections | `.text → .data` pointers |
| 15 | QEMU trace | Dynamic targets from `-d exec` execution traces | Runtime indirect targets |

### Python API

```python
from nt_analyzer.ubrt_engine import UBRTEngine

# Load any binary
engine = UBRTEngine("ntoskrnl.exe")

# Analyze all references
refs = engine.analyze()
print(f"Found {len(refs)} references")
# → Found 109512 references

# Insert 16 bytes at RVA 0x1000
engine.insert_bytes(rva=0x1000, count=16)

# Delete 8 bytes at RVA 0x2000
engine.delete_bytes(rva=0x2000, count=8)

# Patch bytes at an offset (no shift)
engine.patch_bytes(offset=0x400, data=b'\x90\x90\x90\x90')

# Reclaim section padding
engine.compact()

# Strip code signatures before distribution
engine.strip_signature()

# Save the modified binary
engine.save("ntoskrnl_modified.exe")
```

### QEMU Dynamic Tracing

Static analysis can't resolve indirect calls (`call eax`, `call [vtable+0x10]`) because the target depends on runtime state. UBRT solves this by parsing QEMU execution traces:

```bash
# 1. Run the binary under QEMU with execution tracing
qemu-system-i386 -d exec -D trace.log -kernel ntoskrnl.exe

# 2. Load the trace into UBRT
engine = UBRTEngine("ntoskrnl.exe")
engine.merge_trace_coverage("trace.log")

# 3. Now analyze — QEMU targets are included as first-class refs
refs = engine.analyze()
# Indirect call targets from the trace are now tracked by the shift engine
```

### Mach-O Fat Binary Support

```python
from nt_analyzer.ubrt_engine import UBRTEngine

# Extract a thin binary from a fat/universal Mach-O
engine = UBRTEngine("libsystem.dylib")
thin_data = engine.extract_thin_macho(cpu_type=0x0C)  # ARM

# When you modify one arch in a fat binary, UBRT automatically
# shifts the offsets of all subsequent architectures in the fat header
```

### Performance

On a real Windows 2000 SP4 debug ntoskrnl.exe (1.6 MB):
- **Reference analysis:** 109,512 references discovered across 15 passes
- **Breakdown:** 54 indirect calls through memory, 14 resource RVAs, 2 indirect jumps, plus relocations, exports, imports, exceptions, etc.

---

## Deep Analyzer — IDA Pro-Level Analysis Without Symbols

The Deep Analyzer (Tab 13) provides the most comprehensive binary analysis available in the tool, comparable to IDA Pro and Ghidra but fully automated and scriptable.

### How to Use: Discover All Functions

1. Open **Tab 13 (Deep Analyzer)**
2. Browse to any PE file (e.g., `C:\WINNT\system32\ntdll.dll`)
3. Click **Discover All Functions**
4. The analyzer scans the entire code section for function prologues (`push ebp; mov ebp, esp` and variations)
5. Results show: all exported functions + all discovered internal functions, each with:
   - Virtual Address (VA) and Relative Virtual Address (RVA)
   - Size in bytes
   - Detected calling convention (stdcall, cdecl, fastcall, thiscall)
   - Whether it's an export or internal function

### How to Use: Profile a Function

1. After discovering functions, select one from the list
2. Click **Profile** (or right-click → Profile)
3. A new tab opens showing:
   ```
   ═══ Function Profile: NtCreateFile ═══
   Address:    0x77F81234 (RVA: 0x00001234)
   Size:       156 bytes
   Convention: stdcall
   Arguments:  11 (44 bytes)
   Stack frame: 64 bytes
   
   API calls:
     → RtlInitUnicodeString (ntdll.dll)
     → ObOpenObjectByName
     → IoCreateFile
   
   String references:
     "\\Device\\%s"
     "NtCreateFile"
   
   Struct accesses:
     [ebp+0x08] — Arg1 (FileHandle)
     [ebp+0x0C] — Arg2 (DesiredAccess)
   ```

### How to Use: Cross-References

1. Select a function, click **XRefs** (or right-click → Show XRefs)
2. Shows three sections:
   - **Inbound callers** — which functions call this one
   - **Outbound calls** — which functions this one calls
   - **API imports** — which DLL APIs this function uses

### How to Use: Deep Compare

1. Load File A (e.g., Win2000 ntdll.dll) in the main path
2. Load File B (e.g., ReactOS ntdll.dll) in the second path
3. Select a function, click **Deep Compare** (or right-click → Deep Compare with File B)
4. Results show:
   - Hash match (identical / different)
   - Signature similarity percentage
   - Code block structure differences
   - API call differences (added, removed, changed)
   - String reference differences

### How to Use: Batch Deep Compare

1. Load both files, click **Batch Deep Compare**
2. All shared exports are compared, showing a summary table
3. **Double-click any row** to open a **side-by-side diff window** showing the full code comparison

### How to Use: Right-Click Context Menu

Right-click any function in the discovered list for quick access:
- **Select function** → puts name in the function entry box
- **Profile** / **View Code** / **Show XRefs** / **Porting Dependencies**
- **Analyze Behavior** / **Control Flow Analysis** / **Decompile to C**
- **Deep Compare with File B**
- **Scan System32 for Callers** — finds all PEs in System32 that import this function

---

## Symbol Loader — Enrich Disassembly With Debug Info

The Symbol Loader lets you load debug symbols from multiple sources to significantly improve analysis quality.

### Supported Symbol Formats

| Format | How to Get It | File Extension |
|--------|--------------|----------------|
| **MSVC Map** | Compile with `link.exe /MAP` | `.map` |
| **GCC Map** | Link with `ld -Map=output.map` | `.map` |
| **IDA Pro Map** | File → Produce File → Create MAP file | `.map` |
| **Simple Symbols** | Manual: one `address<tab>name` per line | `.sym` |
| **PDB** | From Microsoft Symbol Server or local build | `.pdb` |
| **DBG** | From COFF debug builds | `.dbg` |

### How to Load Symbols in Behavior Analyzer (Tab 10)

1. In **Tab 10 (Behavior Analyzer)**, click **Browse** next to the Symbol file field
2. Select your `.map`, `.pdb`, `.dbg`, or `.sym` file
3. Check the **☑ Use symbols in disassembly** checkbox
4. Now click **Disassemble** — the output will show:
   - Real function names instead of `sub_XXXXX` addresses
   - Argument names and local variable annotations
   - Named call targets instead of raw addresses
   - `(with symbols)` indicator in the status line

### How to Load Symbols in Decompiler (Tab 11)

1. In **Tab 11 (Decompiler)**, browse to a symbol file using the symbol picker
2. Decompilation and disassembly will use the loaded symbols for function naming

### Without Symbols (Default)

If no symbols are loaded, the analyzer still works using:
- Export table names (for exported functions)
- Prologue-based discovery (for internal functions — named as `sub_XXXXXXXX`)
- Heuristic calling convention detection
- API call pattern matching

---

## Decompiler Modes — Pseudo-C, Assembly, Hex Dump

The Decompiler tab (Tab 11) offers three distinct views of any function, inspired by IDA Pro and Ghidra.

### Mode 1: Pseudo-C (📄 Decompile Export)

Converts x86 machine code to readable C-like pseudocode:

```c
// Decompiled: NtCreateFile
// Address: 0x77F81234 | Size: 156 bytes | Convention: stdcall

NTSTATUS __stdcall NtCreateFile(
    PHANDLE FileHandle,          /* [ebp+0x08] */
    ACCESS_MASK DesiredAccess,   /* [ebp+0x0C] */
    POBJECT_ATTRIBUTES ObjectAttributes  /* [ebp+0x10] */
)
{
    NTSTATUS status;
    
    status = ObOpenObjectByName(ObjectAttributes, ...);
    if (status < 0) {    // NT_ERROR(status)
        return status;   // STATUS_UNSUCCESSFUL
    }
    IoCreateFile(FileHandle, DesiredAccess, ...);
    return STATUS_SUCCESS;  // 0x00000000
}
```

**Recognized patterns:** NTSTATUS codes, IRP major codes (IRP_MJ_CREATE etc.), kernel APIs (80+), pool tags, IOCTL codes, device types, IRQL levels.

### Mode 2: Assembly (🖥 Disassemble)

Annotated x86 disassembly with color-coded instructions:

```asm
; NtCreateFile
; Address: 0x77F81234 | Size: 156 bytes

77F81234:  push    ebp                    ; → Function prologue
77F81235:  mov     ebp, esp
77F81237:  sub     esp, 0x20
77F8123A:  push    esi
77F8123B:  push    edi
77F8123C:  mov     esi, [ebp+0x10]        ; ObjectAttributes
77F8123F:  call    ObOpenObjectByName     ; ← API call (green)
77F81244:  test    eax, eax
77F81246:  js      short 0x77F81260       ; ← Branch (peach)
77F81248:  call    IoCreateFile           ; ← API call (green)
77F8124D:  xor     eax, eax               ; STATUS_SUCCESS
77F8124F:  ret     0x2C                   ; ← Return (yellow)
```

**Color coding:** `call` = green, `ret` = yellow, `jmp/jcc` = peach, comments = gray.

### Mode 3: Hex Dump (HEX Hex Dump)

Raw byte view of function code with ASCII representation:

```
HEX dump: NtCreateFile
RVA: 0x00001234 | Size: 156 bytes

Address     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII
──────────  ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──  ──────
77F81234    55 8B EC 83 EC 20 56 57 8B 75 10 E8 12 34 00 00  U....VW.u..å4..
77F81244    85 C0 78 1A E8 56 78 00 00 33 C0 C2 2C 00 CC CC  ..x.åVx..3..,...
```

**Color coding:** `CC` (int3 padding) = red, `C3` (ret) = yellow, `E8` (call) = green.

---

## XRef Scanner — Find All Callers Across System32

The XRef Scanner (Tab 14) answers the critical question: **"Which system DLLs depend on this function?"**

### How to Use

1. Open **Tab 14 (XRef Scanner)**
2. Enter a function name: `NtCreateFile`
3. Browse to a directory: `C:\WINNT\system32`
4. Click **Scan All PEs**
5. The scanner checks every PE file in the directory for imports of that function

### Understanding the Output

```
══ Cross-Reference Scan: NtCreateFile ══
Scanning C:\WINNT\system32 for all callers...
Scanned 412 PE files

── kernel32.dll ──
  Import: ntdll.dll!NtCreateFile  IAT: 0x7C801A34  Type: IAT_IMPORT

── advapi32.dll ──
  Import: ntdll.dll!NtCreateFile  IAT: 0x77DA2F78  Type: IAT_IMPORT

── ws2_32.dll ──
  Import: ntdll.dll!NtCreateFile  IAT: 0x71AB1234  Type: IAT_IMPORT

... (47 more)

Summary: 50 PE files reference NtCreateFile
```

### Why This Matters

Before patching or replacing a system function, you need to know:
- How many DLLs depend on it (impact radius)
- Whether any DLLs import it by ordinal vs. name
- Which IAT addresses to verify after patching

---

## Using with Visual Studio Code

This project works great as a **VS Code workspace**:

1. **Open the folder**: `File > Open Folder > win2k_analyzer`
2. **Run the GUI**: Open terminal (`Ctrl+`` `), type `python win2k_gui.py`
3. **Run CLI commands**: Use the integrated terminal for any CLI command
4. **Edit modules**: All 18 Python modules are in the `nt_analyzer/` package — fully documented and modular
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
from nt_analyzer.ubrt_engine import UBRTEngine

# Universal binary rewriting — insert bytes with automatic reference fixups
engine = UBRTEngine("ntoskrnl.exe")
refs = engine.analyze()           # 109,512 references across 15 passes
engine.insert_bytes(0x1000, 64)   # insert 64 bytes — all refs auto-shift
engine.compact()                  # reclaim section padding
engine.strip_signature()          # remove Authenticode signature
engine.save("ntoskrnl_modified.exe")

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
├── win2k_gui.py               # GUI frontend (17 tabs, dark theme, tabbed output)
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── nt_analyzer/               # Core analysis package (18 modules)
│   ├── __init__.py            # Package init
│   ├── pe_analyzer.py         # PE export/import/header analysis
│   ├── syscall_extractor.py   # Syscall number extraction from ntdll stubs
│   ├── comparator.py          # Side-by-side DLL comparison
│   ├── struct_analyzer.py     # Dynamic PDB structure extractor — native PDB 2.0/7.0 parser, zero static data
│   ├── def_generator.py       # Auto .def file generation
│   ├── syscall_patcher.py     # Syscall header generation (4 styles)
│   ├── ros_patcher.py         # ReactOS source tree auto-patcher
│   ├── build_generator.py     # Build script generation (RosBE/MSVC/CMake)
│   ├── behavior_analyzer.py   # Function fingerprinting, API patterns, SSDT resolver
│   ├── decompiler.py          # x86→C decompiler (works without symbols)
│   ├── compat_analyzer.py     # Deep NT version compatibility detection
│   ├── pe_patcher.py          # KernelEx-inspired PE binary patcher (1900+ lines, 46 methods)
│   ├── deep_analyzer.py       # IDA Pro-level function discovery, profiling, XRefs, deep compare
│   ├── symbol_loader.py       # Multi-format symbol loader (.map/.pdb/.dbg/.sym)
│   ├── emulator.py            # Unicorn-based kernel function emulator with API mocking
│   ├── kernel_debugger.py     # (NEW) Live kernel-state debugger: multi-PE loader, breakpoints, stepping
│   └── ubrt_engine.py         # (NEW) Universal Binary Rewriting Tool: PE/ELF/Mach-O shift engine, 15-pass ref analysis
│
├── generated_headers/         # Output: generated C header files
│   ├── peb_win2k.h
│   ├── teb_win2k.h
│   └── kuser_shared_data_win2k.h
│
└── tests/                     # Test suite (479+ checks across 20 modules)
    ├── __init__.py
    ├── test_full_app.py        # Full application test suite (20 modules, 479+ checks)
    └── test_gui.py            # GUI widget + integration tests
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
A: CLI: `python win2k_analyzer.py structs --pdb ntoskrnl.pdb PEB` or GUI: Tab 4, click **Load PDB**, select your `ntoskrnl.pdb`, then pick any structure from the dropdown. The tool extracts 309+ structure layouts live from the PDB — no hardcoded data.

**Q: How do I extract syscall numbers?**
A: CLI: `python win2k_analyzer.py syscalls C:\WINNT\system32\ntdll.dll` or GUI: Tab 2.

**Q: How do I generate a .def file for building a DLL?**
A: CLI: `python win2k_analyzer.py gen-def <dll_path>` or GUI: Tab 6.

### Decompilation

**Q: How do I decompile a kernel function?**
A: CLI: `python win2k_analyzer.py decompile <pe_file> <function_name>` or GUI: Tab 11, enter function name, click "Decompile Export".

**Q: Can I see assembly instead of C pseudocode?**
A: Yes. In Tab 11, click **🖥 Disassemble** instead of "Decompile Export". This shows annotated x86 assembly with color-coded call/ret/jmp instructions.

**Q: Can I see a hex dump of a function?**
A: Yes. In Tab 11, click **HEX Hex Dump**. Shows raw bytes with address, hex pairs, and ASCII columns. Special bytes are color-highlighted: `CC` (int3) = red, `C3` (ret) = yellow, `E8` (call) = green.

**Q: Can I decompile by address instead of name?**
A: Yes. Use an RVA: `python win2k_analyzer.py decompile ntoskrnl.exe 0x4AE10`

**Q: How do I find functions in a binary without symbols?**
A: CLI: `python win2k_analyzer.py discover-functions <pe_file> --max 100` or GUI: Tab 11 "Discover Functions", or Tab 13 "Discover All Functions" for the deep analyzer.

**Q: What kernel APIs does the decompiler recognize?**
A: 80+ kernel APIs including IoCallDriver, KeWaitForSingleObject, ExAllocatePool, ObReferenceObject, RtlInitUnicodeString, MmProbeAndLockPages, and many more. Plus NTSTATUS codes, IRP major codes, pool types, IRQL levels, device types, and IOCTL decoding.

### Deep Analysis

**Q: What is the Deep Analyzer?**
A: Tab 13 provides IDA Pro-level analysis without symbols. It discovers ALL functions (exported + internal) via prologue scanning, builds cross-reference maps, detects calling conventions, and profiles dependencies. Use it for comprehensive reverse engineering.

**Q: How do I find all internal (non-exported) functions?**
A: Open Tab 13, load a PE, click "Discover All Functions". The deep analyzer scans for `push ebp; mov ebp, esp` patterns and variations to find all function entry points.

**Q: How do I see who calls a function?**
A: Tab 13: select a function, click "XRefs" or right-click → Show XRefs. Shows inbound callers, outbound calls, and API imports.

**Q: How do I compare the same function between two PE versions?**
A: Tab 13: load both files, select a function, click "Deep Compare". Shows hash match, signature similarity, code block differences, API differences.

**Q: How do I find all DLLs in System32 that use a specific function?**
A: Two ways: Tab 14 (XRef Scanner) — enter function name, browse to System32, click "Scan All PEs". Or: Tab 13 — right-click a function → "Scan System32 for Callers".

**Q: What's the difference between Deep Analyzer (Tab 13) and Behavior Analyzer (Tab 10)?**
A: Behavior Analyzer (Tab 10) works on individual exported functions with fingerprinting, pattern detection, and comparison. Deep Analyzer (Tab 13) discovers ALL functions including internals, builds a full function map with cross-references, and supports batch deep comparison.

### Symbols

**Q: How do I load symbols?**
A: In Tab 10 (Behavior) or Tab 11 (Decompiler), browse to a .map, .pdb, .dbg, or .sym file using the symbol file picker. In Tab 10, also check the "Use symbols in disassembly" checkbox.

**Q: What symbol formats are supported?**
A: MSVC .map (link.exe /MAP), GCC .map (ld -Map), IDA Pro .map, Simple .sym (address+name), PDB (Microsoft debug symbols), DBG (COFF debug).

**Q: Do I need symbols for the tool to work?**
A: No. All analysis works without symbols. Symbols just enrich the output with real function names and annotations.

**Q: Where can I get symbols for Windows 2000 system files?**
A: Microsoft's symbol server (`srv*C:\symbols*https://msdl.microsoft.com/download/symbols`) has PDBs for most Windows 2000 SP4 system files. You can also generate .map files by building ReactOS with `/MAP` flag.

### Tabbed Output

**Q: Where did the single output area go?**
A: Every tab now uses tabbed output. Each analysis action opens a new tab with results instead of overwriting. This means you never lose previous results.

**Q: How do I close tabs?**
A: Middle-click a tab to close it. Or right-click for options: Close Tab, Close All Others, Close All. The Clear button also closes all tabs.

**Q: What's the maximum number of tabs?**
A: 20. When you exceed 20, the oldest tab is automatically closed. You can always re-run an analysis.

**Q: Can I compare results from different analyses?**
A: Yes — that's the main benefit. Click between tabs to see different function analyses side by side.

### Compatibility

**Q: What does `compat-analyze` detect?**
A: Calling convention changes (stdcall↔fastcall), HAL dispatch routing differences, bit-shift macro changes (HalpVector), syscall mechanism (int 0x2E vs sysenter), missing/added exports, import changes, section differences, version mismatches, ordinal shifts.

**Q: I got bugcheck 0xA5 (ACPI_BIOS_ERROR) — what's wrong?**
A: Run `python win2k_analyzer.py bugcheck 0xA5`. Common cause: HalpVector macro uses `<<8` (XP) instead of `<<4` (Win2000), or HAL/ACPI version mismatch.

**Q: I got bugcheck 0x7F (UNEXPECTED_KERNEL_MODE_TRAP) — what's wrong?**
A: Run `python win2k_analyzer.py bugcheck 0x7F`. Common cause: Calling convention mismatch — stdcall callee cleans N bytes from stack but fastcall only cleans N-8, causing stack corruption.

**Q: What are the known NT 5.0→5.1 calling convention changes?**
A: Run `python win2k_analyzer.py compat-analyze` with a Win2000 and XP kernel to dynamically detect calling convention differences such as IoAssignDriveLetters, IoReadPartitionTable, IofCallDriver, KfAcquireSpinLock, etc.

**Q: What HAL defines were removed in XP?**
A: Use `compat-analyze` to compare two binaries — the tool will dynamically detect missing exports and HAL dispatch routing differences.

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

### UBRT Engine

**Q: What is the UBRT Engine?**
A: The Universal Binary Rewriting Tool (Tab 17, `nt_analyzer/ubrt_engine.py`) lets you insert, delete, or patch bytes anywhere in a PE, ELF, or Mach-O binary while automatically recalculating every internal reference — relocations, exports, imports, exception handlers, TLS, resources, debug directories, and more.

**Q: How many references does UBRT find?**
A: On Win2K SP4 debug ntoskrnl.exe (1.6 MB), UBRT discovers **109,512 references** across 15 analysis passes. This includes 54 indirect calls through memory, 14 resource RVAs, 2 indirect jumps, plus all standard relocation/export/import references.

**Q: What binary formats does UBRT support?**
A: PE (32/64-bit), ELF (with SHT_RELA addend correction), and Mach-O (including fat/universal binaries). Each format has a dedicated shift engine that knows how to update format-specific headers.

**Q: What is compact()?**
A: `compact()` scans sections for trailing zero padding and removes it, shrinking the binary. Available for PE, ELF, and Mach-O. All section headers, program headers, and load commands are automatically updated.

**Q: What is strip_signature()?**
A: `strip_signature()` removes code signatures so modified binaries don't fail verification. For PE: zeroes the Security data directory, truncates the certificate table, zeroes the PE checksum. For Mach-O: removes the LC_CODE_SIGNATURE load command and signature blob.

**Q: How does QEMU tracing work?**
A: Run your binary under QEMU with `-d exec` to generate an execution trace. Then call `engine.merge_trace_coverage("trace.log")` to parse it. UBRT resolves the traced addresses to file offsets and adds them as first-class references that the shift engine tracks during insert/delete operations.

**Q: What happens if I insert bytes inside the .rsrc section?**
A: UBRT detects the conflict and warns you. It skips internal resource pointer rewriting to prevent corrupting the resource tree's relative offsets. The operation still succeeds, but the warning tells you the resource directory may need manual attention.

### VS Code & Copilot

**Q: Can I use this from VS Code?**
A: Yes. Open the `win2k_analyzer` folder in VS Code. Use the integrated terminal for CLI commands, or press F5 to run the GUI. All modules support IntelliSense autocomplete.

**Q: Does this work with GitHub Copilot?**
A: Yes. Copilot can run CLI commands via Agent Mode, analyze output, suggest patches, and even extend the analyzer modules. Ask Copilot things like *"Run compat-analyze and explain the results"* or *"Patch this DLL for Windows 2000"*.

**Q: Can I extend the analyzer with new features?**
A: Yes. Each module in `nt_analyzer/` is standalone. Add new detection rules to `compat_analyzer.py`, extend the PDB parser in `struct_analyzer.py` to handle additional CodeView leaf types, or add new patch types to `pe_patcher.py`. The CLI and GUI will pick them up automatically.

---

## Contributing

This is a community project for Windows 2000 preservation and ReactOS compatibility research.

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Areas that need help:
- More CodeView leaf type support in the PDB parser (method types, vtables, etc.)
- x86-64 decompiler support
- More calling convention detection heuristics
- Additional NT version difference rules
- Testing on more Win2000 system binaries
- Pre-built patch sets for common ReactOS DLLs
- PDB support for hal.pdb, ntdll.pdb, win32k.pdb structure extraction
- Additional prologue patterns for deep function discovery
- Graph visualization for cross-reference maps
- UBRT: ELF DT_JMPREL / DT_RELA / DT_INIT_ARRAY reference passes
- UBRT: Mach-O chained fixups and bind opcodes reference analysis
- UBRT: lazy delta accumulation for large-scale multi-shift performance
- UBRT: ARM/AArch64 ELF relocation types

---

**Made with love for the Windows 2000 community.**
