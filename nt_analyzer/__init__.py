"""
Win2K NT Internals Analyzer
============================
Extracts undocumented internals from Windows 2000 SP4 system DLLs
for comparison with ReactOS builds.

Capabilities:
  - Export table extraction (names + ordinals)
  - Import table extraction
  - Syscall number extraction from ntdll.dll stubs
  - Side-by-side comparison of Win2000 vs ReactOS DLLs
  - PE header analysis
  - Structure offset hints from debug symbols
  - Deep binary compatibility analysis (NT 5.0 vs 5.1)
  - KernelEx-inspired PE binary patching
  - Deep function analysis (private/internal function discovery)
  - System-wide cross-reference scanning
  - Multi-format symbol loading (.map/.pdb/.dbg/.sym)
"""
__version__ = "3.1.0"
