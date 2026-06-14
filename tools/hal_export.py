"""Run HAL PDB export directly."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.symbol_recovery import SymbolRecoveryEngine

ORIG = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\halmacpi.dll"
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
PDB = r"C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb"
OUT = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi_test.pdb"

e = SymbolRecoveryEngine()
e.diff_binaries(ORIG, PAT)
e.load_symbols(PDB, pe_path=ORIG)
e.recover_symbols()
r = e.export_pdb(PDB, OUT, orig_pe_path=ORIG, patched_pe_path=PAT)
print("export", r)
