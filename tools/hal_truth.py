"""Ground-truth addresses for HalInitSystem* from exports + recovery."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pefile
from nt_analyzer.symbol_recovery import SymbolRecoveryEngine

ORIG = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\halmacpi.dll"
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
PDB = r"C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb"
IB = 0x80062000

pe = pefile.PE(PAT)
print("=== patched exports matching HalInit ===")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        n = s.name.decode() if s.name else ''
        if 'HalInit' in n:
            print(f"  {n} @ RVA 0x{s.address:X} VA 0x{IB+s.address:08X}")
pe.close()

e = SymbolRecoveryEngine()
e.diff_binaries(ORIG, PAT)
e.load_symbols(PDB, pe_path=ORIG)
rec = e.recover_symbols()
print("=== recovered map for HalInit* ===")
for r in rec:
    if 'HalInit' in r.name:
        print(f"  {r.name:30} orig=0x{r.orig_va:08X} recovered=0x{r.recovered_va:08X} "
              f"sec={r.section_name} status={r.status}")
