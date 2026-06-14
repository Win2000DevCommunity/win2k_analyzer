"""Recovery stats for HAL."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nt_analyzer.symbol_recovery import SymbolRecoveryEngine

ORIG = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\halmacpi.dll"
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
PDB = r"C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb"
IMAGE_SIZE = 0x16980
IB = 0x80062000

e = SymbolRecoveryEngine()
e.diff_binaries(ORIG, PAT)
n, meta = e.load_symbols(PDB, pe_path=ORIG)
rec = e.recover_symbols()
from collections import Counter
c = Counter(r.status for r in rec)
print("loaded", n, "status", dict(c))
oob = [r for r in rec if r.status=='ok' and (r.recovered_va-IB) >= IMAGE_SIZE]
print("ok but oob", len(oob))
if oob[:5]:
    for r in oob[:5]:
        print(" ", r.name, hex(r.recovered_va-IB))
outside = [r for r in rec if r.status=='outside']
print("outside", len(outside))
