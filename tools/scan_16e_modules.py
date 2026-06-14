"""Scan orig/patch/symbol availability for 16e batch test."""
import os

ORIG = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU"
PATCH = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU"
SYM_ROOT = r"C:\Users\Win2000\Downloads\symbols"

for d in (ORIG, PATCH, SYM_ROOT):
    print(d, "exists=", os.path.isdir(d))
    if os.path.isdir(d):
        files = sorted(os.listdir(d))
        print(f"  {len(files)} files")
        for f in files[:5]:
            print(f"    {f}")
        if len(files) > 5:
            print(f"    ... +{len(files)-5} more")

print("\n=== symbol subdirs ===")
for sub in ("exe", "dll", "sys"):
    p = os.path.join(SYM_ROOT, sub)
    if os.path.isdir(p):
        pdbs = [f for f in os.listdir(p) if f.lower().endswith((".pdb", ".dbg"))]
        print(f"  {sub}: {len(pdbs)} symbol files")
        for f in sorted(pdbs)[:15]:
            print(f"    {f}")
        if len(pdbs) > 15:
            print(f"    ... +{len(pdbs)-15} more")
