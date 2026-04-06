"""Final integration test for all CLI functionality."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.decompiler import decompile
from nt_analyzer.symbol_loader import load_symbols, load_dbg_file
from nt_analyzer import behavior_analyzer as ba

PE_W2K = 'C:/Users/win2000/Desktop/2kDEBUG/Nouveau dossier/ntoskrnl.exe'
PE_ROS = 'C:/Users/win2000/Desktop/2kDEBUG/ntoskrnl.exe'
PDB_W2K = 'C:/Users/win2000/Desktop/2kDEBUG/Nouveau dossier/ntoskrnl.pdb'
PDB_ROS = 'C:/Users/win2000/Desktop/2kDEBUG/ntoskrnl.pdb'
DBG_W2K = 'C:/Users/win2000/Desktop/2kDEBUG/Nouveau dossier/ntoskrnl.dbg'

errors = []

print("=== Final Integration Test ===\n")

# 1) PDB loading
syms_w2k, meta_w2k = load_symbols(PDB_W2K, pe_path=PE_W2K)
syms_ros, meta_ros = load_symbols(PDB_ROS, pe_path=PE_ROS)
fmt_w2k = meta_w2k.get('format', '?')
fmt_ros = meta_ros.get('format', '?')
print(f"1. PDB Loading:")
print(f"   Win2K: {len(syms_w2k)} symbols ({fmt_w2k})")
print(f"   ReactOS: {len(syms_ros)} symbols ({fmt_ros})")
if len(syms_w2k) < 1000:
    errors.append(f"Win2K PDB only loaded {len(syms_w2k)} symbols (expected >1000)")
if len(syms_ros) < 1000:
    errors.append(f"ReactOS PDB only loaded {len(syms_ros)} symbols (expected >1000)")

# 2) DBG loading
_, dbg_meta = load_dbg_file(DBG_W2K)
fpo = dbg_meta.get('fpo_entries', 0)
pdb_ref = dbg_meta.get('pdb_reference', '')
print(f"2. DBG Loading:")
print(f"   FPO entries: {fpo}")
print(f"   PDB reference: {pdb_ref}")
if fpo == 0:
    errors.append("DBG file loaded 0 FPO entries")
if not pdb_ref:
    errors.append("DBG file missing PDB reference")

# 3) Decompile with symbols — check for wrong fallback annotations
funcs = ['CcInitializeCacheMap', 'IoCreateDevice', 'NtCreateFile',
         'ExAllocatePoolWithTag', 'CcFlushCache', 'NtClose', 'IoCallDriver']
print(f"3. Decompile ({len(funcs)} functions x 2 binaries):")
for name in funcs:
    for label, pe, syms in [('W2K', PE_W2K, syms_w2k), ('ROS', PE_ROS, syms_ros)]:
        r = decompile(pe, name, symbols=syms)
        if r:
            lines = r.split('\n')
            wrong = [l for l in lines if '? DRIVER_OBJECT' in l or '? IRP->' in l]
            if wrong:
                errors.append(f"{label} {name}: {len(wrong)} wrong fallback refs")
                status = f"WRONG={len(wrong)}"
            else:
                status = "OK"
            print(f"   {label} {name}: {len(lines)} lines [{status}]")
        else:
            print(f"   {label} {name}: NOT FOUND")

# 4) Assembly mode
print(f"4. Assembly mode:")
for name in ['CcInitializeCacheMap', 'IoCallDriver']:
    asm = ba.disassemble_function(PE_W2K, name)
    if asm:
        print(f"   {name}: {len(asm.split(chr(10)))} lines [OK]")
    else:
        errors.append(f"Assembly failed for {name}")
        print(f"   {name}: FAILED")

# 5) Behavior scan
print(f"5. Behavior scan (first 20 exports):")
cats = ba.scan_all_exports(PE_W2K, max_functions=20)
total = sum(len(v) for v in cats.values())
print(f"   Categories: {len(cats)}, total entries: {total}")
if total == 0:
    errors.append("Behavior scan returned 0 entries")

# 6) Check symbols resolve internal functions
print(f"6. Internal symbol resolution:")
internal_w2k = [n for n in syms_w2k.values() if n.startswith(('Iop', 'Ki', 'Mi', 'Psp'))]
internal_ros = [n for n in syms_ros.values() if n.startswith(('Iop', 'Ki', 'Mi', 'Psp'))]
print(f"   Win2K internal symbols: {len(internal_w2k)}")
print(f"   ReactOS internal symbols: {len(internal_ros)}")

# Summary
print(f"\n{'='*40}")
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print(f"  - {e}")
else:
    print("ALL TESTS PASSED")
