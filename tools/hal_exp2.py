"""Compare orig vs patched export RVAs for HalInit*."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pefile

ORIG = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\halmacpi.dll"
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"


def exports(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    out = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if s.name:
                out[s.name.decode()] = (s.address, base)
    pe.close()
    return out


o = exports(ORIG)
p = exports(PAT)
print(f"orig base 0x{list(o.values())[0][1]:X}  patched base 0x{list(p.values())[0][1]:X}")
for n in sorted(set(o) | set(p)):
    if 'HalInit' in n or 'Bus' in n:
        orv = o.get(n, ('-', 0))[0]
        prv = p.get(n, ('-', 0))[0]
        os_ = f"0x{orv:X}" if isinstance(orv, int) else orv
        ps_ = f"0x{prv:X}" if isinstance(prv, int) else prv
        print(f"  {n:30} orig_rva={os_:>8}  patched_rva={ps_:>8}")
