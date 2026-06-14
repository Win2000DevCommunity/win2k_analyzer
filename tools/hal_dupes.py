"""Find duplicate HalInitSystem public records in HAL PDB."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.segment_map import parse_section_map, resolve_frame_rva, pe_section_layout
from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices
from nt_analyzer.symbol_loader import _undecorate

PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi.pdb"
if not os.path.isfile(PDB):
    PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi_test.pdb"
IB = 0x80062000
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"

pv, psz = pe_section_layout(PAT)
msf = parse_msf70(PDB)
sm = parse_section_map(msf["read_stream"](3))
_, _, sn = dbi_stream_indices(msf["read_stream"](3))
symrec = msf["read_stream"](sn)

for ro, name, seg, off in walk_pub32(symrec):
    nb = name.decode("ascii", "replace")
    clean = _undecorate(nb)
    if "HalInitSystem" in clean or "HalInitSystem" in nb:
        rva = resolve_frame_rva(seg, off, sm, pv)
        print(f"  raw={nb!r:40} clean={clean!r:20} seg={seg} off=0x{off:X} rva=0x{rva:X} VA=0x{IB+rva:08X} ro=0x{ro:X}")
