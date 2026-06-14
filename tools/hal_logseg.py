"""Check logseg vs frame in HAL PDB."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.segment_map import parse_section_map
from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices

PDB = r"C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb"
msf = parse_msf70(PDB)
sm = parse_section_map(msf["read_stream"](3))
_, _, sn = dbi_stream_indices(msf["read_stream"](3))
diff = 0
total = 0
for _ro, name, seg, off in walk_pub32(msf["read_stream"](sn)):
    total += 1
    frame = sm[seg-1].frame if 0 < seg <= len(sm) else -1
    if seg != frame:
        diff += 1
        if diff <= 10:
            print(name.decode(), "logseg", seg, "frame", frame)
print("total", total, "logseg!=frame", diff)
