"""Verify deployed HAL PDB publics+privates match export table."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pefile
from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.segment_map import (
    parse_section_map, resolve_frame_rva, pe_section_layout,
)
from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices
from nt_analyzer.pdb70.updater import SymbolUpdater70
from nt_analyzer.symbol_loader import _undecorate

PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi.pdb"
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
IB = 0x80062000

pe = pefile.PE(PAT)
exp = {}
for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if s.name:
        exp[s.name.decode()] = s.address
pe.close()

pv, pvz = pe_section_layout(PAT)
msf = parse_msf70(PDB)
dbi = msf['read_stream'](3)
sm = parse_section_map(dbi)
_, _, sn = dbi_stream_indices(dbi)
symrec = msf['read_stream'](sn)

CHECK = ['HalGetBusDataByOffset', 'HalSetBusDataByOffset', 'HalInitSystem',
         'HalGetBusData', 'HalTranslateBusAddress', 'HalInitializeProcessor']

pub_rva = {}
for _ro, name, seg, off in walk_pub32(symrec):
    clean = _undecorate(name.decode('ascii', 'replace'))
    if clean in CHECK:
        pub_rva[clean] = resolve_frame_rva(seg, off, sm, pv)

mod_rva = {}
for msn, _nm in SymbolUpdater70._parse_modules(dbi):
    if msn in (0xFFFF,) or msn >= msf['num_streams']:
        continue
    stream = msf['read_stream'](msn)
    if len(stream) < 4:
        continue
    so = 4
    n = len(stream)
    while so + 4 <= n:
        rl = struct.unpack_from('<H', stream, so)[0]
        if rl < 2 or so + 2 + rl > n:
            break
        rt = struct.unpack_from('<H', stream, so + 2)[0]
        spec = SymbolUpdater70._ADDR_RECS.get(rt)
        if spec:
            offf, segf, namef = spec
            if so + namef <= n:
                nend = stream.find(b'\x00', so + namef)
                raw = stream[so + namef:nend].decode('ascii', 'replace')
                clean = _undecorate(raw)
                if clean in CHECK:
                    o = struct.unpack_from('<I', stream, so + offf)[0]
                    sg = struct.unpack_from('<H', stream, so + segf)[0]
                    mod_rva[clean] = resolve_frame_rva(sg, o, sm, pv)
        so += 2 + rl
        if so % 4:
            so += 4 - (so % 4)

print(f"{'name':28} {'export':>9} {'public':>9} {'module':>9}  ok")
for n in CHECK:
    e = exp.get(n)
    p = pub_rva.get(n)
    m = mod_rva.get(n)
    es = f"0x{e:X}" if e is not None else '-'
    ps = f"0x{p:X}" if p is not None else '-'
    ms = f"0x{m:X}" if m is not None else '-'
    ok = (e is None or p is None or e == p) and (e is None or m is None or e == m)
    print(f"{n:28} {es:>9} {ps:>9} {ms:>9}  {'YES' if ok else 'NO'}")
