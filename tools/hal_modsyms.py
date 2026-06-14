"""Inspect HAL PDB module streams for address-bearing private symbols."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.segment_map import (
    parse_section_map, resolve_frame_rva, pe_section_layout,
)

PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi.pdb"
if not os.path.isfile(PDB):
    PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi_test.pdb"
PAT = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
IB = 0x80062000

# (off_field, seg_field, name_off) relative to record start `so`.
ADDR_TYPES = {
    0x110C: (8, 12, 14),    # S_LDATA32
    0x110D: (8, 12, 14),    # S_GDATA32
    0x110E: (8, 12, 14),    # S_PUB32
    0x110F: (32, 36, 39),   # S_LPROC32
    0x1110: (32, 36, 39),   # S_GPROC32
    0x1146: (32, 36, 39),   # S_LPROC32_ID
    0x1147: (32, 36, 39),   # S_GPROC32_ID
    0x1105: (4, 8, 9),      # S_LABEL32
    0x1112: (8, 12, 14),    # S_LTHREAD32
    0x1113: (8, 12, 14),    # S_GTHREAD32
}


def parse_modules(dbi):
    modi_sz = struct.unpack_from('<i', dbi, 24)[0]
    base = 64
    end = base + modi_sz
    mods = []
    off = base
    while off + 64 <= end:
        sn = struct.unpack_from('<H', dbi, off + 34)[0]
        cb_syms = struct.unpack_from('<i', dbi, off + 38)[0]
        name_off = off + 64
        nend = dbi.find(b'\x00', name_off)
        name = dbi[name_off:nend].decode('ascii', 'replace')
        # two names (module, obj); skip to after both, align 4
        oend = dbi.find(b'\x00', nend + 1)
        rec_end = oend + 1
        if rec_end % 4:
            rec_end += 4 - (rec_end % 4)
        mods.append((sn, cb_syms, name))
        off = rec_end
    return mods


def walk_records(stream):
    if len(stream) < 4:
        return
    so = 4  # skip signature
    n = len(stream)
    while so + 4 <= n:
        reclen = struct.unpack_from('<H', stream, so)[0]
        if reclen < 2 or so + 2 + reclen > n:
            break
        rectyp = struct.unpack_from('<H', stream, so + 2)[0]
        yield so, reclen, rectyp
        so += 2 + reclen
        if so % 4:
            so += 4 - (so % 4)


def main():
    pv, pvz = pe_section_layout(PAT)
    msf = parse_msf70(PDB)
    dbi = msf['read_stream'](3)
    sm = parse_section_map(dbi)
    mods = parse_modules(dbi)
    print(f"PDB: {PDB}")
    print(f"modules: {len(mods)}")
    hits = 0
    for sn, cb, name in mods:
        if sn == 0xFFFF:
            continue
        stream = msf['read_stream'](sn)
        for so, reclen, rectyp in walk_records(stream):
            if rectyp not in ADDR_TYPES:
                continue
            offf, segf, namef = ADDR_TYPES[rectyp]
            if so + namef >= len(stream):
                continue
            nend = stream.find(b'\x00', so + namef)
            sym = stream[so + namef:nend].decode('ascii', 'replace')
            if 'HalInitSystem' in sym:
                off = struct.unpack_from('<I', stream, so + offf)[0]
                seg = struct.unpack_from('<H', stream, so + segf)[0]
                rva = resolve_frame_rva(seg, off, sm, pv)
                rstr = f"0x{rva:X}" if rva is not None else "?"
                vstr = f"0x{IB+rva:08X}" if rva is not None else "?"
                print(f"  mod={name[:30]:30} type=0x{rectyp:X} sym={sym!r:30} "
                      f"seg={seg} off=0x{off:X} rva={rstr} VA={vstr}")
                hits += 1
    print(f"matches: {hits}")


if __name__ == '__main__':
    main()
