"""Read the PDB's own section-header stream (dbghelp ground truth)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices

MS_PDB = r"C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb"


def dbg_header_indices(dbi):
    sizes = struct.unpack_from('<iiiiii', dbi, 24)  # gpmodi, sc, secmap, file, tsmap, ?
    cb_gpmodi = struct.unpack_from('<i', dbi, 24)[0]
    cb_sc = struct.unpack_from('<i', dbi, 28)[0]
    cb_secmap = struct.unpack_from('<i', dbi, 32)[0]
    cb_file = struct.unpack_from('<i', dbi, 36)[0]
    cb_tsmap = struct.unpack_from('<i', dbi, 40)[0]
    cb_ecinfo = struct.unpack_from('<i', dbi, 52)[0]
    cb_dbghdr = struct.unpack_from('<i', dbi, 48)[0]
    base = 64 + cb_gpmodi + cb_sc + cb_secmap + cb_file + cb_tsmap + cb_ecinfo
    print(f"dbghdr base=0x{base:X} len={cb_dbghdr}")
    hdr = dbi[base:base + cb_dbghdr]
    idx = [struct.unpack_from('<H', hdr, i)[0] for i in range(0, len(hdr), 2)]
    return idx


def main():
    msf = parse_msf70(MS_PDB)
    dbi = msf['read_stream'](3)
    idx = dbg_header_indices(dbi)
    print("dbg header stream indices:", idx)
    if len(idx) < 6:
        print("no section header stream")
        return
    sn_sec = idx[5]
    print(f"snSectionHdr = {sn_sec}")
    sec = msf['read_stream'](sn_sec)
    print(f"section header stream {len(sec)} bytes -> {len(sec)//40} sections")
    secs = []
    for i in range(len(sec) // 40):
        off = i * 40
        name = sec[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsize = struct.unpack_from('<I', sec, off + 8)[0]
        va = struct.unpack_from('<I', sec, off + 12)[0]
        secs.append((name, va, vsize))
        print(f"  seg{i+1}: {name:10} VA=0x{va:05X} VSz=0x{vsize:05X}")

    # decode _HalInitSystem@8 using this stream
    _, _, sn = dbi_stream_indices(dbi)
    symrec = msf['read_stream'](sn)
    for _ro, name, seg, off in walk_pub32(symrec):
        nb = name.decode('ascii', 'replace')
        if nb in ('_HalInitSystem@8', '_HalInitSystemPhase2@0',
                  '_HalGetBusDataByOffset@24'):
            if 1 <= seg <= len(secs):
                rva = secs[seg - 1][1] + off
            else:
                rva = off
            print(f"  {nb:30} seg={seg} off=0x{off:X} -> PDBsec RVA=0x{rva:X}")


if __name__ == '__main__':
    main()
