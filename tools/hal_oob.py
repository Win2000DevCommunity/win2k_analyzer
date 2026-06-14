"""Count HAL PDB symbols outside image / compare resolve models."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.pdb70.segment_map import (
    parse_section_map, pe_section_layout, resolve_segment_rva, load_section_map_from_pdb70,
)
from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices

PAT_PE = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
OUT_PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi_test.pdb"
IB = 0x80062000
IMAGE_SIZE = 0x16980


def kd_resolve(seg, off, sm, vas):
    """Match dbghelp: section_map[seg-1].frame -> PE section VA + offset."""
    if seg <= 0 or seg > len(sm):
        return None
    frame = sm[seg - 1].frame
    if frame <= 0 or frame > len(vas):
        return None
    return vas[frame - 1] + off


def main():
    pv, psz = pe_section_layout(PAT_PE)
    msf = parse_msf70(OUT_PDB)
    sm = parse_section_map(msf["read_stream"](3))
    _, _, sn = dbi_stream_indices(msf["read_stream"](3))
    symrec = msf["read_stream"](sn)

    bad_kd = []
    bad_spill = []
    total = 0
    for _ro, name, seg, off in walk_pub32(symrec):
        total += 1
        nb = name.decode("ascii", "replace")
        rva_kd = kd_resolve(seg, off, sm, pv)
        rva_sp = resolve_segment_rva(seg, off, sm, pv, psz)
        if rva_kd is None:
            continue
        if rva_kd >= IMAGE_SIZE:
            bad_kd.append((nb, seg, off, rva_kd))
        if rva_sp is not None and rva_sp >= IMAGE_SIZE:
            bad_spill.append((nb, rva_sp))

    print(f"Total publics: {total}")
    print(f"Outside image (kd model): {len(bad_kd)}")
    print(f"Outside image (spill model): {len(bad_spill)}")
    print("Sample outside (kd model):")
    for row in bad_kd[:20]:
        print(f"  {row[0]:40} seg={row[1]} off=0x{row[2]:X} rva=0x{row[3]:X}")

    # Show frame remap needed
    orig_pe = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\halmacpi.dll"
    ov, _ = pe_section_layout(orig_pe)
    import pefile
    def sec_names(path):
        pe = pefile.PE(path, fast_load=True)
        ns = [s.Name.rstrip(b"\x00").decode("ascii", "replace") for s in pe.sections]
        pe.close()
        return ns
    on = sec_names(orig_pe)
    pn = sec_names(PAT_PE)
    print("Frame remap orig->patched (by name):")
    for i, name in enumerate(on, 1):
        try:
            j = pn.index(name) + 1
            if j != i:
                print(f"  frame {i} ({name}) -> {j}")
        except ValueError:
            print(f"  frame {i} ({name}) -> REMOVED")
    for name in pn:
        if name not in on:
            print(f"  NEW section {name} at index {pn.index(name)+1}")


if __name__ == "__main__":
    main()
