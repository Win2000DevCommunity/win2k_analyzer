"""Diagnostic: HAL PDB segment map and symbol RVAs."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.pdb70.segment_map import (
    parse_section_map, pe_section_layout, resolve_segment_rva, load_section_map_from_pdb70,
)
from nt_analyzer.pdb70.msf import parse_msf70
from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices
import pefile

ORIG_PE = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\halmacpi.dll"
PAT_PE = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\halmacpi.dll"
MS_PDB = r"C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb"
OUT_PDB = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\dll\halmacpi_test.pdb"
IB = 0x80062000

TARGETS = {
    b"HalSetBusDataByOffset",
    b"HalGetBusDataByOffset",
    b"Abios_hdpi_a",
    b"Abios_HGeneric_a",
    b"HalInitSystem",
    b"HalpmmTimerClockInterrupt",
}


def dump_pe(path, label):
    pe = pefile.PE(path, fast_load=True)
    print(f"=== {label} ===")
    for i, s in enumerate(pe.sections):
        name = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        print(f"  {i+1}: {name:8} VA=0x{s.VirtualAddress:05X} VSz=0x{s.Misc_VirtualSize:05X}")
    pe.close()


def main():
    for p in [ORIG_PE, PAT_PE, MS_PDB, OUT_PDB]:
        print(p, "exists=", os.path.isfile(p))

    dump_pe(ORIG_PE, "ORIG PE")
    dump_pe(PAT_PE, "PATCHED PE")

    sm = load_section_map_from_pdb70(MS_PDB)
    print(f"=== PDB section map ({len(sm)} entries) ===")
    ov, osz = pe_section_layout(ORIG_PE)
    pv, psz = pe_section_layout(PAT_PE)
    for e in sm:
        frame = e.frame
        pe_rva = ov[frame - 1] if 1 <= frame <= len(ov) else 0
        pe_name = ""
        if 1 <= frame <= len(ov):
            pe = pefile.PE(ORIG_PE, fast_load=True)
            pe_name = pe.sections[frame - 1].Name.rstrip(b"\x00").decode("ascii", "replace")
            pe.close()
        print(
            f"  seg{e.index}: frame={frame} ({pe_name}) "
            f"map_off=0x{e.map_offset:X} lsize=0x{e.logical_size:X}"
        )

    msf = parse_msf70(MS_PDB)
    _, _, sn = dbi_stream_indices(msf["read_stream"](3))
    symrec = msf["read_stream"](sn)

    def show_syms(label, symrec_b, vas, vsz):
        print(f"=== {label} ===")
        for _ro, name, seg, off in walk_pub32(symrec_b):
            nb = name.decode("ascii", "replace")
            if b"HalSetBusData" in name or b"HalGetBusData" in name or b"HalInit" in name or b"Abios" in name:
                rva = resolve_segment_rva(seg, off, sm, vas, vsz)
                frame = sm[seg - 1].frame if 0 < seg <= len(sm) else 0
                print(
                    f"  {nb:40} logseg={seg:2} frame={frame:2} "
                    f"off=0x{off:05X} rva=0x{rva:05X} VA=0x{IB+rva:08X}"
                )

    show_syms("MS PDB + orig PE", symrec, ov, osz)

    if os.path.isfile(OUT_PDB):
        msf2 = parse_msf70(OUT_PDB)
        sm2 = parse_section_map(msf2["read_stream"](3))
        _, _, sn2 = dbi_stream_indices(msf2["read_stream"](3))
        symrec2 = msf2["read_stream"](sn2)
        print(f"=== EXPORTED section map ({len(sm2)} entries) ===")
        for e in sm2:
            print(f"  seg{e.index}: frame={e.frame} lsize=0x{e.logical_size:X}")
        show_syms("EXPORTED PDB + patched PE (current resolve)", symrec2, pv, psz)
        show_syms("EXPORTED PDB + orig PE (should match MS)", symrec2, ov, osz)

    # Export table check on patched PE
    pe = pefile.PE(PAT_PE)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("=== Patched PE exports (sample) ===")
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            n = sym.name.decode() if sym.name else ""
            if n.startswith("Hal") and "Bus" in n:
                print(f"  {n} @ 0x{sym.address:05X} VA=0x{IB+sym.address:08X}")
    pe.close()


if __name__ == "__main__":
    main()
