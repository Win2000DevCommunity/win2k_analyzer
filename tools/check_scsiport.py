"""Check scsiport bind chain: PE timestamps + dbg + pdb across locations."""
import os
import struct

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pefile

VM_TS = 0x50A1E01D  # from kd lmDvm

PATHS = {
    "rollup orig": r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\scsiport.sys",
    "16e patched": r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU\scsiport.sys",
    "MS symbol pdb": r"C:\Users\Win2000\Downloads\symbols\sys\scsiport.pdb",
    "deployed pdb": r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\sys\scsiport.pdb",
    "deployed dbg (SYS)": r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\SYS\SCSIPORT.dbg",
    "deployed dbg (sys)": r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\sys\scsiport.dbg",
}


def pe_info(path):
    pe = pefile.PE(path, fast_load=True)
    ts = pe.FILE_HEADER.TimeDateStamp
    soi = pe.OPTIONAL_HEADER.SizeOfImage
    nsec = len(pe.sections)
    dbg = []
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for d in pe.DIRECTORY_ENTRY_DEBUG:
            dbg.append(d.struct.Type)
    pe.close()
    return ts, soi, nsec, dbg


def dbg_info(path):
    with open(path, "rb") as f:
        data = f.read()
    # IMAGE_SEPARATE_DEBUG_HEADER: Signature 'DI' (0x4944)
    sig = struct.unpack_from("<H", data, 0)[0]
    ts = struct.unpack_from("<I", data, 8)[0]
    checksum = struct.unpack_from("<I", data, 12)[0]
    soi = struct.unpack_from("<I", data, 24)[0]
    return sig, ts, checksum, soi


print(f"VM scsiport.sys timestamp = 0x{VM_TS:08X}\n")
for label, p in PATHS.items():
    if not os.path.isfile(p):
        print(f"  {label:22} MISSING  {p}")
        continue
    if p.lower().endswith(".dbg"):
        sig, ts, cs, soi = dbg_info(p)
        match = "  <-- MATCHES VM" if ts == VM_TS else ""
        print(f"  {label:22} DBG sig=0x{sig:04X} ts=0x{ts:08X} cs=0x{cs:08X} soi=0x{soi:X}{match}")
    elif p.lower().endswith(".pdb"):
        with open(p, "rb") as f:
            head = f.read(44)
        from nt_analyzer.pdb70.msf import detect_pdb_format
        fmt = detect_pdb_format(p)
        # PDB 2.0 signature/age at offset after header; just report fmt + sig
        print(f"  {label:22} PDB fmt={fmt}  size={os.path.getsize(p)}")
    else:
        ts, soi, nsec, dbg = pe_info(p)
        match = "  <-- MATCHES VM" if ts == VM_TS else ""
        types = ",".join(str(t) for t in dbg) or "none"
        print(f"  {label:22} PE  ts=0x{ts:08X} soi=0x{soi:X} sec={nsec} dbgdir=[{types}]{match}")
