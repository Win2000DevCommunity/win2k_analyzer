"""Dump debug directory + CodeView inside a .dbg and a .pdb 2.0 signature."""
import os
import struct
import sys

DBG_SYS = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\sys\scsiport.dbg"
PDB_SYS = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\sys\scsiport.pdb"
MS_DBG = r"C:\Users\Win2000\Downloads\symbols\sys\scsiport.dbg"


def pdb20_sig(path):
    with open(path, "rb") as f:
        data = f.read(0x100)
    if data[:44] != b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00":
        return None
    # after 44-byte magic: DWORD page_size, WORD start, WORD count, then root...
    # PDB 2.0 signature/age live in the PDB info stream, not header. Report magic ok.
    return "pdb20-magic-ok"


def dump_dbg(path):
    with open(path, "rb") as f:
        data = f.read()
    sig = struct.unpack_from("<H", data, 0)[0]
    if sig != 0x4944:  # 'DI'
        print(f"  not a separate debug file (sig 0x{sig:04X})")
        return
    flags = struct.unpack_from("<H", data, 2)[0]
    machine = struct.unpack_from("<H", data, 4)[0]
    ts = struct.unpack_from("<I", data, 8)[0]
    checksum = struct.unpack_from("<I", data, 12)[0]
    image_base = struct.unpack_from("<I", data, 16)[0]
    soi = struct.unpack_from("<I", data, 20)[0]
    nsec = struct.unpack_from("<I", data, 24)[0]
    exp_names = struct.unpack_from("<I", data, 28)[0]
    dbg_dir_size = struct.unpack_from("<I", data, 32)[0]
    sec_align = struct.unpack_from("<I", data, 36)[0]
    print(f"  ts=0x{ts:08X} checksum=0x{checksum:08X} soi=0x{soi:X} "
          f"nsec={nsec} expnames={exp_names} dbgdirsize={dbg_dir_size}")
    # Layout: header(48) + sections(nsec*40) + exported names + debug dir
    off = 48 + nsec * 40 + exp_names
    n_entries = dbg_dir_size // 28
    print(f"  debug dir at 0x{off:X}, {n_entries} entries:")
    CV_TYPES = {1: "COFF", 2: "CODEVIEW", 4: "MISC", 6: "FIXUP", 9: "BORLAND"}
    for i in range(n_entries):
        e = off + i * 28
        if e + 28 > len(data):
            break
        dtype = struct.unpack_from("<I", data, e + 12)[0]
        size = struct.unpack_from("<I", data, e + 16)[0]
        addr_rva = struct.unpack_from("<I", data, e + 20)[0]
        ptr = struct.unpack_from("<I", data, e + 24)[0]
        tname = CV_TYPES.get(dtype, str(dtype))
        line = f"    [{i}] type={tname} size={size} rva=0x{addr_rva:X} ptr=0x{ptr:X}"
        if dtype == 2 and ptr + 4 <= len(data):  # CODEVIEW
            cv_sig = data[ptr:ptr + 4]
            line += f"  CV={cv_sig!r}"
            if cv_sig in (b"NB10", b"NB09"):
                off2 = struct.unpack_from("<I", data, ptr + 4)[0]
                sig2 = struct.unpack_from("<I", data, ptr + 8)[0]
                age = struct.unpack_from("<I", data, ptr + 12)[0]
                nend = data.find(b"\x00", ptr + 16)
                pdbname = data[ptr + 16:nend].decode("ascii", "replace")
                line += f" sig=0x{sig2:08X} age={age} pdb={pdbname!r}"
            elif cv_sig == b"RSDS":
                line += " (PDB 7.0 RSDS)"
        print(line)


for label, p in [("deployed sys/scsiport.dbg", DBG_SYS),
                 ("MS scsiport.dbg", MS_DBG)]:
    print(f"\n=== {label} ===")
    if os.path.isfile(p):
        dump_dbg(p)
    else:
        print("  MISSING")

print(f"\nscsiport.pdb: {pdb20_sig(PDB_SYS)}")
