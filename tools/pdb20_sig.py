"""Read PDB 2.0 info-stream signature/age (what NB10 matches against)."""
import math
import os
import struct

PATHS = [
    r"C:\Users\Win2000\Downloads\Modified sym\sys\scsiport.pdb",
    r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols\sys\scsiport.pdb",
    r"C:\Users\Win2000\Downloads\symbols\sys\scsiport.pdb",
]


def read_info_sig(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:44] != b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00":
        return None
    page_size = struct.unpack_from("<I", data, 44)[0]
    # alloc table start/count then root
    root_size = struct.unpack_from("<I", data, 52)[0]
    num_root_pages = math.ceil(root_size / page_size)
    root_pages = [struct.unpack_from("<H", data, 60 + i * 2)[0]
                  for i in range(num_root_pages)]
    root = bytearray()
    for pn in root_pages:
        root += data[pn * page_size:pn * page_size + page_size]
    root = root[:root_size]
    num_streams = struct.unpack_from("<H", root, 0)[0]
    # stream table: sizes then page lists
    off = 4
    sizes = []
    for _ in range(num_streams):
        sizes.append(struct.unpack_from("<I", root, off)[0])
        off += 8
    pages = []
    for sz in sizes:
        cnt = math.ceil(sz / page_size) if sz not in (0, 0xFFFFFFFF) else 0
        pl = [struct.unpack_from("<H", root, off + j * 2)[0] for j in range(cnt)]
        off += cnt * 2
        pages.append(pl)
    # stream 1 = PDB info
    s1 = bytearray()
    for pn in pages[1]:
        s1 += data[pn * page_size:pn * page_size + page_size]
    s1 = s1[:sizes[1]]
    version = struct.unpack_from("<I", s1, 0)[0]
    signature = struct.unpack_from("<I", s1, 4)[0]
    age = struct.unpack_from("<I", s1, 8)[0]
    return version, signature, age


for p in PATHS:
    if os.path.isfile(p):
        r = read_info_sig(p)
        if r:
            v, s, a = r
            print(f"{p}\n  version={v} signature=0x{s:08X} age={a}")
        else:
            print(f"{p}\n  not PDB 2.0")
    else:
        print(f"{p}\n  MISSING")
print("\nNB10 in deployed .dbg expects sig=0x50A1E01D age=1")
