"""PDB 7.0 symbol-record helpers (DBI + S_PUB32 walk)."""
from __future__ import annotations

import struct
from typing import Iterator, List, Optional, Tuple

# S_PUB32_16t (PDB 2.0 style) and S_PUB32 (PDB 7 style)
PUB_RECTYPES = (0x1009, 0x110E)


def dbi_stream_indices(dbi: bytes) -> Optional[Tuple[int, int, int]]:
    """Return (snGSSyms, snPSSyms, snSymRecs) from a DBI stream."""
    if len(dbi) < 24:
        return None
    if struct.unpack_from('<I', dbi, 0)[0] == 0xFFFFFFFF:
        sn_gs = struct.unpack_from('<H', dbi, 12)[0]
        sn_ps = struct.unpack_from('<H', dbi, 16)[0]
        sn_sym = struct.unpack_from('<H', dbi, 20)[0]
    else:
        sn_gs = struct.unpack_from('<H', dbi, 0)[0]
        sn_ps = struct.unpack_from('<H', dbi, 2)[0]
        sn_sym = struct.unpack_from('<H', dbi, 4)[0]
    return sn_gs, sn_ps, sn_sym


def walk_pub32(symrec: bytes) -> Iterator[Tuple[int, bytes, int, int]]:
    """Yield (rec_offset, name_bytes, segment, offset) for public symbols."""
    so = 0
    n = len(symrec)
    while so + 4 <= n:
        reclen = struct.unpack_from('<H', symrec, so)[0]
        if reclen < 2 or so + 2 + reclen > n:
            break
        rectyp = struct.unpack_from('<H', symrec, so + 2)[0]
        if rectyp in PUB_RECTYPES:
            rec = symrec[so + 4:so + 2 + reclen]
            if rectyp == 0x1009 and len(rec) >= 11:
                offset_val = struct.unpack_from('<I', rec, 4)[0]
                segment = struct.unpack_from('<H', rec, 8)[0]
                name_len = rec[10]
                name = rec[11:11 + name_len]
                yield so, name, segment, offset_val
            elif rectyp == 0x110E and len(rec) >= 10:
                # S_PUB32: flags(u32) offset(u32) segment(u16) name
                offset_val = struct.unpack_from('<I', rec, 4)[0]
                segment = struct.unpack_from('<H', rec, 8)[0]
                name = _read_nz_name(rec, 10)
                if name:
                    yield so, name, segment, offset_val
        step = 2 + reclen
        if step % 4:
            step += 4 - (step % 4)
        so += step


def _read_nz_name(rec: bytes, off: int) -> bytes:
    end = rec.find(b'\x00', off)
    if end < 0:
        end = len(rec)
    return rec[off:end]


def load_public_symbols_from_pdb70(pdb_path: str, pe_path: str = None,
                                   image_base: int = 0):
    """Load {va: name} from a PDB 7.0 file.  Returns (symbols, meta)."""
    from nt_analyzer.pdb70.msf import parse_msf70
    from nt_analyzer.pdb70.segment_map import (
        parse_section_map, pe_section_layout, resolve_segment_rva,
    )
    from nt_analyzer.symbol_loader import _undecorate

    meta = {'format': 'pdb70', 'source': pdb_path}
    symbols = {}
    p = parse_msf70(pdb_path)
    if not p:
        meta['error'] = 'not a valid MSF 7.00 file'
        return symbols, meta

    dbi = p['read_stream'](3)
    section_map = parse_section_map(dbi)
    idx = dbi_stream_indices(dbi)
    if not idx:
        meta['error'] = 'no DBI header'
        return symbols, meta
    _sn_gs, _sn_ps, sn_sym = idx
    symrec = p['read_stream'](sn_sym)
    if not symrec:
        meta['error'] = 'empty symbol-record stream'
        return symbols, meta

    section_vas: list = []
    section_vsz: list = []
    base = image_base
    if pe_path:
        try:
            import pefile
            section_vas, section_vsz = pe_section_layout(pe_path)
            if base == 0:
                pe = pefile.PE(pe_path, fast_load=True)
                base = pe.OPTIONAL_HEADER.ImageBase
                pe.close()
        except Exception as e:
            meta['pe_warning'] = str(e)

    for _ro, name, segment, offset_val in walk_pub32(symrec):
        clean = _undecorate(name.decode('ascii', errors='replace'))
        if not clean or clean.startswith('.'):
            continue
        rva = resolve_segment_rva(
            segment, offset_val, section_map, section_vas, section_vsz)
        if rva is None:
            continue
        va = (base + rva) if base else rva
        symbols[va] = clean

    meta['total_symbols'] = len(symbols)
    meta['symbol_stream'] = sn_sym
    meta['section_map_entries'] = len(section_map)
    return symbols, meta
