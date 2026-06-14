"""PDB 7.0 DBI section-map parsing and OMF segment -> RVA resolution."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

DBI_HDR_SIZE = 64


@dataclass(frozen=True)
class SectionMapEntry:
    """One logical OMF segment descriptor from the DBI section-map substream."""
    index: int          # 1-based logical segment index
    frame: int          # 1-based PE section index (image section table)
    flags: int
    map_offset: int
    logical_size: int


def dbi_substream_sizes(dbi: bytes) -> Tuple[int, int, int]:
    """Return (mod_info_size, sec_contrib_size, sec_map_size)."""
    return (
        struct.unpack_from('<i', dbi, 24)[0],
        struct.unpack_from('<i', dbi, 28)[0],
        struct.unpack_from('<i', dbi, 32)[0],
    )


def parse_section_map(dbi: bytes) -> List[SectionMapEntry]:
    """Parse the section-map substream embedded in a DBI stream."""
    modi_sz, sec_sz, sm_sz = dbi_substream_sizes(dbi)
    base = DBI_HDR_SIZE + modi_sz + sec_sz
    sm = dbi[base:base + sm_sz]
    if len(sm) < 4:
        return []

    count, _log_count = struct.unpack_from('<HH', sm, 0)
    entries: List[SectionMapEntry] = []
    for i in range(count):
        off = 4 + i * 20
        if off + 20 > len(sm):
            break
        flags, _ovl, _grp, frame, _sname, _cname, map_off, lsize = \
            struct.unpack_from('<HHHHHHI I', sm, off)
        entries.append(SectionMapEntry(
            index=i + 1,
            frame=frame,
            flags=flags,
            map_offset=map_off,
            logical_size=lsize,
        ))
    return entries


def pe_section_layout(pe_path: str) -> Tuple[List[int], List[int]]:
    """Return parallel lists of section RVAs and virtual sizes."""
    import pefile
    pe = pefile.PE(pe_path, fast_load=True)
    vas = [s.VirtualAddress for s in pe.sections]
    vsz = [s.Misc_VirtualSize for s in pe.sections]
    pe.close()
    return vas, vsz


def resolve_frame_rva(segment: int, offset: int,
                      section_map: Sequence[SectionMapEntry],
                      section_vas: Sequence[int]) -> Optional[int]:
    """Resolve a public symbol the way dbghelp / WinDbg does.

    Uses ``section_map[segment-1].frame`` as a 1-based PE section index into
    the *loaded* module's section table — no OMF spill adjustment.
    """
    if segment <= 0 or offset < 0:
        return None
    n_pe = len(section_vas)
    if n_pe == 0:
        return int(offset)
    frame = segment
    if section_map and 1 <= segment <= len(section_map):
        ent = section_map[segment - 1]
        if ent.frame > 0:
            frame = ent.frame
    if 1 <= frame <= n_pe:
        return section_vas[frame - 1] + offset
    return int(offset)


def rva_to_section_offset(rva: int, section_vas: Sequence[int],
                          section_vsz: Sequence[int]) -> Optional[Tuple[int, int]]:
    """Map an image RVA to ``(1-based section index, section offset)``."""
    if rva < 0:
        return None
    best: Optional[Tuple[int, int]] = None
    for i, base in enumerate(section_vas):
        end = base + max(section_vsz[i], 1)
        if base <= rva < end:
            best = (i + 1, rva - base)
    return best


def resolve_segment_rva(segment: int, offset: int,
                      section_map: Sequence[SectionMapEntry],
                      section_vas: Sequence[int],
                      section_vsz: Sequence[int]) -> Optional[int]:
    """Map a public-symbol (segment, offset) pair to an image RVA.

    MSVC sometimes records symbols against a *logical* OMF segment whose
    mapped PE section (``frame``) is physically smaller than the logical
    segment size in the PDB section map.  When ``offset`` exceeds the
    physical section size but remains inside the logical segment, the
    address spills into the preceding PE section — observed for HAL
    ``halmacpi.pdb`` segment 8 (INIT tail symbols tagged against .rsrc).
    """
    if segment <= 0 or offset < 0:
        return None

    n_pe = len(section_vas)
    if n_pe == 0:
        return int(offset)

    # Primary: section-map-aware resolution.
    if section_map and 1 <= segment <= len(section_map):
        ent = section_map[segment - 1]
        frame = ent.frame
        if 1 <= frame <= n_pe:
            base = section_vas[frame - 1]
            phys = section_vsz[frame - 1]
            if offset < phys:
                return base + offset
            if (offset < ent.logical_size and frame > 1
                    and ent.logical_size != 0xFFFFFFFF):
                return section_vas[frame - 2] + offset
            return base + offset

    # Fallback: naive PE section index (legacy behaviour).
    if segment <= n_pe:
        return section_vas[segment - 1] + offset
    return int(offset)


def build_frame_remap(orig_pe_path: str, patched_pe_path: str) -> Dict[int, int]:
    """Map 1-based orig PE section index -> 1-based patched PE section index."""
    import pefile

    def names(path: str) -> List[str]:
        pe = pefile.PE(path, fast_load=True)
        ns = [s.Name.rstrip(b'\x00').decode('ascii', 'replace')
              for s in pe.sections]
        pe.close()
        return ns

    orig = names(orig_pe_path)
    patched = names(patched_pe_path)
    remap: Dict[int, int] = {}
    for i, name in enumerate(orig, 1):
        if name in patched:
            remap[i] = patched.index(name) + 1
    return remap


def patch_section_map_frames(dbi: bytes, frame_remap: Dict[int, int]) -> bytes:
    """Rewrite ``frame`` fields in the DBI section-map substream."""
    modi_sz, sec_sz, sm_sz = dbi_substream_sizes(dbi)
    base = DBI_HDR_SIZE + modi_sz + sec_sz
    if sm_sz <= 0 or base + sm_sz > len(dbi):
        return dbi
    out = bytearray(dbi)
    sm = memoryview(out)[base:base + sm_sz]
    count = struct.unpack_from('<H', sm, 0)[0]
    for i in range(count):
        off = 4 + i * 20
        if off + 20 > sm_sz:
            break
        frame = struct.unpack_from('<H', sm, off + 6)[0]
        if frame in frame_remap:
            struct.pack_into('<H', out, base + off + 6, frame_remap[frame])
    return bytes(out)


def load_section_map_from_pdb70(pdb_path: str) -> List[SectionMapEntry]:
    from nt_analyzer.pdb70.msf import parse_msf70
    msf = parse_msf70(pdb_path)
    if not msf:
        return []
    return parse_section_map(msf['read_stream'](3))
