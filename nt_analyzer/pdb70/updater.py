"""PDB 7.0 symbol patch / inject / validate / publics re-index."""
from __future__ import annotations

import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from nt_analyzer.pdb70.msf import parse_msf70, replace_stream_bytes, write_msf70
from nt_analyzer.pdb70.symbols import (
    PUB_RECTYPES, dbi_stream_indices, walk_pub32,
)
from nt_analyzer.ubrt_engine import SymbolUpdater


class SymbolUpdater70:
    """PDB 7.0 (MSF 7.00) operations — separate from PDB 2.0 ``SymbolUpdater``."""

    @staticmethod
    def _load_msf(path: str):
        msf = parse_msf70(path)
        if not msf:
            raise ValueError(f'Not a valid PDB 7.0 file: {path}')
        return msf

    @staticmethod
    def _sym_stream_index(msf) -> int:
        dbi = msf['read_stream'](3)
        idx = dbi_stream_indices(dbi)
        if not idx:
            raise ValueError('No DBI header')
        return idx[2]

    @staticmethod
    def _section_layout(pe_path: str, image_base: int = 0):
        from nt_analyzer.pdb70.segment_map import pe_section_layout
        section_vas, section_vsz = pe_section_layout(pe_path)
        ib = image_base
        if pe_path and ib == 0:
            import pefile
            pe = pefile.PE(pe_path, fast_load=True)
            ib = pe.OPTIONAL_HEADER.ImageBase
            pe.close()
        return section_vas, section_vsz, ib

    @classmethod
    def _segment_map(cls, msf) -> list:
        from nt_analyzer.pdb70.segment_map import parse_section_map
        return parse_section_map(msf['read_stream'](3))

    @classmethod
    def _resolve_rva(cls, segment: int, offset: int, msf,
                     section_vas, section_vsz) -> int:
        from nt_analyzer.pdb70.segment_map import resolve_segment_rva
        sm = cls._segment_map(msf)
        rva = resolve_segment_rva(segment, offset, sm, section_vas, section_vsz)
        if rva is None:
            if 1 <= segment <= len(section_vas):
                return section_vas[segment - 1] + offset
            return offset
        return rva

    @staticmethod
    def _section_vas(pe_path: str, image_base: int = 0):
        section_vas, _vsz, ib = SymbolUpdater70._section_layout(
            pe_path, image_base)
        # Legacy dict: 1-based section index -> RVA (patch/inject compat).
        return {i + 1: va for i, va in enumerate(section_vas)}, ib

    @classmethod
    def patch_pdb_file(cls, pdb_path: str, shift_rva: int, delta: int,
                       pe_path: str = None,
                       image_base: int = 0,
                       orig_frame: int = 0) -> Dict[str, Any]:
        """Patch public offsets for one PE section (by 1-based frame index).

        Prefer ``remap_publics_by_address`` for PDB 7.0 HAL-style exports.
        """
        result: Dict[str, Any] = {
            'patched': 0, 'total': 0, 'format': 'pdb70', 'errors': []}
        if delta == 0:
            return result
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            result['errors'].append(str(e))
            return result

        section_map = cls._segment_map(msf)
        try:
            sn_sym = cls._sym_stream_index(msf)
        except ValueError as e:
            result['errors'].append(str(e))
            return result

        symrec = bytearray(msf['read_stream'](sn_sym))
        so = 0
        while so + 4 <= len(symrec):
            reclen = struct.unpack_from('<H', symrec, so)[0]
            if reclen < 2 or so + 2 + reclen > len(symrec):
                break
            rectyp = struct.unpack_from('<H', symrec, so + 2)[0]
            if rectyp in PUB_RECTYPES:
                result['total'] += 1
                rec = symrec[so + 4:so + 2 + reclen]
                if rectyp == 0x1009 and len(rec) >= 11:
                    offset_val = struct.unpack_from('<I', rec, 4)[0]
                    segment = struct.unpack_from('<H', rec, 8)[0]
                    off_field = so + 8
                elif rectyp == 0x110E and len(rec) >= 10:
                    offset_val = struct.unpack_from('<I', rec, 4)[0]
                    segment = struct.unpack_from('<H', rec, 8)[0]
                    off_field = so + 8
                else:
                    so += 2 + reclen
                    if so % 4:
                        so += 4 - so % 4
                    continue
                frame = segment
                if section_map and 1 <= segment <= len(section_map):
                    frame = section_map[segment - 1].frame or segment
                if orig_frame and frame != orig_frame:
                    pass
                else:
                    new_off = offset_val + delta
                    if new_off >= 0:
                        struct.pack_into('<I', symrec, off_field,
                                         new_off & 0xFFFFFFFF)
                        result['patched'] += 1
            step = 2 + reclen
            if step % 4:
                step += 4 - step % 4
            so += step

        if result['patched'] and not replace_stream_bytes(msf, sn_sym, bytes(symrec)):
            result['errors'].append('Failed to write symbol stream')
            return result
        if result['patched']:
            try:
                write_msf70(msf, pdb_path)
            except OSError as e:
                result['errors'].append(str(e))
        return result

    @classmethod
    def patch_section_map_for_pe(cls, pdb_path: str, orig_pe_path: str,
                                 patched_pe_path: str) -> Dict[str, Any]:
        """Remap DBI section-map frame numbers for a patched PE layout."""
        from nt_analyzer.pdb70.segment_map import (
            build_frame_remap, patch_section_map_frames,
        )
        result: Dict[str, Any] = {'patched': False, 'frames': {}, 'errors': []}
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            result['errors'].append(str(e))
            return result
        if not orig_pe_path or not patched_pe_path:
            result['errors'].append('orig and patched PE paths required')
            return result
        frame_remap = build_frame_remap(orig_pe_path, patched_pe_path)
        if not frame_remap:
            result['errors'].append('empty frame remap')
            return result
        dbi = bytearray(msf['read_stream'](3))
        new_dbi = patch_section_map_frames(bytes(dbi), frame_remap)
        if new_dbi == bytes(dbi):
            result['errors'].append('section map unchanged')
            return result
        if not replace_stream_bytes(msf, 3, new_dbi):
            result['errors'].append('failed to write DBI stream')
            return result
        try:
            write_msf70(msf, pdb_path)
            result['patched'] = True
            result['frames'] = frame_remap
        except OSError as e:
            result['errors'].append(str(e))
        return result

    @classmethod
    def remap_publics_by_address(cls, pdb_path: str, recovered,
                               patched_pe_path: str,
                               image_base: int = 0) -> Dict[str, Any]:
        """Rewrite PDB 7.0 public records from recovered symbol VAs.

        WinDbg resolves ``S_PUB32`` via ``section_map[seg-1].frame`` against
        the loaded PE section table (no OMF spill).  After a section insertion
        such as HAL ``.xcode``, incremental RVA-threshold patching mis-places
        symbols; rebinding each public to its recovered VA on the patched
        image fixes both out-of-image and wrong-section addresses.
        """
        from nt_analyzer.symbol_loader import _undecorate
        from nt_analyzer.pdb70.segment_map import (
            parse_section_map, rva_to_section_offset,
        )

        result: Dict[str, Any] = {
            'remapped': 0, 'total': 0, 'unmatched': 0,
            'format': 'pdb70', 'errors': [],
        }
        if not recovered:
            result['errors'].append('No recovered symbols')
            return result
        try:
            msf = cls._load_msf(pdb_path)
            sn_sym = cls._sym_stream_index(msf)
        except ValueError as e:
            result['errors'].append(str(e))
            return result

        section_vas, section_vsz, ib = cls._section_layout(
            patched_pe_path, image_base)
        base = image_base or ib
        section_map = parse_section_map(msf['read_stream'](3))

        def logseg_for_frame(frame: int) -> int:
            for ent in section_map:
                if ent.frame == frame:
                    return ent.index
            return frame

        by_name: Dict[str, int] = {}
        for r in recovered:
            if getattr(r, 'status', '') in ('ok', 'discovered'):
                by_name[r.name] = r.recovered_va
        # Export table is authoritative for exported functions — the MS PDB
        # geometry can differ from the user's build, but exports always point
        # at the true entry in the loaded image.
        anchors = cls._export_anchors(patched_pe_path, base)
        result['export_anchors'] = len(anchors)
        by_name.update(anchors)

        symrec = bytearray(msf['read_stream'](sn_sym))
        so = 0
        while so + 4 <= len(symrec):
            reclen = struct.unpack_from('<H', symrec, so)[0]
            if reclen < 2 or so + 2 + reclen > len(symrec):
                break
            rectyp = struct.unpack_from('<H', symrec, so + 2)[0]
            if rectyp in PUB_RECTYPES:
                result['total'] += 1
                rec = symrec[so + 4:so + 2 + reclen]
                if rectyp == 0x1009 and len(rec) >= 11:
                    name_len = rec[10]
                    raw = rec[11:11 + name_len]
                    off_field = so + 8
                    seg_field = so + 12
                elif rectyp == 0x110E and len(rec) >= 10:
                    end = rec.find(b'\x00', 10)
                    raw = rec[10:end if end >= 0 else len(rec)]
                    off_field = so + 8
                    seg_field = so + 12
                else:
                    so += 2 + reclen
                    if so % 4:
                        so += 4 - (so % 4)
                    continue

                clean = _undecorate(raw.decode('ascii', errors='replace'))
                va = by_name.get(clean)
                if va is None:
                    result['unmatched'] += 1
                else:
                    rva = va - base
                    mapped = rva_to_section_offset(
                        rva, section_vas, section_vsz)
                    if mapped is None:
                        result['unmatched'] += 1
                    else:
                        pe_sec, off = mapped
                        seg = logseg_for_frame(pe_sec)
                        struct.pack_into('<I', symrec, off_field,
                                         off & 0xFFFFFFFF)
                        struct.pack_into('<H', symrec, seg_field, seg)
                        result['remapped'] += 1
            step = 2 + reclen
            if step % 4:
                step += 4 - (step % 4)
            so += step

        if result['remapped'] == 0:
            result['errors'].append('No public symbols remapped')
            return result
        if not replace_stream_bytes(msf, sn_sym, bytes(symrec)):
            result['errors'].append('Failed to write symbol stream')
            return result
        try:
            write_msf70(msf, pdb_path)
        except OSError as e:
            result['errors'].append(str(e))
        return result

    # Address-bearing CodeView records in module symbol streams.
    # type -> (off_field, seg_field, name_field) relative to record start.
    _ADDR_RECS = {
        0x110C: (8, 12, 14),    # S_LDATA32
        0x110D: (8, 12, 14),    # S_GDATA32
        0x110E: (8, 12, 14),    # S_PUB32
        0x1111: (8, 12, 14),    # S_LDATA32 (alt)
        0x110F: (32, 36, 39),   # S_LPROC32
        0x1110: (32, 36, 39),   # S_GPROC32
        0x1146: (32, 36, 39),   # S_LPROC32_ID
        0x1147: (32, 36, 39),   # S_GPROC32_ID
        0x1105: (4, 8, 11),     # S_LABEL32
        0x1112: (8, 12, 14),    # S_LTHREAD32
        0x1113: (8, 12, 14),    # S_GTHREAD32
    }

    @staticmethod
    def _export_anchors(pe_path: str, image_base: int) -> Dict[str, int]:
        """Return ``{undecorated_export_name: image_base + export_rva}``.

        Exported function RVAs are the ground truth for the loaded image,
        independent of which build the PDB was produced from.
        """
        anchors: Dict[str, int] = {}
        if not pe_path:
            return anchors
        try:
            import pefile
            pe = pefile.PE(pe_path)
            ib = image_base or pe.OPTIONAL_HEADER.ImageBase
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if s.name and s.address:
                        anchors[s.name.decode('ascii', 'replace')] = ib + s.address
            pe.close()
        except Exception:
            pass
        return anchors

    @classmethod
    def _parse_modules(cls, dbi: bytes):
        """Yield ``(stream_no, module_name)`` for each DBI module info entry."""
        modi_sz = struct.unpack_from('<i', dbi, 24)[0]
        base = 64
        end = base + modi_sz
        off = base
        while off + 64 <= end:
            sn = struct.unpack_from('<H', dbi, off + 34)[0]
            name_off = off + 64
            nend = dbi.find(b'\x00', name_off)
            if nend < 0:
                break
            name = dbi[name_off:nend].decode('ascii', 'replace')
            oend = dbi.find(b'\x00', nend + 1)
            if oend < 0:
                oend = nend
            rec_end = oend + 1
            if rec_end % 4:
                rec_end += 4 - (rec_end % 4)
            yield sn, name
            off = rec_end

    @classmethod
    def remap_module_symbols(cls, pdb_path: str, recovered,
                             patched_pe_path: str,
                             image_base: int = 0) -> Dict[str, Any]:
        """Re-encode address-bearing private symbols in module streams.

        WinDbg's ``private symbols & lines`` view resolves procedures and data
        from per-module CodeView streams (S_GPROC32 etc.), not the publics
        stream.  Those records keep the original (segment, offset); after a
        section insertion / build mismatch they point at the wrong section
        (e.g. ``HalInitSystem`` landing past the image).  Rebind each record
        whose name matches a recovered/exported address.
        """
        from nt_analyzer.symbol_loader import _undecorate
        from nt_analyzer.pdb70.segment_map import (
            parse_section_map, rva_to_section_offset,
        )

        result: Dict[str, Any] = {
            'remapped': 0, 'unmatched': 0, 'modules': 0,
            'format': 'pdb70', 'errors': [],
        }
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            result['errors'].append(str(e))
            return result

        section_vas, section_vsz, ib = cls._section_layout(
            patched_pe_path, image_base)
        base = image_base or ib
        dbi = msf['read_stream'](3)
        section_map = parse_section_map(dbi)

        def logseg_for_frame(frame: int) -> int:
            for ent in section_map:
                if ent.frame == frame:
                    return ent.index
            return frame

        by_name: Dict[str, int] = {}
        for r in recovered or ():
            if getattr(r, 'status', '') in ('ok', 'discovered'):
                by_name[r.name] = r.recovered_va
        by_name.update(cls._export_anchors(patched_pe_path, base))
        if not by_name:
            result['errors'].append('No address anchors')
            return result

        modules = list(cls._parse_modules(dbi))
        for sn, _name in modules:
            if sn in (0xFFFF, 0xFFFFFFFF) or sn >= msf['num_streams']:
                continue
            stream = bytearray(msf['read_stream'](sn))
            if len(stream) < 4:
                continue
            result['modules'] += 1
            changed = False
            so = 4  # skip CV signature
            n = len(stream)
            while so + 4 <= n:
                reclen = struct.unpack_from('<H', stream, so)[0]
                if reclen < 2 or so + 2 + reclen > n:
                    break
                rectyp = struct.unpack_from('<H', stream, so + 2)[0]
                spec = cls._ADDR_RECS.get(rectyp)
                if spec:
                    offf, segf, namef = spec
                    if so + namef <= n:
                        nend = stream.find(b'\x00', so + namef)
                        if nend < 0:
                            nend = n
                        raw = stream[so + namef:nend].decode(
                            'ascii', errors='replace')
                        clean = _undecorate(raw)
                        va = by_name.get(clean)
                        if va is None and raw != clean:
                            va = by_name.get(raw)
                        if va is not None:
                            mapped = rva_to_section_offset(
                                va - base, section_vas, section_vsz)
                            if mapped is None:
                                result['unmatched'] += 1
                            else:
                                pe_sec, off = mapped
                                seg = logseg_for_frame(pe_sec)
                                struct.pack_into('<I', stream, so + offf,
                                                 off & 0xFFFFFFFF)
                                struct.pack_into('<H', stream, so + segf, seg)
                                result['remapped'] += 1
                                changed = True
                        else:
                            result['unmatched'] += 1
                step = 2 + reclen
                if step % 4:
                    step += 4 - (step % 4)
                so += step
            if changed:
                if not replace_stream_bytes(msf, sn, bytes(stream)):
                    result['errors'].append(f'write failed stream {sn}')
                    return result

        if result['remapped']:
            try:
                write_msf70(msf, pdb_path)
            except OSError as e:
                result['errors'].append(str(e))
        return result

    @staticmethod
    def _make_pub32_record(name: str, segment: int, offset: int,
                           use_110e: bool = True) -> bytes:
        name_bytes = name.encode('ascii', errors='replace')[:255]
        if use_110e:
            payload = struct.pack('<I', 0)
            payload += struct.pack('<I', offset & 0xFFFFFFFF)
            payload += struct.pack('<H', segment)
            payload += name_bytes + b'\x00'
            reclen = 2 + len(payload)
            rec = struct.pack('<HH', reclen, 0x110E) + payload
        else:
            reclen = 2 + 4 + 4 + 2 + 1 + len(name_bytes)
            rec = struct.pack('<HH', reclen, 0x1009)
            rec += struct.pack('<I', 0)
            rec += struct.pack('<I', offset & 0xFFFFFFFF)
            rec += struct.pack('<H', segment)
            rec += struct.pack('<B', len(name_bytes))
            rec += name_bytes
        if len(rec) % 4:
            rec += b'\x00' * (4 - len(rec) % 4)
        return rec

    @classmethod
    def inject_symbols_pdb(cls, pdb_path: str, symbols: Dict[int, str],
                           pe_path: str,
                           image_base: int = 0) -> Dict[str, Any]:
        result: Dict[str, Any] = {'injected': 0, 'errors': []}
        if not symbols:
            return result
        try:
            msf = cls._load_msf(pdb_path)
            sn_sym = cls._sym_stream_index(msf)
        except ValueError as e:
            result['errors'].append(str(e))
            return result

        section_vas, ib = cls._section_vas(pe_path, image_base)

        def va_to_seg_off(va: int):
            rva = va - ib
            for i, (sec_rva, sec_vs, _) in enumerate(
                    cls._pe_sections(pe_path)):
                if sec_rva <= rva <= sec_rva + max(sec_vs, 1):
                    return i + 1, rva - sec_rva
            return None

        new_records = bytearray()
        count = 0
        for va, name in sorted(symbols.items()):
            m = va_to_seg_off(va)
            if not m:
                continue
            seg, off = m
            new_records += cls._make_pub32_record(name, seg, off)
            count += 1
        if not new_records:
            result['errors'].append('No symbols mapped to sections')
            return result

        symrec = bytearray(msf['read_stream'](sn_sym))
        symrec += new_records
        if not replace_stream_bytes(msf, sn_sym, bytes(symrec)):
            result['errors'].append('Failed to extend symbol stream')
            return result
        try:
            write_msf70(msf, pdb_path)
            result['injected'] = count
        except OSError as e:
            result['errors'].append(str(e))
        return result

    @staticmethod
    def _pe_sections(pe_path: str):
        import pefile
        pe = pefile.PE(pe_path, fast_load=True)
        secs = [(s.VirtualAddress, s.Misc_VirtualSize,
                 s.Name.rstrip(b'\x00').decode('ascii', errors='replace'))
                for s in pe.sections]
        pe.close()
        return secs

    @classmethod
    def validate_pdb(cls, pdb_path: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            'valid': False, 'errors': [], 'streams': 0,
            'page_size': 0, 'pages': 0, 'format': 'pdb70'}
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            out['errors'].append(str(e))
            return out
        out['streams'] = msf['num_streams']
        out['page_size'] = msf['page_size']
        out['pages'] = len(msf['data']) // msf['page_size']
        dbi = msf['read_stream'](3)
        if not dbi_stream_indices(dbi):
            out['errors'].append('DBI stream missing/invalid')
        try:
            sn_sym = cls._sym_stream_index(msf)
            pubs = list(walk_pub32(msf['read_stream'](sn_sym)))
            if not pubs:
                out['errors'].append('No public symbols in symrec stream')
        except ValueError as e:
            out['errors'].append(str(e))
        out['valid'] = not out['errors']
        return out

    @classmethod
    def _pubs_triples(cls, msf) -> List[Tuple[int, str, int, int]]:
        sn_sym = cls._sym_stream_index(msf)
        symrec = msf['read_stream'](sn_sym)
        pubs = []
        for ro, name, seg, off in walk_pub32(symrec):
            pubs.append((ro, name, seg, off))
        return pubs

    @classmethod
    def verify_publics_reproducible(cls, pdb_path: str) -> Dict[str, Any]:
        res: Dict[str, Any] = {'reproducible': False, 'reason': ''}
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            res['reason'] = str(e)
            return res
        dbi = msf['read_stream'](3)
        idx = dbi_stream_indices(dbi)
        if not idx:
            res['reason'] = 'no DBI header'
            return res
        _sn_gs, sn_ps, sn_sym = idx
        pubstream = msf['read_stream'](sn_ps)
        pubs = cls._pubs_triples(msf)
        if not pubs:
            res['reason'] = 'no public symbols'
            return res
        variant = SymbolUpdater._find_publics_variant(pubs, pubstream)
        if variant:
            res['reproducible'] = True
            res['variant'] = variant
            res['sn_ps'] = sn_ps
            res['sn_sym'] = sn_sym
            res['publics'] = len(pubs)
        else:
            res['reason'] = 'no variant matched (PDB 7.0 publics layout)'
        return res

    @classmethod
    def rebuild_publics_index(cls, pdb_path: str,
                              variant=None) -> Dict[str, Any]:
        res: Dict[str, Any] = {'reindexed': False, 'publics': 0, 'errors': []}
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            res['errors'].append(str(e))
            return res
        dbi = msf['read_stream'](3)
        idx = dbi_stream_indices(dbi)
        if not idx:
            res['errors'].append('no DBI header')
            return res
        _sn_gs, sn_ps, sn_sym = idx
        pubstream = msf['read_stream'](sn_ps)
        pubs = cls._pubs_triples(msf)
        if variant is None:
            variant = {'fmt': 'new', 'off_base': 1, 'cref': 1, 'stride': 12,
                       'bucket_sort': 'len_name'}
        new_pub = SymbolUpdater._serialize_publics_stream(
            pubs, pubstream, variant)
        if new_pub is None:
            res['errors'].append('publics stream not modellable')
            return res
        if not replace_stream_bytes(msf, sn_ps, new_pub):
            res['errors'].append('failed to rewrite publics stream')
            return res
        verify_msf = parse_msf70(bytes(msf['data']))
        if not verify_msf or verify_msf['read_stream'](sn_ps) != new_pub:
            res['errors'].append('post-write verification failed')
            return res
        try:
            write_msf70(msf, pdb_path)
        except OSError as e:
            res['errors'].append(str(e))
            return res
        res['reindexed'] = True
        res['publics'] = len(pubs)
        return res

    @classmethod
    def stamp_pdb_info(cls, pdb_path: str, signature: int,
                       age: int = None) -> Dict[str, Any]:
        """Stamp PDB stream-1 Signature/Age (same offsets as PDB 2.0 info)."""
        res: Dict[str, Any] = {'stamped': False, 'errors': []}
        try:
            msf = cls._load_msf(pdb_path)
        except ValueError as e:
            res['errors'].append(str(e))
            return res
        info = bytearray(msf['read_stream'](1))
        if len(info) < 12:
            res['errors'].append('Info stream too short')
            return res
        struct.pack_into('<I', info, 4, signature & 0xFFFFFFFF)
        if age is not None:
            struct.pack_into('<I', info, 8, age & 0xFFFFFFFF)
        if not replace_stream_bytes(msf, 1, bytes(info)):
            res['errors'].append('Failed to update info stream')
            return res
        try:
            write_msf70(msf, pdb_path)
            res['stamped'] = True
        except OSError as e:
            res['errors'].append(str(e))
        return res

    @classmethod
    def existing_public_cores(cls, pdb_path: str):
        cores = set()
        try:
            msf = cls._load_msf(pdb_path)
            for _ro, name, _s, _o in walk_pub32(
                    msf['read_stream'](cls._sym_stream_index(msf))):
                cores.add(SymbolUpdater._decorated_core(name))
        except Exception:
            pass
        return cores
