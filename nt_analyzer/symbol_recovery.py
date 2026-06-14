"""
Symbol Recovery Engine
======================
Given an original PE binary + its symbols and a patched PE binary,
compute section-level diffs, remap symbol addresses, and produce
a recovered symbol table for the patched binary.

Core algorithm:
1. Parse both PE section tables.
2. Match original sections → patched sections (by name + order).
3. Compute per-section VA deltas.
4. For each symbol, find its owning section in the original PE,
   apply the delta for that section in the patched PE.
5. Detect new/removed sections and unmatched symbols.
"""

import os
import struct
from collections import OrderedDict
from typing import Dict, List, Tuple, Optional, Any

try:
    import pefile
except ImportError:
    pefile = None


class SectionInfo:
    """Represents a PE section for comparison."""
    __slots__ = ('index', 'name', 'va', 'vsize', 'raw_offset', 'raw_size', 'chars')

    def __init__(self, index, name, va, vsize, raw_offset, raw_size, chars):
        self.index = index
        self.name = name
        self.va = va
        self.vsize = vsize
        self.raw_offset = raw_offset
        self.raw_size = raw_size
        self.chars = chars

    def __repr__(self):
        return f"<Section [{self.index}] {self.name} VA=0x{self.va:X} VSize=0x{self.vsize:X}>"


class SectionMatch:
    """A matched pair of original → patched sections."""
    __slots__ = ('orig', 'patched', 'va_delta', 'vsize_delta', 'confidence')

    def __init__(self, orig: SectionInfo, patched: SectionInfo):
        self.orig = orig
        self.patched = patched
        self.va_delta = patched.va - orig.va
        self.vsize_delta = patched.vsize - orig.vsize
        self.confidence = 1.0  # 1.0 = name match, <1.0 = heuristic

    def __repr__(self):
        return (f"<Match {self.orig.name}[{self.orig.index}] -> "
                f"{self.patched.name}[{self.patched.index}] "
                f"delta={self.va_delta:+d}>")


class DiffResult:
    """Complete diff between original and patched PE files."""

    def __init__(self):
        self.orig_sections: List[SectionInfo] = []
        self.patched_sections: List[SectionInfo] = []
        self.matches: List[SectionMatch] = []
        self.new_sections: List[SectionInfo] = []      # in patched only
        self.removed_sections: List[SectionInfo] = []  # in original only
        self.orig_image_base: int = 0
        self.patched_image_base: int = 0
        self.orig_entry_rva: int = 0
        self.patched_entry_rva: int = 0
        self.orig_size: int = 0
        self.patched_size: int = 0
        self.orig_size_of_image: int = 0
        self.patched_size_of_image: int = 0
        self.header_changes: List[str] = []

    def get_section_delta(self, orig_section_index: int) -> Optional[int]:
        """Get the VA delta for a given original section index."""
        for m in self.matches:
            if m.orig.index == orig_section_index:
                return m.va_delta
        return None


class RecoveredSymbol:
    """A symbol with its original and recovered addresses."""
    __slots__ = ('name', 'orig_va', 'recovered_va', 'section_name',
                 'section_index', 'confidence', 'status')

    def __init__(self, name, orig_va, recovered_va, section_name,
                 section_index, confidence=1.0, status='ok'):
        self.name = name
        self.orig_va = orig_va
        self.recovered_va = recovered_va
        self.section_name = section_name
        self.section_index = section_index
        self.confidence = confidence
        self.status = status  # 'ok', 'unmapped', 'section_removed', 'outside'


class SymbolRecoveryEngine:
    """Main engine for binary diff and symbol recovery."""

    def __init__(self):
        self._orig_pe = None
        self._patched_pe = None
        self._diff: Optional[DiffResult] = None
        self._orig_symbols: Dict[int, str] = {}
        self._orig_meta: Dict[str, Any] = {}
        self._recovered: List[RecoveredSymbol] = []

    @property
    def diff(self) -> Optional[DiffResult]:
        return self._diff

    @property
    def recovered_symbols(self) -> List[RecoveredSymbol]:
        return self._recovered

    @property
    def orig_symbols(self) -> Dict[int, str]:
        return self._orig_symbols

    # ------------------------------------------------------------------
    #  PE section extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_sections(pe_path: str) -> Tuple[List[SectionInfo], int, int, int, int]:
        """Parse PE sections. Returns (sections, image_base, entry_rva, file_size, size_of_image)."""
        if pefile is None:
            raise ImportError("pefile is required for symbol recovery")
        pe = pefile.PE(pe_path, fast_load=True)
        sections = []
        for i, s in enumerate(pe.sections):
            name = s.Name.rstrip(b'\x00').decode('ascii', 'replace')
            sections.append(SectionInfo(
                index=i,
                name=name,
                va=s.VirtualAddress,
                vsize=s.Misc_VirtualSize,
                raw_offset=s.PointerToRawData,
                raw_size=s.SizeOfRawData,
                chars=s.Characteristics,
            ))
        ib = pe.OPTIONAL_HEADER.ImageBase
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        soi = pe.OPTIONAL_HEADER.SizeOfImage
        fs = os.path.getsize(pe_path)
        pe.close()
        return sections, ib, ep, fs, soi

    # ------------------------------------------------------------------
    #  Section matching algorithm
    # ------------------------------------------------------------------

    @staticmethod
    def _match_sections(orig: List[SectionInfo],
                        patched: List[SectionInfo]) -> Tuple[
                            List[SectionMatch],
                            List[SectionInfo],
                            List[SectionInfo]]:
        """
        Match original sections to patched sections by name and order.
        Handles duplicate section names by matching in order of appearance.

        Returns: (matches, new_sections, removed_sections)
        """
        matches = []
        used_patched = set()

        # Build name→index lists for patched sections
        patched_by_name: Dict[str, List[int]] = {}
        for s in patched:
            patched_by_name.setdefault(s.name, []).append(s.index)

        # Track which occurrence of each name we've consumed
        name_cursor: Dict[str, int] = {}

        for o in orig:
            name = o.name
            if name not in patched_by_name:
                continue
            cursor = name_cursor.get(name, 0)
            candidates = patched_by_name[name]
            # Find next unused candidate
            while cursor < len(candidates) and candidates[cursor] in used_patched:
                cursor += 1
            if cursor < len(candidates):
                p_idx = candidates[cursor]
                p = patched[p_idx]
                m = SectionMatch(o, p)
                matches.append(m)
                used_patched.add(p_idx)
                name_cursor[name] = cursor + 1
            # else: no more patched sections with this name

        matched_orig = {m.orig.index for m in matches}
        removed = [s for s in orig if s.index not in matched_orig]
        new = [s for s in patched if s.index not in used_patched]

        return matches, new, removed

    # ------------------------------------------------------------------
    #  Binary diff
    # ------------------------------------------------------------------

    def diff_binaries(self, orig_path: str, patched_path: str) -> DiffResult:
        """Compare two PE files and produce a full diff result."""
        o_secs, o_ib, o_ep, o_fs, o_soi = self._parse_sections(orig_path)
        p_secs, p_ib, p_ep, p_fs, p_soi = self._parse_sections(patched_path)

        matches, new_secs, removed_secs = self._match_sections(o_secs, p_secs)

        diff = DiffResult()
        diff.orig_sections = o_secs
        diff.patched_sections = p_secs
        diff.matches = matches
        diff.new_sections = new_secs
        diff.removed_sections = removed_secs
        diff.orig_image_base = o_ib
        diff.patched_image_base = p_ib
        diff.orig_entry_rva = o_ep
        diff.patched_entry_rva = p_ep
        diff.orig_size = o_fs
        diff.patched_size = p_fs
        diff.orig_size_of_image = o_soi
        diff.patched_size_of_image = p_soi

        # Detect notable header changes
        if o_ib != p_ib:
            diff.header_changes.append(
                f"ImageBase changed: 0x{o_ib:X} → 0x{p_ib:X}")
        if o_ep != p_ep:
            diff.header_changes.append(
                f"EntryPoint RVA changed: 0x{o_ep:X} → 0x{p_ep:X}")
        if o_soi != p_soi:
            diff.header_changes.append(
                f"SizeOfImage changed: 0x{o_soi:X} → 0x{p_soi:X}")
        size_delta = p_fs - o_fs
        if size_delta != 0:
            diff.header_changes.append(
                f"File size changed: {o_fs:,} → {p_fs:,} ({size_delta:+,} bytes)")
        if len(o_secs) != len(p_secs):
            diff.header_changes.append(
                f"Section count changed: {len(o_secs)} → {len(p_secs)}")

        self._diff = diff
        return diff

    # ------------------------------------------------------------------
    #  Symbol loading
    # ------------------------------------------------------------------

    def load_symbols(self, symbol_path: str, image_base: int = 0,
                     pe_path: str = None) -> Tuple[int, Dict[str, Any]]:
        """Load symbols from a .pdb/.dbg/.map/.sym file.
        Returns (count, metadata)."""
        from nt_analyzer.symbol_loader import load_symbols
        syms, meta = load_symbols(symbol_path, image_base=image_base,
                                  pe_path=pe_path)
        self._orig_symbols = syms
        self._orig_meta = meta
        return len(syms), meta

    # ------------------------------------------------------------------
    #  Symbol recovery
    # ------------------------------------------------------------------

    def recover_symbols(self, orig_pe_path: str = None) -> List[RecoveredSymbol]:
        """
        Remap original symbols to patched addresses using the section diff.
        Must call diff_binaries() and load_symbols() first.

        For each symbol:
        1. Determine which original section it belongs to (by VA range)
        2. Find the matched patched section
        3. Compute: recovered_va = orig_va + section_va_delta + image_base_delta

        Returns list of RecoveredSymbol.
        """
        if self._diff is None:
            raise RuntimeError("Call diff_binaries() first")
        if not self._orig_symbols:
            raise RuntimeError("Call load_symbols() first")

        diff = self._diff
        ib_delta = diff.patched_image_base - diff.orig_image_base
        recovered = []

        # Build section ranges from original: (va_start, va_end, section_index)
        orig_ranges = []
        for s in diff.orig_sections:
            # Use image_base-relative VAs for matching against symbols
            start_va = diff.orig_image_base + s.va
            end_va = start_va + s.vsize
            orig_ranges.append((start_va, end_va, s.index, s.name))

        # Pre-build match lookup by original section index
        match_by_orig = {m.orig.index: m for m in diff.matches}
        removed_indices = {s.index for s in diff.removed_sections}

        for va, name in sorted(self._orig_symbols.items()):
            # Find which original section owns this va
            owning_section = None
            for start, end, idx, sec_name in orig_ranges:
                if start <= va < end:
                    owning_section = (idx, sec_name)
                    break

            if owning_section is None:
                # Symbol outside any section — try closest match or keep as-is
                rec = RecoveredSymbol(
                    name=name, orig_va=va,
                    recovered_va=va + ib_delta,
                    section_name='<none>',
                    section_index=-1,
                    confidence=0.3,
                    status='outside'
                )
                recovered.append(rec)
                continue

            sec_idx, sec_name = owning_section

            if sec_idx in removed_indices:
                rec = RecoveredSymbol(
                    name=name, orig_va=va,
                    recovered_va=va,
                    section_name=sec_name,
                    section_index=sec_idx,
                    confidence=0.0,
                    status='section_removed'
                )
                recovered.append(rec)
                continue

            m = match_by_orig.get(sec_idx)
            if m is None:
                # Unmatched (shouldn't happen if not removed)
                rec = RecoveredSymbol(
                    name=name, orig_va=va,
                    recovered_va=va + ib_delta,
                    section_name=sec_name,
                    section_index=sec_idx,
                    confidence=0.2,
                    status='unmapped'
                )
                recovered.append(rec)
                continue

            # Apply section delta + image base delta
            new_va = va + m.va_delta + ib_delta
            conf = m.confidence
            # Lower confidence if VSize changed significantly
            if m.orig.vsize > 0:
                size_ratio = abs(m.vsize_delta) / m.orig.vsize
                if size_ratio > 0.5:
                    conf *= 0.5
                elif size_ratio > 0.1:
                    conf *= 0.8

            rec = RecoveredSymbol(
                name=name, orig_va=va,
                recovered_va=new_va,
                section_name=sec_name,
                section_index=sec_idx,
                confidence=conf,
                status='ok'
            )
            recovered.append(rec)

        self._recovered = recovered
        return recovered

    # ------------------------------------------------------------------
    #  Export recovered symbols
    # ------------------------------------------------------------------

    def get_recovered_dict(self) -> Dict[int, str]:
        """Return recovered symbols as {va: name} dict."""
        return {r.recovered_va: r.name for r in self._recovered
                if r.status in ('ok', 'discovered')}

    def export_map_file(self, output_path: str,
                        image_base: int = None) -> str:
        """Export recovered symbols as a .map file."""
        if not self._recovered:
            raise RuntimeError("No recovered symbols to export")
        if self._diff is None:
            raise RuntimeError("No diff result available")

        ib = image_base if image_base is not None else self._diff.patched_image_base
        sym_dict = self.get_recovered_dict()
        sections = []
        for s in self._diff.patched_sections:
            sections.append({
                'name': s.name,
                'rva': s.va,
                'vsize': s.vsize,
                'is_code': bool(s.chars & 0x20),  # IMAGE_SCN_CNT_CODE
            })

        from nt_analyzer.ubrt_engine import SymbolUpdater
        content = SymbolUpdater.generate_map_file(
            sym_dict, image_base=ib, sections=sections,
            output_path=output_path)
        return content

    def export_pdb(self, orig_pdb_path: str, output_path: str,
                   orig_pe_path: str = None,
                   patched_pe_path: str = None) -> Dict[str, Any]:
        """
        Create a patched copy of the original PDB with recovered addresses.

        Strategy: for each matched section, compute the delta and apply
        section-specific shifts using the PDB patcher.  Then inject any
        discovered symbols (new sections) into the PDB.

        Safety model:
          * All edits happen on a temporary copy, never on the source or
            the destination in place.
          * The temp is validated structurally (MSF invariants) before it
            is allowed to replace ``output_path``.
          * If the destination already exists it is backed up (.bak) first.
          * The PDB info-stream signature/age is re-stamped to match the
            *patched* binary's CodeView (NB10) record so WinDbg can bind
            the remapped symbols to the patched image.
        """
        import shutil
        import tempfile
        if self._diff is None:
            raise RuntimeError("No diff result available")

        from nt_analyzer.ubrt_engine import SymbolUpdater
        from nt_analyzer.pdb70.msf import detect_pdb_format
        from nt_analyzer.pdb70.updater import SymbolUpdater70

        if not os.path.isfile(orig_pdb_path):
            raise FileNotFoundError(f"Source PDB not found: {orig_pdb_path}")

        # Work on a temp copy in the destination directory (same volume so
        # the final replace is atomic).
        out_dir = os.path.dirname(os.path.abspath(output_path)) or '.'
        os.makedirs(out_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(suffix='.pdb.tmp', dir=out_dir)
        os.close(fd)
        shutil.copy2(orig_pdb_path, tmp_path)

        pdb_fmt = detect_pdb_format(tmp_path)
        if pdb_fmt == 'pdb70':
            Updater = SymbolUpdater70
        elif pdb_fmt == 'pdb20':
            Updater = SymbolUpdater
        else:
            raise RuntimeError(f'Unsupported PDB format for export: {pdb_fmt}')

        try:
            # Safety gate for publics re-indexing: decide up-front (on the
            # pristine copy, before any edit) whether our GSI serializer can
            # reproduce this file's existing publics hash byte-for-byte.  If
            # it can't, we will append symbols but not touch the hash, so we
            # can never regress symbols that already resolve.
            repro = Updater.verify_publics_reproducible(tmp_path)
            sorted_matches = sorted(self._diff.matches,
                                    key=lambda m: m.orig.va, reverse=True)
            results = []
            remap_result = None
            reindex_result = None

            if pdb_fmt == 'pdb70':
                if not self._recovered:
                    raise RuntimeError(
                        'Call recover_symbols() before export_pdb() for PDB 7.0')
                if not patched_pe_path:
                    raise RuntimeError(
                        'patched_pe_path is required for PDB 7.0 export')
                map_result = Updater.patch_section_map_for_pe(
                    tmp_path, orig_pe_path, patched_pe_path)
                results.append(map_result)
                remap_result = Updater.remap_publics_by_address(
                    tmp_path,
                    self._recovered,
                    patched_pe_path,
                    image_base=self._diff.patched_image_base)
                results.append(remap_result)
                if remap_result.get('errors'):
                    raise RuntimeError(
                        'PDB 7.0 public remap failed: '
                        + '; '.join(remap_result['errors']))
                # Rebind per-module private procs/data (kd "private symbols").
                module_result = Updater.remap_module_symbols(
                    tmp_path,
                    self._recovered,
                    patched_pe_path,
                    image_base=self._diff.patched_image_base)
                results.append(module_result)
                if module_result.get('errors'):
                    raise RuntimeError(
                        'PDB 7.0 module remap failed: '
                        + '; '.join(module_result['errors']))
            else:
                # PDB 2.0: cumulative shifts per section (high VA first).
                for m in sorted_matches:
                    if m.va_delta == 0:
                        continue
                    r = Updater.patch_pdb_file(
                        tmp_path,
                        shift_rva=m.orig.va,
                        delta=m.va_delta,
                        pe_path=orig_pe_path,
                        image_base=self._diff.orig_image_base
                    )
                    results.append({
                        'section': m.orig.name,
                        'orig_va': m.orig.va,
                        'delta': m.va_delta,
                        'patched': r.get('patched', 0),
                        'total': r.get('total', 0),
                        'errors': r.get('errors', []),
                    })

            # Inject discovered symbols (new sections like .sec21).
            inject_result = None
            discovered = {r.recovered_va: r.name for r in self._recovered
                          if r.status == 'discovered'}
            # Drop discovered symbols whose function already has a public
            # symbol in the PDB (e.g. the exported, undecorated `NtCreateJobObject`
            # vs the existing `_NtCreateJobObject@12`).  Injecting those would
            # add a confusing second entry at the export/stub address while the
            # real, correctly-decorated symbol is already present.
            skipped_dupes = []
            if discovered:
                existing_cores = Updater.existing_public_cores(tmp_path)
                if existing_cores:
                    deduped = {}
                    for va, name in discovered.items():
                        if SymbolUpdater._decorated_core(name) in existing_cores:
                            skipped_dupes.append(name)
                        else:
                            deduped[va] = name
                    discovered = deduped
            if discovered and patched_pe_path:
                inject_result = Updater.inject_symbols_pdb(
                    tmp_path, discovered, pe_path=patched_pe_path,
                    image_base=self._diff.patched_image_base)
            if inject_result is not None:
                inject_result['skipped_duplicates'] = skipped_dupes

            # Re-index the publics hash after symrec edits.
            reindex_result = None
            needs_reindex = (
                pdb_fmt == 'pdb70' and remap_result and
                remap_result.get('remapped', 0) > 0)
            if inject_result and inject_result.get('injected'):
                needs_reindex = True
            if needs_reindex and repro.get('reproducible'):
                reindex_result = Updater.rebuild_publics_index(
                    tmp_path, variant=repro.get('variant'))

            # Re-stamp signature/age so the remapped PDB matches the image
            # being debugged (the patched binary).
            stamp_result = None
            cv = {}
            src_dbg = os.path.splitext(orig_pdb_path)[0] + '.dbg'
            has_separate_dbg = os.path.isfile(src_dbg)
            if patched_pe_path and os.path.isfile(patched_pe_path):
                cv = SymbolUpdater.read_pe_codeview(patched_pe_path)
                stamp_sig = cv.get('signature')
                # Patched HAL has no in-image CodeView; kd matches PE NB10
                # signature against PDB stream-1 (see !sym noisy:
                # "mismatched pdb").  Use the patched PE TimeDateStamp.
                if stamp_sig is None and cv.get('timestamp') is not None and \
                        (has_separate_dbg or pdb_fmt == 'pdb70'):
                    stamp_sig = cv['timestamp']
                if stamp_sig is not None:
                    stamp_age = cv.get('age')
                    if stamp_age is None and has_separate_dbg:
                        # Stripped PEs have no in-image CodeView age; kd matches
                        # the PDB info-stream age against the .dbg NB10 age.
                        # sync_dbg_sections_from_pe leaves the NB10 age intact,
                        # so adopt the source .dbg's age (NOT a hard-coded 1) or
                        # the pdb/dbg age pair will disagree and kd rejects it.
                        try:
                            dbg_cv = SymbolUpdater.read_dbg_codeview(src_dbg)
                            if dbg_cv.get('age') is not None:
                                stamp_age = dbg_cv['age']
                        except Exception:
                            pass
                    if stamp_age is None:
                        stamp_age = 1
                    if pdb_fmt == 'pdb70':
                        stamp_result = SymbolUpdater70.stamp_pdb_info(
                            tmp_path, stamp_sig, stamp_age)
                    elif cv.get('format') == 'NB10' or \
                            (pdb_fmt == 'pdb20' and has_separate_dbg):
                        # Stripped drivers (e.g. scsiport) carry no in-PE
                        # CodeView; their separate .dbg NB10 is stamped to the
                        # patched PE timestamp by sync_dbg_sections_from_pe.
                        # Align the PDB 2.0 info-stream signature to the same
                        # value or kd rejects the PDB and shows export symbols.
                        stamp_result = SymbolUpdater.stamp_pdb_signature(
                            tmp_path, stamp_sig, stamp_age)

            # Validate the temp BEFORE it is allowed to replace anything.
            validation = Updater.validate_pdb(tmp_path)
            if not validation.get('valid'):
                raise RuntimeError(
                    "Refusing to write a structurally invalid PDB; the "
                    "existing symbol file was left untouched. Details: "
                    + "; ".join(validation.get('errors', ['unknown'])))

            # Back up an existing destination, then atomically swap in.
            backup_path = None
            if os.path.isfile(output_path) and \
                    os.path.abspath(output_path) != os.path.abspath(tmp_path):
                backup_path = output_path + '.bak'
                shutil.copy2(output_path, backup_path)
            os.replace(tmp_path, output_path)
            tmp_path = None  # consumed by os.replace

            # HAL / stripped DLLs: separate .dbg (MISC debug) binds by timestamp.
            # Copy the sibling .dbg from the source symbol tree, patch its
            # section/symbol RVAs, then re-stamp header + NB10 to the patched PE.
            dbg_export = None
            dbg_stamp = None
            out_dbg = os.path.splitext(output_path)[0] + '.dbg'
            hal_deploy = None
            if os.path.isfile(src_dbg) and patched_pe_path and \
                    os.path.isfile(patched_pe_path):
                dbg_backup = None
                if os.path.isfile(out_dbg) and \
                        os.path.abspath(out_dbg) != os.path.abspath(src_dbg):
                    dbg_backup = out_dbg + '.bak'
                    shutil.copy2(out_dbg, dbg_backup)
                shutil.copy2(src_dbg, out_dbg)
                dbg_patch_results = []
                for m in sorted_matches:
                    if m.va_delta == 0:
                        continue
                    r = SymbolUpdater.patch_dbg_file(
                        out_dbg,
                        shift_rva=m.orig.va,
                        delta=m.va_delta,
                        image_base=self._diff.orig_image_base,
                    )
                    dbg_patch_results.append(r)
                dbg_stamp = SymbolUpdater.sync_dbg_sections_from_pe(
                    out_dbg, patched_pe_path)
                deploy_dir = os.path.dirname(os.path.abspath(output_path))
                hal_deploy = SymbolUpdater.deploy_hal_windbg_symbols(
                    deploy_dir, patched_pe_path, out_dbg, output_path)
                dbg_export = {
                    'output_path': out_dbg,
                    'backup': dbg_backup,
                    'section_results': dbg_patch_results,
                    'stamped': dbg_stamp,
                    'hal_deploy': hal_deploy,
                }
            elif os.path.isfile(out_dbg) and cv.get('timestamp'):
                # Legacy: sibling already present — timestamp-only stamp.
                dbg_stamp = SymbolUpdater.stamp_dbg_timestamp(
                    out_dbg, cv['timestamp'])
        finally:
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        return {
            'output_path': output_path,
            'section_results': results,
            'total_sections_shifted': sum(
                1 for r in results
                if r.get('patched', 0) > 0 or r.get('remapped', 0) > 0),
            'injected': inject_result,
            'publics_reproducible': repro,
            'reindexed': reindex_result,
            'codeview': cv,
            'stamped': stamp_result,
            'dbg_stamped': dbg_stamp,
            'dbg_export': dbg_export,
            'hal_deploy': hal_deploy,
            'validation': validation,
            'backup': backup_path,
            'pdb_format': pdb_fmt,
        }

    # ------------------------------------------------------------------
    #  Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics about the recovery."""
        if not self._recovered:
            return {}
        ok = sum(1 for r in self._recovered if r.status == 'ok')
        unmapped = sum(1 for r in self._recovered if r.status == 'unmapped')
        removed = sum(1 for r in self._recovered if r.status == 'section_removed')
        outside = sum(1 for r in self._recovered if r.status == 'outside')
        discovered = sum(1 for r in self._recovered if r.status == 'discovered')
        high_conf = sum(1 for r in self._recovered
                        if r.status in ('ok', 'discovered') and r.confidence >= 0.8)
        total_ok = ok + discovered
        return {
            'total': len(self._recovered),
            'ok': ok,
            'discovered': discovered,
            'unmapped': unmapped,
            'section_removed': removed,
            'outside': outside,
            'high_confidence': high_conf,
            'success_rate': total_ok / len(self._recovered) if self._recovered else 0,
        }

    # ------------------------------------------------------------------
    #  New section symbol discovery
    # ------------------------------------------------------------------

    def discover_new_section_symbols(self, patched_pe_path: str,
                                     orig_pe_path: str = None) -> List[RecoveredSymbol]:
        """
        Discover symbols in NEW sections of the patched binary.

        Scans for:
        1. Section boundary markers (__<name>_start / __<name>_end)
        2. PE data directory entries that fall in new sections
        3. Exports pointing into new sections
        4. Function prologues (push ebp; mov ebp, esp) in executable sections

        Returns list of newly discovered RecoveredSymbol objects.
        These are also appended to self._recovered.
        """
        if self._diff is None:
            raise RuntimeError("Call diff_binaries() first")
        if not self._diff.new_sections:
            return []
        if pefile is None:
            raise ImportError("pefile is required")

        pe = pefile.PE(patched_pe_path)
        ib = pe.OPTIONAL_HEADER.ImageBase
        discovered = []

        # Collect new section VA ranges
        new_ranges = {}
        for sec in self._diff.new_sections:
            new_ranges[sec.index] = sec

        # 1. Section boundary markers
        for sec in self._diff.new_sections:
            safe_name = sec.name.replace('.', '').replace('$', '')
            discovered.append(RecoveredSymbol(
                name=f'__{safe_name}_start',
                orig_va=0,
                recovered_va=ib + sec.va,
                section_name=sec.name,
                section_index=sec.index,
                confidence=1.0,
                status='discovered',
            ))
            discovered.append(RecoveredSymbol(
                name=f'__{safe_name}_end',
                orig_va=0,
                recovered_va=ib + sec.va + sec.vsize,
                section_name=sec.name,
                section_index=sec.index,
                confidence=1.0,
                status='discovered',
            ))

        # 2. PE data directory entries pointing into new sections
        dir_names = [
            'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION',
            'SECURITY', 'BASERELOC', 'DEBUG', 'ARCHITECTURE',
            'GLOBALPTR', 'TLS', 'LOAD_CONFIG', 'BOUND_IMPORT',
            'IAT', 'DELAY_IMPORT', 'COM_DESCRIPTOR',
        ]
        for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if d.VirtualAddress == 0 or d.Size == 0:
                continue
            rva = d.VirtualAddress
            for sec in self._diff.new_sections:
                if sec.va <= rva < sec.va + sec.vsize:
                    dname = dir_names[i] if i < len(dir_names) else f'DIR_{i}'
                    discovered.append(RecoveredSymbol(
                        name=f'__PE_{dname}_Directory',
                        orig_va=0,
                        recovered_va=ib + rva,
                        section_name=sec.name,
                        section_index=sec.index,
                        confidence=1.0,
                        status='discovered',
                    ))
                    break

        # 3. Export-specific tables in new sections
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            ed = pe.DIRECTORY_ENTRY_EXPORT
            export_tables = [
                ('__ExportAddressTable', ed.struct.AddressOfFunctions),
                ('__ExportNameTable', ed.struct.AddressOfNames),
                ('__ExportOrdinalTable', ed.struct.AddressOfNameOrdinals),
            ]
            for label, rva in export_tables:
                if rva == 0:
                    continue
                for sec in self._diff.new_sections:
                    if sec.va <= rva < sec.va + sec.vsize:
                        discovered.append(RecoveredSymbol(
                            name=label,
                            orig_va=0,
                            recovered_va=ib + rva,
                            section_name=sec.name,
                            section_index=sec.index,
                            confidence=1.0,
                            status='discovered',
                        ))
                        break

            # 3b. Export name strings range in new sections
            name_rvas = []
            for exp in ed.symbols:
                if exp.name_offset:
                    name_rvas.append(exp.name_offset)
            if name_rvas:
                min_rva = min(name_rvas)
                for sec in self._diff.new_sections:
                    if sec.va <= min_rva < sec.va + sec.vsize:
                        discovered.append(RecoveredSymbol(
                            name='__ExportNameStrings',
                            orig_va=0,
                            recovered_va=ib + min_rva,
                            section_name=sec.name,
                            section_index=sec.index,
                            confidence=1.0,
                            status='discovered',
                        ))
                        break

            # 3c. DLL name string in new sections
            dll_name_rva = ed.struct.Name
            if dll_name_rva:
                for sec in self._diff.new_sections:
                    if sec.va <= dll_name_rva < sec.va + sec.vsize:
                        discovered.append(RecoveredSymbol(
                            name='__ExportDllName',
                            orig_va=0,
                            recovered_va=ib + dll_name_rva,
                            section_name=sec.name,
                            section_index=sec.index,
                            confidence=1.0,
                            status='discovered',
                        ))
                        break

            # 4. Exports pointing into new sections
            for exp in ed.symbols:
                if not exp.address:
                    continue
                for sec in self._diff.new_sections:
                    if sec.va <= exp.address < sec.va + sec.vsize:
                        name = exp.name.decode('ascii', 'replace') if exp.name else f'ord_{exp.ordinal}'
                        discovered.append(RecoveredSymbol(
                            name=name,
                            orig_va=0,
                            recovered_va=ib + exp.address,
                            section_name=sec.name,
                            section_index=sec.index,
                            confidence=1.0,
                            status='discovered',
                        ))
                        break

        # 5. Function prologues in executable new sections
        for sec in self._diff.new_sections:
            is_exec = bool(sec.chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            is_code = bool(sec.chars & 0x20)         # IMAGE_SCN_CNT_CODE
            if not (is_exec or is_code):
                continue
            try:
                data = pe.get_data(sec.va, sec.vsize)
            except Exception:
                continue
            # Scan for push ebp; mov ebp, esp (55 8B EC)
            func_num = 0
            i = 0
            while i < len(data) - 2:
                if data[i] == 0x55 and data[i + 1] == 0x8B and data[i + 2] == 0xEC:
                    func_num += 1
                    safe_name = sec.name.replace('.', '').replace('$', '')
                    discovered.append(RecoveredSymbol(
                        name=f'{safe_name}_func_{func_num:04d}',
                        orig_va=0,
                        recovered_va=ib + sec.va + i,
                        section_name=sec.name,
                        section_index=sec.index,
                        confidence=0.7,
                        status='discovered',
                    ))
                    i += 3  # skip past this prologue
                else:
                    i += 1

        # 6. New exports: functions added to the patched binary
        #    Compare export tables to find names not in original
        if orig_pe_path and hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                orig_pe = pefile.PE(orig_pe_path)
                orig_export_names = set()
                if hasattr(orig_pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in orig_pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            orig_export_names.add(
                                exp.name.decode('ascii', 'replace'))
                orig_pe.close()

                # Map patched sections for labeling
                p_sections = []
                for s in pe.sections:
                    nm = s.Name.rstrip(b'\x00').decode('ascii', 'replace')
                    p_sections.append(
                        (nm, s.VirtualAddress, s.Misc_VirtualSize,
                         pe.sections.index(s)))

                def rva_to_section_info(rva):
                    for nm, sva, svs, si in p_sections:
                        if sva <= rva < sva + svs:
                            return nm, si
                    return '???', -1

                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if not exp.name or not exp.address:
                        continue
                    name = exp.name.decode('ascii', 'replace')
                    if name not in orig_export_names:
                        sec_name, sec_idx = rva_to_section_info(exp.address)
                        discovered.append(RecoveredSymbol(
                            name=name,
                            orig_va=0,
                            recovered_va=ib + exp.address,
                            section_name=sec_name,
                            section_index=sec_idx,
                            confidence=1.0,
                            status='discovered',
                        ))
            except Exception:
                pass  # original PE not available, skip

        pe.close()

        # Deduplicate by VA
        seen_vas = {r.recovered_va for r in self._recovered}
        unique = []
        for sym in discovered:
            if sym.recovered_va not in seen_vas:
                seen_vas.add(sym.recovered_va)
                unique.append(sym)

        self._recovered.extend(unique)
        return unique


def read_pdb_info(pdb_path: str) -> Dict[str, Any]:
    """Read a PDB's info-stream identity (format, signature/guid, age).

    Works for both PDB 2.0 (JG) and PDB 7.0 (DS).  Returns a dict with
    keys: format ('pdb20'/'pdb70'/'unknown'), signature (int|None),
    age (int|None), guid (bytes|None), error (str, optional).
    """
    import math
    info: Dict[str, Any] = {'format': 'unknown', 'signature': None,
                            'age': None, 'guid': None}
    try:
        with open(pdb_path, 'rb') as f:
            data = f.read()
    except OSError as e:
        info['error'] = str(e)
        return info

    def _extract_stream1_pdb20(d):
        page_size = struct.unpack_from('<I', d, 44)[0]
        root_size = struct.unpack_from('<I', d, 52)[0]
        if not page_size or page_size > 0x10000:
            return None
        nrp = math.ceil(root_size / page_size) if root_size else 0
        rps = [struct.unpack_from('<H', d, 60 + i * 2)[0] for i in range(nrp)]
        root = b''.join(d[p * page_size:p * page_size + page_size]
                        for p in rps)[:root_size]
        ns = struct.unpack_from('<H', root, 0)[0]
        off = 4
        sizes = [struct.unpack_from('<I', root, off + i * 8)[0]
                 for i in range(ns)]
        off = 4 + ns * 8
        pages = []
        for sz in sizes:
            cnt = math.ceil(sz / page_size) if sz not in (0, 0xFFFFFFFF) else 0
            pages.append([struct.unpack_from('<H', root, off + j * 2)[0]
                          for j in range(cnt)])
            off += cnt * 2
        if len(pages) < 2 or not pages[1]:
            return None
        return b''.join(d[p * page_size:p * page_size + page_size]
                        for p in pages[1])

    try:
        from nt_analyzer.pdb70.msf import detect_pdb_format
        fmt = detect_pdb_format(pdb_path)
    except Exception:
        fmt = 'unknown'

    if fmt == 'pdb70':
        info['format'] = 'pdb70'
        try:
            from nt_analyzer.pdb70.updater import SymbolUpdater70
            msf = SymbolUpdater70._load_msf(pdb_path)
            s1 = msf['read_stream'](1)
            if len(s1) >= 28:
                info['signature'] = struct.unpack_from('<I', s1, 4)[0]
                info['age'] = struct.unpack_from('<I', s1, 8)[0]
                info['guid'] = bytes(s1[12:28])
        except Exception as e:  # pragma: no cover - defensive
            info['error'] = str(e)
    elif fmt == 'pdb20':
        info['format'] = 'pdb20'
        s1 = _extract_stream1_pdb20(data)
        if s1 and len(s1) >= 12:
            info['signature'] = struct.unpack_from('<I', s1, 4)[0]
            info['age'] = struct.unpack_from('<I', s1, 8)[0]
    else:
        info['error'] = 'Unrecognized PDB magic'
    return info


def verify_export_correspondence(patched_pe_path: str, out_pdb_path: str,
                                 orig_pe_path: str = None,
                                 orig_pdb_path: str = None) -> Dict[str, Any]:
    """Verify an exported PDB will bind to the patched image in WinDbg/kd.

    Replicates kd's matching rule: the image's CodeView record (taken from
    the in-PE debug directory, or from the sibling .dbg for stripped PEs)
    must agree with the PDB info stream on signature/guid AND age.  For
    stripped images the .dbg header TimeDateStamp must equal the image
    TimeDateStamp (that is how kd locates the .dbg in the first place).

    Returns a dict:
      {'ok': bool, 'checks': [(label, passed, detail), ...],
       'format': str, 'errors': [...]}
    """
    from nt_analyzer.ubrt_engine import SymbolUpdater
    res: Dict[str, Any] = {'ok': False, 'checks': [], 'errors': [],
                           'format': 'unknown'}

    def chk(label, passed, detail=''):
        res['checks'].append((label, bool(passed), detail))

    if not os.path.isfile(out_pdb_path):
        res['errors'].append(f'Exported PDB not found: {out_pdb_path}')
        return res
    if not patched_pe_path or not os.path.isfile(patched_pe_path):
        res['errors'].append('Patched PE not found')
        return res

    pdb_info = read_pdb_info(out_pdb_path)
    res['format'] = pdb_info.get('format', 'unknown')
    if pdb_info.get('error'):
        res['errors'].append(f"PDB read: {pdb_info['error']}")

    cv = SymbolUpdater.read_pe_codeview(patched_pe_path) or {}
    pe_ts = cv.get('timestamp')
    out_dbg = os.path.splitext(out_pdb_path)[0] + '.dbg'
    has_out_dbg = os.path.isfile(out_dbg)
    dbg_cv = SymbolUpdater.read_dbg_codeview(out_dbg) if has_out_dbg else {}

    # Choose the CodeView record kd will actually use to match the PDB:
    # in-PE record if present, else the sibling .dbg's NB10/RSDS.
    if cv.get('format') in ('NB10', 'RSDS'):
        match_src = 'in-PE CodeView'
        match_cv = cv
    elif dbg_cv.get('format') in ('NB10', 'RSDS'):
        match_src = 'sibling .dbg'
        match_cv = dbg_cv
    else:
        match_src = None
        match_cv = {}

    if match_src is None:
        chk('image has a usable CodeView record', False,
            'stripped PE with no sibling .dbg — kd will fall back to exports')
        return res
    chk('image CodeView source', True,
        f"{match_src} ({match_cv.get('format')})")

    # The IMAGE record's format dictates how kd matches, regardless of the
    # PDB's own MSF version: an NB10 image is matched by the 32-bit info-stream
    # signature (a PDB 7.0 file carries one too); an RSDS image by the GUID.
    if match_cv.get('format') == 'RSDS':
        mguid = match_cv.get('guid')
        same = (mguid is not None and pdb_info.get('guid') == mguid)
        chk('PDB GUID matches image (RSDS)', same,
            f"pdb={(pdb_info.get('guid') or b'').hex()} "
            f"img={(mguid or b'').hex()}")
    else:  # NB10
        msig = match_cv.get('signature')
        sig_p = pdb_info.get('signature')
        same = (msig is not None and sig_p == msig)
        chk('PDB signature matches image (NB10)', same,
            f"pdb=0x{(sig_p or 0):08X} img=0x{(msig or 0):08X}")

    match_age = match_cv.get('age')
    age_ok = (match_age is not None and pdb_info.get('age') == match_age)
    chk('PDB age matches image', age_ok,
        f"pdb={pdb_info.get('age')} img={match_age}")

    # Stripped image: the .dbg is located purely by TimeDateStamp.
    if cv.get('format') not in ('NB10', 'RSDS') and has_out_dbg:
        dbg_ts = dbg_cv.get('timestamp')
        ts_ok = (pe_ts is not None and dbg_ts == pe_ts)
        chk('.dbg TimeDateStamp matches image', ts_ok,
            f"dbg=0x{(dbg_ts or 0):08X} img=0x{(pe_ts or 0):08X}")

    res['ok'] = all(p for _, p, _ in res['checks'])
    return res
