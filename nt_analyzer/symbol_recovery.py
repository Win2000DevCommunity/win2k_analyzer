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

        if not os.path.isfile(orig_pdb_path):
            raise FileNotFoundError(f"Source PDB not found: {orig_pdb_path}")

        # Work on a temp copy in the destination directory (same volume so
        # the final replace is atomic).
        out_dir = os.path.dirname(os.path.abspath(output_path)) or '.'
        os.makedirs(out_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(suffix='.pdb.tmp', dir=out_dir)
        os.close(fd)
        shutil.copy2(orig_pdb_path, tmp_path)

        try:
            # Safety gate for publics re-indexing: decide up-front (on the
            # pristine copy, before any edit) whether our GSI serializer can
            # reproduce this file's existing publics hash byte-for-byte.  If
            # it can't, we will append symbols but not touch the hash, so we
            # can never regress symbols that already resolve.
            repro = SymbolUpdater.verify_publics_reproducible(tmp_path)
            # Apply cumulative shifts per section.  Process sections from
            # highest VA to lowest to avoid double-shifting.
            results = []
            sorted_matches = sorted(self._diff.matches,
                                    key=lambda m: m.orig.va, reverse=True)
            for m in sorted_matches:
                if m.va_delta == 0:
                    continue
                r = SymbolUpdater.patch_pdb_file(
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
                existing_cores = SymbolUpdater.existing_public_cores(tmp_path)
                if existing_cores:
                    deduped = {}
                    for va, name in discovered.items():
                        if SymbolUpdater._decorated_core(name) in existing_cores:
                            skipped_dupes.append(name)
                        else:
                            deduped[va] = name
                    discovered = deduped
            if discovered and patched_pe_path:
                inject_result = SymbolUpdater.inject_symbols_pdb(
                    tmp_path, discovered, pe_path=patched_pe_path,
                    image_base=self._diff.patched_image_base)
            if inject_result is not None:
                inject_result['skipped_duplicates'] = skipped_dupes

            # Re-index the publics hash so the injected symbols become
            # enumerable in WinDbg (`x nt!*`) and resolvable by name.  Only
            # run when injection added records *and* the reproduce gate
            # proved our serializer matches this file exactly.
            reindex_result = None
            if (inject_result and inject_result.get('injected') and
                    repro.get('reproducible')):
                reindex_result = SymbolUpdater.rebuild_publics_index(
                    tmp_path, variant=repro.get('variant'))

            # Re-stamp signature/age so the remapped PDB matches the image
            # being debugged (the patched binary).
            stamp_result = None
            cv = {}
            if patched_pe_path and os.path.isfile(patched_pe_path):
                cv = SymbolUpdater.read_pe_codeview(patched_pe_path)
                if cv.get('format') == 'NB10' and 'signature' in cv:
                    stamp_result = SymbolUpdater.stamp_pdb_signature(
                        tmp_path, cv['signature'], cv.get('age'))

            # Validate the temp BEFORE it is allowed to replace anything.
            validation = SymbolUpdater.validate_pdb(tmp_path)
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

            # If a sibling .dbg lives next to the output, match its
            # TimeDateStamp to the patched image too (stripped images are
            # matched to their .dbg by timestamp only).
            dbg_stamp = None
            sibling_dbg = os.path.splitext(output_path)[0] + '.dbg'
            if cv.get('timestamp') and os.path.isfile(sibling_dbg):
                dbg_stamp = SymbolUpdater.stamp_dbg_timestamp(
                    sibling_dbg, cv['timestamp'])
        finally:
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        return {
            'output_path': output_path,
            'section_results': results,
            'total_sections_shifted': sum(1 for r in results if r['patched'] > 0),
            'injected': inject_result,
            'publics_reproducible': repro,
            'reindexed': reindex_result,
            'codeview': cv,
            'stamped': stamp_result,
            'dbg_stamped': dbg_stamp,
            'validation': validation,
            'backup': backup_path,
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
