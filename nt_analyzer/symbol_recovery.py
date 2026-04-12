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
                if r.status == 'ok'}

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
                   orig_pe_path: str = None) -> Dict[str, Any]:
        """
        Create a patched copy of the original PDB with recovered addresses.

        Strategy: for each matched section, compute the delta and apply
        section-specific shifts using the PDB patcher.
        """
        import shutil
        if self._diff is None:
            raise RuntimeError("No diff result available")

        # Copy original PDB to output
        shutil.copy2(orig_pdb_path, output_path)

        # Apply cumulative shifts per section
        # We process sections from highest VA to lowest to avoid double-shifting
        results = []
        sorted_matches = sorted(self._diff.matches,
                                key=lambda m: m.orig.va, reverse=True)

        from nt_analyzer.ubrt_engine import SymbolUpdater
        for m in sorted_matches:
            if m.va_delta == 0:
                continue
            # shift_rva = start of this original section
            # delta = the VA shift for this section
            r = SymbolUpdater.patch_pdb_file(
                output_path,
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

        return {
            'output_path': output_path,
            'section_results': results,
            'total_sections_shifted': sum(1 for r in results if r['patched'] > 0),
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
        high_conf = sum(1 for r in self._recovered
                        if r.status == 'ok' and r.confidence >= 0.8)
        return {
            'total': len(self._recovered),
            'ok': ok,
            'unmapped': unmapped,
            'section_removed': removed,
            'outside': outside,
            'high_confidence': high_conf,
            'success_rate': ok / len(self._recovered) if self._recovered else 0,
        }
