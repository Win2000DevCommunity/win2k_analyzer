"""
UBRT Engine — Universal Binary Rewriter & Translator
=====================================================
Surgical binary modification with automatic reference recalculation.

Core innovation: Insert, delete, or patch bytes ANYWHERE in a compiled binary
and have ALL internal references (jumps, calls, pointers, tables) automatically
recalculated to maintain binary correctness.

Supports: PE32/PE32+ (Windows), x86/x64 via Capstone disassembly.
Dynamic tracing: QEMU integration for coverage-guided reference discovery.
"""

import struct
import os
import enum
import subprocess
import json
import time
import copy
import bisect
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict

try:
    import pefile
except ImportError:
    pefile = None

try:
    import capstone
    from capstone import x86 as cs_x86
except ImportError:
    capstone = None

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    HAS_ELFTOOLS = True
except ImportError:
    ELFFile = None
    RelocationSection = None
    SymbolTableSection = None
    HAS_ELFTOOLS = False


# ─── Enums ────────────────────────────────────────────────────────────────

class RefType(enum.Enum):
    """Types of address references found in binaries."""
    REL_JUMP_SHORT  = "rel_jump_short"
    REL_JUMP_NEAR   = "rel_jump_near"
    REL_CALL        = "rel_call"
    REL_COND_SHORT  = "rel_cond_short"
    REL_COND_NEAR   = "rel_cond_near"
    ABS_IMMEDIATE   = "abs_immediate"
    ABS_DISPLACEMENT = "abs_displacement"
    RIP_RELATIVE    = "rip_relative"
    RELOC_HIGHLOW   = "reloc_highlow"
    RELOC_DIR64     = "reloc_dir64"
    JUMP_TABLE      = "jump_table"
    VTABLE_ENTRY    = "vtable_entry"
    EXPORT_RVA      = "export_rva"
    IMPORT_THUNK    = "import_thunk"
    EXCEPTION_ENTRY = "exception_entry"
    TLS_CALLBACK    = "tls_callback"
    ENTRY_POINT     = "entry_point"
    DATA_POINTER    = "data_pointer"
    GOT_ENTRY       = "got_entry"
    PLT_STUB        = "plt_stub"
    INIT_FINI_PTR   = "init_fini_ptr"
    ELF_RELATIVE    = "elf_relative"
    SYMBOL_REF      = "symbol_ref"
    # v7: indirect control flow
    INDIRECT_CALL   = "indirect_call"
    INDIRECT_JUMP   = "indirect_jump"
    FUNC_POINTER    = "func_pointer"
    # v7: PE-specific structures
    TLS_DIR_ENTRY   = "tls_dir_entry"
    LOAD_CONFIG_ENTRY = "load_config_entry"
    DELAY_IMPORT    = "delay_import"
    RESOURCE_ENTRY  = "resource_entry"
    DEBUG_DIR_ENTRY = "debug_dir_entry"
    BOUND_IMPORT    = "bound_import"
    # v7: ELF dynamic
    ELF_DYNAMIC_TAG = "elf_dynamic_tag"
    # v7: Mach-O specific
    MACHO_REBASE    = "macho_rebase"
    # v7.1: memory-indirect + fat binary
    INDIRECT_CALL_MEM = "indirect_call_mem"
    RESOURCE_RVA    = "resource_rva"
    BOUND_IMPORT_RVA = "bound_import_rva"


class RefSource(enum.Enum):
    STATIC_DISASM = "static_disasm"
    PE_RELOC      = "pe_reloc"
    PE_TABLE      = "pe_table"
    HEURISTIC     = "heuristic"
    DYNAMIC_TRACE = "dynamic_trace"
    ELF_RELOC     = "elf_reloc"
    ELF_TABLE     = "elf_table"
    DATAFLOW      = "dataflow"       # v7: backward dataflow analysis
    MACHO_TABLE   = "macho_table"    # v7: Mach-O load command tables
    QEMU_TRACE    = "qemu_trace"     # v7.1: QEMU dynamic branch tracing


class ShiftOp(enum.Enum):
    INSERT  = "insert"
    DELETE  = "delete"
    REPLACE = "replace"
    PATCH   = "patch"


# ─── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class Reference:
    """A single address reference in the binary."""
    file_offset: int
    ref_type: RefType
    target_rva: int
    ref_rva: int
    size_bytes: int
    is_relative: bool
    insn_size: int
    section_name: str
    confidence: float
    source: RefSource
    symbol_name: str = ""

    @property
    def ref_end_rva(self):
        return self.ref_rva + self.insn_size

    def to_dict(self):
        return {
            'file_offset': self.file_offset,
            'ref_type': self.ref_type.value,
            'target_rva': self.target_rva,
            'ref_rva': self.ref_rva,
            'size_bytes': self.size_bytes,
            'is_relative': self.is_relative,
            'insn_size': self.insn_size,
            'section_name': self.section_name,
            'confidence': self.confidence,
            'source': self.source.value,
            'symbol_name': self.symbol_name,
        }


@dataclass
class ShiftResult:
    """Result of a shift operation."""
    operation: ShiftOp
    rva: int
    delta: int
    refs_updated: int
    warnings: List[str]
    sections_adjusted: int
    new_file_size: int
    success: bool
    message: str


@dataclass
class TraceBlock:
    """A basic block recorded during dynamic tracing."""
    start_va: int
    end_va: int
    hit_count: int = 1
    branch_targets: List[int] = field(default_factory=list)


# ─── Reference Database ──────────────────────────────────────────────────

class ReferenceDatabase:
    """
    Indexed database of all address references in a binary.

    v7: Adds bisect-based spatial index for O(log N) range queries,
    integrity validation, and batch-friendly bulk operations.
    """

    def __init__(self):
        self._refs: List[Reference] = []
        self._by_target: Dict[int, List[int]] = defaultdict(list)
        self._by_type: Dict[RefType, List[int]] = defaultdict(list)
        self._by_section: Dict[str, List[int]] = defaultdict(list)
        self._by_offset: Dict[Tuple[int, int], int] = {}  # (file_offset, size) → idx
        # v7: sorted index for range queries
        self._sorted_by_rva: List[Tuple[int, int]] = []   # (ref_rva, idx) sorted
        self._sorted_dirty = True

    def add(self, ref: Reference):
        # Deduplicate by (file_offset, size_bytes) — prevents double-writes
        if ref.file_offset > 0:
            key = (ref.file_offset, ref.size_bytes)
            existing_idx = self._by_offset.get(key)
            if existing_idx is not None:
                existing = self._refs[existing_idx]
                # Keep the higher-confidence entry
                if ref.confidence > existing.confidence:
                    existing.confidence = ref.confidence
                    existing.source = ref.source
                    existing.ref_type = ref.ref_type
                    if ref.symbol_name:
                        existing.symbol_name = ref.symbol_name
                return  # don't add duplicate
        idx = len(self._refs)
        self._refs.append(ref)
        self._by_target[ref.target_rva].append(idx)
        self._by_type[ref.ref_type].append(idx)
        self._by_section[ref.section_name].append(idx)
        if ref.file_offset > 0:
            self._by_offset[(ref.file_offset, ref.size_bytes)] = idx
        self._sorted_dirty = True

    def get_all(self) -> List[Reference]:
        return list(self._refs)

    def get_by_target(self, target_rva: int) -> List[Reference]:
        return [self._refs[i] for i in self._by_target.get(target_rva, [])]

    def get_by_section(self, name: str) -> List[Reference]:
        return [self._refs[i] for i in self._by_section.get(name, [])]

    def get_by_type(self, ref_type: RefType) -> List[Reference]:
        return [self._refs[i] for i in self._by_type.get(ref_type, [])]

    @property
    def count(self):
        return len(self._refs)

    def rebuild_indices(self):
        self._by_target.clear()
        self._by_type.clear()
        self._by_section.clear()
        self._by_offset.clear()
        for i, ref in enumerate(self._refs):
            self._by_target[ref.target_rva].append(i)
            self._by_type[ref.ref_type].append(i)
            self._by_section[ref.section_name].append(i)
            if ref.file_offset > 0:
                self._by_offset[(ref.file_offset, ref.size_bytes)] = i
        self._sorted_dirty = True

    def _ensure_sorted(self):
        """Rebuild the sorted RVA index if dirty."""
        if self._sorted_dirty:
            self._sorted_by_rva = sorted(
                ((ref.ref_rva, i) for i, ref in enumerate(self._refs)),
                key=lambda x: x[0]
            )
            self._sorted_dirty = False

    def get_refs_in_range(self, lo: int, hi: int) -> List[Reference]:
        """O(log N + k) range query: all refs with ref_rva in [lo, hi)."""
        self._ensure_sorted()
        left = bisect.bisect_left(self._sorted_by_rva, (lo,))
        right = bisect.bisect_left(self._sorted_by_rva, (hi,))
        return [self._refs[self._sorted_by_rva[i][1]]
                for i in range(left, right)]

    def get_refs_targeting_range(self, lo: int, hi: int) -> List[Reference]:
        """All refs whose target_rva falls in [lo, hi)."""
        return [r for r in self._refs if lo <= r.target_rva < hi]

    def validate_targets(self, valid_ranges: List[Tuple[int, int]]) -> List[Tuple[Reference, str]]:
        """
        Validate that all reference targets land in valid address ranges.
        Returns list of (ref, reason) for invalid refs.
        """
        invalid = []
        for ref in self._refs:
            target = ref.target_rva
            in_range = any(lo <= target < hi for lo, hi in valid_ranges)
            if not in_range:
                invalid.append((ref, f"target 0x{target:X} outside valid ranges"))
        return invalid

    def bulk_shift(self, shift_addr: int, delta: int):
        """Shift all refs >= shift_addr by delta. Used by batch operations."""
        for ref in self._refs:
            if ref.ref_rva >= shift_addr:
                ref.ref_rva += delta
                ref.file_offset += delta
            if ref.target_rva >= shift_addr:
                ref.target_rva += delta
        self._sorted_dirty = True
        self.rebuild_indices()

    def stats(self) -> Dict:
        by_type = defaultdict(int)
        by_source = defaultdict(int)
        conf = {'high': 0, 'medium': 0, 'low': 0}
        for r in self._refs:
            by_type[r.ref_type.value] += 1
            by_source[r.source.value] += 1
            if r.confidence >= 0.9:
                conf['high'] += 1
            elif r.confidence >= 0.7:
                conf['medium'] += 1
            else:
                conf['low'] += 1
        return {
            'total': len(self._refs),
            'by_type': dict(by_type),
            'by_source': dict(by_source),
            'by_confidence': conf,
            'sections': list(self._by_section.keys()),
        }

    def to_json(self) -> str:
        return json.dumps([r.to_dict() for r in self._refs], indent=2)

    def clear(self):
        self._refs.clear()
        self._by_target.clear()
        self._by_type.clear()
        self._by_section.clear()
        self._by_offset.clear()
        self._sorted_by_rva.clear()
        self._sorted_dirty = True


# ─── PE Reference Finder ─────────────────────────────────────────────────

class PEReferenceFinder:
    """
    Finds ALL address references in a PE binary.

    Three sources:
    1. PE relocation table → absolute address locations (confidence 1.0)
    2. Capstone disassembly → relative jumps/calls (confidence 1.0)
    3. PE structure tables → exports, imports, exceptions (confidence 1.0)
    4. Data section scanning → potential code pointers (confidence 0.5-0.8)
    """

    def __init__(self, pe_path: str):
        if pefile is None:
            raise ImportError("pefile is required for PE reference finding")
        if capstone is None:
            raise ImportError("capstone is required for disassembly")
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)
        with open(pe_path, 'rb') as f:
            self.data = bytearray(f.read())
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.is_64 = self.pe.OPTIONAL_HEADER.Magic == 0x20b
        self.ptr_size = 8 if self.is_64 else 4
        self._section_map = {}
        for s in self.pe.sections:
            name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            self._section_map[name] = s

    def find_all(self, callback=None) -> ReferenceDatabase:
        db = ReferenceDatabase()
        steps = [
            ("PE relocations", self._find_from_relocations),
            ("Disassembly (code sections)", self._find_from_disassembly),
            ("Export table", self._find_from_exports),
            ("Import table", self._find_from_imports),
            ("Exception table", self._find_from_exceptions),
            ("Jump tables (switch/case)", self._find_jump_tables),
            ("Vtables (C++ virtual)", self._find_vtables),
            ("Data pointers (heuristic)", self._find_data_pointers),
            # v7: additional structure passes
            ("TLS directory", self._find_tls_entries),
            ("Load config directory", self._find_load_config_entries),
            ("Delay-load imports", self._find_delay_imports),
            ("Debug directory", self._find_debug_entries),
            ("Indirect control flow", self._find_indirect_control_flow),
            # v7.1: resource and bound import passes
            ("Resource directory", self._find_resource_entries),
            ("Bound import table", self._find_bound_imports),
        ]
        for i, (name, func) in enumerate(steps):
            if callback:
                callback(name, i, len(steps))
            refs = func()
            for ref in refs:
                db.add(ref)
        if callback:
            callback("Done", len(steps), len(steps))
        return db

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return rva - s.VirtualAddress + s.PointerToRawData
        return None

    def _offset_to_rva(self, offset: int) -> Optional[int]:
        for s in self.pe.sections:
            if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
                return offset - s.PointerToRawData + s.VirtualAddress
        return None

    def _section_for_rva(self, rva: int) -> str:
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        return "?"

    def _is_code_section(self, section) -> bool:
        return bool(section.Characteristics & 0x20000000)

    def _is_executable_rva(self, rva: int) -> bool:
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return self._is_code_section(s)
        return False

    # ── 1. PE Relocations ─────────────────────────────────────────────
    def _find_from_relocations(self) -> List[Reference]:
        refs = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            return refs
        for reloc_block in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc_block.entries:
                if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    rva = entry.rva
                    foff = self._rva_to_offset(rva)
                    if foff is None or foff + 4 > len(self.data):
                        continue
                    target_va = struct.unpack_from('<I', self.data, foff)[0]
                    target_rva = target_va - self.image_base
                    refs.append(Reference(
                        file_offset=foff, ref_type=RefType.RELOC_HIGHLOW,
                        target_rva=target_rva, ref_rva=rva,
                        size_bytes=4, is_relative=False, insn_size=4,
                        section_name=self._section_for_rva(rva),
                        confidence=1.0, source=RefSource.PE_RELOC,
                    ))
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                    rva = entry.rva
                    foff = self._rva_to_offset(rva)
                    if foff is None or foff + 8 > len(self.data):
                        continue
                    target_va = struct.unpack_from('<Q', self.data, foff)[0]
                    target_rva = target_va - self.image_base
                    refs.append(Reference(
                        file_offset=foff, ref_type=RefType.RELOC_DIR64,
                        target_rva=target_rva, ref_rva=rva,
                        size_bytes=8, is_relative=False, insn_size=8,
                        section_name=self._section_for_rva(rva),
                        confidence=1.0, source=RefSource.PE_RELOC,
                    ))
        return refs

    # ── 2. Disassembly ────────────────────────────────────────────────
    def _find_from_disassembly(self) -> List[Reference]:
        refs = []
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if self.is_64 else capstone.CS_MODE_32
        md = capstone.Cs(arch, mode)
        md.detail = True
        md.skipdata = True

        for section in self.pe.sections:
            if not self._is_code_section(section):
                continue
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            code = section.get_data()
            base_va = self.image_base + section.VirtualAddress
            sec_rva = section.VirtualAddress
            sec_foff = section.PointerToRawData

            for insn in md.disasm(code, base_va):
                mnemonic = insn.mnemonic.lower()
                insn_rva = insn.address - self.image_base
                insn_foff = sec_foff + (insn_rva - sec_rva)

                # ── Relative CALL (E8 rel32) ──
                if insn.id == cs_x86.X86_INS_CALL and len(insn.operands) == 1:
                    op = insn.operands[0]
                    if op.type == cs_x86.X86_OP_IMM:
                        target_va = op.imm
                        target_rva = target_va - self.image_base
                        # Determine displacement offset within instruction
                        disp_off = insn.size - 4
                        refs.append(Reference(
                            file_offset=insn_foff + disp_off,
                            ref_type=RefType.REL_CALL,
                            target_rva=target_rva, ref_rva=insn_rva,
                            size_bytes=4, is_relative=True,
                            insn_size=insn.size, section_name=sec_name,
                            confidence=1.0, source=RefSource.STATIC_DISASM,
                        ))

                # ── Relative JMP (EB rel8 or E9 rel32) ──
                elif insn.id == cs_x86.X86_INS_JMP and len(insn.operands) == 1:
                    op = insn.operands[0]
                    if op.type == cs_x86.X86_OP_IMM:
                        target_va = op.imm
                        target_rva = target_va - self.image_base
                        if insn.size == 2:
                            refs.append(Reference(
                                file_offset=insn_foff + 1,
                                ref_type=RefType.REL_JUMP_SHORT,
                                target_rva=target_rva, ref_rva=insn_rva,
                                size_bytes=1, is_relative=True,
                                insn_size=insn.size, section_name=sec_name,
                                confidence=1.0, source=RefSource.STATIC_DISASM,
                            ))
                        else:
                            disp_off = insn.size - 4
                            refs.append(Reference(
                                file_offset=insn_foff + disp_off,
                                ref_type=RefType.REL_JUMP_NEAR,
                                target_rva=target_rva, ref_rva=insn_rva,
                                size_bytes=4, is_relative=True,
                                insn_size=insn.size, section_name=sec_name,
                                confidence=1.0, source=RefSource.STATIC_DISASM,
                            ))

                # ── Conditional jumps (7x rel8 or 0F 8x rel32) ──
                elif mnemonic.startswith('j') and mnemonic != 'jmp':
                    if len(insn.operands) == 1 and insn.operands[0].type == cs_x86.X86_OP_IMM:
                        target_va = insn.operands[0].imm
                        target_rva = target_va - self.image_base
                        if insn.size == 2:
                            refs.append(Reference(
                                file_offset=insn_foff + 1,
                                ref_type=RefType.REL_COND_SHORT,
                                target_rva=target_rva, ref_rva=insn_rva,
                                size_bytes=1, is_relative=True,
                                insn_size=insn.size, section_name=sec_name,
                                confidence=1.0, source=RefSource.STATIC_DISASM,
                            ))
                        else:
                            disp_off = insn.size - 4
                            refs.append(Reference(
                                file_offset=insn_foff + disp_off,
                                ref_type=RefType.REL_COND_NEAR,
                                target_rva=target_rva, ref_rva=insn_rva,
                                size_bytes=4, is_relative=True,
                                insn_size=insn.size, section_name=sec_name,
                                confidence=1.0, source=RefSource.STATIC_DISASM,
                            ))

                # ── LOOP / LOOPE / LOOPNE (rel8) ──
                elif mnemonic in ('loop', 'loope', 'loopne', 'jecxz', 'jrcxz'):
                    if len(insn.operands) == 1 and insn.operands[0].type == cs_x86.X86_OP_IMM:
                        target_va = insn.operands[0].imm
                        target_rva = target_va - self.image_base
                        refs.append(Reference(
                            file_offset=insn_foff + 1,
                            ref_type=RefType.REL_COND_SHORT,
                            target_rva=target_rva, ref_rva=insn_rva,
                            size_bytes=1, is_relative=True,
                            insn_size=insn.size, section_name=sec_name,
                            confidence=0.95, source=RefSource.STATIC_DISASM,
                        ))

                # ── RIP-relative addressing (x64): LEA, MOV, CMP, etc. ──
                elif self.is_64 and len(insn.operands) >= 2:
                    for op_idx, op in enumerate(insn.operands):
                        if (op.type == cs_x86.X86_OP_MEM and
                                op.mem.base == cs_x86.X86_REG_RIP and
                                op.mem.index == 0):
                            disp = op.mem.disp
                            target_rva = insn_rva + insn.size + disp
                            # Use Capstone's disp_offset for exact byte position
                            if hasattr(insn, 'disp_offset') and insn.disp_offset > 0:
                                disp_foff = insn_foff + insn.disp_offset
                            else:
                                # Fallback: disp32 before any trailing immediate
                                disp_foff = insn_foff + insn.size - 4
                                for op2 in insn.operands:
                                    if op2.type == cs_x86.X86_OP_IMM:
                                        disp_foff -= op2.size
                                        break
                            refs.append(Reference(
                                file_offset=disp_foff,
                                ref_type=RefType.RIP_RELATIVE,
                                target_rva=target_rva, ref_rva=insn_rva,
                                size_bytes=4, is_relative=True,
                                insn_size=insn.size, section_name=sec_name,
                                confidence=1.0, source=RefSource.STATIC_DISASM,
                            ))
                            break  # one RIP-rel per instruction

                # ── MOV with absolute immediate address (x86-32) ──
                elif (not self.is_64 and mnemonic == 'mov' and
                      len(insn.operands) == 2):
                    for op_idx, op in enumerate(insn.operands):
                        if op.type == cs_x86.X86_OP_IMM and op.size == 4:
                            candidate_rva = op.imm - self.image_base
                            if self._is_executable_rva(candidate_rva):
                                # imm32 is the last 4 bytes of the instruction
                                refs.append(Reference(
                                    file_offset=insn_foff + insn.size - 4,
                                    ref_type=RefType.ABS_IMMEDIATE,
                                    target_rva=candidate_rva, ref_rva=insn_rva,
                                    size_bytes=4, is_relative=False,
                                    insn_size=insn.size, section_name=sec_name,
                                    confidence=0.85, source=RefSource.STATIC_DISASM,
                                ))
                                break
                        elif op.type == cs_x86.X86_OP_MEM and op.mem.disp != 0:
                            candidate_rva = op.mem.disp - self.image_base
                            if (0 < candidate_rva < self.pe.OPTIONAL_HEADER.SizeOfImage
                                    and op.mem.base == 0 and op.mem.index == 0):
                                # Direct memory reference like MOV EAX, [0x401234]
                                refs.append(Reference(
                                    file_offset=insn_foff + insn.size - 4,
                                    ref_type=RefType.ABS_DISPLACEMENT,
                                    target_rva=candidate_rva, ref_rva=insn_rva,
                                    size_bytes=4, is_relative=False,
                                    insn_size=insn.size, section_name=sec_name,
                                    confidence=0.80, source=RefSource.STATIC_DISASM,
                                ))
                                break

                # ── PUSH with absolute immediate address (x86-32) ──
                elif (not self.is_64 and mnemonic == 'push' and
                      len(insn.operands) == 1):
                    op = insn.operands[0]
                    if op.type == cs_x86.X86_OP_IMM and op.size == 4:
                        candidate_rva = op.imm - self.image_base
                        if self._is_executable_rva(candidate_rva):
                            refs.append(Reference(
                                file_offset=insn_foff + insn.size - 4,
                                ref_type=RefType.ABS_IMMEDIATE,
                                target_rva=candidate_rva, ref_rva=insn_rva,
                                size_bytes=4, is_relative=False,
                                insn_size=insn.size, section_name=sec_name,
                                confidence=0.80, source=RefSource.STATIC_DISASM,
                            ))

        return refs

    # ── 3. Export Table ───────────────────────────────────────────────
    def _find_from_exports(self) -> List[Reference]:
        refs = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return refs
        exp = self.pe.DIRECTORY_ENTRY_EXPORT
        eat_rva = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
        for sym in exp.symbols:
            if sym.forwarder is not None:
                continue
            func_rva = sym.address
            # The export address entry in the EAT
            ordinal_idx = sym.ordinal - exp.struct.Base
            entry_rva = eat_rva + 0x28 + ordinal_idx * 4
            # Approximate — the struct offset into the AddressOfFunctions array
            eof = self._rva_to_offset(exp.struct.AddressOfFunctions + ordinal_idx * 4)
            if eof is not None:
                refs.append(Reference(
                    file_offset=eof, ref_type=RefType.EXPORT_RVA,
                    target_rva=func_rva,
                    ref_rva=exp.struct.AddressOfFunctions + ordinal_idx * 4,
                    size_bytes=4, is_relative=False, insn_size=4,
                    section_name=".edata",
                    confidence=1.0, source=RefSource.PE_TABLE,
                    symbol_name=sym.name.decode('ascii', errors='replace') if sym.name else f"ord_{sym.ordinal}",
                ))
        return refs

    # ── 4. Import Table ───────────────────────────────────────────────
    def _find_from_imports(self) -> List[Reference]:
        refs = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return refs
        for imp_dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = imp_dll.dll.decode('ascii', errors='replace') if imp_dll.dll else "?"
            for entry in imp_dll.imports:
                if entry.address is None:
                    continue
                iat_rva = entry.address - self.image_base
                eof = self._rva_to_offset(iat_rva)
                if eof is not None:
                    sym_name = entry.name.decode('ascii', errors='replace') if entry.name else f"ord_{entry.ordinal}"
                    refs.append(Reference(
                        file_offset=eof, ref_type=RefType.IMPORT_THUNK,
                        target_rva=iat_rva, ref_rva=iat_rva,
                        size_bytes=self.ptr_size, is_relative=False,
                        insn_size=self.ptr_size,
                        section_name=self._section_for_rva(iat_rva),
                        confidence=1.0, source=RefSource.PE_TABLE,
                        symbol_name=f"{dll_name}!{sym_name}",
                    ))
        return refs

    # ── 5. Exception Table (.pdata) ───────────────────────────────────
    def _find_from_exceptions(self) -> List[Reference]:
        refs = []
        if not self.is_64:
            return refs
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 3:
            return refs
        exc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if exc_dir.VirtualAddress == 0 or exc_dir.Size == 0:
            return refs
        rva = exc_dir.VirtualAddress
        size = exc_dir.Size
        foff = self._rva_to_offset(rva)
        if foff is None:
            return refs
        num_entries = size // 12
        for i in range(num_entries):
            off = foff + i * 12
            if off + 12 > len(self.data):
                break
            begin_rva, end_rva, unwind_rva = struct.unpack_from('<III', self.data, off)
            sec = self._section_for_rva(rva + i * 12)
            refs.append(Reference(
                file_offset=off, ref_type=RefType.EXCEPTION_ENTRY,
                target_rva=begin_rva, ref_rva=rva + i * 12,
                size_bytes=4, is_relative=False, insn_size=4,
                section_name=sec, confidence=1.0, source=RefSource.PE_TABLE,
            ))
            refs.append(Reference(
                file_offset=off + 4, ref_type=RefType.EXCEPTION_ENTRY,
                target_rva=end_rva, ref_rva=rva + i * 12 + 4,
                size_bytes=4, is_relative=False, insn_size=4,
                section_name=sec, confidence=1.0, source=RefSource.PE_TABLE,
            ))
        return refs

    # ── 6. Jump Table Detection ────────────────────────────────────
    def _find_jump_tables(self) -> List[Reference]:
        """
        Detect switch/case jump tables.
        v7: Enhanced with multiple pattern matchers:
        - MSVC: JMP DWORD PTR [reg*4 + table_addr]
        - GCC/Clang PIC: MOVSXD reg, [table+idx*4]; ADD reg, base; JMP reg
        - x64 RIP-relative: JMP [rip+disp + idx*scale]
        """
        refs = []
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if self.is_64 else capstone.CS_MODE_32
        md = capstone.Cs(arch, mode)
        md.detail = True
        md.skipdata = True

        size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage

        for section in self.pe.sections:
            if not self._is_code_section(section):
                continue
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            code = section.get_data()
            base_va = self.image_base + section.VirtualAddress

            insn_window = []  # v7: keep window for PIC pattern detection

            for insn in md.disasm(code, base_va):
                if insn.id == 0:
                    continue
                insn_window.append(insn)
                if len(insn_window) > 6:
                    insn_window.pop(0)

                # Pattern 1: JMP [reg*4 + disp32] or JMP [reg*4 + reg + disp32]
                if insn.id != cs_x86.X86_INS_JMP or len(insn.operands) != 1:
                    continue
                op = insn.operands[0]

                # Pattern 1a: Direct memory with scale (MSVC pattern)
                if op.type == cs_x86.X86_OP_MEM and op.mem.scale in (4, 8):
                    table_va = op.mem.disp
                    if table_va == 0:
                        continue

                    if self.is_64 and op.mem.base == cs_x86.X86_REG_RIP:
                        insn_rva = insn.address - self.image_base
                        table_rva = insn_rva + insn.size + table_va
                    else:
                        table_rva = table_va - self.image_base

                    if 0 < table_rva < size_of_image:
                        table_refs = self._read_jump_table_entries(
                            table_rva, sec_name, size_of_image,
                            is_relative=(self.is_64 and op.mem.base == cs_x86.X86_REG_RIP)
                        )
                        refs.extend(table_refs)

                # Pattern 1b: JMP reg — trace back to find table load (GCC PIC)
                elif op.type == cs_x86.X86_OP_REG:
                    jmp_reg = op.reg
                    table_refs = self._detect_pic_jump_table(
                        insn_window[:-1], jmp_reg, insn, sec_name, size_of_image
                    )
                    refs.extend(table_refs)

        return refs

    def _read_jump_table_entries(self, table_rva: int, sec_name: str,
                                  size_of_image: int, is_relative: bool) -> List[Reference]:
        """Read entries from a jump table at the given RVA."""
        refs = []
        table_foff = self._rva_to_offset(table_rva)
        if table_foff is None:
            return refs

        entry_size = 4
        max_entries = 1024

        for idx in range(max_entries):
            off = table_foff + idx * entry_size
            if off + entry_size > len(self.data):
                break
            if is_relative:
                entry_val = struct.unpack_from('<i', self.data, off)[0]
                target_rva = table_rva + entry_val
            else:
                entry_val = struct.unpack_from('<I', self.data, off)[0]
                target_rva = entry_val - self.image_base

            if not self._is_executable_rva(target_rva):
                break

            refs.append(Reference(
                file_offset=off, ref_type=RefType.JUMP_TABLE,
                target_rva=target_rva, ref_rva=table_rva + idx * entry_size,
                size_bytes=entry_size, is_relative=is_relative,
                insn_size=entry_size, section_name=sec_name,
                confidence=0.90, source=RefSource.STATIC_DISASM,
            ))
        return refs

    def _detect_pic_jump_table(self, window: list, jmp_reg: int,
                                jmp_insn, sec_name: str,
                                size_of_image: int) -> List[Reference]:
        """
        v7: Detect GCC/Clang PIC jump table pattern:
        LEA rbase, [rip+table]
        MOVSXD ridx, DWORD PTR [rbase+rindex*4]
        ADD ridx, rbase
        JMP ridx
        """
        refs = []
        # Look for ADD reg, reg pattern followed by a MOVSXD or MOV with scaled index
        add_insn = None
        movsxd_insn = None
        lea_insn = None
        base_reg = None

        for prev in reversed(window):
            if prev.id == 0:
                continue
            if prev.id == cs_x86.X86_INS_ADD and len(prev.operands) == 2:
                if prev.operands[0].type == cs_x86.X86_OP_REG and prev.operands[0].reg == jmp_reg:
                    if prev.operands[1].type == cs_x86.X86_OP_REG:
                        add_insn = prev
                        base_reg = prev.operands[1].reg
            elif prev.id == cs_x86.X86_INS_MOVSXD and len(prev.operands) == 2 and add_insn:
                if prev.operands[0].type == cs_x86.X86_OP_REG and prev.operands[0].reg == jmp_reg:
                    if prev.operands[1].type == cs_x86.X86_OP_MEM:
                        movsxd_insn = prev
            elif prev.id == cs_x86.X86_INS_LEA and len(prev.operands) == 2 and base_reg:
                if prev.operands[0].type == cs_x86.X86_OP_REG and prev.operands[0].reg == base_reg:
                    if prev.operands[1].type == cs_x86.X86_OP_MEM:
                        mem = prev.operands[1].mem
                        if self.is_64 and mem.base == cs_x86.X86_REG_RIP:
                            lea_insn = prev
                            break

        if lea_insn and movsxd_insn:
            # Compute table base from LEA [rip+disp]
            mem = lea_insn.operands[1].mem
            table_va = lea_insn.address + lea_insn.size + mem.disp
            table_rva = table_va - self.image_base
            if 0 < table_rva < size_of_image:
                refs = self._read_jump_table_entries(
                    table_rva, sec_name, size_of_image, is_relative=True
                )

        return refs

    # ── 7. Vtable Scanner ─────────────────────────────────────────
    def _find_vtables(self) -> List[Reference]:
        """Detect C++ vtables: arrays of consecutive code pointers in .rdata."""
        refs = []
        code_rva_min = None
        code_rva_max = None
        for s in self.pe.sections:
            if self._is_code_section(s):
                lo = s.VirtualAddress
                hi = s.VirtualAddress + s.Misc_VirtualSize
                if code_rva_min is None or lo < code_rva_min:
                    code_rva_min = lo
                if code_rva_max is None or hi > code_rva_max:
                    code_rva_max = hi
        if code_rva_min is None:
            return refs

        step = self.ptr_size
        fmt = '<Q' if self.is_64 else '<I'
        min_vtable_entries = 3  # at least 3 consecutive code ptrs = vtable

        for section in self.pe.sections:
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            # Vtables live in read-only data sections (.rdata, .rodata)
            if sec_name not in ('.rdata', '.rodata', 'rdata'):
                continue
            data = section.get_data()
            foff_base = section.PointerToRawData
            rva_base = section.VirtualAddress

            i = 0
            while i <= len(data) - step:
                # Try to find a run of consecutive code pointers
                run_start = i
                run_count = 0
                while i <= len(data) - step:
                    val = struct.unpack_from(fmt, data, i)[0]
                    candidate_rva = val - self.image_base
                    if code_rva_min <= candidate_rva < code_rva_max:
                        run_count += 1
                        i += step
                    else:
                        break

                if run_count >= min_vtable_entries:
                    # Check for RTTI prefix: pointer before vtable pointing to data
                    has_rtti = False
                    if run_start >= step:
                        rtti_val = struct.unpack_from(fmt, data, run_start - step)[0]
                        rtti_rva = rtti_val - self.image_base
                        # RTTI pointer should point into a valid data section
                        if 0 < rtti_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                            if not self._is_executable_rva(rtti_rva):
                                has_rtti = True
                    conf = 0.95 if has_rtti else 0.85
                    # This is likely a vtable
                    for j in range(run_count):
                        off = run_start + j * step
                        val = struct.unpack_from(fmt, data, off)[0]
                        target_rva = val - self.image_base
                        refs.append(Reference(
                            file_offset=foff_base + off,
                            ref_type=RefType.VTABLE_ENTRY,
                            target_rva=target_rva,
                            ref_rva=rva_base + off,
                            size_bytes=step, is_relative=False,
                            insn_size=step, section_name=sec_name,
                            confidence=conf, source=RefSource.HEURISTIC,
                        ))
                else:
                    i += step
        return refs

    # ── 8. Data Pointer Heuristic ─────────────────────────────────────
    def _find_data_pointers(self) -> List[Reference]:
        refs = []
        code_rva_min = None
        code_rva_max = None
        for s in self.pe.sections:
            if self._is_code_section(s):
                lo = s.VirtualAddress
                hi = s.VirtualAddress + s.Misc_VirtualSize
                if code_rva_min is None or lo < code_rva_min:
                    code_rva_min = lo
                if code_rva_max is None or hi > code_rva_max:
                    code_rva_max = hi
        if code_rva_min is None:
            return refs

        for section in self.pe.sections:
            if self._is_code_section(section):
                continue
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            data = section.get_data()
            foff_base = section.PointerToRawData
            rva_base = section.VirtualAddress
            step = self.ptr_size
            fmt = '<Q' if self.is_64 else '<I'

            for i in range(0, len(data) - step + 1, step):
                val = struct.unpack_from(fmt, data, i)[0]
                candidate_rva = val - self.image_base
                if code_rva_min <= candidate_rva < code_rva_max:
                    # Alignment check: must be pointer-aligned
                    align_mask = 7 if self.is_64 else 3
                    if candidate_rva & align_mask == 0:
                        refs.append(Reference(
                            file_offset=foff_base + i,
                            ref_type=RefType.DATA_POINTER,
                            target_rva=candidate_rva,
                            ref_rva=rva_base + i,
                            size_bytes=step, is_relative=False,
                            insn_size=step, section_name=sec_name,
                            confidence=0.6, source=RefSource.HEURISTIC,
                        ))
        return refs

    # ── v7: 9. TLS Directory ──────────────────────────────────────────
    def _find_tls_entries(self) -> List[Reference]:
        """Parse TLS directory and callback array."""
        refs = []
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 9:
            return refs
        tls_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        if tls_dir.VirtualAddress == 0 or tls_dir.Size == 0:
            return refs
        rva = tls_dir.VirtualAddress
        foff = self._rva_to_offset(rva)
        if foff is None:
            return refs
        if self.is_64:
            # IMAGE_TLS_DIRECTORY64: StartAddressOfRawData(8), EndAddressOfRawData(8),
            # AddressOfIndex(8), AddressOfCallbacks(8), ...
            if foff + 40 > len(self.data):
                return refs
            start_raw = struct.unpack_from('<Q', self.data, foff)[0]
            end_raw = struct.unpack_from('<Q', self.data, foff + 8)[0]
            addr_index = struct.unpack_from('<Q', self.data, foff + 16)[0]
            addr_callbacks = struct.unpack_from('<Q', self.data, foff + 24)[0]
            ptr_size = 8
            fmt = '<Q'
        else:
            if foff + 24 > len(self.data):
                return refs
            start_raw = struct.unpack_from('<I', self.data, foff)[0]
            end_raw = struct.unpack_from('<I', self.data, foff + 4)[0]
            addr_index = struct.unpack_from('<I', self.data, foff + 8)[0]
            addr_callbacks = struct.unpack_from('<I', self.data, foff + 12)[0]
            ptr_size = 4
            fmt = '<I'

        # TLS directory fields point to VAs
        for field_off, va in [(0, start_raw), (ptr_size, end_raw),
                              (ptr_size * 2, addr_index), (ptr_size * 3, addr_callbacks)]:
            if va == 0:
                continue
            target_rva = va - self.image_base
            if 0 < target_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                refs.append(Reference(
                    file_offset=foff + field_off, ref_type=RefType.TLS_DIR_ENTRY,
                    target_rva=target_rva, ref_rva=rva + field_off,
                    size_bytes=ptr_size, is_relative=False, insn_size=ptr_size,
                    section_name=self._section_for_rva(rva),
                    confidence=1.0, source=RefSource.PE_TABLE,
                ))

        # Parse TLS callback array
        if addr_callbacks != 0:
            cb_rva = addr_callbacks - self.image_base
            cb_foff = self._rva_to_offset(cb_rva)
            if cb_foff is not None:
                for i in range(256):  # safety cap
                    off = cb_foff + i * ptr_size
                    if off + ptr_size > len(self.data):
                        break
                    val = struct.unpack_from(fmt, self.data, off)[0]
                    if val == 0:
                        break  # null-terminated array
                    target_rva = val - self.image_base
                    if 0 < target_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                        refs.append(Reference(
                            file_offset=off, ref_type=RefType.TLS_CALLBACK,
                            target_rva=target_rva, ref_rva=cb_rva + i * ptr_size,
                            size_bytes=ptr_size, is_relative=False, insn_size=ptr_size,
                            section_name=self._section_for_rva(cb_rva),
                            confidence=1.0, source=RefSource.PE_TABLE,
                            symbol_name=f"TlsCallback_{i}",
                        ))
        return refs

    # ── v7: 10. Load Config Directory ─────────────────────────────────
    def _find_load_config_entries(self) -> List[Reference]:
        """Parse Load Configuration directory (SEH handler table, Guard CF)."""
        refs = []
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 10:
            return refs
        lc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[10]
        if lc_dir.VirtualAddress == 0 or lc_dir.Size == 0:
            return refs
        rva = lc_dir.VirtualAddress
        foff = self._rva_to_offset(rva)
        if foff is None:
            return refs

        if self.is_64:
            ptr_size = 8
            fmt = '<Q'
            # Key offsets in IMAGE_LOAD_CONFIG_DIRECTORY64
            # SecurityCookie @ 88, SEHandlerTable @ 96, SEHandlerCount @ 104
            # GuardCFCheckFunctionPointer @ 112, GuardCFDispatchFunctionPointer @ 120
            # GuardCFFunctionTable @ 128, GuardCFFunctionCount @ 136
            field_offsets = [
                (88, "SecurityCookie"), (96, "SEHandlerTable"),
                (112, "GuardCFCheckFunctionPointer"),
                (120, "GuardCFDispatchFunctionPointer"),
                (128, "GuardCFFunctionTable"),
            ]
        else:
            ptr_size = 4
            fmt = '<I'
            field_offsets = [
                (56, "SecurityCookie"), (60, "SEHandlerTable"),
                (72, "GuardCFCheckFunctionPointer"),
                (76, "GuardCFDispatchFunctionPointer"),
                (80, "GuardCFFunctionTable"),
            ]

        for field_off, name in field_offsets:
            if foff + field_off + ptr_size > len(self.data):
                continue
            va = struct.unpack_from(fmt, self.data, foff + field_off)[0]
            if va == 0:
                continue
            target_rva = va - self.image_base
            if 0 < target_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                refs.append(Reference(
                    file_offset=foff + field_off, ref_type=RefType.LOAD_CONFIG_ENTRY,
                    target_rva=target_rva, ref_rva=rva + field_off,
                    size_bytes=ptr_size, is_relative=False, insn_size=ptr_size,
                    section_name=self._section_for_rva(rva),
                    confidence=1.0, source=RefSource.PE_TABLE,
                    symbol_name=name,
                ))

        # Parse SEH handler table if present
        if self.is_64 and foff + 104 <= len(self.data):
            seh_table_va = struct.unpack_from('<Q', self.data, foff + 96)[0]
            seh_count = struct.unpack_from('<Q', self.data, foff + 104)[0]
        elif not self.is_64 and foff + 68 <= len(self.data):
            seh_table_va = struct.unpack_from('<I', self.data, foff + 60)[0]
            seh_count = struct.unpack_from('<I', self.data, foff + 64)[0]
        else:
            seh_table_va, seh_count = 0, 0

        if seh_table_va != 0 and 0 < seh_count < 10000:
            seh_rva = seh_table_va - self.image_base
            seh_foff = self._rva_to_offset(seh_rva)
            if seh_foff is not None:
                for i in range(seh_count):
                    off = seh_foff + i * 4  # RVA entries are 32-bit
                    if off + 4 > len(self.data):
                        break
                    handler_rva = struct.unpack_from('<I', self.data, off)[0]
                    if 0 < handler_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                        refs.append(Reference(
                            file_offset=off, ref_type=RefType.LOAD_CONFIG_ENTRY,
                            target_rva=handler_rva, ref_rva=seh_rva + i * 4,
                            size_bytes=4, is_relative=False, insn_size=4,
                            section_name=self._section_for_rva(seh_rva),
                            confidence=1.0, source=RefSource.PE_TABLE,
                            symbol_name=f"SEHandler_{i}",
                        ))

        # Parse Guard CF function table if present
        if self.is_64:
            cfguard_table_off = 128
            cfguard_count_off = 136
        else:
            cfguard_table_off = 80
            cfguard_count_off = 84

        if foff + cfguard_count_off + ptr_size <= len(self.data):
            cf_table_va = struct.unpack_from(fmt, self.data, foff + cfguard_table_off)[0]
            cf_count = struct.unpack_from(fmt, self.data, foff + cfguard_count_off)[0]
            if cf_table_va != 0 and 0 < cf_count < 500000:
                cf_rva = cf_table_va - self.image_base
                cf_foff = self._rva_to_offset(cf_rva)
                if cf_foff is not None:
                    # Guard CF entries are RVA + flags (4 bytes + optional extra)
                    entry_size = 4
                    # Check for STRIDE info in load config (GuardFlags at offset 144/88)
                    for i in range(cf_count):
                        off = cf_foff + i * entry_size
                        if off + 4 > len(self.data):
                            break
                        func_rva = struct.unpack_from('<I', self.data, off)[0]
                        if 0 < func_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                            refs.append(Reference(
                                file_offset=off, ref_type=RefType.LOAD_CONFIG_ENTRY,
                                target_rva=func_rva, ref_rva=cf_rva + i * entry_size,
                                size_bytes=4, is_relative=False, insn_size=entry_size,
                                section_name=self._section_for_rva(cf_rva),
                                confidence=1.0, source=RefSource.PE_TABLE,
                                symbol_name=f"GuardCF_{i}",
                            ))
        return refs

    # ── v7: 11. Delay-Load Imports ────────────────────────────────────
    def _find_delay_imports(self) -> List[Reference]:
        """Parse delay-load import directory."""
        refs = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            return refs
        for dll_entry in self.pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = dll_entry.dll.decode('ascii', errors='replace') if dll_entry.dll else "?"
            for entry in dll_entry.imports:
                if entry.address is None:
                    continue
                iat_rva = entry.address - self.image_base
                eof = self._rva_to_offset(iat_rva)
                if eof is not None:
                    sym_name = entry.name.decode('ascii', errors='replace') if entry.name else f"ord_{entry.ordinal}"
                    refs.append(Reference(
                        file_offset=eof, ref_type=RefType.DELAY_IMPORT,
                        target_rva=iat_rva, ref_rva=iat_rva,
                        size_bytes=self.ptr_size, is_relative=False,
                        insn_size=self.ptr_size,
                        section_name=self._section_for_rva(iat_rva),
                        confidence=1.0, source=RefSource.PE_TABLE,
                        symbol_name=f"delay!{dll_name}!{sym_name}",
                    ))
        return refs

    # ── v7: 12. Debug Directory ───────────────────────────────────────
    def _find_debug_entries(self) -> List[Reference]:
        """Parse debug directory entries."""
        refs = []
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 6:
            return refs
        dbg_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]
        if dbg_dir.VirtualAddress == 0 or dbg_dir.Size == 0:
            return refs
        rva = dbg_dir.VirtualAddress
        foff = self._rva_to_offset(rva)
        if foff is None:
            return refs
        num_entries = dbg_dir.Size // 28  # IMAGE_DEBUG_DIRECTORY is 28 bytes
        for i in range(num_entries):
            off = foff + i * 28
            if off + 28 > len(self.data):
                break
            addr_rva = struct.unpack_from('<I', self.data, off + 20)[0]
            pointer_raw = struct.unpack_from('<I', self.data, off + 24)[0]
            if addr_rva > 0 and addr_rva < self.pe.OPTIONAL_HEADER.SizeOfImage:
                refs.append(Reference(
                    file_offset=off + 20, ref_type=RefType.DEBUG_DIR_ENTRY,
                    target_rva=addr_rva, ref_rva=rva + i * 28 + 20,
                    size_bytes=4, is_relative=False, insn_size=4,
                    section_name=self._section_for_rva(rva),
                    confidence=1.0, source=RefSource.PE_TABLE,
                    symbol_name=f"DebugDir_{i}_RVA",
                ))
        return refs

    # ── v7: 13. Indirect Control Flow (call rax, jmp [reg]) ──────────
    def _find_indirect_control_flow(self) -> List[Reference]:
        """
        Track indirect calls/jumps: call rax, jmp [rbx+8], etc.
        Uses backward dataflow to resolve the target when possible.
        """
        refs = []
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if self.is_64 else capstone.CS_MODE_32
        md = capstone.Cs(arch, mode)
        md.detail = True
        md.skipdata = True

        size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage

        for section in self.pe.sections:
            if not self._is_code_section(section):
                continue
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            code = section.get_data()
            base_va = self.image_base + section.VirtualAddress

            # Collect a small backward window of instructions for dataflow
            insn_window = []
            window_size = 8  # look back 8 instructions

            for insn in md.disasm(code, base_va):
                # Skip SKIPDATA pseudo-instructions (id==0) — no detail info
                if insn.id == 0:
                    continue
                insn_window.append(insn)
                if len(insn_window) > window_size:
                    insn_window.pop(0)

                if insn.id not in (cs_x86.X86_INS_CALL, cs_x86.X86_INS_JMP):
                    continue
                if len(insn.operands) != 1:
                    continue
                op = insn.operands[0]

                # Direct register: call rax, jmp rcx
                if op.type == cs_x86.X86_OP_REG:
                    target_reg = op.reg
                    resolved_va = self._trace_reg_load(insn_window[:-1], target_reg)
                    ref_type = (RefType.INDIRECT_CALL
                                if insn.id == cs_x86.X86_INS_CALL
                                else RefType.INDIRECT_JUMP)
                    insn_rva = insn.address - self.image_base
                    foff = self._rva_to_offset(insn_rva)
                    if foff is None:
                        continue

                    if resolved_va is not None:
                        target_rva = resolved_va - self.image_base
                        if 0 < target_rva < size_of_image:
                            refs.append(Reference(
                                file_offset=foff, ref_type=ref_type,
                                target_rva=target_rva, ref_rva=insn_rva,
                                size_bytes=0, is_relative=False, insn_size=insn.size,
                                section_name=sec_name,
                                confidence=0.7, source=RefSource.DATAFLOW,
                            ))

                # Memory indirect: call [rax+8], jmp QWORD PTR [rip+0x1234]
                elif op.type == cs_x86.X86_OP_MEM:
                    insn_rva = insn.address - self.image_base
                    foff = self._rva_to_offset(insn_rva)
                    if foff is None:
                        continue
                    # v7.1: Handle call/jmp [abs_addr] (x86-32 memory indirect through data)
                    if not self.is_64 and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp != 0:
                        ptr_rva = op.mem.disp - self.image_base
                        deref = self._read_pointer_at_rva(ptr_rva)
                        if deref is not None:
                            target_rva = deref - self.image_base
                            if 0 < target_rva < size_of_image:
                                ref_type = (RefType.INDIRECT_CALL_MEM
                                            if insn.id == cs_x86.X86_INS_CALL
                                            else RefType.INDIRECT_JUMP)
                                refs.append(Reference(
                                    file_offset=foff, ref_type=ref_type,
                                    target_rva=target_rva, ref_rva=insn_rva,
                                    size_bytes=0, is_relative=False,
                                    insn_size=insn.size, section_name=sec_name,
                                    confidence=0.85, source=RefSource.DATAFLOW,
                                ))
                        continue
                    # RIP-relative memory indirect is already caught by disassembly pass
                    if self.is_64 and op.mem.base == cs_x86.X86_REG_RIP:
                        continue
                    # For other reg+disp patterns, try to resolve base register
                    if op.mem.base != 0 and op.mem.disp != 0:
                        base_reg = op.mem.base
                        resolved_base = self._trace_reg_load(insn_window[:-1], base_reg)
                        if resolved_base is not None:
                            effective_va = resolved_base + op.mem.disp
                            target_rva = effective_va - self.image_base
                            ref_type = (RefType.INDIRECT_CALL
                                        if insn.id == cs_x86.X86_INS_CALL
                                        else RefType.INDIRECT_JUMP)
                            insn_rva = insn.address - self.image_base
                            foff = self._rva_to_offset(insn_rva)
                            if foff and 0 < target_rva < size_of_image:
                                refs.append(Reference(
                                    file_offset=foff, ref_type=ref_type,
                                    target_rva=target_rva, ref_rva=insn_rva,
                                    size_bytes=0, is_relative=False,
                                    insn_size=insn.size, section_name=sec_name,
                                    confidence=0.5, source=RefSource.DATAFLOW,
                                ))
        return refs

    def _trace_reg_load(self, window: list, target_reg: int) -> Optional[int]:
        """
        Backward dataflow: trace a register to find its most recent load value.
        Handles: MOV reg, imm; LEA reg, [rip+disp]; MOV reg, [rip+disp].
        v7.1: Also dereferences loads from data sections to resolve function pointers.
        Returns the resolved VA or None.
        """
        for insn in reversed(window):
            if insn.id == 0:
                continue
            if len(insn.operands) < 2:
                continue
            dst = insn.operands[0]
            if dst.type != cs_x86.X86_OP_REG or dst.reg != target_reg:
                continue

            src = insn.operands[1]
            # MOV reg, imm64/imm32
            if insn.id == cs_x86.X86_INS_MOV and src.type == cs_x86.X86_OP_IMM:
                return src.imm
            # LEA reg, [rip+disp]
            if insn.id == cs_x86.X86_INS_LEA and src.type == cs_x86.X86_OP_MEM:
                if self.is_64 and src.mem.base == cs_x86.X86_REG_RIP:
                    return insn.address + insn.size + src.mem.disp
            # MOV reg, [rip+disp] — load from memory, dereference the pointer
            if insn.id == cs_x86.X86_INS_MOV and src.type == cs_x86.X86_OP_MEM:
                if self.is_64 and src.mem.base == cs_x86.X86_REG_RIP:
                    ptr_va = insn.address + insn.size + src.mem.disp
                    ptr_rva = ptr_va - self.image_base
                    deref = self._read_pointer_at_rva(ptr_rva)
                    if deref is not None:
                        return deref
                    return ptr_va
                # v7.1: MOV reg, [abs_addr] (x86-32) — dereference data section pointer
                if not self.is_64 and src.mem.base == 0 and src.mem.index == 0 and src.mem.disp != 0:
                    ptr_rva = src.mem.disp - self.image_base
                    deref = self._read_pointer_at_rva(ptr_rva)
                    if deref is not None:
                        return deref

            # If the register is written by something we can't resolve, stop
            break
        return None

    def _read_pointer_at_rva(self, rva: int) -> Optional[int]:
        """
        v7.1: Read a pointer value from a data section at the given RVA.
        Returns the dereferenced VA if it points to valid image memory, else None.
        """
        size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage
        if rva <= 0 or rva >= size_of_image:
            return None
        foff = self._rva_to_offset(rva)
        if foff is None:
            return None
        if self.is_64:
            if foff + 8 > len(self.data):
                return None
            val = struct.unpack_from('<Q', self.data, foff)[0]
        else:
            if foff + 4 > len(self.data):
                return None
            val = struct.unpack_from('<I', self.data, foff)[0]
        target_rva = val - self.image_base
        if 0 < target_rva < size_of_image:
            return val
        return None

    # ── v7: 14. Code Signing Detection ────────────────────────────────
    def detect_signature(self) -> Optional[Dict]:
        """Detect Authenticode / code signing in PE."""
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
            return None
        cert_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if cert_dir.VirtualAddress == 0 or cert_dir.Size == 0:
            return None
        return {
            'type': 'authenticode',
            'offset': cert_dir.VirtualAddress,  # This is a file offset, not RVA
            'size': cert_dir.Size,
            'warning': 'Binary has Authenticode signature — modifications will invalidate it',
        }

    # ── v7.1: 15. Resource Directory Parsing ──────────────────────────
    def _find_resource_entries(self) -> List[Reference]:
        """
        Parse the PE resource directory tree and extract all OffsetToData RVAs.
        These point to the actual resource data and must be updated during shifts.
        """
        refs = []
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 2:
            return refs
        rsrc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        if rsrc_dir.VirtualAddress == 0 or rsrc_dir.Size == 0:
            return refs

        rsrc_rva = rsrc_dir.VirtualAddress
        rsrc_foff = self._rva_to_offset(rsrc_rva)
        if rsrc_foff is None:
            return refs

        # Find the .rsrc section for bounds checking
        rsrc_section = None
        for s in self.pe.sections:
            if s.VirtualAddress == rsrc_rva:
                rsrc_section = s
                break
        if rsrc_section is None:
            return refs
        rsrc_end = rsrc_foff + rsrc_section.SizeOfRawData

        visited = set()
        self._walk_resource_dir(rsrc_rva, rsrc_foff, rsrc_foff, rsrc_end, refs, visited, depth=0)
        return refs

    def _walk_resource_dir(self, rsrc_rva: int, dir_foff: int,
                           rsrc_base_foff: int, rsrc_end: int,
                           refs: List, visited: set, depth: int):
        """Recursively walk IMAGE_RESOURCE_DIRECTORY entries."""
        if depth > 5 or dir_foff in visited:
            return
        visited.add(dir_foff)

        if dir_foff + 16 > rsrc_end:
            return

        num_named = struct.unpack_from('<H', self.data, dir_foff + 12)[0]
        num_id = struct.unpack_from('<H', self.data, dir_foff + 14)[0]
        total = num_named + num_id

        entry_off = dir_foff + 16  # entries start after the 16-byte directory header
        for _ in range(total):
            if entry_off + 8 > rsrc_end:
                break
            # Each entry: Name/ID (4 bytes) + OffsetToData (4 bytes)
            offset_to_data = struct.unpack_from('<I', self.data, entry_off + 4)[0]

            if offset_to_data & 0x80000000:
                # High bit set → points to another IMAGE_RESOURCE_DIRECTORY
                sub_offset = offset_to_data & 0x7FFFFFFF
                sub_foff = rsrc_base_foff + sub_offset
                self._walk_resource_dir(rsrc_rva, sub_foff, rsrc_base_foff,
                                        rsrc_end, refs, visited, depth + 1)
            else:
                # Points to IMAGE_RESOURCE_DATA_ENTRY
                data_entry_foff = rsrc_base_foff + offset_to_data
                if data_entry_foff + 16 <= rsrc_end:
                    # IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4), Size(4), CodePage(4), Reserved(4)
                    data_rva = struct.unpack_from('<I', self.data, data_entry_foff)[0]
                    if data_rva > 0:
                        refs.append(Reference(
                            file_offset=data_entry_foff,
                            ref_type=RefType.RESOURCE_RVA,
                            target_rva=data_rva, ref_rva=0,
                            size_bytes=4, is_relative=False,
                            insn_size=0, section_name='.rsrc',
                            confidence=1.0, source=RefSource.PE_TABLE,
                        ))
            entry_off += 8

    # ── v7.1: 16. Bound Import Table Parsing ─────────────────────────
    def _find_bound_imports(self) -> List[Reference]:
        """
        Parse the PE bound import table (data directory index 11).
        Bound imports contain OffsetModuleName values that need updating after shifts.
        """
        refs = []
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 11:
            return refs
        bound_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[11]
        if bound_dir.VirtualAddress == 0 or bound_dir.Size == 0:
            return refs

        # Bound import table is at a file offset (not RVA) stored in VirtualAddress
        # Actually in practice this is an RVA in the headers area
        foff = bound_dir.VirtualAddress
        end = foff + bound_dir.Size

        if foff >= len(self.data) or end > len(self.data):
            return refs

        # IMAGE_BOUND_IMPORT_DESCRIPTOR: TimeDateStamp(4), OffsetModuleName(2), NumberOfModuleForwarderRefs(2)
        pos = foff
        while pos + 8 <= end:
            timestamp = struct.unpack_from('<I', self.data, pos)[0]
            offset_name = struct.unpack_from('<H', self.data, pos + 4)[0]
            num_fwdr = struct.unpack_from('<H', self.data, pos + 6)[0]

            # Null terminator
            if timestamp == 0 and offset_name == 0:
                break

            # OffsetModuleName is relative to the start of the bound import table
            if offset_name > 0:
                name_foff = foff + offset_name
                if name_foff < end:
                    refs.append(Reference(
                        file_offset=pos + 4,
                        ref_type=RefType.BOUND_IMPORT_RVA,
                        target_rva=offset_name,  # offset within bound import table
                        ref_rva=0,
                        size_bytes=2, is_relative=False,
                        insn_size=0, section_name='bound_import',
                        confidence=1.0, source=RefSource.PE_TABLE,
                    ))

            # Skip forwarder refs (same structure, 8 bytes each)
            pos += 8 + num_fwdr * 8

        return refs


class ELFReferenceFinder:
    """
    Finds ALL address references in an ELF binary.

    Six analysis passes:
    1. ELF relocations (.rel/.rela sections) → confidence 1.0
    2. Capstone disassembly → relative jumps/calls, RIP-relative → confidence 1.0
    3. Symbol table (.symtab/.dynsym) → confidence 1.0
    4. GOT/PLT entries → confidence 1.0
    5. .init_array / .fini_array → confidence 1.0
    6. Data pointer heuristic scan → confidence 0.6
    """

    def __init__(self, elf_path: str):
        if not HAS_ELFTOOLS:
            raise ImportError("pyelftools is required for ELF reference finding")
        if capstone is None:
            raise ImportError("capstone is required for disassembly")
        self.elf_path = elf_path
        self._fobj = open(elf_path, 'rb')
        self.elf = ELFFile(self._fobj)
        with open(elf_path, 'rb') as f:
            self.data = bytearray(f.read())
        self.is_64 = self.elf.elfclass == 64
        self.ptr_size = 8 if self.is_64 else 4
        self.is_pie = self.elf.header['e_type'] == 'ET_DYN'
        self.image_base = self._compute_image_base()
        self._section_cache = {}
        for sec in self.elf.iter_sections():
            self._section_cache[sec.name] = sec
        self.e_machine = self.elf.header['e_machine']
        self.endian = '>' if self.elf.little_endian is False else '<'

    def _get_capstone_arch(self):
        """Return (arch, mode) tuple for Capstone based on ELF e_machine."""
        machine = self.e_machine
        mapping = {
            'EM_X86_64':    (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
            'EM_386':       (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
            'EM_ARM':       (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
            'EM_AARCH64':   (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            'EM_MIPS':      (capstone.CS_ARCH_MIPS,  capstone.CS_MODE_MIPS32),
            'EM_PPC':       (capstone.CS_ARCH_PPC,   capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN),
            'EM_PPC64':     (capstone.CS_ARCH_PPC,   capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN),
        }
        result = mapping.get(machine)
        if result is not None:
            return result
        # Fallback: try x86 based on bitness
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.is_64 else capstone.CS_MODE_32)

    @property
    def is_x86(self) -> bool:
        return self.e_machine in ('EM_X86_64', 'EM_386')

    def _compute_image_base(self) -> int:
        min_vaddr = None
        for seg in self.elf.iter_segments():
            if seg.header['p_type'] == 'PT_LOAD':
                vaddr = seg.header['p_vaddr']
                if min_vaddr is None or vaddr < min_vaddr:
                    min_vaddr = vaddr
        return min_vaddr or 0

    def _vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.elf.iter_segments():
            if seg.header['p_type'] != 'PT_LOAD':
                continue
            va = seg.header['p_vaddr']
            foff = seg.header['p_offset']
            fsz = seg.header['p_filesz']
            if va <= vaddr < va + fsz:
                return vaddr - va + foff
        return None

    def _offset_to_vaddr(self, offset: int) -> Optional[int]:
        for seg in self.elf.iter_segments():
            if seg.header['p_type'] != 'PT_LOAD':
                continue
            foff = seg.header['p_offset']
            fsz = seg.header['p_filesz']
            va = seg.header['p_vaddr']
            if foff <= offset < foff + fsz:
                return offset - foff + va
        return None

    def _section_for_vaddr(self, vaddr: int) -> str:
        for sec in self.elf.iter_sections():
            sh_addr = sec.header['sh_addr']
            sh_size = sec.header['sh_size']
            if sh_addr and sh_addr <= vaddr < sh_addr + sh_size:
                return sec.name
        return "?"

    def _is_executable_vaddr(self, vaddr: int) -> bool:
        for seg in self.elf.iter_segments():
            if seg.header['p_type'] != 'PT_LOAD':
                continue
            if not (seg.header['p_flags'] & 0x1):  # PF_X
                continue
            va = seg.header['p_vaddr']
            msz = seg.header['p_memsz']
            if va <= vaddr < va + msz:
                return True
        return False

    def _get_code_range(self) -> Tuple[Optional[int], Optional[int]]:
        lo, hi = None, None
        for seg in self.elf.iter_segments():
            if seg.header['p_type'] != 'PT_LOAD':
                continue
            if not (seg.header['p_flags'] & 0x1):
                continue
            va = seg.header['p_vaddr']
            end = va + seg.header['p_memsz']
            if lo is None or va < lo:
                lo = va
            if hi is None or end > hi:
                hi = end
        return lo, hi

    def close(self):
        if self._fobj and not self._fobj.closed:
            self._fobj.close()

    def find_all(self, callback=None) -> ReferenceDatabase:
        db = ReferenceDatabase()
        steps = [
            ("ELF relocations", self._find_from_relocations),
            ("Disassembly (code segments)", self._find_from_disassembly),
            ("Symbol tables", self._find_from_symbols),
            ("GOT / PLT", self._find_got_plt),
            ("Init/Fini arrays", self._find_init_fini),
            ("Dynamic tags", self._find_dynamic_tags),          # v7
            ("Data pointers (heuristic)", self._find_data_pointers),
        ]
        for i, (name, func) in enumerate(steps):
            if callback:
                callback(name, i, len(steps))
            for ref in func():
                db.add(ref)
        if callback:
            callback("Done", len(steps), len(steps))
        self.close()
        return db

    # ── 1. ELF Relocations ────────────────────────────────────────────
    def _find_from_relocations(self) -> List[Reference]:
        refs = []
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            symtab = self.elf.get_section(sec.header['sh_link'])
            for reloc in sec.iter_relocations():
                r_offset = reloc['r_offset']
                r_type = reloc['r_info_type']
                foff = self._vaddr_to_offset(r_offset)
                if foff is None:
                    continue

                sym_name = ""
                target_vaddr = 0
                if reloc['r_info_sym'] != 0 and symtab:
                    sym = symtab.get_symbol(reloc['r_info_sym'])
                    if sym:
                        sym_name = sym.name or ""
                        target_vaddr = sym['st_value']

                addend = reloc.get('r_addend', 0) if reloc.is_RELA() else 0
                target_vaddr += addend

                # Determine ref type from ELF relocation type
                if self.is_x86 and self.is_64:
                    # x86-64 relocation types
                    if r_type == 1:   # R_X86_64_64
                        ref_type = RefType.ELF_RELATIVE
                        size = 8
                    elif r_type == 2:   # R_X86_64_PC32
                        ref_type = RefType.REL_CALL
                        size = 4
                    elif r_type == 6:   # R_X86_64_GLOB_DAT
                        ref_type = RefType.GOT_ENTRY
                        size = 8
                    elif r_type == 7:   # R_X86_64_JUMP_SLOT
                        ref_type = RefType.PLT_STUB
                        size = 8
                    elif r_type == 8:   # R_X86_64_RELATIVE
                        ref_type = RefType.ELF_RELATIVE
                        size = 8
                        if addend:
                            target_vaddr = self.image_base + addend
                    else:
                        ref_type = RefType.ELF_RELATIVE
                        size = 8
                elif self.is_x86:
                    # x86-32 relocation types
                    if r_type == 1:     # R_386_32
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                    elif r_type == 2:   # R_386_PC32
                        ref_type = RefType.REL_CALL
                        size = 4
                    elif r_type == 6:   # R_386_GLOB_DAT
                        ref_type = RefType.GOT_ENTRY
                        size = 4
                    elif r_type == 7:   # R_386_JMP_SLOT
                        ref_type = RefType.PLT_STUB
                        size = 4
                    elif r_type == 8:   # R_386_RELATIVE
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                        if foff + 4 <= len(self.data):
                            stored = struct.unpack_from(f'{self.endian}I', self.data, foff)[0]
                            target_vaddr = stored
                    else:
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                elif self.e_machine == 'EM_AARCH64':
                    # AArch64 relocation types
                    if r_type == 257:     # R_AARCH64_ABS64
                        ref_type = RefType.ELF_RELATIVE
                        size = 8
                    elif r_type == 258:   # R_AARCH64_ABS32
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                    elif r_type == 1025:  # R_AARCH64_GLOB_DAT
                        ref_type = RefType.GOT_ENTRY
                        size = 8
                    elif r_type == 1026:  # R_AARCH64_JUMP_SLOT
                        ref_type = RefType.PLT_STUB
                        size = 8
                    elif r_type == 1027:  # R_AARCH64_RELATIVE
                        ref_type = RefType.ELF_RELATIVE
                        size = 8
                        if addend:
                            target_vaddr = self.image_base + addend
                    elif r_type == 275:   # R_AARCH64_CALL26
                        ref_type = RefType.REL_CALL
                        size = 4
                    elif r_type == 282:   # R_AARCH64_JUMP26
                        ref_type = RefType.REL_JUMP_NEAR
                        size = 4
                    else:
                        ref_type = RefType.ELF_RELATIVE
                        size = 8
                elif self.e_machine == 'EM_ARM':
                    # ARM32 relocation types
                    if r_type == 2:       # R_ARM_ABS32
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                    elif r_type == 3:     # R_ARM_REL32
                        ref_type = RefType.REL_CALL
                        size = 4
                    elif r_type == 21:    # R_ARM_GLOB_DAT
                        ref_type = RefType.GOT_ENTRY
                        size = 4
                    elif r_type == 22:    # R_ARM_JUMP_SLOT
                        ref_type = RefType.PLT_STUB
                        size = 4
                    elif r_type == 23:    # R_ARM_RELATIVE
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                        if foff + 4 <= len(self.data):
                            stored = struct.unpack_from(f'{self.endian}I', self.data, foff)[0]
                            target_vaddr = stored
                    elif r_type == 28:    # R_ARM_CALL
                        ref_type = RefType.REL_CALL
                        size = 4
                    elif r_type == 29:    # R_ARM_JUMP24
                        ref_type = RefType.REL_JUMP_NEAR
                        size = 4
                    else:
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                elif self.e_machine == 'EM_MIPS':
                    # MIPS relocation types
                    if r_type == 2:       # R_MIPS_32
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                    elif r_type == 4:     # R_MIPS_26
                        ref_type = RefType.REL_CALL
                        size = 4
                    elif r_type == 5:     # R_MIPS_HI16
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                    elif r_type == 6:     # R_MIPS_LO16
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                    elif r_type == 10:    # R_MIPS_JUMP_ADDR
                        ref_type = RefType.PLT_STUB
                        size = 4
                    else:
                        ref_type = RefType.ELF_RELATIVE
                        size = 4
                else:
                    # Generic fallback
                    ref_type = RefType.ELF_RELATIVE
                    size = self.ptr_size

                is_rel = r_type == 2  # PC-relative
                refs.append(Reference(
                    file_offset=foff, ref_type=ref_type,
                    target_rva=target_vaddr, ref_rva=r_offset,
                    size_bytes=size, is_relative=is_rel,
                    insn_size=size,
                    section_name=self._section_for_vaddr(r_offset),
                    confidence=1.0, source=RefSource.ELF_RELOC,
                    symbol_name=sym_name,
                ))
        return refs

    # ── 2. Disassembly ────────────────────────────────────────────────
    def _find_from_disassembly(self) -> List[Reference]:
        refs = []
        arch, mode = self._get_capstone_arch()
        md = capstone.Cs(arch, mode)
        md.detail = True
        md.skipdata = True

        for sec in self.elf.iter_sections():
            if not (sec.header['sh_flags'] & 0x4):  # SHF_EXECINSTR
                continue
            sec_name = sec.name
            code = sec.data()
            base_va = sec.header['sh_addr']
            sec_foff = sec.header['sh_offset']

            for insn in md.disasm(code, base_va):
                mnemonic = insn.mnemonic.lower()
                insn_vaddr = insn.address
                insn_foff = sec_foff + (insn_vaddr - base_va)

                if self.is_x86:
                    self._disasm_x86_insn(refs, insn, insn_vaddr, insn_foff, sec_name)
                else:
                    self._disasm_generic_insn(refs, insn, insn_vaddr, insn_foff, sec_name)
        return refs

    def _disasm_x86_insn(self, refs, insn, insn_vaddr, insn_foff, sec_name):
        """Handle x86/x86-64 instruction reference extraction."""
        mnemonic = insn.mnemonic.lower()

        # ── Relative CALL (E8 rel32) ──
        if insn.id == cs_x86.X86_INS_CALL and len(insn.operands) == 1:
            op = insn.operands[0]
            if op.type == cs_x86.X86_OP_IMM:
                target_va = op.imm
                disp_off = insn.size - 4
                refs.append(Reference(
                    file_offset=insn_foff + disp_off,
                    ref_type=RefType.REL_CALL,
                    target_rva=target_va, ref_rva=insn_vaddr,
                    size_bytes=4, is_relative=True,
                    insn_size=insn.size, section_name=sec_name,
                    confidence=1.0, source=RefSource.STATIC_DISASM,
                ))

        # ── Relative JMP ──
        elif insn.id == cs_x86.X86_INS_JMP and len(insn.operands) == 1:
            op = insn.operands[0]
            if op.type == cs_x86.X86_OP_IMM:
                target_va = op.imm
                if insn.size == 2:
                    refs.append(Reference(
                        file_offset=insn_foff + 1,
                        ref_type=RefType.REL_JUMP_SHORT,
                        target_rva=target_va, ref_rva=insn_vaddr,
                        size_bytes=1, is_relative=True,
                        insn_size=insn.size, section_name=sec_name,
                        confidence=1.0, source=RefSource.STATIC_DISASM,
                    ))
                else:
                    disp_off = insn.size - 4
                    refs.append(Reference(
                        file_offset=insn_foff + disp_off,
                        ref_type=RefType.REL_JUMP_NEAR,
                        target_rva=target_va, ref_rva=insn_vaddr,
                        size_bytes=4, is_relative=True,
                        insn_size=insn.size, section_name=sec_name,
                        confidence=1.0, source=RefSource.STATIC_DISASM,
                    ))

        # ── Conditional branches ──
        elif mnemonic.startswith('j') and mnemonic != 'jmp':
            if len(insn.operands) == 1 and insn.operands[0].type == cs_x86.X86_OP_IMM:
                target_va = insn.operands[0].imm
                if insn.size == 2:
                    refs.append(Reference(
                        file_offset=insn_foff + 1,
                        ref_type=RefType.REL_COND_SHORT,
                        target_rva=target_va, ref_rva=insn_vaddr,
                        size_bytes=1, is_relative=True,
                        insn_size=insn.size, section_name=sec_name,
                        confidence=1.0, source=RefSource.STATIC_DISASM,
                    ))
                else:
                    disp_off = insn.size - 4
                    refs.append(Reference(
                        file_offset=insn_foff + disp_off,
                        ref_type=RefType.REL_COND_NEAR,
                        target_rva=target_va, ref_rva=insn_vaddr,
                        size_bytes=4, is_relative=True,
                        insn_size=insn.size, section_name=sec_name,
                        confidence=1.0, source=RefSource.STATIC_DISASM,
                    ))

        # ── RIP-relative addressing (x64) ──
        elif self.is_64 and len(insn.operands) >= 2:
            for op in insn.operands:
                if (op.type == cs_x86.X86_OP_MEM and
                        op.mem.base == cs_x86.X86_REG_RIP and
                        op.mem.index == 0):
                    disp = op.mem.disp
                    target_va = insn_vaddr + insn.size + disp
                    if hasattr(insn, 'disp_offset') and insn.disp_offset > 0:
                        disp_foff = insn_foff + insn.disp_offset
                    else:
                        disp_foff = insn_foff + insn.size - 4
                        for op2 in insn.operands:
                            if op2.type == cs_x86.X86_OP_IMM:
                                disp_foff -= op2.size
                                break
                    refs.append(Reference(
                        file_offset=disp_foff,
                        ref_type=RefType.RIP_RELATIVE,
                        target_rva=target_va, ref_rva=insn_vaddr,
                        size_bytes=4, is_relative=True,
                        insn_size=insn.size, section_name=sec_name,
                        confidence=1.0, source=RefSource.STATIC_DISASM,
                    ))
                    break

    def _disasm_generic_insn(self, refs, insn, insn_vaddr, insn_foff, sec_name):
        """Handle non-x86 instruction reference extraction using generic Capstone groups."""
        if insn.id == 0:
            return
        if not insn.groups:
            return

        is_jump = capstone.CS_GRP_JUMP in insn.groups
        is_call = capstone.CS_GRP_CALL in insn.groups

        if (is_jump or is_call) and insn.operands:
            op0 = insn.operands[0]
            if op0.type == capstone.CS_OP_IMM:
                target_va = op0.imm
                rt = RefType.REL_CALL if is_call else RefType.REL_JUMP_NEAR
                refs.append(Reference(
                    file_offset=insn_foff,
                    ref_type=rt,
                    target_rva=target_va, ref_rva=insn_vaddr,
                    size_bytes=4, is_relative=True,
                    insn_size=insn.size, section_name=sec_name,
                    confidence=1.0, source=RefSource.STATIC_DISASM,
                ))
        return refs

    # ── 3. Symbol Tables ──────────────────────────────────────────────
    def _find_from_symbols(self) -> List[Reference]:
        refs = []
        for sec in self.elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym['st_value'] == 0 or sym['st_shndx'] == 'SHN_UNDEF':
                    continue
                st_type = sym['st_info']['type']
                if st_type not in ('STT_FUNC', 'STT_OBJECT'):
                    continue
                vaddr = sym['st_value']
                refs.append(Reference(
                    file_offset=0,  # symbol table entry, not direct file ref
                    ref_type=RefType.SYMBOL_REF,
                    target_rva=vaddr, ref_rva=vaddr,
                    size_bytes=self.ptr_size, is_relative=False,
                    insn_size=self.ptr_size,
                    section_name=self._section_for_vaddr(vaddr),
                    confidence=1.0, source=RefSource.ELF_TABLE,
                    symbol_name=sym.name or "",
                ))
        return refs

    # ── 4. GOT / PLT ─────────────────────────────────────────────────
    def _find_got_plt(self) -> List[Reference]:
        refs = []
        fmt = f'{self.endian}Q' if self.is_64 else f'{self.endian}I'
        step = self.ptr_size

        for sec_name in ('.got', '.got.plt'):
            sec = self._section_cache.get(sec_name)
            if sec is None:
                continue
            data = sec.data()
            base_va = sec.header['sh_addr']
            base_foff = sec.header['sh_offset']

            for i in range(0, len(data) - step + 1, step):
                val = struct.unpack_from(fmt, data, i)[0]
                if val == 0:
                    continue
                # GOT entries point to code or PLT stubs
                if self._is_executable_vaddr(val):
                    refs.append(Reference(
                        file_offset=base_foff + i,
                        ref_type=RefType.GOT_ENTRY,
                        target_rva=val, ref_rva=base_va + i,
                        size_bytes=step, is_relative=False,
                        insn_size=step, section_name=sec_name,
                        confidence=0.95, source=RefSource.ELF_TABLE,
                    ))
        return refs

    # ── 5. .init_array / .fini_array ──────────────────────────────────
    def _find_init_fini(self) -> List[Reference]:
        refs = []
        fmt = f'{self.endian}Q' if self.is_64 else f'{self.endian}I'
        step = self.ptr_size

        for sec_name in ('.init_array', '.fini_array', '.preinit_array'):
            sec = self._section_cache.get(sec_name)
            if sec is None:
                continue
            data = sec.data()
            base_va = sec.header['sh_addr']
            base_foff = sec.header['sh_offset']

            for i in range(0, len(data) - step + 1, step):
                val = struct.unpack_from(fmt, data, i)[0]
                if val == 0 or val == 0xFFFFFFFF or val == 0xFFFFFFFFFFFFFFFF:
                    continue
                refs.append(Reference(
                    file_offset=base_foff + i,
                    ref_type=RefType.INIT_FINI_PTR,
                    target_rva=val, ref_rva=base_va + i,
                    size_bytes=step, is_relative=False,
                    insn_size=step, section_name=sec_name,
                    confidence=1.0, source=RefSource.ELF_TABLE,
                ))
        return refs

    # ── 6. Data Pointer Heuristic ─────────────────────────────────────
    # ── v7: 7. Dynamic Tags ──────────────────────────────────────────
    def _find_dynamic_tags(self) -> List[Reference]:
        """
        Parse .dynamic section entries that contain virtual addresses.
        These must be updated when binary is shifted.
        """
        refs = []
        dyn_sec = self._section_cache.get('.dynamic')
        if dyn_sec is None:
            return refs

        # Tags that contain virtual addresses needing fixup
        addr_tags = {
            0x03: 'DT_PLTGOT',
            0x04: 'DT_HASH',
            0x05: 'DT_STRTAB',
            0x06: 'DT_SYMTAB',
            0x07: 'DT_RELA',
            0x0C: 'DT_INIT',
            0x0D: 'DT_FINI',
            0x11: 'DT_REL',
            0x15: 'DT_DEBUG',
            0x17: 'DT_JMPREL',
            0x19: 'DT_INIT_ARRAY',
            0x1A: 'DT_FINI_ARRAY',
            0x1C: 'DT_PREINIT_ARRAY',
            0x6FFFFEF5: 'DT_GNU_HASH',
            0x6FFFFFF0: 'DT_VERSYM',
            0x6FFFFFFE: 'DT_VERNEED',
            0x6FFFFFFC: 'DT_VERDEF',
        }

        # Tags with non-address values (sizes, counts, flags)
        skip_tags = {0x01, 0x02, 0x08, 0x09, 0x0A, 0x0B, 0x0E, 0x0F,
                     0x10, 0x12, 0x13, 0x14, 0x16, 0x18, 0x1B, 0x1D,
                     0x1E, 0x1F, 0x20}

        e = self.endian
        base_va = dyn_sec.header['sh_addr']
        base_foff = dyn_sec.header['sh_offset']
        entry_size = 16 if self.is_64 else 8
        data = dyn_sec.data()

        for i in range(0, len(data) - entry_size + 1, entry_size):
            if self.is_64:
                tag = struct.unpack_from(f'{e}q', data, i)[0]
                val = struct.unpack_from(f'{e}Q', data, i + 8)[0]
            else:
                tag = struct.unpack_from(f'{e}i', data, i)[0]
                val = struct.unpack_from(f'{e}I', data, i + 4)[0]

            if tag == 0:  # DT_NULL — end of dynamic section
                break
            if tag in skip_tags or tag < 0:
                continue

            tag_name = addr_tags.get(tag, f'DT_0x{tag:X}')
            if tag not in addr_tags:
                continue  # Only track known address tags

            if val == 0:
                continue

            val_off = i + (8 if self.is_64 else 4)
            foff = base_foff + val_off
            if foff + self.ptr_size > len(self.data):
                continue

            refs.append(Reference(
                file_offset=foff,
                ref_type=RefType.ELF_DYNAMIC_TAG,
                target_rva=val, ref_rva=base_va + val_off,
                size_bytes=self.ptr_size, is_relative=False,
                insn_size=self.ptr_size, section_name='.dynamic',
                confidence=1.0, source=RefSource.ELF_TABLE,
                symbol_name=tag_name,
            ))
        return refs

    # ── 8. Data Pointer Heuristic ─────────────────────────────────────
    def _find_data_pointers(self) -> List[Reference]:
        refs = []
        code_lo, code_hi = self._get_code_range()
        if code_lo is None:
            return refs

        fmt = f'{self.endian}Q' if self.is_64 else f'{self.endian}I'
        step = self.ptr_size
        align_mask = 7 if self.is_64 else 3

        for sec in self.elf.iter_sections():
            # Skip code, symbol tables, relocations, strings, etc.
            if sec.header['sh_flags'] & 0x4:  # SHF_EXECINSTR
                continue
            if sec.header['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM', 'SHT_REL',
                                          'SHT_RELA', 'SHT_STRTAB', 'SHT_NULL'):
                continue
            if sec.header['sh_size'] == 0 or sec.header['sh_addr'] == 0:
                continue

            sec_name = sec.name
            data = sec.data()
            base_va = sec.header['sh_addr']
            base_foff = sec.header['sh_offset']

            for i in range(0, len(data) - step + 1, step):
                val = struct.unpack_from(fmt, data, i)[0]
                if code_lo <= val < code_hi:
                    if val & align_mask == 0:
                        refs.append(Reference(
                            file_offset=base_foff + i,
                            ref_type=RefType.DATA_POINTER,
                            target_rva=val, ref_rva=base_va + i,
                            size_bytes=step, is_relative=False,
                            insn_size=step, section_name=sec_name,
                            confidence=0.6, source=RefSource.HEURISTIC,
                        ))
        return refs


# ─── Mach-O Reference Finder ─────────────────────────────────────────────

class MachOReferenceFinder:
    """
    Finds address references in Mach-O binaries (macOS/iOS).

    Supports: Mach-O 32/64, fat (universal) binaries.

    Analysis passes:
    1. Segment/section enumeration from load commands
    2. Capstone disassembly → relative jumps/calls, RIP-relative
    3. __got / __la_symbol_ptr pointer scanning
    4. Relocation entries from LC_DYSYMTAB
    5. __mod_init_func / __mod_term_func pointer scanning
    """

    # Mach-O magic numbers
    MH_MAGIC_32 = 0xFEEDFACE
    MH_MAGIC_64 = 0xFEEDFACF
    FAT_MAGIC   = 0xCAFEBABE
    FAT_MAGIC_LE = 0xBEBAFECA

    # Load command types
    LC_SEGMENT    = 0x01
    LC_SEGMENT_64 = 0x19
    LC_DYSYMTAB   = 0x0B

    # Mach-O CPU types
    CPU_TYPE_X86     = 7
    CPU_TYPE_X86_64  = 0x01000007
    CPU_TYPE_ARM     = 12
    CPU_TYPE_ARM64   = 0x0100000C
    CPU_TYPE_PPC     = 18
    CPU_TYPE_PPC64   = 0x01000012

    def __init__(self, path: str, arch_index: int = 0):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.buffer = bytearray(self.data)
        self.is_64 = False
        self.is_fat = False
        self.image_base = 0
        self.arch_offset = 0
        self.cputype = 0
        self.sections: List[Dict] = []
        self.segments: List[Dict] = []
        self._dysymtab = None  # (locreloff, nlocrel, extreloff, nextrel)
        self._parse_header(arch_index)

    def _parse_header(self, arch_index: int):
        magic = struct.unpack_from('<I', self.buffer, 0)[0]

        if magic == self.FAT_MAGIC or magic == self.FAT_MAGIC_LE:
            self.is_fat = True
            # Fat binary: use big-endian header
            nfat_arch = struct.unpack_from('>I', self.buffer, 4)[0]
            if arch_index >= nfat_arch:
                arch_index = 0
            # Each fat_arch is 20 bytes: cputype(4), cpusubtype(4), offset(4), size(4), align(4)
            fa_off = 8 + arch_index * 20
            self.cputype = struct.unpack_from('>I', self.buffer, fa_off)[0]
            self.arch_offset = struct.unpack_from('>I', self.buffer, fa_off + 8)[0]
            magic = struct.unpack_from('<I', self.buffer, self.arch_offset)[0]
        else:
            self.arch_offset = 0

        base = self.arch_offset
        if magic == self.MH_MAGIC_64:
            self.is_64 = True
            self.cputype = struct.unpack_from('<I', self.buffer, base + 4)[0]
            # Mach-O 64 header: 32 bytes
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            sizeofcmds = struct.unpack_from('<I', self.buffer, base + 20)[0]
            cmd_offset = base + 32
        elif magic == self.MH_MAGIC_32:
            self.is_64 = False
            self.cputype = struct.unpack_from('<I', self.buffer, base + 4)[0]
            # Mach-O 32 header: 28 bytes
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            sizeofcmds = struct.unpack_from('<I', self.buffer, base + 20)[0]
            cmd_offset = base + 28
        else:
            return  # Not a valid Mach-O

        self._parse_load_commands(cmd_offset, ncmds)

    def _get_capstone_arch(self):
        """Return (arch, mode) tuple for Capstone based on Mach-O cputype."""
        mapping = {
            self.CPU_TYPE_X86:    (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
            self.CPU_TYPE_X86_64: (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
            self.CPU_TYPE_ARM:    (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
            self.CPU_TYPE_ARM64:  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            self.CPU_TYPE_PPC:    (capstone.CS_ARCH_PPC,   capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN),
            self.CPU_TYPE_PPC64:  (capstone.CS_ARCH_PPC,   capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN),
        }
        result = mapping.get(self.cputype)
        if result is not None:
            return result
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.is_64 else capstone.CS_MODE_32)

    @property
    def is_x86(self) -> bool:
        return self.cputype in (self.CPU_TYPE_X86, self.CPU_TYPE_X86_64)

    def _parse_load_commands(self, offset: int, ncmds: int):
        for _ in range(ncmds):
            if offset + 8 > len(self.buffer):
                break
            cmd = struct.unpack_from('<I', self.buffer, offset)[0]
            cmdsize = struct.unpack_from('<I', self.buffer, offset + 4)[0]
            if cmdsize < 8:
                break

            if cmd == self.LC_SEGMENT_64:
                self._parse_segment64(offset)
            elif cmd == self.LC_SEGMENT:
                self._parse_segment32(offset)
            elif cmd == self.LC_DYSYMTAB:
                self._parse_dysymtab(offset)

            offset += cmdsize

    def _parse_segment64(self, offset: int):
        segname = self.buffer[offset + 8:offset + 24].rstrip(b'\x00').decode('ascii', errors='replace')
        vmaddr = struct.unpack_from('<Q', self.buffer, offset + 24)[0]
        vmsize = struct.unpack_from('<Q', self.buffer, offset + 32)[0]
        fileoff = struct.unpack_from('<Q', self.buffer, offset + 40)[0]
        filesize = struct.unpack_from('<Q', self.buffer, offset + 48)[0]
        nsects = struct.unpack_from('<I', self.buffer, offset + 64)[0]

        if segname == '__TEXT' and self.image_base == 0:
            self.image_base = vmaddr

        self.segments.append({
            'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
            'fileoff': fileoff, 'filesize': filesize,
        })

        # Parse sections: each section64 is 80 bytes, starts at offset+72
        sec_off = offset + 72
        for _ in range(nsects):
            if sec_off + 80 > len(self.buffer):
                break
            secname = self.buffer[sec_off:sec_off + 16].rstrip(b'\x00').decode('ascii', errors='replace')
            sec_segname = self.buffer[sec_off + 16:sec_off + 32].rstrip(b'\x00').decode('ascii', errors='replace')
            addr = struct.unpack_from('<Q', self.buffer, sec_off + 32)[0]
            size = struct.unpack_from('<Q', self.buffer, sec_off + 40)[0]
            sec_fileoff = struct.unpack_from('<I', self.buffer, sec_off + 48)[0]
            sec_type = struct.unpack_from('<I', self.buffer, sec_off + 64)[0] & 0xFF

            is_code = secname in ('__text', '__stubs', '__stub_helper')
            self.sections.append({
                'name': secname, 'segment': sec_segname,
                'addr': addr, 'size': size, 'offset': sec_fileoff,
                'type': sec_type, 'is_code': is_code,
            })
            sec_off += 80

    def _parse_segment32(self, offset: int):
        segname = self.buffer[offset + 8:offset + 24].rstrip(b'\x00').decode('ascii', errors='replace')
        vmaddr = struct.unpack_from('<I', self.buffer, offset + 24)[0]
        vmsize = struct.unpack_from('<I', self.buffer, offset + 28)[0]
        fileoff = struct.unpack_from('<I', self.buffer, offset + 32)[0]
        filesize = struct.unpack_from('<I', self.buffer, offset + 36)[0]
        nsects = struct.unpack_from('<I', self.buffer, offset + 48)[0]

        if segname == '__TEXT' and self.image_base == 0:
            self.image_base = vmaddr

        self.segments.append({
            'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
            'fileoff': fileoff, 'filesize': filesize,
        })

        # Parse sections: each section32 is 68 bytes, starts at offset+56
        sec_off = offset + 56
        for _ in range(nsects):
            if sec_off + 68 > len(self.buffer):
                break
            secname = self.buffer[sec_off:sec_off + 16].rstrip(b'\x00').decode('ascii', errors='replace')
            sec_segname = self.buffer[sec_off + 16:sec_off + 32].rstrip(b'\x00').decode('ascii', errors='replace')
            addr = struct.unpack_from('<I', self.buffer, sec_off + 32)[0]
            size = struct.unpack_from('<I', self.buffer, sec_off + 36)[0]
            sec_fileoff = struct.unpack_from('<I', self.buffer, sec_off + 40)[0]
            sec_type = struct.unpack_from('<I', self.buffer, sec_off + 48)[0] & 0xFF

            is_code = secname in ('__text', '__stubs', '__stub_helper')
            self.sections.append({
                'name': secname, 'segment': sec_segname,
                'addr': addr, 'size': size, 'offset': sec_fileoff,
                'type': sec_type, 'is_code': is_code,
            })
            sec_off += 68

    def _parse_dysymtab(self, offset: int):
        """Parse LC_DYSYMTAB load command to extract relocation table info."""
        # LC_DYSYMTAB layout (after cmd+cmdsize):
        # offset+8: ilocalsym, offset+12: nlocalsym, ...
        # offset+32: tocoff, offset+36: ntoc
        # offset+40: modtaboff, offset+44: nmodtab
        # offset+48: extrefsymoff, offset+52: nextrefsyms
        # offset+56: indirectsymoff, offset+60: nindirectsyms
        # offset+64: extreloff, offset+68: nextrel
        # offset+72: locreloff, offset+76: nlocrel
        if offset + 80 > len(self.buffer):
            return
        locreloff = struct.unpack_from('<I', self.buffer, offset + 72)[0]
        nlocrel   = struct.unpack_from('<I', self.buffer, offset + 76)[0]
        extreloff = struct.unpack_from('<I', self.buffer, offset + 64)[0]
        nextrel   = struct.unpack_from('<I', self.buffer, offset + 68)[0]
        self._dysymtab = (locreloff, nlocrel, extreloff, nextrel)

    def _vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.segments:
            va = seg['vmaddr']
            fo = seg['fileoff']
            fs = seg['filesize']
            if va <= vaddr < va + fs:
                return vaddr - va + fo
        return None

    def find_all(self, callback=None) -> ReferenceDatabase:
        db = ReferenceDatabase()
        total_passes = 4
        current = 0

        # Pass 1: Disassemble code sections
        if callback:
            current += 1
            callback(current, total_passes, "Disassembling Mach-O code sections...")
        refs = self._pass_disasm()
        for r in refs:
            db.add(r)

        # Pass 2: Pointer tables (__got, __la_symbol_ptr, __mod_init_func, etc.)
        if callback:
            current += 1
            callback(current, total_passes, "Scanning Mach-O pointer tables...")
        refs = self._pass_pointer_tables()
        for r in refs:
            db.add(r)

        # Pass 3: DYSYMTAB relocations
        if callback:
            current += 1
            callback(current, total_passes, "Parsing Mach-O DYSYMTAB relocations...")
        refs = self._pass_dysymtab_relocs()
        for r in refs:
            db.add(r)

        # Pass 4: Data pointer heuristic scan
        if callback:
            current += 1
            callback(current, total_passes, "Scanning Mach-O data pointers...")
        refs = self._pass_data_pointers()
        for r in refs:
            db.add(r)

        return db

    def _pass_disasm(self) -> List[Reference]:
        refs = []
        if capstone is None:
            return refs

        arch, mode = self._get_capstone_arch()
        md = capstone.Cs(arch, mode)
        md.detail = True

        for sec in self.sections:
            if not sec['is_code']:
                continue
            start_off = sec['offset']
            size = sec['size']
            va = sec['addr']
            code = bytes(self.buffer[start_off:start_off + size])
            sec_name = sec['name']

            for insn in md.disasm(code, va):
                if insn.id == 0:
                    continue
                # Relative jumps and calls
                if len(insn.groups) > 0:
                    is_jump = capstone.CS_GRP_JUMP in insn.groups
                    is_call = capstone.CS_GRP_CALL in insn.groups
                    if (is_jump or is_call) and insn.operands:
                        op0 = insn.operands[0]
                        if op0.type == capstone.CS_OP_IMM:
                            target = op0.imm
                            if self.is_x86:
                                # x86 size-based ref type dispatch
                                disp_size = insn.size - 1
                                if insn.size == 2:
                                    rt = RefType.REL_JUMP_SHORT if is_jump else RefType.REL_CALL
                                    disp_size = 1
                                elif insn.size == 5:
                                    rt = RefType.REL_CALL if is_call else RefType.REL_JUMP_NEAR
                                    disp_size = 4
                                elif insn.size == 6:
                                    rt = RefType.REL_COND_NEAR
                                    disp_size = 4
                                else:
                                    rt = RefType.REL_JUMP_NEAR
                                    disp_size = 4
                                disp_off = self._vaddr_to_offset(insn.address + (insn.size - disp_size))
                            else:
                                # Non-x86: fixed-size instructions
                                rt = RefType.REL_CALL if is_call else RefType.REL_JUMP_NEAR
                                disp_size = 4
                                disp_off = self._vaddr_to_offset(insn.address)

                            if disp_off is not None:
                                refs.append(Reference(
                                    file_offset=disp_off,
                                    ref_rva=insn.address,
                                    target_rva=target,
                                    ref_type=rt,
                                    size_bytes=disp_size,
                                    is_relative=True,
                                    insn_size=insn.size,
                                    section_name=sec_name,
                                    confidence=1.0,
                                    source=RefSource.STATIC_DISASM,
                                ))

                # RIP-relative addressing (x86-64 only)
                if self.is_x86 and self.is_64:
                    for op in insn.operands:
                        if op.type == capstone.CS_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                            target = insn.address + insn.size + op.mem.disp
                            disp_off = self._vaddr_to_offset(insn.address + (insn.size - 4))
                            if disp_off is not None:
                                refs.append(Reference(
                                    file_offset=disp_off,
                                    ref_rva=insn.address,
                                    target_rva=target,
                                    ref_type=RefType.RIP_RELATIVE,
                                    size_bytes=4,
                                    is_relative=True,
                                    insn_size=insn.size,
                                    section_name=sec_name,
                                    confidence=1.0,
                                    source=RefSource.STATIC_DISASM,
                                ))
        return refs

    def _pass_pointer_tables(self) -> List[Reference]:
        refs = []
        ptr_size = 8 if self.is_64 else 4
        ptr_sections = ('__got', '__la_symbol_ptr', '__mod_init_func', '__mod_term_func')

        for sec in self.sections:
            if sec['name'] not in ptr_sections:
                continue
            start_off = sec['offset']
            count = sec['size'] // ptr_size
            va = sec['addr']

            if sec['name'] == '__got':
                rtype = RefType.GOT_ENTRY
            elif sec['name'] == '__la_symbol_ptr':
                rtype = RefType.PLT_STUB
            else:
                rtype = RefType.INIT_FINI_PTR

            for i in range(count):
                off = start_off + i * ptr_size
                if off + ptr_size > len(self.buffer):
                    break
                if ptr_size == 8:
                    val = struct.unpack_from('<Q', self.buffer, off)[0]
                else:
                    val = struct.unpack_from('<I', self.buffer, off)[0]
                if val == 0:
                    continue
                refs.append(Reference(
                    file_offset=off,
                    ref_rva=va + i * ptr_size,
                    target_rva=val,
                    ref_type=rtype,
                    size_bytes=ptr_size,
                    is_relative=False,
                    insn_size=ptr_size,
                    section_name=sec['name'],
                    confidence=1.0,
                    source=RefSource.ELF_TABLE,
                ))
        return refs

    def _pass_dysymtab_relocs(self) -> List[Reference]:
        """Parse DYSYMTAB relocation entries (local + external)."""
        refs = []
        if self._dysymtab is None:
            return refs
        locreloff, nlocrel, extreloff, nextrel = self._dysymtab
        ptr_size = 8 if self.is_64 else 4

        # Each relocation_info is 8 bytes: r_address(4), r_symbolnum:24 | r_pcrel:1 | r_length:2 | r_extern:1 | r_type:4
        for reloff, nrel, source_label in [(locreloff, nlocrel, "local"), (extreloff, nextrel, "external")]:
            for i in range(nrel):
                off = reloff + i * 8
                if off + 8 > len(self.buffer):
                    break
                r_address = struct.unpack_from('<I', self.buffer, off)[0]
                info = struct.unpack_from('<I', self.buffer, off + 4)[0]
                r_pcrel = (info >> 24) & 1
                r_length = (info >> 25) & 3
                r_extern = (info >> 27) & 1

                size = 1 << r_length  # 0->1, 1->2, 2->4, 3->8
                foff = self._vaddr_to_offset(r_address + self.image_base)
                if foff is None:
                    continue

                if r_pcrel:
                    ref_type = RefType.REL_CALL
                    is_rel = True
                else:
                    ref_type = RefType.ELF_RELATIVE
                    is_rel = False

                # Read target from the relocation
                target_va = 0
                if not r_pcrel and foff + size <= len(self.buffer):
                    if size == 4:
                        target_va = struct.unpack_from('<I', self.buffer, foff)[0]
                    elif size == 8:
                        target_va = struct.unpack_from('<Q', self.buffer, foff)[0]

                refs.append(Reference(
                    file_offset=foff,
                    ref_rva=r_address + self.image_base,
                    target_rva=target_va,
                    ref_type=ref_type,
                    size_bytes=size,
                    is_relative=is_rel,
                    insn_size=size,
                    section_name=self._section_for_offset(foff),
                    confidence=1.0,
                    source=RefSource.ELF_TABLE,
                ))
        return refs

    def _section_for_offset(self, foff: int) -> str:
        """Return section name for a given file offset."""
        for sec in self.sections:
            if sec['offset'] <= foff < sec['offset'] + sec['size']:
                return sec['name']
        return ""

    def _pass_data_pointers(self) -> List[Reference]:
        refs = []
        ptr_size = 8 if self.is_64 else 4
        # Determine valid VA range
        min_va = min((s['vmaddr'] for s in self.segments if s['vmsize'] > 0), default=0)
        max_va = max((s['vmaddr'] + s['vmsize'] for s in self.segments if s['vmsize'] > 0), default=0)
        if min_va == 0 and max_va == 0:
            return refs

        data_sections = [s for s in self.sections if not s['is_code'] and s['size'] > 0
                         and s['name'] not in ('__got', '__la_symbol_ptr',
                                               '__mod_init_func', '__mod_term_func')]

        step = ptr_size
        for sec in data_sections:
            start_off = sec['offset']
            count = sec['size'] // step
            va = sec['addr']
            sec_name = sec['name']

            for i in range(count):
                off = start_off + i * step
                if off + ptr_size > len(self.buffer):
                    break
                if ptr_size == 8:
                    val = struct.unpack_from('<Q', self.buffer, off)[0]
                else:
                    val = struct.unpack_from('<I', self.buffer, off)[0]

                if min_va <= val < max_va and val != 0:
                    refs.append(Reference(
                        file_offset=off,
                        ref_rva=va + i * step,
                        target_rva=val,
                        ref_type=RefType.DATA_POINTER,
                        size_bytes=ptr_size,
                        is_relative=False,
                        insn_size=step, section_name=sec_name,
                        confidence=0.6, source=RefSource.HEURISTIC,
                    ))
        return refs

    def close(self):
        pass


# ─── Base Shift Engine ────────────────────────────────────────────────────

class BaseShiftEngine:
    """
    Shared base for PE, ELF, and Mach-O shift engines.

    v7 features:
    - _write_int: safe byte writing to buffer
    - _relax_short_branch: EB→E9 / 7x→0F 8x auto-upgrade
    - _cascade_shift: mini-recalc after relaxation
    - _run_relaxation_pass: multi-pass fixpoint relaxation (v7)
    - Batch/transaction system: begin_batch/commit_batch/rollback_batch (v7)
    - Cross-section validation (v7)
    - Code signing detection (v7)
    """

    # Mapping from short conditional branch opcodes (7x) to near conditional (0F 8x)
    _SHORT_TO_NEAR_JCC = {
        0x70: (0x0F, 0x80), 0x71: (0x0F, 0x81), 0x72: (0x0F, 0x82), 0x73: (0x0F, 0x83),
        0x74: (0x0F, 0x84), 0x75: (0x0F, 0x85), 0x76: (0x0F, 0x86), 0x77: (0x0F, 0x87),
        0x78: (0x0F, 0x88), 0x79: (0x0F, 0x89), 0x7A: (0x0F, 0x8A), 0x7B: (0x0F, 0x8B),
        0x7C: (0x0F, 0x8C), 0x7D: (0x0F, 0x8D), 0x7E: (0x0F, 0x8E), 0x7F: (0x0F, 0x8F),
    }

    def __init__(self):
        self.buffer: bytearray = bytearray()
        self.ref_db: Optional[ReferenceDatabase] = None
        self.is_64: bool = False
        # v7: batch/transaction state
        self._batch_active: bool = False
        self._batch_ops: List[Tuple[ShiftOp, int, int, bytes]] = []
        self._batch_snapshot: Optional[bytes] = None
        # v7: code signing detection
        self._has_signature: bool = False
        self._signature_warning_shown: bool = False

    def _write_int(self, offset: int, value: int, size: int, signed: bool = False):
        if offset < 0 or offset + size > len(self.buffer):
            return
        if signed:
            fmt = {1: '<b', 2: '<h', 4: '<i', 8: '<q'}[size]
        else:
            fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}[size]
        try:
            struct.pack_into(fmt, self.buffer, offset, value)
        except struct.error:
            pass

    def _relax_short_branch(self, ref: Reference) -> bool:
        """
        Upgrade a short branch (2 bytes) to a near branch (5-6 bytes).

        EB rel8 (JMP short)  → E9 rel32 (JMP near)     : +3 bytes
        7x rel8 (Jcc short)  → 0F 8x rel32 (Jcc near)  : +4 bytes

        Returns True if relaxation succeeded.
        """
        insn_foff = ref.file_offset - 1  # file_offset points to disp byte, opcode is 1 before
        if insn_foff < 0 or insn_foff + 2 > len(self.buffer):
            return False

        opcode = self.buffer[insn_foff]

        if ref.ref_type == RefType.REL_JUMP_SHORT and opcode == 0xEB:
            # EB rel8 → E9 rel32 (expand by 3 bytes)
            expand = 3
            new_insn_size = 5
            new_disp = ref.target_rva - (ref.ref_rva + new_insn_size)
            new_bytes = bytes([0xE9]) + struct.pack('<i', new_disp)

            self.buffer[insn_foff:insn_foff + 2] = new_bytes

            ref.ref_type = RefType.REL_JUMP_NEAR
            ref.size_bytes = 4
            ref.insn_size = 5
            ref.file_offset = insn_foff + 1

            self._cascade_shift(ref.ref_rva + 2, expand)
            return True

        elif ref.ref_type == RefType.REL_COND_SHORT and opcode in self._SHORT_TO_NEAR_JCC:
            # 7x rel8 → 0F 8x rel32 (expand by 4 bytes)
            expand = 4
            new_insn_size = 6
            near_op = self._SHORT_TO_NEAR_JCC[opcode]
            new_disp = ref.target_rva - (ref.ref_rva + new_insn_size)
            new_bytes = bytes([near_op[0], near_op[1]]) + struct.pack('<i', new_disp)

            self.buffer[insn_foff:insn_foff + 2] = new_bytes

            ref.ref_type = RefType.REL_COND_NEAR
            ref.size_bytes = 4
            ref.insn_size = 6
            ref.file_offset = insn_foff + 2

            self._cascade_shift(ref.ref_rva + 2, expand)
            return True

        return False

    def _cascade_shift(self, from_addr: int, expand: int):
        """
        After a branch relaxation expands an instruction, shift all refs
        that are after from_addr by expand bytes and update their encoded values.
        Subclasses override _cascade_finalize() for format-specific header updates.
        """
        for ref in self.ref_db.get_all():
            if ref.ref_rva >= from_addr:
                ref.ref_rva += expand
                ref.file_offset += expand
            if ref.target_rva >= from_addr:
                ref.target_rva += expand

            # Re-encode the reference with updated positions
            if ref.file_offset <= 0:
                continue
            if ref.is_relative:
                new_val = ref.target_rva - (ref.ref_rva + ref.insn_size)
                if ref.size_bytes == 1:
                    if -128 <= new_val <= 127:
                        self._write_int(ref.file_offset, new_val, 1, signed=True)
                elif ref.size_bytes == 2:
                    self._write_int(ref.file_offset, new_val, 2, signed=True)
                elif ref.size_bytes == 4:
                    self._write_int(ref.file_offset, new_val, 4, signed=True)
            else:
                if ref.target_rva - expand >= from_addr:
                    self._encode_absolute(ref)

        self.ref_db.rebuild_indices()
        self._cascade_finalize(from_addr, expand)

    def _encode_absolute(self, ref: Reference):
        """Encode an absolute reference value into the buffer. Override per format."""
        pass

    def _cascade_finalize(self, from_addr: int, expand: int):
        """Called after cascade to update format-specific headers. Override per format."""
        pass

    def _run_relaxation_pass(self, relaxations: list, updated: int,
                              warnings: List[str]) -> Tuple[int, List[str]]:
        """
        v7: Multi-pass fixpoint relaxation.
        Processes short branch overflows by relaxing them to near branches.
        Repeats until no more relaxations are needed (fixpoint).
        Max 8 passes to prevent infinite loops.
        """
        if not relaxations:
            return updated, warnings

        max_passes = 8
        for pass_num in range(max_passes):
            if not relaxations:
                break

            relaxations.sort(key=lambda x: x[2], reverse=True)  # highest addr first
            new_relaxations = []

            for ref, foff, ref_addr, target_addr in relaxations:
                result = self._relax_short_branch(ref)
                if result:
                    updated += 1
                    warnings.append(
                        f"RELAXED short→near @0x{ref_addr:X}: "
                        f"{ref.ref_type.value} (auto-upgraded, pass {pass_num + 1})"
                    )
                else:
                    warnings.append(
                        f"SHORT BRANCH OVERFLOW @0x{ref_addr:X}: "
                        f"could not auto-relax (type={ref.ref_type.value})"
                    )

            # Check if cascade caused new overflows
            for ref in self.ref_db.get_all():
                if ref.is_relative and ref.size_bytes == 1:
                    disp = ref.target_rva - (ref.ref_rva + ref.insn_size)
                    if disp < -128 or disp > 127:
                        new_foff = ref.file_offset
                        new_relaxations.append((ref, new_foff, ref.ref_rva, ref.target_rva))

            relaxations = new_relaxations
            if not relaxations:
                break

        if relaxations:
            warnings.append(
                f"WARNING: {len(relaxations)} short branches still overflowing "
                f"after {max_passes} relaxation passes"
            )

        return updated, warnings

    # ── v7: Batch/Transaction System ──────────────────────────────────

    def begin_batch(self):
        """Start a batch transaction. Saves a snapshot for rollback."""
        if self._batch_active:
            raise RuntimeError("Batch already active — commit or rollback first")
        self._batch_active = True
        self._batch_snapshot = bytes(self.buffer)
        self._batch_ops = []

    def commit_batch(self) -> Dict:
        """Commit the batch. Returns summary of all operations."""
        if not self._batch_active:
            raise RuntimeError("No active batch to commit")
        self._batch_active = False
        summary = {
            'operations': len(self._batch_ops),
            'ops': [(op.value, addr, n) for op, addr, n, _ in self._batch_ops],
        }
        self._batch_ops = []
        self._batch_snapshot = None
        return summary

    def rollback_batch(self) -> str:
        """Rollback the batch to the saved snapshot."""
        if not self._batch_active:
            raise RuntimeError("No active batch to rollback")
        if self._batch_snapshot is not None:
            self.buffer = bytearray(self._batch_snapshot)
        self._batch_active = False
        ops_count = len(self._batch_ops)
        self._batch_ops = []
        self._batch_snapshot = None
        return f"Rolled back {ops_count} operations"

    @property
    def batch_active(self) -> bool:
        return self._batch_active

    def _record_batch_op(self, op: ShiftOp, addr: int, n: int, data: bytes):
        """Record an operation in the current batch."""
        if self._batch_active:
            self._batch_ops.append((op, addr, n, data))

    # ── v7: Cross-Section Target Validation ───────────────────────────

    def validate_all_targets(self, valid_ranges: List[Tuple[int, int]]) -> List[Dict]:
        """
        Validate that all reference targets land within valid address ranges.
        Call after shift operations to detect broken references.
        """
        if not self.ref_db:
            return []
        broken = []
        for ref in self.ref_db.get_all():
            target = ref.target_rva
            in_range = any(lo <= target < hi for lo, hi in valid_ranges)
            if not in_range and ref.confidence >= 0.7:
                broken.append({
                    'ref_rva': f'0x{ref.ref_rva:X}',
                    'target_rva': f'0x{target:X}',
                    'type': ref.ref_type.value,
                    'section': ref.section_name,
                    'confidence': ref.confidence,
                })
        return broken

    # ── v7: Code Signing Detection ────────────────────────────────────

    def detect_code_signature(self) -> Optional[Dict]:
        """
        Detect code signatures / Authenticode in the binary.
        Override per format. Returns info dict or None.
        """
        return None

    def _check_signature_warning(self) -> Optional[str]:
        """If binary is signed, return a warning string."""
        if self._has_signature and not self._signature_warning_shown:
            self._signature_warning_shown = True
            return ("WARNING: This binary has a code signature / Authenticode. "
                    "Modifications will invalidate the signature.")
        return None


# ─── ELF Shift Engine ────────────────────────────────────────────────────

class ELFShiftEngine(BaseShiftEngine):
    """
    Applies insert/delete/patch operations on ELF binaries with reference recalculation.

    Similar to ShiftEngine for PE, but works with ELF segments/sections and uses
    virtual addresses directly (no image_base subtraction for non-PIE).
    """

    def __init__(self, elf_path: str, ref_db: ReferenceDatabase):
        super().__init__()
        if not HAS_ELFTOOLS:
            raise ImportError("pyelftools is required")
        self.elf_path = elf_path
        with open(elf_path, 'rb') as f:
            self.buffer = bytearray(f.read())
        self._fobj = open(elf_path, 'rb')
        self.elf = ELFFile(self._fobj)
        self.ref_db = ref_db
        self.is_64 = self.elf.elfclass == 64
        self.ptr_size = 8 if self.is_64 else 4
        self.endian = '>' if self.elf.little_endian is False else '<'
        self._undo_stack: List[Tuple[ShiftOp, int, int, bytes]] = []

    def _vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.elf.iter_segments():
            if seg.header['p_type'] != 'PT_LOAD':
                continue
            va = seg.header['p_vaddr']
            foff = seg.header['p_offset']
            fsz = seg.header['p_filesz']
            if va <= vaddr < va + fsz:
                return vaddr - va + foff
        return None

    def insert_bytes(self, vaddr: int, data: bytes) -> ShiftResult:
        N = len(data)
        if N == 0:
            return ShiftResult(ShiftOp.INSERT, vaddr, 0, 0, [], 0,
                               len(self.buffer), True, "Nothing to insert")

        insert_foff = self._vaddr_to_offset(vaddr)
        if insert_foff is None:
            return ShiftResult(ShiftOp.INSERT, vaddr, N, 0, [],
                               0, len(self.buffer), False,
                               f"VA 0x{vaddr:X} does not map to any segment")

        self._undo_stack.append((ShiftOp.INSERT, insert_foff, N, b''))
        self.buffer[insert_foff:insert_foff] = data

        sections_adjusted = self._update_elf_headers(vaddr, N, insert_foff)
        self._update_elf_relocations(vaddr, N)
        self._update_elf_dynamic_tags(vaddr, N)  # v7
        refs_updated, warnings = self._recalculate_refs(vaddr, N)

        return ShiftResult(
            ShiftOp.INSERT, vaddr, N, refs_updated, warnings,
            sections_adjusted, len(self.buffer), True,
            f"Inserted {N} bytes at VA 0x{vaddr:X}, updated {refs_updated} references"
        )

    def delete_bytes(self, vaddr: int, count: int) -> ShiftResult:
        if count == 0:
            return ShiftResult(ShiftOp.DELETE, vaddr, 0, 0, [], 0,
                               len(self.buffer), True, "Nothing to delete")

        foff = self._vaddr_to_offset(vaddr)
        if foff is None:
            return ShiftResult(ShiftOp.DELETE, vaddr, -count, 0, [],
                               0, len(self.buffer), False,
                               f"VA 0x{vaddr:X} does not map to any segment")

        deleted = bytes(self.buffer[foff:foff + count])
        self._undo_stack.append((ShiftOp.DELETE, foff, count, deleted))
        del self.buffer[foff:foff + count]

        sections_adjusted = self._update_elf_headers(vaddr, -count, foff)
        self._update_elf_relocations(vaddr, -count)
        self._update_elf_dynamic_tags(vaddr, -count)  # v7
        refs_updated, warnings = self._recalculate_refs(vaddr, -count)

        return ShiftResult(
            ShiftOp.DELETE, vaddr, -count, refs_updated, warnings,
            sections_adjusted, len(self.buffer), True,
            f"Deleted {count} bytes at VA 0x{vaddr:X}, updated {refs_updated} references"
        )

    def patch_bytes(self, vaddr: int, data: bytes) -> ShiftResult:
        N = len(data)
        foff = self._vaddr_to_offset(vaddr)
        if foff is None:
            return ShiftResult(ShiftOp.PATCH, vaddr, 0, 0, [],
                               0, len(self.buffer), False,
                               f"VA 0x{vaddr:X} not found")
        old = bytes(self.buffer[foff:foff + N])
        self._undo_stack.append((ShiftOp.PATCH, foff, N, old))
        self.buffer[foff:foff + N] = data
        return ShiftResult(ShiftOp.PATCH, vaddr, 0, 0, [], 0,
                           len(self.buffer), True,
                           f"Patched {N} bytes at VA 0x{vaddr:X} (no shift)")

    def insert_nop_sled(self, vaddr: int, count: int) -> ShiftResult:
        return self.insert_bytes(vaddr, b'\x90' * count)

    def _reparse_elf(self):
        """Re-open and re-parse the ELF object from the current buffer."""
        import io
        if hasattr(self, '_fobj') and self._fobj and not self._fobj.closed:
            self._fobj.close()
        self._fobj = io.BytesIO(bytes(self.buffer))
        self.elf = ELFFile(self._fobj)

    def undo(self) -> Optional[str]:
        if not self._undo_stack:
            return None
        op, foff, n, saved = self._undo_stack.pop()
        if op == ShiftOp.INSERT:
            del self.buffer[foff:foff + n]
            self._reparse_elf()
            return f"Undid INSERT of {n} bytes at offset 0x{foff:X}"
        elif op == ShiftOp.DELETE:
            self.buffer[foff:foff] = saved
            self._reparse_elf()
            return f"Undid DELETE of {n} bytes at offset 0x{foff:X}"
        elif op == ShiftOp.PATCH:
            self.buffer[foff:foff + n] = saved
            return f"Undid PATCH of {n} bytes at offset 0x{foff:X}"
        return None

    def save(self, output_path: str):
        with open(output_path, 'wb') as f:
            f.write(bytes(self.buffer))

    def compact(self) -> Dict:
        """
        v7.2: Reclaim wasted padding in the ELF binary.
        Scans all sections for trailing zero-filled bytes beyond the section's
        actual content size and removes them, updating section headers,
        program headers, and file offsets accordingly.

        WARNING: Destructive operation — clears undo stack.
        Returns dict with compaction results.
        """
        e = self.endian
        reclaimed = 0
        sections_trimmed = 0

        # Read section headers
        if self.is_64:
            e_shoff = struct.unpack_from(f'{e}Q', self.buffer, 40)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 58)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 60)[0]
        else:
            e_shoff = struct.unpack_from(f'{e}I', self.buffer, 32)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 46)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 48)[0]

        # Gather sections sorted by file offset, skip SHT_NOBITS (8) and SHT_NULL (0)
        sections = []
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(self.buffer):
                break
            if self.is_64:
                sh_type = struct.unpack_from(f'{e}I', self.buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 24)[0]
                sh_size = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 32)[0]
                sh_addralign = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 48)[0]
            else:
                sh_type = struct.unpack_from(f'{e}I', self.buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}I', self.buffer, sh_off + 16)[0]
                sh_size = struct.unpack_from(f'{e}I', self.buffer, sh_off + 20)[0]
                sh_addralign = struct.unpack_from(f'{e}I', self.buffer, sh_off + 32)[0]
            if sh_type in (0, 8):  # SHT_NULL, SHT_NOBITS
                continue
            if sh_offset == 0 or sh_size == 0:
                continue
            sections.append({
                'index': i, 'sh_off_pos': sh_off, 'offset': sh_offset,
                'size': sh_size, 'align': max(sh_addralign, 1), 'type': sh_type,
            })

        sections.sort(key=lambda s: s['offset'])

        # Find reclaimable trailing zeros in each section
        cumulative_delta = 0
        for sec in sections:
            raw_off = sec['offset']
            raw_size = sec['size']
            if raw_off + raw_size > len(self.buffer):
                continue

            # Scan backwards from end of section for trailing zeros
            end = raw_off + raw_size
            trim_start = end
            while trim_start > raw_off and self.buffer[trim_start - 1] == 0:
                trim_start -= 1

            # Must keep at least alignment-worth of content
            align = sec['align']
            new_size = trim_start - raw_off
            if new_size == 0:
                new_size = 1  # Never fully empty a section
            aligned_size = (new_size + align - 1) & ~(align - 1)
            if aligned_size >= raw_size:
                continue  # No savings after alignment

            saved = raw_size - aligned_size
            # Remove trailing bytes
            del self.buffer[raw_off + aligned_size:raw_off + raw_size]

            # Update this section's size in its header
            sh_off = sec['sh_off_pos']
            if self.is_64:
                struct.pack_into(f'{e}Q', self.buffer, sh_off + 32, aligned_size)
            else:
                struct.pack_into(f'{e}I', self.buffer, sh_off + 20, aligned_size)

            reclaimed += saved
            sections_trimmed += 1
            cumulative_delta += saved

            # Shift all subsequent sections' file offsets
            # Re-read section header table offset (it may have moved)
            if self.is_64:
                cur_shoff = struct.unpack_from(f'{e}Q', self.buffer, 40)[0]
            else:
                cur_shoff = struct.unpack_from(f'{e}I', self.buffer, 32)[0]
            for j in range(e_shnum):
                other_off = cur_shoff + j * e_shentsize
                if other_off + e_shentsize > len(self.buffer):
                    break
                if self.is_64:
                    o_offset = struct.unpack_from(f'{e}Q', self.buffer, other_off + 24)[0]
                    if o_offset > raw_off:
                        struct.pack_into(f'{e}Q', self.buffer, other_off + 24, o_offset - saved)
                else:
                    o_offset = struct.unpack_from(f'{e}I', self.buffer, other_off + 16)[0]
                    if o_offset > raw_off:
                        struct.pack_into(f'{e}I', self.buffer, other_off + 16, o_offset - saved)

            # Shift program headers' p_offset for segments after this section
            if self.is_64:
                phoff = struct.unpack_from(f'{e}Q', self.buffer, 32)[0]
                phentsize = struct.unpack_from(f'{e}H', self.buffer, 54)[0]
                phnum = struct.unpack_from(f'{e}H', self.buffer, 56)[0]
            else:
                phoff = struct.unpack_from(f'{e}I', self.buffer, 28)[0]
                phentsize = struct.unpack_from(f'{e}H', self.buffer, 42)[0]
                phnum = struct.unpack_from(f'{e}H', self.buffer, 44)[0]

            for pi in range(phnum):
                ph_pos = phoff + pi * phentsize
                if ph_pos + phentsize > len(self.buffer):
                    break
                if self.is_64:
                    p_offset = struct.unpack_from(f'{e}Q', self.buffer, ph_pos + 8)[0]
                    p_filesz = struct.unpack_from(f'{e}Q', self.buffer, ph_pos + 32)[0]
                    p_memsz = struct.unpack_from(f'{e}Q', self.buffer, ph_pos + 40)[0]
                    if p_offset <= raw_off < p_offset + p_filesz:
                        # Segment contains this section — shrink it
                        struct.pack_into(f'{e}Q', self.buffer, ph_pos + 32, p_filesz - saved)
                        struct.pack_into(f'{e}Q', self.buffer, ph_pos + 40, p_memsz - saved)
                    elif p_offset > raw_off:
                        struct.pack_into(f'{e}Q', self.buffer, ph_pos + 8, p_offset - saved)
                else:
                    p_offset = struct.unpack_from(f'{e}I', self.buffer, ph_pos + 4)[0]
                    p_filesz = struct.unpack_from(f'{e}I', self.buffer, ph_pos + 16)[0]
                    p_memsz = struct.unpack_from(f'{e}I', self.buffer, ph_pos + 20)[0]
                    if p_offset <= raw_off < p_offset + p_filesz:
                        struct.pack_into(f'{e}I', self.buffer, ph_pos + 16, p_filesz - saved)
                        struct.pack_into(f'{e}I', self.buffer, ph_pos + 20, p_memsz - saved)
                    elif p_offset > raw_off:
                        struct.pack_into(f'{e}I', self.buffer, ph_pos + 4, p_offset - saved)

            # Update section header table offset if it was after the trimmed area
            if self.is_64:
                shoff = struct.unpack_from(f'{e}Q', self.buffer, 40)[0]
                if shoff > raw_off:
                    struct.pack_into(f'{e}Q', self.buffer, 40, shoff - saved)
            else:
                shoff = struct.unpack_from(f'{e}I', self.buffer, 32)[0]
                if shoff > raw_off:
                    struct.pack_into(f'{e}I', self.buffer, 32, shoff - saved)

        if reclaimed == 0:
            return {'compacted': False, 'message': 'No reclaimable padding found'}

        # Re-parse ELF
        self._fobj.close()
        import io
        self._fobj = io.BytesIO(bytes(self.buffer))
        self.elf = ELFFile(self._fobj)
        self._undo_stack.clear()

        return {
            'compacted': True,
            'bytes_reclaimed': reclaimed,
            'sections_trimmed': sections_trimmed,
            'new_size': len(self.buffer),
        }

    def preview_insert(self, vaddr: int, size: int) -> Dict:
        changes = []
        warnings = []
        for ref in self.ref_db.get_all():
            ref_moved = ref.ref_rva >= vaddr
            target_moved = ref.target_rva >= vaddr
            new_ref_va = ref.ref_rva + (size if ref_moved else 0)
            new_target_va = ref.target_rva + (size if target_moved else 0)

            if ref.is_relative:
                old_val = ref.target_rva - (ref.ref_rva + ref.insn_size)
                new_val = new_target_va - (new_ref_va + ref.insn_size)
                if old_val != new_val:
                    changes.append(
                        f"REF @0x{ref.ref_rva:X} → 0x{ref.target_rva:X}: "
                        f"rel {old_val:+d} → {new_val:+d}"
                    )
                    if ref.size_bytes == 1 and (new_val < -128 or new_val > 127):
                        warnings.append(
                            f"⚠ SHORT BRANCH OVERFLOW at 0x{ref.ref_rva:X}"
                        )
            else:
                if target_moved:
                    changes.append(
                        f"REF @0x{ref.ref_rva:X}: abs 0x{ref.target_rva:X} → 0x{new_target_va:X}"
                    )

        return {
            'operation': 'INSERT', 'vaddr': vaddr, 'size': size,
            'total_refs': self.ref_db.count, 'refs_affected': len(changes),
            'changes': changes, 'warnings': warnings,
        }

    def _encode_absolute(self, ref: Reference):
        """Encode ELF absolute reference (target_rva directly, no image_base)."""
        if ref.size_bytes == 4:
            self._write_int(ref.file_offset, ref.target_rva & 0xFFFFFFFF, 4)
        elif ref.size_bytes == 8:
            self._write_int(ref.file_offset, ref.target_rva, 8)

    def _cascade_finalize(self, from_addr: int, expand: int):
        """Update ELF section/program headers after cascade expansion."""
        foff = self._vaddr_to_offset(from_addr)
        if foff is None:
            foff = 0
        self._update_elf_headers(from_addr, expand, foff)

    def _recalculate_refs(self, insert_va: int, delta: int) -> Tuple[int, List[str]]:
        updated = 0
        warnings = []
        relaxations = []

        for ref in self.ref_db.get_all():
            ref_moved = ref.ref_rva >= insert_va
            target_moved = ref.target_rva >= insert_va

            new_ref_va = ref.ref_rva + (delta if ref_moved else 0)
            new_target_va = ref.target_rva + (delta if target_moved else 0)
            new_foff = ref.file_offset + (delta if ref_moved else 0)

            if ref.is_relative:
                old_val = ref.target_rva - (ref.ref_rva + ref.insn_size)
                new_val = new_target_va - (new_ref_va + ref.insn_size)

                if old_val != new_val:
                    if ref.size_bytes == 1:
                        if new_val < -128 or new_val > 127:
                            relaxations.append((ref, new_foff, new_ref_va, new_target_va))
                            ref.ref_rva = new_ref_va
                            ref.target_rva = new_target_va
                            ref.file_offset = new_foff
                            continue
                        self._write_int(new_foff, new_val, 1, signed=True)
                    elif ref.size_bytes == 4:
                        self._write_int(new_foff, new_val, 4, signed=True)
                    updated += 1
            else:
                if target_moved and ref.file_offset > 0:
                    if ref.size_bytes == 4:
                        self._write_int(new_foff, new_target_va & 0xFFFFFFFF, 4)
                    elif ref.size_bytes == 8:
                        self._write_int(new_foff, new_target_va, 8)
                    updated += 1

            ref.ref_rva = new_ref_va
            ref.target_rva = new_target_va
            ref.file_offset = new_foff

        self.ref_db.rebuild_indices()
        return self._run_relaxation_pass(relaxations, updated, warnings)

    def _update_elf_headers(self, vaddr: int, delta: int, foff: int) -> int:
        """
        Update ELF section headers and program headers after insert/delete.
        Directly patches the binary buffer — ELF headers are at known offsets.
        """
        adjusted = 0
        ehdr_size = 64 if self.is_64 else 52
        e = self.endian

        # ── Update ELF header entry point ──
        if self.is_64:
            entry_off = 24  # e_entry offset in Elf64_Ehdr
            entry = struct.unpack_from(f'{e}Q', self.buffer, entry_off)[0]
            if entry >= vaddr:
                struct.pack_into(f'{e}Q', self.buffer, entry_off, entry + delta)
        else:
            entry_off = 24
            entry = struct.unpack_from(f'{e}I', self.buffer, entry_off)[0]
            if entry >= vaddr:
                struct.pack_into(f'{e}I', self.buffer, entry_off, entry + delta)

        # ── Update program headers (PHDR) ──
        if self.is_64:
            e_phoff = struct.unpack_from(f'{e}Q', self.buffer, 32)[0]
            e_phentsize = struct.unpack_from(f'{e}H', self.buffer, 54)[0]
            e_phnum = struct.unpack_from(f'{e}H', self.buffer, 56)[0]
        else:
            e_phoff = struct.unpack_from(f'{e}I', self.buffer, 28)[0]
            e_phentsize = struct.unpack_from(f'{e}H', self.buffer, 42)[0]
            e_phnum = struct.unpack_from(f'{e}H', self.buffer, 44)[0]

        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            if self.is_64:
                p_type = struct.unpack_from(f'{e}I', self.buffer, ph_off)[0]
                p_offset = struct.unpack_from(f'{e}Q', self.buffer, ph_off + 8)[0]
                p_vaddr = struct.unpack_from(f'{e}Q', self.buffer, ph_off + 16)[0]
                p_filesz = struct.unpack_from(f'{e}Q', self.buffer, ph_off + 32)[0]
                p_memsz = struct.unpack_from(f'{e}Q', self.buffer, ph_off + 40)[0]

                if p_vaddr <= vaddr < p_vaddr + p_filesz:
                    # This segment contains the insertion point — grow it
                    struct.pack_into(f'{e}Q', self.buffer, ph_off + 32, p_filesz + delta)
                    struct.pack_into(f'{e}Q', self.buffer, ph_off + 40, p_memsz + delta)
                    adjusted += 1
                elif p_offset > foff:
                    # Shift segment offset for segments after the insertion
                    struct.pack_into(f'{e}Q', self.buffer, ph_off + 8, p_offset + delta)
                    adjusted += 1
            else:
                p_type = struct.unpack_from(f'{e}I', self.buffer, ph_off)[0]
                p_offset = struct.unpack_from(f'{e}I', self.buffer, ph_off + 4)[0]
                p_vaddr = struct.unpack_from(f'{e}I', self.buffer, ph_off + 8)[0]
                p_filesz = struct.unpack_from(f'{e}I', self.buffer, ph_off + 16)[0]
                p_memsz = struct.unpack_from(f'{e}I', self.buffer, ph_off + 20)[0]

                if p_vaddr <= vaddr < p_vaddr + p_filesz:
                    struct.pack_into(f'{e}I', self.buffer, ph_off + 16, p_filesz + delta)
                    struct.pack_into(f'{e}I', self.buffer, ph_off + 20, p_memsz + delta)
                    adjusted += 1
                elif p_offset > foff:
                    struct.pack_into(f'{e}I', self.buffer, ph_off + 4, p_offset + delta)
                    adjusted += 1

        # ── Update section headers (SHDR) ──
        if self.is_64:
            e_shoff = struct.unpack_from(f'{e}Q', self.buffer, 40)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 58)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 60)[0]
            # If section header table is after insertion, shift it
            if e_shoff > foff:
                struct.pack_into(f'{e}Q', self.buffer, 40, e_shoff + delta)
                e_shoff += delta
        else:
            e_shoff = struct.unpack_from(f'{e}I', self.buffer, 32)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 46)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 48)[0]
            if e_shoff > foff:
                struct.pack_into(f'{e}I', self.buffer, 32, e_shoff + delta)
                e_shoff += delta

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(self.buffer):
                break
            if self.is_64:
                sh_addr = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 16)[0]
                sh_offset = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 24)[0]
                sh_size = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 32)[0]

                if sh_addr and sh_addr <= vaddr < sh_addr + sh_size:
                    struct.pack_into(f'{e}Q', self.buffer, sh_off + 32, sh_size + delta)
                    adjusted += 1
                elif sh_offset > foff:
                    struct.pack_into(f'{e}Q', self.buffer, sh_off + 24, sh_offset + delta)
                    if sh_addr and sh_addr >= vaddr:
                        struct.pack_into(f'{e}Q', self.buffer, sh_off + 16, sh_addr + delta)
                    adjusted += 1
            else:
                sh_addr = struct.unpack_from(f'{e}I', self.buffer, sh_off + 12)[0]
                sh_offset = struct.unpack_from(f'{e}I', self.buffer, sh_off + 16)[0]
                sh_size = struct.unpack_from(f'{e}I', self.buffer, sh_off + 20)[0]

                if sh_addr and sh_addr <= vaddr < sh_addr + sh_size:
                    struct.pack_into(f'{e}I', self.buffer, sh_off + 20, sh_size + delta)
                    adjusted += 1
                elif sh_offset > foff:
                    struct.pack_into(f'{e}I', self.buffer, sh_off + 16, sh_offset + delta)
                    if sh_addr and sh_addr >= vaddr:
                        struct.pack_into(f'{e}I', self.buffer, sh_off + 12, sh_addr + delta)
                    adjusted += 1

        return adjusted

    def _update_elf_relocations(self, shift_va: int, delta: int) -> int:
        """
        Patch r_offset fields in ELF .rel/.rela sections after a shift.
        Any relocation whose r_offset >= shift_va gets adjusted by delta.
        Returns the number of relocation entries updated.
        """
        updated = 0
        e = self.endian
        if self.is_64:
            e_shoff = struct.unpack_from(f'{e}Q', self.buffer, 40)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 58)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 60)[0]
        else:
            e_shoff = struct.unpack_from(f'{e}I', self.buffer, 32)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 46)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 48)[0]

        # SHT_REL=9, SHT_RELA=4
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(self.buffer):
                break
            if self.is_64:
                sh_type = struct.unpack_from(f'{e}I', self.buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 24)[0]
                sh_size = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 32)[0]
                sh_entsize = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 56)[0]
            else:
                sh_type = struct.unpack_from(f'{e}I', self.buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}I', self.buffer, sh_off + 16)[0]
                sh_size = struct.unpack_from(f'{e}I', self.buffer, sh_off + 20)[0]
                sh_entsize = struct.unpack_from(f'{e}I', self.buffer, sh_off + 36)[0]

            if sh_type not in (4, 9):  # SHT_RELA=4, SHT_REL=9
                continue
            if sh_entsize == 0:
                continue

            is_rela = (sh_type == 4)  # SHT_RELA has explicit addend field
            num_entries = sh_size // sh_entsize
            for j in range(num_entries):
                ent_off = sh_offset + j * sh_entsize
                if ent_off + sh_entsize > len(self.buffer):
                    break

                if self.is_64:
                    r_offset = struct.unpack_from(f'{e}Q', self.buffer, ent_off)[0]
                    r_info = struct.unpack_from(f'{e}Q', self.buffer, ent_off + 8)[0]
                    r_type = r_info & 0xFFFFFFFF
                    if r_offset >= shift_va:
                        struct.pack_into(f'{e}Q', self.buffer, ent_off, r_offset + delta)
                        updated += 1
                    # v7.1: For RELA, update addend if it's an address-bearing relocation
                    if is_rela and ent_off + 24 <= len(self.buffer):
                        r_addend = struct.unpack_from(f'{e}q', self.buffer, ent_off + 16)[0]
                        # R_X86_64_RELATIVE=8, R_X86_64_64=1, R_X86_64_GLOB_DAT=6, R_X86_64_JUMP_SLOT=7
                        # R_AARCH64_RELATIVE=1027, R_AARCH64_ABS64=257
                        addr_reloc_types = {8, 1, 6, 7, 1027, 257}
                        if r_type in addr_reloc_types and r_addend >= shift_va:
                            struct.pack_into(f'{e}q', self.buffer, ent_off + 16, r_addend + delta)
                            updated += 1
                else:
                    r_offset = struct.unpack_from(f'{e}I', self.buffer, ent_off)[0]
                    r_info = struct.unpack_from(f'{e}I', self.buffer, ent_off + 4)[0]
                    r_type = r_info & 0xFF
                    if r_offset >= shift_va:
                        struct.pack_into(f'{e}I', self.buffer, ent_off, (r_offset + delta) & 0xFFFFFFFF)
                        updated += 1
                    # v7.1: For RELA, update addend on 32-bit too
                    if is_rela and ent_off + 12 <= len(self.buffer):
                        r_addend = struct.unpack_from(f'{e}i', self.buffer, ent_off + 8)[0]
                        # R_386_RELATIVE=8, R_386_32=1, R_386_GLOB_DAT=6, R_386_JMP_SLOT=7
                        addr_reloc_types_32 = {8, 1, 6, 7}
                        if r_type in addr_reloc_types_32 and r_addend >= shift_va:
                            struct.pack_into(f'{e}i', self.buffer, ent_off + 8,
                                             (r_addend + delta) & 0xFFFFFFFF)
                            updated += 1

        return updated

    def _update_elf_dynamic_tags(self, shift_va: int, delta: int) -> int:
        """
        v7: Update .dynamic section entries that contain virtual addresses.
        Patches DT_* entries whose d_val (address) >= shift_va.
        """
        updated = 0
        e = self.endian

        # Find .dynamic section by scanning section headers
        if self.is_64:
            e_shoff = struct.unpack_from(f'{e}Q', self.buffer, 40)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 58)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 60)[0]
        else:
            e_shoff = struct.unpack_from(f'{e}I', self.buffer, 32)[0]
            e_shentsize = struct.unpack_from(f'{e}H', self.buffer, 46)[0]
            e_shnum = struct.unpack_from(f'{e}H', self.buffer, 48)[0]

        # SHT_DYNAMIC = 6
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(self.buffer):
                break
            if self.is_64:
                sh_type = struct.unpack_from(f'{e}I', self.buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 24)[0]
                sh_size = struct.unpack_from(f'{e}Q', self.buffer, sh_off + 32)[0]
            else:
                sh_type = struct.unpack_from(f'{e}I', self.buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}I', self.buffer, sh_off + 16)[0]
                sh_size = struct.unpack_from(f'{e}I', self.buffer, sh_off + 20)[0]

            if sh_type != 6:  # SHT_DYNAMIC
                continue

            # Tags that contain virtual addresses
            addr_tags = {0x03, 0x04, 0x05, 0x06, 0x07, 0x0C, 0x0D,
                         0x11, 0x15, 0x17, 0x19, 0x1A, 0x1C,
                         0x6FFFFEF5, 0x6FFFFFF0, 0x6FFFFFFE, 0x6FFFFFFC}

            entry_size = 16 if self.is_64 else 8
            num_entries = sh_size // entry_size

            for j in range(num_entries):
                ent_off = sh_offset + j * entry_size
                if ent_off + entry_size > len(self.buffer):
                    break

                if self.is_64:
                    tag = struct.unpack_from(f'{e}q', self.buffer, ent_off)[0]
                    val = struct.unpack_from(f'{e}Q', self.buffer, ent_off + 8)[0]
                else:
                    tag = struct.unpack_from(f'{e}i', self.buffer, ent_off)[0]
                    val = struct.unpack_from(f'{e}I', self.buffer, ent_off + 4)[0]

                if tag == 0:  # DT_NULL
                    break
                if tag not in addr_tags:
                    continue
                if val >= shift_va:
                    new_val = val + delta
                    if self.is_64:
                        struct.pack_into(f'{e}Q', self.buffer, ent_off + 8, new_val)
                    else:
                        struct.pack_into(f'{e}I', self.buffer, ent_off + 4,
                                         new_val & 0xFFFFFFFF)
                    updated += 1
            break  # Only one .dynamic section

        return updated

class MachOShiftEngine(BaseShiftEngine):
    """
    Applies insert/delete/patch operations on Mach-O binaries with reference recalculation.
    """

    def __init__(self, macho_path: str, ref_db: ReferenceDatabase):
        super().__init__()
        self.macho_path = macho_path
        with open(macho_path, 'rb') as f:
            self.buffer = bytearray(f.read())
        self.ref_db = ref_db
        self.finder = MachOReferenceFinder(macho_path)
        self.is_64 = self.finder.is_64
        self.image_base = self.finder.image_base
        self.segments = self.finder.segments
        self.sections = self.finder.sections
        self.arch_offset = self.finder.arch_offset
        self.is_fat = self.finder.is_fat
        self._fat_archs: List[Dict] = []  # v7.1: fat_arch entries
        self._undo_stack: List[Tuple[ShiftOp, int, int, bytes]] = []
        # v7.1: Parse fat header for later update
        if self.is_fat:
            self._parse_fat_archs()
        # v7: Detect code signing
        self._detect_macho_signature()

    def _parse_fat_archs(self):
        """v7.1: Parse all fat_arch entries for fat binary header management."""
        nfat_arch = struct.unpack_from('>I', self.buffer, 4)[0]
        self._fat_archs = []
        for i in range(nfat_arch):
            fa_off = 8 + i * 20
            if fa_off + 20 > len(self.buffer):
                break
            self._fat_archs.append({
                'index': i,
                'cputype': struct.unpack_from('>I', self.buffer, fa_off)[0],
                'cpusubtype': struct.unpack_from('>I', self.buffer, fa_off + 4)[0],
                'offset': struct.unpack_from('>I', self.buffer, fa_off + 8)[0],
                'size': struct.unpack_from('>I', self.buffer, fa_off + 12)[0],
                'align': struct.unpack_from('>I', self.buffer, fa_off + 16)[0],
            })

    def _detect_macho_signature(self):
        """Check for LC_CODE_SIGNATURE in Mach-O."""
        LC_CODE_SIGNATURE = 0x1D
        base = self.arch_offset
        if self.is_64:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            cmd_offset = base + 32
        else:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            cmd_offset = base + 28
        for _ in range(ncmds):
            if cmd_offset + 8 > len(self.buffer):
                break
            cmd = struct.unpack_from('<I', self.buffer, cmd_offset)[0]
            cmdsize = struct.unpack_from('<I', self.buffer, cmd_offset + 4)[0]
            if cmdsize < 8:
                break
            if cmd == LC_CODE_SIGNATURE:
                self._has_signature = True
                return
            cmd_offset += cmdsize

    def detect_code_signature(self) -> Optional[Dict]:
        if not self._has_signature:
            return None
        return {
            'type': 'macho_codesign',
            'warning': 'Binary has Mach-O code signature (LC_CODE_SIGNATURE) — modifications will invalidate it',
        }

    def strip_signature(self) -> Dict:
        """
        v7.2: Remove LC_CODE_SIGNATURE from Mach-O binary.
        Removes the load command and zeroes/truncates the signature blob.
        """
        if not self._has_signature:
            return {'stripped': False, 'message': 'No Mach-O code signature found'}

        LC_CODE_SIGNATURE = 0x1D
        base = self.arch_offset
        if self.is_64:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            sizeofcmds_off = base + 20
            cmd_offset = base + 32
        else:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            sizeofcmds_off = base + 20
            cmd_offset = base + 28

        bytes_removed = 0
        for i in range(ncmds):
            if cmd_offset + 8 > len(self.buffer):
                break
            cmd = struct.unpack_from('<I', self.buffer, cmd_offset)[0]
            cmdsize = struct.unpack_from('<I', self.buffer, cmd_offset + 4)[0]
            if cmdsize < 8:
                break

            if cmd == LC_CODE_SIGNATURE:
                # LC_CODE_SIGNATURE has: cmd, cmdsize, dataoff, datasize
                if cmd_offset + 16 <= len(self.buffer):
                    sig_offset = struct.unpack_from('<I', self.buffer, cmd_offset + 8)[0]
                    sig_size = struct.unpack_from('<I', self.buffer, cmd_offset + 12)[0]

                    # Remove the signature blob if it's at the end of the file
                    if sig_offset > 0 and sig_size > 0:
                        sig_end = sig_offset + sig_size
                        if sig_end == len(self.buffer):
                            del self.buffer[sig_offset:sig_end]
                            bytes_removed += sig_size
                        else:
                            # Not at end — zero it out
                            self.buffer[sig_offset:sig_offset + sig_size] = b'\x00' * sig_size

                # Remove the load command itself from the header
                del self.buffer[cmd_offset:cmd_offset + cmdsize]
                bytes_removed += cmdsize

                # Update ncmds and sizeofcmds in mach_header
                struct.pack_into('<I', self.buffer, base + 16, ncmds - 1)
                old_sizeofcmds = struct.unpack_from('<I', self.buffer, sizeofcmds_off)[0]
                struct.pack_into('<I', self.buffer, sizeofcmds_off, old_sizeofcmds - cmdsize)

                self._has_signature = False
                return {
                    'stripped': True,
                    'bytes_removed': bytes_removed,
                    'new_size': len(self.buffer),
                    'message': 'LC_CODE_SIGNATURE removed',
                }

            cmd_offset += cmdsize

        return {'stripped': False, 'message': 'LC_CODE_SIGNATURE not found in load commands'}

    def _vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.segments:
            va = seg['vmaddr']
            fo = seg['fileoff']
            fs = seg['filesize']
            if va <= vaddr < va + fs:
                return vaddr - va + fo
        return None

    def _encode_absolute(self, ref: Reference):
        """Encode Mach-O absolute reference (target_rva directly)."""
        if ref.size_bytes == 4:
            self._write_int(ref.file_offset, ref.target_rva & 0xFFFFFFFF, 4)
        elif ref.size_bytes == 8:
            self._write_int(ref.file_offset, ref.target_rva, 8)

    def _cascade_finalize(self, from_addr: int, expand: int):
        """Update Mach-O headers after cascade expansion."""
        foff = self._vaddr_to_offset(from_addr)
        if foff is None:
            foff = 0
        self._update_macho_headers(from_addr, expand, foff)

    def _reparse_macho(self):
        """Re-parse Mach-O segments/sections from the current buffer after undo."""
        finder = MachOReferenceFinder.__new__(MachOReferenceFinder)
        finder.buffer = self.buffer
        finder.sections = []
        finder.segments = []
        finder.is_64 = self.is_64
        finder.is_fat = False
        finder.image_base = 0
        finder.arch_offset = self.arch_offset
        finder.cputype = 0
        finder._dysymtab = None
        finder._parse_header(0)
        self.segments = finder.segments
        self.sections = finder.sections

    def insert_bytes(self, vaddr: int, data: bytes) -> ShiftResult:
        N = len(data)
        insert_foff = self._vaddr_to_offset(vaddr)
        if insert_foff is None:
            return ShiftResult(ShiftOp.INSERT, vaddr, N, 0, [],
                               0, len(self.buffer), False,
                               f"VA 0x{vaddr:X} does not map to any segment")

        self._undo_stack.append((ShiftOp.INSERT, insert_foff, N, b''))
        self.buffer[insert_foff:insert_foff] = data

        sections_adjusted = self._update_macho_headers(vaddr, N, insert_foff)
        refs_updated, warnings = self._recalculate_refs(vaddr, N)

        return ShiftResult(
            ShiftOp.INSERT, vaddr, N, refs_updated, warnings,
            sections_adjusted, len(self.buffer), True,
            f"Inserted {N} bytes at VA 0x{vaddr:X}, updated {refs_updated} references"
        )

    def delete_bytes(self, vaddr: int, count: int) -> ShiftResult:
        if count == 0:
            return ShiftResult(ShiftOp.DELETE, vaddr, 0, 0, [], 0,
                               len(self.buffer), True, "Nothing to delete")

        foff = self._vaddr_to_offset(vaddr)
        if foff is None:
            return ShiftResult(ShiftOp.DELETE, vaddr, -count, 0, [],
                               0, len(self.buffer), False,
                               f"VA 0x{vaddr:X} does not map to any segment")

        deleted = bytes(self.buffer[foff:foff + count])
        self._undo_stack.append((ShiftOp.DELETE, foff, count, deleted))
        del self.buffer[foff:foff + count]

        sections_adjusted = self._update_macho_headers(vaddr, -count, foff)
        refs_updated, warnings = self._recalculate_refs(vaddr, -count)

        return ShiftResult(
            ShiftOp.DELETE, vaddr, -count, refs_updated, warnings,
            sections_adjusted, len(self.buffer), True,
            f"Deleted {count} bytes at VA 0x{vaddr:X}, updated {refs_updated} references"
        )

    def patch_bytes(self, vaddr: int, data: bytes) -> ShiftResult:
        N = len(data)
        foff = self._vaddr_to_offset(vaddr)
        if foff is None:
            return ShiftResult(ShiftOp.PATCH, vaddr, 0, 0, [],
                               0, len(self.buffer), False,
                               f"VA 0x{vaddr:X} not found")
        old = bytes(self.buffer[foff:foff + N])
        self._undo_stack.append((ShiftOp.PATCH, foff, N, old))
        self.buffer[foff:foff + N] = data
        return ShiftResult(ShiftOp.PATCH, vaddr, 0, 0, [], 0,
                           len(self.buffer), True,
                           f"Patched {N} bytes at VA 0x{vaddr:X} (no shift)")

    def insert_nop_sled(self, vaddr: int, count: int) -> ShiftResult:
        return self.insert_bytes(vaddr, b'\x90' * count)

    def undo(self) -> Optional[str]:
        if not self._undo_stack:
            return None
        op, foff, n, saved = self._undo_stack.pop()
        if op == ShiftOp.INSERT:
            del self.buffer[foff:foff + n]
            return f"Undid INSERT of {n} bytes at offset 0x{foff:X}"
        elif op == ShiftOp.DELETE:
            self.buffer[foff:foff] = saved
            return f"Undid DELETE of {n} bytes at offset 0x{foff:X}"
        elif op == ShiftOp.PATCH:
            self.buffer[foff:foff + n] = saved
            return f"Undid PATCH of {n} bytes at offset 0x{foff:X}"
        return None

    def save(self, output_path: str):
        # v7.1: Update fat header if this is a universal binary
        if self.is_fat and self._fat_archs:
            self._update_fat_header()
        with open(output_path, 'wb') as f:
            f.write(bytes(self.buffer))

    def _update_fat_header(self):
        """
        v7.2: Recalculate fat_arch sizes AND offsets after modifying an architecture slice.
        When one arch slice changes in size, the fat_arch entry for that arch must be
        updated, and all subsequent architectures' offsets must be shifted by the delta.
        """
        if not self._fat_archs:
            return

        sorted_archs = sorted(self._fat_archs, key=lambda fa: fa['offset'])

        # Find the modified arch and compute the size delta
        mod_idx = None
        old_size = 0
        for i, fa in enumerate(sorted_archs):
            if fa['offset'] == self.arch_offset:
                mod_idx = i
                old_size = fa['size']
                break

        if mod_idx is None:
            return

        # Compute new size for the modified arch
        if mod_idx + 1 < len(sorted_archs):
            # Size = gap between this arch offset and next arch's ORIGINAL offset,
            # but the buffer has changed. We know the total buffer delta.
            original_total = sum(fa['size'] for fa in sorted_archs)
            fat_header_size = 8 + len(sorted_archs) * 20
            original_total_with_header = sorted_archs[-1]['offset'] + sorted_archs[-1]['size']
            buf_delta = len(self.buffer) - original_total_with_header
            new_size = old_size + buf_delta
        else:
            # Last arch — its size extends to end of file
            new_size = len(self.buffer) - sorted_archs[mod_idx]['offset']

        size_delta = new_size - old_size
        sorted_archs[mod_idx]['size'] = new_size

        # Shift offsets for all architectures AFTER the modified one
        for i in range(mod_idx + 1, len(sorted_archs)):
            sorted_archs[i]['offset'] += size_delta

        # Rewrite all fat_arch entries in the buffer
        for i, fa in enumerate(sorted_archs):
            fa_off = 8 + i * 20
            if fa_off + 20 > len(self.buffer):
                break
            struct.pack_into('>I', self.buffer, fa_off, fa['cputype'])
            struct.pack_into('>I', self.buffer, fa_off + 4, fa['cpusubtype'])
            struct.pack_into('>I', self.buffer, fa_off + 8, fa['offset'])
            struct.pack_into('>I', self.buffer, fa_off + 12, fa['size'])
            struct.pack_into('>I', self.buffer, fa_off + 16, fa['align'])

        self._fat_archs = sorted_archs

    def compact(self) -> Dict:
        """
        v7.2: Reclaim wasted padding in the Mach-O binary.
        Scans all sections for trailing zero-filled bytes and removes them,
        updating segment and section load commands accordingly.

        WARNING: Destructive operation — clears undo stack.
        Returns dict with compaction results.
        """
        reclaimed = 0
        sections_trimmed = 0
        base = self.arch_offset

        # Walk load commands to find sections with trimmable padding
        if self.is_64:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            cmd_offset = base + 32
            LC_SEG = MachOReferenceFinder.LC_SEGMENT_64
        else:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            cmd_offset = base + 28
            LC_SEG = MachOReferenceFinder.LC_SEGMENT

        # Collect all sections with their file offsets
        macho_sections = []
        for _ in range(ncmds):
            if cmd_offset + 8 > len(self.buffer):
                break
            cmd = struct.unpack_from('<I', self.buffer, cmd_offset)[0]
            cmdsize = struct.unpack_from('<I', self.buffer, cmd_offset + 4)[0]
            if cmdsize < 8:
                break

            if cmd == MachOReferenceFinder.LC_SEGMENT_64:
                nsects = struct.unpack_from('<I', self.buffer, cmd_offset + 64)[0]
                sec_off = cmd_offset + 72
                seg_cmd_off = cmd_offset
                for si in range(nsects):
                    if sec_off + 80 > len(self.buffer):
                        break
                    s_size = struct.unpack_from('<Q', self.buffer, sec_off + 40)[0]
                    s_offset = struct.unpack_from('<I', self.buffer, sec_off + 48)[0]
                    s_align = struct.unpack_from('<I', self.buffer, sec_off + 52)[0]
                    if s_offset > 0 and s_size > 0:
                        macho_sections.append({
                            'sec_hdr_off': sec_off, 'seg_cmd_off': seg_cmd_off,
                            'offset': s_offset, 'size': s_size,
                            'align': max(1 << s_align, 1) if s_align < 30 else 1,
                            'is_64': True,
                        })
                    sec_off += 80
            elif cmd == MachOReferenceFinder.LC_SEGMENT:
                nsects = struct.unpack_from('<I', self.buffer, cmd_offset + 48)[0]
                sec_off = cmd_offset + 56
                seg_cmd_off = cmd_offset
                for si in range(nsects):
                    if sec_off + 68 > len(self.buffer):
                        break
                    s_size = struct.unpack_from('<I', self.buffer, sec_off + 36)[0]
                    s_offset = struct.unpack_from('<I', self.buffer, sec_off + 40)[0]
                    s_align = struct.unpack_from('<I', self.buffer, sec_off + 44)[0]
                    if s_offset > 0 and s_size > 0:
                        macho_sections.append({
                            'sec_hdr_off': sec_off, 'seg_cmd_off': seg_cmd_off,
                            'offset': s_offset, 'size': s_size,
                            'align': max(1 << s_align, 1) if s_align < 30 else 1,
                            'is_64': False,
                        })
                    sec_off += 68

            cmd_offset += cmdsize

        macho_sections.sort(key=lambda s: s['offset'])

        for sec in macho_sections:
            raw_off = sec['offset']
            raw_size = sec['size']
            if raw_off + raw_size > len(self.buffer):
                continue

            # Scan backwards for trailing zeros
            end = raw_off + raw_size
            trim_start = end
            while trim_start > raw_off and self.buffer[trim_start - 1] == 0:
                trim_start -= 1

            new_size = trim_start - raw_off
            if new_size == 0:
                new_size = 1
            align = sec['align']
            aligned_size = (new_size + align - 1) & ~(align - 1)
            if aligned_size >= raw_size:
                continue

            saved = raw_size - aligned_size
            del self.buffer[raw_off + aligned_size:raw_off + raw_size]

            # Update section header size
            sec_off = sec['sec_hdr_off']
            if sec['is_64']:
                struct.pack_into('<Q', self.buffer, sec_off + 40, aligned_size)
            else:
                struct.pack_into('<I', self.buffer, sec_off + 36, aligned_size)

            # Update parent segment's filesize
            seg_off = sec['seg_cmd_off']
            if sec['is_64']:
                seg_filesize = struct.unpack_from('<Q', self.buffer, seg_off + 48)[0]
                struct.pack_into('<Q', self.buffer, seg_off + 48, seg_filesize - saved)
                seg_vmsize = struct.unpack_from('<Q', self.buffer, seg_off + 32)[0]
                struct.pack_into('<Q', self.buffer, seg_off + 32, seg_vmsize - saved)
            else:
                seg_filesize = struct.unpack_from('<I', self.buffer, seg_off + 36)[0]
                struct.pack_into('<I', self.buffer, seg_off + 36, seg_filesize - saved)
                seg_vmsize = struct.unpack_from('<I', self.buffer, seg_off + 28)[0]
                struct.pack_into('<I', self.buffer, seg_off + 28, seg_vmsize - saved)

            reclaimed += saved
            sections_trimmed += 1

        if reclaimed == 0:
            return {'compacted': False, 'message': 'No reclaimable padding found'}

        # Re-parse Mach-O
        self._reparse_macho()
        self._undo_stack.clear()

        return {
            'compacted': True,
            'bytes_reclaimed': reclaimed,
            'sections_trimmed': sections_trimmed,
            'new_size': len(self.buffer),
        }

    @staticmethod
    def extract_thin_macho(fat_path: str, arch_index: int = 0, output_path: str = None) -> Dict:
        """
        v7.1: Extract a single architecture from a fat (universal) Mach-O binary.

        Args:
            fat_path: Path to the fat binary
            arch_index: Architecture index to extract (0-based)
            output_path: Output path (default: adds arch suffix to filename)

        Returns:
            Dict with extraction details or error
        """
        with open(fat_path, 'rb') as f:
            data = f.read()

        magic = struct.unpack_from('>I', data, 0)[0]
        if magic != 0xCAFEBABE:
            return {'error': 'Not a fat (universal) Mach-O binary'}

        nfat_arch = struct.unpack_from('>I', data, 4)[0]
        if arch_index >= nfat_arch:
            return {'error': f'arch_index {arch_index} out of range ({nfat_arch} architectures)'}

        cpu_names = {
            7: 'x86', 0x01000007: 'x86_64',
            12: 'arm', 0x0100000C: 'arm64',
            18: 'ppc', 0x01000012: 'ppc64',
        }
        archs = []
        for i in range(nfat_arch):
            fa_off = 8 + i * 20
            archs.append({
                'cputype': struct.unpack_from('>I', data, fa_off)[0],
                'offset': struct.unpack_from('>I', data, fa_off + 8)[0],
                'size': struct.unpack_from('>I', data, fa_off + 12)[0],
            })

        target = archs[arch_index]
        thin_data = data[target['offset']:target['offset'] + target['size']]
        cpu_name = cpu_names.get(target['cputype'], f'arch{arch_index}')

        if output_path is None:
            base, ext = os.path.splitext(fat_path)
            output_path = f"{base}_{cpu_name}{ext}"

        with open(output_path, 'wb') as f:
            f.write(thin_data)

        return {
            'success': True, 'output': output_path,
            'arch': cpu_name, 'cputype': target['cputype'], 'size': len(thin_data),
            'architectures': [
                {'index': i, 'cputype': a['cputype'],
                 'name': cpu_names.get(a['cputype'], 'unknown'), 'size': a['size']}
                for i, a in enumerate(archs)
            ],
        }

    def preview_insert(self, vaddr: int, size: int) -> Dict:
        changes = []
        warnings = []
        for ref in self.ref_db.get_all():
            ref_moved = ref.ref_rva >= vaddr
            target_moved = ref.target_rva >= vaddr
            new_ref_va = ref.ref_rva + (size if ref_moved else 0)
            new_target_va = ref.target_rva + (size if target_moved else 0)

            if ref.is_relative:
                old_val = ref.target_rva - (ref.ref_rva + ref.insn_size)
                new_val = new_target_va - (new_ref_va + ref.insn_size)
                if old_val != new_val:
                    changes.append(
                        f"REF @0x{ref.ref_rva:X} → 0x{ref.target_rva:X}: "
                        f"rel {old_val:+d} → {new_val:+d}"
                    )
                    if ref.size_bytes == 1 and (new_val < -128 or new_val > 127):
                        warnings.append(f"⚠ SHORT BRANCH OVERFLOW at 0x{ref.ref_rva:X}")
            else:
                if target_moved:
                    changes.append(
                        f"REF @0x{ref.ref_rva:X}: abs 0x{ref.target_rva:X} → 0x{new_target_va:X}"
                    )

        return {
            'operation': 'INSERT', 'vaddr': vaddr, 'size': size,
            'total_refs': self.ref_db.count, 'refs_affected': len(changes),
            'changes': changes, 'warnings': warnings,
        }

    def _recalculate_refs(self, insert_va: int, delta: int) -> Tuple[int, List[str]]:
        updated = 0
        warnings = []
        relaxations = []

        for ref in self.ref_db.get_all():
            ref_moved = ref.ref_rva >= insert_va
            target_moved = ref.target_rva >= insert_va

            new_ref_va = ref.ref_rva + (delta if ref_moved else 0)
            new_target_va = ref.target_rva + (delta if target_moved else 0)
            new_foff = ref.file_offset + (delta if ref_moved else 0)

            if ref.is_relative:
                old_val = ref.target_rva - (ref.ref_rva + ref.insn_size)
                new_val = new_target_va - (new_ref_va + ref.insn_size)

                if old_val != new_val:
                    if ref.size_bytes == 1:
                        if new_val < -128 or new_val > 127:
                            relaxations.append((ref, new_foff, new_ref_va, new_target_va))
                            ref.ref_rva = new_ref_va
                            ref.target_rva = new_target_va
                            ref.file_offset = new_foff
                            continue
                        self._write_int(new_foff, new_val, 1, signed=True)
                    elif ref.size_bytes == 4:
                        self._write_int(new_foff, new_val, 4, signed=True)
                    updated += 1
            else:
                if target_moved and ref.file_offset > 0:
                    if ref.size_bytes == 4:
                        self._write_int(new_foff, new_target_va & 0xFFFFFFFF, 4)
                    elif ref.size_bytes == 8:
                        self._write_int(new_foff, new_target_va, 8)
                    updated += 1

            ref.ref_rva = new_ref_va
            ref.target_rva = new_target_va
            ref.file_offset = new_foff

        self.ref_db.rebuild_indices()
        return self._run_relaxation_pass(relaxations, updated, warnings)

    def _update_macho_headers(self, vaddr: int, delta: int, foff: int) -> int:
        """Update Mach-O segment/section headers after insert/delete."""
        adjusted = 0
        base = self.arch_offset

        if self.is_64:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            cmd_offset = base + 32
        else:
            ncmds = struct.unpack_from('<I', self.buffer, base + 16)[0]
            cmd_offset = base + 28

        for _ in range(ncmds):
            if cmd_offset + 8 > len(self.buffer):
                break
            cmd = struct.unpack_from('<I', self.buffer, cmd_offset)[0]
            cmdsize = struct.unpack_from('<I', self.buffer, cmd_offset + 4)[0]
            if cmdsize < 8:
                break

            if cmd == MachOReferenceFinder.LC_SEGMENT_64:
                seg_vmaddr = struct.unpack_from('<Q', self.buffer, cmd_offset + 24)[0]
                seg_vmsize = struct.unpack_from('<Q', self.buffer, cmd_offset + 32)[0]
                seg_fileoff = struct.unpack_from('<Q', self.buffer, cmd_offset + 40)[0]
                seg_filesize = struct.unpack_from('<Q', self.buffer, cmd_offset + 48)[0]
                nsects = struct.unpack_from('<I', self.buffer, cmd_offset + 64)[0]

                if seg_vmaddr <= vaddr < seg_vmaddr + seg_vmsize:
                    struct.pack_into('<Q', self.buffer, cmd_offset + 32, seg_vmsize + delta)
                    struct.pack_into('<Q', self.buffer, cmd_offset + 48, seg_filesize + delta)
                    adjusted += 1
                elif seg_fileoff > foff:
                    struct.pack_into('<Q', self.buffer, cmd_offset + 40, seg_fileoff + delta)
                    adjusted += 1

                sec_off = cmd_offset + 72
                for _ in range(nsects):
                    if sec_off + 80 > len(self.buffer):
                        break
                    s_addr = struct.unpack_from('<Q', self.buffer, sec_off + 32)[0]
                    s_size = struct.unpack_from('<Q', self.buffer, sec_off + 40)[0]
                    s_offset = struct.unpack_from('<I', self.buffer, sec_off + 48)[0]

                    if s_addr <= vaddr < s_addr + s_size:
                        struct.pack_into('<Q', self.buffer, sec_off + 40, s_size + delta)
                        adjusted += 1
                    elif s_offset > foff:
                        struct.pack_into('<I', self.buffer, sec_off + 48, s_offset + delta)
                        if s_addr >= vaddr:
                            struct.pack_into('<Q', self.buffer, sec_off + 32, s_addr + delta)
                        adjusted += 1
                    sec_off += 80

            elif cmd == MachOReferenceFinder.LC_SEGMENT:
                seg_vmaddr = struct.unpack_from('<I', self.buffer, cmd_offset + 24)[0]
                seg_vmsize = struct.unpack_from('<I', self.buffer, cmd_offset + 28)[0]
                seg_fileoff = struct.unpack_from('<I', self.buffer, cmd_offset + 32)[0]
                seg_filesize = struct.unpack_from('<I', self.buffer, cmd_offset + 36)[0]
                nsects = struct.unpack_from('<I', self.buffer, cmd_offset + 48)[0]

                if seg_vmaddr <= vaddr < seg_vmaddr + seg_vmsize:
                    struct.pack_into('<I', self.buffer, cmd_offset + 28, seg_vmsize + delta)
                    struct.pack_into('<I', self.buffer, cmd_offset + 36, seg_filesize + delta)
                    adjusted += 1
                elif seg_fileoff > foff:
                    struct.pack_into('<I', self.buffer, cmd_offset + 32, seg_fileoff + delta)
                    adjusted += 1

                sec_off = cmd_offset + 56
                for _ in range(nsects):
                    if sec_off + 68 > len(self.buffer):
                        break
                    s_addr = struct.unpack_from('<I', self.buffer, sec_off + 32)[0]
                    s_size = struct.unpack_from('<I', self.buffer, sec_off + 36)[0]
                    s_offset = struct.unpack_from('<I', self.buffer, sec_off + 40)[0]

                    if s_addr <= vaddr < s_addr + s_size:
                        struct.pack_into('<I', self.buffer, sec_off + 36, s_size + delta)
                        adjusted += 1
                    elif s_offset > foff:
                        struct.pack_into('<I', self.buffer, sec_off + 40, s_offset + delta)
                        if s_addr >= vaddr:
                            struct.pack_into('<I', self.buffer, sec_off + 32, s_addr + delta)
                        adjusted += 1
                    sec_off += 68

            cmd_offset += cmdsize

        # Update in-memory segment list
        for seg in self.segments:
            if seg['vmaddr'] <= vaddr < seg['vmaddr'] + seg['vmsize']:
                seg['vmsize'] += delta
                seg['filesize'] += delta
            elif seg['fileoff'] > foff:
                seg['fileoff'] += delta

        return adjusted


# ─── Symbol Updater ──────────────────────────────────────────────────────

class SymbolUpdater:
    """
    Updates symbol tables (ELF .symtab/.dynsym, PE export/import tables)
    after a shift operation to keep debug info and linking consistent.

    Works on the raw buffer — call after ShiftEngine/ELFShiftEngine operations.
    """

    @staticmethod
    def update_elf_symbols(buffer: bytearray, is_64: bool, shift_va: int, delta: int, endian: str = '<') -> int:
        """
        Patch all symbol st_value entries in .symtab and .dynsym that are >= shift_va.
        Returns the number of symbols updated.
        """
        if len(buffer) < (64 if is_64 else 52):
            return 0

        updated = 0
        e = endian
        # Read ELF header to find section header table
        if is_64:
            e_shoff = struct.unpack_from(f'{e}Q', buffer, 40)[0]
            e_shentsize = struct.unpack_from(f'{e}H', buffer, 58)[0]
            e_shnum = struct.unpack_from(f'{e}H', buffer, 60)[0]
        else:
            e_shoff = struct.unpack_from(f'{e}I', buffer, 32)[0]
            e_shentsize = struct.unpack_from(f'{e}H', buffer, 46)[0]
            e_shnum = struct.unpack_from(f'{e}H', buffer, 48)[0]

        sym_entry_size = 24 if is_64 else 16

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(buffer):
                break

            if is_64:
                sh_type = struct.unpack_from(f'{e}I', buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}Q', buffer, sh_off + 24)[0]
                sh_size = struct.unpack_from(f'{e}Q', buffer, sh_off + 32)[0]
                sh_entsize = struct.unpack_from(f'{e}Q', buffer, sh_off + 56)[0]
            else:
                sh_type = struct.unpack_from(f'{e}I', buffer, sh_off + 4)[0]
                sh_offset = struct.unpack_from(f'{e}I', buffer, sh_off + 16)[0]
                sh_size = struct.unpack_from(f'{e}I', buffer, sh_off + 20)[0]
                sh_entsize = struct.unpack_from(f'{e}I', buffer, sh_off + 36)[0]

            # SHT_SYMTAB = 2, SHT_DYNSYM = 11
            if sh_type not in (2, 11):
                continue

            if sh_entsize == 0:
                sh_entsize = sym_entry_size
            num_syms = sh_size // sh_entsize

            for j in range(num_syms):
                sym_off = sh_offset + j * sh_entsize
                if sym_off + sh_entsize > len(buffer):
                    break

                if is_64:
                    # Elf64_Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
                    st_shndx = struct.unpack_from(f'{e}H', buffer, sym_off + 6)[0]
                    st_value = struct.unpack_from(f'{e}Q', buffer, sym_off + 8)[0]
                    st_size = struct.unpack_from(f'{e}Q', buffer, sym_off + 16)[0]
                else:
                    # Elf32_Sym: st_name(4), st_value(4), st_size(4), st_info(1), st_other(1), st_shndx(2)
                    st_value = struct.unpack_from(f'{e}I', buffer, sym_off + 4)[0]
                    st_size = struct.unpack_from(f'{e}I', buffer, sym_off + 8)[0]
                    st_shndx = struct.unpack_from(f'{e}H', buffer, sym_off + 14)[0]

                # SHN_UNDEF=0, SHN_ABS=0xFFF1 — don't shift these
                if st_shndx == 0 or st_shndx == 0xFFF1:
                    continue
                if st_value == 0:
                    continue

                if st_value >= shift_va:
                    new_value = st_value + delta
                    if is_64:
                        struct.pack_into(f'{e}Q', buffer, sym_off + 8, new_value)
                    else:
                        struct.pack_into(f'{e}I', buffer, sym_off + 4, new_value & 0xFFFFFFFF)
                    updated += 1

        return updated

    @staticmethod
    def update_pe_exports(buffer: bytearray, pe, shift_rva: int, delta: int) -> int:
        """
        Patch export table RVAs in a PE binary.
        The pe object must be a pefile.PE parsed from the same buffer.
        Returns the number of export entries updated.
        """
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return 0

        updated = 0
        exp = pe.DIRECTORY_ENTRY_EXPORT
        addr_of_funcs = exp.struct.AddressOfFunctions
        num_funcs = exp.struct.NumberOfFunctions

        for i in range(num_funcs):
            entry_foff_rva = addr_of_funcs + i * 4
            # Convert RVA to file offset
            foff = None
            for s in pe.sections:
                if s.VirtualAddress <= entry_foff_rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                    foff = entry_foff_rva - s.VirtualAddress + s.PointerToRawData
                    break
            if foff is None or foff + 4 > len(buffer):
                continue

            func_rva = struct.unpack_from('<I', buffer, foff)[0]
            if func_rva >= shift_rva and func_rva != 0:
                struct.pack_into('<I', buffer, foff, func_rva + delta)
                updated += 1

        return updated

    @staticmethod
    def update_pe_debug_dir(buffer: bytearray, pe, shift_rva: int, delta: int) -> int:
        """
        Patch debug directory pointers after shift.
        Returns number of debug entries updated.
        """
        updated = 0
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 6:
            return 0
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]  # IMAGE_DIRECTORY_ENTRY_DEBUG
        if dd.VirtualAddress == 0 or dd.Size == 0:
            return 0

        dbg_foff = None
        for s in pe.sections:
            if s.VirtualAddress <= dd.VirtualAddress < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                dbg_foff = dd.VirtualAddress - s.VirtualAddress + s.PointerToRawData
                break
        if dbg_foff is None:
            return 0

        entry_size = 28  # sizeof(IMAGE_DEBUG_DIRECTORY)
        num_entries = dd.Size // entry_size
        for i in range(num_entries):
            off = dbg_foff + i * entry_size
            if off + entry_size > len(buffer):
                break
            # AddressOfRawData at offset 20 (RVA), PointerToRawData at offset 24 (file offset)
            addr_rva = struct.unpack_from('<I', buffer, off + 20)[0]
            if addr_rva >= shift_rva and addr_rva != 0:
                struct.pack_into('<I', buffer, off + 20, addr_rva + delta)
                updated += 1

        return updated

    @staticmethod
    def update_pe_imports(buffer: bytearray, pe, shift_rva: int, delta: int) -> int:
        """
        Patch import directory and IAT/ILT RVAs after shift.
        Returns number of import entries updated.
        """
        updated = 0
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 1:
            return 0
        imp_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]  # IMAGE_DIRECTORY_ENTRY_IMPORT
        if imp_dd.VirtualAddress == 0 or imp_dd.Size == 0:
            return 0

        # Update the directory entry RVA itself if needed
        if imp_dd.VirtualAddress >= shift_rva:
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress += delta
            updated += 1

        # IAT directory entry (DATA_DIRECTORY[12])
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 12:
            iat_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]
            if iat_dd.VirtualAddress >= shift_rva and iat_dd.VirtualAddress != 0:
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress += delta
                updated += 1

        # Walk import descriptors in the buffer
        imp_foff = None
        for s in pe.sections:
            if s.VirtualAddress <= imp_dd.VirtualAddress < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                imp_foff = imp_dd.VirtualAddress - s.VirtualAddress + s.PointerToRawData
                break
        if imp_foff is None:
            return updated

        desc_size = 20  # sizeof(IMAGE_IMPORT_DESCRIPTOR)
        i = 0
        while True:
            off = imp_foff + i * desc_size
            if off + desc_size > len(buffer):
                break
            ilt_rva = struct.unpack_from('<I', buffer, off)[0]       # OriginalFirstThunk
            name_rva = struct.unpack_from('<I', buffer, off + 12)[0]  # Name
            iat_rva = struct.unpack_from('<I', buffer, off + 16)[0]   # FirstThunk

            # Null terminator
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break

            if ilt_rva >= shift_rva and ilt_rva != 0:
                struct.pack_into('<I', buffer, off, ilt_rva + delta)
                updated += 1
            if name_rva >= shift_rva and name_rva != 0:
                struct.pack_into('<I', buffer, off + 12, name_rva + delta)
                updated += 1
            if iat_rva >= shift_rva and iat_rva != 0:
                struct.pack_into('<I', buffer, off + 16, iat_rva + delta)
                updated += 1
            i += 1

        return updated

    @staticmethod
    def update_pe_exception_table(buffer: bytearray, pe, shift_rva: int, delta: int) -> int:
        """
        Patch .pdata (exception table) entries after shift.
        Each entry is 12 bytes: BeginRVA(4), EndRVA(4), UnwindInfoRVA(4).
        Returns number of entries updated.
        """
        updated = 0
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 3:
            return 0
        exc_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if exc_dd.VirtualAddress == 0 or exc_dd.Size == 0:
            return 0

        exc_foff = None
        for s in pe.sections:
            if s.VirtualAddress <= exc_dd.VirtualAddress < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                exc_foff = exc_dd.VirtualAddress - s.VirtualAddress + s.PointerToRawData
                break
        if exc_foff is None:
            return 0

        num_entries = exc_dd.Size // 12
        for i in range(num_entries):
            off = exc_foff + i * 12
            if off + 12 > len(buffer):
                break
            begin_rva = struct.unpack_from('<I', buffer, off)[0]
            end_rva = struct.unpack_from('<I', buffer, off + 4)[0]
            unwind_rva = struct.unpack_from('<I', buffer, off + 8)[0]

            if begin_rva >= shift_rva and begin_rva != 0:
                struct.pack_into('<I', buffer, off, begin_rva + delta)
                updated += 1
            if end_rva >= shift_rva and end_rva != 0:
                struct.pack_into('<I', buffer, off + 4, end_rva + delta)
                updated += 1
            if unwind_rva >= shift_rva and unwind_rva != 0:
                struct.pack_into('<I', buffer, off + 8, unwind_rva + delta)
                updated += 1

        return updated

    @staticmethod
    def update_pe_base_reloc(buffer: bytearray, pe, shift_rva: int, delta: int) -> int:
        """
        Update base relocation directory RVA pointer after shift.
        Individual reloc fixups are handled by _recalculate_refs, but the
        directory entry itself needs updating.
        """
        updated = 0
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 5:
            return 0
        reloc_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        if reloc_dd.VirtualAddress >= shift_rva and reloc_dd.VirtualAddress != 0:
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress += delta
            updated += 1
        return updated

    @staticmethod
    def shift_symbols(symbols: Dict[int, str], shift_addr: int, delta: int,
                      image_base: int = 0) -> Dict[int, str]:
        """
        Shift a loaded symbol table {VA: name} after an insert/delete.
        Symbols at or above shift_addr+image_base get shifted by delta.
        Returns the updated symbol dict.
        """
        shifted = {}
        threshold = shift_addr + image_base
        for va, name in symbols.items():
            if va >= threshold:
                shifted[va + delta] = name
            else:
                shifted[va] = name
        return shifted

    @staticmethod
    def generate_map_file(symbols: Dict[int, str], image_base: int = 0,
                          sections: list = None, output_path: str = None) -> str:
        """
        Generate a Microsoft-format .map file from a symbol dictionary.
        Returns the map content as a string. Writes to file if output_path given.
        """
        lines = []
        lines.append(f" UBRT Generated Symbol Map")
        lines.append(f" Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"")
        lines.append(f" Preferred load address is {image_base:016X}")
        lines.append(f"")
        lines.append(f" Start         Length     Name                   Class")

        if sections:
            for i, sec in enumerate(sections):
                name = sec.get('name', f'.sec{i}')
                rva = sec.get('rva', 0)
                vsize = sec.get('vsize', 0)
                cls = 'CODE' if sec.get('is_code') else 'DATA'
                lines.append(f" {i+1:04X}:{rva:08X} {vsize:08X}H {name:<24s} {cls}")

        lines.append(f"")
        lines.append(f"  Address         Publics by Value              Rva+Base")
        lines.append(f"")

        # Sort symbols by address
        for va in sorted(symbols.keys()):
            name = symbols[va]
            rva = va - image_base if va >= image_base else va
            # Determine section index
            sec_idx = 1
            sec_off = rva
            if sections:
                for idx, sec in enumerate(sections):
                    s_rva = sec.get('rva', 0)
                    s_sz = sec.get('vsize', 0)
                    if s_rva <= rva < s_rva + s_sz:
                        sec_idx = idx + 1
                        sec_off = rva - s_rva
                        break
            lines.append(f" {sec_idx:04X}:{sec_off:08X}       {name:<32s} {va:016X}")

        lines.append(f"")
        lines.append(f" Total symbols: {len(symbols)}")
        content = '\n'.join(lines) + '\n'

        if output_path:
            with open(output_path, 'w') as f:
                f.write(content)

        return content


# ─── Shift Engine ─────────────────────────────────────────────────────────

class ShiftEngine(BaseShiftEngine):
    """
    Applies insert/delete/patch operations with universal reference recalculation.

    The core algorithm:
    1. Modify the binary buffer (insert/delete bytes)
    2. For each reference: determine if source moved, target moved
    3. Recalculate encoded values (relative displacements or absolute addresses)
    4. Write corrected values back to the buffer
    5. Update PE section headers and directory entries
    """

    def __init__(self, pe_path: str, ref_db: ReferenceDatabase):
        super().__init__()
        if pefile is None:
            raise ImportError("pefile is required")
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path)
        with open(pe_path, 'rb') as f:
            self.buffer = bytearray(f.read())
        self.ref_db = ref_db
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.is_64 = self.pe.OPTIONAL_HEADER.Magic == 0x20b
        self.file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        self.section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        self._undo_stack: List[Tuple[ShiftOp, int, int, bytes]] = []
        # v7: Detect code signing
        self._detect_pe_signature()

    def _detect_pe_signature(self):
        """Check for Authenticode in PE."""
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
            cert_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if cert_dir.VirtualAddress != 0 and cert_dir.Size != 0:
                self._has_signature = True

    def _check_rsrc_conflict(self, rva: int) -> Optional[str]:
        """v7.2: Check if an RVA falls inside the .rsrc section and warn."""
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 2:
            return None
        rsrc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        if rsrc_dir.VirtualAddress == 0 or rsrc_dir.Size == 0:
            return None
        rsrc_rva = rsrc_dir.VirtualAddress
        for s in self.pe.sections:
            if s.VirtualAddress == rsrc_rva:
                rsrc_end = rsrc_rva + s.Misc_VirtualSize
                if rsrc_rva < rva < rsrc_end:
                    return (
                        "⚠ Shift inside .rsrc section — resource directory tree "
                        "internal offsets may be corrupted. Consider adding a new "
                        "section for code modifications instead."
                    )
                break
        return None

    def detect_code_signature(self) -> Optional[Dict]:
        if not self._has_signature:
            return None
        cert_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        return {
            'type': 'authenticode',
            'offset': cert_dir.VirtualAddress,
            'size': cert_dir.Size,
            'warning': 'Binary has Authenticode signature — modifications will invalidate it',
        }

    def strip_signature(self) -> Dict:
        """
        v7.2: Remove Authenticode signature from PE binary.
        Zeroes the security directory entry (DATA_DIRECTORY[4]) and removes
        the certificate table data from the end of the file.
        """
        if not self._has_signature:
            return {'stripped': False, 'message': 'No Authenticode signature found'}

        cert_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        cert_offset = cert_dir.VirtualAddress  # This is a file offset, not RVA
        cert_size = cert_dir.Size

        bytes_removed = 0
        # Certificate table is typically at the very end of the file
        if cert_offset > 0 and cert_size > 0:
            end_of_cert = cert_offset + cert_size
            if end_of_cert == len(self.buffer):
                # Certificate is at the end — truncate
                del self.buffer[cert_offset:end_of_cert]
                bytes_removed = cert_size
            else:
                # Not at end — zero it out instead
                self.buffer[cert_offset:cert_offset + cert_size] = b'\x00' * cert_size

        # Zero the data directory entry
        cert_dir.VirtualAddress = 0
        cert_dir.Size = 0
        self._has_signature = False

        # Update the PE checksum field to 0 (invalidated anyway)
        self.pe.OPTIONAL_HEADER.CheckSum = 0

        # Write the updated directory entry to buffer
        # DATA_DIRECTORY[4] is at optional header offset + 128 (32-bit) or +144 (64-bit)
        dd_offset = self.pe.OPTIONAL_HEADER.get_file_offset()
        if self.is_64:
            dd4_offset = dd_offset + 144 + 4 * 8  # each DD entry is 8 bytes
        else:
            dd4_offset = dd_offset + 128 + 4 * 8
        if dd4_offset + 8 <= len(self.buffer):
            struct.pack_into('<I', self.buffer, dd4_offset, 0)      # VirtualAddress
            struct.pack_into('<I', self.buffer, dd4_offset + 4, 0)  # Size

        # Zero checksum in buffer
        checksum_offset = dd_offset + (64 if self.is_64 else 64)
        if checksum_offset + 4 <= len(self.buffer):
            struct.pack_into('<I', self.buffer, checksum_offset, 0)

        return {
            'stripped': True,
            'bytes_removed': bytes_removed,
            'new_size': len(self.buffer),
            'message': 'Authenticode signature removed',
        }

    def _encode_absolute(self, ref: Reference):
        """Encode PE absolute reference (target_rva + image_base)."""
        new_abs = ref.target_rva + self.image_base
        if ref.size_bytes == 4:
            self._write_int(ref.file_offset, new_abs & 0xFFFFFFFF, 4)
        elif ref.size_bytes == 8:
            self._write_int(ref.file_offset, new_abs, 8)

    def _cascade_finalize(self, from_addr: int, expand: int):
        """Update PE section headers and PE headers after cascade expansion."""
        foff = self._rva_to_offset(from_addr)
        if foff is None:
            foff = 0
        self._update_sections_after_insert(from_addr, expand, foff)
        self._update_pe_headers(from_addr, expand)

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return rva - s.VirtualAddress + s.PointerToRawData
        return None

    def _offset_to_rva(self, offset: int) -> Optional[int]:
        for s in self.pe.sections:
            if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
                return offset - s.PointerToRawData + s.VirtualAddress
        return None

    def _section_for_offset(self, offset: int):
        for s in self.pe.sections:
            if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
                return s
        return None

    def preview_insert(self, rva: int, size: int) -> Dict:
        """Preview what an INSERT operation would change, without applying it."""
        changes = []
        warnings = []
        for ref in self.ref_db.get_all():
            ref_moved = ref.ref_rva >= rva
            target_moved = ref.target_rva >= rva
            new_ref_rva = ref.ref_rva + (size if ref_moved else 0)
            new_target_rva = ref.target_rva + (size if target_moved else 0)

            if ref.is_relative:
                old_val = ref.target_rva - ref.ref_end_rva
                new_val = new_target_rva - (new_ref_rva + ref.insn_size)
                if old_val != new_val:
                    desc = (f"REF @0x{ref.ref_rva:X} → 0x{ref.target_rva:X}: "
                            f"rel value {old_val:+d} → {new_val:+d}")
                    changes.append(desc)
                    # Check overflow
                    if ref.size_bytes == 1 and (new_val < -128 or new_val > 127):
                        warnings.append(
                            f"⚠ SHORT BRANCH OVERFLOW at 0x{ref.ref_rva:X}: "
                            f"displacement {new_val:+d} exceeds ±127, needs relaxation"
                        )
            else:
                if target_moved:
                    desc = (f"REF @0x{ref.ref_rva:X} → 0x{ref.target_rva:X}: "
                            f"abs target 0x{ref.target_rva:X} → 0x{new_target_rva:X}")
                    changes.append(desc)

        return {
            'operation': 'INSERT',
            'rva': rva,
            'size': size,
            'total_refs': self.ref_db.count,
            'refs_affected': len(changes),
            'changes': changes,
            'warnings': warnings,
        }

    def insert_bytes(self, rva: int, data: bytes) -> ShiftResult:
        """Insert bytes at the given RVA, shift everything after, recalculate all refs."""
        N = len(data)
        if N == 0:
            return ShiftResult(ShiftOp.INSERT, rva, 0, 0, [], 0,
                               len(self.buffer), True, "Nothing to insert")

        # v7: signature warning
        warnings_pre = []
        sig_warn = self._check_signature_warning()
        if sig_warn:
            warnings_pre.append(sig_warn)
        # v7.2: .rsrc conflict warning
        rsrc_warn = self._check_rsrc_conflict(rva)
        if rsrc_warn:
            warnings_pre.append(rsrc_warn)

        # Find the file offset for this RVA
        insert_foff = self._rva_to_offset(rva)
        if insert_foff is None:
            return ShiftResult(ShiftOp.INSERT, rva, N, 0, [],
                               0, len(self.buffer), False,
                               f"RVA 0x{rva:X} does not map to any section")

        # Save undo data
        self._undo_stack.append((ShiftOp.INSERT, insert_foff, N, b''))

        # Phase 1: Splice bytes into buffer
        self.buffer[insert_foff:insert_foff] = data

        # Phase 2: Update section headers
        sections_adjusted = self._update_sections_after_insert(rva, N, insert_foff)

        # Phase 3: Recalculate all references
        refs_updated, warnings = self._recalculate_refs(rva, N)
        warnings = warnings_pre + warnings

        # Phase 4: Update PE headers
        self._update_pe_headers(rva, N)

        # Phase 5: v7.1 — Update resource directory RVAs
        self._update_resource_directory(rva, N)

        return ShiftResult(
            ShiftOp.INSERT, rva, N, refs_updated, warnings,
            sections_adjusted, len(self.buffer), True,
            f"Inserted {N} bytes at RVA 0x{rva:X}, updated {refs_updated} references"
        )

    def delete_bytes(self, rva: int, count: int) -> ShiftResult:
        """Delete bytes at the given RVA, shift everything after, recalculate all refs."""
        if count == 0:
            return ShiftResult(ShiftOp.DELETE, rva, 0, 0, [], 0,
                               len(self.buffer), True, "Nothing to delete")

        foff = self._rva_to_offset(rva)
        if foff is None:
            return ShiftResult(ShiftOp.DELETE, rva, -count, 0, [],
                               0, len(self.buffer), False,
                               f"RVA 0x{rva:X} does not map to any section")

        # v7.2: .rsrc conflict warning
        warnings_pre = []
        rsrc_warn = self._check_rsrc_conflict(rva)
        if rsrc_warn:
            warnings_pre.append(rsrc_warn)

        # Save undo data
        deleted = bytes(self.buffer[foff:foff + count])
        self._undo_stack.append((ShiftOp.DELETE, foff, count, deleted))

        # Phase 1: Remove bytes
        del self.buffer[foff:foff + count]

        # Phase 2: Update sections
        sections_adjusted = self._update_sections_after_insert(rva, -count, foff)

        # Phase 3: Recalculate refs (negative delta)
        refs_updated, warnings = self._recalculate_refs(rva, -count)
        warnings = warnings_pre + warnings

        # Phase 4: Update PE headers
        self._update_pe_headers(rva, -count)

        # Phase 5: v7.1 — Update resource directory RVAs
        self._update_resource_directory(rva, -count)

        return ShiftResult(
            ShiftOp.DELETE, rva, -count, refs_updated, warnings,
            sections_adjusted, len(self.buffer), True,
            f"Deleted {count} bytes at RVA 0x{rva:X}, updated {refs_updated} references"
        )

    def patch_bytes(self, rva: int, data: bytes) -> ShiftResult:
        """Overwrite bytes at RVA without changing size — no shift needed."""
        N = len(data)
        foff = self._rva_to_offset(rva)
        if foff is None:
            return ShiftResult(ShiftOp.PATCH, rva, 0, 0, [],
                               0, len(self.buffer), False,
                               f"RVA 0x{rva:X} not found")
        old = bytes(self.buffer[foff:foff + N])
        self._undo_stack.append((ShiftOp.PATCH, foff, N, old))
        self.buffer[foff:foff + N] = data
        return ShiftResult(ShiftOp.PATCH, rva, 0, 0, [], 0,
                           len(self.buffer), True,
                           f"Patched {N} bytes at RVA 0x{rva:X} (no shift)")

    def insert_nop_sled(self, rva: int, count: int) -> ShiftResult:
        """Insert a NOP sled (architecture-aware)."""
        nop = b'\x90' * count
        return self.insert_bytes(rva, nop)

    def undo(self) -> Optional[str]:
        """Undo the last operation."""
        if not self._undo_stack:
            return None
        op, foff, n, saved = self._undo_stack.pop()
        if op == ShiftOp.INSERT:
            del self.buffer[foff:foff + n]
            # Re-parse PE from buffer
            self.pe = pefile.PE(data=bytes(self.buffer))
            return f"Undid INSERT of {n} bytes at offset 0x{foff:X}"
        elif op == ShiftOp.DELETE:
            self.buffer[foff:foff] = saved
            self.pe = pefile.PE(data=bytes(self.buffer))
            return f"Undid DELETE of {n} bytes at offset 0x{foff:X}"
        elif op == ShiftOp.PATCH:
            self.buffer[foff:foff + n] = saved
            return f"Undid PATCH of {n} bytes at offset 0x{foff:X}"
        return None

    def save(self, output_path: str):
        """Write the modified binary to disk."""
        # Update PE checksum
        try:
            pe_out = pefile.PE(data=bytes(self.buffer))
            pe_out.OPTIONAL_HEADER.CheckSum = pe_out.generate_checksum()
            final = pe_out.write()
        except Exception:
            final = bytes(self.buffer)
        with open(output_path, 'wb') as f:
            f.write(final)

    # ── Internal: Reference Recalculation ─────────────────────────────

    def _recalculate_refs(self, insert_rva: int, delta: int) -> Tuple[int, List[str]]:
        """Recalculate all references after a shift at insert_rva by delta bytes."""
        updated = 0
        warnings = []
        relaxations = []

        for ref in self.ref_db.get_all():
            ref_moved = ref.ref_rva >= insert_rva
            target_moved = ref.target_rva >= insert_rva

            new_ref_rva = ref.ref_rva + (delta if ref_moved else 0)
            new_target_rva = ref.target_rva + (delta if target_moved else 0)
            new_foff = ref.file_offset + (delta if ref_moved else 0)

            if ref.is_relative:
                old_val = ref.target_rva - ref.ref_end_rva
                new_val = new_target_rva - (new_ref_rva + ref.insn_size)

                if old_val != new_val:
                    if ref.size_bytes == 1:
                        if new_val < -128 or new_val > 127:
                            relaxations.append((ref, new_foff, new_ref_rva, new_target_rva))
                            ref.ref_rva = new_ref_rva
                            ref.target_rva = new_target_rva
                            ref.file_offset = new_foff
                            continue
                        self._write_int(new_foff, new_val, 1, signed=True)
                    elif ref.size_bytes == 2:
                        self._write_int(new_foff, new_val, 2, signed=True)
                    elif ref.size_bytes == 4:
                        self._write_int(new_foff, new_val, 4, signed=True)
                    updated += 1
            else:
                if target_moved and ref.file_offset > 0:
                    new_abs = new_target_rva + self.image_base
                    if ref.size_bytes == 4:
                        self._write_int(new_foff, new_abs & 0xFFFFFFFF, 4)
                    elif ref.size_bytes == 8:
                        self._write_int(new_foff, new_abs, 8)
                    updated += 1

            ref.ref_rva = new_ref_rva
            ref.target_rva = new_target_rva
            ref.file_offset = new_foff

        self.ref_db.rebuild_indices()
        return self._run_relaxation_pass(relaxations, updated, warnings)

    # ── Internal: Section Header Updates ──────────────────────────────

    def _update_sections_after_insert(self, rva: int, delta: int, foff: int) -> int:
        """Update section headers after inserting/deleting bytes."""
        adjusted = 0
        target_section = None
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                target_section = s
                break

        if target_section:
            target_section.Misc_VirtualSize += delta
            # SizeOfRawData must be aligned to FileAlignment
            new_raw = target_section.SizeOfRawData + delta
            aligned_raw = (new_raw + self.file_alignment - 1) & ~(self.file_alignment - 1)
            # Pad to alignment boundary if needed
            padding_needed = aligned_raw - (target_section.SizeOfRawData + delta)
            if padding_needed > 0 and delta > 0:
                pad_foff = foff + delta  # right after inserted data
                # Find end of this section's raw data
                sec_end_foff = target_section.PointerToRawData + target_section.SizeOfRawData + delta
                self.buffer[sec_end_foff:sec_end_foff] = b'\x00' * padding_needed
                delta += padding_needed
            target_section.SizeOfRawData = aligned_raw
            adjusted += 1

        # Shift PointerToRawData for sections after the target
        for s in self.pe.sections:
            if s != target_section and s.PointerToRawData > foff:
                s.PointerToRawData += delta
                adjusted += 1

        return adjusted

    def _update_pe_headers(self, rva: int, delta: int):
        """Update PE optional header fields after shift."""
        oh = self.pe.OPTIONAL_HEADER
        # Entry point
        if oh.AddressOfEntryPoint >= rva:
            oh.AddressOfEntryPoint += delta
        # SizeOfImage
        last_sec = max(self.pe.sections,
                       key=lambda s: s.VirtualAddress + s.Misc_VirtualSize)
        raw_end = last_sec.VirtualAddress + last_sec.Misc_VirtualSize
        aligned = (raw_end + self.section_alignment - 1) & ~(self.section_alignment - 1)
        oh.SizeOfImage = aligned
        # SizeOfCode
        code_size = sum(s.SizeOfRawData for s in self.pe.sections
                        if s.Characteristics & 0x20000000)
        oh.SizeOfCode = code_size
        # Data directories that have RVAs
        for i, dd in enumerate(oh.DATA_DIRECTORY):
            if dd.VirtualAddress and dd.VirtualAddress >= rva:
                dd.VirtualAddress += delta

    # ── v7: Section Management ────────────────────────────────────────

    def add_section(self, name: str, size: int, characteristics: int = 0xE0000020,
                    data: bytes = None) -> Dict:
        """
        Add a new PE section at the end of the section table.

        Args:
            name: Section name (max 8 chars, e.g. '.ubrt')
            size: Virtual size of the new section
            characteristics: Section characteristics flags (default: RWX + code)
            data: Optional initial data (padded/truncated to aligned size)

        Returns:
            Dict with section details {'name', 'rva', 'vsize', 'raw_offset', 'raw_size'}
        """
        fa = self.file_alignment
        sa = self.section_alignment

        # Validate name
        sec_name = name.encode('ascii')[:8].ljust(8, b'\x00')

        # Compute where the new section goes
        last_sec = max(self.pe.sections, key=lambda s: s.VirtualAddress)
        new_rva = last_sec.VirtualAddress + last_sec.Misc_VirtualSize
        new_rva = (new_rva + sa - 1) & ~(sa - 1)  # align to section alignment

        last_raw = max(self.pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
        new_raw_offset = last_raw.PointerToRawData + last_raw.SizeOfRawData
        new_raw_offset = (new_raw_offset + fa - 1) & ~(fa - 1)  # align to file alignment

        raw_size = (size + fa - 1) & ~(fa - 1)  # file-aligned size

        # Check there's room in the header for a new section entry
        header_end = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        num_sections = self.pe.FILE_HEADER.NumberOfSections
        section_table_offset = (self.pe.OPTIONAL_HEADER.get_file_offset() +
                                self.pe.FILE_HEADER.SizeOfOptionalHeader)
        entry_size = 40  # sizeof(IMAGE_SECTION_HEADER)
        needed = section_table_offset + (num_sections + 1) * entry_size
        if needed > header_end:
            return {'error': f'No room for section header (need {needed}, headers end at {header_end})'}

        # Prepare section data
        if data is not None:
            sec_data = bytearray(data[:raw_size]).ljust(raw_size, b'\x00')
        else:
            sec_data = bytearray(raw_size)

        # Extend buffer
        if new_raw_offset > len(self.buffer):
            self.buffer.extend(b'\x00' * (new_raw_offset - len(self.buffer)))
        if new_raw_offset < len(self.buffer):
            # Insert at the right position
            self.buffer[new_raw_offset:new_raw_offset] = sec_data
        else:
            self.buffer.extend(sec_data)

        # Write the section header entry
        entry_offset = section_table_offset + num_sections * entry_size
        struct.pack_into('8s', self.buffer, entry_offset, sec_name)
        struct.pack_into('<I', self.buffer, entry_offset + 8, size)           # VirtualSize
        struct.pack_into('<I', self.buffer, entry_offset + 12, new_rva)       # VirtualAddress
        struct.pack_into('<I', self.buffer, entry_offset + 16, raw_size)      # SizeOfRawData
        struct.pack_into('<I', self.buffer, entry_offset + 20, new_raw_offset) # PointerToRawData
        struct.pack_into('<I', self.buffer, entry_offset + 24, 0)             # PointerToRelocations
        struct.pack_into('<I', self.buffer, entry_offset + 28, 0)             # PointerToLinenumbers
        struct.pack_into('<H', self.buffer, entry_offset + 32, 0)             # NumberOfRelocations
        struct.pack_into('<H', self.buffer, entry_offset + 34, 0)             # NumberOfLinenumbers
        struct.pack_into('<I', self.buffer, entry_offset + 36, characteristics)

        # Update PE headers
        self.pe.FILE_HEADER.NumberOfSections = num_sections + 1
        oh = self.pe.OPTIONAL_HEADER
        new_image_end = new_rva + size
        oh.SizeOfImage = (new_image_end + sa - 1) & ~(sa - 1)
        if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            oh.SizeOfCode += raw_size
        if characteristics & 0x00000040:  # IMAGE_SCN_CNT_INITIALIZED_DATA
            oh.SizeOfInitializedData += raw_size

        # Re-parse PE to pick up new section
        self.pe = pefile.PE(data=bytes(self.buffer))

        # Record for undo
        self._undo_stack.append((ShiftOp.INSERT, new_raw_offset, raw_size, b''))

        result = {
            'name': name,
            'rva': new_rva,
            'vsize': size,
            'raw_offset': new_raw_offset,
            'raw_size': raw_size,
        }
        self._record_batch_op(('add_section', result))
        return result

    def remove_section(self, name: str) -> Dict:
        """
        Remove a PE section by name. Only the last section can be safely removed.

        Args:
            name: Name of the section to remove (e.g. '.ubrt')

        Returns:
            Dict with removal details or error
        """
        target = None
        for s in self.pe.sections:
            sec_name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if sec_name == name:
                target = s
                break
        if target is None:
            return {'error': f'Section {name!r} not found'}

        # Only allow removing the last section (by VirtualAddress)
        last_sec = max(self.pe.sections, key=lambda s: s.VirtualAddress)
        if target.VirtualAddress != last_sec.VirtualAddress:
            return {'error': f'Can only remove the last section (last is '
                    f'{last_sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")!r})'}

        raw_off = target.PointerToRawData
        raw_size = target.SizeOfRawData
        sec_rva = target.VirtualAddress
        sec_vsize = target.Misc_VirtualSize
        old_data = bytes(self.buffer[raw_off:raw_off + raw_size])

        # Remove section data from buffer
        self.buffer[raw_off:raw_off + raw_size] = b''

        # Clear the section header entry
        num_sections = self.pe.FILE_HEADER.NumberOfSections
        section_table_offset = (self.pe.OPTIONAL_HEADER.get_file_offset() +
                                self.pe.FILE_HEADER.SizeOfOptionalHeader)
        entry_size = 40
        last_entry_offset = section_table_offset + (num_sections - 1) * entry_size
        self.buffer[last_entry_offset:last_entry_offset + entry_size] = b'\x00' * entry_size

        # Update PE headers
        self.pe.FILE_HEADER.NumberOfSections = num_sections - 1
        oh = self.pe.OPTIONAL_HEADER
        if num_sections >= 2:
            prev_sec = sorted(self.pe.sections, key=lambda s: s.VirtualAddress)[-2]
            new_end = prev_sec.VirtualAddress + prev_sec.Misc_VirtualSize
            sa = self.section_alignment
            oh.SizeOfImage = (new_end + sa - 1) & ~(sa - 1)
        if target.Characteristics & 0x20000000:
            oh.SizeOfCode = max(0, oh.SizeOfCode - raw_size)
        if target.Characteristics & 0x00000040:
            oh.SizeOfInitializedData = max(0, oh.SizeOfInitializedData - raw_size)

        # Re-parse PE
        self.pe = pefile.PE(data=bytes(self.buffer))

        # Record for undo
        self._undo_stack.append((ShiftOp.DELETE, raw_off, raw_size, old_data))

        result = {
            'removed': name,
            'rva': sec_rva,
            'vsize': sec_vsize,
            'raw_removed': raw_size,
        }
        self._record_batch_op(('remove_section', result))
        return result

    # ── v7.1: Padding Reclamation ─────────────────────────────────────

    def compact(self) -> Dict:
        """
        v7.1: Reclaim wasted padding in the PE binary.
        Scans all sections and removes trailing zero-filled padding that extends
        beyond Misc_VirtualSize. Truncates the file and updates all headers.

        WARNING: This is a destructive operation that rebuilds section layout.
        Call after all modifications are done. Undo stack is cleared.

        Returns:
            Dict with compaction results
        """
        fa = self.file_alignment
        reclaimed = 0
        sections_trimmed = 0

        # Sorted sections by raw offset
        sorted_secs = sorted(self.pe.sections,
                             key=lambda s: s.PointerToRawData)

        for sec in sorted_secs:
            raw_off = sec.PointerToRawData
            raw_size = sec.SizeOfRawData
            vsize = sec.Misc_VirtualSize

            if raw_size <= vsize:
                continue  # No padding to reclaim

            # Check if bytes beyond vsize are all zero
            check_start = raw_off + vsize
            check_end = raw_off + raw_size
            if check_start >= len(self.buffer) or check_end > len(self.buffer):
                continue

            trailing = self.buffer[check_start:check_end]
            if trailing == b'\x00' * len(trailing):
                # All zeros — can reclaim, but must maintain file alignment
                new_raw_size = (vsize + fa - 1) & ~(fa - 1)
                if new_raw_size >= raw_size:
                    continue  # No savings after alignment

                saved = raw_size - new_raw_size
                # Remove the reclaimed bytes from the buffer
                del self.buffer[raw_off + new_raw_size:raw_off + raw_size]

                # Update this section's SizeOfRawData
                sec.SizeOfRawData = new_raw_size

                # Shift all subsequent sections' PointerToRawData
                for other in sorted_secs:
                    if other.PointerToRawData > raw_off:
                        other.PointerToRawData -= saved

                reclaimed += saved
                sections_trimmed += 1

        if reclaimed == 0:
            return {'compacted': False, 'message': 'No reclaimable padding found'}

        # Re-parse PE from modified buffer
        self.pe = pefile.PE(data=bytes(self.buffer))

        # Clear undo stack (layout changed completely)
        self._undo_stack.clear()

        return {
            'compacted': True,
            'bytes_reclaimed': reclaimed,
            'sections_trimmed': sections_trimmed,
            'new_size': len(self.buffer),
        }

    # ── v7.1: Resource Directory Updater ──────────────────────────────

    def _update_resource_directory(self, shift_rva: int, delta: int):
        """
        v7.2: Walk the PE resource directory tree and update all OffsetToData RVAs.
        Called automatically after insert/delete when .rsrc section is affected.

        If the shift occurs INSIDE the .rsrc section, the internal offsets
        (which are relative to section start) would become invalid. In that case,
        we skip the update and log a warning — callers should avoid modifying
        inside .rsrc or use a separate section for new code.
        """
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 2:
            return
        rsrc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        if rsrc_dir.VirtualAddress == 0 or rsrc_dir.Size == 0:
            return

        rsrc_rva = rsrc_dir.VirtualAddress
        rsrc_foff = self._rva_to_offset(rsrc_rva)
        if rsrc_foff is None:
            return

        rsrc_section = None
        for s in self.pe.sections:
            if s.VirtualAddress == rsrc_rva:
                rsrc_section = s
                break
        if rsrc_section is None:
            return

        rsrc_end_rva = rsrc_rva + rsrc_section.Misc_VirtualSize

        # v7.2: If shift is INSIDE .rsrc, the tree structure itself shifted and
        # internal relative offsets are now broken. We cannot safely update.
        if rsrc_rva < shift_rva < rsrc_end_rva:
            # The shift is inside the resource section — skip update.
            # The resource tree is now potentially corrupted.
            return

        rsrc_end = rsrc_foff + rsrc_section.SizeOfRawData

        visited = set()
        self._walk_and_update_rsrc(rsrc_foff, rsrc_foff, rsrc_end, shift_rva, delta, visited, 0)

    def _walk_and_update_rsrc(self, dir_foff: int, rsrc_base: int, rsrc_end: int,
                               shift_rva: int, delta: int, visited: set, depth: int):
        """Recursively walk and update resource directory RVAs."""
        if depth > 5 or dir_foff in visited:
            return
        visited.add(dir_foff)
        if dir_foff + 16 > rsrc_end or dir_foff + 16 > len(self.buffer):
            return

        num_named = struct.unpack_from('<H', self.buffer, dir_foff + 12)[0]
        num_id = struct.unpack_from('<H', self.buffer, dir_foff + 14)[0]
        total = num_named + num_id

        entry_off = dir_foff + 16
        for _ in range(total):
            if entry_off + 8 > rsrc_end:
                break
            offset_to_data = struct.unpack_from('<I', self.buffer, entry_off + 4)[0]

            if offset_to_data & 0x80000000:
                sub_offset = offset_to_data & 0x7FFFFFFF
                sub_foff = rsrc_base + sub_offset
                self._walk_and_update_rsrc(sub_foff, rsrc_base, rsrc_end,
                                           shift_rva, delta, visited, depth + 1)
            else:
                data_entry_foff = rsrc_base + offset_to_data
                if data_entry_foff + 16 <= rsrc_end and data_entry_foff + 4 <= len(self.buffer):
                    data_rva = struct.unpack_from('<I', self.buffer, data_entry_foff)[0]
                    if data_rva >= shift_rva and data_rva > 0:
                        struct.pack_into('<I', self.buffer, data_entry_foff, data_rva + delta)
            entry_off += 8


# ─── QEMU Tracer ─────────────────────────────────────────────────────────

class QEMUTracer:
    """
    Dynamic tracing via QEMU for coverage-guided reference discovery.

    Supports:
    - QEMU system emulation with execution trace logging
    - GDB stub connection for breakpoints and inspection
    - Trace log parsing for basic block coverage
    """

    def __init__(self, qemu_path: str = "qemu-system-i386"):
        self.qemu_path = qemu_path
        self.process: Optional[subprocess.Popen] = None
        self.trace_log: Optional[str] = None
        self.coverage: Dict[int, TraceBlock] = {}
        self._gdb_port: int = 1234
        self._running = False

    @staticmethod
    def find_qemu() -> Optional[str]:
        """Auto-detect QEMU installation on Windows."""
        search_paths = [
            r"C:\Program Files\qemu",
            r"C:\Program Files (x86)\qemu",
            r"C:\qemu",
            os.path.expandvars(r"%LOCALAPPDATA%\qemu"),
        ]
        for base in search_paths:
            for exe in ("qemu-system-i386.exe", "qemu-system-x86_64.exe"):
                full = os.path.join(base, exe)
                if os.path.isfile(full):
                    return full
        # Try PATH
        for exe in ("qemu-system-i386", "qemu-system-x86_64"):
            try:
                r = subprocess.run([exe, "--version"], capture_output=True, timeout=5)
                if r.returncode == 0:
                    return exe
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    def start_trace(self, disk_image: str, extra_args: List[str] = None,
                    trace_file: str = None, gdb_port: int = 1234,
                    memory: str = "512M") -> Dict:
        """Start QEMU with execution tracing enabled."""
        if self.process and self.process.poll() is None:
            return {'success': False, 'error': 'QEMU already running'}

        self._gdb_port = gdb_port
        self.trace_log = trace_file or os.path.join(
            os.path.dirname(disk_image), "ubrt_trace.log")

        cmd = [
            self.qemu_path,
            "-hda", disk_image,
            "-m", memory,
            "-gdb", f"tcp::{gdb_port}",
            "-d", "exec,in_asm",
            "-D", self.trace_log,
            "-display", "none",
        ]
        if extra_args:
            cmd.extend(extra_args)

        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            self._running = True
            return {
                'success': True,
                'pid': self.process.pid,
                'gdb_port': gdb_port,
                'trace_log': self.trace_log,
                'cmd': ' '.join(cmd),
            }
        except FileNotFoundError:
            return {'success': False, 'error': f'QEMU not found at {self.qemu_path}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop(self) -> Dict:
        """Stop QEMU process."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self._running = False
            return {'success': True, 'message': 'QEMU stopped'}
        return {'success': False, 'error': 'QEMU not running'}

    @property
    def is_running(self) -> bool:
        return self._running and self.process is not None and self.process.poll() is None

    def parse_trace_log(self, image_base: int = 0) -> Dict:
        """
        v7.1: Parse QEMU execution trace log to extract basic block coverage
        AND branch targets (indirect call/jump destinations).

        QEMU -d exec,in_asm produces:
        - "Trace N: 0xADDR [size=XX]" for basic block execution
        - "0xADDR:  mnemonic  operands" for disassembled instructions

        Branch targets are inferred by tracking consecutive Trace entries:
        the start address of block B is a branch target of block A if B doesn't
        immediately follow the last instruction of A.
        """
        if not self.trace_log or not os.path.isfile(self.trace_log):
            return {'success': False, 'error': 'No trace log available'}

        self.coverage.clear()
        block_count = 0
        insn_count = 0
        branch_pairs = 0  # (source_block_rva, target_block_addr) pairs found

        try:
            prev_block_rva = None
            prev_block_addr = None
            prev_block_size = 0
            current_block_insns = []

            with open(self.trace_log, 'r', errors='replace') as f:
                for line in f:
                    line = line.strip()

                    # ── Trace line: basic block start ──
                    if line.startswith('Trace') and '0x' in line:
                        block_addr = None
                        block_size = 0
                        parts = line.split()
                        for j, p in enumerate(parts):
                            if p.startswith('0x'):
                                try:
                                    block_addr = int(p.rstrip(':,[]'), 16)
                                except ValueError:
                                    continue
                            if p.startswith('[size=') or p.startswith('size='):
                                try:
                                    block_size = int(p.strip('[]').split('=')[1])
                                except (ValueError, IndexError):
                                    pass

                        if block_addr is None:
                            continue

                        rva = block_addr - image_base if image_base else block_addr
                        if rva in self.coverage:
                            self.coverage[rva].hit_count += 1
                        else:
                            self.coverage[rva] = TraceBlock(
                                start_va=block_addr,
                                end_va=block_addr + max(block_size, 1))
                        block_count += 1

                        # v7.1: Detect branch targets — if this block doesn't
                        # immediately follow the previous block, it's a branch target
                        if prev_block_addr is not None and prev_block_size > 0:
                            expected_fallthrough = prev_block_addr + prev_block_size
                            if block_addr != expected_fallthrough:
                                # This is a branch target from the previous block
                                if prev_block_rva in self.coverage:
                                    self.coverage[prev_block_rva].branch_targets.append(block_addr)
                                    branch_pairs += 1

                        prev_block_rva = rva
                        prev_block_addr = block_addr
                        prev_block_size = block_size

                    # ── IN_ASM line: disassembled instruction ──
                    elif line and line[0] == '0' and 'x' in line[:4]:
                        try:
                            addr_str = line.split(':')[0].strip()
                            addr = int(addr_str, 16)
                            insn_count += 1
                            # Track instruction mnemonics for indirect call/jmp detection
                            remainder = line.split(':', 1)[1].strip() if ':' in line else ''
                            mnemonic = remainder.split()[0].lower() if remainder else ''
                            if mnemonic in ('call', 'callq', 'jmp', 'jmpq',
                                            'bl', 'blr', 'br', 'b', 'blx', 'bx'):
                                # This is a control transfer — the NEXT Trace line
                                # gives us the actual target. Already handled above
                                # by the fallthrough detection.
                                pass
                        except (ValueError, IndexError):
                            pass

            # Deduplicate branch targets
            for rva, block in self.coverage.items():
                block.branch_targets = list(set(block.branch_targets))

            return {
                'success': True,
                'blocks': block_count,
                'unique_blocks': len(self.coverage),
                'instructions': insn_count,
                'branch_targets_found': branch_pairs,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_coverage_refs(self, image_base: int = 0,
                          addr_to_offset=None) -> List[Reference]:
        """
        v7.2: Convert dynamic trace data into Reference entries.
        Produces branch target refs (from indirect calls/jumps) with high confidence.

        Args:
            image_base: Base address to subtract from virtual addresses to get RVAs.
            addr_to_offset: Optional callable(rva) -> file_offset for computing
                            valid file offsets so the shift engine can update them.
        """
        refs = []
        seen_targets = set()

        for rva, block in self.coverage.items():
            for target in block.branch_targets:
                target_rva = target - image_base if image_base else target
                pair = (rva, target_rva)
                if pair in seen_targets:
                    continue
                seen_targets.add(pair)

                # v7.2: Compute actual file offset so shift engine can update this ref
                foff = 0
                if addr_to_offset is not None:
                    resolved = addr_to_offset(rva)
                    if resolved is not None:
                        foff = resolved

                refs.append(Reference(
                    file_offset=foff,
                    ref_type=RefType.INDIRECT_CALL,
                    target_rva=target_rva,
                    ref_rva=rva,
                    size_bytes=0, is_relative=False, insn_size=0,
                    section_name="qemu_trace",
                    confidence=0.95, source=RefSource.QEMU_TRACE,
                ))
        return refs

    def get_gdb_port(self) -> int:
        return self._gdb_port


# ─── UBRT Engine (Main Coordinator) ──────────────────────────────────────

class UBRTEngine:
    """
    Main engine coordinating all UBRT operations.

    Workflow:
    1. Load binary (auto-detects PE or ELF)
    2. Find all references (static analysis)
    3. [Optional] Run dynamic trace via QEMU
    4. Apply modifications (insert/delete/patch)
    5. Update symbols after shift
    6. Save modified binary
    """

    def __init__(self):
        self.pe_path: Optional[str] = None
        self.ref_db: Optional[ReferenceDatabase] = None
        self.shift_engine = None  # ShiftEngine or ELFShiftEngine
        self.qemu: Optional[QEMUTracer] = None
        self.pe_info: Dict = {}
        self._history: List[ShiftResult] = []
        self.binary_format: str = "unknown"  # "pe" or "elf"
        self._symbol_updater = SymbolUpdater()
        self._symbols: Dict[int, str] = {}    # VA -> symbol name
        self._symbol_meta: Dict = {}           # metadata from symbol loader
        self._symbol_source: Optional[str] = None  # path to loaded symbol file

    @staticmethod
    def detect_format(path: str) -> str:
        """Detect binary format from magic bytes."""
        with open(path, 'rb') as f:
            magic = f.read(4)
        if magic[:2] == b'MZ':
            return 'pe'
        if magic[:4] == b'\x7fELF':
            return 'elf'
        # Mach-O: little-endian magic
        if len(magic) >= 4:
            m32 = struct.unpack_from('<I', magic, 0)[0]
            if m32 in (0xFEEDFACE, 0xFEEDFACF):
                return 'macho'
            # Fat/universal binary (big-endian magic)
            m32_be = struct.unpack_from('>I', magic, 0)[0]
            if m32_be == 0xCAFEBABE:
                return 'macho'
        return 'unknown'

    def load(self, pe_path: str, callback=None) -> Dict:
        """Load a binary (PE or ELF) and analyze all references."""
        if not os.path.isfile(pe_path):
            return {'success': False, 'error': f'File not found: {pe_path}'}

        self.pe_path = pe_path
        self.binary_format = self.detect_format(pe_path)

        if self.binary_format == 'elf':
            return self._load_elf(pe_path, callback)
        elif self.binary_format == 'pe':
            return self._load_pe(pe_path, callback)
        elif self.binary_format == 'macho':
            return self._load_macho(pe_path, callback)
        else:
            return {'success': False, 'error': 'Unknown binary format (expected PE, ELF, or Mach-O)'}

    def _load_pe(self, pe_path: str, callback=None) -> Dict:
        """Load a PE binary and analyze all references."""
        try:
            finder = PEReferenceFinder(pe_path)
            self.ref_db = finder.find_all(callback=callback)
            self.shift_engine = ShiftEngine(pe_path, self.ref_db)
            self.pe_info = {
                'path': pe_path,
                'format': 'pe',
                'size': os.path.getsize(pe_path),
                'image_base': finder.image_base,
                'is_64': finder.is_64,
                'sections': [],
                'entry_point': finder.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            }
            for s in finder.pe.sections:
                name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
                self.pe_info['sections'].append({
                    'name': name,
                    'rva': s.VirtualAddress,
                    'vsize': s.Misc_VirtualSize,
                    'raw_size': s.SizeOfRawData,
                    'raw_offset': s.PointerToRawData,
                    'is_code': bool(s.Characteristics & 0x20000000),
                    'is_data': bool(s.Characteristics & 0x40000000),
                    'is_writable': bool(s.Characteristics & 0x80000000),
                })
            return {
                'success': True,
                'refs_found': self.ref_db.count,
                'stats': self.ref_db.stats(),
                'pe_info': self.pe_info,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _load_elf(self, elf_path: str, callback=None) -> Dict:
        """Load an ELF binary and analyze all references."""
        if not HAS_ELFTOOLS:
            return {'success': False, 'error': 'pyelftools not installed (pip install pyelftools)'}
        try:
            finder = ELFReferenceFinder(elf_path)
            self.ref_db = finder.find_all(callback=callback)
            self.shift_engine = ELFShiftEngine(elf_path, self.ref_db)
            self.pe_info = {
                'path': elf_path,
                'format': 'elf',
                'size': os.path.getsize(elf_path),
                'image_base': finder.image_base,
                'is_64': finder.is_64,
                'is_pie': finder.is_pie,
                'sections': [],
                'entry_point': finder.elf.header['e_entry'],
            }
            for sec in finder.elf.iter_sections():
                self.pe_info['sections'].append({
                    'name': sec.name,
                    'rva': sec.header['sh_addr'],
                    'vsize': sec.header['sh_size'],
                    'raw_size': sec.header['sh_size'],
                    'raw_offset': sec.header['sh_offset'],
                    'is_code': bool(sec.header['sh_flags'] & 0x4),
                    'is_data': bool(sec.header['sh_flags'] & 0x1),
                    'is_writable': bool(sec.header['sh_flags'] & 0x1),
                })
            finder.close()
            return {
                'success': True,
                'refs_found': self.ref_db.count,
                'stats': self.ref_db.stats(),
                'pe_info': self.pe_info,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _load_macho(self, macho_path: str, callback=None) -> Dict:
        """Load a Mach-O binary and analyze all references."""
        try:
            finder = MachOReferenceFinder(macho_path)
            self.ref_db = finder.find_all(callback=callback)
            self.shift_engine = MachOShiftEngine(macho_path, self.ref_db)
            self.pe_info = {
                'path': macho_path,
                'format': 'macho',
                'size': os.path.getsize(macho_path),
                'image_base': finder.image_base,
                'is_64': finder.is_64,
                'is_fat': finder.is_fat,
                'sections': [],
                'entry_point': 0,
            }
            for sec in finder.sections:
                self.pe_info['sections'].append({
                    'name': sec['name'],
                    'rva': sec['addr'],
                    'vsize': sec['size'],
                    'raw_size': sec['size'],
                    'raw_offset': sec['offset'],
                    'is_code': sec['is_code'],
                    'is_data': not sec['is_code'],
                    'is_writable': False,
                })
            finder.close()
            return {
                'success': True,
                'refs_found': self.ref_db.count,
                'stats': self.ref_db.stats(),
                'pe_info': self.pe_info,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def preview(self, operation: str, rva: int, size_or_data) -> Dict:
        """Preview an operation without applying it."""
        if not self.shift_engine:
            return {'success': False, 'error': 'No binary loaded'}
        if operation == 'insert':
            return self.shift_engine.preview_insert(rva, size_or_data)
        return {'success': False, 'error': f'Unknown operation: {operation}'}

    def insert(self, rva: int, data: bytes) -> ShiftResult:
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        result = self.shift_engine.insert_bytes(rva, data)
        if result.success:
            self._update_symbols_after_shift(rva, len(data))
        self._history.append(result)
        return result

    def delete(self, rva: int, count: int) -> ShiftResult:
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        result = self.shift_engine.delete_bytes(rva, count)
        if result.success:
            self._update_symbols_after_shift(rva, -count)
        self._history.append(result)
        return result

    def patch(self, rva: int, data: bytes) -> ShiftResult:
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        result = self.shift_engine.patch_bytes(rva, data)
        self._history.append(result)
        return result

    def insert_nops(self, rva: int, count: int) -> ShiftResult:
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        result = self.shift_engine.insert_nop_sled(rva, count)
        self._history.append(result)
        return result

    def undo(self) -> Optional[str]:
        if not self.shift_engine:
            return None
        msg = self.shift_engine.undo()
        if msg and self._history:
            self._history.pop()
        return msg

    def save(self, output_path: str):
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        self.shift_engine.save(output_path)

    def get_history(self) -> List[Dict]:
        return [
            {
                'op': r.operation.value, 'rva': f'0x{r.rva:X}',
                'delta': r.delta, 'refs_updated': r.refs_updated,
                'warnings': len(r.warnings), 'success': r.success,
                'message': r.message,
            }
            for r in self._history
        ]

    def get_ref_stats(self) -> Dict:
        if not self.ref_db:
            return {}
        return self.ref_db.stats()

    def get_refs_at_rva(self, rva: int, range_size: int = 0x100) -> List[Dict]:
        """Get references near a specific RVA."""
        if not self.ref_db:
            return []
        result = []
        for ref in self.ref_db.get_all():
            if rva <= ref.ref_rva < rva + range_size:
                result.append(ref.to_dict())
        return result

    def setup_qemu(self, qemu_path: str = None):
        """Initialize QEMU tracer."""
        if qemu_path:
            self.qemu = QEMUTracer(qemu_path)
        else:
            found = QEMUTracer.find_qemu()
            if found:
                self.qemu = QEMUTracer(found)
            else:
                self.qemu = None

    def start_trace(self, disk_image: str, **kwargs) -> Dict:
        if not self.qemu:
            return {'success': False, 'error': 'QEMU not configured'}
        return self.qemu.start_trace(disk_image, **kwargs)

    def stop_trace(self) -> Dict:
        if not self.qemu:
            return {'success': False, 'error': 'QEMU not configured'}
        return self.qemu.stop()

    def merge_trace_coverage(self) -> Dict:
        """Merge dynamic trace data into the reference database."""
        if not self.qemu or not self.ref_db:
            return {'success': False, 'error': 'QEMU trace or ref DB not available'}
        ib = self.pe_info.get('image_base', 0)
        result = self.qemu.parse_trace_log(image_base=ib)
        if result.get('success'):
            # v7.2: Provide address-to-offset converter so refs get valid file offsets
            addr_to_offset = None
            if self.shift_engine:
                if hasattr(self.shift_engine, '_rva_to_offset'):
                    addr_to_offset = self.shift_engine._rva_to_offset
                elif hasattr(self.shift_engine, '_vaddr_to_offset'):
                    addr_to_offset = self.shift_engine._vaddr_to_offset
            new_refs = self.qemu.get_coverage_refs(
                image_base=ib, addr_to_offset=addr_to_offset)
            added = 0
            for ref in new_refs:
                self.ref_db.add(ref)
                added += 1
            result['refs_added'] = added
            result['total_refs'] = self.ref_db.count
        return result

    def _update_symbols_after_shift(self, shift_addr: int, delta: int):
        """Update all symbol/directory tables after a shift operation."""
        if not self.shift_engine:
            return
        buf = self.shift_engine.buffer
        is_64 = self.pe_info.get('is_64', False)

        if self.binary_format == 'elf':
            endian = getattr(self.shift_engine, 'endian', '<')
            count = SymbolUpdater.update_elf_symbols(buf, is_64, shift_addr, delta, endian)
        elif self.binary_format == 'pe' and isinstance(self.shift_engine, ShiftEngine):
            count = SymbolUpdater.update_pe_exports(
                buf, self.shift_engine.pe, shift_addr, delta)
            count += SymbolUpdater.update_pe_debug_dir(
                buf, self.shift_engine.pe, shift_addr, delta)
            count += SymbolUpdater.update_pe_imports(
                buf, self.shift_engine.pe, shift_addr, delta)
            count += SymbolUpdater.update_pe_exception_table(
                buf, self.shift_engine.pe, shift_addr, delta)
            count += SymbolUpdater.update_pe_base_reloc(
                buf, self.shift_engine.pe, shift_addr, delta)

        # Update loaded external symbols if present
        if hasattr(self, '_symbols') and self._symbols:
            ib = self.pe_info.get('image_base', 0)
            self._symbols = SymbolUpdater.shift_symbols(
                self._symbols, shift_addr, delta, ib)

    # ── v7: Batch/Transaction Interface ───────────────────────────────

    def begin_batch(self):
        """Start a batch transaction for multiple operations."""
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        self.shift_engine.begin_batch()

    def commit_batch(self) -> Dict:
        """Commit the current batch."""
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        return self.shift_engine.commit_batch()

    def rollback_batch(self) -> str:
        """Rollback the current batch."""
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        return self.shift_engine.rollback_batch()

    # ── v7: Cross-Section Validation ──────────────────────────────────

    def validate_references(self) -> Dict:
        """Validate all reference targets are within valid address ranges."""
        if not self.shift_engine or not self.ref_db:
            return {'success': False, 'error': 'No binary loaded'}

        valid_ranges = []
        for sec in self.pe_info.get('sections', []):
            rva = sec.get('rva', 0)
            vsize = sec.get('vsize', 0)
            if rva > 0 and vsize > 0:
                valid_ranges.append((rva, rva + vsize))

        broken = self.shift_engine.validate_all_targets(valid_ranges)
        return {
            'success': True,
            'total_refs': self.ref_db.count,
            'broken_refs': len(broken),
            'broken': broken[:50],  # cap output
        }

    # ── v7: Code Signing Detection ────────────────────────────────────

    def check_signature(self) -> Optional[Dict]:
        """Check if the loaded binary has a code signature."""
        if not self.shift_engine:
            return None
        return self.shift_engine.detect_code_signature()

    def strip_signature(self) -> Dict:
        """v7.2: Remove code signature (Authenticode / LC_CODE_SIGNATURE)."""
        if not self.shift_engine:
            return {'error': 'No binary loaded'}
        if not hasattr(self.shift_engine, 'strip_signature'):
            return {'error': 'Signature stripping not supported for this format'}
        return self.shift_engine.strip_signature()

    # ── v7: Range Query Interface ─────────────────────────────────────

    def get_refs_in_range(self, lo: int, hi: int) -> List[Dict]:
        """Get all references with ref_rva in [lo, hi)."""
        if not self.ref_db:
            return []
        return [r.to_dict() for r in self.ref_db.get_refs_in_range(lo, hi)]

    def get_refs_targeting_range(self, lo: int, hi: int) -> List[Dict]:
        """Get all references whose target_rva falls in [lo, hi)."""
        if not self.ref_db:
            return []
        return [r.to_dict() for r in self.ref_db.get_refs_targeting_range(lo, hi)]

    # ── v7: Section Management ────────────────────────────────────────

    def add_section(self, name: str, size: int, characteristics: int = 0xE0000020,
                    data: bytes = None) -> Dict:
        """Add a new section to the loaded PE binary."""
        if not self.shift_engine:
            return {'error': 'No binary loaded or shift engine not initialized'}
        if not hasattr(self.shift_engine, 'add_section'):
            return {'error': 'Section management not supported for this format'}
        return self.shift_engine.add_section(name, size, characteristics, data)

    def remove_section(self, name: str) -> Dict:
        """Remove a section from the loaded PE binary (last section only)."""
        if not self.shift_engine:
            return {'error': 'No binary loaded or shift engine not initialized'}
        if not hasattr(self.shift_engine, 'remove_section'):
            return {'error': 'Section management not supported for this format'}
        return self.shift_engine.remove_section(name)

    # ── v7.1: Compact / Padding Reclamation ───────────────────────────

    def compact(self) -> Dict:
        """Reclaim wasted padding in the loaded binary (PE, ELF, or Mach-O)."""
        if not self.shift_engine:
            return {'error': 'No binary loaded'}
        if not hasattr(self.shift_engine, 'compact'):
            return {'error': 'Compact not supported for this binary format'}
        return self.shift_engine.compact()

    # ── v7.1: Mach-O Fat Binary Extraction ────────────────────────────

    @staticmethod
    def extract_thin_macho(fat_path: str, arch_index: int = 0,
                           output_path: str = None) -> Dict:
        """Extract a single architecture from a fat (universal) Mach-O binary."""
        return MachOShiftEngine.extract_thin_macho(fat_path, arch_index, output_path)

    # ── v7.1: QEMU Dynamic Tracing Helpers ────────────────────────────

    def get_trace_stats(self) -> Dict:
        """Get current QEMU trace statistics."""
        if not self.qemu:
            return {'error': 'QEMU not configured'}
        return {
            'is_running': self.qemu.is_running,
            'trace_log': self.qemu.trace_log,
            'unique_blocks': len(self.qemu.coverage),
            'total_branch_targets': sum(
                len(b.branch_targets) for b in self.qemu.coverage.values()
            ),
            'gdb_port': self.qemu.get_gdb_port(),
        }

    # ── Symbol Management ─────────────────────────────────────────────

    def load_symbols(self, symbol_path: str, image_base: int = None) -> Dict:
        """
        Load symbols from a .map / .pdb / .dbg / .sym file.
        Symbols are kept in memory and shifted automatically on insert/delete.
        They annotate the hex editor and can be exported as a .map file.
        """
        from nt_analyzer.symbol_loader import load_symbols as _load_symbols
        try:
            ib = image_base or self.pe_info.get('image_base', 0)
            symbols, meta = _load_symbols(symbol_path, image_base=ib,
                                          pe_path=self.pe_path)
            self._symbols = symbols
            self._symbol_meta = meta
            self._symbol_source = symbol_path
            return {
                'success': True,
                'total_symbols': len(symbols),
                'format': meta.get('format', 'unknown'),
                'source': os.path.basename(symbol_path),
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def load_symbols_from_exports(self) -> Dict:
        """
        Build a symbol table from the loaded binary's own export table.
        Useful when no external symbol file is available.
        """
        if not self.shift_engine or not self.ref_db:
            return {'success': False, 'error': 'No binary loaded'}

        ib = self.pe_info.get('image_base', 0)
        symbols = {}

        # Extract from references that have symbol names
        for ref in self.ref_db.get_all():
            if ref.symbol_name:
                va = ref.target_rva + ib
                if va not in symbols:
                    symbols[va] = ref.symbol_name

        # For PE: also read exports directly from pefile
        if self.binary_format == 'pe' and isinstance(self.shift_engine, ShiftEngine):
            pe = self.shift_engine.pe
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.forwarder is not None:
                        continue
                    name = sym.name.decode('ascii', errors='replace') if sym.name else f"ord_{sym.ordinal}"
                    va = sym.address + ib
                    symbols[va] = name

        self._symbols = symbols
        self._symbol_source = self.pe_path
        return {
            'success': True,
            'total_symbols': len(symbols),
            'format': 'exports',
            'source': os.path.basename(self.pe_path or ''),
        }

    def get_symbols(self) -> Dict[int, str]:
        """Return the currently loaded symbol table {VA: name}."""
        return self._symbols

    def get_symbol_at_rva(self, rva: int) -> Optional[str]:
        """Look up a symbol by RVA (converts to VA internally)."""
        ib = self.pe_info.get('image_base', 0)
        va = rva + ib
        return self._symbols.get(va)

    def get_symbol_at_offset(self, offset: int) -> Optional[str]:
        """Look up a symbol by file offset."""
        if not self.shift_engine:
            return None
        rva = self.shift_engine._offset_to_rva(offset)
        if rva is None:
            return None
        return self.get_symbol_at_rva(rva)

    def get_nearest_symbol(self, rva: int) -> Optional[Tuple[str, int]]:
        """Find the nearest symbol at or before the given RVA.
        Returns (name, offset_from_symbol) or None."""
        if not self._symbols:
            return None
        ib = self.pe_info.get('image_base', 0)
        target_va = rva + ib
        best_va = None
        for va in self._symbols:
            if va <= target_va:
                if best_va is None or va > best_va:
                    best_va = va
        if best_va is not None:
            return (self._symbols[best_va], target_va - best_va)
        return None

    def export_symbol_map(self, output_path: str = None) -> Dict:
        """
        Export the current symbol table as a Microsoft .map file.
        If output_path is None, derives path from the binary filename.
        """
        if not self._symbols:
            return {'success': False, 'error': 'No symbols loaded'}

        if output_path is None:
            base = os.path.splitext(self.pe_path or 'output')[0]
            output_path = base + '_ubrt.map'

        ib = self.pe_info.get('image_base', 0)
        sections = self.pe_info.get('sections', [])
        content = SymbolUpdater.generate_map_file(
            self._symbols, ib, sections, output_path)
        return {
            'success': True,
            'path': output_path,
            'total_symbols': len(self._symbols),
            'size': len(content),
        }

    def get_symbol_stats(self) -> Dict:
        """Get statistics about loaded symbols."""
        if not self._symbols:
            return {
                'loaded': False,
                'total': 0,
                'source': None,
            }
        ib = self.pe_info.get('image_base', 0)
        sections = self.pe_info.get('sections', [])

        # Count symbols per section
        by_section = {}
        for va in self._symbols:
            rva = va - ib
            sec_name = '(header)'
            for sec in sections:
                s_rva = sec.get('rva', 0)
                s_sz = sec.get('vsize', 0)
                if s_rva <= rva < s_rva + s_sz:
                    sec_name = sec.get('name', '?')
                    break
            by_section[sec_name] = by_section.get(sec_name, 0) + 1

        return {
            'loaded': True,
            'total': len(self._symbols),
            'source': self._symbol_source,
            'format': self._symbol_meta.get('format', 'unknown'),
            'by_section': by_section,
        }
