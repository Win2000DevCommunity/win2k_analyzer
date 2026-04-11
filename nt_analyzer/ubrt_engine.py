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


class RefSource(enum.Enum):
    STATIC_DISASM = "static_disasm"
    PE_RELOC      = "pe_reloc"
    PE_TABLE      = "pe_table"
    HEURISTIC     = "heuristic"
    DYNAMIC_TRACE = "dynamic_trace"


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
    """Indexed database of all address references in a binary."""

    def __init__(self):
        self._refs: List[Reference] = []
        self._by_target: Dict[int, List[int]] = defaultdict(list)
        self._by_type: Dict[RefType, List[int]] = defaultdict(list)
        self._by_section: Dict[str, List[int]] = defaultdict(list)

    def add(self, ref: Reference):
        idx = len(self._refs)
        self._refs.append(ref)
        self._by_target[ref.target_rva].append(idx)
        self._by_type[ref.ref_type].append(idx)
        self._by_section[ref.section_name].append(idx)

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
        for i, ref in enumerate(self._refs):
            self._by_target[ref.target_rva].append(i)
            self._by_type[ref.ref_type].append(i)
            self._by_section[ref.section_name].append(i)

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
        """Detect switch/case jump tables: JMP DWORD PTR [reg*4 + table_addr]."""
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

            for insn in md.disasm(code, base_va):
                # Pattern: JMP [reg*4 + disp32] or JMP [reg*4 + reg + disp32]
                if insn.id != cs_x86.X86_INS_JMP or len(insn.operands) != 1:
                    continue
                op = insn.operands[0]
                if op.type != cs_x86.X86_OP_MEM:
                    continue
                # Must have scale == 4 (or 8 for x64) — the index*scale pattern
                if op.mem.scale not in (4, 8):
                    continue
                # The displacement is the table base address
                table_va = op.mem.disp
                if table_va == 0:
                    continue

                if self.is_64 and op.mem.base == cs_x86.X86_REG_RIP:
                    # x64: RIP-relative jump table
                    insn_rva = insn.address - self.image_base
                    table_rva = insn_rva + insn.size + table_va
                else:
                    table_rva = table_va - self.image_base

                if not (0 < table_rva < size_of_image):
                    continue

                # Read entries from the table until they stop pointing to code
                table_foff = self._rva_to_offset(table_rva)
                if table_foff is None:
                    continue

                entry_size = 4  # RVA entries are 32-bit even in x64 PE
                table_sec = self._section_for_rva(table_rva)
                max_entries = 1024  # safety cap

                for idx in range(max_entries):
                    off = table_foff + idx * entry_size
                    if off + entry_size > len(self.data):
                        break
                    if self.is_64 and op.mem.base == cs_x86.X86_REG_RIP:
                        # x64 relative jump tables: entries are RVA offsets from table base
                        entry_val = struct.unpack_from('<i', self.data, off)[0]
                        target_rva = table_rva + entry_val
                    else:
                        entry_val = struct.unpack_from('<I', self.data, off)[0]
                        target_rva = entry_val - self.image_base

                    if not self._is_executable_rva(target_rva):
                        break  # end of table

                    refs.append(Reference(
                        file_offset=off,
                        ref_type=RefType.JUMP_TABLE,
                        target_rva=target_rva,
                        ref_rva=table_rva + idx * entry_size,
                        size_bytes=entry_size,
                        is_relative=(self.is_64 and op.mem.base == cs_x86.X86_REG_RIP),
                        insn_size=entry_size,
                        section_name=table_sec,
                        confidence=0.90, source=RefSource.STATIC_DISASM,
                    ))
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


# ─── Shift Engine ─────────────────────────────────────────────────────────

class ShiftEngine:
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

        # Phase 4: Update PE headers
        self._update_pe_headers(rva, N)

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

        # Save undo data
        deleted = bytes(self.buffer[foff:foff + count])
        self._undo_stack.append((ShiftOp.DELETE, foff, count, deleted))

        # Phase 1: Remove bytes
        del self.buffer[foff:foff + count]

        # Phase 2: Update sections
        sections_adjusted = self._update_sections_after_insert(rva, -count, foff)

        # Phase 3: Recalculate refs (negative delta)
        refs_updated, warnings = self._recalculate_refs(rva, -count)

        # Phase 4: Update PE headers
        self._update_pe_headers(rva, -count)

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

    # Mapping from short conditional branch opcodes (7x) to near conditional (0F 8x)
    _SHORT_TO_NEAR_JCC = {
        0x70: (0x0F, 0x80), 0x71: (0x0F, 0x81), 0x72: (0x0F, 0x82), 0x73: (0x0F, 0x83),
        0x74: (0x0F, 0x84), 0x75: (0x0F, 0x85), 0x76: (0x0F, 0x86), 0x77: (0x0F, 0x87),
        0x78: (0x0F, 0x88), 0x79: (0x0F, 0x89), 0x7A: (0x0F, 0x8A), 0x7B: (0x0F, 0x8B),
        0x7C: (0x0F, 0x8C), 0x7D: (0x0F, 0x8D), 0x7E: (0x0F, 0x8E), 0x7F: (0x0F, 0x8F),
    }

    def _recalculate_refs(self, insert_rva: int, delta: int) -> Tuple[int, List[str]]:
        """Recalculate all references after a shift at insert_rva by delta bytes."""
        updated = 0
        warnings = []
        relaxations = []  # (ref, new_foff, new_ref_rva, new_target_rva) for deferred relaxation

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
                    # Check for short branch overflow
                    if ref.size_bytes == 1:
                        if new_val < -128 or new_val > 127:
                            # Queue for relaxation instead of skipping
                            relaxations.append((ref, new_foff, new_ref_rva, new_target_rva))
                            # Still update the record positions
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
                if target_moved:
                    new_abs = new_target_rva + self.image_base
                    if ref.size_bytes == 4:
                        self._write_int(new_foff, new_abs & 0xFFFFFFFF, 4)
                    elif ref.size_bytes == 8:
                        self._write_int(new_foff, new_abs, 8)
                    updated += 1

            # Update the reference record
            ref.ref_rva = new_ref_rva
            ref.target_rva = new_target_rva
            ref.file_offset = new_foff

        self.ref_db.rebuild_indices()

        # ── Short Branch Relaxation Pass ──
        # Upgrade overflowed rel8 branches to rel32 (EB→E9, 7x→0F 8x)
        # Each relaxation inserts 3-4 bytes, which may cascade. We process
        # from highest RVA to lowest to minimize cascading re-adjustments.
        if relaxations:
            relaxations.sort(key=lambda x: x[2], reverse=True)  # highest RVA first
            for ref, foff, ref_rva, target_rva in relaxations:
                result = self._relax_short_branch(ref)
                if result:
                    updated += 1
                    warnings.append(
                        f"RELAXED short→near @0x{ref_rva:X}: "
                        f"{ref.ref_type.value} (auto-upgraded)"
                    )
                else:
                    warnings.append(
                        f"SHORT BRANCH OVERFLOW @0x{ref_rva:X}: "
                        f"could not auto-relax (type={ref.ref_type.value})"
                    )

        return updated, warnings

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
            # New displacement: target_rva - (ref_rva + 5)
            new_disp = ref.target_rva - (ref.ref_rva + new_insn_size)
            new_bytes = bytes([0xE9]) + struct.pack('<i', new_disp)

            # Replace the 2-byte instruction with 5-byte version
            self.buffer[insn_foff:insn_foff + 2] = new_bytes

            # Update ref record
            ref.ref_type = RefType.REL_JUMP_NEAR
            ref.size_bytes = 4
            ref.insn_size = 5
            ref.file_offset = insn_foff + 1  # disp starts at byte 1

            # Now shift everything after by +3 bytes
            self._cascade_shift(ref.ref_rva + 2, expand)  # old end was ref_rva+2
            return True

        elif ref.ref_type == RefType.REL_COND_SHORT and opcode in self._SHORT_TO_NEAR_JCC:
            # 7x rel8 → 0F 8x rel32 (expand by 4 bytes)
            expand = 4
            new_insn_size = 6
            near_op = self._SHORT_TO_NEAR_JCC[opcode]
            new_disp = ref.target_rva - (ref.ref_rva + new_insn_size)
            new_bytes = bytes([near_op[0], near_op[1]]) + struct.pack('<i', new_disp)

            # Replace the 2-byte instruction with 6-byte version
            self.buffer[insn_foff:insn_foff + 2] = new_bytes

            # Update ref record
            ref.ref_type = RefType.REL_COND_NEAR
            ref.size_bytes = 4
            ref.insn_size = 6
            ref.file_offset = insn_foff + 2  # disp starts at byte 2

            # Shift everything after by +4 bytes
            self._cascade_shift(ref.ref_rva + 2, expand)
            return True

        return False

    def _cascade_shift(self, from_rva: int, expand: int):
        """
        After a branch relaxation expands an instruction, shift all refs
        that are after from_rva by expand bytes and update their encoded values.
        This is a mini version of _recalculate_refs for the cascade.
        """
        # Find the file offset for from_rva to update section headers
        foff = self._rva_to_offset(from_rva)
        if foff is None:
            foff = 0  # fallback

        for ref in self.ref_db.get_all():
            if ref.ref_rva >= from_rva:
                ref.ref_rva += expand
                ref.file_offset += expand
            if ref.target_rva >= from_rva:
                ref.target_rva += expand

            # Re-encode the reference with updated positions
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
                # Absolute refs whose target moved
                if ref.target_rva - expand >= from_rva:  # target was shifted
                    new_abs = ref.target_rva + self.image_base
                    if ref.size_bytes == 4:
                        self._write_int(ref.file_offset, new_abs & 0xFFFFFFFF, 4)
                    elif ref.size_bytes == 8:
                        self._write_int(ref.file_offset, new_abs, 8)

        self.ref_db.rebuild_indices()

        # Update section headers and PE headers for the expansion
        self._update_sections_after_insert(from_rva, expand, foff)
        self._update_pe_headers(from_rva, expand)

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
        """Parse QEMU execution trace log to extract basic block coverage."""
        if not self.trace_log or not os.path.isfile(self.trace_log):
            return {'success': False, 'error': 'No trace log available'}

        self.coverage.clear()
        block_count = 0
        insn_count = 0

        try:
            with open(self.trace_log, 'r', errors='replace') as f:
                current_block_start = None
                current_block_end = None
                for line in f:
                    line = line.strip()
                    # QEMU trace format: "Trace 0: 0x00401000 [size=23]"
                    if line.startswith('Trace') and '0x' in line:
                        parts = line.split()
                        for p in parts:
                            if p.startswith('0x'):
                                try:
                                    addr = int(p.rstrip(':,[]'), 16)
                                    rva = addr - image_base if image_base else addr
                                    if rva in self.coverage:
                                        self.coverage[rva].hit_count += 1
                                    else:
                                        self.coverage[rva] = TraceBlock(
                                            start_va=addr, end_va=addr)
                                    block_count += 1
                                except ValueError:
                                    pass
                                break
                    # IN_ASM lines: "0x00401000:  push   %ebp"
                    elif line and line[0] == '0' and 'x' in line[:4]:
                        try:
                            addr_str = line.split(':')[0].strip()
                            addr = int(addr_str, 16)
                            insn_count += 1
                        except (ValueError, IndexError):
                            pass

            return {
                'success': True,
                'blocks': block_count,
                'unique_blocks': len(self.coverage),
                'instructions': insn_count,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_coverage_refs(self, image_base: int = 0) -> List[Reference]:
        """Convert coverage data into Reference entries for the database."""
        refs = []
        for rva, block in self.coverage.items():
            for target in block.branch_targets:
                refs.append(Reference(
                    file_offset=0,
                    ref_type=RefType.DATA_POINTER,
                    target_rva=target - image_base if image_base else target,
                    ref_rva=rva,
                    size_bytes=4, is_relative=False, insn_size=4,
                    section_name="dynamic",
                    confidence=0.95, source=RefSource.DYNAMIC_TRACE,
                ))
        return refs

    def get_gdb_port(self) -> int:
        return self._gdb_port


# ─── UBRT Engine (Main Coordinator) ──────────────────────────────────────

class UBRTEngine:
    """
    Main engine coordinating all UBRT operations.

    Workflow:
    1. Load PE binary
    2. Find all references (static analysis)
    3. [Optional] Run dynamic trace via QEMU
    4. Apply modifications (insert/delete/patch)
    5. Save modified binary
    """

    def __init__(self):
        self.pe_path: Optional[str] = None
        self.ref_db: Optional[ReferenceDatabase] = None
        self.shift_engine: Optional[ShiftEngine] = None
        self.qemu: Optional[QEMUTracer] = None
        self.pe_info: Dict = {}
        self._history: List[ShiftResult] = []

    def load(self, pe_path: str, callback=None) -> Dict:
        """Load a PE binary and analyze all references."""
        if not os.path.isfile(pe_path):
            return {'success': False, 'error': f'File not found: {pe_path}'}
        self.pe_path = pe_path
        try:
            finder = PEReferenceFinder(pe_path)
            self.ref_db = finder.find_all(callback=callback)
            self.shift_engine = ShiftEngine(pe_path, self.ref_db)
            self.pe_info = {
                'path': pe_path,
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
        self._history.append(result)
        return result

    def delete(self, rva: int, count: int) -> ShiftResult:
        if not self.shift_engine:
            raise RuntimeError("No binary loaded")
        result = self.shift_engine.delete_bytes(rva, count)
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
            new_refs = self.qemu.get_coverage_refs(image_base=ib)
            added = 0
            for ref in new_refs:
                self.ref_db.add(ref)
                added += 1
            result['refs_added'] = added
            result['total_refs'] = self.ref_db.count
        return result
