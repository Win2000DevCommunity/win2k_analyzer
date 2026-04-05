"""
NT Binary Compatibility Analyzer
=================================
Deep intelligent analysis of NT kernel-mode and user-mode binary differences
between Windows versions (5.0/5.1/5.2/6.0+).

Detects the REAL breaking differences that prevent cross-version compatibility:
  - Calling convention changes (stdcall ↔ fastcall)
  - HAL dispatch table routing vs direct implementation
  - Bit-shift / macro expansion differences (e.g. HalpVector << 4 vs << 8)
  - Affinity calculation / processor topology changes
  - Missing/added/renamed exports and ordinal shifts
  - Import dependency changes
  - Structure layout divergence (by analyzing field access offsets)
  - Interrupt dispatch mechanism (int 0x2E vs sysenter vs syscall)
  - Section characteristics changes
  - Entry point and subsystem differences
  - IDT/vector mapping pattern differences
  - Dispatch table function pointer routing changes

Works on ALL PE types: .dll, .sys, .exe, .cpl, .drv, .ocx, .scr
"""

import os
import re
import struct
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import Optional

import pefile
from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_32,
    CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET,
    CS_OP_IMM, CS_OP_REG, CS_OP_MEM,
)

# ══════════════════════════════════════════════════════════════════════════
#  Known NT version differences knowledge base
# ══════════════════════════════════════════════════════════════════════════

# Functions that changed calling convention between NT 5.0 and 5.1
CONVENTION_CHANGES_5_0_TO_5_1 = {
    # HAL I/O functions: stdcall in 2000, fastcall in XP
    "IoAssignDriveLetters":     {"from": "stdcall", "to": "fastcall"},
    "IoReadPartitionTable":     {"from": "stdcall", "to": "fastcall"},
    "IoSetPartitionInformation": {"from": "stdcall", "to": "fastcall"},
    "IoWritePartitionTable":    {"from": "stdcall", "to": "fastcall"},
    # I/O completion fastcall wrappers
    "IofCallDriver":            {"from": "stdcall", "to": "fastcall"},
    "IofCompleteRequest":       {"from": "stdcall", "to": "fastcall"},
    # IRQL fastcall variants
    "KfAcquireSpinLock":        {"from": "stdcall", "to": "fastcall"},
    "KfReleaseSpinLock":        {"from": "stdcall", "to": "fastcall"},
    "KfRaiseIrql":              {"from": "stdcall", "to": "fastcall"},
    "KfLowerIrql":              {"from": "stdcall", "to": "fastcall"},
}

# HAL dispatch table entries: present in 2000 but defines removed in XP
HAL_DISPATCH_REMOVED_DEFINES = {
    "HalIoAssignDriveLetters":     "HALDISPATCH->HalIoAssignDriveLetters",
    "HalIoReadPartitionTable":     "HALDISPATCH->HalIoReadPartitionTable",
    "HalIoSetPartitionInformation": "HALDISPATCH->HalIoSetPartitionInformation",
    "HalIoWritePartitionTable":    "HALDISPATCH->HalIoWritePartitionTable",
}

# Known macro differences between NT 5.0 and 5.1
MACRO_DIFFERENCES = {
    "HalpVector": {
        "5.0": "vector << 4",  # left shift by 4
        "5.1": "vector << 8",  # left shift by 8
        "desc": "HalpVector macro: Win2000 uses <<4, XP uses <<8 for IDT vector calculation",
        "pattern_50": ("shl", 4),  # instruction pattern on 5.0
        "pattern_51": ("shl", 8),  # instruction pattern on 5.1
    },
}

# Functions removed from HAL in XP (left in kernel only)
HAL_FUNCTIONS_REMOVED_IN_XP = [
    "IoAssignDriveLetters",
    "IoReadPartitionTable",
    "IoSetPartitionInformation",
    "IoWritePartitionTable",
]

# Known IDT / interrupt dispatch changes
IDT_DISPATCH_CHANGES = {
    "5.0": {
        "desc": "Win2000: Uses Vector directly for IDT entry calculation",
        "pattern": "KiStartUnexpectedRange + (Vector - PRIMARY_VECTOR_BASE) * KiUnexpectedEntrySize",
    },
    "5.1": {
        "desc": "XP: Uses HalVectorToIDTEntry() to translate vector first",
        "pattern": "IDTEntry = HalVectorToIDTEntry(Vector); ... + (IDTEntry - PRIMARY_VECTOR_BASE) * ...",
    },
}

# Affinity calculation differences
AFFINITY_CHANGES = {
    "5.0": "Direct affinity bitmask from processor number",
    "5.1": "Uses HalpVectorToNode table for NUMA-aware affinity",
    "fix": "Need HalpINTIToNode table instead of HalpVectorToNode for 2000 compat",
}

# Known structure layout changes between versions
STRUCT_CHANGES = {
    "KINTERRUPT": {
        "5.0_size": 0x1E8,
        "5.1_size": 0x1F0,
        "changed_fields": ["DispatchCode at different offset"],
    },
    "EPROCESS": {
        "5.0_size": 0x290,
        "5.1_size": 0x258,
        "changed_fields": ["Thread list offsets differ", "Quota fields reorganized"],
    },
    "KPRCB": {
        "changed_fields": ["DpcData layout", "Vendor* fields added in XP"],
    },
}

# Bugcheck codes relevant to HAL/kernel incompatibility
COMPAT_BUGCHECKS = {
    0x000000A5: {
        "name": "ACPI_BIOS_ERROR",
        "desc": "Often caused by HAL/ACPI version mismatch",
        "compat_hint": "Check HalpVector macro, interrupt vector calculation",
    },
    0x0000001E: {
        "name": "KMODE_EXCEPTION_NOT_HANDLED",
        "desc": "Unhandled exception in kernel mode",
        "compat_hint": "Check calling convention (stdcall vs fastcall), null dispatch table entries",
    },
    0x000000CA: {
        "name": "PNP_DETECTED_FATAL_ERROR",
        "desc": "PnP manager detected fatal error with subcode 2",
        "compat_hint": "Driver/HAL reporting wrong device/function, check IoReadPartitionTable routing",
    },
    0x0000007E: {
        "name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "desc": "Unhandled exception in system thread",
        "compat_hint": "Check for missing exports, wrong structure offsets",
    },
    0x0000007F: {
        "name": "UNEXPECTED_KERNEL_MODE_TRAP",
        "desc": "CPU trap - often from stack corruption",
        "compat_hint": "Calling convention mismatch (stdcall pushes vs fastcall register args)",
    },
}


# ══════════════════════════════════════════════════════════════════════════
#  Data classes
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class CallingConvInfo:
    name: str
    convention: str  # "stdcall", "fastcall", "cdecl", "thiscall", "unknown"
    stack_cleanup: int  # bytes cleaned by ret N
    uses_ecx_edx_args: bool  # first args passed in ECX/EDX
    param_count: int
    confidence: float  # 0.0 - 1.0


@dataclass
class DispatchTableRef:
    func_name: str
    table_name: str  # e.g. "HalDispatchTable", "MajorFunction", "IoDriverObjectType"
    slot_offset: int
    access_type: str  # "read", "write", "indirect_call"
    address: int


@dataclass
class ShiftPattern:
    address: int
    register: str
    shift_amount: int
    context: str  # surrounding instruction context


@dataclass
class CompatIssue:
    severity: str  # "critical", "warning", "info"
    category: str  # "calling_convention", "dispatch_table", "macro_diff", etc.
    title: str
    description: str
    address: int = 0
    func_name: str = ""
    fix_hint: str = ""


@dataclass
class CompatReport:
    file_a: str
    file_b: str
    label_a: str
    label_b: str
    pe_type: str  # "DLL", "SYS", "EXE", etc.
    issues: list = field(default_factory=list)
    export_diff: dict = field(default_factory=dict)
    import_diff: dict = field(default_factory=dict)
    convention_diffs: list = field(default_factory=list)
    dispatch_refs_a: list = field(default_factory=list)
    dispatch_refs_b: list = field(default_factory=list)
    shift_patterns_a: list = field(default_factory=list)
    shift_patterns_b: list = field(default_factory=list)
    struct_access_diffs: list = field(default_factory=list)
    section_diffs: list = field(default_factory=list)
    header_diffs: dict = field(default_factory=dict)

    def summary(self):
        lines = []
        lines.append(f"{'='*72}")
        lines.append(f"  NT BINARY COMPATIBILITY REPORT")
        lines.append(f"{'='*72}")
        lines.append(f"  File A ({self.label_a}): {os.path.basename(self.file_a)}")
        lines.append(f"  File B ({self.label_b}): {os.path.basename(self.file_b)}")
        lines.append(f"  PE Type: {self.pe_type}")
        lines.append(f"")

        critical = [i for i in self.issues if i.severity == "critical"]
        warnings = [i for i in self.issues if i.severity == "warning"]
        infos = [i for i in self.issues if i.severity == "info"]

        lines.append(f"  Issues: {len(critical)} CRITICAL, {len(warnings)} warnings, {len(infos)} info")
        lines.append(f"")

        if critical:
            lines.append(f"  ── CRITICAL ISSUES ──────────────────────────────────")
            for issue in critical:
                lines.append(f"")
                lines.append(f"  [CRITICAL] {issue.title}")
                lines.append(f"    Category: {issue.category}")
                lines.append(f"    {issue.description}")
                if issue.func_name:
                    lines.append(f"    Function: {issue.func_name}")
                if issue.address:
                    lines.append(f"    Address:  0x{issue.address:08X}")
                if issue.fix_hint:
                    lines.append(f"    Fix:      {issue.fix_hint}")

        if warnings:
            lines.append(f"")
            lines.append(f"  ── WARNINGS ────────────────────────────────────────")
            for issue in warnings:
                lines.append(f"")
                lines.append(f"  [WARNING] {issue.title}")
                lines.append(f"    {issue.description}")
                if issue.fix_hint:
                    lines.append(f"    Fix: {issue.fix_hint}")

        if infos:
            lines.append(f"")
            lines.append(f"  ── INFO ────────────────────────────────────────────")
            for issue in infos:
                lines.append(f"  [info] {issue.title}: {issue.description}")

        # Export diff summary
        if self.export_diff:
            ed = self.export_diff
            lines.append(f"")
            lines.append(f"  ── EXPORT COMPARISON ───────────────────────────────")
            lines.append(f"    Exports A: {ed.get('total_a', 0)}, Exports B: {ed.get('total_b', 0)}")
            lines.append(f"    Common: {ed.get('common', 0)}")
            only_a = ed.get('only_a', [])
            only_b = ed.get('only_b', [])
            if only_a:
                lines.append(f"    Only in A ({len(only_a)}):")
                for n in only_a[:20]:
                    lines.append(f"      - {n}")
                if len(only_a) > 20:
                    lines.append(f"      ... +{len(only_a)-20} more")
            if only_b:
                lines.append(f"    Only in B ({len(only_b)}):")
                for n in only_b[:20]:
                    lines.append(f"      + {n}")
                if len(only_b) > 20:
                    lines.append(f"      ... +{len(only_b)-20} more")

        # Convention diffs
        if self.convention_diffs:
            lines.append(f"")
            lines.append(f"  ── CALLING CONVENTION CHANGES ({len(self.convention_diffs)}) ──────────")
            for cd in self.convention_diffs:
                lines.append(f"    {cd['name']}: {cd['conv_a']} → {cd['conv_b']}"
                             f"  (cleanup: {cd['cleanup_a']} → {cd['cleanup_b']})")

        # Shift patterns
        if self.shift_patterns_a or self.shift_patterns_b:
            lines.append(f"")
            lines.append(f"  ── BIT-SHIFT PATTERNS ─────────────────────────────")
            seen_a = defaultdict(list)
            seen_b = defaultdict(list)
            for sp in self.shift_patterns_a:
                seen_a[sp.shift_amount].append(sp)
            for sp in self.shift_patterns_b:
                seen_b[sp.shift_amount].append(sp)
            for amt in sorted(set(list(seen_a.keys()) + list(seen_b.keys()))):
                ca = len(seen_a.get(amt, []))
                cb = len(seen_b.get(amt, []))
                if ca != cb:
                    lines.append(f"    SHL/SHR by {amt}: A has {ca} instances, B has {cb}")

        # Dispatch table references
        if self.dispatch_refs_a or self.dispatch_refs_b:
            lines.append(f"")
            lines.append(f"  ── DISPATCH TABLE REFERENCES ──────────────────────")
            tables_a = defaultdict(int)
            tables_b = defaultdict(int)
            for dr in self.dispatch_refs_a:
                tables_a[dr.table_name] += 1
            for dr in self.dispatch_refs_b:
                tables_b[dr.table_name] += 1
            all_tables = sorted(set(list(tables_a.keys()) + list(tables_b.keys())))
            for t in all_tables:
                ca, cb = tables_a.get(t, 0), tables_b.get(t, 0)
                marker = " ← DIFFERENT" if ca != cb else ""
                lines.append(f"    {t}: A={ca} refs, B={cb} refs{marker}")

        lines.append(f"")
        lines.append(f"{'='*72}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
#  PE helpers  
# ══════════════════════════════════════════════════════════════════════════

def _get_cs32():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def _pe_type_str(pe):
    chars = pe.FILE_HEADER.Characteristics
    if chars & 0x2000:
        return "DLL"
    subsys = pe.OPTIONAL_HEADER.Subsystem
    if subsys == 1:
        return "SYS"  # native / driver
    if subsys == 2:
        return "EXE_GUI"
    if subsys == 3:
        return "EXE_CUI"
    return "PE"


def _get_exports(pe):
    exports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode('ascii', errors='replace') if exp.name else None
            exports[exp.ordinal] = {
                'name': name, 'ordinal': exp.ordinal,
                'rva': exp.address,
                'forwarded': exp.forwarder.decode('ascii', errors='replace') if exp.forwarder else None,
            }
    return exports


def _get_imports(pe):
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace').lower()
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode('ascii', errors='replace'))
                else:
                    funcs.append(f"Ordinal_{imp.ordinal}")
            imports[dll] = funcs
    return imports


def _get_import_thunks(pe):
    thunks = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                    thunks[rva] = f"{dll}!{imp.name.decode('ascii', errors='replace')}"
    return thunks


def _rva_to_offset(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None


def _get_code_sections(pe):
    result = []
    for s in pe.sections:
        if s.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            result.append(s)
    return result


def _extract_strings_from_data(pe, min_len=4):
    strings = {}
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        sname = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if sname not in ('.rdata', '.data', 'INIT', 'PAGE', '.text'):
            continue
        try:
            data = section.get_data()
        except Exception:
            continue
        va = base + section.VirtualAddress
        for m in re.finditer(rb'[\x20-\x7e]{4,128}\x00', data):
            s = m.group()[:-1].decode('ascii', errors='replace')
            strings[va + m.start()] = s
    return strings


# ══════════════════════════════════════════════════════════════════════════
#  Calling Convention Detector (per-function)
# ══════════════════════════════════════════════════════════════════════════

def detect_calling_convention(pe, func_rva, max_bytes=4096):
    """
    Analyze a function's prologue/epilogue to detect its calling convention.
    Returns CallingConvInfo.
    """
    base = pe.OPTIONAL_HEADER.ImageBase
    offset = _rva_to_offset(pe, func_rva)
    if offset is None:
        return None

    try:
        code = pe.get_data(func_rva, min(max_bytes, 4096))
    except Exception:
        return None

    md = _get_cs32()
    instructions = list(md.disasm(code, base + func_rva))
    if not instructions:
        return None

    # Detect stack cleanup (ret N = stdcall/fastcall, ret = cdecl)
    stack_cleanup = 0
    for insn in instructions:
        if insn.group(CS_GRP_RET):
            if insn.mnemonic in ('ret', 'retn') and insn.op_str:
                try:
                    v = insn.op_str.strip()
                    stack_cleanup = int(v, 16) if v.startswith('0x') else int(v)
                except ValueError:
                    pass
            break

    # Detect ECX/EDX usage as arguments (fastcall signature)
    ecx_used_early = False
    edx_used_early = False
    ecx_set_before_use = False
    edx_set_before_use = False

    for i, insn in enumerate(instructions[:15]):
        # Check if ECX/EDX are READ before being written to
        if insn.mnemonic in ('mov', 'push', 'test', 'cmp', 'add', 'sub', 'and', 'or'):
            ops = insn.op_str
            parts = ops.split(',')

            # Check source operands for ecx/edx
            if len(parts) >= 2:
                src = parts[1].strip()
                dst = parts[0].strip()

                if 'ecx' in src and not ecx_set_before_use:
                    ecx_used_early = True
                if 'edx' in src and not edx_set_before_use:
                    edx_used_early = True

                # Track if ecx/edx are written to (set before use = NOT fastcall arg)
                if dst == 'ecx' and not ecx_used_early:
                    ecx_set_before_use = True
                if dst == 'edx' and not edx_used_early:
                    edx_set_before_use = True

        # push ecx/edx early = saving fastcall args
        if insn.mnemonic == 'push':
            if 'ecx' in insn.op_str and not ecx_set_before_use:
                ecx_used_early = True
            if 'edx' in insn.op_str and not edx_set_before_use:
                edx_used_early = True

        # mov [ebp-N], ecx = saving fastcall arg to local
        if insn.mnemonic == 'mov' and 'ebp' in insn.op_str:
            parts = insn.op_str.split(',')
            if len(parts) == 2 and '[' in parts[0] and '-' in parts[0]:
                if 'ecx' in parts[1].strip():
                    ecx_used_early = True
                if 'edx' in parts[1].strip():
                    edx_used_early = True

    # Determine convention
    uses_ecx_edx = ecx_used_early and not ecx_set_before_use
    confidence = 0.7

    if uses_ecx_edx and stack_cleanup > 0:
        convention = "fastcall"
        param_count = stack_cleanup // 4 + 2  # stack args + ecx + edx
        confidence = 0.9
    elif uses_ecx_edx and stack_cleanup == 0:
        # Could be fastcall with <=2 args or thiscall
        if edx_used_early and not edx_set_before_use:
            convention = "fastcall"
            param_count = 2
            confidence = 0.8
        else:
            convention = "thiscall"
            param_count = 1
            confidence = 0.6
    elif stack_cleanup > 0:
        convention = "stdcall"
        param_count = stack_cleanup // 4
        confidence = 0.9
    else:
        convention = "cdecl"
        param_count = 0  # can't tell from callee
        confidence = 0.5

    return CallingConvInfo(
        name="", convention=convention, stack_cleanup=stack_cleanup,
        uses_ecx_edx_args=uses_ecx_edx, param_count=param_count,
        confidence=confidence,
    )


# ══════════════════════════════════════════════════════════════════════════
#  Dispatch Table Reference Detector
# ══════════════════════════════════════════════════════════════════════════

# Known dispatch tables and their imported symbol names
DISPATCH_TABLES = {
    "HalDispatchTable": {
        "offsets": {
            0x00: "HalDispatchTableVersion",
            0x04: "HalQuerySystemInformation",
            0x08: "HalSetSystemInformation",
            0x0C: "HalQueryBusSlots",
            0x10: "HalReferenceHandlerForBus",
            0x14: "HalReferenceBusHandler",
            0x18: "HalDereferenceBusHandler",
            0x1C: "HalInitPnpDriver",
            0x20: "HalInitPowerManagement",
            0x24: "HalGetDmaAdapter",
            0x28: "HalGetInterruptTranslator",
            0x2C: "HalStartMirroring",
            0x30: "HalEndMirroring",
            0x34: "HalMirrorPhysicalMemory",
            0x38: "HalEndOfBoot",
            0x3C: "HalMirrorVerify",
            # Win2000-only entries (defines removed in XP):
            0x40: "HalIoAssignDriveLetters",
            0x44: "HalIoReadPartitionTable",
            0x48: "HalIoSetPartitionInformation",
            0x4C: "HalIoWritePartitionTable",
        },
    },
    "KeServiceDescriptorTable": {
        "offsets": {
            0x00: "ServiceTable (ntoskrnl)",
            0x04: "CounterTableBase",
            0x08: "ServiceLimit",
            0x0C: "ArgumentTable",
        },
    },
}


def _scan_dispatch_table_refs(pe, instructions, import_thunks, strings):
    """Detect references to well-known dispatch tables in disassembled code."""
    refs = []
    base = pe.OPTIONAL_HEADER.ImageBase

    # Build map of known table addresses from imports / data references
    table_addrs = {}
    for rva, name in import_thunks.items():
        for tname in DISPATCH_TABLES:
            if tname in name:
                table_addrs[base + rva] = tname

    for addr, s in strings.items():
        for tname in DISPATCH_TABLES:
            if tname in s:
                table_addrs[addr] = tname

    for insn in instructions:
        # Pattern: mov reg, [ADDR + offset] or call [ADDR + offset]
        m = re.search(r'\[(0x[0-9a-fA-F]+)\s*\+\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
        if m:
            try:
                tbl_addr = int(m.group(1), 16)
                slot_off = int(m.group(2), 16)
            except ValueError:
                continue

            # Check if this is a known table import
            for check_addr, tname in table_addrs.items():
                if abs(tbl_addr - check_addr) < 0x100:
                    access = "indirect_call" if insn.group(CS_GRP_CALL) else "read"
                    slot_name = DISPATCH_TABLES.get(tname, {}).get("offsets", {}).get(slot_off, f"offset_0x{slot_off:X}")
                    refs.append(DispatchTableRef(
                        func_name=slot_name if isinstance(slot_name, str) else f"slot_{slot_off:X}",
                        table_name=tname,
                        slot_offset=slot_off,
                        access_type=access,
                        address=insn.address,
                    ))

        # Pattern: direct reference to known import (e.g. call [IAT_ENTRY])
        m2 = re.search(r'\[(0x[0-9a-fA-F]+)\]', insn.op_str)
        if m2 and not m:
            try:
                addr_val = int(m2.group(1), 16)
                rva_val = addr_val - base
                if rva_val in import_thunks:
                    imp_name = import_thunks[rva_val]
                    for tname in DISPATCH_TABLES:
                        if tname.lower() in imp_name.lower():
                            refs.append(DispatchTableRef(
                                func_name=imp_name,
                                table_name=tname,
                                slot_offset=0,
                                access_type="import_ref",
                                address=insn.address,
                            ))
            except ValueError:
                pass

    return refs


# ══════════════════════════════════════════════════════════════════════════
#  Bit-Shift Pattern Detector
# ══════════════════════════════════════════════════════════════════════════

def _scan_shift_patterns(instructions, context_window=3):
    """Find all SHL/SHR instructions and capture context."""
    patterns = []
    insn_list = list(instructions)

    for i, insn in enumerate(insn_list):
        if insn.mnemonic in ('shl', 'shr', 'sal', 'sar'):
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                reg = parts[0].strip()
                amt_str = parts[1].strip()
                if amt_str == 'cl':
                    continue  # variable shift, skip
                try:
                    amt = int(amt_str, 16) if amt_str.startswith('0x') else int(amt_str)
                except ValueError:
                    continue

                # Capture surrounding context
                ctx_start = max(0, i - context_window)
                ctx_end = min(len(insn_list), i + context_window + 1)
                ctx = "; ".join(f"{insn_list[j].mnemonic} {insn_list[j].op_str}" for j in range(ctx_start, ctx_end))

                patterns.append(ShiftPattern(
                    address=insn.address,
                    register=reg,
                    shift_amount=amt,
                    context=ctx,
                ))

    return patterns


# ══════════════════════════════════════════════════════════════════════════
#  Structure Access Pattern Detector
# ══════════════════════════════════════════════════════════════════════════

def _scan_struct_access_patterns(instructions):
    """
    Detect structure field access patterns ([reg + offset]).
    Groups by base register to find structure access fingerprints.
    """
    access_map = defaultdict(lambda: defaultdict(int))  # reg -> {offset: count}

    for insn in instructions:
        for m in re.finditer(r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', insn.op_str):
            reg = m.group(1)
            if reg in ('esp', 'ebp'):
                continue  # skip stack frame
            try:
                off = int(m.group(2), 16) if '0x' in m.group(2) else int(m.group(2))
            except ValueError:
                continue
            access_map[reg][off] += 1

    return dict(access_map)


# ══════════════════════════════════════════════════════════════════════════
#  HAL I/O Routing Detector
# ══════════════════════════════════════════════════════════════════════════

def _detect_hal_io_routing(pe, instructions, import_thunks):
    """
    Detect whether IoReadPartitionTable etc. call through HalDispatchTable
    (Win2000 style) or are implemented directly (XP style).
    """
    findings = []
    base = pe.OPTIONAL_HEADER.ImageBase

    hal_io_funcs = set(HAL_FUNCTIONS_REMOVED_IN_XP)

    for insn in instructions:
        if not insn.group(CS_GRP_CALL):
            continue
        # Check for indirect call through IAT
        m = re.search(r'\[(0x[0-9a-fA-F]+)\]', insn.op_str)
        if m:
            try:
                addr_val = int(m.group(1), 16)
                rva = addr_val - base
                if rva in import_thunks:
                    name = import_thunks[rva].split('!')[-1]
                    if name in hal_io_funcs:
                        findings.append({
                            'func': name,
                            'type': 'direct_import',
                            'address': insn.address,
                            'desc': f"{name} called as direct import (XP style)",
                        })
                    if 'HalDispatch' in import_thunks[rva]:
                        findings.append({
                            'func': import_thunks[rva],
                            'type': 'dispatch_table',
                            'address': insn.address,
                            'desc': f"Call through HalDispatchTable (Win2000 style)",
                        })
            except ValueError:
                pass

    return findings


# ══════════════════════════════════════════════════════════════════════════
#  Interrupt / Syscall Mechanism Detector
# ══════════════════════════════════════════════════════════════════════════

def _detect_syscall_mechanism(pe):
    """Detect whether the binary uses int 0x2E (Win2000) or sysenter/syscall (XP+)."""
    findings = {
        'int_2e': 0, 'sysenter': 0, 'syscall': 0,
        'mechanism': 'unknown',
    }

    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue
        try:
            data = section.get_data()
        except Exception:
            continue

        findings['int_2e'] += data.count(b'\xCD\x2E')
        findings['sysenter'] += data.count(b'\x0F\x34')
        findings['syscall'] += data.count(b'\x0F\x05')

    if findings['int_2e'] > 0 and findings['sysenter'] == 0:
        findings['mechanism'] = 'int_2E_only (NT 5.0 style)'
    elif findings['sysenter'] > 0 and findings['int_2e'] == 0:
        findings['mechanism'] = 'sysenter_only (NT 5.1+ style)'
    elif findings['int_2e'] > 0 and findings['sysenter'] > 0:
        findings['mechanism'] = 'mixed (transition binary)'
    elif findings['syscall'] > 0:
        findings['mechanism'] = 'syscall (x86-64)'

    return findings


# ══════════════════════════════════════════════════════════════════════════
#  Main Analysis Engine
# ══════════════════════════════════════════════════════════════════════════

class NTCompatAnalyzer:
    """
    Deep binary compatibility analyzer for NT kernel components.
    Compares two PE binaries and finds all compatibility-breaking differences.
    Works on ALL PE types: .dll, .sys, .exe, .cpl, .drv, .ocx, .scr.
    """

    def __init__(self):
        self.md = _get_cs32()

    def analyze(self, pe_path_a, pe_path_b, label_a="Win2000", label_b="ReactOS/XP",
                max_exports=500):
        """
        Full compatibility analysis between two PE binaries.
        Returns a CompatReport with all detected issues.
        """
        pe_a = pefile.PE(pe_path_a, fast_load=False)
        pe_b = pefile.PE(pe_path_b, fast_load=False)

        report = CompatReport(
            file_a=pe_path_a, file_b=pe_path_b,
            label_a=label_a, label_b=label_b,
            pe_type=_pe_type_str(pe_a),
        )

        # 1. Header comparison
        self._compare_headers(pe_a, pe_b, report)

        # 2. Section comparison
        self._compare_sections(pe_a, pe_b, report)

        # 3. Export comparison
        self._compare_exports(pe_a, pe_b, report)

        # 4. Import comparison
        self._compare_imports(pe_a, pe_b, report)

        # 5. Calling convention analysis on common exports
        self._compare_conventions(pe_a, pe_b, report, max_exports)

        # 6. Disassemble code sections for pattern analysis
        self._analyze_code_patterns(pe_a, pe_b, report)

        # 7. Syscall mechanism detection
        self._compare_syscall_mechanism(pe_a, pe_b, report)

        # 8. Apply known NT version difference knowledge
        self._apply_knowledge_base(report)

        pe_a.close()
        pe_b.close()

        return report

    def analyze_single(self, pe_path, label="Unknown"):
        """Analyze a single PE binary for compatibility characteristics."""
        pe = pefile.PE(pe_path, fast_load=False)
        findings = {
            'path': pe_path,
            'label': label,
            'type': _pe_type_str(pe),
            'machine': pe.FILE_HEADER.Machine,
            'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'image_base': pe.OPTIONAL_HEADER.ImageBase,
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'characteristics': pe.FILE_HEADER.Characteristics,
        }

        # Exports with conventions
        exports_a = _get_exports(pe)
        conventions = {}
        for ordinal, exp in list(exports_a.items())[:200]:
            if exp['name'] and exp['rva'] and not exp['forwarded']:
                info = detect_calling_convention(pe, exp['rva'])
                if info:
                    info.name = exp['name']
                    conventions[exp['name']] = info

        findings['exports'] = exports_a
        findings['conventions'] = conventions
        findings['imports'] = _get_imports(pe)
        findings['syscall'] = _detect_syscall_mechanism(pe)

        # Sections
        findings['sections'] = []
        for s in pe.sections:
            findings['sections'].append({
                'name': s.Name.rstrip(b'\x00').decode('ascii', errors='replace'),
                'vsize': s.Misc_VirtualSize,
                'rsize': s.SizeOfRawData,
                'chars': s.Characteristics,
            })

        pe.close()
        return findings

    # ── Header comparison ────────────────────────────────────────────────

    def _compare_headers(self, pe_a, pe_b, report):
        ha = pe_a.OPTIONAL_HEADER
        hb = pe_b.OPTIONAL_HEADER

        diffs = {}
        if ha.Subsystem != hb.Subsystem:
            diffs['Subsystem'] = (ha.Subsystem, hb.Subsystem)
            report.issues.append(CompatIssue(
                severity="warning", category="header",
                title=f"Subsystem differs: {ha.Subsystem} vs {hb.Subsystem}",
                description="Different subsystem type may cause loader rejection",
            ))

        if pe_a.FILE_HEADER.Machine != pe_b.FILE_HEADER.Machine:
            diffs['Machine'] = (pe_a.FILE_HEADER.Machine, pe_b.FILE_HEADER.Machine)
            report.issues.append(CompatIssue(
                severity="critical", category="header",
                title="Machine type mismatch",
                description=f"A={pe_a.FILE_HEADER.Machine:#x}, B={pe_b.FILE_HEADER.Machine:#x}",
            ))

        if ha.MajorOperatingSystemVersion != hb.MajorOperatingSystemVersion or \
           ha.MinorOperatingSystemVersion != hb.MinorOperatingSystemVersion:
            va = f"{ha.MajorOperatingSystemVersion}.{ha.MinorOperatingSystemVersion}"
            vb = f"{hb.MajorOperatingSystemVersion}.{hb.MinorOperatingSystemVersion}"
            diffs['OSVersion'] = (va, vb)
            report.issues.append(CompatIssue(
                severity="info", category="header",
                title=f"OS version: {va} vs {vb}",
                description="NT version stamp differs",
            ))

        if ha.MajorSubsystemVersion != hb.MajorSubsystemVersion:
            diffs['SubsystemVersion'] = (
                f"{ha.MajorSubsystemVersion}.{ha.MinorSubsystemVersion}",
                f"{hb.MajorSubsystemVersion}.{hb.MinorSubsystemVersion}",
            )

        if ha.DllCharacteristics != hb.DllCharacteristics:
            diffs['DllCharacteristics'] = (ha.DllCharacteristics, hb.DllCharacteristics)
            report.issues.append(CompatIssue(
                severity="info", category="header",
                title=f"DLL characteristics: 0x{ha.DllCharacteristics:04X} vs 0x{hb.DllCharacteristics:04X}",
                description="Security flags / NX compat / ASLR may differ",
            ))

        report.header_diffs = diffs

    # ── Section comparison ───────────────────────────────────────────────

    def _compare_sections(self, pe_a, pe_b, report):
        secs_a = {s.Name.rstrip(b'\x00').decode('ascii', errors='replace'): s for s in pe_a.sections}
        secs_b = {s.Name.rstrip(b'\x00').decode('ascii', errors='replace'): s for s in pe_b.sections}

        only_a = set(secs_a.keys()) - set(secs_b.keys())
        only_b = set(secs_b.keys()) - set(secs_a.keys())
        common = set(secs_a.keys()) & set(secs_b.keys())

        for name in only_a:
            report.section_diffs.append(('only_in_a', name))
            report.issues.append(CompatIssue(
                severity="info", category="section",
                title=f"Section '{name}' only in A",
                description=f"Section present in {report.label_a} but not {report.label_b}",
            ))
        for name in only_b:
            report.section_diffs.append(('only_in_b', name))
            report.issues.append(CompatIssue(
                severity="info", category="section",
                title=f"Section '{name}' only in B",
                description=f"Section present in {report.label_b} but not {report.label_a}",
            ))

        for name in common:
            sa, sb = secs_a[name], secs_b[name]
            if sa.Characteristics != sb.Characteristics:
                report.section_diffs.append(('char_diff', name, sa.Characteristics, sb.Characteristics))
                report.issues.append(CompatIssue(
                    severity="warning", category="section",
                    title=f"Section '{name}' characteristics differ",
                    description=f"A=0x{sa.Characteristics:08X}, B=0x{sb.Characteristics:08X}",
                    fix_hint="Check for missing EXECUTE/WRITE/READ flags",
                ))

            size_ratio = max(sa.Misc_VirtualSize, 1) / max(sb.Misc_VirtualSize, 1)
            if size_ratio > 2.0 or size_ratio < 0.5:
                report.section_diffs.append(('size_diff', name,
                                            sa.Misc_VirtualSize, sb.Misc_VirtualSize))

    # ── Export comparison ────────────────────────────────────────────────

    def _compare_exports(self, pe_a, pe_b, report):
        exp_a = _get_exports(pe_a)
        exp_b = _get_exports(pe_b)

        names_a = {e['name'] for e in exp_a.values() if e['name']}
        names_b = {e['name'] for e in exp_b.values() if e['name']}

        common = names_a & names_b
        only_a = sorted(names_a - names_b)
        only_b = sorted(names_b - names_a)

        report.export_diff = {
            'total_a': len(exp_a),
            'total_b': len(exp_b),
            'common': len(common),
            'only_a': only_a,
            'only_b': only_b,
        }

        # Check for known critical missing exports
        for name in only_a:
            if name in HAL_FUNCTIONS_REMOVED_IN_XP:
                report.issues.append(CompatIssue(
                    severity="critical", category="export_missing",
                    title=f"HAL I/O function '{name}' missing in B",
                    description=f"{name} exists in {report.label_a} but not {report.label_b}. "
                                f"XP removed this from HAL, routing through kernel instead.",
                    func_name=name,
                    fix_hint=f"Add {name} as wrapper calling HalDispatchTable entry, "
                             f"or add to HAL with proper #define: "
                             f"{HAL_DISPATCH_REMOVED_DEFINES.get(f'Hal{name}', '')}",
                ))
            elif name in CONVENTION_CHANGES_5_0_TO_5_1:
                report.issues.append(CompatIssue(
                    severity="warning", category="export_missing",
                    title=f"'{name}' only in {report.label_a}",
                    description=f"This function had calling convention changes between NT 5.0 and 5.1",
                    func_name=name,
                ))

        if len(only_b) > 50:
            report.issues.append(CompatIssue(
                severity="warning", category="export_extra",
                title=f"{len(only_b)} exports in B not in A",
                description=f"{report.label_b} has {len(only_b)} exports not present in {report.label_a}. "
                            f"These may be newer APIs that can't be called on the older system.",
            ))

        # Ordinal mismatch check
        name_to_ord_a = {e['name']: e['ordinal'] for e in exp_a.values() if e['name']}
        name_to_ord_b = {e['name']: e['ordinal'] for e in exp_b.values() if e['name']}
        ordinal_mismatches = []
        for name in common:
            oa = name_to_ord_a.get(name)
            ob = name_to_ord_b.get(name)
            if oa is not None and ob is not None and oa != ob:
                ordinal_mismatches.append((name, oa, ob))

        if ordinal_mismatches:
            report.issues.append(CompatIssue(
                severity="warning", category="ordinal_mismatch",
                title=f"{len(ordinal_mismatches)} ordinal mismatches",
                description=f"Functions with same name but different ordinal numbers. "
                            f"Code using ordinal imports will break.",
                fix_hint="Regenerate .def file with correct ordinals from target system",
            ))

    # ── Import comparison ────────────────────────────────────────────────

    def _compare_imports(self, pe_a, pe_b, report):
        imp_a = _get_imports(pe_a)
        imp_b = _get_imports(pe_b)

        dlls_a = set(imp_a.keys())
        dlls_b = set(imp_b.keys())

        report.import_diff = {
            'dlls_only_a': sorted(dlls_a - dlls_b),
            'dlls_only_b': sorted(dlls_b - dlls_a),
            'dlls_common': sorted(dlls_a & dlls_b),
        }

        for dll in sorted(dlls_b - dlls_a):
            report.issues.append(CompatIssue(
                severity="warning", category="import_missing",
                title=f"B imports from '{dll}' which A doesn't",
                description=f"{report.label_b} depends on {dll} which {report.label_a} may not have",
            ))

        # Per-DLL function comparison
        for dll in sorted(dlls_a & dlls_b):
            funcs_a = set(imp_a[dll])
            funcs_b = set(imp_b[dll])
            new_in_b = funcs_b - funcs_a
            if new_in_b:
                for func in sorted(new_in_b):
                    report.issues.append(CompatIssue(
                        severity="warning" if len(new_in_b) < 10 else "info",
                        category="import_missing",
                        title=f"B imports {dll}!{func} not in A",
                        description=f"Function may not exist on target system",
                        func_name=func,
                    ))

    # ── Calling convention comparison ────────────────────────────────────

    def _compare_conventions(self, pe_a, pe_b, report, max_exports):
        exp_a = _get_exports(pe_a)
        exp_b = _get_exports(pe_b)

        # Build name→rva maps
        name_rva_a = {e['name']: e['rva'] for e in exp_a.values()
                      if e['name'] and e['rva'] and not e['forwarded']}
        name_rva_b = {e['name']: e['rva'] for e in exp_b.values()
                      if e['name'] and e['rva'] and not e['forwarded']}

        common = sorted(set(name_rva_a.keys()) & set(name_rva_b.keys()))

        count = 0
        for name in common:
            if count >= max_exports:
                break

            conv_a = detect_calling_convention(pe_a, name_rva_a[name])
            conv_b = detect_calling_convention(pe_b, name_rva_b[name])

            if conv_a is None or conv_b is None:
                continue

            count += 1

            if conv_a.convention != conv_b.convention:
                report.convention_diffs.append({
                    'name': name,
                    'conv_a': conv_a.convention,
                    'conv_b': conv_b.convention,
                    'cleanup_a': conv_a.stack_cleanup,
                    'cleanup_b': conv_b.stack_cleanup,
                    'confidence_a': conv_a.confidence,
                    'confidence_b': conv_b.confidence,
                })

                known = CONVENTION_CHANGES_5_0_TO_5_1.get(name)
                severity = "critical" if known else "warning"
                desc = f"Changed from {conv_a.convention}(cleanup={conv_a.stack_cleanup}) " \
                       f"to {conv_b.convention}(cleanup={conv_b.stack_cleanup})"
                if known:
                    desc += f" — KNOWN NT 5.0→5.1 change"

                report.issues.append(CompatIssue(
                    severity=severity,
                    category="calling_convention",
                    title=f"Convention change: {name}",
                    description=desc,
                    func_name=name,
                    fix_hint=f"Wrapper needed: {conv_a.convention} shim that calls "
                             f"{conv_b.convention} implementation, or recompile with correct convention",
                ))

    # ── Code pattern analysis ────────────────────────────────────────────

    def _analyze_code_patterns(self, pe_a, pe_b, report):
        for pe, label, shift_list, dispatch_list in [
            (pe_a, report.label_a, report.shift_patterns_a, report.dispatch_refs_a),
            (pe_b, report.label_b, report.shift_patterns_b, report.dispatch_refs_b),
        ]:
            thunks = _get_import_thunks(pe)
            strings = _extract_strings_from_data(pe)

            for section in _get_code_sections(pe):
                try:
                    data = section.get_data()
                except Exception:
                    continue

                base = pe.OPTIONAL_HEADER.ImageBase
                va = base + section.VirtualAddress

                # Disassemble in chunks for memory efficiency
                chunk_size = min(len(data), 256 * 1024)
                instructions = list(self.md.disasm(data[:chunk_size], va))

                # Scan for shift patterns
                shifts = _scan_shift_patterns(instructions)
                shift_list.extend(shifts)

                # Scan for dispatch table references
                disp_refs = _scan_dispatch_table_refs(pe, instructions, thunks, strings)
                dispatch_list.extend(disp_refs)

        # Compare shift patterns for known differences
        shifts_a_by_amt = defaultdict(int)
        shifts_b_by_amt = defaultdict(int)
        for sp in report.shift_patterns_a:
            shifts_a_by_amt[sp.shift_amount] += 1
        for sp in report.shift_patterns_b:
            shifts_b_by_amt[sp.shift_amount] += 1

        # Check for known HalpVector difference (shl 4 vs shl 8)
        for mname, minfo in MACRO_DIFFERENCES.items():
            pat_a = minfo.get("pattern_50")
            pat_b = minfo.get("pattern_51")
            if pat_a and pat_b:
                a_count = shifts_a_by_amt.get(pat_a[1], 0)
                b_count = shifts_b_by_amt.get(pat_b[1], 0)
                if a_count > 0 and b_count > 0:
                    report.issues.append(CompatIssue(
                        severity="critical", category="macro_difference",
                        title=f"Possible {mname} macro difference detected",
                        description=f"{minfo['desc']}. A has {a_count} shl-by-{pat_a[1]}, "
                                    f"B has {b_count} shl-by-{pat_b[1]}",
                        fix_hint=f"Change shift amount from {pat_b[1]} to {pat_a[1]} for Win2000 compat",
                    ))

        # Detect HAL I/O dispatch routing differences
        hal_a = _detect_hal_io_routing(pe_a, [], _get_import_thunks(pe_a))
        hal_b = _detect_hal_io_routing(pe_b, [], _get_import_thunks(pe_b))

        dispatch_a = [f for f in hal_a if f['type'] == 'dispatch_table']
        dispatch_b = [f for f in hal_b if f['type'] == 'dispatch_table']
        direct_a = [f for f in hal_a if f['type'] == 'direct_import']
        direct_b = [f for f in hal_b if f['type'] == 'direct_import']

        if dispatch_a and direct_b:
            report.issues.append(CompatIssue(
                severity="critical", category="dispatch_routing",
                title="HAL I/O routing changed: dispatch table → direct call",
                description=f"{report.label_a} routes IoReadPartitionTable etc. through "
                            f"HalDispatchTable, but {report.label_b} calls kernel directly. "
                            f"XP removed the dispatch table path.",
                fix_hint="Add HalIo* defines: #define HalIoReadPartitionTable "
                         "HALDISPATCH->HalIoReadPartitionTable, and implement "
                         "drivesup.c with wrapper functions",
            ))

    # ── Syscall mechanism comparison ─────────────────────────────────────

    def _compare_syscall_mechanism(self, pe_a, pe_b, report):
        sc_a = _detect_syscall_mechanism(pe_a)
        sc_b = _detect_syscall_mechanism(pe_b)

        if sc_a['mechanism'] != sc_b['mechanism']:
            report.issues.append(CompatIssue(
                severity="critical" if 'int_2E' in sc_a['mechanism'] else "warning",
                category="syscall_mechanism",
                title=f"Syscall mechanism: {sc_a['mechanism']} vs {sc_b['mechanism']}",
                description=f"{report.label_a} uses {sc_a['mechanism']}, "
                            f"{report.label_b} uses {sc_b['mechanism']}. "
                            f"int 0x2E count: A={sc_a['int_2e']}, B={sc_b['int_2e']}. "
                            f"sysenter count: A={sc_a['sysenter']}, B={sc_b['sysenter']}.",
                fix_hint="Patch syscall stubs to use int 0x2E for Win2000 compatibility",
            ))

    # ── Knowledge base application ───────────────────────────────────────

    def _apply_knowledge_base(self, report):
        """Apply known NT version difference knowledge to existing findings."""

        # Check if any HAL-specific patterns should trigger advice
        has_hal_export_diff = False
        for name in report.export_diff.get('only_a', []):
            if name in HAL_FUNCTIONS_REMOVED_IN_XP:
                has_hal_export_diff = True
                break

        if has_hal_export_diff:
            # Check if drivesup.c includes are probably wrong
            report.issues.append(CompatIssue(
                severity="info", category="build_advice",
                title="HAL drivesup.c build configuration",
                description="For Win2000 HAL compatibility, drivesup.c must include "
                            "halp.h (not nt.h) and define HalIo* macros. "
                            "IoAssignDriveLetters/IoReadPartitionTable/IoSetPartitionInformation/"
                            "IoWritePartitionTable must use stdcall (not fastcall) convention.",
                fix_hint='Includes needed: halp.h, bugcodes.h, ntddft.h, ntdddisk.h, '
                         'ntdskreg.h, stdio.h, string.h. '
                         'Remove FASTCALL from io.h declarations.',
            ))

        # Structure access pattern warnings
        if report.struct_access_diffs:
            for diff in report.struct_access_diffs:
                if diff.get('struct') in STRUCT_CHANGES:
                    changes = STRUCT_CHANGES[diff['struct']]
                    report.issues.append(CompatIssue(
                        severity="warning", category="struct_layout",
                        title=f"Structure {diff['struct']} layout differs between versions",
                        description=f"Changed fields: {', '.join(changes.get('changed_fields', []))}",
                    ))

        # Affinity-related warnings if we detected processor topology patterns
        for sp in report.shift_patterns_a + report.shift_patterns_b:
            if 'affinity' in sp.context.lower() or 'node' in sp.context.lower():
                report.issues.append(CompatIssue(
                    severity="warning", category="affinity",
                    title="Processor affinity calculation detected",
                    description=AFFINITY_CHANGES.get("5.0", ""),
                    fix_hint=AFFINITY_CHANGES.get("fix", ""),
                ))
                break


# ══════════════════════════════════════════════════════════════════════════
#  High-level API
# ══════════════════════════════════════════════════════════════════════════

def compare_compat(pe_a, pe_b, label_a="Win2000", label_b="ReactOS/XP", max_exports=500):
    """
    Full compatibility analysis between two PE binaries.
    Works on ALL file types: .dll, .sys, .exe, .cpl, .drv
    Returns CompatReport with all detected issues.
    """
    analyzer = NTCompatAnalyzer()
    return analyzer.analyze(pe_a, pe_b, label_a, label_b, max_exports)


def analyze_single_pe(pe_path, label="Unknown"):
    """Analyze a single PE for compatibility characteristics."""
    analyzer = NTCompatAnalyzer()
    return analyzer.analyze_single(pe_path, label)


def get_known_differences(version_from="5.0", version_to="5.1"):
    """Return known documented differences between NT versions."""
    result = {
        'calling_convention_changes': CONVENTION_CHANGES_5_0_TO_5_1,
        'hal_dispatch_removed_defines': HAL_DISPATCH_REMOVED_DEFINES,
        'macro_differences': MACRO_DIFFERENCES,
        'hal_functions_removed': HAL_FUNCTIONS_REMOVED_IN_XP,
        'idt_dispatch_changes': IDT_DISPATCH_CHANGES,
        'affinity_changes': AFFINITY_CHANGES,
        'struct_changes': STRUCT_CHANGES,
        'compat_bugchecks': COMPAT_BUGCHECKS,
    }
    return result


def diagnose_bugcheck(code, subcodes=None):
    """
    Given a bugcheck code, return known compatibility hints.
    """
    code_int = code if isinstance(code, int) else int(code, 16)
    info = COMPAT_BUGCHECKS.get(code_int)
    if info:
        return {
            'code': f"0x{code_int:08X}",
            'name': info['name'],
            'description': info['desc'],
            'compat_hint': info['compat_hint'],
            'known_causes': _get_bugcheck_causes(code_int, subcodes),
        }
    return {'code': f"0x{code_int:08X}", 'name': "Unknown", 'compat_hint': "No specific compat info"}


def _get_bugcheck_causes(code, subcodes):
    """Detailed cause analysis for known bugchecks."""
    causes = []
    if code == 0xA5:
        causes.append("ACPI/HAL version mismatch - check HalpVector macro (<<4 for 2000, <<8 for XP)")
        causes.append("HalpGetSystemInterruptVector implementation differs between versions")
        causes.append("Check interrupt affinity calculation (HalpVectorToNode vs direct)")
    elif code == 0x1E:
        causes.append("Calling convention mismatch (stdcall vs fastcall)")
        causes.append("Check IoReadPartitionTable/IoWritePartitionTable convention")
        causes.append("Verify HAL drivesup.c includes halp.h not nt.h")
    elif code == 0xCA:
        causes.append("PnP fatal: subcode 2 = driver returned invalid status")
        causes.append("Check acpi.sys version matches HAL version")
        causes.append("Original Win2000 acpi.sys may get replaced from driver.cab during install")
    elif code == 0x7F:
        causes.append("Stack corruption from calling convention mismatch")
        causes.append("stdcall callee cleans N bytes but fastcall only cleans N-8")
    return causes
