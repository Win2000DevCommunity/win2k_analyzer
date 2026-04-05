"""
Deep Function Analyzer & Cross-Reference Scanner
===================================================
Provides IDA Pro / Ghidra level deep analysis of PE functions:

  - Discover ALL functions in a PE (exported + internal/private)
  - Build cross-reference tables (xrefs): who calls whom
  - Detect function signatures from prologue/stack frame analysis
  - Identify structure access patterns, data references, internal tables
  - System-wide scanner: scan multiple PE files for callers of a function
  - Deep function comparison: signature, calls, structs, data, xrefs

Works WITHOUT symbols — uses KernelEx-style heuristic analysis:
  - Prologue pattern scanning (push ebp; mov ebp,esp)
  - Stack frame reconstruction
  - Call target resolution
  - Import thunk matching
  - String and data reference detection
"""

import hashlib
import os
import re
import struct
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple

import pefile
from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_32,
    CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET,
    CS_OP_IMM, CS_OP_REG, CS_OP_MEM,
)


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _get_cs():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def _rva_to_offset(pe, rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None


PROLOGUES = [
    b'\x8B\xFF\x55\x8B\xEC',  # hotpatch: mov edi,edi; push ebp; mov ebp,esp
    b'\x55\x8B\xEC',          # push ebp; mov ebp, esp
    b'\x55\x89\xE5',          # push ebp; mov ebp, esp (GCC)
]


# ---------------------------------------------------------------------------
#  Data structures
# ---------------------------------------------------------------------------

@dataclass
class FunctionRecord:
    """Complete record of a discovered function in a PE."""
    va: int                           # Virtual address
    rva: int                          # RVA
    size: int                         # Estimated size
    name: str = ""                    # Export name or sub_XXXXXXXX
    is_exported: bool = False
    ordinal: int = 0

    # Analysis results (filled by analyze_function)
    n_args: int = 0                   # Estimated argument count
    calling_convention: str = ""      # stdcall, cdecl, fastcall, thiscall
    return_type: str = "PVOID"        # Inferred return type
    stack_frame_size: int = 0         # Local variable space
    n_locals: int = 0                 # Number of local variables
    n_instructions: int = 0
    n_basic_blocks: int = 0

    # References
    calls_out: list = field(default_factory=list)    # VAs this function calls
    called_by: list = field(default_factory=list)    # VAs that call this function
    api_imports: list = field(default_factory=list)  # "DLL!Function" imports called
    data_refs: list = field(default_factory=list)    # Data addresses referenced
    string_refs: list = field(default_factory=list)  # Strings referenced
    struct_accesses: list = field(default_factory=list)  # Detected struct offsets

    # Pattern info
    is_syscall_stub: bool = False
    syscall_number: int = -1
    is_forwarder: bool = False
    forward_target: str = ""
    is_thunk: bool = False            # Single jmp to another function

    # Hash for comparison
    normalized_hash: str = ""


@dataclass
class XRef:
    """A cross-reference from caller to callee."""
    caller_va: int
    callee_va: int
    caller_name: str = ""
    callee_name: str = ""
    xref_type: str = "call"    # "call", "jmp", "data_ref", "indirect"
    insn_addr: int = 0         # Address of the referencing instruction
    source_file: str = ""      # PE file containing the caller


@dataclass
class DeepCompareResult:
    """Result of deep comparing two implementations of the same function."""
    func_name: str
    file_a: str = ""
    file_b: str = ""

    sig_match: bool = True
    n_args_a: int = 0
    n_args_b: int = 0
    conv_a: str = ""
    conv_b: str = ""

    # Code similarity
    hash_match: bool = False
    block_similarity: float = 0.0
    insn_count_a: int = 0
    insn_count_b: int = 0

    # API call differences
    apis_only_a: list = field(default_factory=list)
    apis_only_b: list = field(default_factory=list)
    apis_common: list = field(default_factory=list)

    # Data/string differences
    strings_only_a: list = field(default_factory=list)
    strings_only_b: list = field(default_factory=list)

    # Struct access differences
    structs_only_a: list = field(default_factory=list)
    structs_only_b: list = field(default_factory=list)

    # Internal call differences
    internal_calls_a: int = 0
    internal_calls_b: int = 0


# ---------------------------------------------------------------------------
#  PE Function Discovery (ALL functions, not just exports)
# ---------------------------------------------------------------------------

class PEFunctionMap:
    """
    Build a complete function map for a PE file.
    Discovers BOTH exported and internal (private) functions.
    """

    def __init__(self, pe_path, progress_callback=None):
        self.pe_path = pe_path
        self.pe = pefile.PE(pe_path, fast_load=False)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.progress_cb = progress_callback

        # Build lookup tables
        self.import_thunks = self._build_import_thunks()
        self.export_map = self._build_export_map()
        self.strings = self._extract_strings()

        # Results
        self.functions: Dict[int, FunctionRecord] = OrderedDict()
        self.xrefs: List[XRef] = []
        self._va_to_name: Dict[int, str] = {}

    def _report_progress(self, message, pct=0):
        if self.progress_cb:
            self.progress_cb(message, pct)

    def _build_import_thunks(self):
        thunks = {}
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return thunks
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('ascii', errors='replace')
                    rva = imp.address - self.image_base
                    thunks[rva] = f"{dll}!{name}"
                    thunks[imp.address] = f"{dll}!{name}"
        return thunks

    def _build_export_map(self):
        exports = {}
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.address:
                name = exp.name.decode('ascii', errors='replace') if exp.name else f"ord_{exp.ordinal}"
                exports[exp.address] = (name, exp.ordinal)
        return exports

    def _extract_strings(self, min_len=4):
        strings_map = {}
        for section in self.pe.sections:
            sname = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if sname not in ('.rdata', '.data', '.rsrc', 'INIT', 'PAGE', '.text'):
                continue
            try:
                data = section.get_data()
            except Exception:
                continue
            va_start = self.image_base + section.VirtualAddress
            for m in re.finditer(rb'[\x20-\x7e]{4,128}\x00', data):
                s = m.group()[:-1].decode('ascii', errors='replace')
                strings_map[va_start + m.start()] = s
        return strings_map

    def discover_all_functions(self):
        """
        Find ALL functions: exports + internal via prologue scanning.
        This is how IDA Pro and Ghidra do initial auto-analysis.
        """
        self._report_progress("Discovering exported functions...", 5)

        # Phase 1: Add all exports
        for rva, (name, ordinal) in self.export_map.items():
            va = self.image_base + rva
            offset = _rva_to_offset(self.pe, rva)
            if offset is None:
                continue
            func = FunctionRecord(
                va=va, rva=rva, size=0,
                name=name, is_exported=True, ordinal=ordinal,
            )
            self.functions[va] = func
            self._va_to_name[va] = name

        self._report_progress("Scanning for internal functions (prologue detection)...", 15)

        # Phase 2: Scan code sections for function prologues
        for section in self.pe.sections:
            if not (section.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                continue
            try:
                data = section.get_data()
            except Exception:
                continue
            va_base = self.image_base + section.VirtualAddress
            i = 0
            while i < len(data) - 8:
                found = False
                for pro in PROLOGUES:
                    if data[i:i + len(pro)] == pro:
                        # Verify: previous byte should be ret/int3/nop/retn
                        if i == 0 or data[i - 1] in (0xC3, 0xCC, 0x90, 0xC2, 0xCB):
                            va = va_base + i
                            if va not in self.functions:
                                self.functions[va] = FunctionRecord(
                                    va=va, rva=va - self.image_base, size=0,
                                    name=f"sub_{va:08X}",
                                )
                                self._va_to_name[va] = f"sub_{va:08X}"
                            found = True
                            break
                        if i >= 3 and data[i - 3] == 0xC2:
                            va = va_base + i
                            if va not in self.functions:
                                self.functions[va] = FunctionRecord(
                                    va=va, rva=va - self.image_base, size=0,
                                    name=f"sub_{va:08X}",
                                )
                                self._va_to_name[va] = f"sub_{va:08X}"
                            found = True
                            break
                if found:
                    i += 4
                else:
                    i += 1

        # Compute sizes based on next function
        sorted_vas = sorted(self.functions.keys())
        for idx, va in enumerate(sorted_vas):
            if idx + 1 < len(sorted_vas):
                self.functions[va].size = min(sorted_vas[idx + 1] - va, 65536)
            else:
                self.functions[va].size = 4096

        self._report_progress(f"Found {len(self.functions)} functions "
                              f"({sum(1 for f in self.functions.values() if f.is_exported)} exported, "
                              f"{sum(1 for f in self.functions.values() if not f.is_exported)} internal)", 25)
        return self.functions

    # ------------------------------------------------------------------
    #  Phase 2: Analyze individual functions (signature, calls, data)
    # ------------------------------------------------------------------

    def analyze_function(self, va):
        """Deep-analyze a single function to extract its full profile."""
        if va not in self.functions:
            return None
        func = self.functions[va]
        rva = func.rva
        offset = _rva_to_offset(self.pe, rva)
        if offset is None:
            return func

        data = self.pe.get_data(rva, func.size)
        md = _get_cs()

        instructions = list(md.disasm(data, va))
        if not instructions:
            return func

        # Trim at first ret/int3
        trimmed = []
        for insn in instructions:
            trimmed.append(insn)
            if insn.group(CS_GRP_RET):
                break
            if insn.mnemonic == 'int3':
                trimmed.pop()
                break

        func.n_instructions = len(trimmed)

        # Stack frame analysis
        self._analyze_stack_frame(trimmed, func)

        # Calling convention
        self._detect_convention(trimmed, func)

        # Call targets and data references
        self._collect_references(trimmed, func)

        # Basic block count
        func.n_basic_blocks = self._count_blocks(trimmed)

        # Syscall stub detection
        self._detect_syscall(trimmed, func)

        # Thunk/forwarder detection
        self._detect_thunk(trimmed, func)

        # Normalized hash for comparison
        self._compute_hash(trimmed, func)

        return func

    def analyze_all_functions(self, max_functions=5000):
        """Analyze all discovered functions. Reports progress."""
        total = min(len(self.functions), max_functions)
        analyzed = 0
        for va in list(self.functions.keys())[:max_functions]:
            self.analyze_function(va)
            analyzed += 1
            if analyzed % 50 == 0:
                pct = 25 + int(45 * analyzed / total)
                self._report_progress(
                    f"Analyzing function {analyzed}/{total}: "
                    f"{self.functions[va].name}...", pct)
        return self.functions

    # ------------------------------------------------------------------
    #  Phase 3: Build cross-reference table
    # ------------------------------------------------------------------

    def build_xrefs(self):
        """
        Build complete cross-reference table.
        For every call instruction, record caller→callee xref.
        This finds BOTH public and private (internal) function calls.
        """
        self._report_progress("Building cross-reference table...", 70)
        self.xrefs.clear()

        # Clear old xrefs
        for func in self.functions.values():
            func.called_by.clear()

        pe_name = os.path.basename(self.pe_path)

        for va, func in self.functions.items():
            for call_target in func.calls_out:
                if call_target in self.functions:
                    callee = self.functions[call_target]
                    xref = XRef(
                        caller_va=va,
                        callee_va=call_target,
                        caller_name=func.name,
                        callee_name=callee.name,
                        xref_type="call",
                        source_file=pe_name,
                    )
                    self.xrefs.append(xref)
                    if va not in callee.called_by:
                        callee.called_by.append(va)

        self._report_progress(f"Built {len(self.xrefs)} cross-references", 80)
        return self.xrefs

    def get_callers_of(self, target_va):
        """Get all functions that call a given address."""
        callers = []
        for xref in self.xrefs:
            if xref.callee_va == target_va:
                callers.append(xref)
        return callers

    def get_callees_of(self, caller_va):
        """Get all functions called by a given address."""
        callees = []
        for xref in self.xrefs:
            if xref.caller_va == caller_va:
                callees.append(xref)
        return callees

    def find_function_by_name(self, name):
        """Find a function by export name or sub_XXXXXXXX name."""
        for va, func in self.functions.items():
            if func.name == name:
                return func
        return None

    # ------------------------------------------------------------------
    #  Internal analysis helpers
    # ------------------------------------------------------------------

    def _analyze_stack_frame(self, instructions, func):
        """Detect stack frame size and local variable count."""
        for insn in instructions[:20]:
            # sub esp, N → local frame
            if insn.mnemonic == 'sub' and 'esp' in insn.op_str:
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    try:
                        val = parts[1].strip()
                        n = int(val, 16) if val.startswith('0x') else int(val)
                        func.stack_frame_size = n
                        func.n_locals = n // 4
                    except ValueError:
                        pass
                break

        # Count push instructions at start (arguments saved)
        n_push = 0
        for insn in instructions[:15]:
            if insn.mnemonic == 'push' and insn.op_str in (
                    'ebx', 'esi', 'edi', 'ecx', 'edx'):
                n_push += 1
            elif insn.mnemonic in ('sub', 'mov', 'and') and 'esp' in insn.op_str:
                continue
            elif insn.mnemonic in ('push', 'mov') and 'ebp' in insn.op_str:
                continue
            else:
                break

    def _detect_convention(self, instructions, func):
        """Detect calling convention from epilogue + parameter access patterns."""
        # --- Phase 1: Check epilogue (ret vs ret N) ---
        for insn in reversed(instructions):
            if insn.mnemonic == 'ret':
                op = insn.op_str.strip()
                if op:  # ret N  →  stdcall, N/4 args
                    try:
                        cleanup = int(op, 16) if op.startswith('0x') else int(op)
                        func.n_args = cleanup // 4
                        func.calling_convention = 'stdcall'
                    except ValueError:
                        func.calling_convention = 'stdcall'
                else:   # bare ret  →  cdecl (caller cleans stack)
                    func.calling_convention = 'cdecl'
                break

        # --- Phase 2: Count [ebp+N] parameter accesses (N >= 8) ---
        # Even for cdecl we can count how many args are accessed.
        # ebp+8 = arg1, ebp+C = arg2, ebp+10 = arg3, ...
        max_arg_offset = 0
        for insn in instructions:
            op = insn.op_str
            # Match [ebp + 0xNN] or [ebp+0xNN]
            for m in re.finditer(r'\[ebp\s*\+\s*(0x[0-9a-fA-F]+|\d+)', op):
                val_str = m.group(1)
                try:
                    val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                except ValueError:
                    continue
                if val >= 8:  # ebp+8 is first arg, ebp+4 is ret addr
                    if val > max_arg_offset:
                        max_arg_offset = val
            # Also match [esp + N] patterns in frameless functions
            for m in re.finditer(r'\[esp\s*\+\s*(0x[0-9a-fA-F]+|\d+)', op):
                val_str = m.group(1)
                try:
                    val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                except ValueError:
                    continue
                # For esp-relative, offset depends on push count and locals
                # Heuristic: if val > stack_frame + saved_regs, it's an arg
                arg_base = func.stack_frame_size + 4  # return address
                if val >= arg_base and val < arg_base + 128:
                    effective = val - arg_base + 8
                    if effective > max_arg_offset:
                        max_arg_offset = effective

        if max_arg_offset >= 8:
            ebp_args = (max_arg_offset - 4) // 4  # (offset - 4) / 4
            if ebp_args > func.n_args:
                func.n_args = ebp_args

        # --- Phase 3: Check for ecx usage (thiscall/fastcall) ---
        if func.calling_convention == 'stdcall':
            for insn in instructions[:10]:
                if insn.mnemonic == 'mov' and 'ecx' in insn.op_str:
                    if 'ebp+' in insn.op_str or 'esp+' in insn.op_str:
                        break  # ecx is loaded from stack, not a parameter
                    func.calling_convention = 'thiscall'
                    break

    def _collect_references(self, instructions, func):
        """Collect all call targets, data refs, and string refs."""
        func.calls_out.clear()
        func.api_imports.clear()
        func.data_refs.clear()
        func.string_refs.clear()
        func.struct_accesses.clear()

        for insn in instructions:
            # Direct calls
            if insn.group(CS_GRP_CALL):
                if insn.operands and insn.operands[0].type == CS_OP_IMM:
                    target = insn.operands[0].imm
                    func.calls_out.append(target)
                # Indirect call through IAT
                elif 'dword ptr [' in insn.op_str:
                    try:
                        addr_str = insn.op_str.split('[')[1].split(']')[0].strip()
                        if '+' not in addr_str and '-' not in addr_str:
                            addr_val = int(addr_str, 16)
                            if addr_val in self.import_thunks:
                                func.api_imports.append(self.import_thunks[addr_val])
                            else:
                                rva = addr_val - self.image_base
                                if rva in self.import_thunks:
                                    func.api_imports.append(self.import_thunks[rva])
                                else:
                                    func.calls_out.append(addr_val)
                    except (IndexError, ValueError):
                        pass

            # Data references: immediate values that point to .rdata/.data
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    val = op.imm
                    if val in self.strings:
                        func.string_refs.append((val, self.strings[val]))
                    elif self.image_base < val < self.image_base + 0x10000000:
                        # Could be a data reference
                        rva = val - self.image_base
                        sec = self._get_section_name(rva)
                        if sec in ('.rdata', '.data'):
                            func.data_refs.append(val)
                elif op.type == CS_OP_MEM:
                    # Structure access patterns: [reg+offset]
                    if op.mem.base and op.mem.disp:
                        disp = op.mem.disp
                        if 0 < disp < 0x1000:
                            func.struct_accesses.append(disp)

    def _get_section_name(self, rva):
        for section in self.pe.sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        return ""

    def _count_blocks(self, instructions):
        count = 1
        for insn in instructions:
            if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET):
                count += 1
        return count

    def _detect_syscall(self, instructions, func):
        if func.n_basic_blocks > 3 or func.n_instructions > 20:
            return
        for insn in instructions:
            if insn.mnemonic == 'mov' and 'eax' in insn.op_str:
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    try:
                        val = parts[1].strip()
                        num = int(val, 16) if val.startswith('0x') else int(val)
                        if 0 < num < 0x2000:
                            func.is_syscall_stub = True
                            func.syscall_number = num
                    except ValueError:
                        pass

    def _detect_thunk(self, instructions, func):
        if len(instructions) <= 3:
            for insn in instructions:
                if insn.mnemonic == 'jmp':
                    func.is_thunk = True
                    if insn.operands and insn.operands[0].type == CS_OP_IMM:
                        target = insn.operands[0].imm
                        func.forward_target = self._va_to_name.get(target, f"0x{target:08X}")
                    else:
                        func.forward_target = insn.op_str
                    func.is_forwarder = True
                    break

    def _compute_hash(self, instructions, func):
        # Normalize: strip addresses, keep mnemonics
        parts = []
        for insn in instructions:
            norm_op = re.sub(r'0x[0-9a-fA-F]+', '<N>', insn.op_str)
            parts.append(f"{insn.mnemonic} {norm_op}")
        blob = '|'.join(parts)
        func.normalized_hash = hashlib.md5(blob.encode()).hexdigest()

    def close(self):
        self.pe.close()


# ---------------------------------------------------------------------------
#  System-Wide Cross-Reference Scanner
# ---------------------------------------------------------------------------

def scan_system_xrefs(target_func_name, pe_paths, progress_callback=None):
    """
    Scan multiple PE files to find ALL callers of a function.

    Like KernelEx knows that kernel32!CreateFileW is called by shell32,
    comctl32, etc. — this scans the whole System32 to map dependencies.

    Args:
        target_func_name: Name of the function to find callers for
        pe_paths: List of PE file paths to scan
        progress_callback: fn(message, pct) for progress updates

    Returns:
        list of XRef objects from every PE that calls this function
    """
    all_xrefs = []
    total = len(pe_paths)

    for idx, pe_path in enumerate(pe_paths):
        if progress_callback:
            progress_callback(f"Scanning {os.path.basename(pe_path)}...",
                            int(100 * idx / total))
        try:
            pe = pefile.PE(pe_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('ascii', errors='replace')
                            if name == target_func_name:
                                dll = entry.dll.decode('ascii', errors='replace')
                                xref = XRef(
                                    caller_va=0,
                                    callee_va=0,
                                    caller_name=os.path.basename(pe_path),
                                    callee_name=f"{dll}!{target_func_name}",
                                    xref_type="import",
                                    source_file=pe_path,
                                )
                                all_xrefs.append(xref)
            pe.close()
        except Exception:
            continue

    if progress_callback:
        progress_callback(f"Scan complete: {len(all_xrefs)} references found", 100)
    return all_xrefs


def scan_directory_for_xrefs(target_func_name, directory, progress_callback=None):
    """Scan all PE files in a directory for callers of a function."""
    pe_paths = []
    for fname in os.listdir(directory):
        ext = os.path.splitext(fname)[1].lower()
        if ext in ('.dll', '.sys', '.exe', '.drv', '.cpl', '.ocx', '.scr'):
            pe_paths.append(os.path.join(directory, fname))

    return scan_system_xrefs(target_func_name, pe_paths, progress_callback)


# ---------------------------------------------------------------------------
#  Deep Function Comparison
# ---------------------------------------------------------------------------

def deep_compare_function(pe_path_a, pe_path_b, func_name,
                          progress_callback=None):
    """
    Deep comparison of a function between two PE files.
    Shows every difference: signature, API calls, structs, data, strings.
    """
    if progress_callback:
        progress_callback(f"Analyzing {func_name} in file A...", 10)

    map_a = PEFunctionMap(pe_path_a)
    map_a.discover_all_functions()
    func_a = map_a.find_function_by_name(func_name)
    if func_a:
        map_a.analyze_function(func_a.va)

    if progress_callback:
        progress_callback(f"Analyzing {func_name} in file B...", 40)

    map_b = PEFunctionMap(pe_path_b)
    map_b.discover_all_functions()
    func_b = map_b.find_function_by_name(func_name)
    if func_b:
        map_b.analyze_function(func_b.va)

    if progress_callback:
        progress_callback("Comparing...", 70)

    result = DeepCompareResult(
        func_name=func_name,
        file_a=os.path.basename(pe_path_a),
        file_b=os.path.basename(pe_path_b),
    )

    if func_a and func_b:
        # Signature comparison
        result.n_args_a = func_a.n_args
        result.n_args_b = func_b.n_args
        result.conv_a = func_a.calling_convention
        result.conv_b = func_b.calling_convention
        result.sig_match = (func_a.n_args == func_b.n_args and
                           func_a.calling_convention == func_b.calling_convention)

        # Code similarity
        result.hash_match = (func_a.normalized_hash == func_b.normalized_hash)
        result.insn_count_a = func_a.n_instructions
        result.insn_count_b = func_b.n_instructions

        max_insns = max(func_a.n_instructions, func_b.n_instructions, 1)
        min_insns = min(func_a.n_instructions, func_b.n_instructions)
        result.block_similarity = (min_insns / max_insns) * 100

        # API call differences
        apis_a = set(func_a.api_imports)
        apis_b = set(func_b.api_imports)
        result.apis_only_a = sorted(apis_a - apis_b)
        result.apis_only_b = sorted(apis_b - apis_a)
        result.apis_common = sorted(apis_a & apis_b)

        # String differences
        strs_a = set(s for _, s in func_a.string_refs)
        strs_b = set(s for _, s in func_b.string_refs)
        result.strings_only_a = sorted(strs_a - strs_b)
        result.strings_only_b = sorted(strs_b - strs_a)

        # Struct access differences
        acc_a = set(func_a.struct_accesses)
        acc_b = set(func_b.struct_accesses)
        result.structs_only_a = sorted(acc_a - acc_b)
        result.structs_only_b = sorted(acc_b - acc_a)

        # Internal call count
        result.internal_calls_a = len(func_a.calls_out)
        result.internal_calls_b = len(func_b.calls_out)

    map_a.close()
    map_b.close()

    if progress_callback:
        progress_callback("Done", 100)

    return result


def format_deep_compare(result):
    """Format a DeepCompareResult as text."""
    lines = []
    lines.append(f"{'='*70}")
    lines.append(f"  DEEP FUNCTION COMPARISON: {result.func_name}")
    lines.append(f"  File A: {result.file_a}")
    lines.append(f"  File B: {result.file_b}")
    lines.append(f"{'='*70}")
    lines.append("")

    # Signature
    sig_status = "\u2705 MATCH" if result.sig_match else "\u274C MISMATCH"
    lines.append(f"  SIGNATURE {sig_status}")
    lines.append(f"  {'─'*60}")
    lines.append(f"    File A: {result.conv_a}  ({result.n_args_a} args)  "
                 f"{result.insn_count_a} instructions")
    lines.append(f"    File B: {result.conv_b}  ({result.n_args_b} args)  "
                 f"{result.insn_count_b} instructions")
    lines.append("")

    # Code similarity
    hash_status = "\u2705 IDENTICAL" if result.hash_match else "\u26A0 DIFFERENT"
    lines.append(f"  CODE {hash_status}")
    lines.append(f"  {'─'*60}")
    lines.append(f"    Similarity: {result.block_similarity:.1f}%")
    lines.append(f"    Hash match: {'Yes' if result.hash_match else 'No'}")
    lines.append("")

    # API calls
    if result.apis_only_a or result.apis_only_b:
        lines.append(f"  API CALL DIFFERENCES")
        lines.append(f"  {'─'*60}")
        if result.apis_common:
            lines.append(f"    Common ({len(result.apis_common)}):")
            for a in result.apis_common:
                lines.append(f"      \u2022 {a}")
        if result.apis_only_a:
            lines.append(f"    Only in {result.file_a} ({len(result.apis_only_a)}):")
            for a in result.apis_only_a:
                lines.append(f"      \u2796 {a}")
        if result.apis_only_b:
            lines.append(f"    Only in {result.file_b} ({len(result.apis_only_b)}):")
            for a in result.apis_only_b:
                lines.append(f"      \u2795 {a}")
        lines.append("")
    else:
        lines.append(f"  API calls: identical ({len(result.apis_common)})")
        lines.append("")

    # String differences
    if result.strings_only_a or result.strings_only_b:
        lines.append(f"  STRING REFERENCE DIFFERENCES")
        lines.append(f"  {'─'*60}")
        if result.strings_only_a:
            lines.append(f"    Only in {result.file_a}:")
            for s in result.strings_only_a:
                lines.append(f"      \u2796 \"{s}\"")
        if result.strings_only_b:
            lines.append(f"    Only in {result.file_b}:")
            for s in result.strings_only_b:
                lines.append(f"      \u2795 \"{s}\"")
        lines.append("")

    # Struct access differences
    if result.structs_only_a or result.structs_only_b:
        lines.append(f"  STRUCTURE ACCESS DIFFERENCES")
        lines.append(f"  {'─'*60}")
        if result.structs_only_a:
            lines.append(f"    Offsets only in {result.file_a}:")
            for o in result.structs_only_a:
                lines.append(f"      +0x{o:03X}")
        if result.structs_only_b:
            lines.append(f"    Offsets only in {result.file_b}:")
            for o in result.structs_only_b:
                lines.append(f"      +0x{o:03X}")
        lines.append("")

    # Internal calls
    lines.append(f"  INTERNAL CALLS")
    lines.append(f"  {'─'*60}")
    lines.append(f"    File A: {result.internal_calls_a} internal call targets")
    lines.append(f"    File B: {result.internal_calls_b} internal call targets")

    return '\n'.join(lines)


def format_function_profile(func):
    """Format a FunctionRecord as a detailed text profile."""
    lines = []
    lines.append(f"{'='*70}")
    exported = "EXPORTED" if func.is_exported else "INTERNAL"
    lines.append(f"  {func.name}  ({exported})")
    lines.append(f"{'='*70}")
    lines.append(f"  Address: 0x{func.va:08X}  (RVA: 0x{func.rva:08X})")
    lines.append(f"  Size: {func.size} bytes  |  {func.n_instructions} instructions  |  "
                 f"{func.n_basic_blocks} blocks")
    lines.append(f"  Convention: {func.calling_convention}  |  Args: {func.n_args}  |  "
                 f"Frame: {func.stack_frame_size} bytes ({func.n_locals} locals)")

    if func.is_syscall_stub:
        lines.append(f"  Syscall: 0x{func.syscall_number:X}")
    if func.is_thunk:
        lines.append(f"  Thunk → {func.forward_target}")

    if func.api_imports:
        lines.append(f"\n  API IMPORTS ({len(func.api_imports)})")
        lines.append(f"  {'─'*50}")
        for api in sorted(set(func.api_imports)):
            count = func.api_imports.count(api)
            suffix = f" (×{count})" if count > 1 else ""
            lines.append(f"    → {api}{suffix}")

    if func.calls_out:
        internal = [c for c in func.calls_out if c in (self._va_to_name
                    if hasattr(func, '_parent_map') else {})]
        lines.append(f"\n  INTERNAL CALLS ({len(func.calls_out)})")
        lines.append(f"  {'─'*50}")
        for target in sorted(set(func.calls_out)):
            lines.append(f"    → 0x{target:08X}")

    if func.called_by:
        lines.append(f"\n  CALLED BY ({len(func.called_by)})")
        lines.append(f"  {'─'*50}")
        for caller in sorted(func.called_by):
            lines.append(f"    ← 0x{caller:08X}")

    if func.string_refs:
        lines.append(f"\n  STRING REFERENCES ({len(func.string_refs)})")
        lines.append(f"  {'─'*50}")
        for addr, s in func.string_refs[:20]:
            lines.append(f"    0x{addr:08X}: \"{s}\"")
        if len(func.string_refs) > 20:
            lines.append(f"    ... +{len(func.string_refs)-20} more")

    if func.struct_accesses:
        unique = sorted(set(func.struct_accesses))
        lines.append(f"\n  STRUCTURE OFFSETS ({len(unique)} unique)")
        lines.append(f"  {'─'*50}")
        for offset in unique:
            lines.append(f"    +0x{offset:03X}")

    if func.data_refs:
        lines.append(f"\n  DATA REFERENCES ({len(func.data_refs)})")
        lines.append(f"  {'─'*50}")
        for addr in sorted(set(func.data_refs))[:20]:
            lines.append(f"    0x{addr:08X}")

    lines.append(f"\n  Hash: {func.normalized_hash}")
    return '\n'.join(lines)


def format_function_profile_with_map(func, func_map):
    """Format a FunctionRecord with name resolution from PEFunctionMap."""
    lines = []
    lines.append(f"{'='*70}")
    exported = "EXPORTED" if func.is_exported else "INTERNAL"
    lines.append(f"  {func.name}  ({exported})")
    lines.append(f"{'='*70}")
    lines.append(f"  Address: 0x{func.va:08X}  (RVA: 0x{func.rva:08X})")
    lines.append(f"  Size: {func.size} bytes  |  {func.n_instructions} instructions  |  "
                 f"{func.n_basic_blocks} blocks")
    lines.append(f"  Convention: {func.calling_convention}  |  Args: {func.n_args}  |  "
                 f"Frame: {func.stack_frame_size} bytes ({func.n_locals} locals)")

    if func.is_syscall_stub:
        lines.append(f"  Syscall: 0x{func.syscall_number:X}")
    if func.is_thunk:
        lines.append(f"  Thunk → {func.forward_target}")

    if func.api_imports:
        lines.append(f"\n  API IMPORTS ({len(func.api_imports)})")
        lines.append(f"  {'─'*50}")
        for api in sorted(set(func.api_imports)):
            count = func.api_imports.count(api)
            suffix = f" (×{count})" if count > 1 else ""
            lines.append(f"    → {api}{suffix}")

    if func.calls_out:
        lines.append(f"\n  INTERNAL CALLS ({len(func.calls_out)})")
        lines.append(f"  {'─'*50}")
        for target in sorted(set(func.calls_out)):
            name = func_map._va_to_name.get(target, f"0x{target:08X}")
            lines.append(f"    → {name}")

    if func.called_by:
        lines.append(f"\n  CALLED BY ({len(func.called_by)})")
        lines.append(f"  {'─'*50}")
        for caller in sorted(func.called_by):
            name = func_map._va_to_name.get(caller, f"0x{caller:08X}")
            lines.append(f"    ← {name}")

    if func.string_refs:
        lines.append(f"\n  STRING REFERENCES ({len(func.string_refs)})")
        lines.append(f"  {'─'*50}")
        for addr, s in func.string_refs[:20]:
            lines.append(f"    0x{addr:08X}: \"{s}\"")
        if len(func.string_refs) > 20:
            lines.append(f"    ... +{len(func.string_refs)-20} more")

    if func.struct_accesses:
        unique = sorted(set(func.struct_accesses))
        lines.append(f"\n  STRUCTURE OFFSETS ({len(unique)} unique)")
        lines.append(f"  {'─'*50}")
        for offset in unique:
            lines.append(f"    +0x{offset:03X}")

    if func.data_refs:
        lines.append(f"\n  DATA REFERENCES ({len(func.data_refs)})")
        lines.append(f"  {'─'*50}")
        for addr in sorted(set(func.data_refs))[:20]:
            lines.append(f"    0x{addr:08X}")

    lines.append(f"\n  Hash: {func.normalized_hash}")
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
#  Function Code Extraction (full disassembly for porting)
# ---------------------------------------------------------------------------

def disassemble_function_full(func_map, func_name_or_va):
    """
    Get full disassembly of a function with resolved names.
    Returns lines of annotated assembly ready for porting.
    """
    if isinstance(func_name_or_va, int):
        func = func_map.functions.get(func_name_or_va)
    else:
        func = func_map.find_function_by_name(func_name_or_va)
    if not func:
        return None

    rva = func.rva
    try:
        data = func_map.pe.get_data(rva, func.size)
    except Exception:
        return None

    md = _get_cs()
    instructions = list(md.disasm(data, func.va))
    lines = []
    lines.append(f"; ==========================================================")
    lines.append(f"; {func.name}  ({func.calling_convention}, {func.n_args} args)")
    lines.append(f"; Address: 0x{func.va:08X}  Size: {func.size} bytes")
    lines.append(f"; ==========================================================")

    for insn in instructions:
        addr = insn.address
        annotation = ""

        # Annotate calls
        if insn.group(CS_GRP_CALL):
            if insn.operands and insn.operands[0].type == CS_OP_IMM:
                target = insn.operands[0].imm
                name = func_map._va_to_name.get(target, "")
                if name:
                    annotation = f"  ; → {name}"
            elif 'dword ptr [' in insn.op_str:
                try:
                    addr_str = insn.op_str.split('[')[1].split(']')[0].strip()
                    if '+' not in addr_str and '-' not in addr_str:
                        addr_val = int(addr_str, 16)
                        api = func_map.import_thunks.get(addr_val, "")
                        if not api:
                            api = func_map.import_thunks.get(addr_val - func_map.image_base, "")
                        if api:
                            annotation = f"  ; → {api}"
                except (IndexError, ValueError):
                    pass

        # Annotate string refs
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                val = op.imm
                if val in func_map.strings:
                    annotation = f'  ; → "{func_map.strings[val][:60]}"'

        # Annotate ebp offsets
        op_str = insn.op_str
        for m in re.finditer(r'\[ebp\s*\+\s*(0x[0-9a-fA-F]+|\d+)', op_str):
            val_str = m.group(1)
            try:
                val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                if val >= 8:
                    arg_n = (val - 4) // 4
                    annotation += f"  ; arg{arg_n}"
            except ValueError:
                pass
        for m in re.finditer(r'\[ebp\s*-\s*(0x[0-9a-fA-F]+|\d+)', op_str):
            val_str = m.group(1)
            try:
                val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                annotation += f"  ; local_{val:X}"
            except ValueError:
                pass

        line = f"  0x{addr:08X}:  {insn.mnemonic:<10} {insn.op_str:<40}{annotation}"
        lines.append(line)

        # Stop after ret
        if insn.group(CS_GRP_RET):
            break
        if insn.mnemonic == 'int3':
            break

    return '\n'.join(lines)


def get_function_dependencies(func_map, func_name_or_va):
    """
    Analyze everything a function needs — for porting to another PE.
    Returns a dict with all dependencies: internal calls, API imports,
    structures, data, strings, and recursive sub-dependencies.
    """
    if isinstance(func_name_or_va, int):
        func = func_map.functions.get(func_name_or_va)
    else:
        func = func_map.find_function_by_name(func_name_or_va)
    if not func:
        return None

    deps = {
        'function': func.name,
        'va': func.va,
        'convention': func.calling_convention,
        'n_args': func.n_args,
        'size': func.size,
        'api_imports': sorted(set(func.api_imports)),
        'internal_calls': [],
        'string_refs': list(func.string_refs),
        'data_refs': sorted(set(func.data_refs)),
        'struct_offsets': sorted(set(func.struct_accesses)),
        'called_by': [],
        'sub_dependencies': [],
    }

    # Resolve internal call names
    for target_va in sorted(set(func.calls_out)):
        name = func_map._va_to_name.get(target_va, f"sub_{target_va:08X}")
        target_func = func_map.functions.get(target_va)
        size = target_func.size if target_func else 0
        exported = target_func.is_exported if target_func else False
        deps['internal_calls'].append({
            'name': name,
            'va': target_va,
            'size': size,
            'is_exported': exported,
        })

    # Resolve callers
    for caller_va in func.called_by:
        name = func_map._va_to_name.get(caller_va, f"sub_{caller_va:08X}")
        deps['called_by'].append({'name': name, 'va': caller_va})

    # Recursive sub-dependencies (1 level deep)
    for call_info in deps['internal_calls']:
        sub_func = func_map.functions.get(call_info['va'])
        if sub_func and not sub_func.is_exported:
            sub_dep = {
                'name': call_info['name'],
                'api_imports': sorted(set(sub_func.api_imports)),
                'internal_calls': len(sub_func.calls_out),
                'struct_offsets': sorted(set(sub_func.struct_accesses)),
                'size': sub_func.size,
            }
            deps['sub_dependencies'].append(sub_dep)

    return deps


def format_dependencies(deps):
    """Format dependency analysis as text report."""
    lines = []
    lines.append(f"{'='*70}")
    lines.append(f"  PORTING DEPENDENCIES: {deps['function']}")
    lines.append(f"{'='*70}")
    lines.append(f"  Convention: {deps['convention']}  |  Args: {deps['n_args']}  |  Size: {deps['size']} bytes")
    lines.append("")

    if deps['api_imports']:
        lines.append(f"  API IMPORTS REQUIRED ({len(deps['api_imports'])})")
        lines.append(f"  {'─'*60}")
        for api in deps['api_imports']:
            lines.append(f"    ✓ {api}")
        lines.append("")

    if deps['internal_calls']:
        lines.append(f"  INTERNAL CALLS ({len(deps['internal_calls'])})")
        lines.append(f"  {'─'*60}")
        for call in deps['internal_calls']:
            status = "PUBLIC" if call['is_exported'] else "⚠ PRIVATE — must also port"
            lines.append(f"    → {call['name']}  ({call['size']} bytes)  [{status}]")
        lines.append("")

    if deps['struct_offsets']:
        lines.append(f"  STRUCTURE OFFSETS USED ({len(deps['struct_offsets'])})")
        lines.append(f"  {'─'*60}")
        lines.append(f"    ⚠ Verify these match between source and target PE:")
        for off in deps['struct_offsets']:
            lines.append(f"    +0x{off:03X}")
        lines.append("")

    if deps['data_refs']:
        lines.append(f"  DATA REFERENCES ({len(deps['data_refs'])})")
        lines.append(f"  {'─'*60}")
        for addr in deps['data_refs'][:30]:
            lines.append(f"    0x{addr:08X}")
        lines.append("")

    if deps['string_refs']:
        lines.append(f"  STRING REFERENCES ({len(deps['string_refs'])})")
        lines.append(f"  {'─'*60}")
        for addr, s in deps['string_refs'][:20]:
            lines.append(f"    0x{addr:08X}: \"{s}\"")
        lines.append("")

    if deps['called_by']:
        lines.append(f"  ⚠ CALLERS — will be affected ({len(deps['called_by'])})")
        lines.append(f"  {'─'*60}")
        for caller in deps['called_by']:
            lines.append(f"    ← {caller['name']}")
        lines.append("")

    if deps['sub_dependencies']:
        lines.append(f"  RECURSIVE SUB-DEPENDENCIES")
        lines.append(f"  {'─'*60}")
        for sub in deps['sub_dependencies']:
            lines.append(f"    {sub['name']} ({sub['size']} bytes):")
            if sub['api_imports']:
                lines.append(f"      APIs: {', '.join(sub['api_imports'][:5])}")
            if sub['internal_calls']:
                lines.append(f"      Internal calls: {sub['internal_calls']}")
            if sub['struct_offsets']:
                lines.append(f"      Struct offsets: {', '.join(f'+0x{o:03X}' for o in sub['struct_offsets'][:5])}")
        lines.append("")

    total_private = sum(1 for c in deps['internal_calls'] if not c['is_exported'])
    total_size = deps['size'] + sum(c['size'] for c in deps['internal_calls'] if not c['is_exported'])
    lines.append(f"  {'='*70}")
    lines.append(f"  PORTING SUMMARY")
    lines.append(f"  {'─'*60}")
    lines.append(f"    Total code to port: ~{total_size} bytes")
    lines.append(f"    Private functions to also port: {total_private}")
    lines.append(f"    API imports needed: {len(deps['api_imports'])}")
    lines.append(f"    Structure offsets to verify: {len(deps['struct_offsets'])}")
    lines.append(f"    Data references to relocate: {len(deps['data_refs'])}")
    lines.append(f"    Callers that will be affected: {len(deps['called_by'])}")

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
#  Enhanced System-Wide XRef Scanner (with IAT addresses and usage count)
# ---------------------------------------------------------------------------

def scan_system_xrefs_detailed(target_func_name, pe_paths, progress_callback=None):
    """
    Enhanced scan: find ALL callers + IAT address + how many times used.
    """
    all_xrefs = []
    total = len(pe_paths)

    for idx, pe_path in enumerate(pe_paths):
        if progress_callback:
            progress_callback(f"Scanning {os.path.basename(pe_path)}...",
                            int(100 * idx / total))
        try:
            pe = pefile.PE(pe_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('ascii', errors='replace')
                            if name == target_func_name:
                                dll = entry.dll.decode('ascii', errors='replace')
                                iat_addr = imp.address
                                xref = XRef(
                                    caller_va=iat_addr,
                                    callee_va=0,
                                    caller_name=os.path.basename(pe_path),
                                    callee_name=f"{dll}!{target_func_name}",
                                    xref_type="import",
                                    insn_addr=iat_addr,
                                    source_file=pe_path,
                                )
                                all_xrefs.append(xref)
            pe.close()
        except Exception:
            continue

    if progress_callback:
        progress_callback(f"Scan complete: {len(all_xrefs)} references found", 100)
    return all_xrefs


def get_disassembly_lines(func_map, func):
    """
    Get raw annotated disassembly lines for a function.
    Returns list of (address, mnemonic, op_str, annotation) tuples.
    Used for side-by-side diff display.
    """
    if not func:
        return []
    try:
        data = func_map.pe.get_data(func.rva, func.size)
    except Exception:
        return []

    md = _get_cs()
    instructions = list(md.disasm(data, func.va))
    result = []

    for insn in instructions:
        annotation = ""
        # Annotate calls
        if insn.group(CS_GRP_CALL):
            if insn.operands and insn.operands[0].type == CS_OP_IMM:
                target = insn.operands[0].imm
                name = func_map._va_to_name.get(target, "")
                if name:
                    annotation = name
            elif 'dword ptr [' in insn.op_str:
                try:
                    addr_str = insn.op_str.split('[')[1].split(']')[0].strip()
                    if '+' not in addr_str and '-' not in addr_str:
                        addr_val = int(addr_str, 16)
                        api = func_map.import_thunks.get(addr_val, "")
                        if not api:
                            api = func_map.import_thunks.get(addr_val - func_map.image_base, "")
                        if api:
                            annotation = api
                except (IndexError, ValueError):
                    pass

        # Annotate string refs
        for op in insn.operands:
            if op.type == CS_OP_IMM and op.imm in func_map.strings:
                annotation = f'"{func_map.strings[op.imm][:50]}"'

        result.append((insn.address, insn.mnemonic, insn.op_str, annotation))

        if insn.group(CS_GRP_RET) or insn.mnemonic == 'int3':
            break

    return result