"""
Function Behavior Analyzer
===========================
Intelligent disassembly-based function comparison between Win2000 DLLs
and ReactOS builds. Uses capstone for disassembly and heuristic basic-block
analysis to detect semantic similarity.

Capabilities:
  - Disassemble individual exported functions
  - Normalize instructions (strip addresses, classify ops)
  - Build basic-block control-flow graphs
  - Hash basic blocks for fast similarity matching
  - Detect API call patterns (call [IAT] → which import)
  - Compare Win2000 vs ReactOS function implementations
  - Score similarity percentage per function
  - Detect missing / extra / reordered logic
"""

import hashlib
import os
import struct
from collections import defaultdict

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET


# ---------------------------------------------------------------------------
#  Disassembly helpers
# ---------------------------------------------------------------------------

def _get_cs():
    """Return a capstone disassembler for x86-32 (Win2000 target)."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def _rva_to_offset(pe, rva):
    """Convert RVA to file offset."""
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None


def _get_import_thunks(pe):
    """Build a map of IAT RVA → 'DLL!Function' for resolving call targets."""
    thunks = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return thunks
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('ascii', errors='replace')
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode('ascii', errors='replace')
                # IAT entries are at imp.address (VA). Convert to RVA.
                rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                thunks[rva] = f"{dll_name}!{func_name}"
    return thunks


def _get_export_map(pe):
    """Build a map of RVA → export name."""
    exports = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return exports
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.address:
            exports[exp.address] = exp.name.decode('ascii', errors='replace')
    return exports


# ---------------------------------------------------------------------------
#  Function extraction
# ---------------------------------------------------------------------------

def get_function_bytes(pe_path, func_name, max_bytes=4096):
    """
    Extract raw bytes for an exported function from a PE file.
    Returns (bytes, rva, va) or None if not found.
    """
    pe = pefile.PE(pe_path, fast_load=False)
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return None

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
            rva = exp.address
            offset = _rva_to_offset(pe, rva)
            if offset is None:
                return None
            data = pe.get_data(rva, max_bytes)
            va = rva + pe.OPTIONAL_HEADER.ImageBase
            pe.close()
            return data, rva, va

    pe.close()
    return None


# ---------------------------------------------------------------------------
#  Basic block analysis
# ---------------------------------------------------------------------------

class BasicBlock:
    """A basic block: a sequence of instructions ending with a branch/ret."""
    __slots__ = ('start_addr', 'end_addr', 'instructions', 'successors',
                 'calls', 'normalized_hash')

    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.end_addr = start_addr
        self.instructions = []   # list of (mnemonic, op_str_normalized)
        self.successors = []     # list of target addresses
        self.calls = []          # list of call targets (API names or addrs)
        self.normalized_hash = None

    def compute_hash(self):
        """Hash the normalized instruction sequence."""
        blob = '|'.join(f"{m} {o}" for m, o in self.instructions)
        self.normalized_hash = hashlib.md5(blob.encode()).hexdigest()
        return self.normalized_hash


def _normalize_operand(op_str, image_base):
    """
    Normalize an operand string:
      - Replace absolute addresses with <ADDR>
      - Replace displacement-only memory refs with <MEM>
      - Keep register names as-is
    """
    # Simple heuristic: if it looks like a hex number > 0x10000, replace
    tokens = op_str.split(',')
    result = []
    for tok in tokens:
        tok = tok.strip()
        if tok.startswith('0x') or tok.startswith('-0x'):
            try:
                val = int(tok, 16)
                if abs(val) > 0x10000:
                    tok = '<ADDR>'
            except ValueError:
                pass
        result.append(tok)
    return ', '.join(result)


def build_basic_blocks(code_bytes, start_va, import_thunks=None, max_insns=2000):
    """
    Disassemble code and split into basic blocks.

    Returns a dict of {start_addr: BasicBlock}.
    Stops at first RET or when hitting padding (0xCC/0x90 sequences).
    """
    md = _get_cs()
    if import_thunks is None:
        import_thunks = {}

    blocks = {}
    current = None
    insn_count = 0
    leaders = {start_va}  # addresses that start a new block

    # First pass: find all leaders (branch targets)
    for insn in md.disasm(code_bytes, start_va):
        insn_count += 1
        if insn_count > max_insns:
            break
        if insn.mnemonic == 'int3' or (insn.mnemonic == 'nop' and insn_count > 10):
            # Padding between functions
            break
        if insn.group(CS_GRP_JUMP):
            # The target and the fallthrough are leaders
            if insn.operands and insn.operands[0].type == 2:  # IMM
                leaders.add(insn.operands[0].imm)
            leaders.add(insn.address + insn.size)

    # Second pass: build blocks
    md2 = _get_cs()
    current = None
    insn_count = 0
    image_base = start_va & 0xFFFF0000  # rough estimate

    for insn in md2.disasm(code_bytes, start_va):
        insn_count += 1
        if insn_count > max_insns:
            break
        if insn.mnemonic == 'int3' or (insn.mnemonic == 'nop' and insn_count > 10):
            break

        if insn.address in leaders or current is None:
            if current is not None:
                current.end_addr = insn.address
                current.compute_hash()
                if insn.address in leaders and insn.address != current.start_addr:
                    current.successors.append(insn.address)
            current = BasicBlock(insn.address)
            blocks[insn.address] = current

        norm_op = _normalize_operand(insn.op_str, image_base)
        current.instructions.append((insn.mnemonic, norm_op))

        # Track calls
        if insn.group(CS_GRP_CALL):
            if insn.operands and insn.operands[0].type == 2:  # IMM
                target = insn.operands[0].imm
                current.calls.append(target)
            elif 'dword ptr' in insn.op_str:
                # Indirect call through IAT: call dword ptr [0xXXXXXXXX]
                # Try to extract the address
                try:
                    addr_str = insn.op_str.split('[')[1].split(']')[0].strip()
                    addr_val = int(addr_str, 16)
                    iat_rva = addr_val - image_base
                    if iat_rva in import_thunks:
                        current.calls.append(import_thunks[iat_rva])
                    else:
                        current.calls.append(addr_val)
                except (IndexError, ValueError):
                    current.calls.append(insn.op_str)

        # End block on jump/ret
        if insn.group(CS_GRP_JUMP):
            if insn.operands and insn.operands[0].type == 2:
                current.successors.append(insn.operands[0].imm)
            # Conditional jumps also fall through
            if insn.mnemonic != 'jmp':
                current.successors.append(insn.address + insn.size)
            current.end_addr = insn.address + insn.size
            current.compute_hash()
            current = None

        elif insn.group(CS_GRP_RET):
            current.end_addr = insn.address + insn.size
            current.compute_hash()
            current = None

    if current is not None:
        current.end_addr = current.start_addr  # incomplete
        current.compute_hash()

    return blocks


# ---------------------------------------------------------------------------
#  Function fingerprinting
# ---------------------------------------------------------------------------

class FunctionFingerprint:
    """Behavioral fingerprint of a single function."""

    def __init__(self, name, blocks, pe_path=None):
        self.name = name
        self.pe_path = pe_path
        self.blocks = blocks
        self.block_count = len(blocks)
        self.total_insns = sum(len(b.instructions) for b in blocks.values())
        self.block_hashes = set(b.normalized_hash for b in blocks.values() if b.normalized_hash)
        self.api_calls = []
        self.syscall_number = None

        # Collect all API calls
        for b in blocks.values():
            for c in b.calls:
                if isinstance(c, str):
                    self.api_calls.append(c)

        # Detect if it's a syscall stub
        self._detect_syscall()

    def _detect_syscall(self):
        """Check if this function is a simple syscall stub (Nt/Zw functions)."""
        if self.block_count <= 2 and self.total_insns <= 15:
            for b in self.blocks.values():
                for mnem, op in b.instructions:
                    if mnem == 'mov' and 'eax' in op:
                        # mov eax, syscall_number
                        parts = op.split(',')
                        if len(parts) == 2:
                            try:
                                self.syscall_number = int(parts[1].strip(), 16)
                            except ValueError:
                                try:
                                    self.syscall_number = int(parts[1].strip())
                                except ValueError:
                                    pass


def fingerprint_function(pe_path, func_name, max_bytes=8192):
    """
    Build a FunctionFingerprint for a named export.
    Returns FunctionFingerprint or None if the function is not found.
    """
    result = get_function_bytes(pe_path, func_name, max_bytes)
    if result is None:
        return None
    code_bytes, rva, va = result

    pe = pefile.PE(pe_path, fast_load=False)
    import_thunks = _get_import_thunks(pe)
    pe.close()

    blocks = build_basic_blocks(code_bytes, va, import_thunks)
    return FunctionFingerprint(func_name, blocks, pe_path)


# ---------------------------------------------------------------------------
#  Function comparison
# ---------------------------------------------------------------------------

class ComparisonResult:
    """Result of comparing two function implementations."""

    def __init__(self, func_name, fp_a, fp_b):
        self.func_name = func_name
        self.fp_a = fp_a  # e.g., Win2000
        self.fp_b = fp_b  # e.g., ReactOS
        self.similarity = 0.0
        self.matching_blocks = 0
        self.extra_blocks_a = 0
        self.extra_blocks_b = 0
        self.api_diff = {}
        self.syscall_match = None
        self._compute()

    def _compute(self):
        if self.fp_a is None or self.fp_b is None:
            self.similarity = 0.0
            return

        # Block hash similarity (Jaccard index)
        hashes_a = self.fp_a.block_hashes
        hashes_b = self.fp_b.block_hashes

        if not hashes_a and not hashes_b:
            self.similarity = 100.0
            return

        common = hashes_a & hashes_b
        union = hashes_a | hashes_b

        self.matching_blocks = len(common)
        self.extra_blocks_a = len(hashes_a - hashes_b)
        self.extra_blocks_b = len(hashes_b - hashes_a)

        block_sim = (len(common) / len(union) * 100) if union else 0

        # API call similarity
        apis_a = set(self.fp_a.api_calls)
        apis_b = set(self.fp_b.api_calls)
        api_common = apis_a & apis_b
        api_union = apis_a | apis_b
        api_sim = (len(api_common) / len(api_union) * 100) if api_union else 100

        self.api_diff = {
            'only_a': apis_a - apis_b,
            'only_b': apis_b - apis_a,
            'common': api_common,
        }

        # Instruction count similarity
        max_insns = max(self.fp_a.total_insns, self.fp_b.total_insns, 1)
        min_insns = min(self.fp_a.total_insns, self.fp_b.total_insns)
        size_sim = (min_insns / max_insns) * 100

        # Syscall number match
        if self.fp_a.syscall_number is not None and self.fp_b.syscall_number is not None:
            self.syscall_match = (self.fp_a.syscall_number == self.fp_b.syscall_number)

        # Weighted similarity
        self.similarity = block_sim * 0.5 + api_sim * 0.3 + size_sim * 0.2

    def summary(self):
        """Return a human-readable summary."""
        lines = [f"Function: {self.func_name}"]
        lines.append(f"  Similarity: {self.similarity:.1f}%")
        if self.fp_a:
            lines.append(f"  File A: {self.fp_a.total_insns} insns, {self.fp_a.block_count} blocks")
        if self.fp_b:
            lines.append(f"  File B: {self.fp_b.total_insns} insns, {self.fp_b.block_count} blocks")
        lines.append(f"  Matching blocks: {self.matching_blocks}")
        lines.append(f"  Extra in A: {self.extra_blocks_a}, Extra in B: {self.extra_blocks_b}")

        if self.api_diff:
            if self.api_diff.get('only_a'):
                lines.append(f"  APIs only in A: {', '.join(str(a) for a in self.api_diff['only_a'])}")
            if self.api_diff.get('only_b'):
                lines.append(f"  APIs only in B: {', '.join(str(a) for a in self.api_diff['only_b'])}")

        if self.syscall_match is not None:
            status = "MATCH" if self.syscall_match else "MISMATCH"
            lines.append(f"  Syscall: {status} (A=0x{self.fp_a.syscall_number:X}, B=0x{self.fp_b.syscall_number:X})")

        return '\n'.join(lines)


def compare_functions(pe_path_a, pe_path_b, func_name, max_bytes=8192):
    """
    Compare a single function between two PE files.
    Returns a ComparisonResult.
    """
    fp_a = fingerprint_function(pe_path_a, func_name, max_bytes)
    fp_b = fingerprint_function(pe_path_b, func_name, max_bytes)
    return ComparisonResult(func_name, fp_a, fp_b)


def batch_compare(pe_path_a, pe_path_b, func_names=None, max_bytes=8192, progress_callback=None):
    """
    Compare multiple (or all shared) exported functions between two PE files.
    Returns list of ComparisonResult sorted by similarity (lowest first).
    progress_callback(message, pct) is called per function if provided.
    """
    pe_a = pefile.PE(pe_path_a, fast_load=False)
    pe_b = pefile.PE(pe_path_b, fast_load=False)

    exports_a = set()
    exports_b = set()

    if hasattr(pe_a, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe_a.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports_a.add(exp.name.decode('ascii', errors='replace'))
    if hasattr(pe_b, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe_b.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports_b.add(exp.name.decode('ascii', errors='replace'))

    pe_a.close()
    pe_b.close()

    if func_names is None:
        # Compare all shared exports
        func_names = sorted(exports_a & exports_b)

    total = len(func_names)
    results = []
    for i, name in enumerate(func_names):
        if progress_callback:
            pct = int((i / total) * 100) if total else 0
            progress_callback(f"Comparing {name} ({i+1}/{total})", pct)
        has_a = name in exports_a
        has_b = name in exports_b
        if has_a and has_b:
            r = compare_functions(pe_path_a, pe_path_b, name, max_bytes)
            results.append(r)
        else:
            # One side missing
            fp_a = fingerprint_function(pe_path_a, name) if has_a else None
            fp_b = fingerprint_function(pe_path_b, name) if has_b else None
            results.append(ComparisonResult(name, fp_a, fp_b))

    results.sort(key=lambda r: r.similarity)
    return results


# ---------------------------------------------------------------------------
#  API pattern detection
# ---------------------------------------------------------------------------

def detect_api_patterns(pe_path, func_name):
    """
    Analyze a function to detect its behavioral pattern:
      - Syscall stub (Nt/Zw thin wrapper)
      - Forwarder (jmp to another function)
      - API wrapper (calls one other API then returns)
      - Complex logic (multiple blocks, branches, loops)
      - String manipulator (many rep/movs/stos)
      - Memory allocator (calls RtlAllocateHeap / HeapAlloc)
      - Registry function (calls NtOpenKey, NtQueryValueKey, etc)
      - File I/O (calls NtCreateFile, NtReadFile, etc)
    """
    fp = fingerprint_function(pe_path, func_name)
    if fp is None:
        return None

    patterns = []

    # Syscall stub detection
    if fp.syscall_number is not None:
        patterns.append(('syscall_stub', f"Syscall 0x{fp.syscall_number:X}"))
        return {'function': func_name, 'patterns': patterns, 'fingerprint': fp}

    # Forwarder: single block, one jmp, no other logic
    if fp.block_count == 1:
        block = list(fp.blocks.values())[0]
        if len(block.instructions) <= 3:
            for m, o in block.instructions:
                if m == 'jmp':
                    patterns.append(('forwarder', f"Forwards to {o}"))

    # API wrapper: calls exactly one function then returns
    all_calls = [c for b in fp.blocks.values() for c in b.calls]
    if len(all_calls) == 1 and fp.block_count <= 3:
        patterns.append(('api_wrapper', f"Wraps {all_calls[0]}"))

    # Complex logic
    if fp.block_count >= 5:
        patterns.append(('complex', f"{fp.block_count} basic blocks, {fp.total_insns} instructions"))

    # Check API calls for categorization
    api_names = [c.lower() if isinstance(c, str) else '' for c in all_calls]
    api_str = ' '.join(api_names)

    if any(x in api_str for x in ['rtlallocateheap', 'heapalloc', 'virtualalloc', 'rtlcreateheap']):
        patterns.append(('memory_allocator', 'Uses heap/virtual memory allocation'))

    if any(x in api_str for x in ['ntopenkey', 'ntqueryvaluekey', 'ntsetvaluekey', 'regopen', 'regquery']):
        patterns.append(('registry', 'Accesses registry'))

    if any(x in api_str for x in ['ntcreatefile', 'ntreadfile', 'ntwritefile', 'ntopenfile']):
        patterns.append(('file_io', 'Performs file I/O'))

    if any(x in api_str for x in ['ntcreateprocess', 'ntcreatethread', 'rtlcreateuserthread']):
        patterns.append(('process_thread', 'Creates processes or threads'))

    # String operations detection (look at instruction mnemonics)
    all_mnemonics = [m for b in fp.blocks.values() for m, o in b.instructions]
    rep_count = sum(1 for m in all_mnemonics if m.startswith('rep'))
    if rep_count >= 2:
        patterns.append(('string_ops', f"{rep_count} REP string operations"))

    if not patterns:
        patterns.append(('general', f"{fp.total_insns} instructions, {len(all_calls)} API calls"))

    return {'function': func_name, 'patterns': patterns, 'fingerprint': fp}


def scan_all_exports(pe_path, max_functions=500, progress_callback=None):
    """
    Scan all exports in a PE and categorize them by behavioral pattern.
    Returns dict of pattern_type → list of function names.
    progress_callback(message, pct) is called per function if provided.
    """
    pe = pefile.PE(pe_path, fast_load=False)
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('ascii', errors='replace'))
    pe.close()

    total = min(len(exports), max_functions)
    categories = defaultdict(list)
    scanned = 0

    for func_name in exports:
        if scanned >= max_functions:
            break
        if progress_callback:
            pct = int((scanned / total) * 100) if total else 0
            progress_callback(f"Scanning {func_name} ({scanned+1}/{total})", pct)
        result = detect_api_patterns(pe_path, func_name)
        if result:
            for ptype, pdesc in result['patterns']:
                categories[ptype].append((func_name, pdesc))
        scanned += 1

    return dict(categories)


# ---------------------------------------------------------------------------
#  Disassembly listing for display
# ---------------------------------------------------------------------------

def disassemble_function(pe_path, func_name, max_bytes=4096):
    """
    Return a formatted disassembly listing of a function.
    Annotates calls with import names when possible.
    """
    result = get_function_bytes(pe_path, func_name, max_bytes)
    if result is None:
        return None

    code_bytes, rva, va = result

    pe = pefile.PE(pe_path, fast_load=False)
    import_thunks = _get_import_thunks(pe)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pe.close()

    md = _get_cs()
    lines = [f"; Disassembly of {func_name}",
             f"; File: {os.path.basename(pe_path)}",
             f"; RVA: 0x{rva:08X}  VA: 0x{va:08X}",
             ""]

    for insn in md.disasm(code_bytes, va):
        hex_bytes = ' '.join(f'{b:02X}' for b in insn.bytes)
        line = f"  {insn.address:08X}  {hex_bytes:<24s}  {insn.mnemonic:<8s} {insn.op_str}"

        # Annotate calls
        if insn.group(CS_GRP_CALL) and 'dword ptr' in insn.op_str:
            try:
                addr_str = insn.op_str.split('[')[1].split(']')[0].strip()
                addr_val = int(addr_str, 16)
                iat_rva = addr_val - image_base
                if iat_rva in import_thunks:
                    line += f"  ; → {import_thunks[iat_rva]}"
            except (IndexError, ValueError):
                pass

        lines.append(line)

        if insn.group(CS_GRP_RET):
            break
        if insn.mnemonic == 'int3':
            break

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
#  Advanced Control Flow Analysis
# ---------------------------------------------------------------------------

class ControlFlowStructure:
    """Represents a detected control flow structure (loop, if/else, switch)."""
    __slots__ = ('kind', 'header_addr', 'body_addrs', 'exit_addr',
                 'condition', 'details', 'children')

    def __init__(self, kind, header_addr):
        self.kind = kind            # 'loop', 'if_else', 'switch', 'sequence'
        self.header_addr = header_addr
        self.body_addrs = []        # addresses of blocks in this structure
        self.exit_addr = None       # where control goes after this structure
        self.condition = None       # branch condition string
        self.details = {}           # extra info (case count, loop type, etc.)
        self.children = []          # nested structures


def detect_loops(blocks):
    """
    Detect loop structures via back-edge detection (natural loops).
    A back edge is B→A where A dominates B (simplified: A.addr <= B.addr).

    Returns list of ControlFlowStructure(kind='loop').
    """
    sorted_addrs = sorted(blocks.keys())
    loops = []

    for addr in sorted_addrs:
        block = blocks[addr]
        for succ in block.successors:
            if succ in blocks and succ <= addr:
                # Back edge: block→succ forms a loop
                loop = ControlFlowStructure('loop', succ)
                # Collect all blocks between header and tail
                body = set()
                for a in sorted_addrs:
                    if succ <= a <= addr:
                        body.add(a)
                loop.body_addrs = sorted(body)

                # Determine loop type
                header = blocks[succ]
                tail = blocks[addr]
                if any(m == 'cmp' or m == 'test' for m, _ in header.instructions):
                    loop.details['type'] = 'while'
                    # Extract condition from header
                    for m, o in header.instructions:
                        if m in ('cmp', 'test'):
                            loop.condition = f"{m} {o}"
                            break
                elif any(m == 'cmp' or m == 'test' for m, _ in tail.instructions):
                    loop.details['type'] = 'do-while'
                    for m, o in tail.instructions:
                        if m in ('cmp', 'test'):
                            loop.condition = f"{m} {o}"
                            break
                else:
                    loop.details['type'] = 'infinite'

                loop.details['body_insns'] = sum(
                    len(blocks[a].instructions) for a in body if a in blocks
                )

                # Exit = first successor of header that's outside loop body
                for s in header.successors:
                    if s not in body:
                        loop.exit_addr = s
                        break

                loops.append(loop)

    return loops


def detect_if_else(blocks):
    """
    Detect if/else patterns: a block with exactly 2 successors (conditional
    jump) where the successors converge to a common target.

    Returns list of ControlFlowStructure(kind='if_else').
    """
    sorted_addrs = sorted(blocks.keys())
    structures = []

    for addr in sorted_addrs:
        block = blocks[addr]
        if len(block.successors) != 2:
            continue

        # Two successors: true_branch and false_branch
        true_addr, false_addr = block.successors[0], block.successors[1]
        if true_addr not in blocks or false_addr not in blocks:
            continue

        true_block = blocks[true_addr]
        false_block = blocks[false_addr]

        # Extract the condition
        condition = None
        for m, o in reversed(block.instructions):
            if m in ('cmp', 'test'):
                condition = f"{m} {o}"
                break
        # Also get the branch type
        for m, o in reversed(block.instructions):
            if m.startswith('j') and m != 'jmp':
                condition = f"{m} (after {condition})" if condition else m
                break

        ife = ControlFlowStructure('if_else', addr)
        ife.condition = condition

        # Check if both branches converge
        true_succs = set(true_block.successors)
        false_succs = set(false_block.successors)
        merge = true_succs & false_succs

        if merge:
            ife.exit_addr = min(merge)
            ife.details['has_else'] = True
        else:
            # One branch might fall through directly
            if false_addr in true_succs:
                ife.exit_addr = false_addr
                ife.details['has_else'] = False
            elif true_addr in false_succs:
                ife.exit_addr = true_addr
                ife.details['has_else'] = False
            else:
                ife.details['has_else'] = True

        ife.body_addrs = [true_addr, false_addr]
        ife.details['true_branch'] = true_addr
        ife.details['false_branch'] = false_addr
        ife.details['true_insns'] = len(true_block.instructions)
        ife.details['false_insns'] = len(false_block.instructions)

        structures.append(ife)

    return structures


def detect_switches(blocks):
    """
    Detect switch/case patterns by looking for:
    - A cmp+ja (bounds check) followed by indirect jump through a table
    - Multiple blocks branching from the same source with similar structure

    Returns list of ControlFlowStructure(kind='switch').
    """
    sorted_addrs = sorted(blocks.keys())
    switches = []

    for addr in sorted_addrs:
        block = blocks[addr]
        instrs = block.instructions

        # Pattern: cmp reg, N ; ja default ; jmp [reg*4 + table]
        for i, (m, o) in enumerate(instrs):
            if m == 'cmp' and i + 1 < len(instrs):
                next_m, next_o = instrs[i + 1]
                if next_m == 'ja' or next_m == 'jb':
                    # Looks like a switch bounds check
                    sw = ControlFlowStructure('switch', addr)
                    sw.condition = f"{m} {o}"

                    # Try to extract the case count
                    parts = o.split(',')
                    if len(parts) == 2:
                        try:
                            val = parts[1].strip()
                            n = int(val, 16) if val.startswith('0x') else int(val)
                            sw.details['n_cases'] = n + 1
                        except ValueError:
                            sw.details['n_cases'] = '?'

                    sw.details['register'] = parts[0].strip() if parts else '?'
                    sw.body_addrs = list(block.successors)

                    # Count how many unique targets the successors branch to
                    all_targets = set()
                    for s in block.successors:
                        if s in blocks:
                            all_targets.update(blocks[s].successors)
                    sw.details['total_targets'] = len(all_targets)

                    switches.append(sw)
                    break

    return switches


def analyze_control_flow(pe_path, func_name, max_bytes=8192):
    """
    Full control flow analysis combining all structure detectors.

    Returns dict with:
        'function': name
        'blocks': basic blocks dict
        'loops': list of loop structures
        'if_else': list of if/else structures
        'switches': list of switch structures
        'call_tree': list of called functions
        'complexity': cyclomatic complexity estimate
        'summary': human-readable summary
    """
    result = get_function_bytes(pe_path, func_name, max_bytes)
    if result is None:
        return None

    code_bytes, rva, va = result

    pe = pefile.PE(pe_path, fast_load=False)
    import_thunks = _get_import_thunks(pe)
    pe.close()

    blocks = build_basic_blocks(code_bytes, va, import_thunks)

    loops = detect_loops(blocks)
    ifs = detect_if_else(blocks)
    sws = detect_switches(blocks)

    # Build call tree
    all_calls = []
    unknown_calls = []
    for b in blocks.values():
        for c in b.calls:
            if isinstance(c, str):
                all_calls.append(c)
            else:
                unknown_calls.append(c)

    # Cyclomatic complexity: E - N + 2P
    # E = edges, N = nodes, P = connected components (1 for single function)
    n_nodes = len(blocks)
    n_edges = sum(len(b.successors) for b in blocks.values())
    complexity = n_edges - n_nodes + 2

    # Build structured summary
    summary_lines = []
    summary_lines.append(f"Function: {func_name}")
    summary_lines.append(f"Basic blocks: {n_nodes}")
    summary_lines.append(f"Total instructions: {sum(len(b.instructions) for b in blocks.values())}")
    summary_lines.append(f"Cyclomatic complexity: {complexity}")
    summary_lines.append(f"Loops: {len(loops)}")
    summary_lines.append(f"If/else branches: {len(ifs)}")
    summary_lines.append(f"Switch/case: {len(sws)}")
    summary_lines.append(f"API calls: {len(all_calls)}")
    summary_lines.append(f"Unknown call targets: {len(unknown_calls)}")

    return {
        'function': func_name,
        'blocks': blocks,
        'loops': loops,
        'if_else': ifs,
        'switches': sws,
        'call_tree': all_calls,
        'unknown_calls': unknown_calls,
        'complexity': complexity,
        'n_blocks': n_nodes,
        'n_edges': n_edges,
        'summary': '\n'.join(summary_lines),
    }


def format_control_flow(analysis):
    """
    Format control flow analysis as a detailed text report.
    """
    if analysis is None:
        return "Function not found."

    lines = []
    lines.append(f"{'='*70}")
    lines.append(f"  CONTROL FLOW ANALYSIS: {analysis['function']}")
    lines.append(f"{'='*70}")
    lines.append("")

    # Summary
    lines.append(f"  Blocks: {analysis['n_blocks']}  |  Edges: {analysis['n_edges']}  |  "
                 f"Complexity: {analysis['complexity']}")
    lines.append("")

    # Loops
    if analysis['loops']:
        lines.append(f"  LOOPS ({len(analysis['loops'])})")
        lines.append(f"  {'─'*60}")
        for i, loop in enumerate(analysis['loops']):
            ltype = loop.details.get('type', 'unknown')
            n_body = len(loop.body_addrs)
            n_insns = loop.details.get('body_insns', '?')
            lines.append(f"    Loop {i}: {ltype} @ 0x{loop.header_addr:08X}")
            lines.append(f"      Condition: {loop.condition or 'unconditional'}")
            lines.append(f"      Body: {n_body} blocks, {n_insns} instructions")
            if loop.exit_addr:
                lines.append(f"      Exit → 0x{loop.exit_addr:08X}")
            # Show block addresses in loop body
            for baddr in loop.body_addrs:
                if baddr in analysis['blocks']:
                    b = analysis['blocks'][baddr]
                    lines.append(f"        Block 0x{baddr:08X}: {len(b.instructions)} insns")
                    for m, o in b.instructions[:6]:
                        lines.append(f"          {m:<10} {o}")
                    if len(b.instructions) > 6:
                        lines.append(f"          ... +{len(b.instructions)-6} more")
            lines.append("")
    else:
        lines.append("  No loops detected")
        lines.append("")

    # If/else
    if analysis['if_else']:
        lines.append(f"  BRANCHES ({len(analysis['if_else'])})")
        lines.append(f"  {'─'*60}")
        for i, ife in enumerate(analysis['if_else']):
            has_else = ife.details.get('has_else', False)
            true_insns = ife.details.get('true_insns', '?')
            false_insns = ife.details.get('false_insns', '?')
            kind = "if/else" if has_else else "if"
            lines.append(f"    Branch {i}: {kind} @ 0x{ife.header_addr:08X}")
            lines.append(f"      Condition: {ife.condition or '?'}")
            lines.append(f"      True  → 0x{ife.details.get('true_branch', 0):08X} ({true_insns} insns)")
            lines.append(f"      False → 0x{ife.details.get('false_branch', 0):08X} ({false_insns} insns)")
            if ife.exit_addr:
                lines.append(f"      Merge → 0x{ife.exit_addr:08X}")
            lines.append("")
    else:
        lines.append("  No if/else branches detected")
        lines.append("")

    # Switches
    if analysis['switches']:
        lines.append(f"  SWITCH/CASE ({len(analysis['switches'])})")
        lines.append(f"  {'─'*60}")
        for i, sw in enumerate(analysis['switches']):
            n_cases = sw.details.get('n_cases', '?')
            reg = sw.details.get('register', '?')
            lines.append(f"    Switch {i} @ 0x{sw.header_addr:08X}")
            lines.append(f"      Register: {reg}")
            lines.append(f"      Cases: {n_cases}")
            lines.append(f"      Total targets: {sw.details.get('total_targets', '?')}")
            lines.append("")
    else:
        lines.append("  No switch/case detected")
        lines.append("")

    # Call tree
    if analysis['call_tree']:
        lines.append(f"  CALL TREE ({len(analysis['call_tree'])} API calls)")
        lines.append(f"  {'─'*60}")
        seen = set()
        for call in analysis['call_tree']:
            if call not in seen:
                seen.add(call)
                count = analysis['call_tree'].count(call)
                suffix = f" (×{count})" if count > 1 else ""
                lines.append(f"    → {call}{suffix}")
        lines.append("")

    if analysis['unknown_calls']:
        lines.append(f"  UNKNOWN CALL TARGETS ({len(analysis['unknown_calls'])})")
        lines.append(f"  {'─'*60}")
        for addr in sorted(set(analysis['unknown_calls'])):
            lines.append(f"    → 0x{addr:08X}")
        lines.append("")

    # Full block listing with structure annotations
    lines.append(f"  ANNOTATED BLOCK LISTING")
    lines.append(f"  {'─'*60}")

    loop_headers = {l.header_addr for l in analysis['loops']}
    loop_bodies = {}
    for l in analysis['loops']:
        for a in l.body_addrs:
            loop_bodies[a] = l
    if_headers = {i.header_addr for i in analysis['if_else']}

    for addr in sorted(analysis['blocks'].keys()):
        block = analysis['blocks'][addr]
        annotations = []
        if addr in loop_headers:
            loop = loop_bodies.get(addr)
            ltype = loop.details.get('type', 'loop') if loop else 'loop'
            annotations.append(f"◆ {ltype.upper()} HEADER")
        if addr in if_headers:
            annotations.append("◆ BRANCH")
        if addr in loop_bodies and addr not in loop_headers:
            annotations.append("│ loop body")

        ann_str = f"  {'  '.join(annotations)}" if annotations else ""
        n = len(block.instructions)
        lines.append(f"    Block 0x{addr:08X} ({n} insns){ann_str}")

        for m, o in block.instructions:
            prefix = "│   " if addr in loop_bodies else "    "
            lines.append(f"      {prefix}{m:<10} {o}")

        if block.calls:
            for c in block.calls:
                cname = c if isinstance(c, str) else f"0x{c:08X}"
                lines.append(f"      ↳ calls {cname}")

        if block.successors:
            succ_str = ', '.join(f"0x{s:08X}" for s in block.successors)
            lines.append(f"      → {succ_str}")
        lines.append("")

    return '\n'.join(lines)
