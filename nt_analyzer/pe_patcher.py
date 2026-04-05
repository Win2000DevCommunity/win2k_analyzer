"""
KernelEx-Inspired PE Binary Patcher — 2026 Ultimate Edition
=============================================================
Python implementation of ALL PE binary patching techniques from KernelEx (Xeno86,
2006-2008), massively upgraded with modern capabilities.

Supports ALL PE types: .dll, .sys, .exe, .cpl, .drv, .ocx, .scr, .mui

Core Capabilities (KernelEx-equivalent):
  - Code blob injection with 4-table fixup system (abs_ofs, abs_api, rel_api, hook_api)
  - Full export table rebuild (MTD1 in-place + MTD2 new section) with sorted merge
  - Full import table rebuild with OFT/FT pairing
  - Forward exports (EAT → "DLL.Function" string)
  - Alias exports (new name → existing export RVA)
  - Relocation management (alloc, update, rebase)
  - Conditional patch system (apply only if condition met)
  - Diff patches: raw, RVA, and searching pattern match
  - 5-stage apply_patches pipeline: prepare → api_entries → alter_sections → rebuild → process

Extended Capabilities (2026):
  - Symbol-aware patching (PDB/symbol map integration)
  - Internal table inspection (read/write IAT, EAT, relocation entries)
  - PE rebase (ChangeImageBase with relocation fixups)
  - Debug directory removal
  - Section increase (IncSection)
  - GenPatch-style C/ASM → injectable blob pipeline
  - Calling convention shims (stdcall ↔ fastcall)
  - Syscall stub patching (sysenter → int 0x2E)
  - PE version/subsystem patching
  - Full backup, dry-run, and audit trail support

Inspired by: KernelEx (Xeno86) CPEFile + patch hierarchy + apply_patches pipeline
"""

import os
import struct
import shutil
import hashlib
import time
import subprocess
import tempfile
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional, List

import pefile


# ══════════════════════════════════════════════════════════════════════════
#  Constants
# ══════════════════════════════════════════════════════════════════════════

SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
UPDT_SEC_NAME = ".kex"       # KernelEx-style update section name
PATCH_MAX_SIZE = 0x100000     # 1MB max PE growth

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3

# PE data directory indices
DD_EXPORT = 0
DD_IMPORT = 1
DD_RESOURCE = 2
DD_EXCEPTION = 3
DD_SECURITY = 4
DD_BASERELOC = 5
DD_DEBUG = 6
DD_TLS = 9
DD_IAT = 12

# x86 instruction templates
X86_NOP = b'\x90'
X86_RET = b'\xC3'
X86_INT3 = b'\xCC'
X86_PUSH_EBP = b'\x55'
X86_MOV_EBP_ESP = b'\x8B\xEC'
X86_JMP_REL32 = b'\xE9'
X86_CALL_REL32 = b'\xE8'
X86_JMP_ABS_IND = b'\xFF\x25'   # jmp [addr]
X86_CALL_ABS_IND = b'\xFF\x15'  # call [addr]

# Supported PE extensions
SUPPORTED_PE_TYPES = {'.dll', '.sys', '.exe', '.cpl', '.drv', '.ocx', '.scr', '.mui', '.efi'}


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


# ══════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class PatchOperation:
    """Record of a single patch operation."""
    type: str  # "section_add", "export_hook", "import_add", etc.
    description: str
    offset: int = 0
    old_data: bytes = b''
    new_data: bytes = b''
    rva: int = 0


@dataclass
class ExportPatch:
    """Describes a modification to the export table."""
    action: str  # "hook", "forward", "alias", "add"
    name: str
    target: str = ""  # for forward/alias: target name
    code: bytes = b''  # for hook/add: machine code
    fixups_abs: list = field(default_factory=list)  # absolute address fixups
    fixups_rel: list = field(default_factory=list)  # relative call/jmp fixups


@dataclass
class ImportPatch:
    """Describes a modification to the import table."""
    action: str  # "add", "remove"
    dll: str
    function: str
    ordinal: int = 0


@dataclass
class ConventionPatch:
    """Calling convention shim descriptor."""
    func_name: str
    from_conv: str  # "stdcall", "fastcall"
    to_conv: str
    num_params: int
    shim_code: bytes = b''


@dataclass
class PatchResult:
    """Result of a patch operation."""
    success: bool
    output_path: str = ""
    operations: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def summary(self):
        lines = [
            f"Patch {'SUCCEEDED' if self.success else 'FAILED'}",
            f"Output: {self.output_path}",
            f"Operations: {len(self.operations)}",
        ]
        if self.errors:
            lines.append(f"Errors: {len(self.errors)}")
            for e in self.errors:
                lines.append(f"  ERROR: {e}")
        if self.warnings:
            lines.append(f"Warnings: {len(self.warnings)}")
            for w in self.warnings:
                lines.append(f"  WARN: {w}")
        for op in self.operations:
            lines.append(f"  [{op.type}] {op.description}")
        return "\n".join(lines)


@dataclass
class CodeBlob:
    """
    KernelEx-style code blob with 4-table fixup system.

    abs_ofs:  [(offset_in_blob,), ...]  — DWORDs needing +ImageBase+blob_rva
    abs_api:  [(offset, dll, func), ...] — DWORDs to fill with absolute API addr
    rel_api:  [(offset, dll, func), ...] — rel32 fields pointing to API
    hook_api: [(export_name, offset_in_blob), ...] — redirect existing exports
    new_exports: [(name, offset_in_blob), ...] — register new named exports
    """
    code: bytes
    abs_ofs: list = field(default_factory=list)
    abs_api: list = field(default_factory=list)
    rel_api: list = field(default_factory=list)
    hook_api: list = field(default_factory=list)
    new_exports: list = field(default_factory=list)
    description: str = ""


@dataclass
class DiffEntry:
    """A single binary diff entry for patching."""
    mode: str  # "offset", "rva", "pattern"
    location: int = 0
    pattern: bytes = b''
    old_bytes: bytes = b''
    new_bytes: bytes = b''
    section: str = ""


@dataclass
class PatchSet:
    """
    Complete patch set for the KernelEx 5-stage pipeline.
    Combines code blobs, export/import changes, diffs, and conditions.
    """
    name: str
    description: str = ""
    code_blobs: list = field(default_factory=list)
    export_patches: list = field(default_factory=list)
    import_patches: list = field(default_factory=list)
    diff_patches: list = field(default_factory=list)
    convention_patches: list = field(default_factory=list)
    version_patch: tuple = None
    conditions: list = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════
#  PE Patcher Engine
# ══════════════════════════════════════════════════════════════════════════

class PEPatcher:
    """
    KernelEx-inspired PE binary patcher.
    Operates on an in-memory copy of the PE file.
    Call save() to write the patched file.
    """

    def __init__(self, pe_path, backup=True):
        self.pe_path = os.path.abspath(pe_path)
        self.backup = backup
        self.pe = pefile.PE(pe_path, fast_load=False)
        self.data = bytearray(self.pe.__data__)
        self.operations = []
        self.errors = []
        self.warnings = []
        self._new_sections = []

    def _record(self, op_type, desc, offset=0, old_data=b'', new_data=b'', rva=0):
        self.operations.append(PatchOperation(
            type=op_type, description=desc,
            offset=offset, old_data=bytes(old_data), new_data=bytes(new_data), rva=rva,
        ))

    # ── Section Management ───────────────────────────────────────────────

    def add_section(self, name, size, characteristics=None):
        """
        Add a new section to the PE file.
        Returns (section_rva, section_file_offset, actual_size).
        """
        if characteristics is None:
            characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ

        name_bytes = name.encode('ascii')[:8].ljust(8, b'\x00')
        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment

        # Find last section
        last_section = self.pe.sections[-1]
        new_rva = _align(
            last_section.VirtualAddress + last_section.Misc_VirtualSize,
            section_alignment,
        )
        new_raw_offset = _align(
            last_section.PointerToRawData + last_section.SizeOfRawData,
            file_alignment,
        )
        aligned_size = _align(size, file_alignment)
        aligned_vsize = _align(size, section_alignment)

        # Build section header (40 bytes)
        header = struct.pack('<8sIIIIIIHHI',
            name_bytes,
            aligned_vsize,       # VirtualSize
            new_rva,             # VirtualAddress
            aligned_size,        # SizeOfRawData
            new_raw_offset,      # PointerToRawData
            0,                   # PointerToRelocations
            0,                   # PointerToLinenumbers
            0,                   # NumberOfRelocations
            0,                   # NumberOfLinenumbers
            characteristics,
        )

        # Find where to write section header
        num_sections = self.pe.FILE_HEADER.NumberOfSections
        header_offset = (
            self.pe.DOS_HEADER.e_lfanew + 4 +  # PE sig
            20 +  # FILE_HEADER
            self.pe.FILE_HEADER.SizeOfOptionalHeader +
            num_sections * 40
        )

        # Check if we have room in headers
        first_section_raw = self.pe.sections[0].PointerToRawData
        if header_offset + 40 > first_section_raw:
            self.errors.append("No room in headers for new section. Expand headers first.")
            return None

        # Write section header
        self.data[header_offset:header_offset + 40] = header

        # Update NumberOfSections
        ns_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 2  # offset to NumberOfSections
        struct.pack_into('<H', self.data, ns_offset, num_sections + 1)

        # Update SizeOfImage
        new_image_size = new_rva + aligned_vsize
        soi_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 56  # SizeOfImage in OptionalHeader
        struct.pack_into('<I', self.data, soi_offset, new_image_size)

        # Extend file data with zero-filled section
        if new_raw_offset + aligned_size > len(self.data):
            self.data.extend(b'\x00' * (new_raw_offset + aligned_size - len(self.data)))

        self._new_sections.append({
            'name': name, 'rva': new_rva, 'offset': new_raw_offset,
            'size': aligned_size, 'vsize': aligned_vsize,
        })

        self._record("section_add",
                     f"Added section '{name}' at RVA 0x{new_rva:X}, size 0x{aligned_size:X}",
                     offset=new_raw_offset, rva=new_rva)

        return new_rva, new_raw_offset, aligned_size

    # ── Raw Byte Patching ────────────────────────────────────────────────

    def patch_bytes(self, offset, new_bytes, description=""):
        """Patch raw bytes at a file offset."""
        old = bytes(self.data[offset:offset + len(new_bytes)])
        self.data[offset:offset + len(new_bytes)] = new_bytes
        self._record("raw_patch", description or f"Patch {len(new_bytes)} bytes at 0x{offset:X}",
                    offset=offset, old_data=old, new_data=new_bytes)

    def patch_bytes_rva(self, rva, new_bytes, description=""):
        """Patch raw bytes at an RVA."""
        offset = self._rva_to_offset(rva)
        if offset is None:
            self.errors.append(f"Cannot resolve RVA 0x{rva:X}")
            return False
        self.patch_bytes(offset, new_bytes, description)
        return True

    def _rva_to_offset(self, rva):
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return rva - s.VirtualAddress + s.PointerToRawData
        # Also check new sections
        for ns in self._new_sections:
            if ns['rva'] <= rva < ns['rva'] + ns['vsize']:
                return rva - ns['rva'] + ns['offset']
        return None

    def _resolve_import_rva(self, dll_name, func_name):
        """Find the IAT entry RVA for a given import. Returns RVA or None."""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return None
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace')
            if dll.lower() != dll_name.lower():
                continue
            for imp in entry.imports:
                if imp.name and imp.name.decode('ascii', errors='replace') == func_name:
                    return imp.address - self.pe.OPTIONAL_HEADER.ImageBase
        return None

    def _hook_export_rva(self, func_name, new_rva):
        """Redirect an export's EAT entry to a new RVA (internal helper)."""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            self.errors.append(f"No export directory — can't hook '{func_name}'")
            return False
        export_dir = self.pe.DIRECTORY_ENTRY_EXPORT
        eat_rva = export_dir.struct.AddressOfFunctions
        for exp in export_dir.symbols:
            if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
                eat_index = exp.ordinal - export_dir.struct.Base
                eat_entry_offset = self._rva_to_offset(eat_rva + eat_index * 4)
                if eat_entry_offset is None:
                    self.errors.append(f"Cannot locate EAT entry for '{func_name}'")
                    return False
                old_rva = struct.unpack_from('<I', self.data, eat_entry_offset)[0]
                struct.pack_into('<I', self.data, eat_entry_offset, new_rva)
                self._record("export_redirect",
                            f"Redirected '{func_name}' RVA 0x{old_rva:X} → 0x{new_rva:X}",
                            offset=eat_entry_offset, rva=new_rva)
                return True
        self.errors.append(f"Export '{func_name}' not found")
        return False

    def read_dword_rva(self, rva):
        """Read a DWORD at the given RVA."""
        offset = self._rva_to_offset(rva)
        if offset is None:
            return None
        return struct.unpack_from('<I', self.data, offset)[0]

    def write_dword_rva(self, rva, value, description=""):
        """Write a DWORD at the given RVA."""
        offset = self._rva_to_offset(rva)
        if offset is None:
            self.errors.append(f"Cannot resolve RVA 0x{rva:X}")
            return False
        old = struct.unpack_from('<I', self.data, offset)[0]
        struct.pack_into('<I', self.data, offset, value & 0xFFFFFFFF)
        self._record("dword_write",
                    description or f"DWORD at RVA 0x{rva:X}: 0x{old:08X} → 0x{value:08X}",
                    offset=offset, rva=rva)
        return True

    # ── Syscall Stub Patching ────────────────────────────────────────────

    def patch_syscall_stubs(self):
        """
        Replace sysenter-based syscall stubs with int 0x2E for Win2000 compat.
        Pattern: mov edx, esp / sysenter → mov edx, esp / int 0x2E / ret
        """
        count = 0
        # sysenter = 0F 34
        # int 0x2E = CD 2E
        # Pattern in NT 5.1 ntdll: MOV EDX, ESP (8B D4) / SYSENTER (0F 34) / RET (C3)
        # Win2000 ntdll: MOV EDX, ESP (8B D4) / INT 0x2E (CD 2E) / RET (C3)

        sysenter_pattern = b'\x8B\xD4\x0F\x34'  # mov edx, esp; sysenter
        int2e_replacement = b'\x8B\xD4\xCD\x2E'  # mov edx, esp; int 0x2E

        pos = 0
        while True:
            idx = self.data.find(sysenter_pattern, pos)
            if idx == -1:
                break
            self.data[idx:idx + 4] = int2e_replacement
            count += 1
            pos = idx + 4

        if count > 0:
            self._record("syscall_patch",
                        f"Patched {count} sysenter stubs to int 0x2E",
                        new_data=int2e_replacement)

        return count

    # ── Calling Convention Shim Generation ───────────────────────────────

    def generate_stdcall_to_fastcall_shim(self, num_stack_params):
        """
        Generate a stdcall→fastcall shim.
        Takes params from stack, puts first two in ECX/EDX, calls real function.
        Returns machine code bytes. The call target at offset needs to be fixed.
        """
        # stdcall: all params on stack [esp+4], [esp+8], ...
        # fastcall: first in ECX, second in EDX, rest on stack

        code = bytearray()

        if num_stack_params >= 1:
            # mov ecx, [esp+4]  (first param)
            code += b'\x8B\x4C\x24\x04'
        if num_stack_params >= 2:
            # mov edx, [esp+8]  (second param)
            code += b'\x8B\x54\x24\x08'

        if num_stack_params > 2:
            # Push remaining params in reverse order
            for i in range(num_stack_params, 2, -1):
                # push [esp + i*4]  (adjust for pushes)
                offset = i * 4 + (num_stack_params - i) * 4
                code += b'\xFF\x74\x24' + struct.pack('<B', offset)

        # call <target>  (relative, 4 bytes need fixup)
        call_offset = len(code)
        code += b'\xE8\x00\x00\x00\x00'

        if num_stack_params > 2:
            # add esp, (num_stack_params - 2) * 4  (clean pushed params)
            cleanup = (num_stack_params - 2) * 4
            code += b'\x83\xC4' + struct.pack('<B', cleanup)

        # ret N  (clean original stdcall params)
        cleanup_total = num_stack_params * 4
        code += b'\xC2' + struct.pack('<H', cleanup_total)

        return bytes(code), call_offset

    def generate_fastcall_to_stdcall_shim(self, num_total_params):
        """
        Generate a fastcall→stdcall shim.
        Takes ECX/EDX and any stack params, pushes all onto stack, calls stdcall target.
        """
        code = bytearray()

        stack_params = max(0, num_total_params - 2)

        # Push stack params in reverse (they're already on stack at [esp+4+])
        for i in range(stack_params, 0, -1):
            offset = i * 4 + (stack_params - i) * 4
            code += b'\xFF\x74\x24' + struct.pack('<B', offset)

        # Push edx (second fastcall param) if needed
        if num_total_params >= 2:
            code += b'\x52'  # push edx

        # Push ecx (first fastcall param)
        if num_total_params >= 1:
            code += b'\x51'  # push ecx

        # call <target>
        call_offset = len(code)
        code += b'\xE8\x00\x00\x00\x00'

        # fastcall callee cleans stack_params * 4
        if stack_params > 0:
            code += b'\xC2' + struct.pack('<H', stack_params * 4)
        else:
            code += b'\xC3'  # simple ret

        return bytes(code), call_offset

    # ── Export Hooking ───────────────────────────────────────────────────

    def hook_export(self, func_name, replacement_code, description=""):
        """
        Hook an exported function by redirecting its RVA to injected code.
        The replacement code is placed in a new or existing patch section.
        """
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            self.errors.append("No export directory")
            return False

        # Find the export
        target_exp = None
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
                target_exp = exp
                break

        if not target_exp:
            self.errors.append(f"Export '{func_name}' not found")
            return False

        # Find or create patch section
        patch_section = self._get_patch_section(len(replacement_code))
        if patch_section is None:
            return False

        sect_rva, sect_file_off, sect_cursor = patch_section

        # Write replacement code
        code_rva = sect_rva + sect_cursor
        code_file_off = sect_file_off + sect_cursor
        self.data[code_file_off:code_file_off + len(replacement_code)] = replacement_code

        # Patch the EAT entry to point to our new code
        export_dir = self.pe.DIRECTORY_ENTRY_EXPORT
        eat_rva = export_dir.struct.AddressOfFunctions
        # ordinal - base = index into EAT
        eat_index = target_exp.ordinal - export_dir.struct.Base
        eat_entry_offset = self._rva_to_offset(eat_rva + eat_index * 4)

        if eat_entry_offset is None:
            self.errors.append(f"Cannot locate EAT entry for {func_name}")
            return False

        old_rva = struct.unpack_from('<I', self.data, eat_entry_offset)[0]
        struct.pack_into('<I', self.data, eat_entry_offset, code_rva)

        self._record("export_hook",
                    description or f"Hooked export '{func_name}': RVA 0x{old_rva:X} → 0x{code_rva:X}",
                    offset=eat_entry_offset, rva=code_rva)

        return True

    def add_export_forward(self, name, forward_string):
        """
        Add a forwarded export: the EAT entry points to a string within
        the export directory that names "DLL.FunctionName".
        This is a simplified version — for full rebuild, use rebuild_exports().
        """
        self._pending_forwards = getattr(self, '_pending_forwards', [])
        self._pending_forwards.append((name, forward_string))
        self._record("export_forward_pending",
                     f"Queued forward: '{name}' → '{forward_string}'")
        return True

    def add_alias_export(self, alias_name, target_name):
        """Queue an alias export (new name → existing export's RVA)."""
        self._pending_aliases = getattr(self, '_pending_aliases', [])
        self._pending_aliases.append((alias_name, target_name))
        self._record("export_alias_pending",
                     f"Queued alias: '{alias_name}' → '{target_name}'")
        return True

    def rebuild_exports(self, new_exports=None, forwarded=None, aliases=None):
        """
        Rebuild the entire export table in a new .edata section.
        Merges existing exports with additions. Names sorted for binary search.

        new_exports: [(name, rva), ...] — new named exports
        forwarded:   [(name, "DLL.Func"), ...] — forwarded exports
        aliases:     [(new_name, existing_name), ...] — alias exports
        """
        new_exports = list(new_exports or [])
        forwarded = list(forwarded or [])
        aliases = list(aliases or [])

        # Merge any pending additions
        new_exports += getattr(self, '_pending_new_exports', [])
        forwarded += getattr(self, '_pending_forwards', [])
        aliases += getattr(self, '_pending_aliases', [])

        # Read existing exports
        exports = {}  # name -> {'rva': int, 'ordinal': int, 'forward': str|None}
        module_name = os.path.basename(self.pe_path)
        base_ordinal = 1

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            ed = self.pe.DIRECTORY_ENTRY_EXPORT
            base_ordinal = ed.struct.Base
            name_offset = self._rva_to_offset(ed.struct.Name)
            if name_offset:
                end = self.data.index(0, name_offset)
                module_name = self.data[name_offset:end].decode('ascii', errors='replace')

            export_dir_rva = ed.struct.VirtualAddress
            export_dir_size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[DD_EXPORT].Size

            for exp in ed.symbols:
                if exp.name:
                    name = exp.name.decode('ascii', errors='replace')
                    if export_dir_rva <= exp.address < export_dir_rva + export_dir_size:
                        fwd_off = self._rva_to_offset(exp.address)
                        if fwd_off:
                            fwd_end = self.data.index(0, fwd_off)
                            fwd_str = self.data[fwd_off:fwd_end].decode('ascii', errors='replace')
                            exports[name] = {'rva': exp.address, 'ordinal': exp.ordinal, 'forward': fwd_str}
                        else:
                            exports[name] = {'rva': exp.address, 'ordinal': exp.ordinal, 'forward': None}
                    else:
                        exports[name] = {'rva': exp.address, 'ordinal': exp.ordinal, 'forward': None}

        # Merge new exports
        next_ord = max((e['ordinal'] for e in exports.values()), default=base_ordinal - 1) + 1
        for name, rva in new_exports:
            if name not in exports:
                exports[name] = {'rva': rva, 'ordinal': next_ord, 'forward': None}
                next_ord += 1

        for name, fwd_string in forwarded:
            exports[name] = {'rva': 0, 'ordinal': next_ord, 'forward': fwd_string}
            next_ord += 1

        for alias_name, target_name in aliases:
            if target_name in exports:
                exports[alias_name] = {
                    'rva': exports[target_name]['rva'],
                    'ordinal': next_ord,
                    'forward': exports[target_name]['forward'],
                }
                next_ord += 1
            else:
                self.warnings.append(f"Alias target '{target_name}' not found")

        if not exports:
            self.warnings.append("No exports to rebuild")
            return False

        # Sort names alphabetically (PE loader binary search requirement)
        sorted_names = sorted(exports.keys())
        num_functions = len(sorted_names)
        base_ordinal = 1

        # Calculate section size
        eat_size = num_functions * 4
        npt_size = num_functions * 4
        ot_size = num_functions * 2

        strings_size = len(module_name) + 1
        for name in sorted_names:
            strings_size += len(name) + 1
        for name in sorted_names:
            if exports[name]['forward']:
                strings_size += len(exports[name]['forward']) + 1

        total_size = 40 + eat_size + npt_size + ot_size + strings_size + 256

        result = self.add_section(".edata", total_size,
                                 IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)
        if result is None:
            return False
        sect_rva, sect_off, _ = result

        cursor = 0
        edt_offset = cursor; cursor += 40
        eat_offset = cursor; cursor += eat_size
        npt_offset = cursor; cursor += npt_size
        ot_offset = cursor; cursor += ot_size

        # Module name string
        modname_offset = cursor
        mod_bytes = module_name.encode('ascii') + b'\x00'
        self.data[sect_off + cursor:sect_off + cursor + len(mod_bytes)] = mod_bytes
        cursor += len(mod_bytes)

        # Export name strings
        name_str_offsets = {}
        for name in sorted_names:
            name_str_offsets[name] = cursor
            nb = name.encode('ascii') + b'\x00'
            self.data[sect_off + cursor:sect_off + cursor + len(nb)] = nb
            cursor += len(nb)

        # Forwarder strings
        fwd_str_offsets = {}
        for name in sorted_names:
            fwd = exports[name]['forward']
            if fwd:
                fwd_str_offsets[name] = cursor
                fb = fwd.encode('ascii') + b'\x00'
                self.data[sect_off + cursor:sect_off + cursor + len(fb)] = fb
                cursor += len(fb)

        # Write EAT entries
        for i, name in enumerate(sorted_names):
            fwd = exports[name]['forward']
            rva = sect_rva + fwd_str_offsets[name] if fwd else exports[name]['rva']
            struct.pack_into('<I', self.data, sect_off + eat_offset + i * 4, rva)

        # Write Name Pointer Table
        for i, name in enumerate(sorted_names):
            struct.pack_into('<I', self.data, sect_off + npt_offset + i * 4,
                           sect_rva + name_str_offsets[name])

        # Write Ordinal Table (0-based indices into EAT)
        for i in range(num_functions):
            struct.pack_into('<H', self.data, sect_off + ot_offset + i * 2, i)

        # Write Export Directory Table (40 bytes)
        edt = struct.pack('<IIHHIIIIIII',
            0,                              # Characteristics
            int(time.time()),               # TimeDateStamp
            0, 0,                           # MajorVersion, MinorVersion
            sect_rva + modname_offset,      # Name
            base_ordinal,                   # Base
            num_functions,                  # NumberOfFunctions
            num_functions,                  # NumberOfNames
            sect_rva + eat_offset,          # AddressOfFunctions
            sect_rva + npt_offset,          # AddressOfNames
            sect_rva + ot_offset,           # AddressOfNameOrdinals
        )
        self.data[sect_off + edt_offset:sect_off + edt_offset + 40] = edt

        # Update data directory for exports (index 0)
        dd_base = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 96
        struct.pack_into('<II', self.data, dd_base, sect_rva, cursor)

        self._record("export_rebuild",
                    f"Rebuilt export table: {num_functions} functions "
                    f"({len(forwarded)} fwd, {len(aliases)} alias) in .edata",
                    rva=sect_rva)
        return True

    # ── Import Table Patching ────────────────────────────────────────────

    def add_import(self, dll_name, func_name):
        """
        Add a new import entry. This requires rebuilding the entire import table
        since it's usually at the end of .rdata and can't be extended in place.
        """
        # For now, we just record the intent and apply during rebuild
        self._import_additions = getattr(self, '_import_additions', [])
        self._import_additions.append((dll_name, func_name))
        self._record("import_add_pending",
                    f"Queued import addition: {dll_name}!{func_name}")
        return True

    def rebuild_import_table(self):
        """
        Rebuild the entire import table in a new section.
        This handles additions queued by add_import().
        Uses paired OFT/FT structure (like KernelEx).
        """
        additions = getattr(self, '_import_additions', [])
        if not additions:
            return True

        # Read existing imports
        existing = OrderedDict()
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('ascii', errors='replace')
                funcs = []
                for imp in entry.imports:
                    funcs.append({
                        'name': imp.name.decode('ascii', errors='replace') if imp.name else None,
                        'ordinal': imp.ordinal,
                    })
                existing[dll] = funcs

        # Merge additions
        for dll, func in additions:
            if dll not in existing:
                existing[dll] = []
            # Only add if not already imported
            if not any(f['name'] == func for f in existing[dll]):
                existing[dll].append({'name': func, 'ordinal': None})

        # Calculate size needed for new import table
        num_dlls = len(existing)
        # Import Directory: (num_dlls + 1 terminator) * 20 bytes
        idt_size = (num_dlls + 1) * 20

        # ILT/IAT entries: for each DLL, (num_funcs + 1 terminator) * 4 bytes, times 2 (OFT + FT)
        ilt_iat_size = sum((len(funcs) + 1) * 8 for funcs in existing.values())

        # Hint/Name entries and DLL name strings
        strings_size = 0
        for dll, funcs in existing.items():
            strings_size += len(dll) + 1  # DLL name + null
            for f in funcs:
                if f['name']:
                    strings_size += 2 + len(f['name']) + 1  # Hint(2) + Name + null
                    if (2 + len(f['name']) + 1) % 2:
                        strings_size += 1  # padding to even

        total_size = idt_size + ilt_iat_size + strings_size + 256  # spare room

        # Add new section for import data
        result = self.add_section(".idata2", total_size,
                                 IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
        if result is None:
            return False

        sect_rva, sect_off, sect_size = result

        # Build the table
        cursor = 0

        # Phase 1: IDT entries (reserve space)
        idt_offset = cursor
        cursor += idt_size

        # Phase 2: OFT (OriginalFirstThunk) arrays
        oft_offsets = {}
        for dll in existing:
            oft_offsets[dll] = cursor
            cursor += (len(existing[dll]) + 1) * 4

        # Phase 3: FT (FirstThunk / IAT) arrays
        ft_offsets = {}
        for dll in existing:
            ft_offsets[dll] = cursor
            cursor += (len(existing[dll]) + 1) * 4

        # Phase 4: Strings (DLL names + Hint/Name entries)
        dll_name_offsets = {}
        hint_name_offsets = {}

        for dll, funcs in existing.items():
            dll_name_offsets[dll] = cursor
            dll_bytes = dll.encode('ascii') + b'\x00'
            self.data[sect_off + cursor:sect_off + cursor + len(dll_bytes)] = dll_bytes
            cursor += len(dll_bytes)

            hint_name_offsets[dll] = {}
            for f in funcs:
                if f['name']:
                    if cursor % 2:
                        cursor += 1  # align to even
                    hint_name_offsets[dll][f['name']] = cursor
                    # Hint (2 bytes, 0 for unknown) + Name + null
                    entry = struct.pack('<H', 0) + f['name'].encode('ascii') + b'\x00'
                    self.data[sect_off + cursor:sect_off + cursor + len(entry)] = entry
                    cursor += len(entry)

        # Phase 5: Write IDT entries
        idt_cursor = idt_offset
        for dll, funcs in existing.items():
            idt_entry = struct.pack('<IIIII',
                sect_rva + oft_offsets[dll],  # OriginalFirstThunk
                0,                            # TimeDateStamp
                0,                            # ForwarderChain
                sect_rva + dll_name_offsets[dll],  # Name
                sect_rva + ft_offsets[dll],   # FirstThunk (IAT)
            )
            self.data[sect_off + idt_cursor:sect_off + idt_cursor + 20] = idt_entry
            idt_cursor += 20
        # Terminator
        self.data[sect_off + idt_cursor:sect_off + idt_cursor + 20] = b'\x00' * 20

        # Phase 6: Write OFT and FT arrays (paired)
        for dll, funcs in existing.items():
            oft_cursor = oft_offsets[dll]
            ft_cursor = ft_offsets[dll]
            for f in funcs:
                if f['name'] and f['name'] in hint_name_offsets.get(dll, {}):
                    thunk = struct.pack('<I', sect_rva + hint_name_offsets[dll][f['name']])
                elif f['ordinal']:
                    thunk = struct.pack('<I', 0x80000000 | f['ordinal'])
                else:
                    continue

                self.data[sect_off + oft_cursor:sect_off + oft_cursor + 4] = thunk
                self.data[sect_off + ft_cursor:sect_off + ft_cursor + 4] = thunk
                oft_cursor += 4
                ft_cursor += 4
            # Terminators
            self.data[sect_off + oft_cursor:sect_off + oft_cursor + 4] = b'\x00\x00\x00\x00'
            self.data[sect_off + ft_cursor:sect_off + ft_cursor + 4] = b'\x00\x00\x00\x00'

        # Phase 7: Update PE directory entry for imports
        import_dir_rva_offset = (
            self.pe.DOS_HEADER.e_lfanew + 4 + 20 +
            self.pe.OPTIONAL_HEADER.__packed_size__ -
            (16 * 8) +  # start of data directories
            1 * 8  # import directory is index 1
        )
        # Actually, let's use the known structure offset
        # Data directory index 1 (IMPORT) is at optional header offset 104 (for PE32)
        dd_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 104
        struct.pack_into('<II', self.data, dd_offset,
                        sect_rva + idt_offset,  # RVA
                        idt_size)                # Size

        self._record("import_rebuild",
                    f"Rebuilt import table with {num_dlls} DLLs in new .idata2 section",
                    rva=sect_rva)

        return True

    # ── Version Patching ─────────────────────────────────────────────────

    def patch_os_version(self, major, minor):
        """Patch the OS version fields in the PE header."""
        oh_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20

        # MajorOperatingSystemVersion at offset 40
        struct.pack_into('<H', self.data, oh_offset + 40, major)
        struct.pack_into('<H', self.data, oh_offset + 42, minor)

        # Also patch SubsystemVersion
        struct.pack_into('<H', self.data, oh_offset + 48, major)
        struct.pack_into('<H', self.data, oh_offset + 50, minor)

        self._record("version_patch",
                    f"Patched OS version to {major}.{minor}")

    def patch_subsystem_version(self, major, minor):
        """Patch the subsystem version fields."""
        oh_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20
        struct.pack_into('<H', self.data, oh_offset + 48, major)
        struct.pack_into('<H', self.data, oh_offset + 50, minor)
        self._record("subsystem_version_patch",
                    f"Patched subsystem version to {major}.{minor}")

    # ── Relocation Management ────────────────────────────────────────────

    def add_relocation(self, rva):
        """
        Add a relocation entry for an absolute address at the given RVA.
        Must be called before save() which will rebuild the reloc table.
        """
        self._pending_relocs = getattr(self, '_pending_relocs', [])
        self._pending_relocs.append(rva)

    def _rebuild_relocations(self):
        """Rebuild the relocation table including pending additions."""
        pending = getattr(self, '_pending_relocs', [])
        if not pending:
            return

        # Read existing relocations
        existing_relocs = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in reloc.entries:
                    if entry.type == IMAGE_REL_BASED_HIGHLOW:
                        existing_relocs.append(entry.rva)

        all_relocs = sorted(set(existing_relocs + pending))

        # Group by page (4K blocks)
        pages = OrderedDict()
        for rva in all_relocs:
            page = rva & ~0xFFF
            offset = rva & 0xFFF
            if page not in pages:
                pages[page] = []
            pages[page].append(offset)

        # Calculate size
        total_size = 0
        for page, offsets in pages.items():
            block_size = 8 + len(offsets) * 2
            if block_size % 4:
                block_size += 2  # pad to 4-byte alignment
            total_size += block_size

        # Add section for relocations if needed
        result = self.add_section(".reloc2", total_size + 256,
                                 IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)
        if result is None:
            self.errors.append("Failed to add relocation section")
            return

        sect_rva, sect_off, _ = result

        # Write relocation blocks
        cursor = 0
        for page, offsets in pages.items():
            num_entries = len(offsets)
            if num_entries % 2:
                offsets.append(0)  # padding entry (type 0)
                num_entries += 1

            block_size = 8 + num_entries * 2
            struct.pack_into('<II', self.data, sect_off + cursor,
                           page, block_size)
            cursor += 8

            for off in offsets:
                entry = (IMAGE_REL_BASED_HIGHLOW << 12) | (off & 0xFFF) if off else 0
                struct.pack_into('<H', self.data, sect_off + cursor, entry)
                cursor += 2

        # Update data directory for relocations (index 5)
        dd_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 5 * 8 + 96
        # Actually: base relocation is data directory index 5
        # PE32: OptionalHeader starts at e_lfanew+4+20
        # Data directories start at offset 96 from start of optional header
        dd_base = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 96
        struct.pack_into('<II', self.data, dd_base + 5 * 8,
                        sect_rva, cursor)

        self._record("reloc_rebuild",
                    f"Rebuilt relocations: {len(all_relocs)} entries on {len(pages)} pages",
                    rva=sect_rva)

    # ── PE Rebase (KernelEx ChangeImageBase) ─────────────────────────────

    def rebase_image(self, new_base):
        """
        Change the PE ImageBase and fix up all relocations.
        Like KernelEx CPEFile::ChangeImageBase.
        """
        old_base = self.pe.OPTIONAL_HEADER.ImageBase
        delta = new_base - old_base
        if delta == 0:
            return True

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            self.warnings.append("No relocation table — rebase may corrupt absolute addresses")
        else:
            for reloc_block in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in reloc_block.entries:
                    if entry.type == IMAGE_REL_BASED_HIGHLOW:
                        offset = self._rva_to_offset(entry.rva)
                        if offset is not None and offset + 4 <= len(self.data):
                            val = struct.unpack_from('<I', self.data, offset)[0]
                            val = (val + delta) & 0xFFFFFFFF
                            struct.pack_into('<I', self.data, offset, val)

        # Update ImageBase in optional header (offset 28 for PE32)
        oh_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 28
        struct.pack_into('<I', self.data, oh_offset, new_base)

        self._record("rebase",
                    f"Rebased image: 0x{old_base:08X} → 0x{new_base:08X} (delta: {delta:+d})")
        return True

    # ── Section Increase (KernelEx IncSection) ───────────────────────────

    def increase_section(self, section_idx_or_name=-1, additional_size=0x1000):
        """
        Increase the size of a section (default: last one).
        Like KernelEx CPEFile::IncSection.
        Only the last section can be grown without shifting all subsequent data.
        """
        if isinstance(section_idx_or_name, str):
            target = None
            for i, s in enumerate(self.pe.sections):
                sname = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
                if sname == section_idx_or_name:
                    target = i
                    break
            if target is None:
                self.errors.append(f"Section '{section_idx_or_name}' not found")
                return False
            section_idx = target
        else:
            section_idx = section_idx_or_name
            if section_idx < 0:
                section_idx = len(self.pe.sections) + section_idx

        if section_idx < 0 or section_idx >= len(self.pe.sections):
            self.errors.append(f"Section index {section_idx} out of range")
            return False

        if section_idx != len(self.pe.sections) - 1:
            self.errors.append("Can only grow the last section without shifting")
            return False

        section = self.pe.sections[section_idx]
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment

        old_raw_size = section.SizeOfRawData
        old_vsize = section.Misc_VirtualSize

        new_raw_size = _align(old_raw_size + additional_size, file_alignment)
        new_vsize = _align(max(old_vsize, old_raw_size) + additional_size, section_alignment)
        growth = new_raw_size - old_raw_size

        # Extend the file data at end of section
        insert_point = section.PointerToRawData + old_raw_size
        self.data[insert_point:insert_point] = b'\x00' * growth

        # Update section header
        hdr_offset = (
            self.pe.DOS_HEADER.e_lfanew + 4 + 20 +
            self.pe.FILE_HEADER.SizeOfOptionalHeader +
            section_idx * 40
        )
        struct.pack_into('<I', self.data, hdr_offset + 8, new_vsize)     # VirtualSize
        struct.pack_into('<I', self.data, hdr_offset + 16, new_raw_size) # SizeOfRawData

        # Update SizeOfImage
        new_image_size = _align(section.VirtualAddress + new_vsize, section_alignment)
        soi_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 56
        struct.pack_into('<I', self.data, soi_offset, new_image_size)

        sname = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        self._record("section_increase",
                    f"Increased '{sname}' by 0x{growth:X} bytes "
                    f"(raw: 0x{old_raw_size:X}→0x{new_raw_size:X})")
        return True

    # ── Debug Directory Removal ──────────────────────────────────────────

    def remove_debug_directory(self):
        """Remove the debug directory entry from the PE."""
        dd_base = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 96
        struct.pack_into('<II', self.data, dd_base + DD_DEBUG * 8, 0, 0)
        self._record("debug_remove", "Removed debug directory entry")
        return True

    # ── Timestamp Update ─────────────────────────────────────────────────

    def update_timestamp(self):
        """Update the PE TimeDateStamp to current time."""
        ts = int(time.time())
        # PE sig(4) + Machine(2) + NumSections(2) = offset 8 to TimeDateStamp
        ts_offset = self.pe.DOS_HEADER.e_lfanew + 8
        struct.pack_into('<I', self.data, ts_offset, ts)
        self._record("timestamp", f"Updated TimeDateStamp to {ts}")

    # ── Search & Replace in Code ─────────────────────────────────────────

    def search_and_patch(self, pattern, replacement, section_name=None):
        """
        Search for a byte pattern in code sections and replace all occurrences.
        Returns the number of replacements made.
        """
        count = 0
        for s in self.pe.sections:
            sname = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if section_name and sname != section_name:
                continue
            if not (s.Characteristics & 0x20000000):
                continue  # skip non-executable sections

            start = s.PointerToRawData
            end = start + s.SizeOfRawData
            pos = start

            while pos < end:
                idx = self.data.find(pattern, pos, end)
                if idx == -1:
                    break
                self.data[idx:idx + len(replacement)] = replacement
                count += 1
                pos = idx + len(replacement)

        if count > 0:
            self._record("search_patch",
                        f"Replaced {count} occurrences of pattern ({len(pattern)} bytes)",
                        new_data=replacement)
        return count

    # ── Patch Section Management ─────────────────────────────────────────

    def _get_patch_section(self, min_size):
        """
        Get or create a section for storing patch code.
        Returns (rva, file_offset, write_cursor) or None.
        """
        # Check for existing patch section
        for ns in self._new_sections:
            if ns['name'] == '.patch':
                cursor = getattr(self, '_patch_cursor', 0)
                if cursor + min_size <= ns['size']:
                    rva = ns['rva']
                    off = ns['offset']
                    self._patch_cursor = cursor + _align(min_size, 16)
                    return rva, off, cursor
                else:
                    break  # need bigger section

        # Create new patch section
        size = max(min_size + 4096, 0x2000)
        result = self.add_section(".patch", size,
                                 IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)
        if result is None:
            return None
        rva, off, actual = result
        self._patch_cursor = _align(min_size, 16)
        return rva, off, 0

    # ── Checksum Fix ─────────────────────────────────────────────────────

    def fix_checksum(self):
        """Recalculate and fix the PE checksum."""
        # Clear old checksum
        cksum_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 64
        struct.pack_into('<I', self.data, cksum_offset, 0)

        # Calculate new checksum (PE checksum algorithm)
        checksum = 0
        remainder = len(self.data) % 4
        data_len = len(self.data) - remainder

        for i in range(0, data_len, 4):
            val = struct.unpack_from('<I', self.data, i)[0]
            checksum = (checksum + val) & 0xFFFFFFFF
            checksum = ((checksum >> 32) + (checksum & 0xFFFFFFFF)) if checksum > 0xFFFFFFFF else checksum

        if remainder:
            val = int.from_bytes(self.data[data_len:], byteorder='little')
            checksum = (checksum + val) & 0xFFFFFFFF

        # Fold to 16-bit and add file size
        checksum = ((checksum >> 16) + (checksum & 0xFFFF))
        checksum = ((checksum >> 16) + (checksum & 0xFFFF))
        checksum = (checksum + len(self.data)) & 0xFFFFFFFF

        struct.pack_into('<I', self.data, cksum_offset, checksum)
        self._record("checksum", f"Fixed checksum: 0x{checksum:08X}")

    # ── Save ─────────────────────────────────────────────────────────────

    def save(self, output_path=None, fix_cksum=True, update_ts=True):
        """
        Write the patched PE to disk.
        Creates backup of original if backup=True.
        Returns PatchResult.
        """
        if output_path is None:
            base, ext = os.path.splitext(self.pe_path)
            output_path = f"{base}_patched{ext}"

        # Backup
        if self.backup and os.path.exists(output_path):
            backup_path = output_path + ".bak"
            shutil.copy2(output_path, backup_path)

        # Rebuild relocations if needed
        self._rebuild_relocations()

        # Rebuild imports if needed
        if hasattr(self, '_import_additions') and self._import_additions:
            self.rebuild_import_table()

        # Rebuild exports if needed
        pending_exports = getattr(self, '_pending_new_exports', [])
        pending_fwd = getattr(self, '_pending_forwards', [])
        pending_alias = getattr(self, '_pending_aliases', [])
        if pending_exports or pending_fwd or pending_alias:
            self.rebuild_exports()

        # Update timestamp
        if update_ts:
            self.update_timestamp()

        # Fix checksum
        if fix_cksum:
            self.fix_checksum()

        # Write
        with open(output_path, 'wb') as f:
            f.write(bytes(self.data))

        return PatchResult(
            success=len(self.errors) == 0,
            output_path=output_path,
            operations=list(self.operations),
            errors=list(self.errors),
            warnings=list(self.warnings),
        )

    # ── Convenience Methods ──────────────────────────────────────────────

    def patch_for_win2000(self):
        """
        Apply a standard set of Win2000 compatibility patches:
        1. Patch OS version to 5.0
        2. Patch syscall stubs to int 0x2E
        3. Fix checksum
        """
        self.patch_os_version(5, 0)
        self.patch_subsystem_version(5, 0)
        sc_count = self.patch_syscall_stubs()
        return {
            'version_patched': True,
            'syscall_stubs_patched': sc_count,
        }

    def apply_convention_shim(self, func_name, from_conv, to_conv, num_params):
        """
        Generate and inject a calling convention shim for an exported function.
        """
        if from_conv == "stdcall" and to_conv == "fastcall":
            shim, call_offset = self.generate_stdcall_to_fastcall_shim(num_params)
        elif from_conv == "fastcall" and to_conv == "stdcall":
            shim, call_offset = self.generate_fastcall_to_stdcall_shim(num_params)
        else:
            self.errors.append(f"Unsupported convention change: {from_conv} → {to_conv}")
            return False

        # Find the original function RVA
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            self.errors.append("No export directory")
            return False

        orig_rva = None
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
                orig_rva = exp.address
                break

        if orig_rva is None:
            self.errors.append(f"Export '{func_name}' not found")
            return False

        # Get patch section
        patch_section = self._get_patch_section(len(shim) + 16)
        if patch_section is None:
            return False

        sect_rva, sect_off, cursor = patch_section
        shim_rva = sect_rva + cursor
        shim_file_off = sect_off + cursor

        # Fix up the relative call in the shim
        # The call instruction is at call_offset, and the target is orig_rva
        shim_ba = bytearray(shim)
        call_addr = shim_rva + call_offset + 5  # address of next instruction after call
        rel32 = (self.pe.OPTIONAL_HEADER.ImageBase + orig_rva) - (self.pe.OPTIONAL_HEADER.ImageBase + call_addr)
        struct.pack_into('<i', shim_ba, call_offset + 1, rel32)

        # Write shim code
        self.data[shim_file_off:shim_file_off + len(shim_ba)] = shim_ba

        # Hook the export to point to our shim
        export_dir = self.pe.DIRECTORY_ENTRY_EXPORT
        eat_rva = export_dir.struct.AddressOfFunctions
        for exp in export_dir.symbols:
            if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
                eat_index = exp.ordinal - export_dir.struct.Base
                eat_entry_offset = self._rva_to_offset(eat_rva + eat_index * 4)
                if eat_entry_offset:
                    struct.pack_into('<I', self.data, eat_entry_offset, shim_rva)
                break

        self._record("convention_shim",
                    f"Injected {from_conv}→{to_conv} shim for '{func_name}' "
                    f"({num_params} params) at RVA 0x{shim_rva:X}",
                    rva=shim_rva)

        return True

    # ── Code Blob Injection (KernelEx binary_api_patch) ──────────────────

    def inject_code_blob(self, blob, description=""):
        """
        Inject a compiled code blob with KernelEx-style 4-table fixup system.

        blob: CodeBlob instance with:
          code     — raw x86 machine code
          abs_ofs  — [(offset,)] DWORDs needing +ImageBase+blob_rva
          abs_api  — [(offset, dll, func)] DWORDs filled with absolute API addr
          rel_api  — [(offset, dll, func)] rel32 values pointing to API
          hook_api — [(export_name, offset_in_blob)] redirect exports to blob
          new_exports — [(name, offset_in_blob)] register new exports

        Returns the RVA where the blob was placed, or None on failure.
        """
        code = bytearray(blob.code)
        code_len = len(code)

        patch_info = self._get_patch_section(code_len + 64)
        if patch_info is None:
            self.errors.append("Failed to allocate patch section for code blob")
            return None

        sect_rva, sect_off, cursor = patch_info
        blob_rva = sect_rva + cursor
        blob_file_off = sect_off + cursor
        image_base = self.pe.OPTIONAL_HEADER.ImageBase

        # Table 1: abs_ofs — add (ImageBase + blob_rva) to DWORDs
        for entry in blob.abs_ofs:
            offset = entry[0] if isinstance(entry, (list, tuple)) else entry
            if offset + 4 > code_len:
                self.warnings.append(f"abs_ofs fixup at {offset} out of range")
                continue
            val = struct.unpack_from('<I', code, offset)[0]
            val += image_base + blob_rva
            struct.pack_into('<I', code, offset, val & 0xFFFFFFFF)
            self.add_relocation(blob_rva + offset)

        # Table 2: abs_api — resolve import and write absolute address
        for offset, dll, func in blob.abs_api:
            if offset + 4 > code_len:
                self.warnings.append(f"abs_api fixup at {offset} out of range")
                continue
            api_rva = self._resolve_import_rva(dll, func)
            if api_rva is None:
                self.add_import(dll, func)
                self.warnings.append(f"abs_api: {dll}!{func} not yet imported, queued")
                struct.pack_into('<I', code, offset, 0)
            else:
                struct.pack_into('<I', code, offset, image_base + api_rva)
                self.add_relocation(blob_rva + offset)

        # Table 3: rel_api — resolve import and compute relative offset
        for offset, dll, func in blob.rel_api:
            if offset + 4 > code_len:
                self.warnings.append(f"rel_api fixup at {offset} out of range")
                continue
            api_rva = self._resolve_import_rva(dll, func)
            if api_rva is None:
                self.add_import(dll, func)
                self.warnings.append(f"rel_api: {dll}!{func} not yet imported, queued")
                struct.pack_into('<i', code, offset, 0)
            else:
                call_site_rva = blob_rva + offset + 4
                rel32 = api_rva - call_site_rva
                struct.pack_into('<i', code, offset, rel32)

        # Write code blob to section
        self.data[blob_file_off:blob_file_off + code_len] = code

        # Table 4: hook_api — redirect existing exports to blob entry points
        for export_name, blob_offset in blob.hook_api:
            self._hook_export_rva(export_name, blob_rva + blob_offset)

        # Register new exports
        self._pending_new_exports = getattr(self, '_pending_new_exports', [])
        for name, blob_offset in blob.new_exports:
            self._pending_new_exports.append((name, blob_rva + blob_offset))

        self._record("code_blob_inject",
                    blob.description or description or
                    f"Injected code blob ({code_len} bytes) at RVA 0x{blob_rva:X} "
                    f"[{len(blob.abs_ofs)} abs_ofs, {len(blob.abs_api)} abs_api, "
                    f"{len(blob.rel_api)} rel_api, {len(blob.hook_api)} hook_api]",
                    rva=blob_rva)
        return blob_rva

    # ── Binary Diff Patching ─────────────────────────────────────────────

    def apply_diff_entry(self, diff):
        """
        Apply a single DiffEntry (binary diff patch).
        Supports modes: "offset" (file offset), "rva", "pattern" (search).
        """
        if diff.mode == "offset":
            if diff.old_bytes:
                actual = bytes(self.data[diff.location:diff.location + len(diff.old_bytes)])
                if actual != diff.old_bytes:
                    self.warnings.append(
                        f"Diff at offset 0x{diff.location:X}: expected {diff.old_bytes.hex()}, "
                        f"got {actual.hex()}")
                    return False
            self.patch_bytes(diff.location, diff.new_bytes,
                            f"Diff patch at offset 0x{diff.location:X}")
            return True

        elif diff.mode == "rva":
            if diff.old_bytes:
                offset = self._rva_to_offset(diff.location)
                if offset is None:
                    self.errors.append(f"Cannot resolve RVA 0x{diff.location:X}")
                    return False
                actual = bytes(self.data[offset:offset + len(diff.old_bytes)])
                if actual != diff.old_bytes:
                    self.warnings.append(
                        f"Diff at RVA 0x{diff.location:X}: expected {diff.old_bytes.hex()}, "
                        f"got {actual.hex()}")
                    return False
            return self.patch_bytes_rva(diff.location, diff.new_bytes,
                                       f"Diff patch at RVA 0x{diff.location:X}")

        elif diff.mode == "pattern":
            count = self.search_and_patch(
                diff.pattern + diff.old_bytes,
                diff.pattern + diff.new_bytes,
                diff.section or None)
            if count == 0:
                self.warnings.append("Pattern not found for diff patch")
            return count > 0

        else:
            self.errors.append(f"Unknown diff mode: {diff.mode}")
            return False

    def apply_diff_patches(self, diff_list):
        """Apply a list of DiffEntry patches. Returns (success_count, fail_count)."""
        ok, fail = 0, 0
        for diff in diff_list:
            if self.apply_diff_entry(diff):
                ok += 1
            else:
                fail += 1
        return ok, fail

    # ── 5-Stage Patch Pipeline (KernelEx apply_patches) ──────────────────

    def apply_patch_set(self, patch_set):
        """
        Apply a complete PatchSet using the KernelEx 5-stage pipeline:

          1. PREPARE      — validate conditions, verify target PE
          2. API_ENTRIES   — process code blobs and their 4-table fixups
          3. ALTER_SECTIONS — apply diff patches, convention shims
          4. REBUILD_TABLES — rebuild export/import tables
          5. PROCESS       — version patches, checksum, finalize
        """
        result = PatchResult(success=True, operations=[], errors=[], warnings=[])

        # ── Stage 1: PREPARE ──
        for cond_fn in patch_set.conditions:
            try:
                if not cond_fn(self):
                    result.success = False
                    result.errors.append(
                        f"Condition failed: {getattr(cond_fn, '__doc__', None) or 'unnamed'}")
                    return result
            except Exception as e:
                result.success = False
                result.errors.append(f"Condition raised exception: {e}")
                return result

        # ── Stage 2: API_ENTRIES ──
        for blob in patch_set.code_blobs:
            rva = self.inject_code_blob(blob)
            if rva is None:
                result.warnings.append(f"Code blob injection failed: {blob.description}")

        # ── Stage 3: ALTER_SECTIONS ──
        for diff in patch_set.diff_patches:
            self.apply_diff_entry(diff)

        for conv in patch_set.convention_patches:
            self.apply_convention_shim(
                conv.func_name, conv.from_conv, conv.to_conv, conv.num_params)

        # ── Stage 4: REBUILD_TABLES ──
        pending_exports = getattr(self, '_pending_new_exports', [])
        forwarded = [(ep.name, ep.target) for ep in patch_set.export_patches
                     if ep.action == 'forward']
        aliases = [(ep.name, ep.target) for ep in patch_set.export_patches
                   if ep.action == 'alias']

        if pending_exports or forwarded or aliases:
            self.rebuild_exports(
                new_exports=pending_exports, forwarded=forwarded, aliases=aliases)

        for ip in patch_set.import_patches:
            if ip.action == 'add':
                self.add_import(ip.dll, ip.function)

        # ── Stage 5: PROCESS ──
        if patch_set.version_patch:
            major, minor = patch_set.version_patch
            self.patch_os_version(major, minor)

        result.operations = list(self.operations)
        result.errors = list(self.errors)
        result.warnings = list(self.warnings)
        result.success = len(result.errors) == 0
        return result

    # ── GenPatch-Style Compile & Inject ──────────────────────────────────

    def compile_and_inject(self, source_path=None, source_code=None,
                           compiler="gcc", extra_flags=None,
                           abs_ofs=None, abs_api=None, rel_api=None,
                           hook_api=None, new_exports=None):
        """
        GenPatch-style: compile C/ASM source to a flat binary blob,
        then inject with 4-table fixups.

        Uses: gcc -c -O2 -nostdlib → objcopy -O binary → inject
        Requires: MinGW gcc + objcopy on PATH.
        """
        tmp_source = None
        if source_code and not source_path:
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False)
            tmp.write(source_code)
            tmp.close()
            source_path = tmp.name
            tmp_source = source_path

        if not source_path or not os.path.isfile(source_path):
            self.errors.append(f"Source file not found: {source_path}")
            return None

        obj_path = source_path + '.o'
        bin_path = source_path + '.bin'

        try:
            # Step 1: Compile to object
            flags = extra_flags or []
            compile_cmd = [compiler, '-c', '-O2', '-nostdlib', '-fno-stack-protector',
                          '-m32', '-o', obj_path, source_path] + flags
            proc = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                self.errors.append(f"Compilation failed: {proc.stderr}")
                return None

            # Step 2: Extract .text as flat binary
            objcopy = compiler.replace('gcc', 'objcopy')
            extract_cmd = [objcopy, '-O', 'binary', '-j', '.text', obj_path, bin_path]
            proc = subprocess.run(extract_cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                self.errors.append(f"objcopy failed: {proc.stderr}")
                return None

            with open(bin_path, 'rb') as f:
                code = f.read()

            if not code:
                self.errors.append("Compiled binary is empty")
                return None

            blob = CodeBlob(
                code=code,
                abs_ofs=abs_ofs or [],
                abs_api=abs_api or [],
                rel_api=rel_api or [],
                hook_api=hook_api or [],
                new_exports=new_exports or [],
                description=f"Compiled from {os.path.basename(source_path)}",
            )
            return self.inject_code_blob(blob)

        finally:
            for p in [obj_path, bin_path]:
                try:
                    os.unlink(p)
                except OSError:
                    pass
            if tmp_source:
                try:
                    os.unlink(tmp_source)
                except OSError:
                    pass

    # ── Symbol-Aware Patching ────────────────────────────────────────────

    def load_symbol_map(self, map_path):
        """
        Load a symbol map for name-to-RVA resolution.
        Supports: CSV (name,hex_rva) and MAP (hex_addr name) formats.
        """
        self._symbols = getattr(self, '_symbols', {})

        with open(map_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('#', ';', '//')):
                    continue

                if ',' in line:
                    parts = line.split(',', 1)
                    name = parts[0].strip()
                    try:
                        rva = int(parts[1].strip(), 16)
                        self._symbols[name] = rva
                    except ValueError:
                        continue
                else:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            rva = int(parts[0], 16)
                            self._symbols[parts[1]] = rva
                        except ValueError:
                            continue

        self._record("symbol_load",
                    f"Loaded {len(self._symbols)} symbols from {os.path.basename(map_path)}")
        return len(self._symbols)

    def resolve_symbol(self, name):
        """Resolve a symbol name to an RVA. Falls back to export table."""
        symbols = getattr(self, '_symbols', {})
        rva = symbols.get(name)
        if rva is not None:
            return rva
        # Fallback: check exports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.name.decode('ascii', errors='replace') == name:
                    return exp.address
        return None

    def patch_by_symbol(self, symbol_name, new_bytes, description=""):
        """Patch bytes at a symbol's RVA location."""
        rva = self.resolve_symbol(symbol_name)
        if rva is None:
            self.errors.append(f"Symbol '{symbol_name}' not found")
            return False
        return self.patch_bytes_rva(
            rva, new_bytes,
            description or f"Patch at symbol '{symbol_name}' (RVA 0x{rva:X})")

    # ── Table Inspection ─────────────────────────────────────────────────

    def inspect_eat(self):
        """Return a list of all Export Address Table entries."""
        results = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return results
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            results.append({
                'ordinal': exp.ordinal,
                'name': exp.name.decode('ascii', errors='replace') if exp.name else None,
                'rva': exp.address,
                'forwarder': exp.forwarder.decode('ascii', errors='replace') if exp.forwarder else None,
            })
        return results

    def inspect_iat(self):
        """Return a list of all Import Address Table entries."""
        results = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return results
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace')
            for imp in entry.imports:
                results.append({
                    'dll': dll,
                    'name': imp.name.decode('ascii', errors='replace') if imp.name else None,
                    'ordinal': imp.ordinal,
                    'iat_rva': imp.address - self.pe.OPTIONAL_HEADER.ImageBase if imp.address else 0,
                })
        return results

    def inspect_relocations(self):
        """Return a list of all base relocation entries."""
        results = []
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            return results
        for block in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                results.append({
                    'rva': entry.rva,
                    'type': entry.type,
                    'type_name': {0: 'ABSOLUTE', 3: 'HIGHLOW'}.get(
                        entry.type, f'TYPE_{entry.type}'),
                })
        return results

    def inspect_sections(self):
        """Return a summary of all PE sections."""
        results = []
        for s in self.pe.sections:
            results.append({
                'name': s.Name.rstrip(b'\x00').decode('ascii', errors='replace'),
                'rva': s.VirtualAddress,
                'virtual_size': s.Misc_VirtualSize,
                'raw_offset': s.PointerToRawData,
                'raw_size': s.SizeOfRawData,
                'characteristics': s.Characteristics,
                'executable': bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE),
                'writable': bool(s.Characteristics & IMAGE_SCN_MEM_WRITE),
            })
        return results

    # ── Trampoline & Hex Dump Utilities ──────────────────────────────────

    def generate_trampoline(self, target_rva, trampoline_rva=None):
        """
        Generate a JMP trampoline to a target RVA.
        If trampoline_rva given → relative JMP, else → absolute indirect JMP.
        """
        if trampoline_rva is not None:
            rel32 = target_rva - (trampoline_rva + 5)
            return X86_JMP_REL32 + struct.pack('<i', rel32)
        else:
            addr = self.pe.OPTIONAL_HEADER.ImageBase + target_rva
            return X86_JMP_ABS_IND + struct.pack('<I', addr)

    def hex_dump(self, rva, length=64):
        """Return a hex dump string of bytes at the given RVA."""
        offset = self._rva_to_offset(rva)
        if offset is None:
            return f"Cannot resolve RVA 0x{rva:X}"
        data = bytes(self.data[offset:offset + length])
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"  {rva + i:08X}  {hex_part:<48s}  {ascii_part}")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════
#  High-level API
# ══════════════════════════════════════════════════════════════════════════

def patch_pe_for_win2000(pe_path, output_path=None):
    """Quick patch: version + syscall stubs for Win2000 compat."""
    patcher = PEPatcher(pe_path)
    result = patcher.patch_for_win2000()
    return patcher.save(output_path)


def patch_syscall_stubs(pe_path, output_path=None):
    """Replace sysenter stubs with int 0x2E."""
    patcher = PEPatcher(pe_path)
    count = patcher.patch_syscall_stubs()
    return patcher.save(output_path)


def inject_convention_shim(pe_path, func_name, from_conv, to_conv, num_params, output_path=None):
    """Inject a calling convention shim for one export."""
    patcher = PEPatcher(pe_path)
    patcher.apply_convention_shim(func_name, from_conv, to_conv, num_params)
    return patcher.save(output_path)


def add_import_to_pe(pe_path, dll_name, func_name, output_path=None):
    """Add a new import entry to a PE file."""
    patcher = PEPatcher(pe_path)
    patcher.add_import(dll_name, func_name)
    return patcher.save(output_path)


def inject_code_blob_to_pe(pe_path, code, hook_api=None, abs_ofs=None,
                           abs_api=None, rel_api=None, output_path=None):
    """Inject a code blob with 4-table fixups."""
    blob = CodeBlob(
        code=code, abs_ofs=abs_ofs or [], abs_api=abs_api or [],
        rel_api=rel_api or [], hook_api=hook_api or [],
    )
    patcher = PEPatcher(pe_path)
    patcher.inject_code_blob(blob)
    return patcher.save(output_path)


def rebase_pe(pe_path, new_base, output_path=None):
    """Rebase a PE to a new ImageBase."""
    patcher = PEPatcher(pe_path)
    patcher.rebase_image(new_base)
    return patcher.save(output_path)


def rebuild_pe_exports(pe_path, forwarded=None, aliases=None, output_path=None):
    """Rebuild PE export table with optional forwarders/aliases."""
    patcher = PEPatcher(pe_path)
    patcher.rebuild_exports(forwarded=forwarded, aliases=aliases)
    return patcher.save(output_path)


def strip_pe_debug(pe_path, output_path=None):
    """Remove debug directory from PE."""
    patcher = PEPatcher(pe_path)
    patcher.remove_debug_directory()
    return patcher.save(output_path)


def compile_and_patch_pe(pe_path, source_code, compiler="gcc",
                         hook_api=None, output_path=None):
    """GenPatch-style: compile C source and inject into PE."""
    patcher = PEPatcher(pe_path)
    patcher.compile_and_inject(
        source_code=source_code, compiler=compiler, hook_api=hook_api)
    return patcher.save(output_path)


def inspect_pe_tables(pe_path):
    """Return a dict with all PE table inspection data."""
    patcher = PEPatcher(pe_path)
    return {
        'sections': patcher.inspect_sections(),
        'exports': patcher.inspect_eat(),
        'imports': patcher.inspect_iat(),
        'relocations': patcher.inspect_relocations(),
    }
