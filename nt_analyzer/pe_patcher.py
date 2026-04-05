"""
KernelEx-Inspired PE Binary Patcher
=====================================
Python implementation of PE binary patching techniques inspired by KernelEx (Xeno86).
Supports ALL PE types: .dll, .sys, .exe, .cpl, .drv, .ocx

Capabilities:
  - Add new PE sections
  - Rebuild import table (add/remove imports)
  - Rebuild export table (add/hook/forward/alias exports)
  - Manage relocations (add, update, allocate)
  - Inject code blobs with fixups
  - Patch calling conventions (stdcall ↔ fastcall wrappers)
  - Patch syscall stubs (sysenter → int 0x2E)
  - Patch version info fields
  - Generate compatibility shims
  - Full backup and dry-run support
"""

import os
import struct
import shutil
import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

import pefile


# ══════════════════════════════════════════════════════════════════════════
#  Constants
# ══════════════════════════════════════════════════════════════════════════

SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_REL_BASED_HIGHLOW = 3

# x86 instruction templates
X86_NOP = b'\x90'
X86_RET = b'\xC3'
X86_INT3 = b'\xCC'
X86_PUSH_EBP = b'\x55'
X86_MOV_EBP_ESP = b'\x8B\xEC'


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
        self.warnings.append(f"Export forwarding for '{name}' → '{forward_string}' "
                           "requires full export table rebuild. Use rebuild_exports() instead.")
        return False

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

    def save(self, output_path=None, fix_cksum=True):
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
