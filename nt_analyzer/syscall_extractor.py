"""
NT Syscall Extractor
====================
Extracts syscall numbers from ntdll.dll by disassembling Nt*/Zw* export stubs.

Supports:
  - Windows 2000 pattern: mov eax, NUM; lea edx, [esp+4]; int 0x2E; ret
  - Windows XP+ pattern:  mov eax, NUM; mov edx, 0x7FFE0300; call [edx]; ret
  - ReactOS patterns (both styles)
"""

import pefile
import struct
import json
import os


# Syscall stub patterns (x86 32-bit)
# Win2000: B8 XX XX 00 00 ... CD 2E ... C2 XX XX
# WinXP:   B8 XX XX 00 00 BA 00 03 FE 7F FF 12 C2 XX XX
# Also:    B8 XX XX 00 00 ... 8D 54 24 04 CD 2E C2 XX XX


def extract_syscalls(ntdll_path):
    """
    Extract syscall numbers from ntdll.dll.
    Reads each Nt*/Zw* export, disassembles the stub, and pulls the syscall number.

    Returns: list of {name, syscall_number, mechanism, raw_bytes_hex}
    """
    if not os.path.isfile(ntdll_path):
        raise FileNotFoundError(f"File not found: {ntdll_path}")

    pe = pefile.PE(ntdll_path, fast_load=False)

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        pe.close()
        return []

    syscalls = []

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue

        name = exp.name.decode('utf-8', errors='replace')

        # Only analyze Nt* and Zw* functions (syscall stubs)
        if not (name.startswith('Nt') or name.startswith('Zw')):
            continue

        # Skip NtDll* helper functions (not syscalls)
        if name.startswith('NtDll') or name.startswith('Ntdll'):
            continue

        rva = exp.address
        try:
            # Read up to 32 bytes of the stub - that's more than enough
            offset = pe.get_offset_from_rva(rva)
            stub_bytes = pe.get_data(rva, 32)
        except Exception:
            continue

        syscall_info = _parse_syscall_stub(name, stub_bytes)
        if syscall_info:
            syscalls.append(syscall_info)

    pe.close()

    # Sort by syscall number
    syscalls.sort(key=lambda x: x['syscall_number'])
    return syscalls


def _parse_syscall_stub(name, stub_bytes):
    """
    Parse a syscall stub and extract the syscall number and mechanism.
    Supports x86 (Win2000/XP) and x64 (Vista+) patterns.
    """
    if len(stub_bytes) < 7:
        return None

    # x64 pattern: 4C 8B D1 B8 XX XX 00 00 ... 0F 05 ... C3
    # (mov r10, rcx; mov eax, NUM; ... syscall; ... ret)
    if stub_bytes[0] == 0x4C and stub_bytes[1] == 0x8B and stub_bytes[2] == 0xD1:
        if stub_bytes[3] == 0xB8:
            syscall_num = struct.unpack('<I', stub_bytes[4:8])[0]
            mechanism = 'unknown'
            for i in range(8, min(len(stub_bytes) - 1, 28)):
                if stub_bytes[i] == 0x0F and stub_bytes[i + 1] == 0x05:
                    mechanism = 'syscall (x64)'
                    break
                if stub_bytes[i] == 0xCD and stub_bytes[i + 1] == 0x2E:
                    mechanism = 'int 0x2E (x64 compat)'
                    break
            return {
                'name': name,
                'syscall_number': syscall_num,
                'syscall_hex': hex(syscall_num),
                'mechanism': mechanism,
                'raw_bytes_hex': stub_bytes[:20].hex(' '),
            }

    # x86 pattern: B8 XX XX XX XX (mov eax, imm32)
    if stub_bytes[0] == 0xB8:
        syscall_num = struct.unpack('<I', stub_bytes[1:5])[0]

        # Determine mechanism by scanning for int 0x2E (CD 2E) or sysenter (0F 34)
        mechanism = 'unknown'
        for i in range(5, min(len(stub_bytes) - 1, 28)):
            if stub_bytes[i] == 0xCD and stub_bytes[i + 1] == 0x2E:
                mechanism = 'int 0x2E'
                break
            if stub_bytes[i] == 0x0F and stub_bytes[i + 1] == 0x34:
                mechanism = 'sysenter'
                break
            # call dword ptr [edx] (FF 12) -> KiFastSystemCall
            if stub_bytes[i] == 0xFF and stub_bytes[i + 1] == 0x12:
                mechanism = 'KiFastSystemCall'
                break
            # call dword ptr [0x7FFE0300] (FF 15 00 03 FE 7F)
            if stub_bytes[i] == 0xFF and stub_bytes[i + 1] == 0x15:
                mechanism = 'KiFastSystemCall (indirect)'
                break
            # jmp to shared user data
            if stub_bytes[i] == 0xE9 or stub_bytes[i] == 0xEB:
                mechanism = 'jmp (patched/hooked?)'
                break

        return {
            'name': name,
            'syscall_number': syscall_num,
            'syscall_hex': hex(syscall_num),
            'mechanism': mechanism,
            'raw_bytes_hex': stub_bytes[:20].hex(' '),
        }

    return None


def extract_syscall_table(ntdll_path):
    """
    Build a clean syscall number -> function name mapping.
    Only includes Nt* functions (Zw* are duplicates with same numbers).
    """
    all_syscalls = extract_syscalls(ntdll_path)

    # Prefer Nt* names, but include Zw* if no Nt* counterpart
    nt_funcs = {}
    zw_funcs = {}

    for sc in all_syscalls:
        if sc['name'].startswith('Nt'):
            nt_funcs[sc['syscall_number']] = sc
        elif sc['name'].startswith('Zw'):
            zw_funcs[sc['syscall_number']] = sc

    # Merge: prefer Nt* names
    table = {}
    all_nums = set(list(nt_funcs.keys()) + list(zw_funcs.keys()))
    for num in sorted(all_nums):
        if num in nt_funcs:
            entry = nt_funcs[num]
        else:
            entry = zw_funcs[num]
        table[num] = {
            'name': entry['name'],
            'mechanism': entry['mechanism'],
            'has_zw_pair': num in zw_funcs,
        }

    return table


def save_syscall_table(ntdll_path, output_path):
    """Save the syscall table to JSON for later comparison."""
    table = extract_syscall_table(ntdll_path)
    # Convert int keys to strings for JSON
    json_table = {str(k): v for k, v in table.items()}

    data = {
        'source_file': os.path.basename(ntdll_path),
        'total_syscalls': len(json_table),
        'syscalls': json_table,
    }

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    return output_path


def compare_syscall_tables(table1, table2):
    """
    Compare two syscall tables (from extract_syscall_table).
    Returns: {matching, mismatched, only_in_first, only_in_second}
    """
    nums1 = set(table1.keys())
    nums2 = set(table2.keys())

    # Functions in both (by name)
    names1 = {v['name']: k for k, v in table1.items()}
    names2 = {v['name']: k for k, v in table2.items()}

    common_names = set(names1.keys()) & set(names2.keys())
    only_in_first_names = set(names1.keys()) - set(names2.keys())
    only_in_second_names = set(names2.keys()) - set(names1.keys())

    matching = []
    mismatched = []

    for name in sorted(common_names):
        num1 = names1[name]
        num2 = names2[name]
        if num1 == num2:
            matching.append({
                'name': name,
                'syscall_number': num1,
            })
        else:
            mismatched.append({
                'name': name,
                'number_first': num1,
                'number_second': num2,
                'delta': num2 - num1,
            })

    return {
        'matching_count': len(matching),
        'mismatched_count': len(mismatched),
        'only_in_first_count': len(only_in_first_names),
        'only_in_second_count': len(only_in_second_names),
        'matching': matching,
        'mismatched': mismatched,
        'only_in_first': sorted(only_in_first_names),
        'only_in_second': sorted(only_in_second_names),
    }
