"""
ReactOS Syscall Table Patcher
==============================
Takes extracted Win2000 SP4 syscall numbers and generates patched header files
that ReactOS uses to define its syscall table.

ReactOS defines syscalls in several files:
  - ntoskrnl/include/internal/napi.h       (Nt* syscall numbers)
  - win32ss/user/ntuser/w32ksvc.h          (Win32k syscall numbers)
  - sdk/include/ndk/sysfuncs.h             (alternate syscall defs)

This module generates replacement content for those files with Win2000 numbers.
"""

import os
import json
from .syscall_extractor import extract_syscall_table


def generate_syscall_header(ntdll_path, output_path=None, header_style='napi'):
    """
    Generate a ReactOS-compatible syscall number header from a Win2000 ntdll.dll.

    header_style:
        'napi'     - NTSTATUS NTAPI format (napi.h style)
        'define'   - #define SYS_NtXxx N format (sysfuncs.h style)
        'asm'      - Assembly .equ format for ntdll stubs
        'table'    - C array initializer for syscall dispatch table
    """
    table = extract_syscall_table(ntdll_path)

    if header_style == 'napi':
        content = _gen_napi_header(table, ntdll_path)
    elif header_style == 'define':
        content = _gen_define_header(table, ntdll_path)
    elif header_style == 'asm':
        content = _gen_asm_stubs(table, ntdll_path)
    elif header_style == 'table':
        content = _gen_dispatch_table(table, ntdll_path)
    else:
        raise ValueError(f"Unknown header style: {header_style}")

    if output_path:
        with open(output_path, 'w') as f:
            f.write(content)

    return {
        'content': content,
        'total_syscalls': len(table),
        'output_path': output_path,
        'style': header_style,
    }


def _gen_napi_header(table, source_path):
    """Generate napi.h style: syscall number definitions."""
    lines = []
    lines.append("/*")
    lines.append(f" * NT System Call Numbers - Windows 2000 SP4")
    lines.append(f" * Auto-generated from {os.path.basename(source_path)}")
    lines.append(f" * Total syscalls: {len(table)}")
    lines.append(f" *")
    lines.append(f" * Replace ReactOS napi.h with this file for Win2000 compatibility.")
    lines.append(f" * WARNING: These numbers are ONLY valid for Windows 2000 SP4 (build 2195)")
    lines.append(f" */")
    lines.append("")
    lines.append("#ifndef _WIN2K_SYSCALL_NUMBERS_H")
    lines.append("#define _WIN2K_SYSCALL_NUMBERS_H")
    lines.append("")

    # Group by number ranges for readability
    for num in sorted(table.keys()):
        entry = table[num]
        name = entry['name']
        # ReactOS uses format: #define SYSCALL_NtXxx  0xNNNN
        lines.append(f"#define SYSCALL_{name:<50s} 0x{num:04X}  /* {num} */")

    lines.append("")
    lines.append(f"#define MAX_SYSCALL_NUMBER 0x{max(table.keys()):04X}")
    lines.append(f"#define NUM_SYSCALLS {len(table)}")
    lines.append("")
    lines.append("#endif /* _WIN2K_SYSCALL_NUMBERS_H */")
    lines.append("")

    return '\n'.join(lines)


def _gen_define_header(table, source_path):
    """Generate sysfuncs.h style: simple #define mapping."""
    lines = []
    lines.append(f"/* Windows 2000 SP4 Syscall Definitions */")
    lines.append(f"/* From: {os.path.basename(source_path)} */")
    lines.append("")

    for num in sorted(table.keys()):
        entry = table[num]
        name = entry['name']
        lines.append(f"#define SYS_{name} {num}")

    lines.append("")
    return '\n'.join(lines)


def _gen_asm_stubs(table, source_path):
    """
    Generate assembly syscall stubs for ntdll.dll.
    These use 'int 0x2E' (Windows 2000's syscall mechanism).
    """
    lines = []
    lines.append(f"; NT Syscall Stubs - Windows 2000 SP4 (int 0x2E)")
    lines.append(f"; Auto-generated from {os.path.basename(source_path)}")
    lines.append(f"; Uses int 0x2E (NOT sysenter/KiFastSystemCall)")
    lines.append(f";")
    lines.append(f"; To use: assemble with NASM/MASM and link into ntdll.dll")
    lines.append("")
    lines.append(".386")
    lines.append(".model flat, stdcall")
    lines.append("")
    lines.append(".code")
    lines.append("")

    for num in sorted(table.keys()):
        entry = table[num]
        name = entry['name']
        # Also generate Zw alias
        zw_name = 'Zw' + name[2:] if name.startswith('Nt') else None

        lines.append(f"; Syscall #{num} (0x{num:04X})")
        lines.append(f"PUBLIC {name}")
        if zw_name:
            lines.append(f"PUBLIC {zw_name}")
            lines.append(f"{zw_name}:")
        lines.append(f"{name} PROC")
        lines.append(f"    mov eax, 0{num:04X}h")
        lines.append(f"    lea edx, [esp+4]")
        lines.append(f"    int 2Eh")
        lines.append(f"    ret")
        lines.append(f"{name} ENDP")
        lines.append("")

    lines.append("END")
    lines.append("")
    return '\n'.join(lines)


def _gen_dispatch_table(table, source_path):
    """Generate a C array for kernel syscall dispatch table verification."""
    lines = []
    lines.append(f"/*")
    lines.append(f" * Syscall dispatch table - Windows 2000 SP4")
    lines.append(f" * For verifying that ntoskrnl's KiServiceTable matches")
    lines.append(f" */")
    lines.append("")
    lines.append(f"typedef struct _SYSCALL_ENTRY {{")
    lines.append(f"    ULONG Number;")
    lines.append(f"    PCSTR Name;")
    lines.append(f"}} SYSCALL_ENTRY;")
    lines.append("")
    lines.append(f"static const SYSCALL_ENTRY Win2kSyscallTable[] = {{")

    for num in sorted(table.keys()):
        entry = table[num]
        lines.append(f'    {{ 0x{num:04X}, "{entry["name"]}" }},')

    lines.append(f"}};")
    lines.append(f"")
    lines.append(f"#define WIN2K_SYSCALL_COUNT {len(table)}")
    lines.append("")
    return '\n'.join(lines)


def generate_win32k_syscall_header(win32k_path, output_path=None):
    """
    Generate w32ksvc.h-style header for win32k.sys syscalls.
    Win32k syscalls are in a separate table (W32pServiceTable) with numbers
    starting at 0x1000 (table index 1).

    This requires analyzing win32k.sys's export of W32pServiceTable,
    or extracting from user32/gdi32's syscall stubs.
    """
    # Win32k syscalls are dispatched differently - they're called from
    # user32.dll/gdi32.dll via NtUser*/NtGdi* stubs
    # The syscall number has bit 12 set (0x1000) to indicate win32k table

    from .syscall_extractor import extract_syscalls
    import pefile

    pe = pefile.PE(win32k_path, fast_load=False)

    # Try to find W32pServiceTable and W32pServiceLimit
    service_table_rva = None
    service_limit_rva = None

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            name = exp.name.decode('utf-8', errors='replace')
            if name == 'W32pServiceTable':
                service_table_rva = exp.address
            elif name == 'W32pServiceLimit':
                service_limit_rva = exp.address

    pe.close()

    lines = []
    lines.append(f"/*")
    lines.append(f" * Win32k Syscall Numbers - Windows 2000 SP4")
    lines.append(f" * Auto-generated from {os.path.basename(win32k_path)}")
    lines.append(f" *")
    lines.append(f" * Win32k syscalls use table index 1 (bit 12 set):")
    lines.append(f" *   Syscall number = 0x1000 | index")
    lines.append(f" *")
    lines.append(f" * W32pServiceTable RVA: {hex(service_table_rva) if service_table_rva else 'NOT FOUND'}")
    lines.append(f" * W32pServiceLimit RVA: {hex(service_limit_rva) if service_limit_rva else 'NOT FOUND'}")
    lines.append(f" */")
    lines.append("")
    lines.append("#ifndef _WIN2K_W32KSVC_H")
    lines.append("#define _WIN2K_W32KSVC_H")
    lines.append("")

    if service_table_rva:
        lines.append(f"/* W32pServiceTable found at RVA 0x{service_table_rva:X} */")
        lines.append(f"/* Extract individual NtUser*/NtGdi* numbers from user32.dll/gdi32.dll stubs */")
    else:
        lines.append("/* W32pServiceTable not exported - extract from user32/gdi32 syscall stubs */")

    lines.append("")
    lines.append("/* Known Win2000 SP4 Win32k syscall numbers (NtUser*) */")
    lines.append("/* These must be extracted from user32.dll's syscall stubs */")
    lines.append("")
    lines.append("#endif /* _WIN2K_W32KSVC_H */")
    lines.append("")

    content = '\n'.join(lines)
    if output_path:
        with open(output_path, 'w') as f:
            f.write(content)

    return {
        'content': content,
        'service_table_rva': service_table_rva,
        'service_limit_rva': service_limit_rva,
        'output_path': output_path,
    }


def extract_win32k_syscalls_from_user32(user32_path, gdi32_path=None):
    """
    Extract Win32k syscall numbers from user32.dll and gdi32.dll.
    These DLLs contain NtUser* and NtGdi* syscall stubs that dispatch
    to win32k.sys via the second service table (syscall | 0x1000).
    """
    from .syscall_extractor import extract_syscalls

    results = {}

    # user32: NtUser* stubs
    user_syscalls = extract_syscalls(user32_path)
    for sc in user_syscalls:
        if sc['name'].startswith('NtUser') or sc['name'].startswith('NtGdi'):
            results[sc['name']] = {
                'number': sc['syscall_number'],
                'table_index': sc['syscall_number'] & 0xFFF,
                'is_win32k': bool(sc['syscall_number'] & 0x1000),
                'source': 'user32.dll',
                'mechanism': sc['mechanism'],
            }

    # gdi32: NtGdi* stubs
    if gdi32_path:
        gdi_syscalls = extract_syscalls(gdi32_path)
        for sc in gdi_syscalls:
            if sc['name'].startswith('NtGdi') or sc['name'].startswith('NtUser'):
                if sc['name'] not in results:
                    results[sc['name']] = {
                        'number': sc['syscall_number'],
                        'table_index': sc['syscall_number'] & 0xFFF,
                        'is_win32k': bool(sc['syscall_number'] & 0x1000),
                        'source': 'gdi32.dll',
                        'mechanism': sc['mechanism'],
                    }

    return results
