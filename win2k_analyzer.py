"""
Win2K NT Internals Analyzer - CLI
==================================
Command-line interface for analyzing Windows 2000 SP4 system DLLs
and comparing them with ReactOS builds.

Usage:
  python win2k_analyzer.py exports <dll_path>                   - Dump export table
  python win2k_analyzer.py imports <dll_path>                   - Dump import table
  python win2k_analyzer.py header <dll_path>                    - Dump PE header info
  python win2k_analyzer.py syscalls <ntdll_path>                - Extract syscall numbers
  python win2k_analyzer.py compare <win2k_dll> <reactos_dll>    - Full comparison
  python win2k_analyzer.py structs [name]                       - Show known NT structures
  python win2k_analyzer.py gen-headers <output_dir>             - Generate C headers
  python win2k_analyzer.py scan <system32_dir>                  - Scan all DLLs in a directory
  python win2k_analyzer.py batch-compare <win2k_dir> <ros_dir>  - Compare all matching DLLs
  python win2k_analyzer.py gen-def <dll_path>                   - Generate .def file
  python win2k_analyzer.py syscall-patch <ntdll_path>           - Generate syscall header
  python win2k_analyzer.py build-script <reactos_dir>           - Generate build script
  python win2k_analyzer.py disasm <dll_path> <function>         - Disassemble a function
  python win2k_analyzer.py behavior <dll_path> <function>       - Analyze function behavior
"""

import argparse
import json
import os
import sys
import glob

from nt_analyzer.pe_analyzer import (
    analyze_exports, analyze_imports, analyze_pe_header,
    save_exports_json, save_imports_json
)
from nt_analyzer.syscall_extractor import (
    extract_syscalls, extract_syscall_table, save_syscall_table
)
from nt_analyzer.comparator import (
    compare_exports, compare_imports, compare_pe_headers,
    full_comparison, save_comparison_report, print_comparison_summary
)
from nt_analyzer.struct_analyzer import (
    get_known_structure, list_known_structures,
    generate_c_header, save_all_headers
)
from nt_analyzer.def_generator import generate_def_file
from nt_analyzer.syscall_patcher import generate_syscall_header
from nt_analyzer.build_generator import generate_rosbe_script, generate_msvc_script, generate_individual_dll_cmake
from nt_analyzer.behavior_analyzer import (
    disassemble_function, detect_api_patterns, compare_functions,
    batch_compare as behavior_batch_compare, scan_all_exports
)
from nt_analyzer.decompiler import (
    decompile, decompile_no_symbols, batch_decompile, X86Decompiler
)
from nt_analyzer.compat_analyzer import (
    compare_compat, analyze_single_pe, get_known_differences, diagnose_bugcheck
)
from nt_analyzer.pe_patcher import (
    PEPatcher, patch_pe_for_win2000, patch_syscall_stubs as patch_sysenter,
    inject_convention_shim, add_import_to_pe
)


def cmd_exports(args):
    """Dump export table."""
    data = analyze_exports(args.dll)
    print(f"\n{'='*70}")
    print(f"  EXPORTS: {data['dll_name']} ({data['total_exports']} exports)")
    print(f"{'='*70}\n")
    print(f"  {'Ordinal':<10} {'Name':<50} {'RVA':<12} {'Forwarded'}")
    print(f"  {'-'*10} {'-'*50} {'-'*12} {'-'*20}")

    for exp in data['exports']:
        name = exp['name'] or f"(ordinal only)"
        fwd = exp['forwarded_to'] or ''
        print(f"  {exp['ordinal']:<10} {name:<50} {hex(exp['rva']):<12} {fwd}")

    if args.output:
        save_exports_json(args.dll, args.output)
        print(f"\n  Saved to: {args.output}")


def cmd_imports(args):
    """Dump import table."""
    data = analyze_imports(args.dll)
    print(f"\n{'='*70}")
    print(f"  IMPORTS: {os.path.basename(args.dll)}")
    print(f"{'='*70}\n")

    for dll_name, funcs in sorted(data.items()):
        print(f"  [{dll_name}] ({len(funcs)} functions)")
        for f in funcs:
            name = f['name'] or f"ordinal #{f['ordinal']}"
            print(f"    {name}")
        print()

    if args.output:
        save_imports_json(args.dll, args.output)
        print(f"  Saved to: {args.output}")


def cmd_header(args):
    """Dump PE header info."""
    info = analyze_pe_header(args.dll)
    print(f"\n{'='*70}")
    print(f"  PE HEADER: {os.path.basename(args.dll)}")
    print(f"{'='*70}\n")

    for key, val in info.items():
        if key == 'sections':
            continue
        print(f"  {key:<35} {val}")

    print(f"\n  SECTIONS:")
    print(f"  {'Name':<10} {'VAddr':<12} {'VSize':<12} {'RawSize':<12} {'Characteristics'}")
    for sec in info.get('sections', []):
        print(f"  {sec['name']:<10} {sec['virtual_address']:<12} {sec['virtual_size']:<12} "
              f"{sec['raw_size']:<12} {sec['characteristics']}")


def cmd_syscalls(args):
    """Extract syscall numbers from ntdll.dll."""
    syscalls = extract_syscalls(args.ntdll)
    print(f"\n{'='*70}")
    print(f"  SYSCALL TABLE: {os.path.basename(args.ntdll)} ({len(syscalls)} syscalls)")
    print(f"{'='*70}\n")
    print(f"  {'Number':<10} {'Hex':<10} {'Name':<45} {'Mechanism'}")
    print(f"  {'-'*10} {'-'*10} {'-'*45} {'-'*20}")

    for sc in syscalls:
        print(f"  {sc['syscall_number']:<10} {sc['syscall_hex']:<10} {sc['name']:<45} {sc['mechanism']}")

    print(f"\n  Total: {len(syscalls)} syscalls found")

    if args.output:
        save_syscall_table(args.ntdll, args.output)
        print(f"  Saved to: {args.output}")


def cmd_compare(args):
    """Compare two DLLs."""
    is_ntdll = 'ntdll' in os.path.basename(args.dll1).lower()
    report = full_comparison(
        args.dll1, args.dll2,
        label1=args.label1 or "Win2000",
        label2=args.label2 or "ReactOS",
        is_ntdll=is_ntdll
    )

    summary = print_comparison_summary(report)
    print(summary)

    # Print detailed ordinal mismatches
    exp = report.get('export_comparison', {})
    mismatches = exp.get('ordinal_mismatches', [])
    if mismatches:
        print(f"\n  ORDINAL MISMATCHES (may break ordinal-based imports):")
        for m in mismatches[:50]:
            l1 = report['label1']
            l2 = report['label2']
            print(f"    {m['name']}: {m.get(f'ordinal_{l1}', '?')} -> {m.get(f'ordinal_{l2}', '?')}")

    # Print functions only in Win2000 (ReactOS must implement these)
    only1_key = f"only_in_{report['label1']}"
    only_in_1 = exp.get(only1_key, [])
    if only_in_1:
        print(f"\n  MISSING IN {report['label2']} (must be implemented):")
        for name in only_in_1[:50]:
            print(f"    {name}")
        if len(only_in_1) > 50:
            print(f"    ... and {len(only_in_1) - 50} more")

    if args.output:
        save_comparison_report(report, args.output)
        print(f"\n  Full report saved to: {args.output}")


def cmd_structs(args):
    """Show known NT structure layouts."""
    if args.name:
        struct_def = get_known_structure(args.name.upper())
        if not struct_def:
            # Try case-insensitive
            for n in list_known_structures():
                if n.upper() == args.name.upper():
                    struct_def = get_known_structure(n)
                    break

        if not struct_def:
            print(f"  Unknown structure: {args.name}")
            print(f"  Known structures: {', '.join(list_known_structures())}")
            return

        print(f"\n{'='*70}")
        print(f"  {struct_def['name']} ({struct_def['os']})")
        print(f"  Total size: 0x{struct_def['size']:X} ({struct_def['size']} bytes)")
        print(f"{'='*70}\n")
        print(f"  {'Offset':<10} {'Size':<8} {'Name':<40} {'Type'}")
        print(f"  {'-'*10} {'-'*8} {'-'*40} {'-'*30}")

        for field in struct_def['fields']:
            print(f"  0x{field['offset']:03X}     0x{field['size']:<5X} {field['name']:<40} {field['type']}")

        if args.c_header:
            print(f"\n  --- C HEADER ---\n")
            print(generate_c_header(struct_def))
    else:
        print(f"\n  Known Windows 2000 SP4 structures:")
        for name in list_known_structures():
            s = get_known_structure(name)
            print(f"    {name:<25} size=0x{s['size']:X} ({s['size']} bytes), {len(s['fields'])} fields")
        print(f"\n  Use: win2k_analyzer.py structs <name> to see details")
        print(f"  Use: win2k_analyzer.py structs <name> --c-header to generate C header")


def cmd_gen_headers(args):
    """Generate C headers for all known structures."""
    files = save_all_headers(args.output_dir)
    print(f"\n  Generated {len(files)} header files in: {args.output_dir}")
    for f in files:
        print(f"    {os.path.basename(f)}")


def cmd_scan(args):
    """Scan a directory for DLLs/SYS files and provide a summary."""
    patterns = ['*.dll', '*.sys', '*.exe']
    files = []
    for pat in patterns:
        files.extend(glob.glob(os.path.join(args.directory, pat)))

    print(f"\n{'='*70}")
    print(f"  SCAN: {args.directory} ({len(files)} PE files)")
    print(f"{'='*70}\n")

    key_files = ['ntdll.dll', 'kernel32.dll', 'shell32.dll', 'user32.dll',
                 'gdi32.dll', 'advapi32.dll', 'ntoskrnl.exe', 'win32k.sys',
                 'ole32.dll', 'rpcrt4.dll', 'msvcrt.dll']

    print(f"  {'File':<25} {'Exports':<10} {'Imports (DLLs)':<18} {'ImageBase':<14} {'Sections'}")
    print(f"  {'-'*25} {'-'*10} {'-'*18} {'-'*14} {'-'*8}")

    for filepath in sorted(files):
        basename = os.path.basename(filepath).lower()
        # Only process key files unless --all is specified
        if not args.all and basename not in key_files:
            continue
        try:
            exp = analyze_exports(filepath)
            imp = analyze_imports(filepath)
            hdr = analyze_pe_header(filepath)
            print(f"  {basename:<25} {exp['total_exports']:<10} {len(imp):<18} "
                  f"{hdr['image_base']:<14} {hdr['number_of_sections']}")
        except Exception as e:
            print(f"  {basename:<25} ERROR: {e}")

    if not args.all:
        print(f"\n  (Showing key files only. Use --all to scan all {len(files)} files)")


def cmd_batch_compare(args):
    """Compare all matching DLLs between two directories."""
    files1 = {}
    for f in glob.glob(os.path.join(args.dir1, '*.dll')) + glob.glob(os.path.join(args.dir1, '*.sys')):
        files1[os.path.basename(f).lower()] = f

    files2 = {}
    for f in glob.glob(os.path.join(args.dir2, '*.dll')) + glob.glob(os.path.join(args.dir2, '*.sys')):
        files2[os.path.basename(f).lower()] = f

    common = set(files1.keys()) & set(files2.keys())
    print(f"\n  Found {len(common)} matching files to compare\n")

    output_dir = args.output or 'comparison_reports'
    os.makedirs(output_dir, exist_ok=True)

    for name in sorted(common):
        print(f"  Comparing {name}...", end=' ')
        try:
            is_ntdll = 'ntdll' in name
            report = full_comparison(
                files1[name], files2[name],
                label1=args.label1 or "Win2000",
                label2=args.label2 or "ReactOS",
                is_ntdll=is_ntdll
            )
            exp = report.get('export_comparison', {})
            print(f"OK - {exp.get('compatibility_pct', 0)}% export compat")

            out_path = os.path.join(output_dir, f"{name}_comparison.json")
            save_comparison_report(report, out_path)
        except Exception as e:
            print(f"ERROR: {e}")

    print(f"\n  Reports saved to: {output_dir}")


def cmd_gen_def(args):
    """Generate .def file from a DLL."""
    output = args.output
    result = generate_def_file(args.dll, output_path=output)
    if output:
        info = result
        print(f"\n  Generated {info['output_path']}")
        print(f"  Library: {info['library']}")
        print(f"  Exports: {info['total_exports']} (named: {info['named_exports']}, noname: {info['noname_exports']})")
    else:
        print(result)


def cmd_syscall_patch(args):
    """Generate syscall header from ntdll.dll."""
    header = generate_syscall_header(args.ntdll, style=args.style)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(header)
        print(f"  Saved syscall header ({args.style}) to {args.output}")
    else:
        print(header)


def cmd_build_script(args):
    """Generate build script."""
    targets = args.targets.split(',') if args.targets else None
    if args.system == 'rosbe':
        script = generate_rosbe_script(args.reactos_dir, targets)
    elif args.system == 'msvc':
        script = generate_msvc_script(args.reactos_dir, targets)
    else:
        t = targets[0] if targets else 'ntdll.dll'
        script = generate_individual_dll_cmake(t, args.reactos_dir)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(script)
        print(f"  Saved build script to {args.output}")
    else:
        print(script)


def cmd_disasm(args):
    """Disassemble an exported function."""
    result = disassemble_function(args.dll, args.function)
    if result is None:
        print(f"  Function '{args.function}' not found in {args.dll}")
    else:
        print(result)


def cmd_behavior(args):
    """Analyze function behavior patterns."""
    if args.compare:
        # Compare mode: two DLLs
        if not args.dll2:
            print("  ERROR: --dll2 required for compare mode", file=sys.stderr)
            return
        result = compare_functions(args.dll, args.dll2, args.function)
        print(result.summary())
    elif args.scan:
        # Scan all exports mode
        categories = scan_all_exports(args.dll, args.max or 200)
        for cat, funcs in sorted(categories.items(), key=lambda x: -len(x[1])):
            print(f"\n  [{cat}] ({len(funcs)} functions)")
            for fname, fdesc in funcs[:20]:
                print(f"    {fname:<48} {fdesc}")
            if len(funcs) > 20:
                print(f"    ... +{len(funcs)-20} more")
    else:
        # Single function pattern detection
        result = detect_api_patterns(args.dll, args.function)
        if result is None:
            print(f"  Function '{args.function}' not found")
        else:
            fp = result['fingerprint']
            print(f"\n  Function: {args.function}")
            print(f"  Instructions: {fp.total_insns}, Blocks: {fp.block_count}")
            if fp.syscall_number is not None:
                print(f"  Syscall: 0x{fp.syscall_number:X}")
            print(f"\n  Patterns:")
            for pt, pd in result['patterns']:
                print(f"    [{pt}] {pd}")
            if fp.api_calls:
                print(f"\n  API calls:")
                for c in fp.api_calls:
                    print(f"    -> {c}")


def cmd_decompile(args):
    """Decompile a function to C pseudocode."""
    func = args.function
    if func.startswith('0x') or func.startswith('0X'):
        func = int(func, 16)
    result = decompile(args.pe, func)
    if result is None:
        print(f"  Function '{args.function}' not found in {args.pe}")
    else:
        print(result)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(result)
            print(f"\n  Saved to {args.output}")


def cmd_discover(args):
    """Discover and decompile functions without symbols."""
    results = decompile_no_symbols(args.pe, max_funcs=args.max)
    print(f"\n  Discovered {len(results)} functions in {args.pe}\n")
    for name, code in results.items():
        print(f"{'='*70}")
        print(code)
        print()
    if args.output:
        with open(args.output, 'w') as f:
            for name, code in results.items():
                f.write(f"{'='*70}\n{code}\n\n")
        print(f"  Saved {len(results)} functions to {args.output}")


def cmd_batch_decompile(args):
    """Batch decompile all exports from a PE."""
    results = batch_decompile(args.pe, max_funcs=args.max)
    print(f"\n  Decompiled {len(results)} functions from {args.pe}\n")
    for name, code in results.items():
        print(f"{'='*70}")
        print(code)
        print()
    if args.output:
        with open(args.output, 'w') as f:
            for name, code in results.items():
                f.write(f"{'='*70}\n{code}\n\n")
        print(f"  Saved {len(results)} functions to {args.output}")


def cmd_compat_analyze(args):
    """Deep compatibility analysis between two PE binaries."""
    label_a = getattr(args, 'label_a', 'Win2000')
    label_b = getattr(args, 'label_b', 'ReactOS/XP')
    max_exports = getattr(args, 'max', 500)
    report = compare_compat(args.pe_a, args.pe_b, label_a, label_b, max_exports)
    print(report.summary())
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report.summary())
        print(f"\n  Saved report to {args.output}")


def cmd_compat_single(args):
    """Analyze a single PE for compatibility characteristics."""
    result = analyze_single_pe(args.pe, getattr(args, 'label', 'Unknown'))
    print(f"\n{'='*70}")
    print(f"  PE COMPATIBILITY PROFILE: {os.path.basename(args.pe)}")
    print(f"{'='*70}")
    print(f"  Type: {result['type']}")
    print(f"  Machine: 0x{result['machine']:04X}")
    print(f"  Subsystem: {result['subsystem']}")
    print(f"  Image Base: 0x{result['image_base']:08X}")
    print(f"  Entry Point: 0x{result['entry_point']:08X}")
    sc = result.get('syscall', {})
    if sc:
        print(f"  Syscall mechanism: {sc.get('mechanism', 'N/A')}")
        print(f"    int 0x2E: {sc.get('int_2e', 0)}, sysenter: {sc.get('sysenter', 0)}")
    convs = result.get('conventions', {})
    if convs:
        fc = sum(1 for c in convs.values() if c.convention == 'fastcall')
        sc_count = sum(1 for c in convs.values() if c.convention == 'stdcall')
        print(f"  Calling conventions: {sc_count} stdcall, {fc} fastcall, {len(convs)-fc-sc_count} other")
    print(f"  Sections:")
    for s in result.get('sections', []):
        print(f"    {s['name']:<10} vsize=0x{s['vsize']:X}  raw=0x{s['rsize']:X}  chars=0x{s['chars']:08X}")


def cmd_compat_known(args):
    """Show known NT version differences."""
    diffs = get_known_differences()
    print(f"\n{'='*70}")
    print(f"  KNOWN NT 5.0 → 5.1 DIFFERENCES")
    print(f"{'='*70}")
    print(f"\n  ── Calling Convention Changes ──")
    for name, info in diffs['calling_convention_changes'].items():
        print(f"    {name}: {info['from']} → {info['to']}")
    print(f"\n  ── HAL Dispatch Removed Defines ──")
    for name, routing in diffs['hal_dispatch_removed_defines'].items():
        print(f"    {name}: was routed through {routing}")
    print(f"\n  ── Macro Differences ──")
    for name, info in diffs['macro_differences'].items():
        print(f"    {name}: {info['desc']}")
    print(f"\n  ── HAL Functions Removed in XP ──")
    for name in diffs['hal_functions_removed']:
        print(f"    {name}")
    print(f"\n  ── IDT Dispatch Changes ──")
    for ver, info in diffs['idt_dispatch_changes'].items():
        print(f"    NT {ver}: {info['desc']}")
    print(f"\n  ── Bugcheck Codes ──")
    for code, info in diffs['compat_bugchecks'].items():
        print(f"    0x{code:08X} {info['name']}: {info['compat_hint']}")


def cmd_bugcheck(args):
    """Diagnose a bugcheck code for compatibility issues."""
    result = diagnose_bugcheck(args.code)
    print(f"\n  Bugcheck: {result['code']}")
    print(f"  Name: {result['name']}")
    if 'description' in result:
        print(f"  Description: {result['description']}")
    print(f"  Compat hint: {result['compat_hint']}")
    if 'known_causes' in result:
        for cause in result['known_causes']:
            print(f"    - {cause}")


def cmd_patch_pe(args):
    """Patch a PE binary for Win2000 compatibility."""
    output = args.output
    if args.quick:
        result = patch_pe_for_win2000(args.pe, output)
    else:
        patcher = PEPatcher(args.pe)
        if args.version:
            parts = args.version.split('.')
            patcher.patch_os_version(int(parts[0]), int(parts[1]))
        if args.syscalls:
            count = patcher.patch_syscall_stubs()
            print(f"  Patched {count} syscall stubs")
        if args.shim:
            parts = args.shim.split(',')
            if len(parts) == 4:
                patcher.apply_convention_shim(parts[0], parts[1], parts[2], int(parts[3]))
        result = patcher.save(output)
    print(f"\n{result.summary()}")


def main():
    parser = argparse.ArgumentParser(
        description='Win2K NT Internals Analyzer - Analyze Windows 2000 SP4 system DLLs for ReactOS compatibility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s exports C:\\WINNT\\system32\\kernel32.dll
  %(prog)s syscalls C:\\WINNT\\system32\\ntdll.dll
  %(prog)s compare C:\\win2k\\ntdll.dll C:\\reactos\\ntdll.dll
  %(prog)s structs PEB --c-header
  %(prog)s compat-analyze C:\\win2k\\ntoskrnl.exe C:\\reactos\\ntoskrnl.exe
  %(prog)s compat-known
  %(prog)s patch-pe --quick C:\\reactos\\ntdll.dll
  %(prog)s bugcheck 0xA5
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # exports
    p = subparsers.add_parser('exports', help='Dump export table from a DLL')
    p.add_argument('dll', help='Path to the DLL file')
    p.add_argument('-o', '--output', help='Save to JSON file')

    # imports
    p = subparsers.add_parser('imports', help='Dump import table from a DLL')
    p.add_argument('dll', help='Path to the DLL file')
    p.add_argument('-o', '--output', help='Save to JSON file')

    # header
    p = subparsers.add_parser('header', help='Dump PE header info')
    p.add_argument('dll', help='Path to the DLL/EXE/SYS file')

    # syscalls
    p = subparsers.add_parser('syscalls', help='Extract syscall numbers from ntdll.dll')
    p.add_argument('ntdll', help='Path to ntdll.dll')
    p.add_argument('-o', '--output', help='Save syscall table to JSON file')

    # compare
    p = subparsers.add_parser('compare', help='Compare two DLLs (Win2000 vs ReactOS)')
    p.add_argument('dll1', help='Path to first DLL (Win2000)')
    p.add_argument('dll2', help='Path to second DLL (ReactOS)')
    p.add_argument('--label1', help='Label for first DLL (default: Win2000)')
    p.add_argument('--label2', help='Label for second DLL (default: ReactOS)')
    p.add_argument('-o', '--output', help='Save full report to JSON file')

    # structs
    p = subparsers.add_parser('structs', help='Show known NT structure layouts')
    p.add_argument('name', nargs='?', help='Structure name (PEB, TEB, KUSER_SHARED_DATA)')
    p.add_argument('--c-header', action='store_true', help='Generate C header output')

    # gen-headers
    p = subparsers.add_parser('gen-headers', help='Generate C header files for all known structures')
    p.add_argument('output_dir', help='Output directory for .h files')

    # scan
    p = subparsers.add_parser('scan', help='Scan a directory for PE files')
    p.add_argument('directory', help='Directory to scan (e.g., C:\\WINNT\\system32)')
    p.add_argument('--all', action='store_true', help='Show all files, not just key ones')

    # batch-compare
    p = subparsers.add_parser('batch-compare', help='Compare all matching DLLs in two directories')
    p.add_argument('dir1', help='First directory (Win2000 DLLs)')
    p.add_argument('dir2', help='Second directory (ReactOS DLLs)')
    p.add_argument('--label1', help='Label for first set (default: Win2000)')
    p.add_argument('--label2', help='Label for second set (default: ReactOS)')
    p.add_argument('-o', '--output', help='Output directory for reports')

    # gen-def
    p = subparsers.add_parser('gen-def', help='Generate .def file from DLL exports')
    p.add_argument('dll', help='Path to the DLL file')
    p.add_argument('-o', '--output', help='Output .def file path (omit to print to stdout)')

    # syscall-patch
    p = subparsers.add_parser('syscall-patch', help='Generate syscall header from ntdll.dll')
    p.add_argument('ntdll', help='Path to ntdll.dll')
    p.add_argument('--style', choices=['napi', 'define', 'asm', 'table'], default='napi',
                   help='Header style (default: napi)')
    p.add_argument('-o', '--output', help='Output file path')

    # build-script
    p = subparsers.add_parser('build-script', help='Generate build script for ReactOS DLLs')
    p.add_argument('reactos_dir', help='Path to ReactOS source tree')
    p.add_argument('--system', choices=['rosbe', 'msvc', 'cmake'], default='rosbe',
                   help='Build system (default: rosbe)')
    p.add_argument('--targets', help='Comma-separated DLL targets (e.g., ntdll.dll,kernel32.dll)')
    p.add_argument('-o', '--output', help='Output script file path')

    # disasm
    p = subparsers.add_parser('disasm', help='Disassemble an exported function')
    p.add_argument('dll', help='Path to the DLL file')
    p.add_argument('function', help='Export function name')

    # behavior
    p = subparsers.add_parser('behavior', help='Analyze function behavior patterns')
    p.add_argument('dll', help='Path to DLL A')
    p.add_argument('function', nargs='?', help='Function name (omit for --scan)')
    p.add_argument('--dll2', help='Path to DLL B (for compare mode)')
    p.add_argument('--compare', action='store_true', help='Compare function between two DLLs')
    p.add_argument('--scan', action='store_true', help='Scan all exports for behavior patterns')
    p.add_argument('--max', type=int, default=200, help='Max functions for scan (default: 200)')

    # decompile
    p = subparsers.add_parser('decompile', help='Decompile an exported function to C pseudocode')
    p.add_argument('pe', help='Path to PE file (.dll/.sys/.exe)')
    p.add_argument('function', help='Exported function name or RVA (hex: 0x1234)')
    p.add_argument('-o', '--output', help='Save pseudocode to file')

    # discover-functions
    p = subparsers.add_parser('discover-functions', help='Discover and decompile functions without symbols')
    p.add_argument('pe', help='Path to PE file (.dll/.sys/.exe)')
    p.add_argument('--max', type=int, default=50, help='Max functions to discover (default: 50)')
    p.add_argument('-o', '--output', help='Save output to file')

    # batch-decompile
    p = subparsers.add_parser('batch-decompile', help='Decompile all exported functions')
    p.add_argument('pe', help='Path to PE file (.dll/.sys/.exe)')
    p.add_argument('--max', type=int, default=100, help='Max functions (default: 100)')
    p.add_argument('-o', '--output', help='Save output to file')

    # compat-analyze
    p = subparsers.add_parser('compat-analyze', help='Deep compatibility analysis between two PE binaries')
    p.add_argument('pe_a', help='First PE file (e.g. Win2000 binary)')
    p.add_argument('pe_b', help='Second PE file (e.g. ReactOS binary)')
    p.add_argument('--label-a', default='Win2000', help='Label for first file')
    p.add_argument('--label-b', default='ReactOS/XP', help='Label for second file')
    p.add_argument('--max', type=int, default=500, help='Max exports to convention-check')
    p.add_argument('-o', '--output', help='Save report to file')

    # compat-single
    p = subparsers.add_parser('compat-single', help='Analyze a single PE for compat characteristics')
    p.add_argument('pe', help='Path to PE file')
    p.add_argument('--label', default='Unknown', help='Version label')

    # compat-known
    p = subparsers.add_parser('compat-known', help='Show known NT 5.0 vs 5.1 differences')

    # bugcheck
    p = subparsers.add_parser('bugcheck', help='Diagnose a bugcheck code for compat issues')
    p.add_argument('code', help='Bugcheck code (hex: 0xA5 or decimal)')

    # patch-pe
    p = subparsers.add_parser('patch-pe', help='Patch a PE binary for Win2000 compatibility')
    p.add_argument('pe', help='Path to PE file to patch')
    p.add_argument('-o', '--output', help='Output path (default: <name>_patched.<ext>)')
    p.add_argument('--quick', action='store_true', help='Quick patch: version + syscalls')
    p.add_argument('--version', help='Set OS version (e.g. 5.0)')
    p.add_argument('--syscalls', action='store_true', help='Patch sysenter to int 0x2E')
    p.add_argument('--shim', help='Add convention shim: funcname,from,to,nparams')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    commands = {
        'exports': cmd_exports,
        'imports': cmd_imports,
        'header': cmd_header,
        'syscalls': cmd_syscalls,
        'compare': cmd_compare,
        'structs': cmd_structs,
        'gen-headers': cmd_gen_headers,
        'scan': cmd_scan,
        'batch-compare': cmd_batch_compare,
        'gen-def': cmd_gen_def,
        'syscall-patch': cmd_syscall_patch,
        'build-script': cmd_build_script,
        'disasm': cmd_disasm,
        'behavior': cmd_behavior,
        'decompile': cmd_decompile,
        'discover-functions': cmd_discover,
        'batch-decompile': cmd_batch_decompile,
        'compat-analyze': cmd_compat_analyze,
        'compat-single': cmd_compat_single,
        'compat-known': cmd_compat_known,
        'bugcheck': cmd_bugcheck,
        'patch-pe': cmd_patch_pe,
    }

    try:
        commands[args.command](args)
    except FileNotFoundError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
