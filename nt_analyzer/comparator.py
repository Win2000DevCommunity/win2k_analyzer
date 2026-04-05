"""
DLL Comparison Engine
=====================
Side-by-side comparison of Win2000 vs ReactOS DLLs.
Compares exports, imports, PE headers, and syscall tables.
Generates a full compatibility report.
"""

import json
import os
from .pe_analyzer import analyze_exports, analyze_imports, analyze_pe_header
from .syscall_extractor import extract_syscall_table, compare_syscall_tables


def compare_exports(dll_path_1, dll_path_2, label1="Win2000", label2="ReactOS"):
    """
    Compare export tables of two DLLs.
    Returns detailed comparison with matching, missing, and extra exports.
    """
    exp1 = analyze_exports(dll_path_1)
    exp2 = analyze_exports(dll_path_2)

    names1 = {e['name']: e for e in exp1['exports'] if e['name']}
    names2 = {e['name']: e for e in exp2['exports'] if e['name']}

    ordinals1 = {e['ordinal']: e for e in exp1['exports']}
    ordinals2 = {e['ordinal']: e for e in exp2['exports']}

    common = set(names1.keys()) & set(names2.keys())
    only_in_1 = set(names1.keys()) - set(names2.keys())
    only_in_2 = set(names2.keys()) - set(names1.keys())

    # Check ordinal mismatches for common exports
    ordinal_mismatches = []
    ordinal_matches = []
    for name in sorted(common):
        e1 = names1[name]
        e2 = names2[name]
        if e1['ordinal'] != e2['ordinal']:
            ordinal_mismatches.append({
                'name': name,
                f'ordinal_{label1}': e1['ordinal'],
                f'ordinal_{label2}': e2['ordinal'],
            })
        else:
            ordinal_matches.append({
                'name': name,
                'ordinal': e1['ordinal'],
            })

    return {
        'label1': label1,
        'label2': label2,
        'total_1': exp1['total_exports'],
        'total_2': exp2['total_exports'],
        'common_by_name': len(common),
        'ordinal_matches': len(ordinal_matches),
        'ordinal_mismatches': ordinal_mismatches,
        f'only_in_{label1}': sorted(only_in_1),
        f'only_in_{label2}': sorted(only_in_2),
        'compatibility_pct': round(len(common) / max(exp1['total_exports'], 1) * 100, 1),
    }


def compare_imports(dll_path_1, dll_path_2, label1="Win2000", label2="ReactOS"):
    """
    Compare import tables of two DLLs.
    Shows which DLLs and functions each imports.
    """
    imp1 = analyze_imports(dll_path_1)
    imp2 = analyze_imports(dll_path_2)

    dlls_1 = set(imp1.keys())
    dlls_2 = set(imp2.keys())

    common_dlls = dlls_1 & dlls_2
    only_in_1 = dlls_1 - dlls_2
    only_in_2 = dlls_2 - dlls_1

    # Per-DLL function comparison
    dll_comparison = {}
    for dll in sorted(common_dlls):
        funcs1 = {f['name'] for f in imp1[dll] if f['name']}
        funcs2 = {f['name'] for f in imp2[dll] if f['name']}
        dll_comparison[dll] = {
            'common': sorted(funcs1 & funcs2),
            f'only_in_{label1}': sorted(funcs1 - funcs2),
            f'only_in_{label2}': sorted(funcs2 - funcs1),
        }

    return {
        'label1': label1,
        'label2': label2,
        f'imported_dlls_{label1}': sorted(dlls_1),
        f'imported_dlls_{label2}': sorted(dlls_2),
        'common_dlls': sorted(common_dlls),
        f'dlls_only_in_{label1}': sorted(only_in_1),
        f'dlls_only_in_{label2}': sorted(only_in_2),
        'per_dll_comparison': dll_comparison,
    }


def compare_pe_headers(dll_path_1, dll_path_2, label1="Win2000", label2="ReactOS"):
    """Compare PE headers of two DLLs."""
    h1 = analyze_pe_header(dll_path_1)
    h2 = analyze_pe_header(dll_path_2)

    differences = {}
    matches = {}

    # Compare scalar fields
    skip_fields = ['sections']
    for key in h1:
        if key in skip_fields:
            continue
        if h1[key] != h2.get(key):
            differences[key] = {label1: h1[key], label2: h2.get(key)}
        else:
            matches[key] = h1[key]

    return {
        'matching_fields': matches,
        'differing_fields': differences,
        f'sections_{label1}': h1.get('sections', []),
        f'sections_{label2}': h2.get('sections', []),
    }


def full_comparison(dll_path_1, dll_path_2, label1="Win2000", label2="ReactOS", is_ntdll=False):
    """
    Run a complete comparison between two DLLs.
    If is_ntdll=True, also compares syscall tables.
    """
    report = {
        'file1': os.path.basename(dll_path_1),
        'file2': os.path.basename(dll_path_2),
        'label1': label1,
        'label2': label2,
        'pe_header_comparison': compare_pe_headers(dll_path_1, dll_path_2, label1, label2),
        'export_comparison': compare_exports(dll_path_1, dll_path_2, label1, label2),
        'import_comparison': compare_imports(dll_path_1, dll_path_2, label1, label2),
    }

    if is_ntdll:
        table1 = extract_syscall_table(dll_path_1)
        table2 = extract_syscall_table(dll_path_2)
        report['syscall_comparison'] = compare_syscall_tables(table1, table2)

    return report


def save_comparison_report(report, output_path):
    """Save a comparison report to JSON."""
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    return output_path


def print_comparison_summary(report):
    """Print a human-readable summary of a comparison report."""
    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f"  COMPARISON: {report['file1']} ({report['label1']}) vs {report['file2']} ({report['label2']})")
    lines.append(f"{'='*70}")

    # Export summary
    exp = report.get('export_comparison', {})
    lines.append(f"\n  EXPORTS:")
    lines.append(f"    {report['label1']}: {exp.get('total_1', 0)} exports")
    lines.append(f"    {report['label2']}: {exp.get('total_2', 0)} exports")
    lines.append(f"    Common (by name): {exp.get('common_by_name', 0)}")
    lines.append(f"    Ordinal matches: {exp.get('ordinal_matches', 0)}")
    lines.append(f"    Ordinal mismatches: {len(exp.get('ordinal_mismatches', []))}")
    lines.append(f"    Compatibility: {exp.get('compatibility_pct', 0)}%")

    only1_key = f"only_in_{report['label1']}"
    only2_key = f"only_in_{report['label2']}"
    if exp.get(only1_key):
        lines.append(f"    Only in {report['label1']}: {len(exp[only1_key])} functions")
    if exp.get(only2_key):
        lines.append(f"    Only in {report['label2']}: {len(exp[only2_key])} functions")

    # Import summary
    imp = report.get('import_comparison', {})
    lines.append(f"\n  IMPORTS:")
    lines.append(f"    Common DLLs: {len(imp.get('common_dlls', []))}")
    dlls_only1 = f"dlls_only_in_{report['label1']}"
    dlls_only2 = f"dlls_only_in_{report['label2']}"
    if imp.get(dlls_only1):
        lines.append(f"    DLLs only in {report['label1']}: {', '.join(imp[dlls_only1])}")
    if imp.get(dlls_only2):
        lines.append(f"    DLLs only in {report['label2']}: {', '.join(imp[dlls_only2])}")

    # PE header diffs
    pe = report.get('pe_header_comparison', {})
    diffs = pe.get('differing_fields', {})
    if diffs:
        lines.append(f"\n  PE HEADER DIFFERENCES:")
        for field, vals in diffs.items():
            lines.append(f"    {field}: {vals.get(report['label1'])} -> {vals.get(report['label2'])}")

    # Syscall comparison
    sc = report.get('syscall_comparison')
    if sc:
        lines.append(f"\n  SYSCALL TABLE:")
        lines.append(f"    Matching syscall numbers: {sc['matching_count']}")
        lines.append(f"    Mismatched syscall numbers: {sc['mismatched_count']}")
        lines.append(f"    Only in {report['label1']}: {sc['only_in_first_count']}")
        lines.append(f"    Only in {report['label2']}: {sc['only_in_second_count']}")
        if sc['mismatched']:
            lines.append(f"\n    MISMATCHED SYSCALLS (need patching!):")
            for m in sc['mismatched'][:30]:
                lines.append(f"      {m['name']}: {m['number_first']} -> {m['number_second']} (delta: {m['delta']:+d})")
            if len(sc['mismatched']) > 30:
                lines.append(f"      ... and {len(sc['mismatched']) - 30} more")

    lines.append(f"\n{'='*70}\n")
    return '\n'.join(lines)
