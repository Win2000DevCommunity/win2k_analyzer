"""
DEF File Generator
==================
Auto-generates .def files from Win2000 DLLs so that when ReactOS DLLs
are linked, ordinals and exports match the originals exactly.

The .def file is what the linker uses to assign ordinal numbers and
control which functions are exported. If ReactOS uses a different .def
than Win2000, the ordinals won't match and ordinal-based imports break.
"""

import os
import pefile


def generate_def_file(pe_path, output_path=None, dll_name_override=None):
    """
    Generate a .def file from a PE DLL with exact ordinal assignments.

    Args:
        pe_path: Path to the Win2000 DLL
        output_path: Where to write the .def file (default: same name .def)
        dll_name_override: Override the LIBRARY name (e.g., "kernel32.dll")

    Returns: path to generated .def file
    """
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(f"File not found: {pe_path}")

    pe = pefile.PE(pe_path, fast_load=False)

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        pe.close()
        raise ValueError(f"{pe_path} has no export directory")

    # Get library name
    lib_name = dll_name_override
    if not lib_name:
        lib_name = pe.DIRECTORY_ENTRY_EXPORT.name
        if lib_name:
            lib_name = lib_name.decode('utf-8', errors='replace')
        else:
            lib_name = os.path.splitext(os.path.basename(pe_path))[0]

    # Remove extension for LIBRARY directive
    lib_base = os.path.splitext(lib_name)[0] if '.' in lib_name else lib_name

    # Collect exports
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode('utf-8', errors='replace') if exp.name else None
        forwarded = exp.forwarder.decode('utf-8', errors='replace') if exp.forwarder else None
        exports.append({
            'ordinal': exp.ordinal,
            'name': name,
            'rva': exp.address,
            'forwarded': forwarded,
        })

    pe.close()
    exports.sort(key=lambda x: x['ordinal'])

    # Generate .def content
    lines = []
    lines.append(f"; Generated from {os.path.basename(pe_path)}")
    lines.append(f"; For Windows 2000 SP4 ordinal compatibility")
    lines.append(f"; Total exports: {len(exports)}")
    lines.append(f";")
    lines.append(f"LIBRARY {lib_base}")
    lines.append(f"EXPORTS")

    # Track which ordinals are named vs unnamed
    noname_count = 0
    for exp in exports:
        parts = []

        if exp['name']:
            parts.append(f"    {exp['name']}")
        else:
            # Unnamed export - still need to reserve the ordinal
            parts.append(f"    ord{exp['ordinal']}")
            noname_count += 1

        # Always specify ordinal explicitly
        parts.append(f" @{exp['ordinal']}")

        # If no name, mark NONAME so linker doesn't put the placeholder in name table
        if not exp['name']:
            parts.append(" NONAME")

        # Handle forwarders - comment them since .def can't forward directly
        # ReactOS linker forwarder syntax
        if exp['forwarded']:
            # Forwarder format: "NTDLL.RtlAcquireSRWLockExclusive" -> we write as comment
            # and add the = redirect syntax
            fwd = exp['forwarded']
            # Convert "NTDLL.RtlFoo" to module.function format for linker
            parts.append(f"  ; FORWARDER -> {fwd}")

        lines.append(''.join(parts))

    content = '\n'.join(lines) + '\n'

    # Output
    if output_path is None:
        # If no explicit path, just return the content string
        return content

    with open(output_path, 'w') as f:
        f.write(content)

    return {
        'output_path': output_path,
        'library': lib_base,
        'total_exports': len(exports),
        'named_exports': len(exports) - noname_count,
        'noname_exports': noname_count,
        'forwarded_exports': sum(1 for e in exports if e['forwarded']),
        'content': content,
    }


def generate_def_for_directory(dir_path, output_dir=None, target_dlls=None):
    """
    Generate .def files for all DLLs in a directory (or specific targets).

    Args:
        dir_path: Directory containing Win2000 DLLs
        output_dir: Where to write .def files (default: dir_path/def_files/)
        target_dlls: List of specific DLL names to process (default: all)

    Returns: list of result dicts
    """
    if not output_dir:
        output_dir = os.path.join(dir_path, 'def_files')
    os.makedirs(output_dir, exist_ok=True)

    results = []
    for fname in sorted(os.listdir(dir_path)):
        if not fname.lower().endswith(('.dll', '.sys', '.exe')):
            continue
        if target_dlls and fname.lower() not in [t.lower() for t in target_dlls]:
            continue

        pe_path = os.path.join(dir_path, fname)
        def_path = os.path.join(output_dir, os.path.splitext(fname)[0] + '.def')

        try:
            result = generate_def_file(pe_path, def_path)
            result['source_file'] = fname
            result['status'] = 'ok'
            results.append(result)
        except Exception as e:
            results.append({
                'source_file': fname,
                'status': 'error',
                'error': str(e),
            })

    return results


def compare_def_with_reactos(win2k_def_path, reactos_def_path):
    """
    Compare a Win2000-generated .def with ReactOS's existing .def file.
    Returns differences that need to be corrected in ReactOS.
    """
    def parse_def(path):
        """Parse a .def file into {name: ordinal} and {ordinal: name} maps."""
        exports_by_name = {}
        exports_by_ord = {}
        with open(path, 'r') as f:
            in_exports = False
            for line in f:
                line = line.strip()
                if line.upper().startswith('EXPORTS'):
                    in_exports = True
                    continue
                if not in_exports or not line or line.startswith(';'):
                    continue

                # Parse: FunctionName @ordinal [NONAME] [DATA] [PRIVATE]
                parts = line.split(';')[0].strip()  # Remove comments
                if not parts:
                    continue

                tokens = parts.split()
                if not tokens:
                    continue

                name = tokens[0]
                ordinal = None
                noname = 'NONAME' in [t.upper() for t in tokens]

                for t in tokens:
                    if t.startswith('@'):
                        try:
                            ordinal = int(t[1:])
                        except ValueError:
                            pass

                if ordinal is not None:
                    exports_by_name[name] = ordinal
                    exports_by_ord[ordinal] = name

        return exports_by_name, exports_by_ord

    w_name, w_ord = parse_def(win2k_def_path)
    r_name, r_ord = parse_def(reactos_def_path)

    # Find ordinal mismatches
    ordinal_fixes = []
    common = set(w_name.keys()) & set(r_name.keys())
    for name in sorted(common):
        if w_name[name] != r_name[name]:
            ordinal_fixes.append({
                'name': name,
                'win2k_ordinal': w_name[name],
                'reactos_ordinal': r_name[name],
            })

    missing_in_reactos = sorted(set(w_name.keys()) - set(r_name.keys()))
    extra_in_reactos = sorted(set(r_name.keys()) - set(w_name.keys()))

    return {
        'ordinal_fixes_needed': ordinal_fixes,
        'missing_in_reactos': missing_in_reactos,
        'extra_in_reactos': extra_in_reactos,
        'total_common': len(common),
        'total_ordinal_matches': len(common) - len(ordinal_fixes),
    }
