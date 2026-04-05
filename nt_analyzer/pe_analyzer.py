"""
PE Export/Import Table Analyzer
Extracts all exports (name + ordinal + RVA) and imports from PE files.
"""

import pefile
import os
import json


def analyze_exports(pe_path):
    """
    Extract all exports from a PE file.
    Returns list of dicts: {ordinal, name, rva, forwarded_to}
    """
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(f"File not found: {pe_path}")

    pe = pefile.PE(pe_path, fast_load=False)
    exports = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return exports

    dll_name = pe.DIRECTORY_ENTRY_EXPORT.name
    if dll_name:
        dll_name = dll_name.decode('utf-8', errors='replace')

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        entry = {
            'ordinal': exp.ordinal,
            'name': exp.name.decode('utf-8', errors='replace') if exp.name else None,
            'rva': exp.address,
            'forwarded_to': exp.forwarder.decode('utf-8', errors='replace') if exp.forwarder else None,
        }
        exports.append(entry)

    pe.close()
    return {
        'dll_name': dll_name,
        'total_exports': len(exports),
        'exports': sorted(exports, key=lambda x: x['ordinal'])
    }


def analyze_imports(pe_path):
    """
    Extract all imports from a PE file.
    Returns dict of {dll_name: [{name, ordinal, hint}]}
    """
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(f"File not found: {pe_path}")

    pe = pefile.PE(pe_path, fast_load=False)
    imports = {}

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        pe.close()
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='replace')
        funcs = []
        for imp in entry.imports:
            funcs.append({
                'name': imp.name.decode('utf-8', errors='replace') if imp.name else None,
                'ordinal': imp.ordinal if not imp.name else None,
                'hint': imp.hint if hasattr(imp, 'hint') else None,
            })
        imports[dll_name] = sorted(funcs, key=lambda x: x['name'] or '')

    pe.close()
    return imports


def analyze_pe_header(pe_path):
    """
    Extract key PE header info: subsystem, image base, entry point, etc.
    """
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(f"File not found: {pe_path}")

    pe = pefile.PE(pe_path, fast_load=True)

    info = {
        'machine': hex(pe.FILE_HEADER.Machine),
        'machine_str': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, 'UNKNOWN'),
        'number_of_sections': pe.FILE_HEADER.NumberOfSections,
        'timestamp': pe.FILE_HEADER.TimeDateStamp,
        'characteristics': hex(pe.FILE_HEADER.Characteristics),
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        'size_of_image': hex(pe.OPTIONAL_HEADER.SizeOfImage),
        'size_of_headers': hex(pe.OPTIONAL_HEADER.SizeOfHeaders),
        'checksum': hex(pe.OPTIONAL_HEADER.CheckSum),
        'major_os_version': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'minor_os_version': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'major_subsystem_version': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'minor_subsystem_version': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
    }

    # Sections
    sections = []
    for section in pe.sections:
        sections.append({
            'name': section.Name.decode('utf-8', errors='replace').rstrip('\x00'),
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': hex(section.Misc_VirtualSize),
            'raw_size': hex(section.SizeOfRawData),
            'characteristics': hex(section.Characteristics),
        })
    info['sections'] = sections

    pe.close()
    return info


def save_exports_json(pe_path, output_path):
    """Export the export table to a JSON file for later comparison."""
    data = analyze_exports(pe_path)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    return output_path


def save_imports_json(pe_path, output_path):
    """Export the import table to a JSON file for later comparison."""
    data = analyze_imports(pe_path)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    return output_path
