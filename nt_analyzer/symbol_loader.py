"""
Symbol Loader — .map / .pdb / .sym file parser
=================================================
Loads debug symbols from multiple formats and returns a dict of {VA: name}
compatible with X86Decompiler(symbols=...) and behavior_analyzer.

Supported formats:
  - Microsoft linker .map files   (link.exe /MAP output)
  - GCC/MinGW .map files          (ld -Map output)
  - IDA Pro .map files             (File → Produce → MAP file)
  - Simple .sym files              (address<tab>name per line)
  - PDB files                      (via pdbparse if installed)
  - DBG files                      (COFF debug symbol section)
"""

import os
import re
import struct
from collections import OrderedDict


# ---------------------------------------------------------------------------
#  .MAP file parsing — Microsoft LINK.EXE format
# ---------------------------------------------------------------------------

_MSVC_MAP_ADDR = re.compile(
    r'^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8})\s+'   # section:offset
    r'(\S+)\s+'                                      # symbol name
    r'([0-9a-fA-F]{8})',                             # flat address / RVA
    re.MULTILINE
)

_MSVC_MAP_SECTION = re.compile(
    r'^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8})\s+'
    r'([0-9a-fA-F]+)[Hh]\s+'                        # length
    r'(\S+)',                                         # section name
    re.MULTILINE
)

_MSVC_MAP_PREFERRED = re.compile(
    r'Preferred load address is\s+([0-9a-fA-F]+)',
    re.IGNORECASE
)


def load_map_file(map_path, image_base=None):
    """
    Parse a Microsoft or IDA .map file.

    Returns:
        dict of {virtual_address: symbol_name}
        metadata dict with 'image_base', 'entry_point', 'section_count'
    """
    with open(map_path, 'r', errors='replace') as f:
        content = f.read()

    symbols = {}
    meta = {'source': os.path.basename(map_path), 'format': 'unknown'}

    # Try to detect the preferred load address
    m = _MSVC_MAP_PREFERRED.search(content)
    if m:
        detected_base = int(m.group(1), 16)
        if image_base is None:
            image_base = detected_base
        meta['image_base'] = detected_base
        meta['format'] = 'msvc_map'

    # Parse Microsoft/IDA format: SSSS:OOOOOOOO  name  AAAAAAAA
    for match in _MSVC_MAP_ADDR.finditer(content):
        section = int(match.group(1), 16)
        offset = int(match.group(2), 16)
        name = match.group(3)
        flat_addr = int(match.group(4), 16)

        # Clean up decorated names
        clean_name = _undecorate(name)

        if image_base is not None:
            va = image_base + flat_addr
        else:
            va = flat_addr

        symbols[va] = clean_name

    # If no MSVC matches, try GCC/MinGW format
    if not symbols:
        symbols, meta = _parse_gcc_map(content, image_base)

    # If still nothing, try simple IDA format (just addr name)
    if not symbols:
        symbols, meta = _parse_ida_simple_map(content, image_base)

    meta['total_symbols'] = len(symbols)
    return symbols, meta


# ---------------------------------------------------------------------------
#  GCC/MinGW ld -Map format
# ---------------------------------------------------------------------------

_GCC_SYMBOL = re.compile(
    r'^\s+0x([0-9a-fA-F]{8,16})\s+(\S+)\s*$',
    re.MULTILINE
)


def _parse_gcc_map(content, image_base=None):
    """Parse a GCC/MinGW linker map."""
    symbols = {}
    meta = {'format': 'gcc_map'}

    for match in _GCC_SYMBOL.finditer(content):
        addr = int(match.group(1), 16)
        name = match.group(2)
        if name.startswith('.') or name.startswith('LOAD') or '=' in name:
            continue
        clean = _undecorate(name)
        symbols[addr] = clean

    meta['total_symbols'] = len(symbols)
    return symbols, meta


# ---------------------------------------------------------------------------
#  IDA Pro simple .map format
# ---------------------------------------------------------------------------

_IDA_SIMPLE = re.compile(
    r'^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{4,8})\s+(\S+)\s*$',
    re.MULTILINE
)


def _parse_ida_simple_map(content, image_base=None):
    """Parse IDA simple map (segment:offset name)."""
    symbols = {}
    meta = {'format': 'ida_map'}
    base = image_base or 0

    for match in _IDA_SIMPLE.finditer(content):
        seg = int(match.group(1), 16)
        ofs = int(match.group(2), 16)
        name = match.group(3)
        # IDA typically uses section 0001 = .text starting at image_base
        va = base + ofs
        symbols[va] = _undecorate(name)

    meta['total_symbols'] = len(symbols)
    return symbols, meta


# ---------------------------------------------------------------------------
#  Simple .sym format (addr<TAB>name or addr<SPACE>name)
# ---------------------------------------------------------------------------

_SYM_LINE = re.compile(r'^([0-9a-fA-F]{4,16})\s+(.+)$')


def load_sym_file(sym_path, image_base=None):
    """
    Parse a simple symbol file with format: HEX_ADDR<whitespace>NAME

    Returns:
        dict of {virtual_address: symbol_name}
        metadata dict
    """
    symbols = {}
    meta = {'source': os.path.basename(sym_path), 'format': 'sym'}
    base = image_base or 0

    with open(sym_path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            m = _SYM_LINE.match(line)
            if m:
                addr = int(m.group(1), 16)
                name = m.group(2).strip()
                # If address looks like an RVA (< 0x10000000), add base
                if addr < 0x10000000 and base:
                    addr += base
                symbols[addr] = _undecorate(name)

    meta['total_symbols'] = len(symbols)
    return symbols, meta


# ---------------------------------------------------------------------------
#  PDB parsing (optional — requires pdbparse)
# ---------------------------------------------------------------------------

def load_pdb_file(pdb_path, image_base=None):
    """
    Parse a PDB file for public symbols.
    Requires pdbparse: pip install pdbparse

    Returns:
        dict of {virtual_address: symbol_name}
        metadata dict
    """
    try:
        import pdbparse
        import pdbparse.pepi
    except ImportError:
        return {}, {'error': 'pdbparse not installed (pip install pdbparse)',
                    'format': 'pdb', 'total_symbols': 0}

    symbols = {}
    meta = {'source': os.path.basename(pdb_path), 'format': 'pdb'}
    base = image_base or 0

    try:
        pdb = pdbparse.parse(pdb_path)

        # Try to get the OMAP or section headers for address translation
        try:
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
        except AttributeError:
            try:
                sects = pdb.STREAM_SECT_HDR.sections
            except AttributeError:
                sects = []

        # Get public symbols (global symbols stream)
        try:
            gsyms = pdb.STREAM_GSYM
            for sym in gsyms.globals:
                if hasattr(sym, 'offset') and hasattr(sym, 'segment'):
                    name = getattr(sym, 'name', None)
                    if name:
                        # Convert segment:offset to RVA
                        seg_idx = sym.segment - 1
                        if 0 <= seg_idx < len(sects):
                            rva = sects[seg_idx].VirtualAddress + sym.offset
                            va = base + rva
                        else:
                            va = base + sym.offset
                        symbols[va] = _undecorate(name)
        except AttributeError:
            pass

        # Also try DBI stream public symbols
        try:
            pdb_publics = pdb.STREAM_DBI
            if hasattr(pdb_publics, 'publics'):
                for pub in pdb_publics.publics:
                    if hasattr(pub, 'offset') and hasattr(pub, 'name'):
                        name = pub.name
                        seg_idx = getattr(pub, 'segment', 1) - 1
                        if 0 <= seg_idx < len(sects):
                            rva = sects[seg_idx].VirtualAddress + pub.offset
                        else:
                            rva = pub.offset
                        va = base + rva
                        symbols[va] = _undecorate(name)
        except (AttributeError, Exception):
            pass

    except Exception as e:
        meta['error'] = f'PDB parse error: {e}'

    meta['total_symbols'] = len(symbols)
    return symbols, meta


# ---------------------------------------------------------------------------
#  DBG / COFF symbol extraction
# ---------------------------------------------------------------------------

def load_dbg_file(dbg_path, image_base=None):
    """
    Parse a .dbg file (IMAGE_SEPARATE_DEBUG_HEADER) for COFF symbols.

    Returns:
        dict of {virtual_address: symbol_name}
        metadata dict
    """
    symbols = {}
    meta = {'source': os.path.basename(dbg_path), 'format': 'dbg'}
    base = image_base or 0

    try:
        with open(dbg_path, 'rb') as f:
            data = f.read()

        # IMAGE_SEPARATE_DEBUG_HEADER signature = 0x4944 ("DI")
        if len(data) < 48:
            meta['error'] = 'File too small for DBG format'
            return symbols, meta

        sig = struct.unpack_from('<H', data, 0)[0]
        if sig != 0x4944:
            meta['error'] = f'Invalid DBG signature: 0x{sig:04X}'
            return symbols, meta

        # Parse header
        (_, flags, machine, characteristics, timestamp,
         check_sum, image_base_dbg, size_of_image,
         num_sections, exported_names_size,
         debug_dir_size, section_alignment,
         reserved_0, reserved_1) = struct.unpack_from('<HHHHI I I I I I I I I I', data, 0)

        if image_base is None:
            base = image_base_dbg

        # COFF symbol table is after section headers and debug directories
        # We'll try to find the COFF symbols at the debug directory offset
        offset = 48 + num_sections * 40  # after section headers

        # Look for IMAGE_DEBUG_TYPE_COFF (1) in debug directories
        debug_dir_offset = offset
        for i in range(debug_dir_size // 28):
            dd_offset = debug_dir_offset + i * 28
            if dd_offset + 28 > len(data):
                break
            dd_type = struct.unpack_from('<I', data, dd_offset + 12)[0]
            dd_size = struct.unpack_from('<I', data, dd_offset + 16)[0]
            dd_ptr = struct.unpack_from('<I', data, dd_offset + 24)[0]

            if dd_type == 1 and dd_ptr + dd_size <= len(data):  # COFF
                coff_data = data[dd_ptr:dd_ptr + dd_size]
                coff_symbols = _parse_coff_symbols(coff_data, base)
                symbols.update(coff_symbols)

    except Exception as e:
        meta['error'] = f'DBG parse error: {e}'

    meta['total_symbols'] = len(symbols)
    return symbols, meta


def _parse_coff_symbols(coff_data, base):
    """Parse COFF symbol table entries."""
    symbols = {}
    if len(coff_data) < 8:
        return symbols

    # COFF debug info header
    num_symbols = struct.unpack_from('<I', coff_data, 0)[0]
    sym_offset = struct.unpack_from('<I', coff_data, 4)[0]
    string_table_offset = sym_offset + num_symbols * 18

    for i in range(min(num_symbols, 10000)):  # safety limit
        entry_offset = 8 + i * 18
        if entry_offset + 18 > len(coff_data):
            break

        # Parse COFF symbol entry (18 bytes)
        name_bytes = coff_data[entry_offset:entry_offset + 8]
        value = struct.unpack_from('<I', coff_data, entry_offset + 8)[0]
        section = struct.unpack_from('<h', coff_data, entry_offset + 12)[0]
        stype = struct.unpack_from('<H', coff_data, entry_offset + 14)[0]
        sclass = coff_data[entry_offset + 16]
        aux_count = coff_data[entry_offset + 17]

        # Skip aux entries
        i += aux_count

        # Only care about external or static symbols in valid sections
        if section <= 0:
            continue
        if sclass not in (2, 3, 6):  # External, Static, Label
            continue

        # Get name
        if name_bytes[:4] == b'\x00\x00\x00\x00':
            # Name is in string table
            str_offset = struct.unpack_from('<I', name_bytes, 4)[0]
            abs_offset = string_table_offset + str_offset
            if abs_offset < len(coff_data):
                end = coff_data.index(b'\x00', abs_offset) if b'\x00' in coff_data[abs_offset:] else len(coff_data)
                name = coff_data[abs_offset:end].decode('ascii', errors='replace')
            else:
                continue
        else:
            name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')

        if name and not name.startswith('.'):
            va = base + value
            symbols[va] = _undecorate(name)

    return symbols


# ---------------------------------------------------------------------------
#  Name undecorating
# ---------------------------------------------------------------------------

def _undecorate(name):
    """Clean up a decorated C/C++ symbol name."""
    # Remove leading underscore (MSVC C convention)
    if name.startswith('_') and not name.startswith('__'):
        name = name[1:]
    # Remove @N suffix (stdcall decoration like _NtCreateFile@44)
    if '@' in name:
        at_pos = name.rfind('@')
        suffix = name[at_pos + 1:]
        if suffix.isdigit():
            name = name[:at_pos]
    # Remove leading ? (C++ mangled — basic cleanup only)
    if name.startswith('?'):
        # Full C++ demangling is complex; just strip the ? prefix hint
        pass
    return name


# ---------------------------------------------------------------------------
#  Unified loader — auto-detect format
# ---------------------------------------------------------------------------

def load_symbols(path, image_base=None):
    """
    Auto-detect file format and load symbols.

    Args:
        path: Path to .map, .pdb, .dbg, or .sym file
        image_base: Override image base address (auto-detected if possible)

    Returns:
        tuple of (symbols_dict, metadata_dict)
        symbols_dict: {virtual_address: symbol_name}
        metadata_dict: {'format', 'total_symbols', 'source', ...}
    """
    ext = os.path.splitext(path)[1].lower()

    if ext == '.map':
        return load_map_file(path, image_base)
    elif ext == '.pdb':
        return load_pdb_file(path, image_base)
    elif ext == '.dbg':
        return load_dbg_file(path, image_base)
    elif ext in ('.sym', '.txt'):
        return load_sym_file(path, image_base)
    else:
        # Try to auto-detect by reading first bytes
        try:
            with open(path, 'rb') as f:
                header = f.read(4)
            if header[:2] == b'DI':
                return load_dbg_file(path, image_base)
            elif header[:4] == b'Micr':  # "Microsoft ..." map files
                return load_map_file(path, image_base)
            else:
                # Try as text symbol file
                return load_sym_file(path, image_base)
        except Exception:
            return load_sym_file(path, image_base)


def merge_symbols(*symbol_dicts):
    """Merge multiple symbol dictionaries. Later dicts override earlier ones."""
    merged = {}
    for d in symbol_dicts:
        merged.update(d)
    return merged


# ---------------------------------------------------------------------------
#  DLL export scanning — KernelEx-style function resolution
# ---------------------------------------------------------------------------

def resolve_from_dlls(unknown_addresses, dll_search_paths, image_base=0):
    """
    KernelEx-style unknown function resolution.
    For each unknown call target address, search nearby DLLs for exports
    at matching RVAs.

    Like KernelEx's binary_api_patch::add_missing_imports() which does:
        SearchPath(NULL, module, ".dll", ...)
        CPEFile module; module.LoadFromFile(module_path);
        hint = module.GetApiExportHintNumber(name);

    Args:
        unknown_addresses: list of unknown call target VAs
        dll_search_paths: list of directories to search for DLLs
        image_base: image base of the PE being analyzed

    Returns:
        dict of {address: "DLL!FunctionName"} for resolved addresses
    """
    import pefile

    resolved = {}
    if not unknown_addresses or not dll_search_paths:
        return resolved

    # Build export cache from all DLLs in search paths
    dll_exports = {}  # {dll_path: {rva: name, va_with_dll_base: name}}

    for search_dir in dll_search_paths:
        if not os.path.isdir(search_dir):
            continue
        for fname in os.listdir(search_dir):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in ('.dll', '.sys', '.exe', '.drv', '.cpl', '.ocx'):
                continue
            dll_path = os.path.join(search_dir, fname)
            try:
                pe = pefile.PE(dll_path, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                exports = {}
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    dll_base = pe.OPTIONAL_HEADER.ImageBase
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name and exp.address:
                            name = exp.name.decode('ascii', errors='replace')
                            exports[exp.address] = name           # RVA
                            exports[dll_base + exp.address] = name  # VA
                dll_exports[dll_path] = exports
                pe.close()
            except Exception:
                continue

    # Now resolve each unknown address
    for addr in unknown_addresses:
        if addr in resolved:
            continue

        # Strategy 1: Direct VA match against DLL exports
        for dll_path, exports in dll_exports.items():
            if addr in exports:
                dll_name = os.path.basename(dll_path)
                resolved[addr] = f"{dll_name}!{exports[addr]}"
                break

        if addr in resolved:
            continue

        # Strategy 2: RVA match (addr - image_base) against DLL export RVAs
        rva = addr - image_base if image_base else addr
        if 0 < rva < 0x10000000:  # reasonable RVA range
            for dll_path, exports in dll_exports.items():
                if rva in exports:
                    dll_name = os.path.basename(dll_path)
                    resolved[addr] = f"{dll_name}!{exports[rva]}"
                    break

        if addr in resolved:
            continue

        # Strategy 3: Check if address is in IAT range of any known DLL
        # (indirect call targets through IAT — the address pointed TO by IAT)
        for dll_path, exports in dll_exports.items():
            for exp_addr, exp_name in exports.items():
                if abs(addr - exp_addr) < 16:  # within a few bytes (thunk proximity)
                    dll_name = os.path.basename(dll_path)
                    resolved[addr] = f"{dll_name}!{exp_name} (near)"
                    break
            if addr in resolved:
                break

    return resolved


def scan_directory_exports(directory):
    """
    Scan all PE files in a directory and collect their exports.
    Returns dict of {'dll_name': [list of export names]}
    """
    import pefile

    result = {}
    if not os.path.isdir(directory):
        return result

    for fname in sorted(os.listdir(directory)):
        ext = os.path.splitext(fname)[1].lower()
        if ext not in ('.dll', '.sys', '.exe', '.drv', '.cpl', '.ocx'):
            continue
        fpath = os.path.join(directory, fname)
        try:
            pe = pefile.PE(fpath, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('ascii', errors='replace'))
            if exports:
                result[fname] = exports
            pe.close()
        except Exception:
            continue

    return result


def find_function_in_dlls(func_name, dll_search_paths):
    """
    Search for a function name across all DLLs in the given directories.
    Like KernelEx's SearchPath + GetApiExportHintNumber approach.

    Returns list of {'dll': name, 'path': full_path, 'ordinal_hint': int}
    """
    import pefile

    matches = []
    for search_dir in dll_search_paths:
        if not os.path.isdir(search_dir):
            continue
        for fname in os.listdir(search_dir):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in ('.dll', '.sys', '.exe', '.drv', '.cpl', '.ocx'):
                continue
            fpath = os.path.join(search_dir, fname)
            try:
                pe = pefile.PE(fpath, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for i, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols):
                        if exp.name:
                            ename = exp.name.decode('ascii', errors='replace')
                            if ename == func_name:
                                matches.append({
                                    'dll': fname,
                                    'path': fpath,
                                    'ordinal': exp.ordinal,
                                    'hint': i,
                                    'rva': exp.address,
                                })
                pe.close()
            except Exception:
                continue

    return matches
