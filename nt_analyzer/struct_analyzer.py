"""
Structure Offset Analyzer — Dynamic PDB Extraction
===================================================
Extracts structure layouts dynamically from PDB (Program Database) files.

Supports:
  - PDB 2.0 (JG / MSF 2.0) — Win2K-era format with native parser
  - PDB 7.0 (DS / MSF 7.0) — native parser (no external deps)

Parses the TPI (Type Program Information) stream to extract full
struct/union/enum definitions including field names, offsets, sizes,
and resolved type names.
"""

import math
import os
import struct as _struct

# ════════════════════════════════════════════════════════════════════
#  CodeView leaf type constants
# ════════════════════════════════════════════════════════════════════

LF_MODIFIER    = 0x1001
LF_POINTER     = 0x1002
LF_ARRAY_ST    = 0x1003   # PDB 2.0 _ST (length-prefixed name)
LF_CLASS_ST    = 0x1004
LF_STRUCTURE   = 0x1005   # LF_STRUCTURE_ST in PDB 2.0
LF_UNION       = 0x1006   # LF_UNION_ST in PDB 2.0
LF_ENUM_ST     = 0x1007
LF_PROCEDURE   = 0x1008
LF_MFUNCTION   = 0x1009
LF_ARGLIST     = 0x1201
LF_FIELDLIST   = 0x1203
LF_BITFIELD    = 0x1205
LF_MEMBER_ST   = 0x1405
LF_MEMBER      = 0x150D
# PDB 7.0 non-_ST variants
LF_ARRAY       = 0x1503
LF_STRUCTURE7  = 0x1505
LF_UNION7      = 0x1506
LF_ENUM        = 0x1507


# ════════════════════════════════════════════════════════════════════
#  Built-in primitive type index resolution (TI < 0x1000)
# ════════════════════════════════════════════════════════════════════

_BUILTIN_BASE = {
    0x00: 'void',       0x03: 'void',
    0x10: 'char',       0x11: 'short',       0x12: 'long',        0x13: '__int64',
    0x20: 'UCHAR',      0x21: 'USHORT',      0x22: 'ULONG',       0x23: 'ULONGLONG',
    0x30: 'BOOLEAN',    0x31: 'BOOLEAN',
    0x40: 'float',      0x41: 'double',      0x42: 'long double',
    0x68: 'int',        0x69: 'unsigned int',
    0x70: 'HRESULT',    0x72: 'long',        0x73: 'unsigned long',
    0x74: 'WCHAR',      0x75: '__int16',
}

_PTR_MODE = {
    0: '',      # direct
    1: '*',     # 16-bit near
    2: '*',     # 16-bit far
    3: '*',     # huge
    4: '*',     # 32-bit near
    5: '*',     # 32-bit far
    6: '*',     # 64-bit
}


def _builtin_type_name(ti):
    """Resolve a built-in type index (< 0x1000) to a readable name."""
    base = ti & 0xFF
    mode = (ti >> 8) & 0xF
    name = _BUILTIN_BASE.get(base, f'T_{ti:04X}')
    ptr = _PTR_MODE.get(mode, '')
    if ptr:
        return 'P' + name.upper() if name.islower() else 'P' + name
    return name


# ════════════════════════════════════════════════════════════════════
#  Numeric leaf reader
# ════════════════════════════════════════════════════════════════════

def _read_numeric_leaf(buf, off):
    """Read a CodeView numeric leaf. Returns (value, next_offset)."""
    if off + 2 > len(buf):
        return 0, off
    val = _struct.unpack_from('<H', buf, off)[0]
    if val < 0x8000:
        return val, off + 2
    if val == 0x8000:  # LF_CHAR
        return _struct.unpack_from('<b', buf, off + 2)[0], off + 3
    if val == 0x8001:  # LF_SHORT
        return _struct.unpack_from('<h', buf, off + 2)[0], off + 4
    if val == 0x8002:  # LF_USHORT
        return _struct.unpack_from('<H', buf, off + 2)[0], off + 4
    if val == 0x8003:  # LF_LONG
        return _struct.unpack_from('<i', buf, off + 2)[0], off + 6
    if val == 0x8004:  # LF_ULONG
        return _struct.unpack_from('<I', buf, off + 2)[0], off + 6
    if val == 0x8009:  # LF_QUADWORD
        return _struct.unpack_from('<q', buf, off + 2)[0], off + 10
    if val == 0x800A:  # LF_UQUADWORD
        return _struct.unpack_from('<Q', buf, off + 2)[0], off + 10
    return val, off + 2


# ════════════════════════════════════════════════════════════════════
#  PDB 2.0 MSF reader
# ════════════════════════════════════════════════════════════════════

PDB20_SIGNATURE = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00'


class _PDB20Reader:
    """Reads PDB 2.0 (JG / MSF 2.0) files — native, no dependencies."""

    def __init__(self, data):
        self.data = data
        self.page_size = _struct.unpack_from('<I', data, 44)[0]
        self.file_pages = _struct.unpack_from('<H', data, 50)[0]
        self.root_size = _struct.unpack_from('<I', data, 52)[0]
        self._parse_root()

    def _read_pages(self, pages, size):
        buf = bytearray()
        for pn in pages:
            start = pn * self.page_size
            buf.extend(self.data[start:start + self.page_size])
        return bytes(buf[:size])

    def _parse_root(self):
        num_root_pages = math.ceil(self.root_size / self.page_size)
        root_pages = [_struct.unpack_from('<H', self.data, 60 + i * 2)[0]
                      for i in range(num_root_pages)]
        root = self._read_pages(root_pages, self.root_size)

        self.num_streams = _struct.unpack_from('<H', root, 0)[0]
        off = 4
        self._stream_sizes = []
        for _ in range(self.num_streams):
            self._stream_sizes.append(_struct.unpack_from('<I', root, off)[0])
            off += 8

        self._stream_pages = []
        for sz in self._stream_sizes:
            cnt = math.ceil(sz / self.page_size) if sz > 0 else 0
            pages = [_struct.unpack_from('<H', root, off + j * 2)[0]
                     for j in range(cnt)]
            off += cnt * 2
            self._stream_pages.append(pages)

    def read_stream(self, idx):
        if idx >= self.num_streams or self._stream_sizes[idx] == 0:
            return b''
        return self._read_pages(self._stream_pages[idx], self._stream_sizes[idx])


# ════════════════════════════════════════════════════════════════════
#  TPI (Type Program Information) stream parser
# ════════════════════════════════════════════════════════════════════

class PDBTypeInfo:
    """
    Parses PDB type information stream and provides structure lookups.

    Usage:
        ti = PDBTypeInfo(pdb_path)
        names = ti.list_structures()          # ['_PEB', '_TEB', ...]
        peb = ti.get_structure('_PEB')        # full layout dict
        peb = ti.get_structure('PEB')         # also works (auto-prefixes _)
    """

    def __init__(self, pdb_path):
        self.pdb_path = pdb_path
        self.source = os.path.basename(pdb_path)
        self._type_records = {}   # ti -> (leaf, data_bytes)
        self._ti_min = 0
        self._ti_max = 0
        self._struct_index = {}   # name -> ti (non-forward-ref structs)
        self._union_index = {}    # name -> ti
        self._enum_index = {}     # name -> ti
        self._type_name_cache = {}

        with open(pdb_path, 'rb') as f:
            data = f.read()

        if data[:44] == PDB20_SIGNATURE:
            self._parse_pdb20(data)
        elif b'Microsoft C/C++ MSF 7.00' in data[:32]:
            self._parse_pdb70(data)
        else:
            raise ValueError(f"Unknown PDB format: {data[:24]!r}")

    # ── PDB 2.0 ──────────────────────────────────────────────────

    def _parse_pdb20(self, data):
        reader = _PDB20Reader(data)
        tpi = reader.read_stream(2)
        self._parse_tpi_stream(tpi)

    # ── PDB 7.0 ──────────────────────────────────────────────────

    def _parse_pdb70(self, data):
        page_size = _struct.unpack_from('<I', data, 32)[0]
        root_size = _struct.unpack_from('<I', data, 40)[0]

        num_root_pages = math.ceil(root_size / page_size)
        num_ptr_pages = math.ceil(num_root_pages * 4 / page_size)
        ptr_start = _struct.unpack_from('<I', data, 52)[0]

        ptr_page_data = data[ptr_start * page_size:
                             ptr_start * page_size + num_ptr_pages * page_size]
        root_page_nums = [_struct.unpack_from('<I', ptr_page_data, i * 4)[0]
                          for i in range(num_root_pages)]

        root = bytearray()
        for pn in root_page_nums:
            root.extend(data[pn * page_size:(pn + 1) * page_size])
        root = bytes(root[:root_size])

        num_streams = _struct.unpack_from('<I', root, 0)[0]
        off = 4
        stream_sizes = []
        for _ in range(num_streams):
            stream_sizes.append(_struct.unpack_from('<I', root, off)[0])
            off += 4

        stream_pages = []
        for sz in stream_sizes:
            cnt = math.ceil(sz / page_size) if (sz > 0 and sz != 0xFFFFFFFF) else 0
            pages = [_struct.unpack_from('<I', root, off + j * 4)[0]
                     for j in range(cnt)]
            off += cnt * 4
            stream_pages.append(pages)

        def read_stream(idx):
            if idx >= num_streams or stream_sizes[idx] in (0, 0xFFFFFFFF):
                return b''
            buf = bytearray()
            for pn in stream_pages[idx]:
                buf.extend(data[pn * page_size:(pn + 1) * page_size])
            return bytes(buf[:stream_sizes[idx]])

        tpi = read_stream(2)
        self._parse_tpi_stream(tpi)

    # ── Common TPI parser ────────────────────────────────────────

    def _parse_tpi_stream(self, tpi):
        if len(tpi) < 20:
            return

        hdr_size = _struct.unpack_from('<I', tpi, 4)[0]
        self._ti_min = _struct.unpack_from('<I', tpi, 8)[0]
        self._ti_max = _struct.unpack_from('<I', tpi, 12)[0]

        pos = hdr_size
        ti = self._ti_min
        while pos + 4 <= len(tpi) and ti < self._ti_max:
            rec_len = _struct.unpack_from('<H', tpi, pos)[0]
            if rec_len < 2 or pos + 2 + rec_len > len(tpi):
                break
            leaf = _struct.unpack_from('<H', tpi, pos + 2)[0]
            rec_data = tpi[pos + 4:pos + 2 + rec_len]
            self._type_records[ti] = (leaf, rec_data)
            pos += 2 + rec_len
            if pos % 4:
                pos += 4 - (pos % 4)
            ti += 1

        # Index named structures / unions / enums
        for type_idx, (leaf, rec_data) in self._type_records.items():
            if leaf in (LF_STRUCTURE, LF_STRUCTURE7) and len(rec_data) >= 16:
                name, is_fwd, count = self._parse_struct_header(rec_data)
                if name:
                    if count > 0 and not is_fwd:
                        self._struct_index[name] = type_idx
            elif leaf in (LF_UNION, LF_UNION7) and len(rec_data) >= 12:
                name, is_fwd, count = self._parse_union_header(rec_data)
                if name:
                    if count > 0 and not is_fwd:
                        self._union_index[name] = type_idx
            elif leaf in (LF_ENUM_ST, LF_ENUM) and len(rec_data) >= 12:
                name = self._parse_enum_name(rec_data)
                if name:
                    self._enum_index[name] = type_idx

    def _read_name(self, buf, off):
        """Read length-prefixed or null-terminated name at offset."""
        if off >= len(buf):
            return '', off
        # Length-prefixed (PDB 2.0 _ST variants)
        name_len = buf[off]
        if 0 < name_len < 200 and off + 1 + name_len <= len(buf):
            # Verify it looks like ASCII
            candidate = buf[off + 1:off + 1 + name_len]
            if all(32 <= b < 127 for b in candidate):
                return candidate.decode('ascii', errors='replace'), off + 1 + name_len
        # Null-terminated (PDB 7.0)
        null_idx = buf[off:off + 256].find(0)
        if null_idx >= 0:
            name = buf[off:off + null_idx].decode('ascii', errors='replace')
            return name, off + null_idx + 1
        return '', off

    def _parse_struct_header(self, d):
        """Parse LF_STRUCTURE record. Returns (name, is_forward_ref, count)."""
        count = _struct.unpack_from('<H', d, 0)[0]
        prop = _struct.unpack_from('<H', d, 2)[0]
        is_fwd = (prop & 0x80) != 0
        # field_ti(u32), dList(u32), vshape(u32), size(numeric_leaf), name
        _, name_off = _read_numeric_leaf(d, 16)
        name, _ = self._read_name(d, name_off)
        return name, is_fwd, count

    def _parse_union_header(self, d):
        """Parse LF_UNION record."""
        count = _struct.unpack_from('<H', d, 0)[0]
        prop = _struct.unpack_from('<H', d, 2)[0]
        is_fwd = (prop & 0x80) != 0
        _, name_off = _read_numeric_leaf(d, 8)
        name, _ = self._read_name(d, name_off)
        return name, is_fwd, count

    def _parse_enum_name(self, d):
        """Parse LF_ENUM record to get name."""
        if len(d) < 12:
            return ''
        name, _ = self._read_name(d, 12)
        return name

    # ── Type name resolution ─────────────────────────────────────

    def resolve_type_name(self, ti, depth=0):
        """Resolve a type index to a human-readable C type name."""
        if ti in self._type_name_cache:
            return self._type_name_cache[ti]
        name = self._resolve_type_impl(ti, depth)
        self._type_name_cache[ti] = name
        return name

    def _resolve_type_impl(self, ti, depth):
        if depth > 12:
            return '...'
        if ti == 0:
            return 'void'
        if ti < 0x1000:
            return _builtin_type_name(ti)

        rec = self._type_records.get(ti)
        if not rec:
            return f'T_{ti:04X}'

        leaf, d = rec

        if leaf in (LF_STRUCTURE, LF_STRUCTURE7):
            _, name_off = _read_numeric_leaf(d, 16)
            name, _ = self._read_name(d, name_off)
            if name:
                return name.lstrip('_') if not name.startswith('__') else name
            return f'STRUCT_{ti:04X}'

        if leaf in (LF_UNION, LF_UNION7):
            _, name_off = _read_numeric_leaf(d, 8)
            name, _ = self._read_name(d, name_off)
            if name:
                return name.lstrip('_') if not name.startswith('__') else name
            return f'UNION_{ti:04X}'

        if leaf in (LF_ENUM_ST, LF_ENUM):
            name, _ = self._read_name(d, 12)
            if name:
                return name.lstrip('_') if not name.startswith('__') else name
            return f'ENUM_{ti:04X}'

        if leaf == LF_MODIFIER and len(d) >= 4:
            return self.resolve_type_name(_struct.unpack_from('<I', d, 0)[0], depth + 1)

        if leaf == LF_POINTER:
            if len(d) >= 4:
                base = self.resolve_type_name(_struct.unpack_from('<I', d, 0)[0], depth + 1)
                if base.islower():
                    return 'P' + base.upper()
                return 'P' + base
            return 'PVOID'

        if leaf in (LF_ARRAY_ST, LF_ARRAY) and len(d) >= 8:
            elem_ti = _struct.unpack_from('<I', d, 0)[0]
            arr_size, _ = _read_numeric_leaf(d, 8)
            elem_name = self.resolve_type_name(elem_ti, depth + 1)
            if arr_size:
                elem_sz = self._type_size(elem_ti)
                count = arr_size // elem_sz if elem_sz else 0
                if count > 0:
                    return f'{elem_name}[{count}]'
                return f'{elem_name}[{arr_size}]'
            return f'{elem_name}[]'

        if leaf == LF_PROCEDURE:
            return 'PROC'

        if leaf == LF_MFUNCTION:
            return 'MFUNC'

        if leaf == LF_BITFIELD and len(d) >= 6:
            base_ti = _struct.unpack_from('<I', d, 0)[0]
            n_bits = d[4]
            base_name = self.resolve_type_name(base_ti, depth + 1)
            return f'{base_name}:{n_bits}'

        return f'L_{leaf:04X}'

    # ── Compute type size ────────────────────────────────────────

    def _type_size(self, ti):
        """Compute size of a type in bytes."""
        if ti == 0:
            return 0
        if ti < 0x1000:
            base = ti & 0xFF
            mode = (ti >> 8) & 0xF
            if mode in (4, 5, 6):
                return 4  # 32-bit pointer
            sizes = {
                0x00: 0, 0x03: 0, 0x10: 1, 0x11: 2, 0x12: 4, 0x13: 8,
                0x20: 1, 0x21: 2, 0x22: 4, 0x23: 8,
                0x30: 1, 0x31: 1, 0x40: 4, 0x41: 8,
                0x68: 4, 0x69: 4, 0x70: 4, 0x72: 4, 0x73: 4,
                0x74: 2, 0x75: 2,
            }
            return sizes.get(base, 4)

        rec = self._type_records.get(ti)
        if not rec:
            return 0
        leaf, d = rec

        if leaf in (LF_STRUCTURE, LF_STRUCTURE7) and len(d) >= 16:
            size, _ = _read_numeric_leaf(d, 16)
            if size == 0:
                # Forward ref — look up the real definition
                _, name_off = _read_numeric_leaf(d, 16)
                name, _ = self._read_name(d, name_off)
                real_ti = self._struct_index.get(name)
                if real_ti and real_ti != ti:
                    return self._type_size(real_ti)
            return size

        if leaf in (LF_UNION, LF_UNION7) and len(d) >= 8:
            size, _ = _read_numeric_leaf(d, 8)
            if size == 0:
                _, name_off = _read_numeric_leaf(d, 8)
                name, _ = self._read_name(d, name_off)
                real_ti = self._union_index.get(name)
                if real_ti and real_ti != ti:
                    return self._type_size(real_ti)
            return size

        if leaf in (LF_ARRAY_ST, LF_ARRAY) and len(d) >= 8:
            size, _ = _read_numeric_leaf(d, 8)
            return size

        if leaf == LF_POINTER:
            return 4

        if leaf == LF_MODIFIER and len(d) >= 4:
            return self._type_size(_struct.unpack_from('<I', d, 0)[0])

        if leaf in (LF_ENUM_ST, LF_ENUM) and len(d) >= 8:
            return self._type_size(_struct.unpack_from('<I', d, 4)[0])

        if leaf == LF_BITFIELD and len(d) >= 4:
            return self._type_size(_struct.unpack_from('<I', d, 0)[0])

        return 0

    # ── Field list parsing ───────────────────────────────────────

    def _parse_fieldlist(self, fl_ti, struct_size=0):
        """Parse a LF_FIELDLIST record and return list of member fields."""
        rec = self._type_records.get(fl_ti)
        if not rec:
            return []
        leaf, d = rec
        if leaf != LF_FIELDLIST:
            return []

        fields = []
        fpos = 0
        while fpos + 4 <= len(d):
            sub_leaf = _struct.unpack_from('<H', d, fpos)[0]

            if sub_leaf in (LF_MEMBER_ST, LF_MEMBER):
                # attr(u16), type_ti(u32), offset(numeric_leaf), name
                if fpos + 8 > len(d):
                    break
                type_ti = _struct.unpack_from('<I', d, fpos + 4)[0]
                offset_val, noff = _read_numeric_leaf(d, fpos + 8)
                name, end = self._read_name(d, noff)
                type_name = self.resolve_type_name(type_ti)
                size = self._type_size(type_ti)
                fields.append({
                    'offset': offset_val,
                    'size': size,
                    'name': name,
                    'type': type_name,
                })
                fpos = end
                if fpos % 4:
                    fpos += 4 - (fpos % 4)

            elif sub_leaf >= 0xF0:
                # Padding bytes
                fpos += sub_leaf - 0xF0 + 1

            else:
                # Skip unknown sub-records (LF_ENUMERATE, LF_NESTTYPE, etc.)
                fpos += 2
                while fpos + 2 <= len(d):
                    nl = _struct.unpack_from('<H', d, fpos)[0]
                    if nl in (LF_MEMBER_ST, LF_MEMBER) or nl >= 0xF0:
                        break
                    fpos += 1

        # Fill in zero sizes from next field offset
        for i, f in enumerate(fields):
            if f['size'] == 0:
                if i + 1 < len(fields):
                    f['size'] = fields[i + 1]['offset'] - f['offset']
                elif struct_size > f['offset']:
                    f['size'] = struct_size - f['offset']

        return fields

    # ── Public API ───────────────────────────────────────────────

    def list_structures(self):
        """Return sorted list of all structure names found in PDB."""
        return sorted(self._struct_index.keys())

    def list_unions(self):
        """Return sorted list of all union names found in PDB."""
        return sorted(self._union_index.keys())

    def list_enums(self):
        """Return sorted list of all enum names found in PDB."""
        return sorted(self._enum_index.keys())

    def list_all_types(self):
        """Return sorted list of all named structs, unions, and enums."""
        return sorted(set(list(self._struct_index.keys()) +
                          list(self._union_index.keys()) +
                          list(self._enum_index.keys())))

    def get_structure(self, name):
        """
        Get a full structure layout by name.
        Accepts '_PEB' or 'PEB' (auto-tries _ prefix).
        Returns dict: {name, size, os, fields, field_count, source, raw_name}
        """
        ti = self._struct_index.get(name)
        if ti is None and not name.startswith('_'):
            ti = self._struct_index.get('_' + name)
        if ti is None:
            # Case-insensitive fallback
            name_upper = name.upper().lstrip('_')
            for k, v in self._struct_index.items():
                if k.upper().lstrip('_') == name_upper:
                    ti = v
                    break
        if ti is None:
            return None

        leaf, d = self._type_records[ti]
        count = _struct.unpack_from('<H', d, 0)[0]
        field_ti = _struct.unpack_from('<I', d, 4)[0]
        struct_size, name_off = _read_numeric_leaf(d, 16)
        struct_name, _ = self._read_name(d, name_off)

        fields = self._parse_fieldlist(field_ti, struct_size)

        return {
            'name': struct_name.lstrip('_'),
            'size': struct_size,
            'os': f'from {self.source}',
            'fields': fields,
            'field_count': len(fields),
            'source': self.source,
            'raw_name': struct_name,
        }

    def get_structure_names_matching(self, pattern):
        """Return struct names containing the given substring (case-insensitive)."""
        p = pattern.upper()
        return sorted(n for n in self._struct_index if p in n.upper())


# ════════════════════════════════════════════════════════════════════
#  Module-level convenience API
# ════════════════════════════════════════════════════════════════════

_current_pdb = None  # type: PDBTypeInfo | None


def load_pdb(pdb_path):
    """Load a PDB file and set it as the active type source."""
    global _current_pdb
    _current_pdb = PDBTypeInfo(pdb_path)
    return _current_pdb


def get_current_pdb():
    """Return the currently loaded PDBTypeInfo, or None."""
    return _current_pdb


def list_structures():
    """List structure names from the currently loaded PDB."""
    if _current_pdb is None:
        return []
    return _current_pdb.list_structures()


def get_structure(name):
    """Get a structure layout from the currently loaded PDB."""
    if _current_pdb is None:
        return None
    return _current_pdb.get_structure(name)


# Backward compatibility aliases
list_known_structures = list_structures
get_known_structure = get_structure


def generate_c_header(struct_def):
    """Generate a C header definition from a structure layout dict."""
    lines = []
    name = struct_def['name']
    os_label = struct_def.get('os', '')
    size = struct_def.get('size', 0)

    lines.append(f"/* {name} - {os_label} */")
    lines.append(f"/* Total size: 0x{size:X} ({size} bytes) */")
    lines.append(f"typedef struct _{name} {{")

    prev_end = 0
    for field in struct_def.get('fields', []):
        offset = field['offset']
        fsz = field.get('size', 0)
        ftype = field.get('type', 'UCHAR')
        fname = field.get('name', '???')

        if offset > prev_end:
            gap = offset - prev_end
            lines.append(f"    UCHAR _padding_{prev_end:03X}[{gap}];  "
                         f"/* offset 0x{prev_end:03X} */")

        lines.append(f"    {ftype:40s} {fname};  "
                     f"/* offset 0x{offset:03X}, size 0x{fsz:X} */")
        prev_end = offset + fsz

    lines.append(f"}} {name}, *P{name};")
    lines.append("")
    return '\n'.join(lines)


def save_all_headers(output_dir, pdb_info=None):
    """Generate C headers for all structures in the loaded PDB."""
    src = pdb_info or _current_pdb
    if src is None:
        return []

    os.makedirs(output_dir, exist_ok=True)
    files = []
    for name in src.list_structures():
        s = src.get_structure(name)
        if not s:
            continue
        clean = s['name']
        path = os.path.join(output_dir, f"{clean.lower()}.h")
        guard = clean.upper() + '_H'
        with open(path, 'w') as f:
            f.write(f"#ifndef _{guard}\n")
            f.write(f"#define _{guard}\n\n")
            f.write(generate_c_header(s))
            f.write(f"\n#endif /* _{guard} */\n")
        files.append(path)
    return files
