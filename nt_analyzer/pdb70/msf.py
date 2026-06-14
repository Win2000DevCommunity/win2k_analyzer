"""MSF 7.00 (PDB 7.0 / DS) container read/write helpers."""
from __future__ import annotations

import math
import os
import struct
from typing import Any, Callable, Dict, List, Optional

PDB20_SIG = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00'
PDB70_SIG = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'

# MSF 7.00 superblock (after 32-byte magic)
MSF_OFF_PAGE_SIZE = 32
MSF_OFF_FPM = 36
MSF_OFF_NUM_BLOCKS = 40
MSF_OFF_NUM_DIRECTORY_BYTES = 44
MSF_OFF_BLOCK_MAP = 52


def _num_blocks(data: bytearray, page_size: int) -> int:
    return len(data) // page_size if page_size else 0


def _sync_superblock_counts(data: bytearray, page_size: int,
                            directory_bytes: int = None) -> None:
    """Write NumBlocks (off 40) and optionally NumDirectoryBytes (off 44)."""
    struct.pack_into('<I', data, MSF_OFF_NUM_BLOCKS,
                     _num_blocks(data, page_size))
    if directory_bytes is not None:
        struct.pack_into('<I', data, MSF_OFF_NUM_DIRECTORY_BYTES,
                         directory_bytes)


def detect_pdb_format(path: str) -> str:
    """Return ``pdb20``, ``pdb70``, or ``unknown``."""
    try:
        with open(path, 'rb') as f:
            head = f.read(44)
    except OSError:
        return 'unknown'
    if head == PDB20_SIG:
        return 'pdb20'
    if head[:32] == PDB70_SIG[:32]:
        return 'pdb70'
    return 'unknown'


def parse_msf70(data_or_path) -> Optional[Dict[str, Any]]:
    """Parse an MSF 7.00 file from *data_or_path* (bytes or path).

    Returns a dict with ``data``, ``page_size``, ``num_streams``, ``sizes``,
    ``stream_pages``, and ``read_stream(idx)`` — or None on failure.
    """
    if isinstance(data_or_path, (bytes, bytearray)):
        data = bytearray(data_or_path)
    else:
        try:
            with open(data_or_path, 'rb') as f:
                data = bytearray(f.read())
        except OSError:
            return None

    if len(data) < 64 or data[:32] != PDB70_SIG[:32]:
        return None

    page_size = struct.unpack_from('<I', data, MSF_OFF_PAGE_SIZE)[0]
    if page_size == 0 or page_size > 0x10000:
        return None

    # Pad to whole pages (same invariant as PDB 2.0 path).
    if len(data) % page_size:
        data.extend(b'\x00' * (page_size - (len(data) % page_size)))

    # Off 40 = NumBlocks, off 44 = NumDirectoryBytes (stream directory size).
    root_size = struct.unpack_from('<I', data, MSF_OFF_NUM_DIRECTORY_BYTES)[0]
    num_root_pages = math.ceil(root_size / page_size) if root_size else 0
    num_ptr_pages = math.ceil(num_root_pages * 4 / page_size) if num_root_pages else 0
    ptr_start = struct.unpack_from('<I', data, MSF_OFF_BLOCK_MAP)[0]

    if ptr_start * page_size + page_size > len(data):
        return None

    # Root page list lives in the block-map stream page(s).  Read consecutive
    # valid page numbers until 0 / out-of-range (dir_bytes alone can be short).
    ptr_page = data[ptr_start * page_size:ptr_start * page_size + page_size]
    file_pages = len(data) // page_size
    root_page_nums: List[int] = []
    for i in range(0, len(ptr_page), 4):
        pn = struct.unpack_from('<I', ptr_page, i)[0]
        if pn == 0 or pn >= file_pages:
            break
        root_page_nums.append(pn)
    if not root_page_nums:
        # Fallback: derive from directory byte count.
        num_root_pages = math.ceil(root_size / page_size) if root_size else 0
        root_page_nums = [struct.unpack_from('<I', ptr_page, i * 4)[0]
                          for i in range(num_root_pages)]

    root = bytearray()
    for pn in root_page_nums:
        if pn * page_size >= len(data):
            return None
        root.extend(data[pn * page_size:pn * page_size + page_size])
    root = bytes(root)

    if len(root) < 4:
        return None

    num_streams = struct.unpack_from('<I', root, 0)[0]
    off = 4
    sizes: List[int] = []
    for _ in range(num_streams):
        if off + 4 > len(root):
            break
        sizes.append(struct.unpack_from('<I', root, off)[0])
        off += 4

    stream_pages: List[List[int]] = []
    for sz in sizes:
        if sz in (0, 0xFFFFFFFF):
            stream_pages.append([])
            continue
        cnt = math.ceil(sz / page_size)
        pages: List[int] = []
        for j in range(cnt):
            if off + 4 > len(root):
                break
            pages.append(struct.unpack_from('<I', root, off + j * 4)[0])
        off += cnt * 4
        stream_pages.append(pages)

    file_pages = len(data) // page_size

    def read_stream(idx: int) -> bytes:
        if idx < 0 or idx >= num_streams:
            return b''
        sz = sizes[idx]
        if sz in (0, 0xFFFFFFFF):
            return b''
        buf = bytearray()
        for pn in stream_pages[idx]:
            if pn >= file_pages:
                continue
            start = pn * page_size
            buf.extend(data[start:start + page_size])
        return bytes(buf[:sz])

    return {
        'data': data,
        'page_size': page_size,
        'num_streams': num_streams,
        'sizes': sizes,
        'stream_pages': stream_pages,
        'root_size': root_size,
        'read_stream': read_stream,
    }


def replace_stream_bytes(msf: Dict[str, Any], stream_idx: int,
                         new_bytes: bytes) -> bool:
    """Replace stream *stream_idx* contents in the in-memory MSF *msf* dict."""
    data = msf['data']
    page_size = msf['page_size']
    sizes = msf['sizes']
    stream_pages = msf['stream_pages']
    num_streams = msf['num_streams']

    if stream_idx >= num_streams:
        return False

    logical_size = len(new_bytes)
    stored = new_bytes
    if logical_size % page_size:
        stored = new_bytes + b'\x00' * (page_size - (logical_size % page_size))

    need_pages = math.ceil(len(stored) / page_size) if stored else 0
    have_pages = len(stream_pages[stream_idx])

    # MSF 7: free page map is stream 0 / dedicated — for safety we append pages.
    if need_pages > have_pages:
        total = len(data) // page_size
        extra = list(range(total, total + (need_pages - have_pages)))
        data.extend(b'\x00' * ((need_pages - have_pages) * page_size))
        stream_pages[stream_idx].extend(extra)
        _sync_superblock_counts(data, page_size)

    stream_pages[stream_idx] = stream_pages[stream_idx][:max(need_pages, 0)]
    sizes[stream_idx] = logical_size

    for pi, pn in enumerate(stream_pages[stream_idx]):
        base = pn * page_size
        data[base:base + page_size] = b'\x00' * page_size
    for i, b in enumerate(stored):
        pi = i // page_size
        ip = i % page_size
        pn = stream_pages[stream_idx][pi]
        data[pn * page_size + ip] = b

    _rebuild_root(msf)
    return True


def _rebuild_root(msf: Dict[str, Any]) -> None:
    """Rebuild the MSF 7.00 root directory stream in-place."""
    data = msf['data']
    page_size = msf['page_size']
    sizes = msf['sizes']
    stream_pages = msf['stream_pages']
    num_streams = msf['num_streams']

    ptr_start = struct.unpack_from('<I', data, MSF_OFF_BLOCK_MAP)[0]
    file_pages = len(data) // page_size
    ptr_page = data[ptr_start * page_size:ptr_start * page_size + page_size]
    root_page_nums: List[int] = []
    for i in range(0, len(ptr_page), 4):
        pn = struct.unpack_from('<I', ptr_page, i)[0]
        if pn == 0 or pn >= file_pages:
            break
        root_page_nums.append(pn)

    new_root = bytearray()
    new_root += struct.pack('<I', num_streams)
    for sz in sizes:
        new_root += struct.pack('<I', sz)
    for si in range(num_streams):
        sz = sizes[si]
        cnt = math.ceil(sz / page_size) if sz not in (0, 0xFFFFFFFF) else 0
        pages = stream_pages[si]
        for pi in range(cnt):
            new_root += struct.pack('<I', pages[pi] if pi < len(pages) else 0)

    # Grow root if needed (append root pages at EOF).
    root_pages_needed = math.ceil(len(new_root) / page_size)
    if root_pages_needed > len(root_page_nums):
        total = len(data) // page_size
        for _ in range(root_pages_needed - len(root_page_nums)):
            root_page_nums.append(total)
            data.extend(b'\x00' * page_size)
            total += 1
        _sync_superblock_counts(data, page_size)
        # Rewrite pointer stream
        new_ptr = bytearray()
        for pn in root_page_nums:
            new_ptr += struct.pack('<I', pn)
        ps = ptr_start * page_size
        data[ps:ps + len(new_ptr)] = new_ptr

    for pi, rpn in enumerate(root_page_nums):
        s = pi * page_size
        e = min(s + page_size, len(new_root))
        if s < len(new_root):
            chunk = new_root[s:e]
            data[rpn * page_size:rpn * page_size + len(chunk)] = chunk

    _sync_superblock_counts(data, page_size, len(new_root))
    msf['root_size'] = len(new_root)


def write_msf70(msf: Dict[str, Any], path: str) -> None:
    with open(path, 'wb') as f:
        f.write(msf['data'])
