"""
Tests for PDB export safety (Win2K NT Internals Analyzer)
=========================================================
Covers the structural-validation and image-matching helpers added to
``SymbolUpdater`` so that a recovered/exported PDB can never silently
replace a working symbol file with a broken one:

  * validate_pdb        - MSF container invariants dbghelp checks
  * stamp_pdb_signature - write NB10 signature/age into the info stream
  * inject_symbols_pdb   - must keep the file structurally valid

These tests build a minimal but valid PDB 2.0 (JG/MSF) in memory, so
they do not depend on any external symbol files.

Run:  python -m pytest tests/test_pdb_export_safety.py -v
"""

import os
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.ubrt_engine import SymbolUpdater

PDB20_SIG = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00'


def build_minimal_pdb(page_size=1024,
                      version=19960307,
                      signature=0x11111111,
                      age=1):
    """
    Build a minimal valid PDB 2.0 image:

      page 0 : MSF header
      page 1 : free page map (content irrelevant to readers)
      page 2 : stream 1 (PDB info) -> Version, Signature, Age
      page 3 : root / stream directory

    Stream 0 is empty (old-MSF directory placeholder); stream 1 is the
    info stream that carries the signature/age WinDbg matches.
    """
    num_pages = 4
    data = bytearray(b'\x00' * (num_pages * page_size))

    # Stream 1 info payload on page 2
    info = struct.pack('<III', version, signature, age)
    data[2 * page_size:2 * page_size + len(info)] = info
    info_size = len(info)

    # Root directory on page 3
    root = bytearray()
    root += struct.pack('<HH', 2, 0)         # num_streams=2, pad
    root += struct.pack('<II', 0, 0)         # stream0 size=0
    root += struct.pack('<II', info_size, 0)  # stream1 size
    # page lists: stream0 has none, stream1 -> [2]
    root += struct.pack('<H', 2)
    root_size = len(root)
    data[3 * page_size:3 * page_size + root_size] = root

    # MSF header
    data[:44] = PDB20_SIG
    struct.pack_into('<I', data, 44, page_size)   # page size
    struct.pack_into('<H', data, 48, 1)           # free page map page
    struct.pack_into('<H', data, 50, num_pages)   # file page count
    struct.pack_into('<I', data, 52, root_size)   # root size
    struct.pack_into('<I', data, 56, 0)           # reserved
    struct.pack_into('<H', data, 60, 3)           # root page = 3
    return bytes(data)


def build_pdb_with_symstream(sym_payload, page_size=1024):
    """
    Build a valid-MSF PDB 2.0 with 6 streams where stream 5 is a symbol
    (GSI-style) stream carrying ``sym_payload``.  Used to exercise the
    validator's symbol-record walk.

      page 0 : header     page 1 : free page map
      page 2 : info (1)   page 3 : root      page 4 : symbol stream (5)
    """
    num_pages = 5
    data = bytearray(b'\x00' * (num_pages * page_size))

    info = struct.pack('<III', 19960307, 0x11111111, 1)
    data[2 * page_size:2 * page_size + len(info)] = info
    data[4 * page_size:4 * page_size + len(sym_payload)] = sym_payload

    sizes = [0, len(info), 0, 0, 0, len(sym_payload)]
    page_lists = {1: [2], 5: [4]}

    root = bytearray()
    root += struct.pack('<HH', len(sizes), 0)
    for sz in sizes:
        root += struct.pack('<II', sz, 0)
    for si, sz in enumerate(sizes):
        for pn in page_lists.get(si, []):
            root += struct.pack('<H', pn)
    root_size = len(root)
    data[3 * page_size:3 * page_size + root_size] = root

    data[:44] = PDB20_SIG
    struct.pack_into('<I', data, 44, page_size)
    struct.pack_into('<H', data, 48, 1)
    struct.pack_into('<H', data, 50, num_pages)
    struct.pack_into('<I', data, 52, root_size)
    struct.pack_into('<I', data, 56, 0)
    struct.pack_into('<H', data, 60, 3)
    return bytes(data)


def make_pub32(name=b'x', offset=0, segment=1):
    """A well-formed S_PUB32_16t record (4-byte aligned)."""
    reclen = 2 + 4 + 4 + 2 + 1 + len(name)
    rec = struct.pack('<HH', reclen, 0x1009)
    rec += struct.pack('<I', 0) + struct.pack('<I', offset)
    rec += struct.pack('<H', segment) + struct.pack('<B', len(name)) + name
    if len(rec) % 4:
        rec += b'\x00' * (4 - len(rec) % 4)
    return rec


class ValidatePdbTests(unittest.TestCase):

    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix='.pdb')
        os.close(fd)
        with open(path, 'wb') as f:
            f.write(data)
        self.addCleanup(lambda: os.path.isfile(path) and os.remove(path))
        return path

    def test_minimal_pdb_is_valid(self):
        path = self._write(build_minimal_pdb())
        res = SymbolUpdater.validate_pdb(path)
        self.assertTrue(res['valid'], res.get('errors'))
        self.assertEqual(res['streams'], 2)
        self.assertEqual(res['file_pages'], 4)

    def test_truncated_file_is_invalid(self):
        data = bytearray(build_minimal_pdb())
        path = self._write(bytes(data[:-512]))   # chop half the last page
        res = SymbolUpdater.validate_pdb(path)
        self.assertFalse(res['valid'])
        self.assertTrue(any('file size' in e.lower() for e in res['errors']))

    def test_bad_page_count_is_invalid(self):
        data = bytearray(build_minimal_pdb())
        struct.pack_into('<H', data, 50, 999)     # lie about file pages
        path = self._write(bytes(data))
        res = SymbolUpdater.validate_pdb(path)
        self.assertFalse(res['valid'])

    def test_out_of_range_stream_page_is_invalid(self):
        data = bytearray(build_minimal_pdb())
        # Rewrite root so stream1 points at a non-existent page 250
        root_off = 3 * 1024
        # page list entry for stream1 is the last uint16 of the root
        struct.pack_into('<H', data, root_off + 4 + 16, 250)
        path = self._write(bytes(data))
        res = SymbolUpdater.validate_pdb(path)
        self.assertFalse(res['valid'])

    def test_non_pdb_file_is_invalid(self):
        path = self._write(b'not a pdb at all' * 100)
        res = SymbolUpdater.validate_pdb(path)
        self.assertFalse(res['valid'])

    def test_clean_symbol_stream_is_valid(self):
        payload = make_pub32(b'foo') + make_pub32(b'bar')
        path = self._write(build_pdb_with_symstream(payload))
        res = SymbolUpdater.validate_pdb(path)
        self.assertTrue(res['valid'], res.get('errors'))

    def test_overrunning_symbol_record_is_invalid(self):
        # A record whose length runs past the stream end (what a broken
        # inject leaves behind).
        bad = struct.pack('<HH', 200, 0x1009) + b'\x00' * 12
        path = self._write(build_pdb_with_symstream(bad))
        res = SymbolUpdater.validate_pdb(path)
        self.assertFalse(res['valid'])
        self.assertTrue(any('overrun' in e.lower() for e in res['errors']))


class StampSignatureTests(unittest.TestCase):

    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix='.pdb')
        os.close(fd)
        with open(path, 'wb') as f:
            f.write(data)
        self.addCleanup(lambda: os.path.isfile(path) and os.remove(path))
        return path

    def test_stamp_updates_info_stream_and_stays_valid(self):
        path = self._write(build_minimal_pdb(signature=0x11111111, age=1))
        res = SymbolUpdater.stamp_pdb_signature(path, 0xDEADBEEF, age=7)
        self.assertTrue(res['stamped'], res.get('errors'))

        # File must still be structurally valid after stamping
        self.assertTrue(SymbolUpdater.validate_pdb(path)['valid'])

        # Info stream (page 2) should now carry the new sig/age
        with open(path, 'rb') as f:
            data = f.read()
        sig = struct.unpack_from('<I', data, 2 * 1024 + 4)[0]
        age = struct.unpack_from('<I', data, 2 * 1024 + 8)[0]
        self.assertEqual(sig, 0xDEADBEEF)
        self.assertEqual(age, 7)


class StampDbgTimestampTests(unittest.TestCase):

    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix='.dbg')
        os.close(fd)
        with open(path, 'wb') as f:
            f.write(data)
        self.addCleanup(lambda: os.path.isfile(path) and os.remove(path))
        return path

    def test_stamp_sets_timestamp(self):
        # Minimal IMAGE_SEPARATE_DEBUG_HEADER: sig 'DI' (0x4944) + zeros
        hdr = bytearray(64)
        struct.pack_into('<H', hdr, 0, 0x4944)
        path = self._write(bytes(hdr))
        res = SymbolUpdater.stamp_dbg_timestamp(path, 0x427B58BB)
        self.assertTrue(res['stamped'], res.get('errors'))
        with open(path, 'rb') as f:
            data = f.read()
        self.assertEqual(struct.unpack_from('<I', data, 8)[0], 0x427B58BB)

    def test_bad_signature_is_rejected(self):
        path = self._write(b'\x00' * 64)
        res = SymbolUpdater.stamp_dbg_timestamp(path, 1)
        self.assertFalse(res['stamped'])


def build_pdb(streams, page_size=1024):
    """Lay out an arbitrary list of streams into a valid PDB 2.0 container.

    page 0 = header, page 1 = free page map, then each non-empty stream on
    its own run of pages, then the root directory.
    """
    sizes = [len(s) for s in streams]
    stream_pages = []
    page_blobs = {}
    next_page = 2
    for s in streams:
        if not s:
            stream_pages.append([])
            continue
        cnt = (len(s) + page_size - 1) // page_size
        pl = list(range(next_page, next_page + cnt))
        for i, pn in enumerate(pl):
            page_blobs[pn] = s[i * page_size:(i + 1) * page_size]
        stream_pages.append(pl)
        next_page += cnt

    root = bytearray()
    root += struct.pack('<HH', len(streams), 0)
    for sz in sizes:
        root += struct.pack('<II', sz, 0)
    for pl in stream_pages:
        for pn in pl:
            root += struct.pack('<H', pn)
    root_size = len(root)
    root_cnt = (root_size + page_size - 1) // page_size
    root_pages = list(range(next_page, next_page + root_cnt))
    for i, pn in enumerate(root_pages):
        page_blobs[pn] = root[i * page_size:(i + 1) * page_size]
    next_page += root_cnt

    num_pages = next_page
    data = bytearray(b'\x00' * (num_pages * page_size))
    for pn, blob in page_blobs.items():
        data[pn * page_size:pn * page_size + len(blob)] = blob
    data[:44] = PDB20_SIG
    struct.pack_into('<I', data, 44, page_size)
    struct.pack_into('<H', data, 48, 1)
    struct.pack_into('<H', data, 50, num_pages)
    struct.pack_into('<I', data, 52, root_size)
    struct.pack_into('<I', data, 56, 0)
    for i, pn in enumerate(root_pages):
        struct.pack_into('<H', data, 60 + i * 2, pn)
    return bytes(data)


def build_pdb_with_publics(names):
    """Build a PDB whose publics stream (stream 5) is exactly what the
    serializer produces for the S_PUB32 records in the symbol-record stream
    (stream 4), wired through an old-format DBI header (stream 3)."""
    symrec = bytearray()
    for i, nm in enumerate(names):
        symrec += make_pub32(nm, offset=0x1000 * (i + 1), segment=1)
    pubs = SymbolUpdater._walk_pub32(bytes(symrec))
    seed = struct.pack('<iiIiHHii', 0, 0, 0, 0, 0, 0, 0, 0)   # PSGSIHDR, no thunks
    v_new = {'fmt': 'new', 'off_base': 1, 'cref': 1, 'stride': 12}
    publics = SymbolUpdater._serialize_publics_stream(pubs, seed, v_new)

    info = struct.pack('<III', 19960307, 0x11111111, 1)
    dbi = bytearray(24)
    struct.pack_into('<H', dbi, 0, 0xFFFF)   # snGSSyms: none
    struct.pack_into('<H', dbi, 2, 5)        # snPSSyms = stream 5
    struct.pack_into('<H', dbi, 4, 4)        # snSymRecs = stream 4
    streams = [b'', info, b'', bytes(dbi), bytes(symrec), publics]
    return build_pdb(streams), pubs


class PublicsIndexTests(unittest.TestCase):

    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix='.pdb')
        os.close(fd)
        with open(path, 'wb') as f:
            f.write(data)
        self.addCleanup(lambda: os.path.isfile(path) and os.remove(path))
        return path

    def test_hash_name_is_deterministic_and_in_range(self):
        a = SymbolUpdater._gsi_hash_name(b'NtCreateFile')
        b = SymbolUpdater._gsi_hash_name(b'NtCreateFile')
        self.assertEqual(a, b)
        self.assertTrue(0 <= a < SymbolUpdater._IPHR_HASH)

    def test_reproduce_gate_passes_on_self_consistent_file(self):
        data, pubs = build_pdb_with_publics([b'NtClose', b'NtCreateFile',
                                             b'KeBugCheck', b'IoCreateDevice'])
        path = self._write(data)
        res = SymbolUpdater.verify_publics_reproducible(path)
        self.assertTrue(res['reproducible'], res.get('reason'))
        self.assertEqual(res['publics'], len(pubs))
        # The container itself stays structurally valid.
        self.assertTrue(SymbolUpdater.validate_pdb(path)['valid'])

    def test_rebuild_index_round_trips(self):
        data, pubs = build_pdb_with_publics([b'foo', b'bar', b'baz', b'qux'])
        path = self._write(data)
        res = SymbolUpdater.rebuild_publics_index(path)
        self.assertTrue(res['reindexed'], res.get('errors'))
        self.assertEqual(res['publics'], len(pubs))
        self.assertTrue(SymbolUpdater.validate_pdb(path)['valid'])
        # Rebuild is idempotent: the publics stream still reproduces.
        again = SymbolUpdater.verify_publics_reproducible(path)
        self.assertTrue(again['reproducible'], again.get('reason'))

    def test_reproduce_gate_fails_on_tampered_publics(self):
        data, _ = build_pdb_with_publics([b'aaa', b'bbb'])
        data = bytearray(data)
        # Corrupt one byte inside the publics stream payload (page for
        # stream 5 sits after header/fpm/info/dbi/symrec; flip a byte well
        # inside the GSI hash records region).
        # Find stream 5's first page via the parser to stay robust.
        p = SymbolUpdater._parse_pdb20(bytes(data))
        ps_page = p['stream_pages'][5][0]
        data[ps_page * p['page_size'] + 40] ^= 0xFF
        path = self._write(bytes(data))
        res = SymbolUpdater.verify_publics_reproducible(path)
        self.assertFalse(res['reproducible'])


if __name__ == '__main__':
    unittest.main()
