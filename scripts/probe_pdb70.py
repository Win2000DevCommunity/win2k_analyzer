#!/usr/bin/env python3
"""Probe a PDB 7.0 (MSF 7.00) file — stream layout, DBI, symbol counts."""
import struct
import math
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.pdb70.msf import parse_msf70, detect_pdb_format


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        r'C:\Users\Win2000\Downloads\symbols\dll\halmacpi.pdb'
    fmt = detect_pdb_format(path)
    print('File:', path)
    print('Format:', fmt)
    p = parse_msf70(path)
    if not p:
        print('parse failed')
        return 1
    print('page_size', p['page_size'], 'streams', p['num_streams'],
          'file_pages', len(p['data']) // p['page_size'])
    for i, sz in enumerate(p['sizes']):
        if sz and sz != 0xFFFFFFFF:
            print(f'  stream[{i}] size={sz}')
    dbi = p['read_stream'](3)
    print('DBI len', len(dbi))
    if len(dbi) >= 24:
        print('DBI word0', hex(struct.unpack_from('<I', dbi, 0)[0]))
    from nt_analyzer.pdb70.symbols import dbi_stream_indices, walk_pub32
    idx = dbi_stream_indices(dbi)
    print('DBI indices', idx)
    if idx:
        sn_gs, sn_ps, sn_sym = idx
        symrec = p['read_stream'](sn_sym)
        pubs = list(walk_pub32(symrec))
        print('symrec stream', sn_sym, 'len', len(symrec),
              'S_PUB32 count', len(pubs))
        if pubs[:3]:
            for t in pubs[:3]:
                print(' ', t)
        ps = p['read_stream'](sn_ps)
        print('publics stream', sn_ps, 'len', len(ps))
        if len(ps) >= 8:
            print('  hdr words', struct.unpack_from('<ii', ps, 0))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
