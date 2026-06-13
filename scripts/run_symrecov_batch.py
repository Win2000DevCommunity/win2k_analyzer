#!/usr/bin/env python3
"""Run symbol recovery on a set of Win2000 kernel modules via CLI."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, 'win2k_analyzer.py')

ORIG_DIR = r'C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU'
PATCH_DIR = r'C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU'
SYM_DIR = r'C:\Users\Win2000\Downloads\symbols\exe'
OUT_DIR = r'C:\Users\Win2000\Downloads\Modified sym'

# basename (case-insensitive) → optional alternate symbol basename
MODULES = [
    'ntkrnlmp',
    'hal',
    'halacpi',
    'halapic',
    'halmacpi',
    'halmps',
    'ntoskrnl',
    'kdcom',
    'bootvid',
    'ci',
    'diskdump',
    'framebuf',
    'ksecdd',
    'msrpc',
    'ndis',
    'ntfs',
    'scsiport',
    'symevent',
    'win32k',
    'winsrv',
]


def find_file(directory, basename):
    """Return first path in *directory* whose stem matches *basename*."""
    if not os.path.isdir(directory):
        return None
    target = basename.lower()
    for name in os.listdir(directory):
        stem, ext = os.path.splitext(name)
        if stem.lower() == target and ext.lower() in ('.exe', '.dll', '.sys', ''):
            return os.path.join(directory, name)
    return None


def find_symbol(basename):
    for ext in ('.pdb', '.dbg', '.map'):
        p = os.path.join(SYM_DIR, basename + ext)
        if os.path.isfile(p):
            return p
        # try uppercase stem variants
        for name in os.listdir(SYM_DIR) if os.path.isdir(SYM_DIR) else []:
            stem, e = os.path.splitext(name)
            if stem.lower() == basename.lower() and e.lower() == ext:
                return os.path.join(SYM_DIR, name)
    return None


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    report = []

    print('Scanning module triples...\n')
    for mod in MODULES:
        orig = find_file(ORIG_DIR, mod)
        patched = find_file(PATCH_DIR, mod)
        sym = find_symbol(mod)
        line = f'{mod:12s}  orig={bool(orig)}  patch={bool(patched)}  sym={bool(sym)}'
        if orig:
            line += f'  ({os.path.basename(orig)})'
        print(line)
        if not (orig and patched and sym):
            report.append((mod, 'SKIP', 'missing file(s)'))
            continue

        out_pdb = os.path.join(OUT_DIR, os.path.splitext(os.path.basename(sym))[0] + '.pdb')
        cmd = [
            sys.executable, CLI, 'symrecov',
            '--orig', orig,
            '--patched', patched,
            '--symbols', sym,
            '-o', out_pdb,
        ]
        print(f'\n>>> {" ".join(cmd)}\n')
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              encoding='utf-8', errors='replace')
        out = (proc.stdout or '') + (proc.stderr or '')
        try:
            sys.stdout.buffer.write(out.encode('utf-8', errors='replace'))
        except Exception:
            print(out)
        status = 'OK' if proc.returncode == 0 else f'FAIL({proc.returncode})'
        report.append((mod, status, out_pdb if proc.returncode == 0 else proc.stderr[:200]))

    print('\n' + '=' * 70)
    print('  BATCH SUMMARY')
    print('=' * 70)
    for mod, status, detail in report:
        print(f'  {mod:12s}  {status:8s}  {detail}')


if __name__ == '__main__':
    main()
