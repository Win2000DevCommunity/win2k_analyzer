#!/usr/bin/env python3
"""Batch SymRecov for KB979683 (16e2) patch set vs rollup + MS symbols.

Discovers PE files in the patch folder, pairs each with rollup original
and MS symbol (.pdb), exports patched PDBs, and writes a summary report.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ORIG_DIR = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU"
PATCH_DIR = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU"
SYM_ROOT = r"C:\Users\Win2000\Downloads\symbols"
OUT_ROOT = r"C:\Users\Win2000\Desktop\Windows2000Debugging\Symbols"
REPORT_PATH = os.path.join(ROOT, "symrecov_16e_batch_report.json")

PE_EXT = {".exe", ".dll", ".sys", ".drv"}

# Patched HAL.DLL shares halmacpi build
SYM_ALIASES = {
    "hal": ["halmacpi", "halaacpi", "halacpi"],
}


def find_pe(directory: str, stem: str) -> str | None:
    if not os.path.isdir(directory):
        return None
    t = stem.lower()
    for name in os.listdir(directory):
        s, ext = os.path.splitext(name)
        if s.lower() == t and ext.lower() in PE_EXT:
            return os.path.join(directory, name)
    return None


def find_symbol(stem: str) -> str | None:
    for sub in ("exe", "dll", "sys"):
        d = os.path.join(SYM_ROOT, sub)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            s, ext = os.path.splitext(name)
            if s.lower() == stem.lower() and ext.lower() == ".pdb":
                return os.path.join(d, name)
    return None


def resolve_orig(stem: str) -> str | None:
    p = find_pe(ORIG_DIR, stem)
    if p:
        return p
    for alt in SYM_ALIASES.get(stem.lower(), []):
        p = find_pe(ORIG_DIR, alt)
        if p:
            return p
    return None


def resolve_sym(stem: str) -> str | None:
    p = find_symbol(stem)
    if p:
        return p
    for alt in SYM_ALIASES.get(stem.lower(), []):
        p = find_symbol(alt)
        if p:
            return p
    return None


def symbol_subdir(sym_path: str) -> str:
    for sub in ("exe", "dll", "sys"):
        if f"{os.sep}{sub}{os.sep}" in sym_path.replace("/", os.sep):
            return sub
    return "exe"


def count_oob_pdb70(pdb_path: str, pe_path: str) -> int:
    from nt_analyzer.pdb70.msf import parse_msf70
    from nt_analyzer.pdb70.segment_map import (
        parse_section_map, resolve_frame_rva, pe_section_layout,
    )
    from nt_analyzer.pdb70.symbols import walk_pub32, dbi_stream_indices
    import pefile

    pe = pefile.PE(pe_path, fast_load=True)
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    pe.close()
    pv, _ = pe_section_layout(pe_path)
    msf = parse_msf70(pdb_path)
    if not msf:
        return -1
    sm = parse_section_map(msf["read_stream"](3))
    _, _, sn = dbi_stream_indices(msf["read_stream"](3))
    symrec = msf["read_stream"](sn)
    oob = 0
    for _ro, _name, seg, off in walk_pub32(symrec):
        rva = resolve_frame_rva(seg, off, sm, pv)
        if rva is not None and rva >= image_size:
            oob += 1
    return oob


def process_one(patched_name: str, orig: str, sym: str, out_pdb: str) -> dict:
    from nt_analyzer.symbol_recovery import SymbolRecoveryEngine
    from nt_analyzer.pdb70.msf import detect_pdb_format

    engine = SymbolRecoveryEngine()
    engine.diff_binaries(orig, os.path.join(PATCH_DIR, patched_name))
    count, meta = engine.load_symbols(sym, pe_path=orig)
    if not count:
        return {"status": "FAIL", "error": f"no symbols loaded: {meta.get('error')}"}

    engine.recover_symbols(orig_pe_path=orig)
    stats = engine.get_stats()

    patched_pe = find_pe(PATCH_DIR, os.path.splitext(patched_name)[0])
    if not patched_pe:
        patched_pe = os.path.join(PATCH_DIR, patched_name)

    result = engine.export_pdb(sym, out_pdb,
                               orig_pe_path=orig,
                               patched_pe_path=patched_pe)
    fmt = result.get("pdb_format") or detect_pdb_format(out_pdb)
    val = result.get("validation") or {}

    entry = {
        "status": "OK" if val.get("valid") else "FAIL",
        "patched": patched_name,
        "orig": orig,
        "symbols": sym,
        "output": out_pdb,
        "pdb_format": fmt,
        "loaded": count,
        "recovery": stats,
        "validation": val,
        "export": {
            "reindexed": (result.get("reindexed") or {}).get("reindexed"),
            "section_results": result.get("section_results"),
            "hal_deploy": bool(result.get("hal_deploy")),
        },
    }
    if fmt == "pdb70" and os.path.isfile(out_pdb):
        entry["oob_publics"] = count_oob_pdb70(out_pdb, patched_pe)
    return entry


def discover_modules():
    rows = []
    for name in sorted(os.listdir(PATCH_DIR)):
        stem, ext = os.path.splitext(name)
        if ext.lower() not in PE_EXT:
            continue
        orig = resolve_orig(stem)
        sym = resolve_sym(stem)
        rows.append({
            "patched": name,
            "stem": stem,
            "orig": orig,
            "symbols": sym,
            "ready": bool(orig and sym),
        })
    return rows


def main():
    os.makedirs(OUT_ROOT, exist_ok=True)
    modules = discover_modules()
    report = {
        "when": datetime.now().isoformat(timespec="seconds"),
        "patch_dir": PATCH_DIR,
        "orig_dir": ORIG_DIR,
        "sym_root": SYM_ROOT,
        "out_root": OUT_ROOT,
        "modules": modules,
        "results": [],
    }

    print("KB979683 (16e2) SymRecov batch")
    print("=" * 70)
    ready = [m for m in modules if m["ready"]]
    skip = [m for m in modules if not m["ready"]]
    print(f"  Patch PE files: {len(modules)}  ready: {len(ready)}  skip: {len(skip)}\n")

    for m in modules:
        tag = "READY" if m["ready"] else "SKIP "
        print(f"  {tag}  {m['patched']}")

    print("\n" + "=" * 70)
    print("  EXPORTING\n")

    for m in ready:
        sub = symbol_subdir(m["symbols"])
        out_dir = os.path.join(OUT_ROOT, sub)
        os.makedirs(out_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(m["symbols"]))[0]
        out_pdb = os.path.join(out_dir, base + ".pdb")

        print(f"\n>>> {m['patched']}  ({base}.pdb, fmt pending...)")
        try:
            entry = process_one(m["patched"], m["orig"], m["symbols"], out_pdb)
            entry["module"] = m["patched"]
            report["results"].append(entry)
            st = entry["status"]
            fmt = entry.get("pdb_format", "?")
            ok = entry.get("recovery", {}).get("ok", 0)
            tot = entry.get("recovery", {}).get("total", 0)
            rate = entry.get("recovery", {}).get("success_rate", 0)
            line = f"    {st}  fmt={fmt}  recovery={ok}/{tot} ({rate:.1%})"
            if "oob_publics" in entry:
                line += f"  oob={entry['oob_publics']}"
            print(line)
            if entry.get("export", {}).get("hal_deploy"):
                print("    HAL bundle deployed")
        except Exception as e:
            print(f"    FAIL  {e}")
            report["results"].append({
                "module": m["patched"],
                "status": "FAIL",
                "error": str(e),
                "trace": traceback.format_exc(),
            })

    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    ok_n = sum(1 for r in report["results"] if r.get("status") == "OK")
    fail_n = sum(1 for r in report["results"] if r.get("status") == "FAIL")
    print(f"  Exported OK: {ok_n}   Failed: {fail_n}   Skipped: {len(skip)}")
    for r in report["results"]:
        detail = r.get("output", r.get("error", ""))[:60]
        print(f"    {r.get('module','?'):20}  {r.get('status','?'):6}  {detail}")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report: {REPORT_PATH}")


if __name__ == "__main__":
    main()
