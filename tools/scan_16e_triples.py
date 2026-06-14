"""Discover PE modules in 16e patch folder with orig+symbol triples."""
import os

ORIG = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU"
PATCH = r"C:\Users\Win2000\Downloads\Windows2000-KB979683-v16e2-x86-ENU"
SYM_ROOT = r"C:\Users\Win2000\Downloads\symbols"
PE_EXT = {".exe", ".dll", ".sys", ".drv"}


def find_in_dir(directory, stem):
    if not os.path.isdir(directory):
        return None
    t = stem.lower()
    for name in os.listdir(directory):
        s, ext = os.path.splitext(name)
        if s.lower() == t and ext.lower() in PE_EXT:
            return os.path.join(directory, name)
    return None


def find_symbol(stem):
    for sub in ("exe", "dll", "sys"):
        d = os.path.join(SYM_ROOT, sub)
        if not os.path.isdir(d):
            continue
        for ext in (".pdb",):
            p = os.path.join(d, stem + ext)
            if os.path.isfile(p):
                return p
            for name in os.listdir(d):
                s, e = os.path.splitext(name)
                if s.lower() == stem.lower() and e.lower() == ext:
                    return os.path.join(d, name)
    return None


# HAL alias: patched HAL.DLL often pairs with halmacpi symbols
ALIASES = {
    "hal": ["halmacpi", "halaacpi", "halacpi", "halapic", "halmps", "halsp", "halborg"],
}


def resolve_orig(stem):
    p = find_in_dir(ORIG, stem)
    if p:
        return p
    for alt in ALIASES.get(stem.lower(), []):
        p = find_in_dir(ORIG, alt)
        if p:
            return p
    return None


def resolve_sym(stem):
    p = find_symbol(stem)
    if p:
        return p
    for alt in ALIASES.get(stem.lower(), []):
        p = find_symbol(alt)
        if p:
            return p
    return None


print("16e patch PE modules:\n")
rows = []
for name in sorted(os.listdir(PATCH)):
    stem, ext = os.path.splitext(name)
    if ext.lower() not in PE_EXT:
        continue
    orig = resolve_orig(stem)
    sym = resolve_sym(stem)
    rows.append((stem, name, orig, sym))
    o = os.path.basename(orig) if orig else "-"
    s = os.path.basename(sym) if sym else "-"
    ok = "READY" if orig and sym else "MISSING"
    print(f"  {ok:7}  {name:20}  orig={o:20}  sym={s}")

ready = sum(1 for r in rows if r[2] and r[3])
print(f"\n{ready}/{len(rows)} ready for symrecov")
