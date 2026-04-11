"""Regression test for UBRT v7.2"""
import sys
from nt_analyzer.ubrt_engine import UBRTEngine

e = UBRTEngine()
info = e.load(r'C:\Users\win2000\Desktop\2kDEBUG\ntoskrnl.exe')
print(f"success: {info['success']}")
print(f"refs_found: {info['refs_found']}")

# Check signature detection + strip
sig = e.check_signature()
print(f"has_signature: {sig is not None}")
if sig:
    print(f"sig_type: {sig['type']}")

# Check stats
stats = info['stats']
by_type = stats['by_type']
new_types = {}
for t in ['indirect_call_mem', 'resource_rva', 'bound_import_rva', 'indirect_jump']:
    if t in by_type:
        new_types[t] = by_type[t]
print(f"v7.1_refs: {new_types}")
print(f"confidence: {stats['by_confidence']}")

# Test strip_signature (on a copy, don't corrupt the engine)
strip_result = e.strip_signature()
print(f"strip_result: {strip_result}")

# Line count
with open('nt_analyzer/ubrt_engine.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
print(f"total_lines: {len(lines)}")
