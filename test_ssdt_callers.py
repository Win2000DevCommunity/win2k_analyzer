"""Test SSDT-aware find_callers on NtPowerInformation."""
import sys
sys.path.insert(0, '.')

from nt_analyzer.kernel_debugger import KernelEnvironment, DebugSession

SYSTEM32 = r"C:\Users\win2000\Desktop\2kDEBUG\system32"

env = KernelEnvironment(SYSTEM32)
env.load_core()
env.auto_load_dependencies()

dbg = DebugSession(env)

# Test 1: NtPowerInformation — should find SSDT + Zw stub + direct callers
print("=" * 60)
print("TEST: find_callers('NtPowerInformation')")
print("=" * 60)
callers = dbg.find_callers('NtPowerInformation')

direct = [c for c in callers if c.get('call_type') == 'direct']
ssdt = [c for c in callers if c.get('call_type') == 'ssdt']
stubs = [c for c in callers if c.get('call_type') == 'syscall_stub']

print(f"Total: {len(callers)}")
print(f"  Direct CALL: {len(direct)}")
print(f"  SSDT dispatch: {len(ssdt)}")
print(f"  Syscall stubs: {len(stubs)}")
print()

for c in callers:
    addr = f"0x{c['caller_address']:08X}" if c['caller_address'] else "(indirect)"
    print(f"  [{c['call_type']:12s}] {addr}  {c['caller_module']:16s}  {c['caller_function']}")
    if c['syscall_num'] is not None:
        print(f"                 syscall# = 0x{c['syscall_num']:X} ({c['syscall_num']})")

print()

# Verify SSDT was detected
assert len(ssdt) >= 1, "FAIL: No SSDT dispatch detected for NtPowerInformation"
assert any('KiSystemService' in c['caller_function'] for c in ssdt), "FAIL: KiSystemService not in SSDT callers"
print("PASS: SSDT dispatch detected")

# Verify Zw stub was found
assert any('Zw' in c['caller_function'] for c in ssdt), "FAIL: ZwPowerInformation stub not found"
print("PASS: ZwPowerInformation stub detected")

# Verify syscall number is present
sc_nums = [c['syscall_num'] for c in callers if c['syscall_num'] is not None]
assert len(sc_nums) > 0, "FAIL: No syscall number found"
print(f"PASS: Syscall number = 0x{sc_nums[0]:X} ({sc_nums[0]})")

# Test 2: ExAcquireResourceExclusiveLite — NOT in SSDT, should be direct only
print()
print("=" * 60)
print("TEST: find_callers('ExAcquireResourceExclusiveLite')")
print("=" * 60)
callers2 = dbg.find_callers('ExAcquireResourceExclusiveLite')

direct2 = [c for c in callers2 if c.get('call_type') == 'direct']
ssdt2 = [c for c in callers2 if c.get('call_type') == 'ssdt']
stubs2 = [c for c in callers2 if c.get('call_type') == 'syscall_stub']

print(f"Total: {len(callers2)}")
print(f"  Direct CALL: {len(direct2)}")
print(f"  SSDT dispatch: {len(ssdt2)}")
print(f"  Syscall stubs: {len(stubs2)}")

assert len(ssdt2) == 0, "FAIL: ExAcquireResourceExclusiveLite should not have SSDT callers"
assert len(direct2) > 50, f"FAIL: Expected many direct callers, got {len(direct2)}"
print(f"PASS: {len(direct2)} direct callers, no SSDT (correct)")

print()
print("ALL TESTS PASSED")
