"""Temporary test for kernel debugger step mode and quick_debug."""
import sys
sys.path.insert(0, '.')
from nt_analyzer.kernel_debugger import *

SYS32 = r'C:\Users\win2000\Desktop\2kDEBUG\system32'

# Test 1: Step mode
print('=== Test 1: Step Mode ===')
env = KernelEnvironment(SYS32)
env.load_core()
env.auto_load_dependencies()

dbg = DebugSession(env)
result = dbg.run('NtPowerInformation', args=[0, 0, 0, 0x1000, 0x1000],
                 stop_at_entry=True)
print(f'After run: state={dbg.state.name}')
for i in range(10):
    regs = dbg.inspect_registers()
    eip = regs["eip"]
    eip_name = regs.get("eip_name", "?")
    esp = regs["esp"]
    print(f'Step {i}: EIP=0x{eip:08X} ({eip_name}), ESP=0x{esp:08X}')
    r = dbg.step()
    if r and r.get("state") == "completed":
        retval = r.get("return_value", 0)
        print(f'  => Function returned: 0x{retval:08X}')
        break

# Continue with full run
if dbg.state == DebugState.PAUSED:
    print('Continuing from pause...')
    result2 = dbg.continue_run()
    retval = result2.get("return_value", 0)
    print(f'Final: 0x{retval:08X} ({ntstatus_name(retval)}) in {result2.get("instructions",0)} insns')

env.close()

# Test 2: quick_debug convenience function
print('\n=== Test 2: quick_debug ===')
report = quick_debug(SYS32, 'NtPowerInformation', args=[0, 0, 0, 0x1000, 0x1000])
print(report[:2000])

# Test 3: NtQuerySystemInformation (class 0 = SystemBasicInformation)
print('\n=== Test 3: NtQuerySystemInformation ===')
report2 = quick_debug(SYS32, 'NtQuerySystemInformation', args=[0, 0x1000, 0x100, 0x1000])
print(report2[:2000])

print('\n=== ALL TESTS PASSED ===')
