"""Quick test: NtCreateFile callers."""
import sys
sys.path.insert(0, '.')
from nt_analyzer.kernel_debugger import KernelEnvironment, DebugSession

SYSTEM32 = r"C:\Users\win2000\Desktop\2kDEBUG\system32"
env = KernelEnvironment(SYSTEM32)
env.load_core()
env.auto_load_dependencies()
dbg = DebugSession(env)

callers = dbg.find_callers('NtCreateFile')
direct = [c for c in callers if c.get('call_type') == 'direct']
ssdt = [c for c in callers if c.get('call_type') == 'ssdt']
stubs = [c for c in callers if c.get('call_type') == 'syscall_stub']
print(f"NtCreateFile: {len(callers)} total  ({len(direct)} direct, {len(ssdt)} ssdt, {len(stubs)} stubs)")
for c in callers:
    if c['call_type'] != 'direct':
        addr = f"0x{c['caller_address']:08X}" if c['caller_address'] else "(indirect)"
        print(f"  [{c['call_type']:12s}] {addr}  {c['caller_module']:16s}  {c['caller_function']}")
if direct:
    print(f"  + {len(direct)} direct callers")
if ssdt:
    print(f"  syscall# = 0x{ssdt[0]['syscall_num']:X} ({ssdt[0]['syscall_num']})")
