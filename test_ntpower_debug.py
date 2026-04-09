"""
Comprehensive NtPowerInformation Kernel Debugger Test
=====================================================
Tests NtPowerInformation with many different InformationClass values,
buffer sizes, edge cases, breakpoints, stepping, and object inspection.

Results saved to: ntpower_debug_results.txt
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(__file__))

from nt_analyzer.kernel_debugger import (
    KernelEnvironment, DebugSession, ObjectInspector, DebugState,
    ntstatus_name, quick_debug,
)

SYS32 = r"C:\Users\win2000\Desktop\2kDEBUG\system32"
OUT   = os.path.join(os.path.dirname(__file__), "ntpower_debug_results.txt")

# NtPowerInformation InformationClass values (Win2K)
POWER_CLASSES = {
    0:  "SystemPowerPolicyAc",
    1:  "SystemPowerPolicyDc",
    2:  "VerifySystemPolicies",
    3:  "SystemPowerPolicyCurrent",
    4:  "SystemPowerStateHandler",
    5:  "ProcessorStateHandler",
    6:  "SystemPowerPolicyOld",
    7:  "ProcessorInformation",
    8:  "SystemBatteryState",
    9:  "SystemPowerStateNotifyHandler",
    10: "ProcessorPowerPolicyAc",
    11: "ProcessorPowerPolicyDc",
    12: "VerifyProcessorPowerPolicy",
    13: "ProcessorPowerPolicyCurrent",
    14: "SystemPowerStateLogging",
    15: "SystemPowerLoggingEntry",
    16: "SetPowerSettingValue",
    17: "NotifyUserPowerSetting",
    18: "PowerInformationLevelUnused0",
    19: "PowerInformationLevelUnused1",
    20: "SystemVideoState",
    21: "TraceApplicationPowerMessage",
    22: "TraceApplicationPowerMessageEnd",
    23: "ProcessorPerfStates",
    24: "ProcessorIdleStates",
    25: "ProcessorCap",
    26: "SystemWakeSource",
    27: "SystemHiberFileInformation",
    28: "TraceServicePowerMessage",
    29: "ProcessorLoad",
    30: "PowerShutdownNotification",
    31: "MonitorInvocation",
    32: "FirmwareTableInformationRegistered",
    # Higher values — likely invalid on Win2K
    50: "InvalidClass_50",
    99: "InvalidClass_99",
    0xFF: "InvalidClass_0xFF",
    0xFFFFFFFF: "InvalidClass_MAX",
}

def run_test():
    lines = []
    def W(s=""):
        lines.append(s)
        print(s)

    W("=" * 80)
    W("  NtPowerInformation — LIVE KERNEL DEBUGGER TEST REPORT")
    W(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    W(f"  System32: {SYS32}")
    W("=" * 80)

    # ── Load environment ──────────────────────────────────────────────
    W("\n[1] LOADING KERNEL ENVIRONMENT")
    W("-" * 60)
    t0 = time.perf_counter()
    env = KernelEnvironment(SYS32)
    env.load_core()
    env.auto_load_dependencies()
    load_time = time.perf_counter() - t0
    W(f"  Load time: {load_time:.3f}s")

    info = env.get_info()
    W(f"  Modules loaded: {info['modules_loaded']}")
    W(f"  Available files: {info['available_files']}")
    for name, minfo in info['modules'].items():
        W(f"    {name:24s}  base={minfo['base']}  "
          f"exports={minfo['exports']:5d}  unresolved={minfo['unresolved']}")

    # Resolve NtPowerInformation
    resolved = env.resolve_function("NtPowerInformation")
    if resolved:
        va, mod_name = resolved
        W(f"\n  NtPowerInformation resolved at: {mod_name}!0x{va:08X}")
    else:
        W("\n  ERROR: Cannot resolve NtPowerInformation!")
        return

    # ── Scenario 1: All InformationClass values ───────────────────────
    W("\n" + "=" * 80)
    W("[2] SCENARIO: ALL POWER INFORMATION CLASSES")
    W("    Args: NtPowerInformation(class, NULL, 0, OutputBuf, 0x1000)")
    W("-" * 80)
    W(f"  {'Class':<6} {'Name':<40} {'Return':<16} {'Status':<30} {'Insns':>6}")
    W(f"  {'-'*5:<6} {'-'*39:<40} {'-'*15:<16} {'-'*29:<30} {'-'*6:>6}")

    for cls_val, cls_name in sorted(POWER_CLASSES.items()):
        dbg = DebugSession(env)
        result = dbg.run("NtPowerInformation",
                         args=[cls_val, 0, 0, 0x1000, 0x1000])
        ret = result["return_value"]
        status = ntstatus_name(ret)
        insns = result["instructions"]
        W(f"  {cls_val:<6} {cls_name:<40} 0x{ret:08X}      {status:<30} {insns:>6}")

    # ── Scenario 2: Buffer size variations ────────────────────────────
    W("\n" + "=" * 80)
    W("[3] SCENARIO: BUFFER SIZE VARIATIONS (Class=0 SystemPowerPolicyAc)")
    W("    Testing different output buffer sizes")
    W("-" * 80)
    W(f"  {'BufSize':<12} {'Return':<16} {'Status':<30} {'Insns':>6}")
    W(f"  {'-'*11:<12} {'-'*15:<16} {'-'*29:<30} {'-'*6:>6}")

    for buf_size in [0, 1, 4, 16, 64, 128, 256, 512, 0x1000, 0x10000]:
        dbg = DebugSession(env)
        # Allocate real buffer for non-zero sizes
        buf_addr = env.heap_alloc(max(buf_size, 16)) if buf_size > 0 else 0
        result = dbg.run("NtPowerInformation",
                         args=[0, 0, 0, buf_addr, buf_size])
        ret = result["return_value"]
        status = ntstatus_name(ret)
        insns = result["instructions"]
        size_str = f"0x{buf_size:X}" if buf_size >= 16 else str(buf_size)
        W(f"  {size_str:<12} 0x{ret:08X}      {status:<30} {insns:>6}")

    # ── Scenario 3: With input buffer ─────────────────────────────────
    W("\n" + "=" * 80)
    W("[4] SCENARIO: INPUT BUFFER TESTS")
    W("    Testing classes that expect input data (Set operations)")
    W("-" * 80)
    W(f"  {'Class':<6} {'Name':<35} {'InBuf':<10} {'Return':<16} {'Status':<30}")
    W(f"  {'-'*5:<6} {'-'*34:<35} {'-'*9:<10} {'-'*15:<16} {'-'*29:<30}")

    input_tests = [
        (0, "SystemPowerPolicyAc",      0,      0,      "NULL, 0"),
        (0, "SystemPowerPolicyAc",      0x1000, 256,    "buf, 256"),
        (2, "VerifySystemPolicies",     0,      0,      "NULL, 0"),
        (2, "VerifySystemPolicies",     0x1000, 0x100,  "buf, 256"),
        (7, "ProcessorInformation",     0,      0,      "NULL, 0"),
        (7, "ProcessorInformation",     0x1000, 64,     "buf, 64"),
        (8, "SystemBatteryState",       0,      0,      "NULL, 0"),
        (10, "ProcessorPowerPolicyAc",  0,      0,      "NULL, 0"),
        (10, "ProcessorPowerPolicyAc",  0x1000, 128,    "buf, 128"),
    ]

    for cls_val, cls_name, in_buf, in_size, desc in input_tests:
        dbg = DebugSession(env)
        out_buf = env.heap_alloc(0x1000)
        result = dbg.run("NtPowerInformation",
                         args=[cls_val, in_buf, in_size, out_buf, 0x1000])
        ret = result["return_value"]
        status = ntstatus_name(ret)
        W(f"  {cls_val:<6} {cls_name:<35} {desc:<10} 0x{ret:08X}      {status:<30}")

    # ── Scenario 4: NULL output buffer ────────────────────────────────
    W("\n" + "=" * 80)
    W("[5] SCENARIO: NULL OUTPUT BUFFER")
    W("    NtPowerInformation(class, NULL, 0, NULL, 0)")
    W("-" * 80)
    W(f"  {'Class':<6} {'Name':<40} {'Return':<16} {'Status':<30} {'Insns':>6}")
    W(f"  {'-'*5:<6} {'-'*39:<40} {'-'*15:<16} {'-'*29:<30} {'-'*6:>6}")

    for cls_val in [0, 3, 7, 8, 23, 29]:
        cls_name = POWER_CLASSES.get(cls_val, f"Class_{cls_val}")
        dbg = DebugSession(env)
        result = dbg.run("NtPowerInformation",
                         args=[cls_val, 0, 0, 0, 0])
        ret = result["return_value"]
        status = ntstatus_name(ret)
        insns = result["instructions"]
        W(f"  {cls_val:<6} {cls_name:<40} 0x{ret:08X}      {status:<30} {insns:>6}")

    # ── Scenario 5: Breakpoint + step demo ────────────────────────────
    W("\n" + "=" * 80)
    W("[6] SCENARIO: BREAKPOINT + STEPPING (Class=0)")
    W("    Stop at entry, step 20 instructions, then continue")
    W("-" * 80)

    dbg = DebugSession(env)
    result = dbg.run("NtPowerInformation",
                     args=[0, 0, 0, 0x1000, 0x1000],
                     stop_at_entry=True)
    W(f"  State after run: {dbg.state.name}")

    for i in range(20):
        regs = dbg.inspect_registers()
        eip = regs["eip"]
        eip_name = regs.get("eip_name", f"0x{eip:08X}")
        eax = regs["eax"]
        esp = regs["esp"]
        W(f"  Step {i:2d}: EIP=0x{eip:08X}  {eip_name:<50s} "
          f"EAX=0x{eax:08X}  ESP=0x{esp:08X}")
        r = dbg.step()
        if r and r.get("state") == "completed":
            retval = r.get("return_value", 0)
            W(f"  => Function returned: 0x{retval:08X} ({ntstatus_name(retval)})")
            break

    if dbg.state == DebugState.PAUSED:
        W("\n  Call stack at step 20:")
        frames = dbg.get_call_stack()
        for j, f in enumerate(frames):
            mod = f.module or "???"
            func = f.function or f"0x{f.return_address:08X}"
            W(f"    #{j}: {mod}!{func}  (FP=0x{f.frame_pointer:08X})")

        W("\n  Continuing execution...")
        result2 = dbg.continue_run()
        ret = result2.get("return_value", 0)
        W(f"  Final: 0x{ret:08X} ({ntstatus_name(ret)}) "
          f"in {result2.get('instructions', 0)} instructions")
    dbg.close()

    # ── Scenario 6: Named breakpoint on internal function ─────────────
    W("\n" + "=" * 80)
    W("[7] SCENARIO: BREAKPOINT ON ExAcquireResourceExclusiveLite")
    W("    Verify the function calls into resource acquisition")
    W("-" * 80)

    dbg = DebugSession(env)
    dbg.set_breakpoint("ExAcquireResourceExclusiveLite")
    result = dbg.run("NtPowerInformation",
                     args=[0, 0, 0, 0x1000, 0x1000])
    W(f"  State: {dbg.state.name}")
    if dbg.state == DebugState.PAUSED:
        regs = dbg.inspect_registers()
        eip = regs["eip"]
        eip_name = regs.get("eip_name", f"0x{eip:08X}")
        W(f"  Paused at: {eip_name} (EIP=0x{eip:08X})")
        W(f"  Events so far:")
        for ev in dbg.events:
            W(f"    [{ev.event_type}] {ev.message}")
        W("\n  Continuing to completion...")
        result2 = dbg.continue_run()
        ret = result2.get("return_value", 0)
        W(f"  Final: 0x{ret:08X} ({ntstatus_name(ret)})")
    else:
        ret = result.get("return_value", 0)
        W(f"  Result: 0x{ret:08X} ({ntstatus_name(ret)})")
        W(f"  Events: {len(result.get('events', []))}")
    dbg.close()

    # ── Scenario 7: Full trace for class 0 ────────────────────────────
    W("\n" + "=" * 80)
    W("[8] SCENARIO: FULL INSTRUCTION TRACE (Class=0)")
    W("    Complete instruction-by-instruction trace")
    W("-" * 80)

    dbg = DebugSession(env)
    result = dbg.run("NtPowerInformation",
                     args=[0, 0, 0, 0x1000, 0x1000],
                     show_trace=True)
    trace = result.get("trace", [])
    W(f"  Total instructions: {result['instructions']}")
    W(f"  Trace entries: {len(trace)}")
    W(f"  Return: 0x{result['return_value']:08X} ({ntstatus_name(result['return_value'])})")
    W(f"\n  {'VA':<14} {'Instruction':<50} {'Note'}")
    W(f"  {'-'*13:<14} {'-'*49:<50} {'-'*15}")

    for t in trace:
        instr = f"{t['mnemonic']} {t['op_str']}".strip()
        note = ""
        if t['mnemonic'] == "ret" or t['mnemonic'].startswith("ret"):
            note = "<-- RETURN"
        elif t['mnemonic'] == "call":
            note = "<-- CALL"
        elif t['mnemonic'].startswith("j") and t['mnemonic'] != "jmp":
            note = "<-- BRANCH"
        elif "fs:" in t['op_str']:
            note = "<-- FS SEGMENT"
        elif "rep" in t['mnemonic']:
            note = "<-- REP"
        func_info = env.find_function_at(t['address'])
        if func_info:
            fn_name, fn_mod = func_info
            if fn_name != func_info[0]:
                note += f"  [{fn_mod}!{fn_name}]"
        W(f"  0x{t['address']:08X}     {instr:<50} {note}")

    # ── Scenario 8: Cross-module call analysis ────────────────────────
    W("\n" + "=" * 80)
    W("[9] SCENARIO: CROSS-MODULE CALL ANALYSIS")
    W("    Which modules does NtPowerInformation call into?")
    W("-" * 80)

    module_calls = {}
    for t in trace:
        mod = env.find_module_at(t['address'])
        if mod:
            module_calls[mod.name] = module_calls.get(mod.name, 0) + 1

    W(f"  {'Module':<30} {'Instructions':>12} {'%':>8}")
    W(f"  {'-'*29:<30} {'-'*12:>12} {'-'*7:>8}")
    total = sum(module_calls.values())
    for mc_name, count in sorted(module_calls.items(), key=lambda x: -x[1]):
        pct = count / total * 100 if total else 0
        W(f"  {mc_name:<30} {count:>12} {pct:>7.1f}%")

    # Unique call targets
    call_targets = set()
    for t in trace:
        if t['mnemonic'] == 'call':
            # The next trace entry is the call target
            pass  # We'll look at cross-module transitions instead

    # Find module transitions
    W(f"\n  Module transitions (cross-module calls):")
    prev_mod = None
    transitions = []
    for t in trace:
        cur_mod = env.find_module_at(t['address'])
        cur_name = cur_mod.name if cur_mod else "???"
        if prev_mod and cur_name != prev_mod:
            func_info = env.find_function_at(t['address'])
            fn = func_info[0] if func_info else f"0x{t['address']:08X}"
            transitions.append((prev_mod, cur_name, fn, t['address']))
        prev_mod = cur_name

    for src, dst, fn, addr in transitions:
        W(f"    {src} --> {dst}!{fn} (0x{addr:08X})")

    # ── Scenario 9: Register state at key points ──────────────────────
    W("\n" + "=" * 80)
    W("[10] SCENARIO: REGISTER INSPECTION (Step through prologue)")
    W("     Show how registers change during function setup")
    W("-" * 80)

    dbg = DebugSession(env)
    dbg.run("NtPowerInformation",
            args=[7, 0, 0, 0x1000, 0x1000],  # ProcessorInformation
            stop_at_entry=True)

    W(f"  {'Step':<6} {'EIP':<14} {'EAX':<14} {'ECX':<14} {'ESP':<14} "
      f"{'EBP':<14} {'Location'}")
    W(f"  {'-'*5:<6} {'-'*13:<14} {'-'*13:<14} {'-'*13:<14} {'-'*13:<14} "
      f"{'-'*13:<14} {'-'*30}")

    for i in range(30):
        regs = dbg.inspect_registers()
        eip = regs["eip"]
        eip_name = regs.get("eip_name", f"0x{eip:08X}")
        W(f"  {i:<6} 0x{eip:08X}    0x{regs['eax']:08X}    "
          f"0x{regs['ecx']:08X}    0x{regs['esp']:08X}    "
          f"0x{regs['ebp']:08X}    {eip_name}")
        r = dbg.step()
        if r and r.get("state") == "completed":
            retval = r.get("return_value", 0)
            W(f"  => COMPLETED: 0x{retval:08X} ({ntstatus_name(retval)})")
            break

    if dbg.state == DebugState.PAUSED:
        result3 = dbg.continue_run()
        ret = result3.get("return_value", 0)
        W(f"\n  Final: 0x{ret:08X} ({ntstatus_name(ret)}) "
          f"in {result3.get('instructions', 0)} insns")
    dbg.close()

    # ── Scenario 10: Stack memory analysis ────────────────────────────
    W("\n" + "=" * 80)
    W("[11] SCENARIO: STACK MEMORY ANALYSIS")
    W("     Dump stack after stopping at entry for class 8 (BatteryState)")
    W("-" * 80)

    dbg = DebugSession(env)
    dbg.run("NtPowerInformation",
            args=[8, 0, 0, 0x1000, 0x1000],  # SystemBatteryState
            stop_at_entry=True)

    W(f"  State: {dbg.state.name}")
    entries = dbg.inspect_stack(depth=24)
    W(f"\n  {'Offset':<10} {'Address':<14} {'Value':<14} {'Symbol'}")
    W(f"  {'-'*9:<10} {'-'*13:<14} {'-'*13:<14} {'-'*40}")
    for e in entries:
        sym = e.get("symbol", "")
        W(f"  +0x{e['offset']:04X}    0x{e['address']:08X}    "
          f"0x{e['value']:08X}    {sym}")

    if dbg.state == DebugState.PAUSED:
        result4 = dbg.continue_run()
        ret = result4.get("return_value", 0)
        W(f"\n  Final: 0x{ret:08X} ({ntstatus_name(ret)})")
    dbg.close()

    # ── Scenario 11: Handle table / object inspection ─────────────────
    W("\n" + "=" * 80)
    W("[12] SCENARIO: KERNEL OBJECT INSPECTION")
    W("     Dump handle table + EPROCESS from live environment")
    W("-" * 80)

    insp = ObjectInspector(env)
    W("\n  Handle Table:")
    ht_rows = insp.walk_handle_table()
    for row in ht_rows:
        W(f"    {row}")

    W(f"\n  EPROCESS at 0x{env.kstate.system_eprocess:08X}:")
    obj_dump = insp.dump_object(env.kstate.system_eprocess)
    for row in obj_dump[:20]:
        W(f"    {row}")

    W(f"\n  Null pointer check on EPROCESS:")
    nulls = insp.check_null_pointers(env.kstate.system_eprocess, "EPROCESS")
    if nulls:
        for n in nulls:
            W(f"    ⚠ {n}")
    else:
        W(f"    ✅ No critical null pointers detected")

    # ── Scenario 12: Events and error detection ───────────────────────
    W("\n" + "=" * 80)
    W("[13] SCENARIO: ERROR / EVENT DETECTION")
    W("     Run with invalid parameters to trigger error events")
    W("-" * 80)

    error_tests = [
        ("Invalid class 0xFF",          [0xFF, 0, 0, 0x1000, 0x1000]),
        ("Invalid class MAX",           [0xFFFFFFFF, 0, 0, 0x1000, 0x1000]),
        ("Zero output buffer+size",     [0, 0, 0, 0, 0]),
        ("Huge output size (0xFFFF)",   [0, 0, 0, 0x1000, 0xFFFF]),
        ("Class 7 tiny buffer",         [7, 0, 0, 0x1000, 1]),
        ("Class 8 tiny buffer",         [8, 0, 0, 0x1000, 1]),
    ]

    for desc, args in error_tests:
        dbg = DebugSession(env)
        result = dbg.run("NtPowerInformation", args=args)
        ret = result["return_value"]
        status = ntstatus_name(ret)
        events = result.get("events", [])
        ev_summary = ", ".join(f"{e.event_type}" for e in events) if events else "none"
        W(f"\n  Test: {desc}")
        W(f"    Args: {[f'0x{a:X}' if a > 9 else str(a) for a in args]}")
        W(f"    Return: 0x{ret:08X} ({status})")
        W(f"    Instructions: {result['instructions']}")
        W(f"    Events ({len(events)}): {ev_summary}")
        for ev in events[:5]:
            W(f"      [{ev.event_type}] {ev.message}")

    # ── Summary ───────────────────────────────────────────────────────
    W("\n" + "=" * 80)
    W("[SUMMARY]")
    W("=" * 80)
    W(f"  System32 path:     {SYS32}")
    W(f"  Modules loaded:    {info['modules_loaded']}")
    W(f"  Test scenarios:    13")
    W(f"  Function tested:   NtPowerInformation ({mod_name}!0x{va:08X})")
    W(f"  Power classes:     {len(POWER_CLASSES)} tested")
    W(f"  Buffer variations: 10 sizes tested")
    W(f"  Error scenarios:   {len(error_tests)} tested")
    W(f"  Trace captured:    {len(trace)} instructions for class 0")
    W(f"  Cross-module:      {len(transitions)} module transitions detected")
    W("=" * 80)

    env.close()

    # Save to file
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n>>> Results saved to: {OUT}")


if __name__ == "__main__":
    run_test()
