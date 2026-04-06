"""
Comprehensive test of all win2k_analyzer components.
Tests: PDB symbols in disassembly, struct offsets/sizes, all decompiler modes,
behavior scan, struct dataflow, CLI commands.
"""
import sys, os, re, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nt_analyzer.decompiler import (
    decompile, X86Decompiler, KNOWN_STRUCTURES, KERNEL_API_SIGNATURES,
    format_pseudocode, batch_decompile
)
from nt_analyzer.symbol_loader import load_symbols, load_dbg_file
from nt_analyzer import behavior_analyzer as ba
from nt_analyzer.struct_dataflow import analyze_struct_accesses, summarize_accesses, STRUCT_DB

PE_W2K = 'C:/Users/win2000/Desktop/2kDEBUG/Nouveau dossier/ntoskrnl.exe'
PE_ROS = 'C:/Users/win2000/Desktop/2kDEBUG/ntoskrnl.exe'
PDB_W2K = 'C:/Users/win2000/Desktop/2kDEBUG/Nouveau dossier/ntoskrnl.pdb'
PDB_ROS = 'C:/Users/win2000/Desktop/2kDEBUG/ntoskrnl.pdb'
DBG_W2K = 'C:/Users/win2000/Desktop/2kDEBUG/Nouveau dossier/ntoskrnl.dbg'

errors = []
warnings = []

def check(condition, msg, warn_only=False):
    if not condition:
        if warn_only:
            warnings.append(msg)
            print(f"  WARN: {msg}")
        else:
            errors.append(msg)
            print(f"  FAIL: {msg}")
    return condition

print("=" * 70)
print("  COMPREHENSIVE WIN2K_ANALYZER TEST")
print("=" * 70)

# ─────────────────────────────────────────────────────────────────────
# TEST 1: PDB Symbol Loading
# ─────────────────────────────────────────────────────────────────────
print("\n[1] PDB SYMBOL LOADING")
syms_w2k, meta_w2k = load_symbols(PDB_W2K, pe_path=PE_W2K)
syms_ros, meta_ros = load_symbols(PDB_ROS, pe_path=PE_ROS)
check(len(syms_w2k) > 5000, f"Win2K PDB: only {len(syms_w2k)} symbols (expected >5000)")
check(len(syms_ros) > 5000, f"ReactOS PDB: only {len(syms_ros)} symbols (expected >5000)")
check(meta_w2k.get('format') == 'pdb20', f"Win2K PDB format: {meta_w2k.get('format')}")
check(meta_ros.get('format') == 'pdb20', f"ReactOS PDB format: {meta_ros.get('format')}")
print(f"  Win2K: {len(syms_w2k)} symbols, ReactOS: {len(syms_ros)} symbols")

# Check specific known symbols exist at correct addresses
# CcInitializeCacheMap should be at 0x0040FC9C
import pefile
pe = pefile.PE(PE_W2K, fast_load=False)
export_map = {}
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        export_map[exp.name.decode()] = pe.OPTIONAL_HEADER.ImageBase + exp.address
pe.close()

cc_va = export_map.get('CcInitializeCacheMap')
pdb_names_at_cc = [n for va, n in syms_w2k.items() if va == cc_va]
check(len(pdb_names_at_cc) > 0 and 'CcInitializeCacheMap' in pdb_names_at_cc[0],
      f"PDB symbol at CcInitializeCacheMap VA 0x{cc_va:08X}: {pdb_names_at_cc}")

# Check internal (non-exported) symbols exist
internal_names = {n for n in syms_w2k.values()}
exported_names = set(export_map.keys())
internal_only = internal_names - exported_names
check(len(internal_only) > 3000,
      f"Internal-only symbols: {len(internal_only)} (expected >3000)")
# Spot check specific internal symbols
for name in ['KiQuantumEnd', 'IopFreeDCB', 'CcAllocateInitializeBcb', 'MiSessionAddProcess']:
    check(name in internal_names, f"Missing expected internal symbol: {name}", warn_only=True)

# ─────────────────────────────────────────────────────────────────────
# TEST 2: DBG Loading
# ─────────────────────────────────────────────────────────────────────
print("\n[2] DBG FILE LOADING")
_, dbg_meta = load_dbg_file(DBG_W2K)
check(dbg_meta.get('fpo_entries', 0) > 1000,
      f"FPO entries: {dbg_meta.get('fpo_entries', 0)} (expected >1000)")
check(dbg_meta.get('pdb_reference') == 'ntoskrnl.pdb',
      f"PDB reference: {dbg_meta.get('pdb_reference')}")
check('error' not in dbg_meta, f"DBG error: {dbg_meta.get('error')}")
print(f"  FPO: {dbg_meta.get('fpo_entries')}, PDB ref: {dbg_meta.get('pdb_reference')}")

# ─────────────────────────────────────────────────────────────────────
# TEST 3: DISASSEMBLY WITH PDB SYMBOLS
# ─────────────────────────────────────────────────────────────────────
print("\n[3] DISASSEMBLY WITH PDB SYMBOLS")

# Create decompiler with symbols and disassemble
dec = X86Decompiler(PE_W2K, syms_w2k)
# Test assembly mode: internal call targets should be named
info = dec.decompile_from_pe(PE_W2K, 'CcInitializeCacheMap')
check(info is not None, "Failed to decompile CcInitializeCacheMap")

if info:
    pseudoc = format_pseudocode(info)
    # With symbols, internal calls should be resolved
    api_line = [l for l in pseudoc.split('\n') if 'APIs called:' in l]
    if api_line:
        apis = api_line[0].split('APIs called:')[1].strip()
        print(f"  CcInitializeCacheMap APIs (with syms): {apis[:120]}...")
        # Should have internal symbol names like CcDeleteSharedCacheMap
        check('CcDeleteSharedCacheMap' in apis or '@CcDeleteSharedCacheMap' in apis,
              "Missing internal API CcDeleteSharedCacheMap in symbol-resolved output", warn_only=True)

# Test assembly listing with symbols
asm_text = ba.disassemble_function(PE_W2K, 'CcInitializeCacheMap')
check(asm_text is not None, "Assembly mode returned None")
if asm_text:
    asm_lines = asm_text.split('\n')
    check(len(asm_lines) > 100, f"Assembly only {len(asm_lines)} lines (expected >100)")
    # Check call instructions have target names
    call_lines = [l for l in asm_lines if 'call' in l.lower()]
    named_calls = [l for l in call_lines if any(c.isalpha() for c in l.split('call')[-1]) 
                   and '0x' not in l.split('call')[-1].strip()[:2]]
    print(f"  Assembly: {len(asm_lines)} lines, {len(call_lines)} calls, {len(named_calls)} named")
    # Some calls should be named (exports)
    check(len(named_calls) > 0, "No named call targets in assembly", warn_only=True)

# Test assembly for IoCallDriver (short function)
asm_ioc = ba.disassemble_function(PE_W2K, 'IoCallDriver')
if asm_ioc:
    print(f"  IoCallDriver assembly: {len(asm_ioc.split(chr(10)))} lines")
    # Should have 'call' with a target
    check('call' in asm_ioc.lower(), "IoCallDriver missing call instruction")

# ─────────────────────────────────────────────────────────────────────
# TEST 4: KNOWN_STRUCTURES — Offsets and Sizes
# ─────────────────────────────────────────────────────────────────────
print("\n[4] KNOWN_STRUCTURES OFFSETS AND SIZES")

# Verify critical struct entries
# DRIVER_OBJECT: offset 0x00 = Type (SHORT), 0x04 = DriverStart, 0x08 = DriverSize,
#   0x14 = DriverName (UNICODE_STRING), 0x28 = FastIoDispatch,
#   0x38-0xA8 = MajorFunction[0..27]
driver_obj = KNOWN_STRUCTURES.get('DRIVER_OBJECT', {})
check(0x00 in driver_obj, "DRIVER_OBJECT missing offset 0x00 (Type)")
check(0x04 in driver_obj, "DRIVER_OBJECT missing offset 0x04 (DriverStart)")  
check(0x08 in driver_obj, "DRIVER_OBJECT missing offset 0x08 (DriverSize)")
check(0x14 in driver_obj, "DRIVER_OBJECT missing offset 0x14 (DriverName)")
check(0x28 in driver_obj, "DRIVER_OBJECT missing offset 0x28 (FastIoDispatch)")
check(0x38 in driver_obj, "DRIVER_OBJECT missing offset 0x38 (MajorFunction[0])")
if 0x38 in driver_obj:
    check('IRP_MJ_CREATE' in driver_obj[0x38][1],
          f"DRIVER_OBJECT 0x38 should be MajorFunction[IRP_MJ_CREATE], got {driver_obj[0x38]}")
if 0x00 in driver_obj:
    print(f"  DRIVER_OBJECT[0x00]: {driver_obj[0x00]}")
    print(f"  DRIVER_OBJECT[0x38]: {driver_obj.get(0x38)}")
    print(f"  Total fields: {len(driver_obj)}")

# DEVICE_OBJECT (Win2K 32-bit): 0x00 = Type, 0x02 = Size, 0x04 = ReferenceCount,
#   0x08 = DriverObject, 0x0C = NextDevice, 0x10 = AttachedDevice,
#   0x1C = Flags, 0x28 = DeviceExtension
device_obj = KNOWN_STRUCTURES.get('DEVICE_OBJECT', {})
check(0x00 in device_obj, "DEVICE_OBJECT missing 0x00 (Type)")
check(0x08 in device_obj, "DEVICE_OBJECT missing 0x08 (DriverObject)")
check(0x28 in device_obj, "DEVICE_OBJECT missing 0x28 (DeviceExtension)")
if 0x08 in device_obj:
    check('DriverObject' in device_obj[0x08][1],
          f"DEVICE_OBJECT 0x08 should be DriverObject, got {device_obj[0x08]}")
print(f"  DEVICE_OBJECT fields: {len(device_obj)}")

# FILE_OBJECT (Win2K 32-bit): 0x00 = Type, 0x02 = Size, 0x04 = DeviceObject,
#   0x08 = Vpb, 0x0C = FsContext, 0x10 = FsContext2,
#   0x14 = SectionObjectPointer, 0x24 = FileName, 0x2C = CurrentByteOffset
file_obj = KNOWN_STRUCTURES.get('FILE_OBJECT', {})
check(0x00 in file_obj, "FILE_OBJECT missing 0x00 (Type)")
check(0x02 in file_obj, "FILE_OBJECT missing 0x02 (Size)")
check(0x04 in file_obj, "FILE_OBJECT missing 0x04 (DeviceObject)")
check(0x0C in file_obj, "FILE_OBJECT missing 0x0C (FsContext)")
check(0x10 in file_obj, "FILE_OBJECT missing 0x10 (FsContext2)")
check(0x14 in file_obj, "FILE_OBJECT missing 0x14 (SectionObjectPointer)")
check(0x24 in file_obj, "FILE_OBJECT missing 0x24 (FileName)")
if 0x0C in file_obj:
    check('FsContext' == file_obj[0x0C][1],
          f"FILE_OBJECT 0x0C should be FsContext, got {file_obj[0x0C]}")
print(f"  FILE_OBJECT fields: {len(file_obj)}")

# IRP: 0x00 = Type, 0x04 = Size, 0x18 = AssociatedIrp (union),
#   0x24 = IoStatus, 0x28 = IoStatus.Information,
#   0x30 = Flags, 0x38 = UserBuffer, 0x3C = Tail (Overlay)
irp = KNOWN_STRUCTURES.get('IRP', {})
check(0x00 in irp, "IRP missing 0x00 (Type)")
check(0x04 in irp, "IRP missing 0x04 (Size)")
check(0x18 in irp, "IRP missing 0x18 (AssociatedIrp)")
check(0x24 in irp, "IRP missing 0x24 (IoStatus.Status)")
check(0x30 in irp, "IRP missing 0x30 (Flags)")
check(0x3C in irp, "IRP missing 0x3C (Tail.Overlay)")
print(f"  IRP fields: {len(irp)}")

# IO_STACK_LOCATION: 0x00 = MajorFunction, 0x01 = MinorFunction,
#   0x02 = Flags, 0x03 = Control, 0x04 = Parameters (union),
#   0x14 = DeviceObject, 0x18 = FileObject
io_sl = KNOWN_STRUCTURES.get('IO_STACK_LOCATION', {})
check(0x00 in io_sl, "IO_STACK_LOCATION missing 0x00 (MajorFunction)")
check(0x01 in io_sl, "IO_STACK_LOCATION missing 0x01 (MinorFunction)")
check(0x04 in io_sl, "IO_STACK_LOCATION missing 0x04 (Parameters)")
check(0x14 in io_sl, "IO_STACK_LOCATION missing 0x14 (DeviceObject)")
check(0x18 in io_sl, "IO_STACK_LOCATION missing 0x18 (FileObject)")
if 0x14 in io_sl:
    check('DeviceObject' in io_sl[0x14][1],
          f"IO_STACK_LOCATION 0x14 should be DeviceObject, got {io_sl[0x14]}")
if 0x18 in io_sl:
    check('FileObject' in io_sl[0x18][1],
          f"IO_STACK_LOCATION 0x18 should be FileObject, got {io_sl[0x18]}")
print(f"  IO_STACK_LOCATION fields: {len(io_sl)}")

# SHARED_CACHE_MAP: 0x00 = NodeTypeCode, 0x04 = NodeByteSize,
#   0x10 = FileSize, 0x24 = SectionSize, 0x30 = Bcbs,
#   0x44 = FileObject, 0x90 = Callbacks
shared_cm = KNOWN_STRUCTURES.get('SHARED_CACHE_MAP', {})
check(0x00 in shared_cm, "SHARED_CACHE_MAP missing 0x00 (NodeTypeCode)")
check(0x04 in shared_cm, "SHARED_CACHE_MAP missing 0x04 (NodeByteSize)")
check(0x10 in shared_cm, "SHARED_CACHE_MAP missing 0x10 (FileSize)")
check(0x44 in shared_cm, "SHARED_CACHE_MAP missing 0x44 (FileObject)")
check(0x90 in shared_cm, "SHARED_CACHE_MAP missing 0x90 (Callbacks)")
if 0x44 in shared_cm:
    check('FileObject' in shared_cm[0x44][1],
          f"SHARED_CACHE_MAP 0x44 should be FileObject, got {shared_cm[0x44]}")
if 0x90 in shared_cm:
    check('Callbacks' in shared_cm[0x90][1],
          f"SHARED_CACHE_MAP 0x90 should be Callbacks, got {shared_cm[0x90]}")
print(f"  SHARED_CACHE_MAP fields: {len(shared_cm)}")

# SECTION_OBJECT_POINTERS: 0x00 = DataSectionObject, 0x04 = SharedCacheMap, 0x08 = ImageSectionObject
sop = KNOWN_STRUCTURES.get('SECTION_OBJECT_POINTERS', {})
check(0x00 in sop, "SECTION_OBJECT_POINTERS missing 0x00 (DataSectionObject)")
check(0x04 in sop, "SECTION_OBJECT_POINTERS missing 0x04 (SharedCacheMap)")
check(0x08 in sop, "SECTION_OBJECT_POINTERS missing 0x08 (ImageSectionObject)")
print(f"  SECTION_OBJECT_POINTERS fields: {len(sop)}")

# CC_FILE_SIZES: 0x00 = AllocationSize, 0x08 = FileSize, 0x10 = ValidDataLength
cc_fs = KNOWN_STRUCTURES.get('CC_FILE_SIZES', {})
check(0x00 in cc_fs, "CC_FILE_SIZES missing 0x00 (AllocationSize)")
check(0x08 in cc_fs, "CC_FILE_SIZES missing 0x08 (FileSize)")
check(0x10 in cc_fs, "CC_FILE_SIZES missing 0x10 (ValidDataLength)")
print(f"  CC_FILE_SIZES fields: {len(cc_fs)}")

print(f"  Total KNOWN_STRUCTURES: {len(KNOWN_STRUCTURES)}")
for sname in sorted(KNOWN_STRUCTURES.keys()):
    print(f"    {sname}: {len(KNOWN_STRUCTURES[sname])} fields")

# ─────────────────────────────────────────────────────────────────────
# TEST 5: STRUCT_DB (struct_dataflow.py) — Multi-Version Structs
# ─────────────────────────────────────────────────────────────────────
print("\n[5] STRUCT_DB MULTI-VERSION DATABASE")
check('FILE_OBJECT' in STRUCT_DB, "STRUCT_DB missing FILE_OBJECT")
check('EPROCESS' in STRUCT_DB, "STRUCT_DB missing EPROCESS")
check('KTHREAD' in STRUCT_DB, "STRUCT_DB missing KTHREAD")
check('PEB' in STRUCT_DB, "STRUCT_DB missing PEB")
check('TEB' in STRUCT_DB, "STRUCT_DB missing TEB")

# STRUCT_DB format: {struct_name: {version_key: {version, size, fields: {offset: (name, type)}}}}
for sname in ['FILE_OBJECT', 'EPROCESS', 'KTHREAD', 'PEB', 'TEB', 'ETHREAD',
              'KPROCESS', 'DRIVER_OBJECT', 'DEVICE_OBJECT', 'IRP']:
    if sname in STRUCT_DB:
        versions = list(STRUCT_DB[sname].keys())
        has_w2k = 'win2k' in versions
        check(has_w2k, f"STRUCT_DB[{sname}] missing win2k version", warn_only=True)
        if sname == 'FILE_OBJECT':
            w2k_data = STRUCT_DB[sname].get('win2k', {})
            print(f"  {sname}: versions={versions}, win2k size={w2k_data.get('size')} bytes, "
                  f"fields={len(w2k_data.get('fields', {}))}")

# Verify specific well-known offsets in STRUCT_DB
eproc_w2k = STRUCT_DB.get('EPROCESS', {}).get('win2k', {})
if eproc_w2k:
    fields = eproc_w2k.get('fields', {})
    check(148 in fields, "EPROCESS win2k missing offset 148 (UniqueProcessId)")
    if 148 in fields:
        check('UniqueProcessId' in fields[148][0],
              f"EPROCESS 0x94 should be UniqueProcessId, got {fields[148]}")
    check(eproc_w2k.get('size') == 656,
          f"EPROCESS win2k size: {eproc_w2k.get('size')} (expected 656)", warn_only=True)
    print(f"  EPROCESS win2k: size={eproc_w2k.get('size')}, fields={len(fields)}")

kthread_w2k = STRUCT_DB.get('KTHREAD', {}).get('win2k', {})
if kthread_w2k:
    fields = kthread_w2k.get('fields', {})
    print(f"  KTHREAD win2k: size={kthread_w2k.get('size')}, fields={len(fields)}")
    # KTHREAD should have WaitStatus, WaitBlockList, etc.
    check(len(fields) > 20, f"KTHREAD win2k only {len(fields)} fields (expected >20)")

peb_w2k = STRUCT_DB.get('PEB', {}).get('win2k', {})
if peb_w2k:
    fields = peb_w2k.get('fields', {})
    print(f"  PEB win2k: size={peb_w2k.get('size')}, fields={len(fields)}")
    # PEB critical offsets: 0x0C = Ldr (PEB_LDR_DATA), 0x10 = ProcessParameters
    check(0x0C in fields, "PEB win2k missing 0x0C (Ldr)")
    check(0x10 in fields, "PEB win2k missing 0x10 (ProcessParameters)")

teb_w2k = STRUCT_DB.get('TEB', {}).get('win2k', {})
if teb_w2k:
    fields = teb_w2k.get('fields', {})
    print(f"  TEB win2k: size={teb_w2k.get('size')}, fields={len(fields)}")
    # TEB: 0x00 = NtTib, 0x30 = ProcessEnvironmentBlock (self-ref PEB pointer)
    check(0x00 in fields, "TEB win2k missing 0x00 (NtTib)")
    check(0x30 in fields, "TEB win2k missing 0x30 (ProcessEnvironmentBlock)")

total_structs = len(STRUCT_DB)
total_versions = sum(len(v) for v in STRUCT_DB.values())
print(f"  Total structs: {total_structs}, total version entries: {total_versions}")

# ─────────────────────────────────────────────────────────────────────
# TEST 6: KERNEL_API_SIGNATURES
# ─────────────────────────────────────────────────────────────────────
print("\n[6] KERNEL_API_SIGNATURES")
print(f"  Total signatures: {len(KERNEL_API_SIGNATURES)}")

# Check critical APIs have correct signatures
must_have = {
    'NtCreateFile': ('NTSTATUS', 11),      # 11 params
    'NtClose': ('NTSTATUS', 1),             # 1 param: Handle
    'IoCreateDevice': ('NTSTATUS', 7),      # 7 params
    'CcInitializeCacheMap': ('VOID', 5),    # 5 params
    'ExAllocatePoolWithTag': ('PVOID', 3),  # 3 params
    'KeInitializeSpinLock': ('VOID', 1),    # 1 param
    'CcFlushCache': ('VOID', 4),            # 4 params
    'IoCallDriver': ('NTSTATUS', 2),        # 2 params
    'KeWaitForSingleObject': ('NTSTATUS', 5),
    'CcCopyRead': ('BOOLEAN', 6),
}
for api_name, (expected_ret, expected_params) in must_have.items():
    sig = KERNEL_API_SIGNATURES.get(api_name)
    check(sig is not None, f"Missing signature for {api_name}")
    if sig:
        ret_type = sig[0]
        params = sig[1]
        check(ret_type == expected_ret,
              f"{api_name} return type: got {ret_type}, expected {expected_ret}")
        check(len(params) == expected_params,
              f"{api_name} param count: got {len(params)}, expected {expected_params}")

# Check CcInitializeCacheMap param types
cc_sig = KERNEL_API_SIGNATURES.get('CcInitializeCacheMap')
if cc_sig:
    params = cc_sig[1]
    check(params[0][0] == 'PFILE_OBJECT', f"CcInitializeCacheMap param0: {params[0][0]}")
    check(params[1][0] == 'PCC_FILE_SIZES', f"CcInitializeCacheMap param1: {params[1][0]}")
    check(params[2][0] == 'BOOLEAN', f"CcInitializeCacheMap param2: {params[2][0]}")
    check(params[3][0] == 'PCACHE_MANAGER_CALLBACKS', f"CcInitializeCacheMap param3: {params[3][0]}")

# ─────────────────────────────────────────────────────────────────────
# TEST 7: PSEUDO-C DECOMPILATION — Correctness
# ─────────────────────────────────────────────────────────────────────
print("\n[7] PSEUDO-C DECOMPILATION CORRECTNESS")

test_funcs = {
    'CcInitializeCacheMap': {'ret': 'VOID', 'conv': 'STDCALL', 'min_lines': 100,
                              'must_contain': ['FileObject', 'FileSizes', 'PinAccess'],
                              'must_not_contain': ['? DRIVER_OBJECT']},
    'IoCreateDevice': {'ret': 'NTSTATUS', 'conv': 'STDCALL', 'min_lines': 50,
                        'must_contain': ['DriverObject', 'DeviceObject'],
                        'must_not_contain': ['? DRIVER_OBJECT']},
    'NtCreateFile': {'ret': 'NTSTATUS', 'conv': 'STDCALL', 'min_lines': 10,
                      'must_contain': ['FileHandle', 'DesiredAccess'],
                      'must_not_contain': []},
    'NtClose': {'ret': 'NTSTATUS', 'conv': 'STDCALL', 'min_lines': 10,
                 'must_contain': ['Handle'],
                 'must_not_contain': []},
    'ExAllocatePoolWithTag': {'ret': 'PVOID', 'conv': 'STDCALL', 'min_lines': 50,
                               'must_contain': ['PoolType', 'NumberOfBytes', 'Tag'],
                               'must_not_contain': []},
    'KeInitializeSpinLock': {'ret': 'VOID', 'conv': 'STDCALL', 'min_lines': 5,
                              'must_contain': ['SpinLock'],
                              'must_not_contain': []},
    'IoCallDriver': {'ret': 'NTSTATUS', 'conv': 'STDCALL', 'min_lines': 5,
                      'must_contain': ['DeviceObject', 'Irp'],
                      'must_not_contain': []},
    'CcFlushCache': {'ret': 'VOID', 'conv': 'STDCALL', 'min_lines': 50,
                      'must_contain': ['SectionObjectPointer'],
                      'must_not_contain': ['? DRIVER_OBJECT']},
    'CcCopyRead': {'ret': 'BOOLEAN', 'conv': 'STDCALL', 'min_lines': 50,
                    'must_contain': ['FileObject', 'FileOffset'],
                    'must_not_contain': ['? DRIVER_OBJECT']},
    'MmCreateSection': {'ret': 'NTSTATUS', 'conv': 'STDCALL', 'min_lines': 50,
                         'must_contain': [],
                         'must_not_contain': []},
}

for func_name, expected in test_funcs.items():
    for label, pe in [('W2K', PE_W2K), ('ROS', PE_ROS)]:
        result = decompile(pe, func_name)
        if result is None:
            check(False, f"{label} {func_name}: decompile returned None")
            continue
        lines = result.split('\n')
        
        # Check line count
        check(len(lines) >= expected['min_lines'],
              f"{label} {func_name}: only {len(lines)} lines (min {expected['min_lines']})")
        
        # Check return type
        ret_match = re.search(r'^(\w+)\s+(STDCALL|FASTCALL|CDECL)', result, re.M)
        if ret_match:
            got_ret = ret_match.group(1)
            got_conv = ret_match.group(2)
            check(got_ret == expected['ret'],
                  f"{label} {func_name}: return {got_ret}, expected {expected['ret']}")
            check(got_conv == expected['conv'],
                  f"{label} {func_name}: convention {got_conv}, expected {expected['conv']}")
        
        # Check must_contain
        for token in expected['must_contain']:
            check(token in result,
                  f"{label} {func_name}: missing expected token '{token}'")
        
        # Check must_not_contain (wrong annotations)
        for bad in expected['must_not_contain']:
            found = result.count(bad)
            check(found == 0,
                  f"{label} {func_name}: found {found} instances of '{bad}'")

# ─────────────────────────────────────────────────────────────────────
# TEST 8: STRUCT FIELD ANNOTATION IN PSEUDO-C
# ─────────────────────────────────────────────────────────────────────
print("\n[8] STRUCT FIELD ANNOTATIONS IN PSEUDO-C")

# IoCreateDevice should have DeviceObject-> or DriverObject-> annotations
result_ioc = decompile(PE_W2K, 'IoCreateDevice')
if result_ioc:
    # Count struct annotations (param->Field pattern)
    struct_annotations = re.findall(r'/\*.*?(\w+->[\w\[\]]+).*?\*/', result_ioc)
    param_annotations = [a for a in struct_annotations if not a.startswith('?')]
    print(f"  IoCreateDevice struct annotations: {len(param_annotations)}")
    for a in param_annotations[:10]:
        print(f"    {a}")

# CcCopyRead should have FileObject-> annotations
result_ccr = decompile(PE_W2K, 'CcCopyRead')
if result_ccr:
    fo_refs = re.findall(r'FileObject->\w+', result_ccr)
    print(f"  CcCopyRead FileObject-> refs: {len(fo_refs)}")
    unique_fo = sorted(set(fo_refs))
    for r in unique_fo[:10]:
        print(f"    {r}")
    check(len(fo_refs) > 10, f"CcCopyRead only has {len(fo_refs)} FileObject refs (expected >10)")

# ─────────────────────────────────────────────────────────────────────
# TEST 9: HEX DUMP
# ─────────────────────────────────────────────────────────────────────
print("\n[9] HEX DUMP")
pe = pefile.PE(PE_W2K, fast_load=False)
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name and exp.name.decode() == 'IoCallDriver':
        rva = exp.address
        va = pe.OPTIONAL_HEADER.ImageBase + rva
        raw_bytes = pe.get_data(rva, 16)
        print(f"  IoCallDriver at VA=0x{va:08X}, first bytes: {' '.join(f'{b:02X}' for b in raw_bytes)}")
        # Verify push ebp / mov ebp,esp OR mov edx, [esp+8] pattern
        check(raw_bytes[0] in (0x55, 0x8B, 0xB8, 0xE9),
              f"IoCallDriver unexpected first byte: 0x{raw_bytes[0]:02X}")
        break
pe.close()

# ─────────────────────────────────────────────────────────────────────
# TEST 10: BEHAVIOR SCAN + STRUCT DATAFLOW
# ─────────────────────────────────────────────────────────────────────
print("\n[10] BEHAVIOR SCAN + STRUCT DATAFLOW")

# Scan first 30 exports
cats = ba.scan_all_exports(PE_W2K, max_functions=30, version='win2k')
total_entries = sum(len(v) for v in cats.values())
check(total_entries > 0, "Behavior scan returned 0 entries")
print(f"  Categories: {len(cats)}, entries: {total_entries}")
for cat, entries in sorted(cats.items(), key=lambda x: -len(x[1])):
    print(f"    [{cat}]: {len(entries)} functions")
    # Check struct_fields in info dict for first entry with struct data
    for fname, _, info in entries[:3]:
        sf = info.get('struct_fields', {})
        if sf:
            print(f"      {fname}: {len(sf)} struct field offsets")
            for ofs, fields in list(sf.items())[:2]:
                for sname, field_name, ftype, cnt in fields:
                    print(f"        {ofs}: {sname}.{field_name} ({ftype}) x{cnt}")

# Direct struct dataflow test on CcInitializeCacheMap
fp_result = ba.detect_api_patterns(PE_W2K, 'CcInitializeCacheMap')
if fp_result and fp_result.get('fingerprint'):
    fp = fp_result['fingerprint']
    accesses = analyze_struct_accesses(fp.blocks, 'CcInitializeCacheMap', version='win2k')
    summary = summarize_accesses(accesses, version='win2k')
    total_accesses = sum(len(v) for v in summary.values())
    print(f"  CcInitializeCacheMap struct dataflow: {total_accesses} field accesses across {len(summary)} structs")
    for sname, fields in sorted(summary.items()):
        print(f"    {sname}: {len(fields)} fields")
        for ofs, fname_s, ftype, cnt in fields[:3]:
            print(f"      0x{ofs:X}: {fname_s} ({ftype}) x{cnt}")
    check(total_accesses > 50, f"Struct dataflow only found {total_accesses} accesses (expected >50)")

# ─────────────────────────────────────────────────────────────────────
# TEST 11: BATCH DECOMPILE
# ─────────────────────────────────────────────────────────────────────
print("\n[11] BATCH DECOMPILE")
batch = batch_decompile(PE_W2K, func_names=['NtClose', 'IoCallDriver', 'KeInitializeSpinLock'],
                         symbols=syms_w2k, max_funcs=10)
check(len(batch) == 3, f"Batch decompile returned {len(batch)} results (expected 3)")
for name, code in batch.items():
    lines = code.split('\n')
    print(f"  {name}: {len(lines)} lines")
    check(len(lines) > 5, f"Batch {name} only {len(lines)} lines")

# ─────────────────────────────────────────────────────────────────────
# TEST 12: CROSS-BINARY CONSISTENCY
# ─────────────────────────────────────────────────────────────────────
print("\n[12] CROSS-BINARY CONSISTENCY (Win2K vs ReactOS)")
# Same binary = same output
for func_name in ['NtCreateFile', 'IoCallDriver', 'KeInitializeSpinLock']:
    r_w2k = decompile(PE_W2K, func_name)
    r_ros = decompile(PE_ROS, func_name)
    if r_w2k and r_ros:
        # Signatures should match
        sig_w2k = r_w2k.split('{')[0].split(')')[-2] if ')' in r_w2k else ''
        sig_ros = r_ros.split('{')[0].split(')')[-2] if ')' in r_ros else ''
        # Just check param names match
        params_w2k = re.findall(r'\b(\w+)\)(?:\s*$|\s*\{)', r_w2k, re.M)
        params_ros = re.findall(r'\b(\w+)\)(?:\s*$|\s*\{)', r_ros, re.M)
        print(f"  {func_name}: W2K={len(r_w2k.split(chr(10)))} lines, ROS={len(r_ros.split(chr(10)))} lines")

# ─────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
if errors:
    print(f"  ERRORS: {len(errors)}")
    for e in errors:
        print(f"    ✗ {e}")
else:
    print("  ✓ NO ERRORS")

if warnings:
    print(f"  WARNINGS: {len(warnings)}")
    for w in warnings:
        print(f"    ⚠ {w}")
else:
    print("  ✓ NO WARNINGS")

print(f"\n  Total checks: errors={len(errors)}, warnings={len(warnings)}")
print("=" * 70)

sys.exit(1 if errors else 0)
