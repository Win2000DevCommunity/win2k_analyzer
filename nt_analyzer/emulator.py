"""
Kernel Function Emulator
========================
x86-32 function emulation engine using Unicorn.  Loads a PE image into
emulated memory, resolves imports, hooks kernel API calls with mock
implementations and lets you run individual functions with controlled
inputs to verify behaviour *before* patching a live system.

Works with ANY Win2K system PE (ntoskrnl.exe, hal.dll, win32k.sys,
ntdll.dll, kernel32.dll, ...).  For ntoskrnl, uses SSDT resolution to
find private Nt* functions without any symbols.

Usage (programmatic):
    emu = KernelEmulator(r"C:\\2kDEBUG\\ntoskrnl.exe")
    emu.load()
    result = emu.run_function("NtPowerInformation",
                              args=[0, 0, 0, 0x1000, 4])
    print(result)
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_32,
    UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_INTR,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
)

from . import behavior_analyzer as _ba

# ---------------------------------------------------------------------------
#  Sizing defaults (actual addresses are computed per-PE in _compute_layout)
# ---------------------------------------------------------------------------

_STACK_SIZE = 0x0010_0000   # 1 MB
_HEAP_SIZE  = 0x0040_0000   # 4 MB
_STUB_SIZE  = 0x0001_0000   # 64 KB for IAT hook stubs
_RET_SLED   = b"\xCC" * 0x1000

_MAX_INSTRUCTIONS = 500_000


# ---------------------------------------------------------------------------
#  NTSTATUS helpers
# ---------------------------------------------------------------------------

STATUS_SUCCESS              = 0x00000000
STATUS_INVALID_PARAMETER    = 0xC000000D
STATUS_ACCESS_VIOLATION     = 0xC0000005
STATUS_NOT_IMPLEMENTED      = 0xC0000002
STATUS_BUFFER_TOO_SMALL     = 0xC0000023
STATUS_PRIVILEGE_NOT_HELD   = 0xC0000061
STATUS_NO_MEMORY            = 0xC0000017
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

_STATUS_NAMES = {
    STATUS_SUCCESS:              "STATUS_SUCCESS",
    STATUS_INVALID_PARAMETER:    "STATUS_INVALID_PARAMETER",
    STATUS_ACCESS_VIOLATION:     "STATUS_ACCESS_VIOLATION",
    STATUS_NOT_IMPLEMENTED:      "STATUS_NOT_IMPLEMENTED",
    STATUS_BUFFER_TOO_SMALL:     "STATUS_BUFFER_TOO_SMALL",
    STATUS_PRIVILEGE_NOT_HELD:   "STATUS_PRIVILEGE_NOT_HELD",
    STATUS_NO_MEMORY:            "STATUS_NO_MEMORY",
    STATUS_INFO_LENGTH_MISMATCH: "STATUS_INFO_LENGTH_MISMATCH",
}


def ntstatus_name(code: int) -> str:
    if code in _STATUS_NAMES:
        return _STATUS_NAMES[code]
    if code & 0x80000000:
        return f"STATUS_FAILURE(0x{code:08X})"
    return f"STATUS_OK(0x{code:08X})"


# ---------------------------------------------------------------------------
#  Data classes
# ---------------------------------------------------------------------------

@dataclass
class TraceEntry:
    address: int
    size: int
    mnemonic: str = ""
    op_str: str = ""
    is_call: bool = False
    call_target: str = ""


@dataclass
class EmulationResult:
    function_name: str
    return_value: int = 0
    return_status: str = ""
    trace: List[TraceEntry] = field(default_factory=list)
    api_calls: List[Tuple[str, List[int], int]] = field(default_factory=list)
    branches_taken: int = 0
    branches_not_taken: int = 0
    instructions_executed: int = 0
    coverage_pct: float = 0.0
    exception: Optional[str] = None
    elapsed_sec: float = 0.0
    heap_allocs: Dict[int, int] = field(default_factory=dict)


@dataclass
class TestScenario:
    name: str
    args: List[int] = field(default_factory=list)
    description: str = ""
    expected_status: Optional[int] = None
    user_mode: bool = False
    output_buffer_size: int = 0x1000


class EmulationException(Exception):
    """Raised when emulated code triggers a fatal kernel call."""


# ---------------------------------------------------------------------------
#  Kernel API Mocks
# ---------------------------------------------------------------------------

class KernelMocks:
    def __init__(self, emu: "KernelEmulator"):
        self._emu = emu
        self._heap_ptr = 0
        self.privilege_enabled = True
        self.current_irql = 0

    # -- memory probes --
    def ProbeForRead(self, args):
        if args[0] == 0 or args[1] == 0:
            return STATUS_ACCESS_VIOLATION
        return STATUS_SUCCESS

    def ProbeForWrite(self, args):
        if args[0] == 0 or args[1] == 0:
            return STATUS_ACCESS_VIOLATION
        return STATUS_SUCCESS

    # -- privilege / security --
    def SeSinglePrivilegeCheck(self, args):
        return 1 if self.privilege_enabled else 0

    def SePrivilegeCheck(self, args):
        return 1 if self.privilege_enabled else 0

    # -- object manager --
    def ObReferenceObjectByHandle(self, args):
        if len(args) >= 5 and args[4] != 0:
            self._emu._write_u32(args[4], self._alloc(0x100))
        return STATUS_SUCCESS

    def ObDereferenceObject(self, args):
        return STATUS_SUCCESS

    def ObfDereferenceObject(self, args):
        return STATUS_SUCCESS

    # -- memory allocation --
    def ExAllocatePool(self, args):
        size = args[1] if len(args) >= 2 else 0x100
        return self._alloc(max(size, 0x10))

    def ExAllocatePoolWithTag(self, args):
        size = args[1] if len(args) >= 2 else 0x100
        return self._alloc(max(size, 0x10))

    def ExFreePool(self, args):
        return STATUS_SUCCESS

    def ExFreePoolWithTag(self, args):
        return STATUS_SUCCESS

    # -- MDL --
    def IoAllocateMdl(self, args):
        return self._alloc(0x40)

    def IoFreeMdl(self, args):
        return STATUS_SUCCESS

    def MmProbeAndLockPages(self, args):
        return STATUS_SUCCESS

    def MmUnlockPages(self, args):
        return STATUS_SUCCESS

    def MmGetSystemAddressForMdlSafe(self, args):
        return self._alloc(0x100)

    def MmMapLockedPagesSpecifyCache(self, args):
        return self._alloc(0x100)

    # -- process / thread --
    def PsGetCurrentProcess(self, args):
        return 0xDEAD0001

    def PsGetCurrentProcessId(self, args):
        return 4

    def PsGetCurrentThread(self, args):
        return 0xDEAD0002

    def KeGetCurrentIrql(self, args):
        return self.current_irql

    def KfRaiseIrql(self, args):
        old = self.current_irql
        if args:
            self.current_irql = args[0]
        return old

    def KfLowerIrql(self, args):
        if args:
            self.current_irql = args[0]
        return STATUS_SUCCESS

    # -- synchronisation --
    def KeInitializeSpinLock(self, args):   return STATUS_SUCCESS
    def KeAcquireSpinLockRaiseToDpc(self, args): return self.current_irql
    def KeReleaseSpinLock(self, args):      return STATUS_SUCCESS
    def ExAcquireFastMutex(self, args):     return STATUS_SUCCESS
    def ExReleaseFastMutex(self, args):     return STATUS_SUCCESS
    def ExAcquireResourceExclusiveLite(self, args): return 1
    def ExReleaseResourceLite(self, args):  return STATUS_SUCCESS

    # -- misc --
    def RtlCopyMemory(self, args):
        dst, src, length = args[0], args[1], args[2]
        if dst and src and length and length < 0x10000:
            try:
                data = self._emu.uc.mem_read(src, length)
                self._emu.uc.mem_write(dst, bytes(data))
            except Exception:
                pass
        return STATUS_SUCCESS

    def memcpy(self, args):
        return self.RtlCopyMemory(args)

    def RtlZeroMemory(self, args):
        dst, length = args[0], args[1]
        if dst and length and length < 0x10000:
            try:
                self._emu.uc.mem_write(dst, b"\x00" * length)
            except Exception:
                pass
        return STATUS_SUCCESS

    def memset(self, args):
        dst, val, length = args[0], args[1] & 0xFF, args[2]
        if dst and length and length < 0x10000:
            try:
                self._emu.uc.mem_write(dst, bytes([val]) * length)
            except Exception:
                pass
        return dst

    def ExRaiseStatus(self, args):
        status = args[0] if args else STATUS_ACCESS_VIOLATION
        raise EmulationException(f"ExRaiseStatus(0x{status:08X})")

    def KeBugCheckEx(self, args):
        code = args[0] if args else 0
        raise EmulationException(f"KeBugCheckEx(0x{code:08X})")

    def DbgPrint(self, args):          return STATUS_SUCCESS
    def DbgBreakPoint(self, args):     return STATUS_SUCCESS
    def IoGetCurrentProcess(self, args): return 0xDEAD0001

    def KeGetPreviousMode(self, args):
        return 1 if self._emu._current_user_mode else 0

    def ExGetPreviousMode(self, args):
        return self.KeGetPreviousMode(args)

    # -- registry --
    def ZwOpenKey(self, args):
        if len(args) >= 1 and args[0]:
            self._emu._write_u32(args[0], 0xBADC0DE0)
        return STATUS_SUCCESS

    def ZwQueryValueKey(self, args):   return STATUS_SUCCESS
    def ZwClose(self, args):           return STATUS_SUCCESS

    # -- IRP / IO --
    def IoCompleteRequest(self, args):  return STATUS_SUCCESS
    def IoCallDriver(self, args):       return STATUS_SUCCESS
    def IofCompleteRequest(self, args): return STATUS_SUCCESS
    def IofCallDriver(self, args):      return STATUS_SUCCESS

    # -- power --
    def PoSetPowerState(self, args):      return STATUS_SUCCESS
    def PoStartNextPowerIrp(self, args):  return STATUS_SUCCESS
    def PoRequestPowerIrp(self, args):    return STATUS_SUCCESS

    # -- string --
    def RtlInitUnicodeString(self, args):    return STATUS_SUCCESS
    def RtlCompareUnicodeString(self, args): return 0
    def RtlEqualUnicodeString(self, args):   return 1
    def RtlCopyUnicodeString(self, args):    return STATUS_SUCCESS

    # -- HAL --
    def HalMakeBeep(self, args):       return 1
    def READ_PORT_UCHAR(self, args):   return 0
    def WRITE_PORT_UCHAR(self, args):  return STATUS_SUCCESS

    # -- fallback --
    def _default_mock(self, name, args):
        return STATUS_SUCCESS

    def _alloc(self, size):
        size = (size + 0xF) & ~0xF
        ptr = self._heap_ptr
        self._heap_ptr += size
        if self._heap_ptr >= self._emu._heap_base + _HEAP_SIZE:
            return 0
        self._emu._record_alloc(ptr, size)
        return ptr

    def dispatch(self, name, args):
        func = name.split("!")[-1] if "!" in name else name
        method = getattr(self, func, None)
        if callable(method) and not func.startswith("_"):
            return method(args)
        return self._default_mock(name, args)


# ---------------------------------------------------------------------------
#  Main emulator
# ---------------------------------------------------------------------------

class KernelEmulator:
    """
    Unicorn-based x86-32 PE emulator for any Win2K system file.

    Lifecycle:
      1. __init__(pe_path)
      2. load()  - parse PE, map memory, hook IAT
      3. run_function(name, args, ...) -> EmulationResult
    """

    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self.uc: Optional[Uc] = None
        self.pe: Optional[pefile.PE] = None
        self.image_base: int = 0
        self.image_size: int = 0

        # Dynamic memory layout (set by _compute_layout)
        self._stack_base: int = 0
        self._stack_top: int = 0
        self._heap_base: int = 0
        self._ret_addr: int = 0
        self._stub_base: int = 0

        self._import_hooks: Dict[int, str] = {}
        self._export_map: Dict[int, str] = {}
        self._iat_va_to_name: Dict[int, str] = {}

        self.mocks: Optional[KernelMocks] = None

        self._trace: List[TraceEntry] = []
        self._api_calls: List[Tuple[str, List[int], int]] = []
        self._branches_taken = 0
        self._branches_not_taken = 0
        self._insn_count = 0
        self._stopped = False
        self._stop_reason = ""
        self._current_user_mode = False
        self._alloc_map: Dict[int, int] = {}
        self._coverage_set: set = set()

        self._cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self._cs.detail = True

        self._next_stub: int = 0

    # -------------------------------------------------------------- layout

    def _compute_layout(self):
        """
        Dynamically place stack / heap / stubs so they NEVER overlap the
        PE image, regardless of where the image loads.

        Win2K examples:
          ntoskrnl.exe  0x00400000 - 0x005ACB40
          ntdll.dll     0x77F40000 - 0x77FCC000
          kernel32.dll  0x77E40000 - 0x77F32000
          hal.dll       0x80062000 - ...
        """
        image_end = self.image_base + self.image_size
        # Put everything after the PE image, aligned to 64 KB + 64 KB gap
        base = ((image_end + 0xFFFF) & ~0xFFFF) + 0x10000

        total_needed = _STACK_SIZE + _HEAP_SIZE + _STUB_SIZE + 0x2000

        # If that would overflow 32-bit space, try below the image
        if base + total_needed > 0xFFF00000:
            base = 0x0100_0000
            if base + total_needed >= self.image_base:
                base = 0x0001_0000

        self._stack_base = base
        self._stack_top  = base + _STACK_SIZE
        base += _STACK_SIZE

        self._heap_base = base
        base += _HEAP_SIZE

        self._ret_addr = base
        base += 0x1000

        self._stub_base = base
        self._next_stub = base

    # ----------------------------------------------------------------- load

    def load(self, progress_cb=None):
        if progress_cb:
            progress_cb("Parsing PE...", 5)

        self.pe = pefile.PE(self.pe_path, fast_load=False)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.image_size = self.pe.OPTIONAL_HEADER.SizeOfImage

        self._compute_layout()

        aligned_img = (self.image_size + 0xFFF) & ~0xFFF

        if progress_cb:
            progress_cb("Initializing emulator...", 10)

        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # Map PE image
        self.uc.mem_map(self.image_base, aligned_img)
        hdr_size = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        self.uc.mem_write(self.image_base, self.pe.__data__[:hdr_size])

        for sec in self.pe.sections:
            raw = sec.get_data()
            va = self.image_base + sec.VirtualAddress
            self.uc.mem_write(va, raw)

        if progress_cb:
            progress_cb("Mapping stack & heap...", 20)

        self.uc.mem_map(self._stack_base, _STACK_SIZE)
        self.uc.mem_map(self._heap_base, _HEAP_SIZE)
        self.uc.mem_map(self._ret_addr, 0x1000)
        self.uc.mem_write(self._ret_addr, _RET_SLED)
        self.uc.mem_map(self._stub_base, _STUB_SIZE)

        if progress_cb:
            progress_cb("Resolving imports...", 30)

        self._setup_iat_hooks()

        if progress_cb:
            progress_cb("Building export map...", 50)

        self._build_export_map()

        self.mocks = KernelMocks(self)
        self.mocks._heap_ptr = self._heap_base

        if progress_cb:
            progress_cb("Ready.", 100)

    # ----------------------------------------------------------------- IAT

    def _setup_iat_hooks(self):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('ascii', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('ascii', errors='replace')
                else:
                    func_name = f"ordinal_{imp.ordinal}"
                full_name = f"{dll_name}!{func_name}"

                stub_va = self._next_stub
                self._next_stub += 16
                self.uc.mem_write(stub_va, b"\xC3" + b"\xCC" * 15)

                self._import_hooks[stub_va] = full_name
                self._iat_va_to_name[imp.address] = full_name

                iat_offset = imp.address - self.image_base
                if 0 <= iat_offset < self.image_size:
                    self.uc.mem_write(imp.address, struct.pack('<I', stub_va))

    def _build_export_map(self):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.address:
                self._export_map[exp.address] = exp.name.decode('ascii', errors='replace')

    # ----------------------------------------------------------------- run

    def run_function(
        self,
        func_name: str,
        args: Optional[List[int]] = None,
        symbols: Optional[Dict[int, str]] = None,
        max_instructions: int = _MAX_INSTRUCTIONS,
        user_mode: bool = False,
        privilege_enabled: bool = True,
    ) -> EmulationResult:
        if self.uc is None:
            raise RuntimeError("Call load() first")

        func_va = self._resolve_function_va(func_name, symbols)
        if func_va is None:
            res = EmulationResult(function_name=func_name)
            res.exception = f"Function '{func_name}' not found"
            return res

        # Reset per-run state
        self._trace.clear()
        self._api_calls.clear()
        self._branches_taken = 0
        self._branches_not_taken = 0
        self._insn_count = 0
        self._stopped = False
        self._stop_reason = ""
        self._current_user_mode = user_mode
        self._alloc_map.clear()
        self._coverage_set.clear()

        self.mocks.privilege_enabled = privilege_enabled
        self.mocks._heap_ptr = self._heap_base

        # Setup stdcall stack: return addr, then args right-to-left
        esp = self._stack_top - 0x100
        if args is None:
            args = []

        for arg in reversed(args):
            esp -= 4
            self.uc.mem_write(esp, struct.pack('<I', arg & 0xFFFFFFFF))
        esp -= 4
        self.uc.mem_write(esp, struct.pack('<I', self._ret_addr))

        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp + 4)
        self.uc.reg_write(UC_X86_REG_EAX, 0)
        self.uc.reg_write(UC_X86_REG_EBX, 0)
        self.uc.reg_write(UC_X86_REG_ECX, 0)
        self.uc.reg_write(UC_X86_REG_EDX, 0)
        self.uc.reg_write(UC_X86_REG_ESI, 0)
        self.uc.reg_write(UC_X86_REG_EDI, 0)

        h_code  = self.uc.hook_add(UC_HOOK_CODE, self._hook_code, max_instructions)
        h_memr  = self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_unmapped)
        h_memw  = self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_unmapped)
        h_memf  = self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_unmapped)
        h_intr  = self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)

        t0 = time.perf_counter()
        exception_msg = None

        try:
            self.uc.emu_start(func_va, self._ret_addr, timeout=30_000_000)
        except EmulationException as e:
            exception_msg = str(e)
        except Exception as e:
            exception_msg = f"Unicorn error: {e}"

        elapsed = time.perf_counter() - t0
        eax = self.uc.reg_read(UC_X86_REG_EAX)

        for h in (h_code, h_memr, h_memw, h_memf, h_intr):
            self.uc.hook_del(h)

        return EmulationResult(
            function_name=func_name,
            return_value=eax,
            return_status=ntstatus_name(eax),
            trace=list(self._trace),
            api_calls=list(self._api_calls),
            branches_taken=self._branches_taken,
            branches_not_taken=self._branches_not_taken,
            instructions_executed=self._insn_count,
            exception=exception_msg or self._stop_reason or None,
            elapsed_sec=elapsed,
            heap_allocs=dict(self._alloc_map),
        )

    # ----------------------------------------------------------- hook impls

    def _hook_code(self, uc, address, size, max_insns):
        self._insn_count += 1
        if self._insn_count > max_insns:
            self._stopped = True
            self._stop_reason = f"Instruction limit ({max_insns})"
            uc.emu_stop()
            return

        self._coverage_set.add(address)

        if address in self._import_hooks:
            self._handle_api_hook(uc, self._import_hooks[address])
            return

        try:
            code = bytes(uc.mem_read(address, min(size, 15)))
            insns = list(self._cs.disasm(code, address, count=1))
        except Exception:
            return

        if not insns:
            return

        insn = insns[0]
        mn = insn.mnemonic
        if mn.startswith('j') and mn != 'jmp':
            self._branches_taken += 1

        if len(self._trace) < 50000:
            self._trace.append(TraceEntry(
                address=address, size=size,
                mnemonic=mn, op_str=insn.op_str,
            ))

    def _handle_api_hook(self, uc, api_name):
        esp = uc.reg_read(UC_X86_REG_ESP)
        args = []
        for i in range(8):
            try:
                val = struct.unpack('<I', bytes(uc.mem_read(esp + 4 + i * 4, 4)))[0]
                args.append(val)
            except Exception:
                args.append(0)

        try:
            ret_val = self.mocks.dispatch(api_name, args)
        except EmulationException:
            raise
        except Exception:
            ret_val = STATUS_SUCCESS

        uc.reg_write(UC_X86_REG_EAX, ret_val & 0xFFFFFFFF)
        self._api_calls.append((api_name, args[:4], ret_val))

        if len(self._trace) < 50000:
            self._trace.append(TraceEntry(
                address=uc.reg_read(UC_X86_REG_EIP), size=0,
                mnemonic="call", op_str=api_name,
                is_call=True, call_target=api_name,
            ))

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000)
            uc.mem_write(page, b'\x00' * 0x1000)
            return True
        except Exception:
            self._stopped = True
            self._stop_reason = f"Unmapped memory at 0x{address:08X}"
            uc.emu_stop()
            return False

    def _hook_interrupt(self, uc, intno, user_data):
        if intno == 3:
            uc.emu_stop()
        elif intno == 0x2E:
            pass
        else:
            self._stop_reason = f"Interrupt {intno} at 0x{uc.reg_read(UC_X86_REG_EIP):08X}"
            uc.emu_stop()

    # ----------------------------------------------------------- resolution

    def _resolve_function_va(self, func_name, symbols=None):
        ib = self.image_base

        # 1) export table
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.name.decode('ascii', errors='replace') == func_name:
                    return exp.address + ib

        # 2) SSDT for Nt* kernel functions
        if func_name.startswith('Nt') and not func_name.startswith('Ntdll'):
            ssdt = _ba.resolve_nt_via_ssdt(self.pe_path, func_name)
            if ssdt:
                return ssdt[1]  # va

        # 3) Nt<->Zw alias
        alt = None
        if func_name.startswith('Nt') and not func_name.startswith('Ntdll'):
            alt = 'Zw' + func_name[2:]
        elif func_name.startswith('Zw'):
            alt = 'Nt' + func_name[2:]
        if alt and hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.name.decode('ascii', errors='replace') == alt:
                    return exp.address + ib

        # 4) loaded symbols
        if symbols:
            for va, name in symbols.items():
                if name == func_name:
                    return va

        return None

    # ----------------------------------------------------------- helpers

    def _write_u32(self, address, value):
        try:
            self.uc.mem_write(address, struct.pack('<I', value & 0xFFFFFFFF))
        except Exception:
            pass

    def _read_u32(self, address):
        try:
            return struct.unpack('<I', bytes(self.uc.mem_read(address, 4)))[0]
        except Exception:
            return 0

    def _record_alloc(self, ptr, size):
        self._alloc_map[ptr] = size

    def get_layout_info(self):
        """Return memory layout for display/debug."""
        return {
            "image_base": self.image_base,
            "image_end":  self.image_base + self.image_size,
            "stack":      (self._stack_base, self._stack_top),
            "heap":       (self._heap_base, self._heap_base + _HEAP_SIZE),
            "ret_sled":   self._ret_addr,
            "stubs":      (self._stub_base, self._stub_base + _STUB_SIZE),
            "imports_hooked": len(self._import_hooks),
            "exports":    len(self._export_map),
        }

    def close(self):
        if self.pe:
            self.pe.close()
            self.pe = None
        self.uc = None


# ---------------------------------------------------------------------------
#  Scenario auto-generator
# ---------------------------------------------------------------------------

def generate_scenarios(func_name: str, arg_count: int = 5,
                       heap_base: int = 0x10000000) -> List[TestScenario]:
    out_buf = heap_base + 0x20_0000
    in_buf  = heap_base + 0x21_0000

    scenarios = []

    scenarios.append(TestScenario(
        name="Null arguments",
        args=[0] * arg_count,
        description="All arguments zero / NULL - should fail gracefully",
        expected_status=STATUS_INVALID_PARAMETER,
        user_mode=True,
    ))

    scenarios.append(TestScenario(
        name="Class 0 - Kernel mode",
        args=[0, 0, 0, out_buf, 0x1000][:arg_count],
        description="InformationClass=0, valid output buffer, kernel mode",
        expected_status=STATUS_SUCCESS,
        user_mode=False,
    ))

    scenarios.append(TestScenario(
        name="Class 0 - User mode",
        args=[0, 0, 0, out_buf, 0x1000][:arg_count],
        description="InformationClass=0, valid output buffer, user mode",
        user_mode=True,
    ))

    scenarios.append(TestScenario(
        name="Small buffer",
        args=[0, 0, 0, out_buf, 4][:arg_count],
        description="Output buffer too small",
        expected_status=STATUS_BUFFER_TOO_SMALL,
        user_mode=False,
    ))

    scenarios.append(TestScenario(
        name="Invalid class 0xFFFF",
        args=[0xFFFF, 0, 0, out_buf, 0x1000][:arg_count],
        description="Very large information class - should return INVALID_PARAMETER",
        expected_status=STATUS_INVALID_PARAMETER,
        user_mode=False,
    ))

    scenarios.append(TestScenario(
        name="User mode - no privilege",
        args=[0, 0, 0, out_buf, 0x1000][:arg_count],
        description="User mode call with privilege check disabled",
        user_mode=True,
    ))

    scenarios.append(TestScenario(
        name="Valid input buffer",
        args=[0, in_buf, 0x100, out_buf, 0x1000][:arg_count],
        description="Both InputBuffer and OutputBuffer valid",
        expected_status=STATUS_SUCCESS,
        user_mode=False,
    ))

    for cls_val in range(1, 6):
        scenarios.append(TestScenario(
            name=f"Class {cls_val}",
            args=[cls_val, 0, 0, out_buf, 0x1000][:arg_count],
            description=f"InformationClass={cls_val}, kernel mode",
            user_mode=False,
        ))

    return scenarios


# ---------------------------------------------------------------------------
#  High-level runner
# ---------------------------------------------------------------------------

def run_test_suite(
    pe_path: str,
    func_name: str,
    scenarios: Optional[List[TestScenario]] = None,
    symbols: Optional[Dict[int, str]] = None,
    progress_cb=None,
) -> List[Tuple[TestScenario, EmulationResult]]:
    emu = KernelEmulator(pe_path)
    emu.load(progress_cb=progress_cb)

    if scenarios is None:
        scenarios = generate_scenarios(func_name, heap_base=emu._heap_base)

    results = []
    total = len(scenarios)

    for idx, sc in enumerate(scenarios):
        if progress_cb:
            pct = 60 + int(35 * idx / max(total, 1))
            progress_cb(f"Scenario {idx + 1}/{total}: {sc.name}...", pct)

        emu.close()
        emu = KernelEmulator(pe_path)
        emu.load()
        emu.mocks.privilege_enabled = True

        if "no privilege" in sc.name.lower():
            emu.mocks.privilege_enabled = False

        res = emu.run_function(
            func_name,
            args=sc.args,
            symbols=symbols,
            user_mode=sc.user_mode,
            privilege_enabled=emu.mocks.privilege_enabled,
        )
        results.append((sc, res))

    emu.close()

    if progress_cb:
        progress_cb("Done.", 100)

    return results


# ---------------------------------------------------------------------------
#  Text report
# ---------------------------------------------------------------------------

def format_report(func_name, suite_results):
    lines = [
        "=" * 72,
        "  KERNEL FUNCTION EMULATION REPORT",
        f"  Function: {func_name}",
        f"  Scenarios tested: {len(suite_results)}",
        "=" * 72,
        "",
    ]

    passed = failed = 0

    for i, (sc, res) in enumerate(suite_results, 1):
        status_ok = True
        if res.exception:
            status_ok = False
        elif sc.expected_status is not None and res.return_value != sc.expected_status:
            status_ok = False

        icon = "\u2705" if status_ok else "\u274C"
        if status_ok:
            passed += 1
        else:
            failed += 1

        lines.append(f"{'─' * 72}")
        lines.append(f" {icon}  Scenario {i}: {sc.name}")
        lines.append(f"    {sc.description}")
        lines.append(f"    Mode: {'User' if sc.user_mode else 'Kernel'}")
        lines.append(f"    Args: [{', '.join(f'0x{a:X}' for a in sc.args)}]")
        lines.append(f"    Return: 0x{res.return_value:08X} ({res.return_status})")

        if sc.expected_status is not None:
            exp = ntstatus_name(sc.expected_status)
            lines.append(f"    Expected: 0x{sc.expected_status:08X} ({exp})")
            lines.append(f"    Match: {'YES' if res.return_value == sc.expected_status else 'NO'}")

        lines.append(f"    Instructions: {res.instructions_executed}")
        lines.append(f"    Time: {res.elapsed_sec:.3f}s")

        if res.exception:
            lines.append(f"    Exception: {res.exception}")

        if res.api_calls:
            lines.append(f"    API calls ({len(res.api_calls)}):")
            seen = {}
            for api_name, _a, _r in res.api_calls:
                fn = api_name.split("!")[-1]
                seen[fn] = seen.get(fn, 0) + 1
            for fn, cnt in list(seen.items())[:15]:
                lines.append(f"      {fn} (x{cnt})")
            if len(seen) > 15:
                lines.append(f"      ... and {len(seen) - 15} more")

        lines.append("")

    lines.append("=" * 72)
    lines.append(f"  SUMMARY: {passed} passed, {failed} failed"
                 f" out of {len(suite_results)} scenarios")
    lines.append("=" * 72)

    return '\n'.join(lines)
