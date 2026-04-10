"""
Live Kernel Environment Debugger
================================
A full kernel-state emulator that loads multiple system PEs into a shared
address space, builds realistic NT kernel structures (KPCR, EPROCESS,
ETHREAD, DRIVER_OBJECT, etc.), resolves cross-module imports, and provides
an interactive debugging experience with breakpoints, stepping, error
detection, and missing-module resolution.

Think of it as a portable WinDbg that runs entirely in Python — no live
kernel, no VM, no debug cables.  Point it at a Win2K System32 folder and
it builds a complete kernel environment in RAM.

Usage:
    env = KernelEnvironment(r"C:\\2kDEBUG")
    env.load_core()                      # ntoskrnl + hal
    env.auto_load_dependencies()         # pull in what's needed

    dbg = DebugSession(env)
    dbg.set_breakpoint("NtPowerInformation")
    dbg.set_breakpoint(0x004DC97E)       # raw VA
    dbg.on_missing_module = my_callback  # called when DLL needed

    result = dbg.run("NtPowerInformation", args=[0, 0, 0, buf, 0x1000])

    # step-by-step
    dbg.run("NtClose", args=[0x10], stop_at_entry=True)
    while dbg.state == DebugState.PAUSED:
        print(dbg.inspect_registers())
        print(dbg.get_call_stack())
        dbg.step()

    # inspect kernel objects
    insp = ObjectInspector(env)
    insp.dump_driver_object(va)
    insp.dump_eprocess(va)
    insp.check_null_pointers(va, "DRIVER_OBJECT")
"""

from __future__ import annotations

import enum
import glob
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Callable, Dict, List, Optional, Set, Tuple,
)

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
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_FS,
    UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
)

from . import behavior_analyzer as _ba

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

_PAGE = 0x1000
_ALIGN64K = 0x10000

# Win2K kernel virtual addresses (well-known)
KPCR_BASE          = 0xFFDFF000   # FS segment base, Kernel Processor Control Region
KUSER_SHARED_DATA  = 0x7FFE0000   # SharedUserData
KPCR_SIZE          = 0x3000       # KPCR + embedded KPRCB

# Emulator memory regions (placed outside any realistic PE range)
_ENV_STACK_SIZE    = 0x0020_0000  # 2 MB stack
_ENV_HEAP_SIZE     = 0x0100_0000  # 16 MB heap
_ENV_STUB_SIZE     = 0x0010_0000  # 1 MB for import stubs
_ENV_OBJ_POOL_SIZE = 0x0040_0000  # 4 MB for kernel object pool

_MAX_INSTRUCTIONS  = 5_000_000
_SPIN_THRESHOLD    = 500

# NTSTATUS codes
STATUS_SUCCESS              = 0x00000000
STATUS_INVALID_PARAMETER    = 0xC000000D
STATUS_ACCESS_VIOLATION     = 0xC0000005
STATUS_NOT_IMPLEMENTED      = 0xC0000002
STATUS_BUFFER_TOO_SMALL     = 0xC0000023
STATUS_INVALID_HANDLE       = 0xC0000008
STATUS_NO_MEMORY            = 0xC0000017
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_TYPE_MISMATCH = 0xC0000024

_STATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000024: "STATUS_OBJECT_TYPE_MISMATCH",
    0xC0000061: "STATUS_PRIVILEGE_NOT_HELD",
    0x40000024: "STATUS_NO_YIELD_PERFORMED",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0x0000009F: "STATUS_POWER_STATE_INVALID",
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

class DebugState(enum.Enum):
    IDLE     = "idle"
    RUNNING  = "running"
    PAUSED   = "paused"       # at breakpoint or step
    STOPPED  = "stopped"      # finished or error
    WAITING  = "waiting"      # waiting for user (missing module)


@dataclass
class LoadedModule:
    """A PE file loaded into the emulated address space."""
    name: str                           # e.g. "ntoskrnl.exe"
    path: str                           # filesystem path
    image_base: int = 0
    image_size: int = 0
    pe: Optional[pefile.PE] = None
    exports: Dict[str, int] = field(default_factory=dict)    # name -> VA
    ordinal_exports: Dict[int, int] = field(default_factory=dict)  # ordinal -> VA
    imports_needed: Dict[str, List[str]] = field(default_factory=dict)  # dll -> [funcs]
    unresolved: List[Tuple[str, str]] = field(default_factory=list)  # (dll, func) still missing
    symbols: Dict[int, str] = field(default_factory=dict)          # VA -> name
    ssdt_map: Dict[int, int] = field(default_factory=dict)         # idx -> VA


@dataclass
class Breakpoint:
    id: int
    address: int
    name: str = ""
    condition: Optional[str] = None     # python expression evaluated at hit
    hit_count: int = 0
    enabled: bool = True
    temporary: bool = False             # one-shot breakpoint (step-over)
    callback: Optional[Callable] = None


@dataclass
class DebugEvent:
    """An event raised during debugging."""
    event_type: str     # "breakpoint", "error", "missing_module", "exception",
                        # "null_deref", "invalid_call", "spin_loop", "step"
    address: int = 0
    message: str = ""
    module: str = ""
    function: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class StackFrame:
    return_address: int
    frame_pointer: int
    module: str = ""
    function: str = ""
    offset: int = 0


# ---------------------------------------------------------------------------
#  Win2K Kernel Structure Builder
# ---------------------------------------------------------------------------

class KernelStateBuilder:
    """
    Builds realistic Win2K kernel structures in emulated memory.

    Creates:
     - KPCR + embedded KPRCB at 0xFFDFF000 (FS segment base)
     - KUSER_SHARED_DATA at 0x7FFE0000
     - System EPROCESS + ETHREAD
     - Object table with handle entries
     - KeServiceDescriptorTable
    """

    def __init__(self, uc: Uc, obj_pool_base: int):
        self.uc = uc
        self._pool_base = obj_pool_base
        self._pool_ptr = obj_pool_base

        # Kernel objects we create
        self.kpcr_va = KPCR_BASE
        self.kprcb_va = KPCR_BASE + 0x120     # embedded in KPCR
        self.system_eprocess = 0
        self.system_ethread = 0
        self.idle_thread = 0
        self.handle_table_va = 0
        self.service_descriptor_table = 0

    def _alloc(self, size: int) -> int:
        """Allocate from the kernel object pool."""
        size = (size + 0xF) & ~0xF
        ptr = self._pool_ptr
        self._pool_ptr += size
        return ptr

    def _write_u8(self, addr, val):
        self.uc.mem_write(addr, struct.pack('<B', val & 0xFF))

    def _write_u16(self, addr, val):
        self.uc.mem_write(addr, struct.pack('<H', val & 0xFFFF))

    def _write_u32(self, addr, val):
        self.uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))

    def _write_u64(self, addr, val):
        self.uc.mem_write(addr, struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))

    def _write_unicode(self, addr, text: str, max_len: int = 256) -> int:
        """Write UNICODE_STRING struct. Returns VA of the buffer."""
        encoded = text.encode('utf-16-le')[:max_len]
        buf = self._alloc(len(encoded) + 2)
        self.uc.mem_write(buf, encoded + b'\x00\x00')
        # UNICODE_STRING: Length, MaximumLength, Buffer
        self._write_u16(addr, len(encoded))
        self._write_u16(addr + 2, len(encoded) + 2)
        self._write_u32(addr + 4, buf)
        return buf

    def build_all(self):
        """Build the complete kernel state."""
        self._build_kuser_shared_data()
        self._build_system_process()
        self._build_idle_thread()
        self._build_system_thread()
        self._build_kpcr()
        self._build_handle_table()

    def _build_kuser_shared_data(self):
        """KUSER_SHARED_DATA at 0x7FFE0000 — Win2K layout."""
        base = KUSER_SHARED_DATA
        # TickCountLow
        self._write_u32(base + 0x000, 0x00100000)
        # TickCountMultiplier
        self._write_u32(base + 0x004, 0x0FA00000)
        # InterruptTime (KSYSTEM_TIME)
        self._write_u32(base + 0x008, 0x00100000)  # LowPart
        self._write_u32(base + 0x00C, 0)            # High1Time
        self._write_u32(base + 0x010, 0)            # High2Time
        # SystemTime (KSYSTEM_TIME)
        self._write_u32(base + 0x014, 0xD0000000)  # LowPart — fake time
        self._write_u32(base + 0x018, 0x01C00000)  # High1Time
        self._write_u32(base + 0x01C, 0x01C00000)  # High2Time
        # TimeZoneBias
        self._write_u64(base + 0x020, 0)
        # ImageNumberLow / ImageNumberHigh
        self._write_u16(base + 0x02A, 0x14C)       # IMAGE_FILE_MACHINE_I386
        self._write_u16(base + 0x02C, 0x14C)
        # NtSystemRoot — "C:\WINNT"
        root = "C:\\WINNT".encode('utf-16-le')
        self.uc.mem_write(base + 0x030, root + b'\x00\x00')
        # MaxStackTraceDepth
        self._write_u32(base + 0x0F0, 0x20)
        # NtProductType (1 = WinNt, 2 = LanManNt, 3 = Server)
        self._write_u32(base + 0x264, 1)
        # ProductTypeIsValid
        self._write_u8(base + 0x268, 1)
        # NtMajorVersion = 5, NtMinorVersion = 0 (Win2K)
        self._write_u32(base + 0x26C, 5)
        self._write_u32(base + 0x270, 0)
        # ProcessorFeatures[64]
        self._write_u8(base + 0x274, 1)   # PF_FLOATING_POINT_PRECISION_ERRATA
        # SuiteMask
        self._write_u16(base + 0x2D0, 0)
        # NumberOfPhysicalPages
        self._write_u32(base + 0x2E8, 0x00020000)  # 128K pages = 512MB RAM

    def _build_system_process(self):
        """Create a minimal EPROCESS for the System process (PID 4)."""
        ep = self._alloc(0x200)
        self.system_eprocess = ep

        # KPROCESS header (offset 0x000)
        self._write_u16(ep + 0x000, 3)              # Header.Type = ProcessObject
        self._write_u16(ep + 0x002, 0x1B0)           # Header.Size
        self._write_u32(ep + 0x004, ep + 0x004)      # ProfileListHead (self-link)
        self._write_u32(ep + 0x008, ep + 0x004)
        self._write_u32(ep + 0x018, 0x00185000)      # DirectoryTableBase[0] (fake PD)
        # BasePriority
        self._write_u8(ep + 0x060, 8)
        # State = ProcessInMemory
        self._write_u8(ep + 0x065, 0)

        # EPROCESS fields
        self._write_u32(ep + 0x084, 4)               # UniqueProcessId = 4
        # ActiveProcessLinks — self-linked list
        self._write_u32(ep + 0x0A0, ep + 0x0A0)
        self._write_u32(ep + 0x0A4, ep + 0x0A0)
        # ImageFileName = "System"
        self.uc.mem_write(ep + 0x1FC, b"System\x00")
        # Token (fake)
        token = self._alloc(0x100)
        self._write_u32(ep + 0x12C, token)
        # ObjectTable
        ot = self._alloc(0x40)
        self._write_u32(ep + 0x128, ot)

    def _build_idle_thread(self):
        """Idle thread for KPRCB."""
        et = self._alloc(0x250)
        self.idle_thread = et
        self._write_u16(et + 0x000, 6)     # Header.Type = ThreadObject
        self._write_u16(et + 0x002, 0x70)   # Header.Size
        self._write_u8(et + 0x02C, 0)       # State = Initialized
        self._write_u8(et + 0x033, 0)       # Priority = 0 (idle)
        self._write_u8(et + 0x034, 1)       # WaitIrql = APC_LEVEL
        self._write_u32(et + 0x044, self.system_eprocess)  # ApcState.Process
        # Teb = NULL for kernel thread
        self._write_u32(et + 0x020, 0)

    def _build_system_thread(self):
        """System thread (the 'current' thread for emulation)."""
        et = self._alloc(0x250)
        self.system_ethread = et
        self._write_u16(et + 0x000, 6)        # ThreadObject
        self._write_u16(et + 0x002, 0x70)
        self._write_u8(et + 0x02C, 2)         # State = Running
        self._write_u8(et + 0x033, 8)          # Priority = 8
        self._write_u8(et + 0x034, 0)          # WaitIrql = PASSIVE
        self._write_u32(et + 0x044, self.system_eprocess)  # ApcState.Process
        self._write_u32(et + 0x020, 0)         # Teb
        # Cid
        self._write_u32(et + 0x1E0, 4)        # ProcessId
        self._write_u32(et + 0x1E4, 8)        # ThreadId
        # PreviousMode = KernelMode (0)
        self._write_u8(et + 0x140, 0)

    def _build_kpcr(self):
        """
        KPCR at 0xFFDFF000 with embedded KPRCB at +0x120.

        The FS segment base is set to KPCR_BASE so that
        FS:[0x1C] -> SelfPcr, FS:[0x20] -> Prcb, etc. work.
        """
        kpcr = self.kpcr_va
        kprcb = self.kprcb_va

        # NtTib.ExceptionList = -1 (end of chain)
        self._write_u32(kpcr + 0x000, 0xFFFFFFFF)
        # NtTib.StackBase / StackLimit (not critical but fill)
        self._write_u32(kpcr + 0x004, 0x80800000)
        self._write_u32(kpcr + 0x008, 0x80700000)
        # SelfPcr
        self._write_u32(kpcr + 0x01C, kpcr)
        # Prcb pointer
        self._write_u32(kpcr + 0x020, kprcb)
        # Irql
        self._write_u8(kpcr + 0x024, 0)  # PASSIVE_LEVEL
        # Number (processor 0)
        self._write_u32(kpcr + 0x030, 0)
        # MajorVersion = 1, MinorVersion = 1
        self._write_u16(kpcr + 0x042, 1)
        self._write_u16(kpcr + 0x040, 1)
        # KdVersionBlock
        kd_ver = self._alloc(0x40)
        self._write_u32(kpcr + 0x034, kd_ver)
        # IDT, GDT, TSS (allocate fake tables)
        idt = self._alloc(0x800)
        gdt = self._alloc(0x400)
        tss = self._alloc(0x68)
        self._write_u32(kpcr + 0x038, idt)
        self._write_u32(kpcr + 0x03C, gdt)
        self._write_u32(kpcr + 0x040, tss)

        # --- KPRCB at kpcr + 0x120 ---
        # MinorVersion = 1, MajorVersion = 1
        self._write_u16(kprcb + 0x000, 1)
        self._write_u16(kprcb + 0x002, 1)
        # CurrentThread
        self._write_u32(kprcb + 0x004, self.system_ethread)
        # NextThread = NULL
        self._write_u32(kprcb + 0x008, 0)
        # IdleThread
        self._write_u32(kprcb + 0x00C, self.idle_thread)
        # Number = 0
        self._write_u8(kprcb + 0x010, 0)
        # BuildType (free build = 0, checked = 1)
        self._write_u16(kprcb + 0x050, 0)
        # ProcessorState … (leave zeroed)

    def _build_handle_table(self):
        """
        Build a minimal object handle table.
        Pre-populate handles so ObReferenceObjectByHandle can work.
        """
        ht = self._alloc(0x1000)
        self.handle_table_va = ht

        # Each handle entry: 8 bytes (Object pointer + GrantedAccess)
        # Handle values are multiples of 4: 0x04, 0x08, etc.
        # The first entry (index 0) is the table header.
        self._write_u32(ht + 0x00, 0)           # table header
        self._write_u32(ht + 0x04, 0)

        # Handle 0x04 = NtCurrentProcess pseudo-handle (-1 maps here)
        self._write_u32(ht + 0x08, self.system_eprocess | 0x01)  # OBJ_KERNEL_HANDLE
        self._write_u32(ht + 0x0C, 0x001F0FFF)   # PROCESS_ALL_ACCESS

        # Handle 0x08 = NtCurrentThread pseudo-handle (-2 maps here)
        self._write_u32(ht + 0x10, self.system_ethread | 0x01)
        self._write_u32(ht + 0x14, 0x001F03FF)    # THREAD_ALL_ACCESS

    def get_current_irql(self) -> int:
        try:
            return struct.unpack('<B', bytes(self.uc.mem_read(
                self.kpcr_va + 0x024, 1)))[0]
        except Exception:
            return 0

    def set_current_irql(self, irql: int):
        self._write_u8(self.kpcr_va + 0x024, irql)

    def set_previous_mode(self, user_mode: bool):
        """Set PreviousMode on the current thread."""
        self._write_u8(self.system_ethread + 0x140, 1 if user_mode else 0)


# ---------------------------------------------------------------------------
#  Kernel Environment — Multi-PE Loader
# ---------------------------------------------------------------------------

class KernelEnvironment:
    """
    Loads multiple Win2K system PEs into a single Unicorn address space
    and resolves cross-module imports — like a real kernel boot.

    Usage:
        env = KernelEnvironment(r"C:\\2kDEBUG")
        env.load_core()            # ntoskrnl.exe + hal.dll
        env.auto_load_dependencies()
    """

    # The core kernel must be loaded first
    CORE_MODULES = ["ntoskrnl.exe", "hal.dll"]
    # Alternate kernel names  (uniprocessor, multiprocessor, PAE, …)
    KERNEL_ALIASES = {
        "ntkrnlmp.exe":  "ntoskrnl.exe",
        "ntkrnlpa.exe":  "ntoskrnl.exe",
        "ntkrpamp.exe":  "ntoskrnl.exe",
    }

    def __init__(self, system_root: str):
        """
        system_root: folder containing .exe / .dll / .sys files.
                     E.g. "C:\\2kDEBUG" or "C:\\WINNT\\System32".
        """
        self.system_root = os.path.abspath(system_root)
        self.uc: Optional[Uc] = None
        self.modules: Dict[str, LoadedModule] = {}   # normalized name -> module
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

        # Memory layout markers
        self._stack_base = 0
        self._stack_top = 0
        self._heap_base = 0
        self._heap_ptr = 0
        self._stub_base = 0
        self._stub_ptr = 0
        self._obj_pool_base = 0

        # Import stubs for unresolved imports
        self._stub_hooks: Dict[int, Tuple[str, str]] = {}   # stub_va -> (dll, func)

        # Mapping: VA of resolved import -> (module, funcname)
        self._resolved_imports: Dict[int, Tuple[str, str]] = {}

        # Kernel state
        self.kstate: Optional[KernelStateBuilder] = None

        # Available files found in system_root
        self._available_files: Dict[str, str] = {}  # normalized name -> full path

        # Missing modules requested during execution
        self._missing_modules: List[Tuple[str, str]] = []  # (dll, func)

        # Callbacks
        self.on_missing_module: Optional[Callable[[str, str], Optional[str]]] = None
        self.on_progress: Optional[Callable[[str, int], None]] = None

    # ---------------------------------------------------------------- scan

    def scan_available_files(self):
        """Scan system_root for PE files."""
        self._available_files.clear()
        if not os.path.isdir(self.system_root):
            return

        for ext in ("*.exe", "*.dll", "*.sys", "*.drv", "*.ocx"):
            for fp in glob.glob(os.path.join(self.system_root, ext)):
                name = os.path.basename(fp).lower()
                self._available_files[name] = fp
            # Also try subdirectories (drivers folder etc.)
            for fp in glob.glob(os.path.join(self.system_root, "**", ext), recursive=True):
                name = os.path.basename(fp).lower()
                if name not in self._available_files:
                    self._available_files[name] = fp

    def _find_file(self, name: str) -> Optional[str]:
        """Find a PE file by name in the system root."""
        norm = name.lower()
        if norm in self._available_files:
            return self._available_files[norm]
        # Check kernel aliases
        alias = self.KERNEL_ALIASES.get(norm)
        if alias and alias in self._available_files:
            return self._available_files[alias]
        # Exact path?
        full = os.path.join(self.system_root, name)
        if os.path.isfile(full):
            return full
        return None

    # ---------------------------------------------------------------- init

    def _progress(self, msg: str, pct: int):
        if self.on_progress:
            self.on_progress(msg, pct)

    def load_core(self, progress_cb=None):
        """Load ntoskrnl.exe + hal.dll and build kernel state."""
        if progress_cb:
            self.on_progress = progress_cb

        self._progress("Scanning system folder…", 2)
        self.scan_available_files()

        if not self._available_files:
            raise FileNotFoundError(
                f"No PE files found in {self.system_root}")

        self._progress("Initializing Unicorn engine…", 5)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # Map KPCR + KUSER_SHARED_DATA first
        self._progress("Mapping kernel structures…", 8)
        # KPCR at high address
        kpcr_page = KPCR_BASE & ~0xFFF
        self.uc.mem_map(kpcr_page, KPCR_SIZE)
        # KUSER_SHARED_DATA
        self.uc.mem_map(KUSER_SHARED_DATA, _PAGE)

        # Load core modules
        self._progress("Loading ntoskrnl.exe…", 10)
        kernel_path = self._find_kernel()
        if not kernel_path:
            raise FileNotFoundError(
                f"Cannot find ntoskrnl.exe (or variant) in {self.system_root}. "
                f"Available: {', '.join(sorted(self._available_files.keys())[:20])}")

        self._load_pe(kernel_path, "ntoskrnl.exe")

        hal_path = self._find_file("hal.dll")
        if hal_path:
            self._progress("Loading hal.dll…", 25)
            self._load_pe(hal_path, "hal.dll")
        else:
            self._progress("hal.dll not found, continuing without it…", 25)

        # Allocate environment memory (stack, heap, stubs, obj pool)
        self._progress("Allocating emulation memory…", 30)
        self._allocate_env_memory()

        # Build kernel state structures
        self._progress("Building kernel state (KPCR, EPROCESS, ETHREAD)…", 40)
        self.kstate = KernelStateBuilder(self.uc, self._obj_pool_base)
        self.kstate.build_all()

        # Setup FS segment to point to KPCR
        self._setup_segments()

        # Resolve cross-module imports
        self._progress("Resolving cross-module imports…", 50)
        self._resolve_all_imports()

        # Build SSDT for ntoskrnl
        self._progress("Building SSDT map…", 60)
        self._build_ssdt()

        self._progress("Core loaded.", 70)

    def _find_kernel(self) -> Optional[str]:
        """Find the kernel executable."""
        for name in ["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"]:
            path = self._find_file(name)
            if path:
                return path
        return None

    # ---------------------------------------------------------------- PE load

    def _find_free_base(self, size: int, preferred: int = 0) -> int:
        """Find a free address range for a PE that needs relocation."""
        aligned_size = (size + 0xFFFF) & ~0xFFFF  # 64KB aligned size
        # Collect all occupied ranges
        occupied = []
        for m in self.modules.values():
            occupied.append((m.image_base, m.image_base + ((m.image_size + 0xFFF) & ~0xFFF)))
        occupied.sort()

        # Try near the preferred base first (scan upward in 64KB steps)
        candidate = ((preferred + 0xFFFF) & ~0xFFFF) if preferred else 0x70000000
        for _ in range(4096):
            end = candidate + aligned_size
            if end > 0xFFC00000:
                break
            conflict = False
            for (ob, oe) in occupied:
                if candidate < oe and end > ob:
                    conflict = True
                    candidate = (oe + 0xFFFF) & ~0xFFFF
                    break
            if not conflict:
                return candidate
        raise RuntimeError(f"Cannot find free address space for {aligned_size:#x} bytes")

    def _apply_relocations(self, pe: pefile.PE, old_base: int, new_base: int):
        """Apply PE base relocations to adjust for new load address."""
        delta = new_base - old_base
        if delta == 0 or not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            return
        for reloc_block in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in reloc_block.entries:
                if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    rva = entry.rva
                    addr = new_base + rva
                    try:
                        val = struct.unpack_from('<I', bytes(self.uc.mem_read(addr, 4)))[0]
                        val += delta
                        self.uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))
                    except Exception:
                        pass
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGH']:
                    addr = new_base + entry.rva
                    try:
                        val = struct.unpack_from('<H', bytes(self.uc.mem_read(addr, 2)))[0]
                        val += (delta >> 16) & 0xFFFF
                        self.uc.mem_write(addr, struct.pack('<H', val & 0xFFFF))
                    except Exception:
                        pass
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_LOW']:
                    addr = new_base + entry.rva
                    try:
                        val = struct.unpack_from('<H', bytes(self.uc.mem_read(addr, 2)))[0]
                        val += delta & 0xFFFF
                        self.uc.mem_write(addr, struct.pack('<H', val & 0xFFFF))
                    except Exception:
                        pass
                # type 0 = IMAGE_REL_BASED_ABSOLUTE = padding, skip

    def _load_pe(self, path: str, force_name: Optional[str] = None):
        """Load a single PE into the Unicorn address space."""
        pe = pefile.PE(path, fast_load=False)
        name = (force_name or os.path.basename(path)).lower()
        ib = pe.OPTIONAL_HEADER.ImageBase
        size = pe.OPTIONAL_HEADER.SizeOfImage
        aligned = (size + 0xFFF) & ~0xFFF

        # Check for overlap with already loaded modules — relocate if needed
        needs_reloc = False
        for m in self.modules.values():
            if (ib < m.image_base + m.image_size and
                    ib + size > m.image_base):
                if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') and pe.DIRECTORY_ENTRY_BASERELOC:
                    old_base = ib
                    ib = self._find_free_base(size, ib)
                    needs_reloc = True
                    self._progress(f"Relocating {name}: 0x{old_base:08X} → 0x{ib:08X}", 0)
                    break
                else:
                    raise RuntimeError(
                        f"Address space collision: {name} at 0x{pe.OPTIONAL_HEADER.ImageBase:08X}-"
                        f"0x{pe.OPTIONAL_HEADER.ImageBase + size:08X} "
                        f"overlaps {m.name} at 0x{m.image_base:08X}-0x{m.image_base + m.image_size:08X} "
                        f"(no relocation data)")

        # Map memory
        try:
            self.uc.mem_map(ib, aligned)
        except Exception:
            # May already be partially mapped; try page by page
            for offset in range(0, aligned, _PAGE):
                try:
                    self.uc.mem_map(ib + offset, _PAGE)
                except Exception:
                    pass

        # Write PE headers
        hdr_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        self.uc.mem_write(ib, pe.__data__[:hdr_size])

        # Write sections
        for sec in pe.sections:
            raw = sec.get_data()
            va = ib + sec.VirtualAddress
            try:
                self.uc.mem_write(va, raw)
            except Exception:
                pass  # may extend beyond mapped region

        # Apply relocations if we moved the image
        if needs_reloc:
            self._apply_relocations(pe, pe.OPTIONAL_HEADER.ImageBase, ib)

        # Build export map
        mod = LoadedModule(name=name, path=path, image_base=ib,
                           image_size=size, pe=pe)

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.address:
                    fn = exp.name.decode('ascii', errors='replace')
                    mod.exports[fn] = ib + exp.address
                if exp.ordinal and exp.address:
                    mod.ordinal_exports[exp.ordinal] = ib + exp.address

        # Record needed imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('ascii', errors='replace').lower()
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('ascii', errors='replace'))
                    elif imp.ordinal:
                        funcs.append(f"#ord{imp.ordinal}")
                mod.imports_needed[dll] = funcs

        self.modules[name] = mod

    # ---------------------------------------------------------------- env mem

    def _allocate_env_memory(self):
        """Allocate stack/heap/stubs outside all loaded PE ranges."""
        # Find highest PE end
        max_end = 0
        for m in self.modules.values():
            end = m.image_base + m.image_size
            if end > max_end:
                max_end = end

        base = ((max_end + 0xFFFF) & ~0xFFFF) + _ALIGN64K

        total = _ENV_STACK_SIZE + _ENV_HEAP_SIZE + _ENV_STUB_SIZE + _ENV_OBJ_POOL_SIZE + 0x2000
        if base + total > 0xFFD00000:
            base = 0x0100_0000

        self._stack_base = base
        self._stack_top = base + _ENV_STACK_SIZE
        self.uc.mem_map(self._stack_base, _ENV_STACK_SIZE)
        base += _ENV_STACK_SIZE

        self._heap_base = base
        self._heap_ptr = base
        self.uc.mem_map(self._heap_base, _ENV_HEAP_SIZE)
        base += _ENV_HEAP_SIZE

        self._stub_base = base
        self._stub_ptr = base
        self.uc.mem_map(self._stub_base, _ENV_STUB_SIZE)
        base += _ENV_STUB_SIZE

        self._obj_pool_base = base
        self.uc.mem_map(self._obj_pool_base, _ENV_OBJ_POOL_SIZE)
        base += _ENV_OBJ_POOL_SIZE

        # Return sled (INT3 page)
        self._ret_sled = base
        self.uc.mem_map(self._ret_sled, _PAGE)
        self.uc.mem_write(self._ret_sled, b"\xCC" * _PAGE)

    def _alloc_stub(self) -> int:
        """Allocate a 16-byte import stub."""
        va = self._stub_ptr
        self._stub_ptr += 16
        # Write RET so we can hook on entry
        self.uc.mem_write(va, b"\xC3" + b"\xCC" * 15)
        return va

    def heap_alloc(self, size: int) -> int:
        """Allocate from the emulator heap."""
        size = (size + 0xF) & ~0xF
        ptr = self._heap_ptr
        self._heap_ptr += size
        if ptr + size >= self._heap_base + _ENV_HEAP_SIZE:
            return 0
        return ptr

    # ---------------------------------------------------------------- imports

    def _resolve_all_imports(self):
        """Wire up IAT entries across all loaded modules."""
        for mod in self.modules.values():
            if not hasattr(mod.pe, 'DIRECTORY_ENTRY_IMPORT'):
                continue

            for entry in mod.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('ascii', errors='replace').lower()
                target_mod = self._find_target_module(dll)

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('ascii', errors='replace')
                    elif imp.ordinal:
                        func_name = f"#ord{imp.ordinal}"
                    else:
                        continue

                    resolved_va = None

                    # Try to resolve from loaded modules
                    if target_mod and func_name in target_mod.exports:
                        resolved_va = target_mod.exports[func_name]
                    elif target_mod and func_name.startswith("#ord"):
                        ordinal = int(func_name[4:])
                        resolved_va = target_mod.ordinal_exports.get(ordinal)

                    if resolved_va:
                        # Patch IAT entry to point to real function
                        self._write_iat(imp.address, resolved_va)
                        self._resolved_imports[resolved_va] = (dll, func_name)
                    else:
                        # Unresolved — create stub for mock hooking
                        stub = self._alloc_stub()
                        self._write_iat(imp.address, stub)
                        self._stub_hooks[stub] = (dll, func_name)
                        mod.unresolved.append((dll, func_name))

    def _find_target_module(self, dll_name: str) -> Optional[LoadedModule]:
        """Find which loaded module provides exports for a given DLL name."""
        norm = dll_name.lower().replace('.dll', '').replace('.exe', '').replace('.sys', '')

        # Direct match
        for ext in ['.exe', '.dll', '.sys', '']:
            candidate = norm + ext
            if candidate in self.modules:
                return self.modules[candidate]

        # ntoskrnl provides exports for many names
        if norm in ('ntoskrnl', 'ntkrnlmp', 'ntkrnlpa', 'ntkrpamp'):
            return self.modules.get('ntoskrnl.exe')

        return None

    def _write_iat(self, iat_rva_addr: int, target_va: int):
        """Write a resolved VA into an IAT slot."""
        try:
            self.uc.mem_write(iat_rva_addr,
                              struct.pack('<I', target_va & 0xFFFFFFFF))
        except Exception:
            pass

    # ---------------------------------------------------------------- SSDT

    def _build_ssdt(self):
        """Build SSDT map for the kernel module."""
        kernel = self.modules.get('ntoskrnl.exe')
        if not kernel:
            return
        try:
            ssdt_map = _ba.build_ssdt_map(kernel.path)
            if ssdt_map:
                kernel.ssdt_map = {idx: va for idx, (name, va) in ssdt_map.items()}
        except Exception:
            pass

    # ---------------------------------------------------------------- segments

    def _setup_segments(self):
        """
        Configure x86 segment registers.
        FS -> KPCR_BASE so kernel code can do mov eax, fs:[0x124] etc.
        """
        # Unicorn doesn't support GDT-based FS natively for UC_MODE_32.
        # We set up a minimal GDT entry and point FS to it.
        gdt_base = self.kstate._alloc(0x100)  # small GDT
        gdt_entries = 3  # null + CS + DS + FS

        # Write GDT entries  — each is 8 bytes
        # Entry 0: null
        self.uc.mem_write(gdt_base, b'\x00' * 8)

        # Entry 1 (selector 0x08): Code segment — base=0, limit=4GB
        self._write_gdt_entry(gdt_base + 8, base=0, limit=0xFFFFF,
                              access=0x9B, flags=0xC)

        # Entry 2 (selector 0x10): Data segment — base=0, limit=4GB
        self._write_gdt_entry(gdt_base + 16, base=0, limit=0xFFFFF,
                              access=0x93, flags=0xC)

        # Entry 3 (selector 0x18): FS segment — base=KPCR_BASE
        self._write_gdt_entry(gdt_base + 24, base=KPCR_BASE, limit=0xFFFF,
                              access=0x93, flags=0x4)

        # Load GDT into Unicorn via MSR/GDTR helper
        # Unicorn requires: uc.mem_write for GDT, then set GDTR
        from unicorn.x86_const import UC_X86_REG_GDTR
        # GDTR: [base:32][limit:16] packed as  limit(16) + base(32)
        # But Unicorn expects a tuple: (0, base, limit, 0)
        self.uc.reg_write(UC_X86_REG_GDTR, (0, gdt_base, 4 * 8 - 1, 0))

        # Set segment registers
        self.uc.reg_write(UC_X86_REG_CS, 0x08)
        self.uc.reg_write(UC_X86_REG_DS, 0x10)
        self.uc.reg_write(UC_X86_REG_ES, 0x10)
        self.uc.reg_write(UC_X86_REG_SS, 0x10)
        self.uc.reg_write(UC_X86_REG_FS, 0x18)

    def _write_gdt_entry(self, addr, base, limit, access, flags):
        """Write an x86 GDT descriptor entry (8 bytes)."""
        # GDT entry layout (8 bytes):
        #   [0:2]  limit_low (bits 0-15)
        #   [2:4]  base_low  (bits 0-15)
        #   [4]    base_mid  (bits 16-23)
        #   [5]    access byte
        #   [6]    flags:4 | limit_hi:4
        #   [7]    base_hi   (bits 24-31)
        b0 = limit & 0xFFFF
        b1 = base & 0xFFFF
        b2 = (base >> 16) & 0xFF
        b3 = access & 0xFF
        b4 = ((flags & 0xF) << 4) | ((limit >> 16) & 0xF)
        b5 = (base >> 24) & 0xFF
        data = struct.pack('<HHBBBB', b0, b1, b2, b3, b4, b5)
        self.uc.mem_write(addr, data)

    # ---------------------------------------------------------------- module loading on demand

    def load_module(self, name_or_path: str) -> Optional[LoadedModule]:
        """Load an additional PE module."""
        if os.path.isfile(name_or_path):
            path = name_or_path
            name = os.path.basename(path).lower()
        else:
            name = name_or_path.lower()
            path = self._find_file(name)
            if not path:
                return None

        if name in self.modules:
            return self.modules[name]

        try:
            self._load_pe(path, name)
            self._resolve_all_imports()  # re-resolve with new module
            return self.modules.get(name)
        except Exception:
            return None

    def auto_load_dependencies(self, max_depth: int = 3, progress_cb=None):
        """
        Iteratively load missing modules up to max_depth levels.
        Returns list of modules that could NOT be found.
        """
        if progress_cb:
            self.on_progress = progress_cb

        truly_missing = set()

        for depth in range(max_depth):
            needed = set()
            for mod in list(self.modules.values()):
                for dll, func in mod.unresolved:
                    norm = dll.lower()
                    if norm not in self.modules and norm not in truly_missing:
                        needed.add(norm)

            if not needed:
                break

            loaded_any = False
            total_needed = len(needed)
            for i, dll in enumerate(needed):
                pct = 70 + int(25 * (depth * total_needed + i) /
                               (max_depth * max(total_needed, 1)))
                self._progress(f"Loading dependency: {dll}…", pct)
                result = self.load_module(dll)
                if result:
                    loaded_any = True
                else:
                    truly_missing.add(dll)

            if not loaded_any:
                break

        self._progress("Dependencies resolved.", 100)
        return sorted(truly_missing)

    # ---------------------------------------------------------------- symbols

    def load_symbols(self, module_name: str, symbols: Dict[int, str]):
        """Attach symbol information to a loaded module."""
        norm = module_name.lower()
        mod = self.modules.get(norm)
        if mod:
            mod.symbols.update(symbols)

    def load_symbols_from_file(self, module_name: str, symbol_path: str):
        """Load symbols from a .map/.pdb/.dbg file for a module."""
        from . import symbol_loader
        try:
            result = symbol_loader.load_symbols(symbol_path)
            if result and result.get('symbols'):
                self.load_symbols(module_name, result['symbols'])
                return len(result['symbols'])
        except Exception:
            pass
        return 0

    # ---------------------------------------------------------------- resolve function

    def resolve_function(self, name: str) -> Optional[Tuple[int, str]]:
        """
        Resolve a function name to (VA, module_name).
        Searches: exports → SSDT → symbols across all modules.
        """
        for mod in self.modules.values():
            if name in mod.exports:
                return (mod.exports[name], mod.name)

        # SSDT for Nt* functions
        kernel = self.modules.get('ntoskrnl.exe')
        if kernel and name.startswith('Nt') and not name.startswith('Ntdll'):
            ssdt = _ba.resolve_nt_via_ssdt(kernel.path, name)
            if ssdt:
                return (ssdt[1], 'ntoskrnl.exe')

        # Nt<->Zw alias
        alt = None
        if name.startswith('Nt') and not name.startswith('Ntdll'):
            alt = 'Zw' + name[2:]
        elif name.startswith('Zw'):
            alt = 'Nt' + name[2:]
        if alt:
            for mod in self.modules.values():
                if alt in mod.exports:
                    return (mod.exports[alt], mod.name)

        # Symbols
        for mod in self.modules.values():
            for va, sym in mod.symbols.items():
                if sym == name:
                    return (va, mod.name)

        return None

    def find_module_at(self, va: int) -> Optional[LoadedModule]:
        """Find which module contains a given VA."""
        for mod in self.modules.values():
            if mod.image_base <= va < mod.image_base + mod.image_size:
                return mod
        return None

    def find_function_at(self, va: int) -> Optional[Tuple[str, str]]:
        """Find function name + module at VA, searching exports and symbols."""
        mod = self.find_module_at(va)
        if not mod:
            # Check stub hooks
            if va in self._stub_hooks:
                dll, func = self._stub_hooks[va]
                return (func, dll)
            return None

        # Check exports (find closest export <= va)
        best_name = None
        best_va = 0
        for name, exp_va in mod.exports.items():
            if exp_va <= va and exp_va > best_va:
                best_va = exp_va
                best_name = name

        # Check symbols
        for sym_va, sym_name in mod.symbols.items():
            if sym_va <= va and sym_va > best_va:
                best_va = sym_va
                best_name = sym_name

        if best_name:
            offset = va - best_va
            if offset == 0:
                return (best_name, mod.name)
            return (f"{best_name}+0x{offset:X}", mod.name)

        return (f"{mod.name}+0x{va - mod.image_base:X}", mod.name)

    # ---------------------------------------------------------------- info

    def get_info(self) -> dict:
        return {
            "system_root": self.system_root,
            "modules_loaded": len(self.modules),
            "modules": {
                name: {
                    "base": f"0x{m.image_base:08X}",
                    "size": f"0x{m.image_size:08X}",
                    "exports": len(m.exports),
                    "unresolved": len(m.unresolved),
                    "symbols": len(m.symbols),
                }
                for name, m in self.modules.items()
            },
            "available_files": len(self._available_files),
            "stack": f"0x{self._stack_base:08X}-0x{self._stack_top:08X}",
            "heap": f"0x{self._heap_base:08X}",
            "kpcr": f"0x{KPCR_BASE:08X}",
            "system_eprocess": f"0x{self.kstate.system_eprocess:08X}" if self.kstate else "N/A",
        }

    def close(self):
        for mod in self.modules.values():
            if mod.pe:
                mod.pe.close()
                mod.pe = None
        self.uc = None
        self.modules.clear()


# ---------------------------------------------------------------------------
#  Object Inspector
# ---------------------------------------------------------------------------

class ObjectInspector:
    """
    Inspect kernel objects in emulated memory.
    Detect object type, dump fields, check for null pointers.
    """

    # Object type identifiers (OBJECT_HEADER.Type index)
    OBJECT_TYPES = {
        0: "None",
        1: "Type",
        2: "Directory",
        3: "Process",
        4: "Thread",
        5: "Token",
        6: "Event",
        7: "Mutex",
        8: "Semaphore",
        9: "Timer",
        10: "Profile",
        11: "WindowStation",
        12: "Desktop",
        13: "Section",
        14: "Key",
        15: "Port",
        16: "WaitablePort",
        17: "Adapter",
        18: "Controller",
        19: "Device",
        20: "Driver",
        21: "IoCompletion",
        22: "File",
    }

    # Field layouts for common kernel objects
    DRIVER_OBJECT_FIELDS = [
        (0x000, 2, "Type",           "should be 4"),
        (0x002, 2, "Size",           ""),
        (0x004, 4, "DeviceObject",   "PDEVICE_OBJECT — first device in chain"),
        (0x008, 4, "Flags",          ""),
        (0x00C, 4, "DriverStart",    "base address of driver image"),
        (0x010, 4, "DriverSize",     "size of driver image"),
        (0x014, 4, "DriverSection",  "PLDR_DATA_TABLE_ENTRY"),
        (0x018, 4, "DriverExtension", "PDRIVER_EXTENSION"),
        (0x01C, 8, "DriverName",     "UNICODE_STRING"),
        (0x024, 4, "HardwareDatabase", "PUNICODE_STRING"),
        (0x028, 4, "FastIoDispatch", "PFAST_IO_DISPATCH"),
        (0x02C, 4, "DriverInit",     "entry point"),
        (0x030, 4, "DriverStartIo",  ""),
        (0x034, 4, "DriverUnload",   "cleanup routine"),
        (0x038, 112, "MajorFunction[28]", "IRP dispatch table"),
    ]

    DEVICE_OBJECT_FIELDS = [
        (0x000, 2, "Type",           "should be 3"),
        (0x002, 2, "Size",           ""),
        (0x004, 4, "ReferenceCount", ""),
        (0x008, 4, "DriverObject",   "PDRIVER_OBJECT — owning driver"),
        (0x00C, 4, "NextDevice",     "next device in driver's chain"),
        (0x010, 4, "AttachedDevice", "device attached on top"),
        (0x014, 4, "CurrentIrp",     ""),
        (0x018, 4, "Timer",          ""),
        (0x01C, 4, "Flags",          ""),
        (0x020, 4, "Characteristics", ""),
        (0x024, 4, "Vpb",            "PVPB"),
        (0x028, 4, "DeviceExtension", "driver-specific data"),
        (0x02C, 4, "DeviceType",     ""),
        (0x030, 1, "StackSize",      "IRP stack depth"),
    ]

    EPROCESS_FIELDS = [
        (0x000, 2, "Pcb.Header.Type",  "should be 3"),
        (0x002, 2, "Pcb.Header.Size",  ""),
        (0x018, 4, "DirectoryTableBase", "page directory physical addr"),
        (0x060, 1, "BasePriority",      ""),
        (0x084, 4, "UniqueProcessId",   "PID"),
        (0x0A0, 4, "ActiveProcessLinks.Flink", ""),
        (0x0A4, 4, "ActiveProcessLinks.Blink", ""),
        (0x128, 4, "ObjectTable",       "PHANDLE_TABLE"),
        (0x12C, 4, "Token",            ""),
        (0x1FC, 16, "ImageFileName",    "process name string"),
    ]

    IRP_FIELDS = [
        (0x000, 2, "Type",             "should be 6"),
        (0x002, 2, "Size",             ""),
        (0x004, 4, "MdlAddress",       "PMDL"),
        (0x008, 4, "Flags",            ""),
        (0x018, 4, "AssociatedIrp.SystemBuffer", ""),
        (0x020, 4, "IoStatus.Status",  ""),
        (0x024, 4, "IoStatus.Information", ""),
        (0x028, 1, "RequestorMode",    "0=Kernel, 1=User"),
        (0x02C, 4, "Cancel",           ""),
        (0x030, 1, "CancelIrql",       ""),
        (0x038, 4, "UserEvent",        "PKEVENT"),
        (0x040, 8, "Overlay",          ""),
        (0x048, 4, "CancelRoutine",    ""),
        (0x04C, 4, "UserBuffer",       ""),
    ]

    def __init__(self, env: KernelEnvironment):
        self.env = env

    def _read_u8(self, addr) -> int:
        try:
            return struct.unpack('<B', bytes(self.env.uc.mem_read(addr, 1)))[0]
        except Exception:
            return 0

    def _read_u16(self, addr) -> int:
        try:
            return struct.unpack('<H', bytes(self.env.uc.mem_read(addr, 2)))[0]
        except Exception:
            return 0

    def _read_u32(self, addr) -> int:
        try:
            return struct.unpack('<I', bytes(self.env.uc.mem_read(addr, 4)))[0]
        except Exception:
            return 0

    def _read_string(self, addr, max_len=32) -> str:
        try:
            data = bytes(self.env.uc.mem_read(addr, max_len))
            return data.split(b'\x00')[0].decode('ascii', errors='replace')
        except Exception:
            return "<error>"

    def _read_unicode_string(self, addr) -> str:
        """Read UNICODE_STRING struct: Length, MaxLength, Buffer."""
        length = self._read_u16(addr)
        buf = self._read_u32(addr + 4)
        if not buf or not length or length > 512:
            return "<null>"
        try:
            data = bytes(self.env.uc.mem_read(buf, min(length, 512)))
            return data.decode('utf-16-le', errors='replace')
        except Exception:
            return "<error>"

    def detect_type(self, addr: int) -> str:
        """Try to detect what kernel object lives at addr."""
        type_val = self._read_u16(addr)

        # DRIVER_OBJECT: Type=4, Size=0xA8
        if type_val == 4:
            size = self._read_u16(addr + 2)
            if 0x90 <= size <= 0x100:
                return "DRIVER_OBJECT"

        # DEVICE_OBJECT: Type=3
        if type_val == 3:
            size = self._read_u16(addr + 2)
            if 0x80 <= size <= 0x200:
                drv = self._read_u32(addr + 8)
                if drv and self._read_u16(drv) == 4:
                    return "DEVICE_OBJECT"
                return "EPROCESS"  # KPROCESS also has Type=3

        # ETHREAD: Type=6
        if type_val == 6:
            size = self._read_u16(addr + 2)
            if size > 0x40:
                return "ETHREAD"

        # IRP: Type=6 (same type, different size range)
        if type_val == 6:
            size = self._read_u16(addr + 2)
            if 0x40 <= size <= 0x200:
                return "IRP"

        return f"Unknown(Type={type_val})"

    def dump_object(self, addr: int, type_hint: Optional[str] = None) -> List[str]:
        """Dump any kernel object's fields."""
        obj_type = type_hint or self.detect_type(addr)

        field_map = {
            "DRIVER_OBJECT": self.DRIVER_OBJECT_FIELDS,
            "DEVICE_OBJECT": self.DEVICE_OBJECT_FIELDS,
            "EPROCESS":      self.EPROCESS_FIELDS,
            "IRP":           self.IRP_FIELDS,
        }

        fields = field_map.get(obj_type)
        if not fields:
            return [f"Unknown object type: {obj_type} at 0x{addr:08X}"]

        lines = [
            f"{'═' * 60}",
            f"  {obj_type} at 0x{addr:08X}",
            f"{'═' * 60}",
        ]

        for offset, size, name, comment in fields:
            va = addr + offset
            if size == 1:
                val = self._read_u8(va)
                val_str = f"0x{val:02X}"
            elif size == 2:
                val = self._read_u16(va)
                val_str = f"0x{val:04X}"
            elif size == 4:
                val = self._read_u32(va)
                val_str = f"0x{val:08X}"
                # Annotate pointers
                if val and "PTR" not in name.upper() and comment and (
                        "P" in comment[:2] or "pointer" in comment.lower()):
                    mod = self.env.find_module_at(val)
                    if mod:
                        val_str += f"  [{mod.name}]"
                    elif val == 0:
                        val_str += "  [NULL!]"
            elif size == 8 and "UNICODE_STRING" in comment:
                ustr = self._read_unicode_string(va)
                val_str = f'"{ustr}"'
            elif size == 16 and "FileName" in name:
                val_str = f'"{self._read_string(va)}"'
            else:
                val_str = f"({size} bytes)"

            # NULL pointer warning
            warning = ""
            if size == 4 and val == 0 and any(
                    kw in comment.lower() for kw in
                    ['pointer', 'pdevice', 'pdriver', 'entry point',
                     'dispatch', 'routine']):
                warning = " ⚠️ NULL"

            lines.append(f"  +0x{offset:03X} {name:<30} = {val_str}"
                         f"  {comment}{warning}")

        return lines

    def check_null_pointers(self, addr: int, type_hint: Optional[str] = None) -> List[str]:
        """Find NULL pointers in a kernel object that shouldn't be NULL."""
        obj_type = type_hint or self.detect_type(addr)
        field_map = {
            "DRIVER_OBJECT": self.DRIVER_OBJECT_FIELDS,
            "DEVICE_OBJECT": self.DEVICE_OBJECT_FIELDS,
            "EPROCESS":      self.EPROCESS_FIELDS,
            "IRP":           self.IRP_FIELDS,
        }
        fields = field_map.get(obj_type, [])
        issues = []

        critical_keywords = ['entry point', 'dispatch', 'routine', 'object',
                             'pdriver', 'pdevice', 'table']

        for offset, size, name, comment in fields:
            if size != 4:
                continue
            val = self._read_u32(addr + offset)
            if val == 0:
                is_critical = any(kw in comment.lower() for kw in critical_keywords)
                if is_critical:
                    issues.append(f"  ⚠️  {name} (+0x{offset:03X}) is NULL — {comment}")

        return issues

    def dump_device_stack(self, device_va: int) -> List[str]:
        """Walk the device stack from a DEVICE_OBJECT."""
        lines = ["Device Stack:"]
        va = device_va
        depth = 0
        seen = set()

        while va and va not in seen and depth < 32:
            seen.add(va)
            drv = self._read_u32(va + 0x008)
            attached = self._read_u32(va + 0x010)
            dev_type = self._read_u32(va + 0x02C)
            stack_size = self._read_u8(va + 0x030)

            drv_name = ""
            if drv:
                drv_name = self._read_unicode_string(drv + 0x01C)

            indent = "  " * depth
            lines.append(
                f"{indent}[{depth}] DEVICE 0x{va:08X}  Type={dev_type}  "
                f"StackSize={stack_size}  Driver=\"{drv_name}\"")

            va = attached
            depth += 1

        return lines

    def walk_handle_table(self) -> List[str]:
        """Dump the current process handle table."""
        if not self.env.kstate:
            return ["No kernel state available"]

        ht = self.env.kstate.handle_table_va
        lines = [
            f"Handle Table at 0x{ht:08X}",
            f"{'Handle':>10} | {'Object':>12} | {'Access':>12} | Type",
            f"{'-' * 10}-+-{'-' * 12}-+-{'-' * 12}-+{'-' * 20}",
        ]

        for i in range(1, 64):  # scan first 64 handles
            handle = i * 4
            obj_ptr = self._read_u32(ht + handle * 2)
            access = self._read_u32(ht + handle * 2 + 4)
            if obj_ptr:
                clean_ptr = obj_ptr & ~0x07  # remove flags
                obj_type = self.detect_type(clean_ptr) if clean_ptr else "?"
                lines.append(
                    f"  0x{handle:04X}   | 0x{clean_ptr:08X}   | "
                    f"0x{access:08X}   | {obj_type}")

        return lines


# ---------------------------------------------------------------------------
#  Enhanced Kernel Mocks (with full env access)
# ---------------------------------------------------------------------------

class EnvKernelMocks:
    """
    Mock implementations of kernel APIs with full environment access.
    Unlike the simple emulator mocks, these can access actual loaded
    modules, kernel structures, and the object pool.
    """

    def __init__(self, env: KernelEnvironment, session: "DebugSession"):
        self.env = env
        self.session = session
        self.privilege_enabled = True
        self.current_irql = 0
        self._irql_call_count = 0

    def _write_u32(self, addr, val):
        try:
            self.env.uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))
        except Exception:
            pass

    def _read_u32(self, addr):
        try:
            return struct.unpack('<I', bytes(self.env.uc.mem_read(addr, 4)))[0]
        except Exception:
            return 0

    def reset(self):
        self._irql_call_count = 0
        self.current_irql = 0

    # -- memory probes --
    def ProbeForRead(self, args):
        addr, length = args[0], args[1]
        if addr == 0 or length == 0:
            return STATUS_ACCESS_VIOLATION
        # Check if address is in valid mapped memory
        try:
            self.env.uc.mem_read(addr, min(length, 1))
            return STATUS_SUCCESS
        except Exception:
            self.session._raise_event(DebugEvent(
                event_type="null_deref",
                address=addr,
                message=f"ProbeForRead: invalid memory 0x{addr:08X}, length={length}"))
            return STATUS_ACCESS_VIOLATION

    def ProbeForWrite(self, args):
        addr, length = args[0], args[1]
        if addr == 0 or length == 0:
            return STATUS_ACCESS_VIOLATION
        try:
            self.env.uc.mem_read(addr, min(length, 1))
            return STATUS_SUCCESS
        except Exception:
            self.session._raise_event(DebugEvent(
                event_type="null_deref",
                address=addr,
                message=f"ProbeForWrite: invalid memory 0x{addr:08X}, length={length}"))
            return STATUS_ACCESS_VIOLATION

    # -- privilege --
    def SeSinglePrivilegeCheck(self, args):
        return 1 if self.privilege_enabled else 0

    def SePrivilegeCheck(self, args):
        return 1 if self.privilege_enabled else 0

    # -- object manager --
    def ObReferenceObjectByHandle(self, args):
        handle = args[0]
        obj_type = args[1] if len(args) > 1 else 0
        desired_access = args[2] if len(args) > 2 else 0
        access_mode = args[3] if len(args) > 3 else 0
        obj_out = args[4] if len(args) > 4 else 0

        # Pseudo handles
        if handle == 0xFFFFFFFF:  # NtCurrentProcess
            if obj_out:
                self._write_u32(obj_out, self.env.kstate.system_eprocess)
            return STATUS_SUCCESS
        elif handle == 0xFFFFFFFE:  # NtCurrentThread
            if obj_out:
                self._write_u32(obj_out, self.env.kstate.system_ethread)
            return STATUS_SUCCESS

        # Real handle lookup
        ht = self.env.kstate.handle_table_va
        if handle < 0x100:
            obj_ptr = self._read_u32(ht + handle * 2)
            if obj_ptr:
                if obj_out:
                    self._write_u32(obj_out, obj_ptr & ~0x07)
                return STATUS_SUCCESS

        self.session._raise_event(DebugEvent(
            event_type="invalid_call",
            message=f"ObReferenceObjectByHandle: invalid handle 0x{handle:X}"))
        return STATUS_INVALID_HANDLE

    def ObDereferenceObject(self, args):   return STATUS_SUCCESS
    def ObfDereferenceObject(self, args):  return STATUS_SUCCESS

    # -- memory --
    def ExAllocatePool(self, args):
        size = args[1] if len(args) >= 2 else 0x100
        return self.env.heap_alloc(max(size, 0x10))

    def ExAllocatePoolWithTag(self, args):
        size = args[1] if len(args) >= 2 else 0x100
        return self.env.heap_alloc(max(size, 0x10))

    def ExFreePool(self, args):            return STATUS_SUCCESS
    def ExFreePoolWithTag(self, args):     return STATUS_SUCCESS

    # -- MDL --
    def IoAllocateMdl(self, args):         return self.env.heap_alloc(0x40)
    def IoFreeMdl(self, args):             return STATUS_SUCCESS
    def MmProbeAndLockPages(self, args):   return STATUS_SUCCESS
    def MmUnlockPages(self, args):         return STATUS_SUCCESS
    def MmGetSystemAddressForMdlSafe(self, args):
        return self.env.heap_alloc(0x100)
    def MmMapLockedPagesSpecifyCache(self, args):
        return self.env.heap_alloc(0x100)

    # -- process / thread --
    def PsGetCurrentProcess(self, args):
        return self.env.kstate.system_eprocess

    def PsGetCurrentProcessId(self, args):
        return 4

    def PsGetCurrentThread(self, args):
        return self.env.kstate.system_ethread

    def IoGetCurrentProcess(self, args):
        return self.env.kstate.system_eprocess

    def KeGetPreviousMode(self, args):
        return 1 if self.session._user_mode else 0

    def ExGetPreviousMode(self, args):
        return self.KeGetPreviousMode(args)

    # -- IRQL --
    def KeGetCurrentIrql(self, args):
        self._irql_call_count += 1
        if self._irql_call_count > 50:
            cycle = [0, 1, 2, 0]
            self.current_irql = cycle[self._irql_call_count % len(cycle)]
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

    def KeRaiseIrqlToDpcLevel(self, args):
        old = self.current_irql
        self.current_irql = 2
        return old

    # -- sync --
    def KeInitializeSpinLock(self, args):        return STATUS_SUCCESS
    def KeAcquireSpinLockRaiseToDpc(self, args):
        old = self.current_irql; self.current_irql = 2; return old
    def KeReleaseSpinLock(self, args):           return STATUS_SUCCESS
    def KfAcquireSpinLock(self, args):           return self.current_irql
    def KfReleaseSpinLock(self, args):
        if args: self.current_irql = args[0]
        return STATUS_SUCCESS
    def KeAcquireSpinLockAtDpcLevel(self, args): return STATUS_SUCCESS
    def KeReleaseSpinLockFromDpcLevel(self, args): return STATUS_SUCCESS
    def ExAcquireFastMutex(self, args):          return STATUS_SUCCESS
    def ExReleaseFastMutex(self, args):          return STATUS_SUCCESS
    def ExAcquireResourceExclusiveLite(self, args): return 1
    def ExReleaseResourceLite(self, args):       return STATUS_SUCCESS
    def KeWaitForSingleObject(self, args):       return STATUS_SUCCESS
    def KeWaitForMultipleObjects(self, args):    return STATUS_SUCCESS
    def KeDelayExecutionThread(self, args):      return STATUS_SUCCESS
    def KeSetEvent(self, args):                  return 0
    def KeResetEvent(self, args):                return 0
    def KeInitializeEvent(self, args):           return STATUS_SUCCESS

    # -- memory copy --
    def RtlCopyMemory(self, args):
        dst, src, length = args[0], args[1], args[2]
        if dst and src and length and length < 0x100000:
            try:
                data = self.env.uc.mem_read(src, length)
                self.env.uc.mem_write(dst, bytes(data))
            except Exception:
                pass
        return STATUS_SUCCESS

    def memcpy(self, args):  return self.RtlCopyMemory(args)

    def RtlZeroMemory(self, args):
        dst, length = args[0], args[1]
        if dst and length and length < 0x100000:
            try:
                self.env.uc.mem_write(dst, b'\x00' * length)
            except Exception:
                pass
        return STATUS_SUCCESS

    def memset(self, args):
        dst, val, length = args[0], args[1] & 0xFF, args[2]
        if dst and length and length < 0x100000:
            try:
                self.env.uc.mem_write(dst, bytes([val]) * length)
            except Exception:
                pass
        return dst

    # -- fatal --
    def ExRaiseStatus(self, args):
        status = args[0] if args else STATUS_ACCESS_VIOLATION
        self.session._raise_event(DebugEvent(
            event_type="exception",
            message=f"ExRaiseStatus(0x{status:08X}) — {ntstatus_name(status)}"))
        raise _DebugException(f"ExRaiseStatus(0x{status:08X})")

    def KeBugCheckEx(self, args):
        code = args[0] if args else 0
        p1 = args[1] if len(args) > 1 else 0
        p2 = args[2] if len(args) > 2 else 0
        p3 = args[3] if len(args) > 3 else 0
        self.session._raise_event(DebugEvent(
            event_type="exception",
            message=f"*** BUGCHECK 0x{code:08X} "
                    f"(0x{p1:08X}, 0x{p2:08X}, 0x{p3:08X}) ***",
            details={"code": code, "p1": p1, "p2": p2, "p3": p3}))
        raise _DebugException(f"KeBugCheckEx(0x{code:08X})")

    def DbgPrint(self, args):       return STATUS_SUCCESS
    def DbgBreakPoint(self, args):
        self.session._raise_event(DebugEvent(
            event_type="breakpoint",
            address=self.env.uc.reg_read(UC_X86_REG_EIP),
            message="DbgBreakPoint() called"))
        self.session._pause("DbgBreakPoint()")
        return STATUS_SUCCESS

    # -- registry --
    def ZwOpenKey(self, args):
        if args and args[0]:
            self._write_u32(args[0], 0xBADC0DE0)
        return STATUS_SUCCESS
    def ZwQueryValueKey(self, args):  return STATUS_SUCCESS
    def ZwClose(self, args):          return STATUS_SUCCESS

    # -- IRP / IO --
    def IoCompleteRequest(self, args): return STATUS_SUCCESS
    def IoCallDriver(self, args):     return STATUS_SUCCESS
    def IofCompleteRequest(self, args): return STATUS_SUCCESS
    def IofCallDriver(self, args):    return STATUS_SUCCESS

    # -- power --
    def PoSetPowerState(self, args):     return STATUS_SUCCESS
    def PoStartNextPowerIrp(self, args): return STATUS_SUCCESS
    def PoRequestPowerIrp(self, args):   return STATUS_SUCCESS

    # -- string --
    def RtlInitUnicodeString(self, args):    return STATUS_SUCCESS
    def RtlCompareUnicodeString(self, args): return 0
    def RtlEqualUnicodeString(self, args):   return 1
    def RtlCopyUnicodeString(self, args):    return STATUS_SUCCESS

    # -- HAL --
    def HalMakeBeep(self, args):       return 1
    def HalRequestSoftwareInterrupt(self, args): return STATUS_SUCCESS
    def HalQuerySystemInformation(self, args):   return STATUS_SUCCESS
    def HalSetSystemInformation(self, args):     return STATUS_SUCCESS
    def READ_PORT_UCHAR(self, args):   return 0
    def WRITE_PORT_UCHAR(self, args):  return STATUS_SUCCESS
    def READ_PORT_ULONG(self, args):   return 0
    def WRITE_PORT_ULONG(self, args):  return STATUS_SUCCESS

    def dispatch(self, full_name: str, args: list) -> int:
        func = full_name.split("!")[-1] if "!" in full_name else full_name
        method = getattr(self, func, None)
        if callable(method) and not func.startswith("_"):
            return method(args)
        # Check if this is a missing-module function
        if full_name in [f"{d}!{f}" for d, f in self.env._stub_hooks.values()]:
            dll, fname = full_name.split("!", 1) if "!" in full_name else ("?", full_name)
            self.session._raise_event(DebugEvent(
                event_type="missing_module",
                message=f"Unresolved import: {full_name}",
                module=dll, function=fname))
        return STATUS_SUCCESS


class _DebugException(Exception):
    """Internal exception to halt emulation at a debug event."""


# ---------------------------------------------------------------------------
#  Debug Session  — the heart of the live debugger
# ---------------------------------------------------------------------------

class DebugSession:
    """
    Interactive debugging session on top of a KernelEnvironment.

    Features:
     - Breakpoints (address or function name, conditional, temporary)
     - Single-step execution
     - Error detection BEFORE crash (null deref, invalid handle, etc.)
     - Missing module detection (pauses and asks user)
     - Call stack reconstruction
     - Full register/memory inspection
     - Execution trace
    """

    def __init__(self, env: KernelEnvironment):
        self.env = env
        self.state = DebugState.IDLE
        self.mocks = EnvKernelMocks(env, self)
        self.inspector = ObjectInspector(env)

        # Breakpoints
        self._breakpoints: Dict[int, Breakpoint] = {}   # address -> bp
        self._next_bp_id = 1

        # Execution state
        self._trace: list = []
        self._api_calls: list = []
        self._insn_count = 0
        self._block_hits: Dict[int, int] = {}
        self._user_mode = False
        self._max_instructions = _MAX_INSTRUCTIONS
        self._stop_reason = ""
        self._hooks = []

        # Events log
        self.events: List[DebugEvent] = []

        # Callbacks
        self.on_breakpoint: Optional[Callable[[Breakpoint, dict], None]] = None
        self.on_event: Optional[Callable[[DebugEvent], None]] = None
        self.on_missing_module: Optional[Callable[[str, str], Optional[str]]] = None

        # Step control
        self._step_mode = False
        self._paused = False
        self._pause_reason = ""

        # Exception-raising function addresses (populated at run time)
        self._exception_func_addrs: Dict[int, str] = {}

    # ----------------------------------------------------------- breakpoints

    def set_breakpoint(self, target, condition=None, callback=None) -> int:
        """
        Set a breakpoint on an address or function name.
        Returns breakpoint ID.
        """
        if isinstance(target, str):
            result = self.env.resolve_function(target)
            if not result:
                raise ValueError(f"Cannot resolve function: {target}")
            addr, mod_name = result
            name = f"{mod_name}!{target}"
        else:
            addr = target
            func_info = self.env.find_function_at(addr)
            name = f"0x{addr:08X}"
            if func_info:
                name = f"{func_info[1]}!{func_info[0]}"

        bp = Breakpoint(
            id=self._next_bp_id,
            address=addr,
            name=name,
            condition=condition,
            callback=callback,
        )
        self._next_bp_id += 1
        self._breakpoints[addr] = bp
        return bp.id

    def remove_breakpoint(self, bp_id: int):
        for addr, bp in list(self._breakpoints.items()):
            if bp.id == bp_id:
                del self._breakpoints[addr]
                return True
        return False

    def list_breakpoints(self) -> List[Breakpoint]:
        return list(self._breakpoints.values())

    # ----------------------------------------------------------- run

    def run(
        self,
        func_name: str,
        args: Optional[List[int]] = None,
        user_mode: bool = False,
        max_instructions: int = _MAX_INSTRUCTIONS,
        stop_at_entry: bool = False,
        show_trace: bool = False,
    ) -> dict:
        """
        Run a kernel function with full environment support.

        Returns dict with: return_value, return_status, trace, api_calls,
        events, instructions, elapsed_sec, exception.
        """
        result = self.env.resolve_function(func_name)
        if not result:
            return {"error": f"Function '{func_name}' not found",
                    "events": list(self.events)}

        func_va, mod_name = result
        return self._run_at(func_va, func_name, args or [], user_mode,
                            max_instructions, stop_at_entry, show_trace)

    def _run_at(self, func_va, func_name, args, user_mode,
                max_instructions, stop_at_entry, show_trace):
        """Core emulation loop."""
        uc = self.env.uc

        # Clean up any stale hooks from a previous run on this session
        self._cleanup_hooks()

        self.state = DebugState.RUNNING
        self._user_mode = user_mode
        self._max_instructions = max_instructions
        self._trace.clear()
        self._api_calls.clear()
        self._insn_count = 0
        self._block_hits.clear()
        self._stop_reason = ""
        self._paused = False
        self.events.clear()
        self.mocks.reset()
        self._pre_return_snapshot = None  # registers just before final ret

        # Set PreviousMode
        if self.env.kstate:
            self.env.kstate.set_previous_mode(user_mode)

        # Setup stack
        esp = self.env._stack_top - 0x200
        for arg in reversed(args):
            esp -= 4
            uc.mem_write(esp, struct.pack('<I', arg & 0xFFFFFFFF))
        esp -= 4
        uc.mem_write(esp, struct.pack('<I', self.env._ret_sled))

        # Init registers
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_EBP, esp + 4)
        for reg in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                    UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI):
            uc.reg_write(reg, 0)

        if stop_at_entry:
            bp = Breakpoint(id=0, address=func_va, name=func_name,
                            temporary=True)
            self._breakpoints[func_va] = bp

        # Resolve exception-raising functions for interception
        self._resolve_exception_funcs()

        # Install hooks
        h_code = uc.hook_add(UC_HOOK_CODE, self._hook_code)
        h_memr = uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_unmapped)
        h_memw = uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_unmapped)
        h_memf = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_fetch_unmapped)
        h_intr = uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._hooks = [h_code, h_memr, h_memw, h_memf, h_intr]

        t0 = time.perf_counter()
        exception_msg = None

        try:
            uc.emu_start(func_va, self.env._ret_sled, timeout=60_000_000)
        except _DebugException as e:
            exception_msg = str(e)
        except Exception as e:
            exception_msg = f"Unicorn error: {e}"

        elapsed = time.perf_counter() - t0
        eax = uc.reg_read(UC_X86_REG_EAX)

        # If paused at breakpoint, keep hooks alive for step()
        if self.state == DebugState.PAUSED:
            self._run_state = {
                "func_name": func_name,
                "show_trace": show_trace,
                "start_time": t0,
            }
            return {
                "function": func_name,
                "return_value": eax,
                "return_status": ntstatus_name(eax),
                "instructions": self._insn_count,
                "elapsed_sec": elapsed,
                "state": "paused",
                "exception": None,
                "trace": list(self._trace) if show_trace else [],
                "api_calls": list(self._api_calls),
                "events": list(self.events),
                "breakpoint_hits": sum(bp.hit_count for bp in
                                       self._breakpoints.values()),
            }

        # Cleanup hooks
        for h in self._hooks:
            try:
                uc.hook_del(h)
            except Exception:
                pass
        self._hooks.clear()

        self.state = DebugState.STOPPED

        return {
            "function": func_name,
            "args": list(args),
            "return_value": eax,
            "return_status": ntstatus_name(eax),
            "instructions": self._insn_count,
            "elapsed_sec": elapsed,
            "exception": exception_msg or self._stop_reason or None,
            "trace": list(self._trace) if show_trace else [],
            "api_calls": list(self._api_calls),
            "events": list(self.events),
            "breakpoint_hits": sum(bp.hit_count for bp in self._breakpoints.values()),
            "pre_return_snapshot": self._pre_return_snapshot,
        }

    # ----------------------------------------------------------- hooks

    def _hook_code(self, uc, address, size, user_data):
        self._insn_count += 1

        # Instruction limit
        if self._insn_count > self._max_instructions:
            self._stop_reason = f"Instruction limit ({self._max_instructions})"
            uc.emu_stop()
            return

        # Spin loop detection
        self._block_hits[address] = self._block_hits.get(address, 0) + 1
        if self._block_hits[address] > _SPIN_THRESHOLD:
            self._stop_reason = (f"Spin loop at 0x{address:08X} "
                                 f"({self._block_hits[address]} hits)")
            self._raise_event(DebugEvent(
                event_type="spin_loop",
                address=address,
                message=self._stop_reason))
            uc.emu_stop()
            return

        # Breakpoint check
        bp = self._breakpoints.get(address)
        if bp and bp.enabled:
            bp.hit_count += 1

            # Conditional breakpoint
            if bp.condition:
                try:
                    regs = self._get_regs(uc)
                    if not eval(bp.condition, {"__builtins__": {}}, regs):
                        if bp.temporary:
                            del self._breakpoints[address]
                        return  # condition not met, continue
                except Exception:
                    pass

            self._raise_event(DebugEvent(
                event_type="breakpoint",
                address=address,
                message=f"Breakpoint hit: {bp.name}",
                details={"bp_id": bp.id, "hit_count": bp.hit_count}))

            if bp.callback:
                bp.callback(bp, self._get_regs(uc))

            if bp.temporary:
                del self._breakpoints[address]

            if self.on_breakpoint:
                self.on_breakpoint(bp, self._get_regs(uc))

            # Pause execution at breakpoint
            self._pause(f"Breakpoint: {bp.name}")
            uc.emu_stop()
            return

        # Exception-raising function interception (ExRaiseStatus etc.)
        if address in self._exception_func_addrs:
            self._intercept_exception_raise(uc, address)
            return

        # Import stub hook
        if address in self.env._stub_hooks:
            dll_name, func_name = self.env._stub_hooks[address]
            full_name = f"{dll_name}!{func_name}"
            self._handle_stub_call(uc, full_name, address)
            return

        # Trace recording
        if len(self._trace) < 100000:
            try:
                code = bytes(uc.mem_read(address, min(size, 15)))
                insns = list(self.env.cs.disasm(code, address, count=1))
                if insns:
                    insn = insns[0]
                    self._trace.append({
                        "address": address,
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "size": size,
                    })
                    # Capture state at leave/pop ebp (pre-epilogue, stack still intact)
                    if insn.mnemonic == "leave" or (
                            insn.mnemonic == "pop" and insn.op_str == "ebp"):
                        regs = self._get_regs(uc)
                        func_info = self.env.find_function_at(address)
                        regs["eip_name"] = (f"{func_info[1]}!{func_info[0]}"
                                            if func_info else f"0x{address:08X}")
                        try:
                            frames = self.get_call_stack()
                        except Exception:
                            frames = []
                        try:
                            stack_entries = self.inspect_stack(depth=16)
                        except Exception:
                            stack_entries = []
                        self._pre_return_snapshot = {
                            "regs": regs,
                            "call_stack": frames,
                            "stack_memory": stack_entries,
                        }
                    # Also capture at ret as fallback if no leave/pop ebp was seen
                    elif insn.mnemonic == "ret" and self._pre_return_snapshot is None:
                        regs = self._get_regs(uc)
                        func_info = self.env.find_function_at(address)
                        regs["eip_name"] = (f"{func_info[1]}!{func_info[0]}"
                                            if func_info else f"0x{address:08X}")
                        try:
                            frames = self.get_call_stack()
                        except Exception:
                            frames = []
                        try:
                            stack_entries = self.inspect_stack(depth=16)
                        except Exception:
                            stack_entries = []
                        self._pre_return_snapshot = {
                            "regs": regs,
                            "call_stack": frames,
                            "stack_memory": stack_entries,
                        }
            except Exception:
                pass

    # --------------------------------------------------------- exception interception

    def _resolve_exception_funcs(self):
        """Resolve addresses of exception-raising functions for interception."""
        self._exception_func_addrs.clear()
        for name in ("ExRaiseStatus", "RtlRaiseStatus"):
            result = self.env.resolve_function(name)
            if result:
                self._exception_func_addrs[result[0]] = name

    def _intercept_exception_raise(self, uc, address):
        """
        Intercept ExRaiseStatus / RtlRaiseStatus at entry.
        Reads the NTSTATUS arg, unwinds the SEH chain, sets EAX,
        and cleanly terminates execution with the exception status.
        """
        esp = uc.reg_read(UC_X86_REG_ESP)
        func_name = self._exception_func_addrs.get(address, "ExRaiseStatus")

        # Read NTSTATUS argument ([ESP+4], first arg after return address)
        try:
            ntstatus = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
        except Exception:
            ntstatus = 0xC0000001  # STATUS_UNSUCCESSFUL

        # Record event
        self._raise_event(DebugEvent(
            event_type="exception",
            address=address,
            message=f"{func_name}(0x{ntstatus:08X}) — {ntstatus_name(ntstatus)} — SEH unwind",
            details={"ntstatus": ntstatus}))

        # Capture pre-exception snapshot for the report
        regs = self._get_regs(uc)
        func_info = self.env.find_function_at(address)
        regs["eip_name"] = (f"{func_info[1]}!{func_info[0]}"
                            if func_info else f"0x{address:08X}")
        try:
            frames = self.get_call_stack()
        except Exception:
            frames = []
        try:
            stack_entries = self.inspect_stack(depth=16)
        except Exception:
            stack_entries = []
        self._pre_return_snapshot = {
            "regs": regs,
            "call_stack": frames,
            "stack_memory": stack_entries,
        }

        # SEH unwind: walk fs:[0] to restore the nearest handler frame
        try:
            seh_ptr = struct.unpack('<I',
                bytes(uc.mem_read(KPCR_BASE, 4)))[0]  # fs:[0]

            if seh_ptr not in (0xFFFFFFFF, 0):
                next_seh = struct.unpack('<I',
                    bytes(uc.mem_read(seh_ptr, 4)))[0]
                # Restore fs:[0] to next handler (unwind this SEH level)
                uc.mem_write(KPCR_BASE, struct.pack('<I', next_seh))
                # Standard __except_handler3 frame: EBP = seh_ptr + 0x10
                frame_ebp = seh_ptr + 0x10
                uc.reg_write(UC_X86_REG_EBP, frame_ebp)
                uc.reg_write(UC_X86_REG_ESP, frame_ebp + 4)
        except Exception:
            pass

        # Set return value to the exception NTSTATUS and stop
        uc.reg_write(UC_X86_REG_EAX, ntstatus)
        uc.emu_stop()

    def _handle_stub_call(self, uc, api_name, stub_addr):
        """Handle a call to an unresolved import stub."""
        # Read args from stack
        esp = uc.reg_read(UC_X86_REG_ESP)
        args = []
        for i in range(8):
            try:
                val = struct.unpack('<I', bytes(uc.mem_read(esp + 4 + i * 4, 4)))[0]
                args.append(val)
            except Exception:
                args.append(0)

        # Try mock first
        try:
            ret = self.mocks.dispatch(api_name, args)
        except _DebugException:
            raise
        except Exception:
            ret = STATUS_SUCCESS

        uc.reg_write(UC_X86_REG_EAX, ret & 0xFFFFFFFF)
        self._api_calls.append({
            "name": api_name,
            "args": args[:4],
            "return": ret,
            "address": stub_addr,
        })

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory access — auto-map or report."""
        page = address & ~0xFFF

        # Report potential null pointer dereference
        if address < 0x10000:
            self._raise_event(DebugEvent(
                event_type="null_deref",
                address=address,
                message=f"Near-NULL memory access at 0x{address:08X} "
                        f"(size={size}, value=0x{value:X})"))

        try:
            uc.mem_map(page, _PAGE)
            uc.mem_write(page, b'\x00' * _PAGE)
            return True
        except Exception:
            self._stop_reason = f"Unmapped memory at 0x{address:08X}"
            uc.emu_stop()
            return False

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped code fetch — likely a missing module."""
        # Check if this looks like a module base
        mod = self.env.find_module_at(address)
        if not mod:
            # This is fetching code from an unmapped area — likely a missing DLL
            self._raise_event(DebugEvent(
                event_type="missing_module",
                address=address,
                message=f"Code fetch from unmapped memory 0x{address:08X} — "
                        f"likely a missing module or invalid call target"))

            # Try to load the module if we can identify it
            if self.on_missing_module:
                path = self.on_missing_module("?", f"0x{address:08X}")
                if path and os.path.isfile(path):
                    self.env.load_module(path)
                    return True

        page = address & ~0xFFF
        try:
            uc.mem_map(page, _PAGE)
            uc.mem_write(page, b'\xCC' * _PAGE)  # INT3 fill
            return True
        except Exception:
            self._stop_reason = f"Unmapped code fetch at 0x{address:08X}"
            uc.emu_stop()
            return False

    def _hook_interrupt(self, uc, intno, user_data):
        if intno == 3:  # INT3 — breakpoint
            eip = uc.reg_read(UC_X86_REG_EIP)
            self._raise_event(DebugEvent(
                event_type="breakpoint",
                address=eip,
                message=f"INT3 at 0x{eip:08X}"))
            uc.emu_stop()
        elif intno == 0x2E:  # syscall
            pass
        else:
            eip = uc.reg_read(UC_X86_REG_EIP)
            self._raise_event(DebugEvent(
                event_type="exception",
                address=eip,
                message=f"Interrupt {intno} at 0x{eip:08X}"))
            uc.emu_stop()

    # ----------------------------------------------------------- stepping

    def step(self) -> Optional[dict]:
        """Execute one instruction and return state."""
        if self.state != DebugState.PAUSED:
            return None

        uc = self.env.uc
        eip = uc.reg_read(UC_X86_REG_EIP)

        # Check if we've returned to the sled (function completed)
        if eip == self.env._ret_sled:
            self._cleanup_hooks()
            self.state = DebugState.STOPPED
            return {"state": "completed",
                    "return_value": uc.reg_read(UC_X86_REG_EAX)}

        self.state = DebugState.RUNNING
        try:
            uc.emu_start(eip, self.env._ret_sled, count=1)
        except Exception as e:
            return {"error": str(e)}

        # After step, pause again (unless a breakpoint already paused us)
        if self.state == DebugState.RUNNING:
            new_eip = uc.reg_read(UC_X86_REG_EIP)
            if new_eip == self.env._ret_sled:
                self._cleanup_hooks()
                self.state = DebugState.STOPPED
                return {"state": "completed",
                        "return_value": uc.reg_read(UC_X86_REG_EAX)}
            self._pause("single step")

        return self.inspect_registers()

    def continue_run(self) -> Optional[dict]:
        """Continue execution from PAUSED state until next breakpoint or end."""
        if self.state != DebugState.PAUSED:
            return None

        uc = self.env.uc
        eip = uc.reg_read(UC_X86_REG_EIP)

        # If paused at a breakpoint, single-step past it first so we don't
        # re-trigger the same breakpoint immediately.
        bp = self._breakpoints.get(eip)
        if bp and bp.enabled:
            bp.enabled = False
            self.state = DebugState.RUNNING
            try:
                uc.emu_start(eip, self.env._ret_sled, count=1)
            except Exception:
                pass
            bp.enabled = True
            eip = uc.reg_read(UC_X86_REG_EIP)
            # Check if function completed during that single step
            if eip == self.env._ret_sled:
                self._cleanup_hooks()
                self.state = DebugState.STOPPED
                rs = self._run_state or {}
                return {
                    "function": rs.get("func_name", "?"),
                    "return_value": uc.reg_read(UC_X86_REG_EAX),
                    "return_status": ntstatus_name(uc.reg_read(UC_X86_REG_EAX)),
                    "instructions": self._insn_count,
                    "elapsed_sec": 0,
                    "state": "completed",
                    "exception": None,
                    "trace": list(self._trace) if rs.get("show_trace") else [],
                    "api_calls": list(self._api_calls),
                    "events": list(self.events),
                }

        self.state = DebugState.RUNNING
        t0 = time.perf_counter()
        exception_msg = None

        try:
            uc.emu_start(eip, self.env._ret_sled, timeout=60_000_000)
        except Exception as e:
            exception_msg = str(e)

        elapsed = time.perf_counter() - t0
        eax = uc.reg_read(UC_X86_REG_EAX)

        if self.state == DebugState.PAUSED:
            # Hit another breakpoint
            return {
                "state": "paused",
                "return_value": eax,
                "instructions": self._insn_count,
                "elapsed_sec": elapsed,
                "events": list(self.events),
            }

        self._cleanup_hooks()
        self.state = DebugState.STOPPED
        rs = self._run_state or {}
        return {
            "function": rs.get("func_name", "?"),
            "return_value": eax,
            "return_status": ntstatus_name(eax),
            "instructions": self._insn_count,
            "elapsed_sec": elapsed,
            "state": "completed",
            "exception": exception_msg or self._stop_reason or None,
            "trace": list(self._trace) if rs.get("show_trace") else [],
            "api_calls": list(self._api_calls),
            "events": list(self.events),
        }

    def _cleanup_hooks(self):
        """Remove all Unicorn hooks."""
        uc = self.env.uc
        for h in self._hooks:
            try:
                uc.hook_del(h)
            except Exception:
                pass
        self._hooks.clear()

    def close(self):
        """Clean up hooks and reset state.  Call when done with this session."""
        self._cleanup_hooks()
        self._breakpoints.clear()
        self.state = DebugState.STOPPED

    def _pause(self, reason: str):
        self.state = DebugState.PAUSED
        self._pause_reason = reason

    # ----------------------------------------------------------- inspection

    def inspect_registers(self) -> dict:
        """Get all CPU registers."""
        uc = self.env.uc
        regs = self._get_regs(uc)
        eip = regs["eip"]

        # Annotate EIP with module!function
        func_info = self.env.find_function_at(eip)
        if func_info:
            regs["eip_name"] = f"{func_info[1]}!{func_info[0]}"
        else:
            regs["eip_name"] = f"0x{eip:08X}"

        return regs

    def _get_regs(self, uc) -> dict:
        return {
            "eax": uc.reg_read(UC_X86_REG_EAX),
            "ebx": uc.reg_read(UC_X86_REG_EBX),
            "ecx": uc.reg_read(UC_X86_REG_ECX),
            "edx": uc.reg_read(UC_X86_REG_EDX),
            "esi": uc.reg_read(UC_X86_REG_ESI),
            "edi": uc.reg_read(UC_X86_REG_EDI),
            "ebp": uc.reg_read(UC_X86_REG_EBP),
            "esp": uc.reg_read(UC_X86_REG_ESP),
            "eip": uc.reg_read(UC_X86_REG_EIP),
            "eflags": uc.reg_read(UC_X86_REG_EFLAGS),
        }

    def inspect_memory(self, address: int, size: int = 0x100) -> bytes:
        """Read raw memory."""
        try:
            return bytes(self.env.uc.mem_read(address, size))
        except Exception:
            return b""

    def inspect_stack(self, depth: int = 16) -> List[dict]:
        """Dump stack entries from ESP upward."""
        uc = self.env.uc
        esp = uc.reg_read(UC_X86_REG_ESP)
        entries = []

        for i in range(depth):
            addr = esp + i * 4
            try:
                val = struct.unpack('<I', bytes(uc.mem_read(addr, 4)))[0]
                func_info = self.env.find_function_at(val)
                entries.append({
                    "offset": i * 4,
                    "address": addr,
                    "value": val,
                    "symbol": f"{func_info[1]}!{func_info[0]}" if func_info else "",
                })
            except Exception:
                break

        return entries

    def get_call_stack(self) -> List[StackFrame]:
        """Reconstruct call stack by walking EBP chain."""
        uc = self.env.uc
        ebp = uc.reg_read(UC_X86_REG_EBP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        frames = []
        seen = set()

        # Current frame
        func_info = self.env.find_function_at(eip)
        mod = self.env.find_module_at(eip)
        frames.append(StackFrame(
            return_address=eip,
            frame_pointer=ebp,
            module=mod.name if mod else "",
            function=func_info[0] if func_info else f"0x{eip:08X}",
        ))

        # Walk EBP chain
        while ebp and ebp not in seen and len(frames) < 64:
            seen.add(ebp)
            try:
                next_ebp = struct.unpack('<I', bytes(uc.mem_read(ebp, 4)))[0]
                ret_addr = struct.unpack('<I', bytes(uc.mem_read(ebp + 4, 4)))[0]
            except Exception:
                break

            if ret_addr == 0 or ret_addr == self.env._ret_sled:
                break

            func_info = self.env.find_function_at(ret_addr)
            mod = self.env.find_module_at(ret_addr)
            frames.append(StackFrame(
                return_address=ret_addr,
                frame_pointer=next_ebp,
                module=mod.name if mod else "",
                function=func_info[0] if func_info else f"0x{ret_addr:08X}",
            ))

            ebp = next_ebp

        return frames

    # ----------------------------------------------------------- disassembly

    def disassemble_function(self, target: str, max_call_depth: int = 8) -> List[dict]:
        """Disassemble a function and all called functions recursively.

        Returns list of dicts, each representing a disassembled function:
        {
            'name': str, 'module': str, 'address': int,
            'instructions': [{'address': int, 'size': int,
                               'mnemonic': str, 'op_str': str,
                               'bytes': bytes, 'call_target': int|None,
                               'call_name': str|None}]
        }
        """
        # Resolve target
        if isinstance(target, str):
            result = self.env.resolve_function(target)
            if result is None:
                raise ValueError(f"Cannot resolve function: {target}")
            addr = result[0]
        else:
            addr = target

        results = []
        visited = set()
        queue = [(addr, target if isinstance(target, str) else None, 0)]

        while queue:
            func_addr, func_name, depth = queue.pop(0)
            if func_addr in visited:
                continue
            visited.add(func_addr)

            # Check if this address is in an import stub — skip disassembly
            if hasattr(self.env, '_stub_base') and self.env._stub_base:
                stub_end = getattr(self.env, '_stub_ptr', self.env._stub_base)
                if self.env._stub_base <= func_addr < stub_end:
                    continue

            # Find containing module
            mod = self.env.find_module_at(func_addr)
            if not mod:
                continue

            # Resolve name if not known
            if not func_name:
                fi = self.env.find_function_at(func_addr)
                func_name = fi[0] if fi else f"sub_{func_addr:08X}"

            # Disassemble from function start
            instructions = []
            try:
                # Read up to 16KB of code from the function start
                max_size = 0x4000
                # Don't read past module end
                mod_end = mod.image_base + mod.image_size
                read_size = min(max_size, mod_end - func_addr)
                if read_size <= 0:
                    continue
                code = bytes(self.env.uc.mem_read(func_addr, read_size))
            except Exception:
                continue

            # Disassemble until ret or end
            for insn in self.env.cs.disasm(code, func_addr):
                call_target = None
                call_name = None

                # Detect call targets
                if insn.mnemonic == 'call':
                    # Try to parse immediate call target from op_str
                    op = insn.op_str.strip()
                    if op.startswith('0x') or op.startswith('0X'):
                        try:
                            call_target = int(op, 16)
                        except ValueError:
                            pass

                    if call_target:
                        fi = self.env.find_function_at(call_target)
                        if fi:
                            call_name = f"{fi[1]}!{fi[0]}"
                        else:
                            call_name = f"sub_{call_target:08X}"
                        # Queue for recursive disassembly
                        if depth < max_call_depth and call_target not in visited:
                            queue.append((call_target, fi[0] if fi else None, depth + 1))

                instructions.append({
                    'address': insn.address,
                    'size': insn.size,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': bytes(insn.bytes),
                    'call_target': call_target,
                    'call_name': call_name,
                })

                # Stop at ret/retn
                if insn.mnemonic in ('ret', 'retn', 'retf'):
                    break
                # Stop at int3 (padding)
                if insn.mnemonic == 'int3':
                    break
                # Stop at jmp to another function (tail call) — but not short jumps
                if insn.mnemonic == 'jmp' and insn.op_str.strip().startswith('0x'):
                    try:
                        jmp_target = int(insn.op_str.strip(), 16)
                        # If jumping far away (>4KB), likely a tail call
                        if abs(jmp_target - func_addr) > 0x1000:
                            if depth < max_call_depth and jmp_target not in visited:
                                fi = self.env.find_function_at(jmp_target)
                                queue.append((jmp_target, fi[0] if fi else None, depth + 1))
                            break
                    except ValueError:
                        pass

            if instructions:
                results.append({
                    'name': func_name,
                    'module': mod.name if mod else '???',
                    'address': func_addr,
                    'instructions': instructions,
                })

        # Sort by address for stable display
        results.sort(key=lambda r: r['address'])
        return results

    # ----------------------------------------------------------- events

    def _raise_event(self, event: DebugEvent):
        """Record an event and notify callback."""
        self.events.append(event)
        if self.on_event:
            self.on_event(event)

    # ----------------------------------------------------------- formatting

    def format_result(self, result: dict, show_trace: bool = False) -> str:
        """Format a run result into a readable report."""
        func = result.get('function', '?')
        args = result.get('args', [])
        args_str = ', '.join(f'0x{a:X}' for a in args) if args else '(none)'
        lines = [
            "═" * 72,
            "  LIVE KERNEL DEBUG REPORT",
            f"  Function: {func}",
            f"  Args: {args_str}",
            f"  Return: 0x{result.get('return_value', 0):08X} "
            f"({result.get('return_status', '?')})",
            f"  Instructions: {result.get('instructions', 0)}",
            f"  Time: {result.get('elapsed_sec', 0):.3f}s",
            "═" * 72,
        ]

        if result.get('exception'):
            lines.append(f"\n  ⚠️  Exception: {result['exception']}")

        # Events
        events = result.get('events', [])
        if not events:
            lines.append("\n  Debug Events: none")
        if events:
            lines.append(f"\n  Debug Events ({len(events)}):")
            lines.append(f"  {'─' * 60}")
            for ev in events[:50]:
                icon = {
                    "breakpoint": "🔴",
                    "error": "❌",
                    "missing_module": "📦",
                    "exception": "⚡",
                    "null_deref": "⚠️",
                    "invalid_call": "🚫",
                    "spin_loop": "🔄",
                }.get(ev.event_type, "•")
                lines.append(f"    {icon} [{ev.event_type}] {ev.message}")
                if ev.address:
                    ev_func = self.env.find_function_at(ev.address)
                    if ev_func:
                        lines.append(f"       at {ev_func[1]}!{ev_func[0]}")

        # API calls summary
        api_calls = result.get('api_calls', [])
        if not api_calls:
            lines.append("\n  API Calls: none (no external stubs hit)")
        if api_calls:
            lines.append(f"\n  API Calls ({len(api_calls)}):")
            seen = {}
            for call in api_calls:
                name = call.get('name', '?').split('!')[-1]
                seen[name] = seen.get(name, 0) + 1
            for fn, cnt in list(seen.items())[:20]:
                lines.append(f"    {fn} (x{cnt})")

        # Execution trace
        if show_trace and result.get('trace'):
            trace = result['trace']
            lines.append(f"\n  Execution Trace ({len(trace)} entries):")
            lines.append(f"    {'VA':<12}| {'Instruction':<40}")
            lines.append(f"    {'-' * 11}+{'-' * 40}")
            for t in trace:
                instr = f"{t['mnemonic']} {t['op_str']}".strip()
                tag = ""
                if t['mnemonic'] == "ret":
                    tag = "  <-- RETURN"
                elif t['mnemonic'].startswith("j") and t['mnemonic'] != "jmp":
                    tag = "  <-- BRANCH"
                elif t['mnemonic'] == "call":
                    tag = "  <-- CALL"
                lines.append(f"    0x{t['address']:08X} | {instr}{tag}")

        # Use pre-return snapshot if available (captured at last ret instruction)
        snap = result.get('pre_return_snapshot')

        # ── Final registers ──────────────────────────────────────────────
        try:
            regs = snap['regs'] if snap else self.inspect_registers()
            lines.append("\n  Final Registers (before epilogue):")
            lines.append(f"  {'─' * 60}")
            reg_names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
            row = "   "
            for i, rn in enumerate(reg_names):
                row += f" {rn.upper()}=0x{regs.get(rn, 0):08X}"
                if (i + 1) % 4 == 0:
                    lines.append(row)
                    row = "   "
            if row.strip():
                lines.append(row)
            # Use original function name if the resolved name is an offset approx
            eip_name = regs.get("eip_name", "")
            if eip_name and '+' in eip_name and func != '?':
                # The resolved name is e.g. PoShutdownBugCheck+0x19A8 — show both
                lines.append(f"    EIP → {func} (nearest export: {eip_name})")
            elif eip_name:
                lines.append(f"    EIP → {eip_name}")
        except Exception:
            pass

        # ── Call stack ────────────────────────────────────────────────────
        try:
            frames = snap['call_stack'] if snap else self.get_call_stack()
            if frames:
                lines.append(f"\n  Call Stack ({len(frames)} frames):")
                lines.append(f"  {'─' * 60}")
                for i, fr in enumerate(frames):
                    mod = fr.module or "???"
                    lines.append(
                        f"    #{i:<2d}  0x{fr.return_address:08X}  "
                        f"{mod}!{fr.function}")
        except Exception:
            pass

        # ── Stack memory ──────────────────────────────────────────────────
        try:
            stack_entries = snap['stack_memory'] if snap else self.inspect_stack(depth=16)
            if stack_entries:
                lines.append(f"\n  Stack Memory (top 16 DWORDs):")
                lines.append(f"  {'─' * 60}")
                lines.append(f"    {'Offset':>6}  {'Address':<12} {'Value':<12} {'Symbol'}")
                for e in stack_entries:
                    sym = e.get('symbol', '')
                    lines.append(
                        f"    +{e['offset']:04X}   0x{e['address']:08X}  "
                        f"0x{e['value']:08X}  {sym}")
        except Exception:
            pass

        lines.append("")

        return '\n'.join(lines)

    def format_environment_info(self) -> str:
        """Format environment status for display."""
        info = self.env.get_info()
        lines = [
            "═" * 72,
            "  KERNEL ENVIRONMENT STATUS",
            "═" * 72,
            f"  System Root: {info['system_root']}",
            f"  Modules Loaded: {info['modules_loaded']}",
            f"  Available Files: {info['available_files']}",
            f"  Stack: {info['stack']}",
            f"  Heap: {info['heap']}",
            f"  KPCR: {info['kpcr']}",
            f"  System EPROCESS: {info['system_eprocess']}",
            "",
            "  Loaded Modules:",
            f"  {'Name':<25} {'Base':<14} {'Size':<14} {'Exports':>8} {'Unresolved':>11} {'Symbols':>8}",
            f"  {'-' * 25} {'-' * 14} {'-' * 14} {'-' * 8} {'-' * 11} {'-' * 8}",
        ]

        for name, minfo in info['modules'].items():
            lines.append(
                f"  {name:<25} {minfo['base']:<14} {minfo['size']:<14} "
                f"{minfo['exports']:>8} {minfo['unresolved']:>11} {minfo['symbols']:>8}")

        # List unresolved imports
        all_unresolved = []
        for mod in self.env.modules.values():
            for dll, func in mod.unresolved:
                all_unresolved.append((mod.name, dll, func))

        if all_unresolved:
            lines.append(f"\n  Unresolved Imports ({len(all_unresolved)}):")
            # Group by DLL
            by_dll = {}
            for mod_name, dll, func in all_unresolved:
                by_dll.setdefault(dll, []).append(f"{func} (needed by {mod_name})")
            for dll, funcs in sorted(by_dll.items()):
                lines.append(f"    {dll}:")
                for f in funcs[:10]:
                    lines.append(f"      • {f}")
                if len(funcs) > 10:
                    lines.append(f"      ... and {len(funcs) - 10} more")

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
#  Convenience: run from CLI or script
# ---------------------------------------------------------------------------

def quick_debug(
    system_root: str,
    func_name: str,
    args: Optional[List[int]] = None,
    load_deps: bool = True,
    show_trace: bool = False,
    breakpoints: Optional[List[str]] = None,
    progress_cb=None,
) -> str:
    """
    One-shot convenience function: load environment, run function, return report.

    >>> print(quick_debug(r"C:\\2kDEBUG", "NtPowerInformation",
    ...                   args=[0, 0, 0, 0x1000, 4]))
    """
    env = KernelEnvironment(system_root)
    env.load_core(progress_cb=progress_cb)

    if load_deps:
        missing = env.auto_load_dependencies()

    dbg = DebugSession(env)

    if breakpoints:
        for bp in breakpoints:
            try:
                dbg.set_breakpoint(bp)
            except ValueError:
                pass

    # Use heap for output buffer if args have placeholders
    if args:
        buf = env.heap_alloc(0x2000)
        args = [buf if a == 0x1000 else a for a in args]

    result = dbg.run(func_name, args=args, show_trace=show_trace)

    report = dbg.format_result(result, show_trace=show_trace)
    env_info = dbg.format_environment_info()

    env.close()

    return env_info + "\n\n" + report
