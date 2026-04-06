"""
Structure Data-Flow Analyzer
=============================
Performs register-level data-flow analysis on x86 basic blocks to:
  1. Track which registers hold pointers to known NT structures
  2. Map [reg+offset] memory accesses to actual structure field names
  3. Support multiple Windows versions (NT4 through Windows 11)

The struct database contains field layouts from public symbols (PDB)
and community reverse-engineering research.
"""

import re
from collections import defaultdict

# ============================================================================
# Multi-version NT structure database
# Key structures with fields that differ across Windows versions.
# Each entry: (offset, field_name, type, [optional size])
# Offsets are for x86 (32-bit) unless noted.
# ============================================================================

# ----------- EPROCESS -----------
EPROCESS_FIELDS = {
    # Windows 2000 SP4 (NT 5.0)
    'win2k': {
        'version': 'Windows 2000 SP4',
        'build': 2195,
        'size': 0x290,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x06C: ('ExitStatus', 'NTSTATUS'),
            0x070: ('LockEvent', 'KEVENT'),
            0x078: ('LockCount', 'ULONG'),
            0x080: ('CreateTime', 'LARGE_INTEGER'),
            0x088: ('ExitTime', 'LARGE_INTEGER'),
            0x090: ('LockOwner', 'PKTHREAD'),
            0x094: ('UniqueProcessId', 'HANDLE'),
            0x098: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x0A0: ('QuotaPeakPoolUsage[0]', 'SIZE_T'),
            0x0A4: ('QuotaPeakPoolUsage[1]', 'SIZE_T'),
            0x0A8: ('QuotaPoolUsage[0]', 'SIZE_T'),
            0x0AC: ('QuotaPoolUsage[1]', 'SIZE_T'),
            0x0B0: ('PagefileUsage', 'SIZE_T'),
            0x0B4: ('PeakPagefileUsage', 'SIZE_T'),
            0x0B8: ('CommitCharge', 'SIZE_T'),
            0x0BC: ('PeakVirtualSize', 'SIZE_T'),
            0x0C0: ('VirtualSize', 'SIZE_T'),
            0x0C4: ('SessionProcessLinks', 'LIST_ENTRY'),
            0x0CC: ('DebugPort', 'PVOID'),
            0x0D0: ('ExceptionPort', 'PVOID'),
            0x0D4: ('ObjectTable', 'PHANDLE_TABLE'),
            0x0D8: ('Token', 'EX_FAST_REF'),
            0x0DC: ('WorkingSetLock', 'FAST_MUTEX'),
            0x104: ('WorkingSetPage', 'PFN_NUMBER'),
            0x108: ('AddressCreationLock', 'FAST_MUTEX'),
            0x128: ('HyperSpaceLock', 'KSPIN_LOCK'),
            0x12C: ('ForkInProgress', 'PETHREAD'),
            0x130: ('HardwareTrigger', 'ULONG'),
            0x134: ('VadRoot', 'PMM_AVL_TABLE'),
            0x138: ('VadHint', 'PVOID'),
            0x13C: ('CloneRoot', 'PVOID'),
            0x140: ('NumberOfPrivatePages', 'PFN_NUMBER'),
            0x144: ('NumberOfLockedPages', 'PFN_NUMBER'),
            0x148: ('Win32Process', 'PVOID'),
            0x14C: ('Job', 'PEJOB'),
            0x150: ('SectionObject', 'PVOID'),
            0x154: ('SectionBaseAddress', 'PVOID'),
            0x158: ('QuotaBlock', 'PEPROCESS_QUOTA_BLOCK'),
            0x174: ('WorkingSetWatch', 'PPAGEFAULT_HISTORY'),
            0x178: ('Win32WindowStation', 'HANDLE'),
            0x17C: ('InheritedFromUniqueProcessId', 'HANDLE'),
            0x180: ('LdtInformation', 'PVOID'),
            0x184: ('VadFreeHint', 'PVOID'),
            0x188: ('VdmObjects', 'PVOID'),
            0x18C: ('DeviceMap', 'PDEVICE_MAP'),
            0x1A0: ('ImageFileName[16]', 'UCHAR[16]'),
            0x1B0: ('VmTrimFaultValue', 'ULONG'),
            0x1B4: ('SetTimerResolution', 'UCHAR'),
            0x1B8: ('PriorityClass', 'UCHAR'),
            0x1FC: ('SubSystemVersion', 'ULONG'),
            0x200: ('SubSystemMinorVersion', 'UCHAR'),
            0x204: ('Peb', 'PPEB'),
        },
    },
    # Windows XP SP3 (NT 5.1)
    'winxp': {
        'version': 'Windows XP SP3',
        'build': 2600,
        'size': 0x260,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x06C: ('ProcessLock', 'EX_PUSH_LOCK'),
            0x070: ('CreateTime', 'LARGE_INTEGER'),
            0x078: ('ExitTime', 'LARGE_INTEGER'),
            0x080: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x084: ('UniqueProcessId', 'HANDLE'),
            0x088: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x090: ('QuotaUsage[0]', 'SIZE_T'),
            0x094: ('QuotaUsage[1]', 'SIZE_T'),
            0x098: ('QuotaUsage[2]', 'SIZE_T'),
            0x09C: ('QuotaPeak[0]', 'SIZE_T'),
            0x0A0: ('QuotaPeak[1]', 'SIZE_T'),
            0x0A4: ('QuotaPeak[2]', 'SIZE_T'),
            0x0A8: ('CommitCharge', 'SIZE_T'),
            0x0AC: ('PeakVirtualSize', 'SIZE_T'),
            0x0B0: ('VirtualSize', 'SIZE_T'),
            0x0B4: ('SessionProcessLinks', 'LIST_ENTRY'),
            0x0BC: ('DebugPort', 'PVOID'),
            0x0C0: ('ExceptionPort', 'PVOID'),
            0x0C4: ('ObjectTable', 'PHANDLE_TABLE'),
            0x0C8: ('Token', 'EX_FAST_REF'),
            0x0CC: ('WorkingSetPage', 'PFN_NUMBER'),
            0x0D0: ('AddressCreationLock', 'KGUARDED_MUTEX'),
            0x0F0: ('HyperSpaceLock', 'KSPIN_LOCK'),
            0x0F4: ('ForkInProgress', 'PETHREAD'),
            0x0F8: ('HardwareTrigger', 'ULONG'),
            0x0FC: ('PhysicalVadRoot', 'PMM_AVL_TABLE'),
            0x100: ('CloneRoot', 'PVOID'),
            0x104: ('NumberOfPrivatePages', 'PFN_NUMBER'),
            0x108: ('NumberOfLockedPages', 'PFN_NUMBER'),
            0x10C: ('Win32Process', 'PVOID'),
            0x110: ('Job', 'PEJOB'),
            0x114: ('SectionObject', 'PVOID'),
            0x118: ('SectionBaseAddress', 'PVOID'),
            0x11C: ('QuotaBlock', 'PEPROCESS_QUOTA_BLOCK'),
            0x138: ('WorkingSetWatch', 'PPAGEFAULT_HISTORY'),
            0x148: ('Peb', 'PPEB'),
            0x170: ('ImageFileName[16]', 'UCHAR[16]'),
        },
    },
    # Windows Server 2003 SP2 (NT 5.2)
    'win2k3': {
        'version': 'Windows Server 2003 SP2',
        'build': 3790,
        'size': 0x278,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x078: ('ProcessLock', 'EX_PUSH_LOCK'),
            0x080: ('CreateTime', 'LARGE_INTEGER'),
            0x088: ('ExitTime', 'LARGE_INTEGER'),
            0x090: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x094: ('UniqueProcessId', 'HANDLE'),
            0x098: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x0A0: ('QuotaUsage[0]', 'SIZE_T'),
            0x0B8: ('CommitCharge', 'SIZE_T'),
            0x0D4: ('ObjectTable', 'PHANDLE_TABLE'),
            0x0D8: ('Token', 'EX_FAST_REF'),
            0x11C: ('Win32Process', 'PVOID'),
            0x120: ('Job', 'PEJOB'),
            0x124: ('SectionObject', 'PVOID'),
            0x128: ('SectionBaseAddress', 'PVOID'),
            0x154: ('Peb', 'PPEB'),
            0x174: ('ImageFileName[16]', 'UCHAR[16]'),
        },
    },
    # Windows Vista SP2 / Server 2008 (NT 6.0)
    'vista': {
        'version': 'Windows Vista SP2',
        'build': 6002,
        'size': 0x2C0,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x080: ('ProcessLock', 'EX_PUSH_LOCK'),
            0x088: ('CreateTime', 'LARGE_INTEGER'),
            0x090: ('ExitTime', 'LARGE_INTEGER'),
            0x098: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x09C: ('UniqueProcessId', 'HANDLE'),
            0x0A0: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x0C0: ('ObjectTable', 'PHANDLE_TABLE'),
            0x0C4: ('Token', 'EX_FAST_REF'),
            0x130: ('Win32Process', 'PVOID'),
            0x134: ('Job', 'PEJOB'),
            0x138: ('SectionObject', 'PVOID'),
            0x13C: ('SectionBaseAddress', 'PVOID'),
            0x16C: ('Peb', 'PPEB'),
            0x18C: ('ImageFileName[15]', 'UCHAR[15]'),
        },
    },
    # Windows 7 SP1 (NT 6.1)
    'win7': {
        'version': 'Windows 7 SP1',
        'build': 7601,
        'size': 0x2C0,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x080: ('ProcessLock', 'EX_PUSH_LOCK'),
            0x088: ('CreateTime', 'LARGE_INTEGER'),
            0x090: ('ExitTime', 'LARGE_INTEGER'),
            0x098: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x09C: ('UniqueProcessId', 'HANDLE'),
            0x0A0: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x0C4: ('ObjectTable', 'PHANDLE_TABLE'),
            0x0C8: ('Token', 'EX_FAST_REF'),
            0x134: ('Win32Process', 'PVOID'),
            0x138: ('Job', 'PEJOB'),
            0x13C: ('SectionObject', 'PVOID'),
            0x140: ('SectionBaseAddress', 'PVOID'),
            0x170: ('Peb', 'PPEB'),
            0x190: ('ImageFileName[15]', 'UCHAR[15]'),
        },
    },
    # Windows 10 21H2 (NT 10.0)
    'win10': {
        'version': 'Windows 10 21H2',
        'build': 19044,
        'size': 0x480,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x0E0: ('ProcessLock', 'EX_PUSH_LOCK'),
            0x0E8: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x0EC: ('UniqueProcessId', 'HANDLE'),
            0x0F0: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x128: ('ObjectTable', 'PHANDLE_TABLE'),
            0x12C: ('Token', 'EX_FAST_REF'),
            0x150: ('CreateTime', 'LARGE_INTEGER'),
            0x1A8: ('Win32Process', 'PVOID'),
            0x1AC: ('Job', 'PEJOB'),
            0x1B0: ('SectionObject', 'PVOID'),
            0x1B4: ('SectionBaseAddress', 'PVOID'),
            0x1EC: ('Peb', 'PPEB'),
            0x2DC: ('ImageFileName[15]', 'UCHAR[15]'),
        },
    },
    # Windows 11 (NT 10.0.22000+)
    'win11': {
        'version': 'Windows 11 22H2',
        'build': 22621,
        'size': 0x500,
        'fields': {
            0x000: ('Pcb', 'KPROCESS'),
            0x0E0: ('ProcessLock', 'EX_PUSH_LOCK'),
            0x0E8: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x0EC: ('UniqueProcessId', 'HANDLE'),
            0x0F0: ('ActiveProcessLinks', 'LIST_ENTRY'),
            0x128: ('ObjectTable', 'PHANDLE_TABLE'),
            0x12C: ('Token', 'EX_FAST_REF'),
            0x150: ('CreateTime', 'LARGE_INTEGER'),
            0x1A8: ('Win32Process', 'PVOID'),
            0x1AC: ('Job', 'PEJOB'),
            0x1B0: ('SectionObject', 'PVOID'),
            0x1B4: ('SectionBaseAddress', 'PVOID'),
            0x1EC: ('Peb', 'PPEB'),
            0x2E4: ('ImageFileName[15]', 'UCHAR[15]'),
        },
    },
}

# ----------- ETHREAD -----------
ETHREAD_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x258,
        'fields': {
            0x000: ('Tcb', 'KTHREAD'),
            0x1B0: ('CreateTime', 'LARGE_INTEGER'),
            0x1B8: ('ExitTime', 'LARGE_INTEGER'),
            0x1C0: ('ExitStatus', 'NTSTATUS'),
            0x1C4: ('PostBlockList', 'LIST_ENTRY'),
            0x1CC: ('TerminationPort', 'PTERMINATION_PORT'),
            0x1D0: ('ActiveTimerListLock', 'KSPIN_LOCK'),
            0x1D4: ('ActiveTimerListHead', 'LIST_ENTRY'),
            0x1DC: ('Cid', 'CLIENT_ID'),
            0x1E4: ('LpcReplySemaphore', 'KSEMAPHORE'),
            0x1F8: ('LpcReplyMessage', 'PVOID'),
            0x1FC: ('ImpersonationInfo', 'PPS_IMPERSONATION_INFORMATION'),
            0x200: ('IrpList', 'LIST_ENTRY'),
            0x208: ('TopLevelIrp', 'ULONG'),
            0x20C: ('DeviceToVerify', 'PDEVICE_OBJECT'),
            0x210: ('ThreadsProcess', 'PEPROCESS'),
            0x214: ('StartAddress', 'PVOID'),
            0x218: ('Win32StartAddress', 'PVOID'),
            0x21C: ('ThreadListEntry', 'LIST_ENTRY'),
            0x224: ('RundownProtect', 'EX_RUNDOWN_REF'),
            0x228: ('ThreadLock', 'EX_PUSH_LOCK'),
            0x22C: ('LpcReplyMessageId', 'ULONG'),
            0x230: ('ReadClusterSize', 'ULONG'),
            0x234: ('GrantedAccess', 'ACCESS_MASK'),
            0x238: ('CrossThreadFlags', 'ULONG'),
            0x23C: ('SameThreadPassiveFlags', 'ULONG'),
            0x240: ('SameThreadApcFlags', 'ULONG'),
            0x244: ('ForwardClusterOnly', 'UCHAR'),
            0x245: ('DisablePageFaultClustering', 'UCHAR'),
        },
    },
    'winxp': {
        'version': 'Windows XP SP3',
        'size': 0x258,
        'fields': {
            0x000: ('Tcb', 'KTHREAD'),
            0x1B0: ('CreateTime', 'LARGE_INTEGER'),
            0x1C0: ('ExitStatus', 'NTSTATUS'),
            0x1C4: ('PostBlockList', 'LIST_ENTRY'),
            0x1DC: ('Cid', 'CLIENT_ID'),
            0x210: ('ThreadsProcess', 'PEPROCESS'),
            0x214: ('StartAddress', 'PVOID'),
            0x218: ('Win32StartAddress', 'PVOID'),
            0x21C: ('ThreadListEntry', 'LIST_ENTRY'),
            0x234: ('GrantedAccess', 'ACCESS_MASK'),
            0x238: ('CrossThreadFlags', 'ULONG'),
        },
    },
    'win7': {
        'version': 'Windows 7 SP1',
        'size': 0x2B8,
        'fields': {
            0x000: ('Tcb', 'KTHREAD'),
            0x200: ('CreateTime', 'LARGE_INTEGER'),
            0x218: ('ExitStatus', 'NTSTATUS'),
            0x224: ('Cid', 'CLIENT_ID'),
            0x268: ('ThreadsProcess', 'PEPROCESS'),
            0x26C: ('StartAddress', 'PVOID'),
            0x270: ('Win32StartAddress', 'PVOID'),
            0x28C: ('CrossThreadFlags', 'ULONG'),
        },
    },
    'win10': {
        'version': 'Windows 10 21H2',
        'size': 0x480,
        'fields': {
            0x000: ('Tcb', 'KTHREAD'),
            0x2B0: ('CreateTime', 'LARGE_INTEGER'),
            0x2C8: ('ExitStatus', 'NTSTATUS'),
            0x2D4: ('Cid', 'CLIENT_ID'),
            0x318: ('ThreadsProcess', 'PEPROCESS'),
            0x31C: ('StartAddress', 'PVOID'),
            0x320: ('Win32StartAddress', 'PVOID'),
        },
    },
}

# ----------- KPROCESS (embedded at offset 0 of EPROCESS) -----------
KPROCESS_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x06C,
        'fields': {
            0x000: ('Header', 'DISPATCHER_HEADER'),
            0x010: ('ProfileListHead', 'LIST_ENTRY'),
            0x018: ('DirectoryTableBase', 'ULONG'),
            0x01C: ('LdtDescriptor', 'KGDTENTRY'),
            0x024: ('Int21Descriptor', 'KIDTENTRY'),
            0x02C: ('IopmOffset', 'USHORT'),
            0x02E: ('Iopl', 'UCHAR'),
            0x02F: ('VdmFlag', 'BOOLEAN'),
            0x030: ('ActiveProcessors', 'KAFFINITY'),
            0x034: ('KernelTime', 'ULONG'),
            0x038: ('UserTime', 'ULONG'),
            0x03C: ('ReadyListHead', 'LIST_ENTRY'),
            0x044: ('SwapListEntry', 'SINGLE_LIST_ENTRY'),
            0x048: ('ThreadListHead', 'LIST_ENTRY'),
            0x050: ('ProcessLock', 'KSPIN_LOCK'),
            0x054: ('Affinity', 'KAFFINITY'),
            0x058: ('StackCount', 'USHORT'),
            0x05A: ('BasePriority', 'SCHAR'),
            0x05B: ('ThreadQuantum', 'SCHAR'),
            0x05C: ('AutoAlignment', 'BOOLEAN'),
            0x05D: ('State', 'UCHAR'),
            0x05E: ('ThreadSeed', 'UCHAR'),
            0x05F: ('DisableBoost', 'BOOLEAN'),
            0x060: ('PowerState', 'UCHAR'),
            0x061: ('DisableQuantum', 'BOOLEAN'),
            0x064: ('IdealNode', 'UCHAR'),
            0x068: ('Flags', 'KEXECUTE_OPTIONS'),
        },
    },
    'winxp': {
        'version': 'Windows XP SP3',
        'size': 0x06C,
        'fields': {
            0x000: ('Header', 'DISPATCHER_HEADER'),
            0x010: ('ProfileListHead', 'LIST_ENTRY'),
            0x018: ('DirectoryTableBase', 'ULONG'),
            0x030: ('ActiveProcessors', 'KAFFINITY'),
            0x034: ('KernelTime', 'ULONG'),
            0x038: ('UserTime', 'ULONG'),
            0x03C: ('ReadyListHead', 'LIST_ENTRY'),
            0x048: ('ThreadListHead', 'LIST_ENTRY'),
            0x054: ('Affinity', 'KAFFINITY'),
            0x058: ('StackCount', 'USHORT'),
            0x05A: ('BasePriority', 'SCHAR'),
            0x05B: ('ThreadQuantum', 'SCHAR'),
        },
    },
}

# ----------- FILE_OBJECT -----------
FILE_OBJECT_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x070,
        'fields': {
            0x000: ('Type', 'CSHORT'),
            0x002: ('Size', 'CSHORT'),
            0x004: ('DeviceObject', 'PDEVICE_OBJECT'),
            0x008: ('Vpb', 'PVPB'),
            0x00C: ('FsContext', 'PVOID'),
            0x010: ('FsContext2', 'PVOID'),
            0x014: ('SectionObjectPointer', 'PSECTION_OBJECT_POINTERS'),
            0x018: ('PrivateCacheMap', 'PVOID'),
            0x01C: ('FinalStatus', 'NTSTATUS'),
            0x020: ('RelatedFileObject', 'PFILE_OBJECT'),
            0x024: ('LockOperation', 'BOOLEAN'),
            0x025: ('DeletePending', 'BOOLEAN'),
            0x026: ('ReadAccess', 'BOOLEAN'),
            0x027: ('WriteAccess', 'BOOLEAN'),
            0x028: ('DeleteAccess', 'BOOLEAN'),
            0x029: ('SharedRead', 'BOOLEAN'),
            0x02A: ('SharedWrite', 'BOOLEAN'),
            0x02B: ('SharedDelete', 'BOOLEAN'),
            0x02C: ('Flags', 'ULONG'),
            0x030: ('FileName', 'UNICODE_STRING'),
            0x038: ('CurrentByteOffset', 'LARGE_INTEGER'),
            0x040: ('Waiters', 'ULONG'),
            0x044: ('Busy', 'ULONG'),
            0x048: ('LastLock', 'PVOID'),
            0x04C: ('Lock', 'KEVENT'),
            0x05C: ('Event', 'KEVENT'),
            0x06C: ('CompletionContext', 'PIO_COMPLETION_CONTEXT'),
        },
    },
    # FILE_OBJECT is stable across versions (same layout XP through Win11)
    'winxp': {'version': 'Windows XP+', 'size': 0x070, 'fields': {}},
}
# XP+ reuses same layout
for _v in ('win2k3', 'vista', 'win7', 'win10', 'win11'):
    FILE_OBJECT_FIELDS[_v] = {
        'version': FILE_OBJECT_FIELDS['win2k']['version'],
        'size': 0x070,
        'fields': dict(FILE_OBJECT_FIELDS['win2k']['fields']),
    }

# ----------- SECTION_OBJECT_POINTERS -----------
SECTION_OBJECT_POINTERS_FIELDS = {
    'win2k': {
        'version': 'All versions',
        'size': 0x00C,
        'fields': {
            0x000: ('DataSectionObject', 'PVOID'),
            0x004: ('SharedCacheMap', 'PVOID'),
            0x008: ('ImageSectionObject', 'PVOID'),
        },
    },
}
for _v in ('winxp', 'win2k3', 'vista', 'win7', 'win10', 'win11'):
    SECTION_OBJECT_POINTERS_FIELDS[_v] = dict(SECTION_OBJECT_POINTERS_FIELDS['win2k'])

# ----------- SHARED_CACHE_MAP (Cc internal, Win2K) -----------
SHARED_CACHE_MAP_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x0D0,
        'fields': {
            0x000: ('NodeTypeCode', 'CSHORT'),
            0x002: ('NodeByteSize', 'CSHORT'),
            0x004: ('OpenCount', 'ULONG'),
            0x008: ('FileSize', 'LARGE_INTEGER'),
            0x010: ('BcbList', 'LIST_ENTRY'),
            0x018: ('SectionSize', 'LARGE_INTEGER'),
            0x020: ('ValidDataLength', 'LARGE_INTEGER'),
            0x028: ('ValidDataGoal', 'LARGE_INTEGER'),
            0x030: ('FilteredList', 'LIST_ENTRY'),
            0x038: ('InitialVacbs[0]', 'PVACB'),
            0x04C: ('Vacbs', 'PPVACB'),
            0x050: ('FileObject', 'PFILE_OBJECT'),
            0x054: ('ActiveVacb', 'PVACB'),
            0x058: ('NeedToZero', 'PVOID'),
            0x05C: ('NeedToZeroPage', 'ULONG'),
            0x060: ('ActivePage', 'ULONG'),
            0x064: ('ValidDataCount', 'ULONG'),
            0x068: ('VacbActiveCount', 'ULONG'),
            0x06C: ('DirtyPages', 'ULONG'),
            0x070: ('SharedCacheMapLinks', 'LIST_ENTRY'),
            0x078: ('Flags', 'ULONG'),
            0x07C: ('Status', 'NTSTATUS'),
            0x080: ('MbcbSpinLock', 'KSPIN_LOCK'),
            0x084: ('OpenCountSpinLock', 'KSPIN_LOCK'),
            0x088: ('Event', 'PKEVENT'),
            0x090: ('LazyWriteContext', 'PVOID'),
            0x094: ('PrivateList', 'LIST_ENTRY'),
            0x09C: ('LogHandle', 'PVOID'),
            0x0A0: ('FlushToLsnRoutine', 'PFLUSH_TO_LSN'),
            0x0A4: ('DirtyPageThreshold', 'ULONG'),
            0x0A8: ('LazyWritePassCount', 'ULONG'),
            0x0AC: ('UninitializeEvent', 'PCACHE_UNINITIALIZE_EVENT'),
            0x0B0: ('NeedToZeroVacb', 'PVACB'),
            0x0B4: ('BcbSpinLock', 'KSPIN_LOCK'),
            0x0B8: ('Reserved', 'PVOID'),
            0x0BC: ('Event2', 'KEVENT'),
            0x0C0: ('CreateEvent', 'PKEVENT'),
            0x0C4: ('WaitOnActiveCount', 'PFN_NUMBER'),
            0x0C8: ('SectionObjectPointers', 'PSECTION_OBJECT_POINTERS'),
        },
    },
}

# ----------- BCB (Buffer Control Block, Cc internal) -----------
BCB_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x048,
        'fields': {
            0x000: ('NodeTypeCode', 'CSHORT'),
            0x002: ('NodeByteSize', 'CSHORT'),
            0x004: ('BcbLinks', 'LIST_ENTRY'),
            0x00C: ('SharedCacheMap', 'PSHARED_CACHE_MAP'),
            0x010: ('FileOffset', 'LARGE_INTEGER'),
            0x018: ('PinCount', 'ULONG'),
            0x01C: ('MappedLength', 'ULONG'),
            0x020: ('Vacb', 'PVACB'),
            0x024: ('MappedFileOffset', 'LARGE_INTEGER'),
            0x02C: ('MappedLength2', 'ULONG'),
            0x030: ('Flags', 'ULONG'),
            0x034: ('BcbSpinLock', 'KSPIN_LOCK'),
            0x038: ('Resource', 'PERESOURCE'),
            0x03C: ('SharedCacheMapLinks', 'LIST_ENTRY'),
            0x044: ('OwnerPointer', 'PVOID'),
        },
    },
}

# ----------- ERESOURCE -----------
ERESOURCE_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x038,
        'fields': {
            0x000: ('SystemResourcesList', 'LIST_ENTRY'),
            0x008: ('OwnerTable', 'POWNER_ENTRY'),
            0x00C: ('ActiveCount', 'SHORT'),
            0x00E: ('Flag', 'USHORT'),
            0x010: ('SharedWaiters', 'PKSEMAPHORE'),
            0x014: ('ExclusiveWaiters', 'PKEVENT'),
            0x018: ('OwnerThreads[0]', 'OWNER_ENTRY'),
            0x020: ('OwnerThreads[1]', 'OWNER_ENTRY'),
            0x028: ('ContentionCount', 'ULONG'),
            0x02C: ('NumberOfSharedWaiters', 'USHORT'),
            0x02E: ('NumberOfExclusiveWaiters', 'USHORT'),
            0x030: ('Address', 'PVOID'),
            0x034: ('SpinLock', 'KSPIN_LOCK'),
        },
    },
    # Stable across XP+
    'winxp': {
        'version': 'Windows XP+',
        'size': 0x038,
        'fields': {
            0x000: ('SystemResourcesList', 'LIST_ENTRY'),
            0x008: ('OwnerTable', 'POWNER_ENTRY'),
            0x00C: ('ActiveCount', 'SHORT'),
            0x00E: ('Flag', 'USHORT'),
            0x010: ('SharedWaiters', 'PKSEMAPHORE'),
            0x014: ('ExclusiveWaiters', 'PKEVENT'),
            0x018: ('OwnerEntry', 'OWNER_ENTRY'),
            0x020: ('ActiveEntries', 'ULONG'),
            0x024: ('ContentionCount', 'ULONG'),
            0x028: ('NumberOfSharedWaiters', 'ULONG'),
            0x02C: ('NumberOfExclusiveWaiters', 'ULONG'),
            0x030: ('Address', 'PVOID'),
            0x034: ('SpinLock', 'KSPIN_LOCK'),
        },
    },
}

# ----------- LOOKASIDE_LIST (ExAllocateFrom/FreeToPagedLookasideList) -----------
GENERAL_LOOKASIDE_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x060,
        'fields': {
            0x000: ('ListHead', 'SLIST_HEADER'),
            0x008: ('Depth', 'USHORT'),
            0x00A: ('MaximumDepth', 'USHORT'),
            0x00C: ('TotalAllocates', 'ULONG'),
            0x010: ('AllocateMisses', 'ULONG'),
            0x014: ('TotalFrees', 'ULONG'),
            0x018: ('FreeMisses', 'ULONG'),
            0x01C: ('Type', 'POOL_TYPE'),
            0x020: ('Tag', 'ULONG'),
            0x024: ('Size', 'ULONG'),
            0x028: ('Allocate', 'PALLOCATE_FUNCTION'),
            0x02C: ('Free', 'PFREE_FUNCTION'),
            0x030: ('ListEntry', 'LIST_ENTRY'),
            0x038: ('LastTotalAllocates', 'ULONG'),
            0x03C: ('LastAllocateMisses', 'ULONG'),
            0x040: ('Future[0]', 'ULONG'),
            0x048: ('Reserved', 'ULONG'),
        },
    },
}

# ----------- IRP (I/O Request Packet) -----------
IRP_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x070,
        'fields': {
            0x000: ('Type', 'CSHORT'),
            0x002: ('Size', 'USHORT'),
            0x004: ('MdlAddress', 'PMDL'),
            0x008: ('Flags', 'ULONG'),
            0x00C: ('AssociatedIrp', 'union'),
            0x010: ('ThreadListEntry', 'LIST_ENTRY'),
            0x018: ('IoStatus', 'IO_STATUS_BLOCK'),
            0x020: ('RequestorMode', 'KPROCESSOR_MODE'),
            0x021: ('PendingReturned', 'BOOLEAN'),
            0x022: ('StackCount', 'CHAR'),
            0x023: ('CurrentLocation', 'CHAR'),
            0x024: ('Cancel', 'BOOLEAN'),
            0x025: ('CancelIrql', 'KIRQL'),
            0x026: ('ApcEnvironment', 'CCHAR'),
            0x027: ('AllocationFlags', 'UCHAR'),
            0x028: ('UserIosb', 'PIO_STATUS_BLOCK'),
            0x02C: ('UserEvent', 'PKEVENT'),
            0x030: ('Overlay', 'union'),
            0x038: ('CancelRoutine', 'PDRIVER_CANCEL'),
            0x03C: ('UserBuffer', 'PVOID'),
            0x040: ('Tail', 'union'),
        },
    },
}

# ----------- DEVICE_OBJECT -----------
DEVICE_OBJECT_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x0B8,
        'fields': {
            0x000: ('Type', 'CSHORT'),
            0x002: ('Size', 'USHORT'),
            0x004: ('ReferenceCount', 'LONG'),
            0x008: ('DriverObject', 'PDRIVER_OBJECT'),
            0x00C: ('NextDevice', 'PDEVICE_OBJECT'),
            0x010: ('AttachedDevice', 'PDEVICE_OBJECT'),
            0x014: ('CurrentIrp', 'PIRP'),
            0x018: ('Timer', 'PIO_TIMER'),
            0x01C: ('Flags', 'ULONG'),
            0x020: ('Characteristics', 'ULONG'),
            0x024: ('Vpb', 'PVPB'),
            0x028: ('DeviceExtension', 'PVOID'),
            0x02C: ('DeviceType', 'DEVICE_TYPE'),
            0x030: ('StackSize', 'CCHAR'),
            0x034: ('Queue', 'union'),
            0x058: ('AlignmentRequirement', 'ULONG'),
            0x05C: ('DeviceQueue', 'KDEVICE_QUEUE'),
            0x074: ('Dpc', 'KDPC'),
            0x094: ('ActiveThreadCount', 'ULONG'),
            0x098: ('SecurityDescriptor', 'PSECURITY_DESCRIPTOR'),
            0x09C: ('DeviceLock', 'KEVENT'),
            0x0AC: ('SectorSize', 'USHORT'),
            0x0AE: ('Spare1', 'USHORT'),
            0x0B0: ('DeviceObjectExtension', 'PDEVOBJ_EXTENSION'),
            0x0B4: ('Reserved', 'PVOID'),
        },
    },
}

# ----------- POOL_HEADER (executive pool allocations) -----------
POOL_HEADER_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x008,
        'fields': {
            0x000: ('PreviousSize:9', 'USHORT (bits)'),
            0x000: ('PoolIndex:7', 'USHORT (bits)'),
            0x002: ('BlockSize:9', 'USHORT (bits)'),
            0x002: ('PoolType:7', 'USHORT (bits)'),
            0x004: ('PoolTag', 'ULONG'),
        },
    },
}

# ----------- FAST_MUTEX -----------
FAST_MUTEX_FIELDS = {
    'win2k': {
        'version': 'All versions',
        'size': 0x020,
        'fields': {
            0x000: ('Count', 'LONG'),
            0x004: ('Owner', 'PKTHREAD'),
            0x008: ('Contention', 'ULONG'),
            0x00C: ('Event', 'KEVENT'),
            0x01C: ('OldIrql', 'ULONG'),
        },
    },
}

# ----------- DISPATCHER_HEADER -----------
DISPATCHER_HEADER_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x010,
        'fields': {
            0x000: ('Type', 'UCHAR'),
            0x001: ('Absolute', 'UCHAR'),
            0x002: ('Size', 'UCHAR'),
            0x003: ('Inserted', 'UCHAR'),
            0x004: ('SignalState', 'LONG'),
            0x008: ('WaitListHead', 'LIST_ENTRY'),
        },
    },
}

# ----------- HANDLE_TABLE -----------
HANDLE_TABLE_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x05C,
        'fields': {
            0x000: ('TableCode', 'ULONG'),
            0x004: ('QuotaProcess', 'PEPROCESS'),
            0x008: ('UniqueProcessId', 'HANDLE'),
            0x00C: ('HandleTableLock[0]', 'EX_PUSH_LOCK'),
            0x010: ('HandleTableList', 'LIST_ENTRY'),
            0x018: ('HandleContentionEvent', 'EX_PUSH_LOCK'),
            0x01C: ('DebugInfo', 'PHANDLE_TRACE_DEBUG_INFO'),
            0x020: ('ExtraInfoPages', 'LONG'),
            0x024: ('FirstFree', 'ULONG'),
            0x028: ('LastFree', 'ULONG'),
            0x02C: ('NextHandleNeedingPool', 'ULONG'),
            0x030: ('HandleCount', 'LONG'),
            0x034: ('Flags', 'ULONG'),
            0x049: ('StrictFIFO', 'BOOLEAN'),
        },
    },
}

# ----------- KTHREAD (partial, key fields) -----------
KTHREAD_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x1B0,
        'fields': {
            0x000: ('Header', 'DISPATCHER_HEADER'),
            0x018: ('InitialStack', 'PVOID'),
            0x01C: ('StackLimit', 'PVOID'),
            0x020: ('Teb', 'PVOID'),
            0x024: ('TlsArray', 'PVOID'),
            0x028: ('KernelStack', 'PVOID'),
            0x02C: ('DebugActive', 'BOOLEAN'),
            0x02D: ('State', 'UCHAR'),
            0x02E: ('Alerted[0]', 'BOOLEAN'),
            0x030: ('Iopl', 'UCHAR'),
            0x031: ('NpxState', 'UCHAR'),
            0x032: ('Saturation', 'SCHAR'),
            0x033: ('Priority', 'SCHAR'),
            0x034: ('ApcState', 'KAPC_STATE'),
            0x04C: ('ContextSwitches', 'ULONG'),
            0x050: ('WaitStatus', 'NTSTATUS'),
            0x054: ('WaitIrql', 'KIRQL'),
            0x055: ('WaitMode', 'KPROCESSOR_MODE'),
            0x056: ('WaitNext', 'BOOLEAN'),
            0x057: ('WaitReason', 'UCHAR'),
            0x058: ('WaitBlockList', 'PKWAIT_BLOCK'),
            0x060: ('WaitTime', 'ULONG'),
            0x064: ('BasePriority', 'SCHAR'),
            0x066: ('DecrementCount', 'UCHAR'),
            0x067: ('PriorityDecrement', 'SCHAR'),
            0x068: ('Quantum', 'SCHAR'),
            0x06C: ('KernelApcDisable', 'LONG'),
            0x070: ('UserAffinity', 'KAFFINITY'),
            0x074: ('SystemAffinityActive', 'BOOLEAN'),
            0x078: ('ApcStateIndex', 'UCHAR'),
            0x07C: ('IdealProcessor', 'UCHAR'),
            0x080: ('ApcStatePointer[0]', 'PKAPC_STATE'),
            0x088: ('SavedApcState', 'KAPC_STATE'),
            0x0A0: ('Alertable', 'BOOLEAN'),
            0x0A4: ('Affinity', 'KAFFINITY'),
            0x0AC: ('Timer', 'KTIMER'),
            0x0D4: ('WaitListEntry', 'LIST_ENTRY'),
            0x0EC: ('Queue', 'PKQUEUE'),
            0x100: ('ServiceTable', 'PVOID'),
            0x134: ('PreviousMode', 'KPROCESSOR_MODE'),
            0x137: ('Preempted', 'BOOLEAN'),
            0x138: ('ProcessReadyQueue', 'BOOLEAN'),
            0x13C: ('Process', 'PKPROCESS'),
        },
    },
}

# ----------- PEB (partial, key fields across versions) -----------
PEB_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0x1E8,
        'fields': {
            0x002: ('BeingDebugged', 'BOOLEAN'),
            0x008: ('ImageBaseAddress', 'PVOID'),
            0x00C: ('Ldr', 'PPEB_LDR_DATA'),
            0x010: ('ProcessParameters', 'PRTL_USER_PROCESS_PARAMETERS'),
            0x018: ('ProcessHeap', 'PVOID'),
            0x01C: ('FastPebLock', 'PRTL_CRITICAL_SECTION'),
            0x030: ('SystemReserved', 'ULONG'),
            0x068: ('NtGlobalFlag', 'ULONG'),
            0x0A4: ('OSMajorVersion', 'ULONG'),
            0x0A8: ('OSMinorVersion', 'ULONG'),
            0x0AC: ('OSBuildNumber', 'USHORT'),
            0x1D4: ('SessionId', 'ULONG'),
        },
    },
    'winxp': {
        'version': 'Windows XP SP3',
        'size': 0x230,
        'fields': {
            0x002: ('BeingDebugged', 'BOOLEAN'),
            0x008: ('ImageBaseAddress', 'PVOID'),
            0x00C: ('Ldr', 'PPEB_LDR_DATA'),
            0x010: ('ProcessParameters', 'PRTL_USER_PROCESS_PARAMETERS'),
            0x018: ('ProcessHeap', 'PVOID'),
            0x068: ('NtGlobalFlag', 'ULONG'),
            0x0A4: ('OSMajorVersion', 'ULONG'),
            0x0A8: ('OSMinorVersion', 'ULONG'),
            0x1D4: ('SessionId', 'ULONG'),
        },
    },
    'win10': {
        'version': 'Windows 10',
        'size': 0x7C8,
        'fields': {
            0x002: ('BeingDebugged', 'BOOLEAN'),
            0x008: ('ImageBaseAddress', 'PVOID'),
            0x00C: ('Ldr', 'PPEB_LDR_DATA'),
            0x010: ('ProcessParameters', 'PRTL_USER_PROCESS_PARAMETERS'),
            0x018: ('ProcessHeap', 'PVOID'),
            0x0BC: ('NtGlobalFlag', 'ULONG'),
            0x0A4: ('OSMajorVersion', 'ULONG'),
            0x0A8: ('OSMinorVersion', 'ULONG'),
            0x2C0: ('SessionId', 'ULONG'),
        },
    },
}

# ----------- TEB (partial, key fields) -----------
TEB_FIELDS = {
    'win2k': {
        'version': 'Windows 2000 SP4',
        'size': 0xF88,
        'fields': {
            0x000: ('NtTib.ExceptionList', 'PEXCEPTION_REGISTRATION_RECORD'),
            0x004: ('NtTib.StackBase', 'PVOID'),
            0x008: ('NtTib.StackLimit', 'PVOID'),
            0x018: ('NtTib.Self', 'PNT_TIB'),
            0x020: ('ClientId.UniqueProcess', 'HANDLE'),
            0x024: ('ClientId.UniqueThread', 'HANDLE'),
            0x030: ('ProcessEnvironmentBlock', 'PPEB'),
            0x034: ('LastErrorValue', 'ULONG'),
            0x040: ('TlsSlots[0]', 'PVOID'),
            0x0C4: ('RealClientId', 'CLIENT_ID'),
            0x134: ('PreviousMode', 'ULONG'),
        },
    },
}

# ============================================================================
# Master struct registry — maps struct name to per-version field database
# ============================================================================

STRUCT_DB = {
    'EPROCESS':                  EPROCESS_FIELDS,
    'ETHREAD':                   ETHREAD_FIELDS,
    'KPROCESS':                  KPROCESS_FIELDS,
    'KTHREAD':                   KTHREAD_FIELDS,
    'FILE_OBJECT':               FILE_OBJECT_FIELDS,
    'SECTION_OBJECT_POINTERS':   SECTION_OBJECT_POINTERS_FIELDS,
    'SHARED_CACHE_MAP':          SHARED_CACHE_MAP_FIELDS,
    'BCB':                       BCB_FIELDS,
    'ERESOURCE':                 ERESOURCE_FIELDS,
    'GENERAL_LOOKASIDE':         GENERAL_LOOKASIDE_FIELDS,
    'IRP':                       IRP_FIELDS,
    'DEVICE_OBJECT':             DEVICE_OBJECT_FIELDS,
    'POOL_HEADER':               POOL_HEADER_FIELDS,
    'FAST_MUTEX':                FAST_MUTEX_FIELDS,
    'DISPATCHER_HEADER':         DISPATCHER_HEADER_FIELDS,
    'HANDLE_TABLE':              HANDLE_TABLE_FIELDS,
    'PEB':                       PEB_FIELDS,
    'TEB':                       TEB_FIELDS,
}

# Ordered version keys (oldest → newest) for fallback resolution
VERSION_ORDER = ['win2k', 'winxp', 'win2k3', 'vista', 'win7', 'win10', 'win11']

VERSION_LABELS = {
    'win2k':  'Windows 2000',
    'winxp':  'Windows XP',
    'win2k3': 'Windows Server 2003',
    'vista':  'Windows Vista',
    'win7':   'Windows 7',
    'win10':  'Windows 10',
    'win11':  'Windows 11',
}


def lookup_field(struct_name, offset, version='win2k'):
    """
    Look up a field name given a struct name and offset.
    Falls back to nearest version if exact version lacks the field.
    Returns (field_name, field_type) or None.
    """
    db = STRUCT_DB.get(struct_name)
    if not db:
        return None

    # Try exact version first
    ver_data = db.get(version)
    if ver_data and offset in ver_data['fields']:
        return ver_data['fields'][offset]

    # Fallback: try versions from most-similar outward
    idx = VERSION_ORDER.index(version) if version in VERSION_ORDER else 0
    for dist in range(1, len(VERSION_ORDER)):
        for candidate_idx in (idx - dist, idx + dist):
            if 0 <= candidate_idx < len(VERSION_ORDER):
                vk = VERSION_ORDER[candidate_idx]
                ver_data = db.get(vk)
                if ver_data and offset in ver_data['fields']:
                    return ver_data['fields'][offset]
    return None


def lookup_field_all_structs(offset, version='win2k'):
    """
    Given an offset, check ALL struct databases and return all possible
    matches: list of (struct_name, field_name, field_type).
    """
    matches = []
    for sname, db in STRUCT_DB.items():
        result = lookup_field(sname, offset, version)
        if result:
            matches.append((sname, result[0], result[1]))
    return matches


# ============================================================================
# Heuristic register → struct mapping for NT kernel functions
# ============================================================================

# Common patterns: if a function accesses fs:[0] or fs:[0x124], the resulting
# register typically holds KTHREAD/TEB.  If a Cc* function receives FileObject
# in first arg (typically [ebp+8]), and then loads SectionObjectPointer from
# [reg+0x14], the next load is SECTION_OBJECT_POINTERS, etc.

# These heuristic "pointer chain" rules describe common NT kernel idioms.
# Format: (source_struct, source_offset, target_struct)
# Meaning: if reg holds source_struct and you load [reg+source_offset],
#          the result register holds target_struct.
POINTER_CHAINS = [
    ('FILE_OBJECT',        0x014, 'SECTION_OBJECT_POINTERS'),
    ('SECTION_OBJECT_POINTERS', 0x004, 'SHARED_CACHE_MAP'),
    ('SHARED_CACHE_MAP',   0x050, 'FILE_OBJECT'),
    ('SHARED_CACHE_MAP',   0x070, 'SHARED_CACHE_MAP'),  # Links
    ('EPROCESS',           0x0D4, 'HANDLE_TABLE'),
    ('EPROCESS',           0x000, 'KPROCESS'),    # embedded
    ('ETHREAD',            0x000, 'KTHREAD'),      # embedded
    ('ETHREAD',            0x210, 'EPROCESS'),    # ThreadsProcess (win2k)
    ('KTHREAD',            0x034, 'KAPC_STATE'),
    ('KTHREAD',            0x13C, 'KPROCESS'),    # Process
    ('DEVICE_OBJECT',      0x008, 'DRIVER_OBJECT'),
    ('DEVICE_OBJECT',      0x028, 'PVOID'),       # DeviceExtension
    ('IRP',                0x004, 'MDL'),
    ('BCB',                0x00C, 'SHARED_CACHE_MAP'),
    ('BCB',                0x038, 'ERESOURCE'),
]

# Special TEB/KPCR access patterns
FS_SEGMENT_MAP = {
    # fs:[offset] → (struct, field_name)
    0x000: ('TEB', 'NtTib.ExceptionList'),
    0x004: ('TEB', 'NtTib.StackBase'),
    0x008: ('TEB', 'NtTib.StackLimit'),
    0x018: ('TEB', 'NtTib.Self'),
    0x020: ('TEB', 'ClientId.UniqueProcess'),
    0x024: ('TEB', 'ClientId.UniqueThread'),
    0x030: ('TEB', 'ProcessEnvironmentBlock'),
    0x034: ('TEB', 'LastErrorValue'),
    0x124: ('KPCR', 'PrcbData.CurrentThread → KTHREAD'),
    0x134: ('KTHREAD', 'PreviousMode'),
    0x138: ('KTHREAD', 'ProcessReadyQueue'),
    0x13C: ('KTHREAD', 'Process → KPROCESS'),
    0x140: ('KTHREAD', 'NextProcessor'),
    0x148: ('KTHREAD', 'CallbackStack'),
    0x1B8: ('KTHREAD', 'Teb'),
}


# ============================================================================
# Data-flow analysis engine
# ============================================================================

_REG_OFFSET_RE = re.compile(
    r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]'
)
_FS_ACCESS_RE = re.compile(
    r'(?:dword\s+ptr\s+)?fs:\[(0x[0-9a-fA-F]+|\d+)\]'
)
_MOV_REG_REG_RE = re.compile(
    r'^(e[abcds][xip]|esi|edi)\s*,\s*(e[abcds][xip]|esi|edi)$'
)
_LEA_RE = re.compile(
    r'^(e[abcds][xip]|esi|edi)\s*,\s*\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]$'
)


def _parse_offset(s):
    """Parse an offset string ('0x1c' or '28') to int."""
    s = s.strip()
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s)


def analyze_struct_accesses(blocks, func_name='', version='win2k'):
    """
    Perform data-flow analysis on basic blocks to identify structure field
    accesses.

    Args:
        blocks: dict of {addr: BasicBlock} from behavior_analyzer
        func_name: function name (used for heuristic hints)
        version: Windows version key for struct field lookup

    Returns:
        list of StructAccess objects, each containing:
          - offset: the raw offset accessed
          - register: which register held the base pointer
          - struct_name: identified structure name (or None)
          - field_name: identified field name (or None)
          - field_type: identified field type (or None)
          - instruction: the raw instruction text
          - confidence: 'high', 'medium', 'low'
    """
    # reg_state: maps register name → (struct_name, confidence)
    reg_state = {}
    accesses = []

    # Heuristic: Cc* functions typically get FileObject in first arg
    fn_lower = func_name.lower()
    if fn_lower.startswith('cc'):
        # CcXxx functions: first param is usually FileObject or SharedCacheMap
        reg_state['_arg1'] = ('FILE_OBJECT', 'medium')
    elif fn_lower.startswith(('nt', 'zw')):
        pass  # syscall stubs, args vary
    elif fn_lower.startswith('ex'):
        # ExXxxResource: first param often PERESOURCE
        if 'resource' in fn_lower:
            reg_state['_arg1'] = ('ERESOURCE', 'medium')
        elif 'lookaside' in fn_lower:
            reg_state['_arg1'] = ('GENERAL_LOOKASIDE', 'medium')
    elif fn_lower.startswith('io'):
        if 'device' in fn_lower:
            reg_state['_arg1'] = ('DEVICE_OBJECT', 'medium')
        elif 'irp' in fn_lower:
            reg_state['_arg1'] = ('IRP', 'medium')
    elif fn_lower.startswith('ob'):
        pass
    elif fn_lower.startswith('ps'):
        if 'process' in fn_lower:
            reg_state['_arg1'] = ('EPROCESS', 'medium')
        elif 'thread' in fn_lower:
            reg_state['_arg1'] = ('ETHREAD', 'medium')

    # Sort blocks by address for sequential analysis
    sorted_addrs = sorted(blocks.keys())

    for addr in sorted_addrs:
        block = blocks[addr]
        for mnem, op in block.instructions:
            op_stripped = op.strip()

            # 1) Detect fs:[offset] accesses (TEB/KPCR)
            fs_m = _FS_ACCESS_RE.search(op_stripped)
            if fs_m and mnem in ('mov', 'cmp', 'test', 'push'):
                fs_ofs = _parse_offset(fs_m.group(1))
                if fs_ofs in FS_SEGMENT_MAP:
                    sname, fname = FS_SEGMENT_MAP[fs_ofs]
                    accesses.append(StructAccess(
                        offset=fs_ofs, register='fs',
                        struct_name=sname, field_name=fname,
                        field_type='', instruction=f'{mnem} {op_stripped}',
                        confidence='high'
                    ))
                    # If loading into a register, track it
                    if mnem == 'mov':
                        dst_parts = op_stripped.split(',')
                        if dst_parts:
                            dst = dst_parts[0].strip()
                            if dst in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
                                # fs:[0x124] → KTHREAD pointer
                                if fs_ofs == 0x124:
                                    reg_state[dst] = ('KTHREAD', 'high')
                                elif fs_ofs == 0x13C:
                                    reg_state[dst] = ('KPROCESS', 'high')
                                elif fs_ofs == 0x030:
                                    reg_state[dst] = ('PEB', 'high')
                continue

            # 2) Handle mov reg, reg (propagate struct type)
            if mnem == 'mov':
                mrr = _MOV_REG_REG_RE.match(op_stripped)
                if mrr:
                    dst, src = mrr.group(1), mrr.group(2)
                    if src in reg_state:
                        reg_state[dst] = reg_state[src]
                    elif dst in reg_state:
                        # Loading something unknown clobbers it
                        del reg_state[dst]
                    continue

            # 3) Handle mov reg, [ebp+N] for first few args
            if mnem in ('mov', 'lea') and 'ebp' in op_stripped:
                parts = op_stripped.split(',')
                if len(parts) == 2:
                    dst = parts[0].strip()
                    m = _REG_OFFSET_RE.search(parts[1])
                    if m and m.group(1) == 'ebp':
                        ofs = _parse_offset(m.group(2))
                        if ofs == 0x08 and '_arg1' in reg_state:
                            if dst in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
                                reg_state[dst] = reg_state['_arg1']
                        elif ofs == 0x0C and '_arg2' in reg_state:
                            if dst in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
                                reg_state[dst] = reg_state['_arg2']
                        continue

            # 4) Handle lea reg, [reg+offset] (sub-struct pointer)
            if mnem == 'lea':
                lea_m = _LEA_RE.match(op_stripped)
                if lea_m:
                    dst = lea_m.group(1)
                    src_reg = lea_m.group(2)
                    ofs = _parse_offset(lea_m.group(3))
                    if src_reg in reg_state:
                        src_struct, conf = reg_state[src_reg]
                        # Check pointer chain: lea into sub-struct
                        for chain_src, chain_ofs, chain_dst in POINTER_CHAINS:
                            if chain_src == src_struct and chain_ofs == ofs:
                                reg_state[dst] = (chain_dst, 'medium')
                                break
                        # Also record as a field access
                        result = lookup_field(src_struct, ofs, version)
                        if result:
                            accesses.append(StructAccess(
                                offset=ofs, register=src_reg,
                                struct_name=src_struct, field_name=result[0],
                                field_type=result[1],
                                instruction=f'{mnem} {op_stripped}',
                                confidence=conf
                            ))
                    continue

            # 5) Detect [reg+offset] in mov/cmp/push/etc instructions
            m = _REG_OFFSET_RE.search(op_stripped)
            if m:
                base_reg = m.group(1)
                ofs = _parse_offset(m.group(2))

                # Skip ebp-relative (stack frame)
                if base_reg == 'ebp':
                    continue
                # Skip esp-relative (stack)
                if base_reg == 'esp':
                    continue

                struct_name = None
                field_name = None
                field_type = None
                confidence = 'low'

                if base_reg in reg_state:
                    struct_name, conf = reg_state[base_reg]
                    result = lookup_field(struct_name, ofs, version)
                    if result:
                        field_name, field_type = result
                        confidence = conf
                    else:
                        confidence = 'low'

                # If no known struct in register, try all structs
                if not field_name:
                    candidates = lookup_field_all_structs(ofs, version)
                    if len(candidates) == 1:
                        struct_name, field_name, field_type = candidates[0]
                        confidence = 'low'
                    elif candidates:
                        # Multiple matches — record first but low confidence
                        struct_name, field_name, field_type = candidates[0]
                        confidence = 'low'

                accesses.append(StructAccess(
                    offset=ofs, register=base_reg,
                    struct_name=struct_name, field_name=field_name,
                    field_type=field_type,
                    instruction=f'{mnem} {op_stripped}',
                    confidence=confidence
                ))

                # Track pointer chains: if loading from a known struct field
                # that points to another struct
                if mnem == 'mov' and struct_name:
                    parts = op_stripped.split(',')
                    if parts:
                        dst = parts[0].strip()
                        if dst in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
                            for chain_src, chain_ofs, chain_dst in POINTER_CHAINS:
                                if chain_src == struct_name and chain_ofs == ofs:
                                    reg_state[dst] = (chain_dst, 'medium')
                                    break

    return accesses


class StructAccess:
    """Represents a single identified structure field access."""
    __slots__ = ('offset', 'register', 'struct_name', 'field_name',
                 'field_type', 'instruction', 'confidence')

    def __init__(self, offset, register, struct_name, field_name,
                 field_type, instruction, confidence):
        self.offset = offset
        self.register = register
        self.struct_name = struct_name
        self.field_name = field_name
        self.field_type = field_type
        self.instruction = instruction
        self.confidence = confidence

    def __repr__(self):
        if self.struct_name and self.field_name:
            return f'{self.struct_name}.{self.field_name} (0x{self.offset:X}) [{self.confidence}]'
        return f'[{self.register}+0x{self.offset:X}] [{self.confidence}]'


def summarize_accesses(accesses, version='win2k'):
    """
    Summarize struct accesses into a compact display format.
    Groups by struct, deduplicates, sorts by offset.

    Returns: dict of struct_name → list of (offset, field_name, field_type, count)
    """
    # Group by (struct_name, offset, field_name)
    counter = defaultdict(int)
    info = {}
    for a in accesses:
        if a.struct_name and a.field_name:
            key = (a.struct_name, a.offset, a.field_name)
            counter[key] += 1
            info[key] = a.field_type

    result = defaultdict(list)
    for (sname, ofs, fname), cnt in sorted(counter.items(), key=lambda x: (x[0][0], x[0][1])):
        ftype = info[(sname, ofs, fname)]
        result[sname].append((ofs, fname, ftype, cnt))

    return dict(result)


def format_struct_accesses(accesses, version='win2k'):
    """
    Format struct accesses for display.
    Returns a multi-line string showing identified structures and fields.
    """
    summary = summarize_accesses(accesses, version)
    if not summary:
        return ''

    lines = []
    for sname in sorted(summary.keys()):
        fields = summary[sname]
        lines.append(f'  {sname}:')
        for ofs, fname, ftype, cnt in fields:
            freq = f' (×{cnt})' if cnt > 1 else ''
            lines.append(f'    +0x{ofs:03X} {fname:<40s} {ftype}{freq}')
    return '\n'.join(lines)


def get_supported_versions():
    """Return list of supported Windows version keys."""
    return list(VERSION_ORDER)


def get_version_label(version_key):
    """Return human-readable name for a version key."""
    return VERSION_LABELS.get(version_key, version_key)
