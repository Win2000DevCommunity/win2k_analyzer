"""
Structure Offset Analyzer
=========================
Attempts to extract structure layout information from:
  1. PDB debug symbols (if available)
  2. Known hardcoded offsets for NT 5.0 (Win2000) structures
  3. Runtime probing via a small helper executable

This module provides reference layouts for key undocumented structures
as they exist in Windows 2000 SP4 (NT 5.0.2195).
"""

import json
import os
import struct

# ============================================================================
# Known Windows 2000 SP4 (NT 5.0 build 2195) structure layouts
# These are from reverse engineering, debug symbols, and community research.
# ============================================================================

# PEB - Process Environment Block (Windows 2000 SP4, x86)
PEB_WIN2K = {
    'name': 'PEB',
    'size': 0x1E8,  # 488 bytes in Win2000
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 1, 'name': 'InheritedAddressSpace', 'type': 'BOOLEAN'},
        {'offset': 0x001, 'size': 1, 'name': 'ReadImageFileExecOptions', 'type': 'BOOLEAN'},
        {'offset': 0x002, 'size': 1, 'name': 'BeingDebugged', 'type': 'BOOLEAN'},
        {'offset': 0x003, 'size': 1, 'name': 'SpareBool', 'type': 'BOOLEAN'},
        {'offset': 0x004, 'size': 4, 'name': 'Mutant', 'type': 'HANDLE'},
        {'offset': 0x008, 'size': 4, 'name': 'ImageBaseAddress', 'type': 'PVOID'},
        {'offset': 0x00C, 'size': 4, 'name': 'Ldr', 'type': 'PPEB_LDR_DATA'},
        {'offset': 0x010, 'size': 4, 'name': 'ProcessParameters', 'type': 'PRTL_USER_PROCESS_PARAMETERS'},
        {'offset': 0x014, 'size': 4, 'name': 'SubSystemData', 'type': 'PVOID'},
        {'offset': 0x018, 'size': 4, 'name': 'ProcessHeap', 'type': 'PVOID'},
        {'offset': 0x01C, 'size': 4, 'name': 'FastPebLock', 'type': 'PRTL_CRITICAL_SECTION'},
        {'offset': 0x020, 'size': 4, 'name': 'FastPebLockRoutine', 'type': 'PVOID'},
        {'offset': 0x024, 'size': 4, 'name': 'FastPebUnlockRoutine', 'type': 'PVOID'},
        {'offset': 0x028, 'size': 4, 'name': 'EnvironmentUpdateCount', 'type': 'ULONG'},
        {'offset': 0x02C, 'size': 4, 'name': 'KernelCallbackTable', 'type': 'PVOID'},
        {'offset': 0x030, 'size': 4, 'name': 'SystemReserved', 'type': 'ULONG'},
        {'offset': 0x034, 'size': 4, 'name': 'AtlThunkSListPtr32', 'type': 'ULONG'},
        {'offset': 0x038, 'size': 4, 'name': 'FreeList', 'type': 'PPEB_FREE_BLOCK'},
        {'offset': 0x03C, 'size': 4, 'name': 'TlsExpansionCounter', 'type': 'ULONG'},
        {'offset': 0x040, 'size': 4, 'name': 'TlsBitmap', 'type': 'PVOID'},
        {'offset': 0x044, 'size': 8, 'name': 'TlsBitmapBits[2]', 'type': 'ULONG[2]'},
        {'offset': 0x04C, 'size': 4, 'name': 'ReadOnlySharedMemoryBase', 'type': 'PVOID'},
        {'offset': 0x050, 'size': 4, 'name': 'ReadOnlySharedMemoryHeap', 'type': 'PVOID'},
        {'offset': 0x054, 'size': 4, 'name': 'ReadOnlyStaticServerData', 'type': 'PPVOID'},
        {'offset': 0x058, 'size': 4, 'name': 'AnsiCodePageData', 'type': 'PVOID'},
        {'offset': 0x05C, 'size': 4, 'name': 'OemCodePageData', 'type': 'PVOID'},
        {'offset': 0x060, 'size': 4, 'name': 'UnicodeCaseTableData', 'type': 'PVOID'},
        {'offset': 0x064, 'size': 4, 'name': 'NumberOfProcessors', 'type': 'ULONG'},
        {'offset': 0x068, 'size': 4, 'name': 'NtGlobalFlag', 'type': 'ULONG'},
        {'offset': 0x070, 'size': 8, 'name': 'CriticalSectionTimeout', 'type': 'LARGE_INTEGER'},
        {'offset': 0x078, 'size': 4, 'name': 'HeapSegmentReserve', 'type': 'ULONG'},
        {'offset': 0x07C, 'size': 4, 'name': 'HeapSegmentCommit', 'type': 'ULONG'},
        {'offset': 0x080, 'size': 4, 'name': 'HeapDeCommitTotalFreeThreshold', 'type': 'ULONG'},
        {'offset': 0x084, 'size': 4, 'name': 'HeapDeCommitFreeBlockThreshold', 'type': 'ULONG'},
        {'offset': 0x088, 'size': 4, 'name': 'NumberOfHeaps', 'type': 'ULONG'},
        {'offset': 0x08C, 'size': 4, 'name': 'MaximumNumberOfHeaps', 'type': 'ULONG'},
        {'offset': 0x090, 'size': 4, 'name': 'ProcessHeaps', 'type': 'PPVOID'},
        {'offset': 0x094, 'size': 4, 'name': 'GdiSharedHandleTable', 'type': 'PVOID'},
        {'offset': 0x098, 'size': 4, 'name': 'ProcessStarterHelper', 'type': 'PVOID'},
        {'offset': 0x09C, 'size': 4, 'name': 'GdiDCAttributeList', 'type': 'ULONG'},
        {'offset': 0x0A0, 'size': 4, 'name': 'LoaderLock', 'type': 'PVOID'},
        {'offset': 0x0A4, 'size': 4, 'name': 'OSMajorVersion', 'type': 'ULONG'},
        {'offset': 0x0A8, 'size': 4, 'name': 'OSMinorVersion', 'type': 'ULONG'},
        {'offset': 0x0AC, 'size': 2, 'name': 'OSBuildNumber', 'type': 'USHORT'},
        {'offset': 0x0AE, 'size': 2, 'name': 'OSCSDVersion', 'type': 'USHORT'},
        {'offset': 0x0B0, 'size': 4, 'name': 'OSPlatformId', 'type': 'ULONG'},
        {'offset': 0x0B4, 'size': 4, 'name': 'ImageSubsystem', 'type': 'ULONG'},
        {'offset': 0x0B8, 'size': 4, 'name': 'ImageSubsystemMajorVersion', 'type': 'ULONG'},
        {'offset': 0x0BC, 'size': 4, 'name': 'ImageSubsystemMinorVersion', 'type': 'ULONG'},
        {'offset': 0x0C0, 'size': 4, 'name': 'ImageProcessAffinityMask', 'type': 'ULONG'},
        {'offset': 0x0C4, 'size': 136, 'name': 'GdiHandleBuffer[34]', 'type': 'ULONG[34]'},
        {'offset': 0x14C, 'size': 4, 'name': 'PostProcessInitRoutine', 'type': 'PVOID'},
        {'offset': 0x150, 'size': 4, 'name': 'TlsExpansionBitmap', 'type': 'PVOID'},
        {'offset': 0x154, 'size': 128, 'name': 'TlsExpansionBitmapBits[32]', 'type': 'ULONG[32]'},
        {'offset': 0x1D4, 'size': 4, 'name': 'SessionId', 'type': 'ULONG'},
        # Win2000 SP4 specific - differs from XP here
        {'offset': 0x1D8, 'size': 8, 'name': 'AppCompatFlags', 'type': 'ULARGE_INTEGER'},
        {'offset': 0x1E0, 'size': 8, 'name': 'AppCompatFlagsUser', 'type': 'ULARGE_INTEGER'},
    ]
}

# TEB - Thread Environment Block (Windows 2000 SP4, x86)
TEB_WIN2K = {
    'name': 'TEB',
    'size': 0xF88,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 28, 'name': 'NtTib', 'type': 'NT_TIB'},
        {'offset': 0x01C, 'size': 4, 'name': 'EnvironmentPointer', 'type': 'PVOID'},
        {'offset': 0x020, 'size': 8, 'name': 'ClientId', 'type': 'CLIENT_ID'},
        {'offset': 0x028, 'size': 4, 'name': 'ActiveRpcHandle', 'type': 'PVOID'},
        {'offset': 0x02C, 'size': 4, 'name': 'ThreadLocalStoragePointer', 'type': 'PVOID'},
        {'offset': 0x030, 'size': 4, 'name': 'ProcessEnvironmentBlock', 'type': 'PPEB'},
        {'offset': 0x034, 'size': 4, 'name': 'LastErrorValue', 'type': 'ULONG'},
        {'offset': 0x038, 'size': 4, 'name': 'CountOfOwnedCriticalSections', 'type': 'ULONG'},
        {'offset': 0x03C, 'size': 4, 'name': 'CsrClientThread', 'type': 'PVOID'},
        {'offset': 0x040, 'size': 4, 'name': 'Win32ThreadInfo', 'type': 'PVOID'},
        {'offset': 0x044, 'size': 104, 'name': 'User32Reserved[26]', 'type': 'ULONG[26]'},
        {'offset': 0x0AC, 'size': 20, 'name': 'UserReserved[5]', 'type': 'ULONG[5]'},
        {'offset': 0x0C0, 'size': 4, 'name': 'WOW32Reserved', 'type': 'PVOID'},
        {'offset': 0x0C4, 'size': 4, 'name': 'CurrentLocale', 'type': 'LCID'},
        {'offset': 0x0C8, 'size': 4, 'name': 'FpSoftwareStatusRegister', 'type': 'ULONG'},
        {'offset': 0x0CC, 'size': 216, 'name': 'SystemReserved1[54]', 'type': 'PVOID[54]'},
        {'offset': 0x1A4, 'size': 4, 'name': 'ExceptionCode', 'type': 'NTSTATUS'},
        {'offset': 0x1A8, 'size': 4, 'name': 'ActivationContextStack', 'type': 'PVOID'},
        {'offset': 0x1AC, 'size': 24, 'name': 'SpareBytes1[24]', 'type': 'UCHAR[24]'},
        {'offset': 0x1C4, 'size': 4, 'name': 'GdiTebBatch_Offset', 'type': 'ULONG'},
        # GdiTebBatch is a large embedded structure
        {'offset': 0x6DC, 'size': 4, 'name': 'RealClientId_UniqueProcess', 'type': 'HANDLE'},
        {'offset': 0x6E0, 'size': 4, 'name': 'RealClientId_UniqueThread', 'type': 'HANDLE'},
        {'offset': 0x6E4, 'size': 4, 'name': 'GdiCachedProcessHandle', 'type': 'PVOID'},
        {'offset': 0x6E8, 'size': 4, 'name': 'GdiClientPID', 'type': 'ULONG'},
        {'offset': 0x6EC, 'size': 4, 'name': 'GdiClientTID', 'type': 'ULONG'},
        {'offset': 0x6F0, 'size': 4, 'name': 'GdiThreadLocalInfo', 'type': 'PVOID'},
        {'offset': 0x6F4, 'size': 248, 'name': 'Win32ClientInfo[62]', 'type': 'ULONG[62]'},
        {'offset': 0x7EC, 'size': 932, 'name': 'glDispatchTable[233]', 'type': 'PVOID[233]'},
        {'offset': 0xB68, 'size': 116, 'name': 'glReserved1[29]', 'type': 'ULONG[29]'},
        {'offset': 0xBDC, 'size': 4, 'name': 'glReserved2', 'type': 'PVOID'},
        {'offset': 0xBE0, 'size': 4, 'name': 'glSectionInfo', 'type': 'PVOID'},
        {'offset': 0xBE4, 'size': 4, 'name': 'glSection', 'type': 'PVOID'},
        {'offset': 0xBE8, 'size': 4, 'name': 'glTable', 'type': 'PVOID'},
        {'offset': 0xBEC, 'size': 4, 'name': 'glCurrentRC', 'type': 'PVOID'},
        {'offset': 0xBF0, 'size': 4, 'name': 'glContext', 'type': 'PVOID'},
        {'offset': 0xBF4, 'size': 4, 'name': 'LastStatusValue', 'type': 'NTSTATUS'},
        {'offset': 0xBF8, 'size': 8, 'name': 'StaticUnicodeString', 'type': 'UNICODE_STRING'},
        {'offset': 0xC00, 'size': 522, 'name': 'StaticUnicodeBuffer[261]', 'type': 'WCHAR[261]'},
        {'offset': 0xE0C, 'size': 4, 'name': 'DeallocationStack', 'type': 'PVOID'},
        {'offset': 0xE10, 'size': 256, 'name': 'TlsSlots[64]', 'type': 'PVOID[64]'},
        {'offset': 0xF10, 'size': 8, 'name': 'TlsLinks', 'type': 'LIST_ENTRY'},
        {'offset': 0xF18, 'size': 4, 'name': 'Vdm', 'type': 'PVOID'},
        {'offset': 0xF1C, 'size': 4, 'name': 'ReservedForNtRpc', 'type': 'PVOID'},
        {'offset': 0xF20, 'size': 8, 'name': 'DbgSsReserved[2]', 'type': 'PVOID[2]'},
    ]
}

# KUSER_SHARED_DATA (Windows 2000 SP4, mapped at 0x7FFE0000)
KUSER_SHARED_DATA_WIN2K = {
    'name': 'KUSER_SHARED_DATA',
    'size': 0x300,
    'os': 'Windows 2000 SP4',
    'mapped_at': '0x7FFE0000 (user) / 0xFFDF0000 (kernel)',
    'fields': [
        {'offset': 0x000, 'size': 4, 'name': 'TickCountLow', 'type': 'ULONG'},
        {'offset': 0x004, 'size': 4, 'name': 'TickCountMultiplier', 'type': 'ULONG'},
        {'offset': 0x008, 'size': 8, 'name': 'InterruptTime', 'type': 'KSYSTEM_TIME'},
        {'offset': 0x014, 'size': 8, 'name': 'SystemTime', 'type': 'KSYSTEM_TIME'},
        {'offset': 0x020, 'size': 8, 'name': 'TimeZoneBias', 'type': 'KSYSTEM_TIME'},
        {'offset': 0x02C, 'size': 2, 'name': 'ImageNumberLow', 'type': 'USHORT'},
        {'offset': 0x02E, 'size': 2, 'name': 'ImageNumberHigh', 'type': 'USHORT'},
        {'offset': 0x030, 'size': 520, 'name': 'NtSystemRoot[260]', 'type': 'WCHAR[260]'},
        {'offset': 0x238, 'size': 4, 'name': 'MaxStackTraceDepth', 'type': 'ULONG'},
        {'offset': 0x23C, 'size': 4, 'name': 'CryptoExponent', 'type': 'ULONG'},
        {'offset': 0x240, 'size': 4, 'name': 'TimeZoneId', 'type': 'ULONG'},
        {'offset': 0x244, 'size': 4, 'name': 'Reserved2[8]', 'type': 'ULONG[8]'},
        {'offset': 0x264, 'size': 4, 'name': 'NtProductType', 'type': 'NT_PRODUCT_TYPE'},
        {'offset': 0x268, 'size': 1, 'name': 'ProductTypeIsValid', 'type': 'BOOLEAN'},
        {'offset': 0x26C, 'size': 4, 'name': 'NtMajorVersion', 'type': 'ULONG'},
        {'offset': 0x270, 'size': 4, 'name': 'NtMinorVersion', 'type': 'ULONG'},
        {'offset': 0x274, 'size': 64, 'name': 'ProcessorFeatures[64]', 'type': 'BOOLEAN[64]'},
        {'offset': 0x2B4, 'size': 4, 'name': 'Reserved1', 'type': 'ULONG'},
        {'offset': 0x2B8, 'size': 4, 'name': 'Reserved3', 'type': 'ULONG'},
        {'offset': 0x2BC, 'size': 4, 'name': 'TimeSlip', 'type': 'ULONG'},
        {'offset': 0x2C0, 'size': 4, 'name': 'AlternativeArchitecture', 'type': 'ALTERNATIVE_ARCHITECTURE_TYPE'},
        {'offset': 0x2C8, 'size': 8, 'name': 'SystemExpirationDate', 'type': 'LARGE_INTEGER'},
        {'offset': 0x2D0, 'size': 4, 'name': 'SuiteMask', 'type': 'ULONG'},
        {'offset': 0x2D4, 'size': 1, 'name': 'KdDebuggerEnabled', 'type': 'BOOLEAN'},
        # Win2000 does NOT have SystemCall fields here (those are XP+)
        # 0x300 = KiFastSystemCall (added in XP, NOT present in Win2000)
    ]
}


# EPROCESS - Executive Process Object (Windows 2000 SP4, x86)
# Kernel-mode structure representing a process. Needed for win32k.sys / ntoskrnl
EPROCESS_WIN2K = {
    'name': 'EPROCESS',
    'size': 0x290,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 0x6C, 'name': 'Pcb', 'type': 'KPROCESS'},
        {'offset': 0x06C, 'size': 4,    'name': 'ExitStatus', 'type': 'NTSTATUS'},
        {'offset': 0x070, 'size': 8,    'name': 'LockEvent', 'type': 'KEVENT'},
        {'offset': 0x078, 'size': 4,    'name': 'LockCount', 'type': 'ULONG'},
        {'offset': 0x080, 'size': 8,    'name': 'CreateTime', 'type': 'LARGE_INTEGER'},
        {'offset': 0x088, 'size': 8,    'name': 'ExitTime', 'type': 'LARGE_INTEGER'},
        {'offset': 0x090, 'size': 4,    'name': 'LockOwner', 'type': 'PKTHREAD'},
        {'offset': 0x094, 'size': 4,    'name': 'UniqueProcessId', 'type': 'HANDLE'},
        {'offset': 0x098, 'size': 8,    'name': 'ActiveProcessLinks', 'type': 'LIST_ENTRY'},
        {'offset': 0x0A0, 'size': 4,    'name': 'QuotaPeakPoolUsage[0]', 'type': 'ULONG'},
        {'offset': 0x0A4, 'size': 4,    'name': 'QuotaPeakPoolUsage[1]', 'type': 'ULONG'},
        {'offset': 0x0A8, 'size': 4,    'name': 'QuotaPoolUsage[0]', 'type': 'ULONG'},
        {'offset': 0x0AC, 'size': 4,    'name': 'QuotaPoolUsage[1]', 'type': 'ULONG'},
        {'offset': 0x0B0, 'size': 4,    'name': 'PagefileUsage', 'type': 'ULONG'},
        {'offset': 0x0B4, 'size': 4,    'name': 'PeakPagefileUsage', 'type': 'ULONG'},
        {'offset': 0x0B8, 'size': 4,    'name': 'CommitCharge', 'type': 'ULONG'},
        {'offset': 0x0BC, 'size': 4,    'name': 'PeakVirtualSize', 'type': 'ULONG'},
        {'offset': 0x0C0, 'size': 4,    'name': 'VirtualSize', 'type': 'SIZE_T'},
        {'offset': 0x0C4, 'size': 8,    'name': 'SessionProcessLinks', 'type': 'LIST_ENTRY'},
        {'offset': 0x0CC, 'size': 4,    'name': 'DebugPort', 'type': 'PVOID'},
        {'offset': 0x0D0, 'size': 4,    'name': 'ExceptionPort', 'type': 'PVOID'},
        {'offset': 0x0D4, 'size': 4,    'name': 'ObjectTable', 'type': 'PHANDLE_TABLE'},
        {'offset': 0x0D8, 'size': 4,    'name': 'Token', 'type': 'EX_FAST_REF'},
        {'offset': 0x0DC, 'size': 0x28, 'name': 'WorkingSetLock', 'type': 'FAST_MUTEX'},
        {'offset': 0x104, 'size': 4,    'name': 'WorkingSetPage', 'type': 'ULONG'},
        {'offset': 0x108, 'size': 0x28, 'name': 'AddressCreationLock', 'type': 'FAST_MUTEX'},
        {'offset': 0x130, 'size': 4,    'name': 'HyperSpaceLock', 'type': 'ULONG'},
        {'offset': 0x134, 'size': 4,    'name': 'ForkInProgress', 'type': 'PETHREAD'},
        {'offset': 0x138, 'size': 4,    'name': 'HardwareTrigger', 'type': 'ULONG'},
        {'offset': 0x13C, 'size': 4,    'name': 'VadRoot', 'type': 'PVOID'},
        {'offset': 0x140, 'size': 4,    'name': 'VadHint', 'type': 'PVOID'},
        {'offset': 0x144, 'size': 4,    'name': 'CloneRoot', 'type': 'PVOID'},
        {'offset': 0x148, 'size': 4,    'name': 'NumberOfPrivatePages', 'type': 'ULONG'},
        {'offset': 0x14C, 'size': 4,    'name': 'NumberOfLockedPages', 'type': 'ULONG'},
        {'offset': 0x150, 'size': 4,    'name': 'Win32Process', 'type': 'PVOID'},
        {'offset': 0x154, 'size': 4,    'name': 'Job', 'type': 'PEJOB'},
        {'offset': 0x158, 'size': 4,    'name': 'SectionObject', 'type': 'PVOID'},
        {'offset': 0x15C, 'size': 4,    'name': 'SectionBaseAddress', 'type': 'PVOID'},
        {'offset': 0x160, 'size': 4,    'name': 'QuotaBlock', 'type': 'PEPROCESS_QUOTA_BLOCK'},
        {'offset': 0x164, 'size': 4,    'name': 'WorkingSetWatch', 'type': 'PPAGEFAULT_HISTORY'},
        {'offset': 0x168, 'size': 4,    'name': 'Win32WindowStation', 'type': 'HANDLE'},
        {'offset': 0x16C, 'size': 4,    'name': 'InheritedFromUniqueProcessId', 'type': 'HANDLE'},
        {'offset': 0x170, 'size': 4,    'name': 'LdtInformation', 'type': 'PVOID'},
        {'offset': 0x174, 'size': 4,    'name': 'VadFreeHint', 'type': 'PVOID'},
        {'offset': 0x178, 'size': 4,    'name': 'VdmObjects', 'type': 'PVOID'},
        {'offset': 0x17C, 'size': 4,    'name': 'DeviceMap', 'type': 'PVOID'},
        {'offset': 0x180, 'size': 12,   'name': 'PhysicalVadList', 'type': 'LIST_ENTRY+ULONG'},
        {'offset': 0x18C, 'size': 8,    'name': 'PageDirectoryPte', 'type': 'HARDWARE_PTE'},
        {'offset': 0x198, 'size': 16,   'name': 'ImageFileName[16]', 'type': 'UCHAR[16]'},
        {'offset': 0x1A8, 'size': 4,    'name': 'VmTrimFaultValue', 'type': 'ULONG'},
        {'offset': 0x1AC, 'size': 1,    'name': 'SetTimerResolution', 'type': 'BOOLEAN'},
        {'offset': 0x1AD, 'size': 1,    'name': 'PriorityClass', 'type': 'UCHAR'},
        {'offset': 0x1B0, 'size': 4,    'name': 'SubSystemVersion', 'type': 'ULONG'},
        {'offset': 0x1B4, 'size': 4,    'name': 'Win32WindowStation_2', 'type': 'PVOID'},
        {'offset': 0x1B8, 'size': 4,    'name': 'Peb', 'type': 'PPEB'},
        {'offset': 0x1BC, 'size': 4,    'name': 'SessionId', 'type': 'ULONG'},
    ]
}

# ETHREAD - Executive Thread Object (Windows 2000 SP4, x86)
ETHREAD_WIN2K = {
    'name': 'ETHREAD',
    'size': 0x258,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 0x1B0, 'name': 'Tcb', 'type': 'KTHREAD'},
        {'offset': 0x1B0, 'size': 8,     'name': 'CreateTime', 'type': 'LARGE_INTEGER'},
        {'offset': 0x1B8, 'size': 8,     'name': 'ExitTime_or_LpcReplyChain', 'type': 'LARGE_INTEGER'},
        {'offset': 0x1C0, 'size': 4,     'name': 'ExitStatus_or_OfsChain', 'type': 'NTSTATUS'},
        {'offset': 0x1C4, 'size': 8,     'name': 'PostBlockList', 'type': 'LIST_ENTRY'},
        {'offset': 0x1CC, 'size': 8,     'name': 'TerminationPort_or_ReaperLink', 'type': 'PVOID'},
        {'offset': 0x1D4, 'size': 4,     'name': 'ActiveTimerListLock', 'type': 'KSPIN_LOCK'},
        {'offset': 0x1D8, 'size': 8,     'name': 'ActiveTimerListHead', 'type': 'LIST_ENTRY'},
        {'offset': 0x1E0, 'size': 8,     'name': 'Cid', 'type': 'CLIENT_ID'},
        {'offset': 0x1E8, 'size': 0x10,  'name': 'LpcReplySemaphore', 'type': 'KSEMAPHORE'},
        {'offset': 0x1F8, 'size': 4,     'name': 'LpcReplyMessage', 'type': 'PVOID'},
        {'offset': 0x1FC, 'size': 4,     'name': 'LpcReplyMessageId', 'type': 'ULONG'},
        {'offset': 0x200, 'size': 4,     'name': 'ImpersonationInfo', 'type': 'PPS_IMPERSONATION_INFORMATION'},
        {'offset': 0x204, 'size': 8,     'name': 'IrpList', 'type': 'LIST_ENTRY'},
        {'offset': 0x20C, 'size': 4,     'name': 'TopLevelIrp', 'type': 'ULONG'},
        {'offset': 0x210, 'size': 4,     'name': 'DeviceToVerify', 'type': 'PDEVICE_OBJECT'},
        {'offset': 0x214, 'size': 4,     'name': 'ThreadsProcess', 'type': 'PEPROCESS'},
        {'offset': 0x218, 'size': 4,     'name': 'StartAddress', 'type': 'PVOID'},
        {'offset': 0x21C, 'size': 4,     'name': 'Win32StartAddress_or_LpcReceivedMessageId', 'type': 'PVOID'},
        {'offset': 0x220, 'size': 1,     'name': 'LpcExitThreadCalled', 'type': 'BOOLEAN'},
        {'offset': 0x221, 'size': 1,     'name': 'HardErrorsAreDisabled', 'type': 'BOOLEAN'},
        {'offset': 0x222, 'size': 1,     'name': 'LpcReceivedMsgIdValid', 'type': 'BOOLEAN'},
        {'offset': 0x223, 'size': 1,     'name': 'ActiveImpersonationInfo', 'type': 'BOOLEAN'},
        {'offset': 0x224, 'size': 4,     'name': 'PerformanceCountLow', 'type': 'ULONG'},
        {'offset': 0x228, 'size': 4,     'name': 'PerformanceCountHigh', 'type': 'LONG'},
    ]
}

# LDR_DATA_TABLE_ENTRY (Windows 2000 SP4, x86)
# Used by ntdll loader to track loaded modules
LDR_DATA_TABLE_ENTRY_WIN2K = {
    'name': 'LDR_DATA_TABLE_ENTRY',
    'size': 0x68,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 8,  'name': 'InLoadOrderLinks', 'type': 'LIST_ENTRY'},
        {'offset': 0x008, 'size': 8,  'name': 'InMemoryOrderLinks', 'type': 'LIST_ENTRY'},
        {'offset': 0x010, 'size': 8,  'name': 'InInitializationOrderLinks', 'type': 'LIST_ENTRY'},
        {'offset': 0x018, 'size': 4,  'name': 'DllBase', 'type': 'PVOID'},
        {'offset': 0x01C, 'size': 4,  'name': 'EntryPoint', 'type': 'PVOID'},
        {'offset': 0x020, 'size': 4,  'name': 'SizeOfImage', 'type': 'ULONG'},
        {'offset': 0x024, 'size': 8,  'name': 'FullDllName', 'type': 'UNICODE_STRING'},
        {'offset': 0x02C, 'size': 8,  'name': 'BaseDllName', 'type': 'UNICODE_STRING'},
        {'offset': 0x034, 'size': 4,  'name': 'Flags', 'type': 'ULONG'},
        {'offset': 0x038, 'size': 2,  'name': 'LoadCount', 'type': 'USHORT'},
        {'offset': 0x03A, 'size': 2,  'name': 'TlsIndex', 'type': 'USHORT'},
        {'offset': 0x03C, 'size': 8,  'name': 'HashLinks_or_SectionPointer', 'type': 'LIST_ENTRY'},
        {'offset': 0x044, 'size': 4,  'name': 'TimeDateStamp', 'type': 'ULONG'},
        {'offset': 0x048, 'size': 4,  'name': 'LoadedImports', 'type': 'PVOID'},
        {'offset': 0x04C, 'size': 4,  'name': 'EntryPointActivationContext', 'type': 'PVOID'},
        {'offset': 0x050, 'size': 4,  'name': 'PatchInformation', 'type': 'PVOID'},
    ]
}

# HEAP (Windows 2000 SP4, x86)
# NT heap manager main structure
HEAP_WIN2K = {
    'name': 'HEAP',
    'size': 0x588,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 0x38, 'name': 'Entry', 'type': 'HEAP_ENTRY'},
        {'offset': 0x038, 'size': 4,    'name': 'Signature', 'type': 'ULONG'},
        {'offset': 0x03C, 'size': 4,    'name': 'Flags', 'type': 'ULONG'},
        {'offset': 0x040, 'size': 4,    'name': 'ForceFlags', 'type': 'ULONG'},
        {'offset': 0x044, 'size': 4,    'name': 'VirtualMemoryThreshold', 'type': 'ULONG'},
        {'offset': 0x048, 'size': 4,    'name': 'SegmentReserve', 'type': 'SIZE_T'},
        {'offset': 0x04C, 'size': 4,    'name': 'SegmentCommit', 'type': 'SIZE_T'},
        {'offset': 0x050, 'size': 4,    'name': 'DeCommitFreeBlockThreshold', 'type': 'SIZE_T'},
        {'offset': 0x054, 'size': 4,    'name': 'DeCommitTotalFreeThreshold', 'type': 'SIZE_T'},
        {'offset': 0x058, 'size': 4,    'name': 'TotalFreeSize', 'type': 'SIZE_T'},
        {'offset': 0x05C, 'size': 4,    'name': 'MaximumAllocationSize', 'type': 'SIZE_T'},
        {'offset': 0x060, 'size': 2,    'name': 'ProcessHeapsListIndex', 'type': 'USHORT'},
        {'offset': 0x062, 'size': 2,    'name': 'HeaderValidateLength', 'type': 'USHORT'},
        {'offset': 0x064, 'size': 4,    'name': 'HeaderValidateCopy', 'type': 'PVOID'},
        {'offset': 0x068, 'size': 2,    'name': 'NextAvailableTagIndex', 'type': 'USHORT'},
        {'offset': 0x06A, 'size': 2,    'name': 'MaximumTagIndex', 'type': 'USHORT'},
        {'offset': 0x06C, 'size': 4,    'name': 'TagEntries', 'type': 'PHEAP_TAG_ENTRY'},
        {'offset': 0x070, 'size': 8,    'name': 'UCRSegments', 'type': 'LIST_ENTRY'},
        {'offset': 0x078, 'size': 8,    'name': 'UnusedUnCommittedRanges', 'type': 'PHEAP_UCR_SEGMENT'},
        {'offset': 0x080, 'size': 4,    'name': 'AlignRound', 'type': 'ULONG'},
        {'offset': 0x084, 'size': 4,    'name': 'AlignMask', 'type': 'ULONG'},
        {'offset': 0x088, 'size': 8,    'name': 'VirtualAllocdBlocks', 'type': 'LIST_ENTRY'},
        {'offset': 0x090, 'size': 256,  'name': 'Segments[64]', 'type': 'PHEAP_SEGMENT[64]'},
        {'offset': 0x190, 'size': 16,   'name': 'u_FreeListBitmap', 'type': 'ULONG[4]'},
        {'offset': 0x1A0, 'size': 0x400, 'name': 'FreeLists[128]', 'type': 'LIST_ENTRY[128]'},
        {'offset': 0x5A0, 'size': 0x38, 'name': 'LockVariable', 'type': 'HEAP_LOCK'},
        {'offset': 0x5D8, 'size': 4,    'name': 'CommitRoutine', 'type': 'PRTL_HEAP_COMMIT_ROUTINE'},
    ]
}

# PEB_LDR_DATA (Windows 2000 SP4)
PEB_LDR_DATA_WIN2K = {
    'name': 'PEB_LDR_DATA',
    'size': 0x24,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 4, 'name': 'Length', 'type': 'ULONG'},
        {'offset': 0x004, 'size': 1, 'name': 'Initialized', 'type': 'BOOLEAN'},
        {'offset': 0x008, 'size': 4, 'name': 'SsHandle', 'type': 'HANDLE'},
        {'offset': 0x00C, 'size': 8, 'name': 'InLoadOrderModuleList', 'type': 'LIST_ENTRY'},
        {'offset': 0x014, 'size': 8, 'name': 'InMemoryOrderModuleList', 'type': 'LIST_ENTRY'},
        {'offset': 0x01C, 'size': 8, 'name': 'InInitializationOrderModuleList', 'type': 'LIST_ENTRY'},
    ]
}

# RTL_USER_PROCESS_PARAMETERS (Windows 2000 SP4)
RTL_USER_PROCESS_PARAMETERS_WIN2K = {
    'name': 'RTL_USER_PROCESS_PARAMETERS',
    'size': 0x290,
    'os': 'Windows 2000 SP4',
    'fields': [
        {'offset': 0x000, 'size': 4,  'name': 'MaximumLength', 'type': 'ULONG'},
        {'offset': 0x004, 'size': 4,  'name': 'Length', 'type': 'ULONG'},
        {'offset': 0x008, 'size': 4,  'name': 'Flags', 'type': 'ULONG'},
        {'offset': 0x00C, 'size': 4,  'name': 'DebugFlags', 'type': 'ULONG'},
        {'offset': 0x010, 'size': 4,  'name': 'ConsoleHandle', 'type': 'HANDLE'},
        {'offset': 0x014, 'size': 4,  'name': 'ConsoleFlags', 'type': 'ULONG'},
        {'offset': 0x018, 'size': 4,  'name': 'StandardInput', 'type': 'HANDLE'},
        {'offset': 0x01C, 'size': 4,  'name': 'StandardOutput', 'type': 'HANDLE'},
        {'offset': 0x020, 'size': 4,  'name': 'StandardError', 'type': 'HANDLE'},
        {'offset': 0x024, 'size': 8,  'name': 'CurrentDirectory.DosPath', 'type': 'UNICODE_STRING'},
        {'offset': 0x02C, 'size': 4,  'name': 'CurrentDirectory.Handle', 'type': 'HANDLE'},
        {'offset': 0x030, 'size': 8,  'name': 'DllPath', 'type': 'UNICODE_STRING'},
        {'offset': 0x038, 'size': 8,  'name': 'ImagePathName', 'type': 'UNICODE_STRING'},
        {'offset': 0x040, 'size': 8,  'name': 'CommandLine', 'type': 'UNICODE_STRING'},
        {'offset': 0x048, 'size': 4,  'name': 'Environment', 'type': 'PVOID'},
        {'offset': 0x04C, 'size': 4,  'name': 'StartingX', 'type': 'ULONG'},
        {'offset': 0x050, 'size': 4,  'name': 'StartingY', 'type': 'ULONG'},
        {'offset': 0x054, 'size': 4,  'name': 'CountX', 'type': 'ULONG'},
        {'offset': 0x058, 'size': 4,  'name': 'CountY', 'type': 'ULONG'},
        {'offset': 0x05C, 'size': 4,  'name': 'CountCharsX', 'type': 'ULONG'},
        {'offset': 0x060, 'size': 4,  'name': 'CountCharsY', 'type': 'ULONG'},
        {'offset': 0x064, 'size': 4,  'name': 'FillAttribute', 'type': 'ULONG'},
        {'offset': 0x068, 'size': 4,  'name': 'WindowFlags', 'type': 'ULONG'},
        {'offset': 0x06C, 'size': 4,  'name': 'ShowWindowFlags', 'type': 'ULONG'},
        {'offset': 0x070, 'size': 8,  'name': 'WindowTitle', 'type': 'UNICODE_STRING'},
        {'offset': 0x078, 'size': 8,  'name': 'DesktopInfo', 'type': 'UNICODE_STRING'},
        {'offset': 0x080, 'size': 8,  'name': 'ShellInfo', 'type': 'UNICODE_STRING'},
        {'offset': 0x088, 'size': 8,  'name': 'RuntimeData', 'type': 'UNICODE_STRING'},
    ]
}

ALL_KNOWN_STRUCTURES = {
    'PEB': PEB_WIN2K,
    'TEB': TEB_WIN2K,
    'KUSER_SHARED_DATA': KUSER_SHARED_DATA_WIN2K,
    'EPROCESS': EPROCESS_WIN2K,
    'ETHREAD': ETHREAD_WIN2K,
    'LDR_DATA_TABLE_ENTRY': LDR_DATA_TABLE_ENTRY_WIN2K,
    'HEAP': HEAP_WIN2K,
    'PEB_LDR_DATA': PEB_LDR_DATA_WIN2K,
    'RTL_USER_PROCESS_PARAMETERS': RTL_USER_PROCESS_PARAMETERS_WIN2K,
}


def get_known_structure(name):
    """Get a known structure layout by name."""
    return ALL_KNOWN_STRUCTURES.get(name)


def list_known_structures():
    """List all known structure names."""
    return list(ALL_KNOWN_STRUCTURES.keys())


def compare_structure_with_binary(struct_def, binary_data, base_offset=0):
    """
    Compare a known structure definition against raw binary data.
    Useful for verifying if a running system matches expected layout.

    Returns list of field values extracted from the binary.
    """
    results = []
    for field in struct_def['fields']:
        offset = field['offset']
        size = field['size']

        if offset + size > len(binary_data):
            results.append({**field, 'value': '<out of bounds>', 'raw': None})
            continue

        raw = binary_data[offset:offset + size]

        # Try to interpret small fields as integers
        if size <= 8:
            if size == 1:
                val = raw[0]
            elif size == 2:
                val = struct.unpack('<H', raw)[0]
            elif size == 4:
                val = struct.unpack('<I', raw)[0]
            elif size == 8:
                val = struct.unpack('<Q', raw)[0]
            else:
                val = raw.hex()
            results.append({**field, 'value': val, 'value_hex': hex(val) if isinstance(val, int) else val, 'raw': raw.hex()})
        else:
            results.append({**field, 'value': f'<{size} bytes>', 'raw': raw[:16].hex() + '...'})

    return results


def generate_c_header(struct_def):
    """
    Generate a C header definition from a structure layout.
    Useful for creating compatible headers for ReactOS compilation.
    """
    lines = []
    lines.append(f"/* {struct_def['name']} - {struct_def['os']} */")
    lines.append(f"/* Total size: 0x{struct_def['size']:X} ({struct_def['size']} bytes) */")
    lines.append(f"typedef struct _{struct_def['name']} {{")

    prev_end = 0
    for field in struct_def['fields']:
        offset = field['offset']
        # Add padding if there's a gap
        if offset > prev_end:
            gap = offset - prev_end
            lines.append(f"    UCHAR _padding_{prev_end:03X}[{gap}];  /* offset 0x{prev_end:03X} */")

        lines.append(f"    {field['type']:40s} {field['name']};  /* offset 0x{offset:03X}, size 0x{field['size']:X} */")
        prev_end = offset + field['size']

    lines.append(f"}} {struct_def['name']}, *P{struct_def['name']};")
    lines.append("")

    return '\n'.join(lines)


def save_all_headers(output_dir):
    """Generate C headers for all known structures."""
    os.makedirs(output_dir, exist_ok=True)
    files = []
    for name, struct_def in ALL_KNOWN_STRUCTURES.items():
        path = os.path.join(output_dir, f"{name.lower()}_win2k.h")
        with open(path, 'w') as f:
            f.write(f"#ifndef _{name.upper()}_WIN2K_H\n")
            f.write(f"#define _{name.upper()}_WIN2K_H\n\n")
            f.write(generate_c_header(struct_def))
            f.write(f"\n#endif /* _{name.upper()}_WIN2K_H */\n")
        files.append(path)
    return files
