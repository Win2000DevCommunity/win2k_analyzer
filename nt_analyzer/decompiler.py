"""
x86 Pseudocode Decompiler - Enhanced Symbol-less Edition
=========================================================
Converts x86-32 disassembly into readable C-like pseudocode.
Designed for reversing Windows 2000 kernel-mode drivers and system DLLs.

Works intelligently WITHOUT symbols by using:
  - Heuristic function boundary detection (prologue/epilogue scanning)
  - Data-flow analysis for register tracking & argument resolution
  - Structure access pattern recognition (DRIVER_OBJECT, IRP, DEVICE_OBJECT)
  - Driver dispatch table detection (DriverObject->MajorFunction[IRP_MJ_*])
  - Loop/switch/if-else reconstruction from CFG
  - Automatic type inference from API usage patterns
  - Pool tag string extraction
  - IRQL, spinlock, IRP pattern recognition
"""

import os
import re
import struct
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Optional

import pefile
from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_32,
    CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET,
    CS_OP_IMM, CS_OP_REG, CS_OP_MEM,
)

# ── Known NT status codes ────────────────────────────────────────────────
NTSTATUS_CODES = {
    0x00000000: "STATUS_SUCCESS",
    0x00000001: "STATUS_WAIT_1",
    0x00000002: "STATUS_WAIT_2",
    0x00000003: "STATUS_WAIT_3",
    0x0000003F: "STATUS_WAIT_63",
    0x00000080: "STATUS_ABANDONED_WAIT_0",
    0x00000102: "STATUS_TIMEOUT",
    0x00000103: "STATUS_PENDING",
    0x00000104: "STATUS_REPARSE",
    0x00000105: "STATUS_MORE_ENTRIES",
    0x00000106: "STATUS_MARK_AS_SYSTEM_RESERVED",
    0x00000107: "STATUS_MEDIA_CHANGED",
    0x0000010C: "STATUS_NOTIFY_CLEANUP",
    0x00000110: "STATUS_NOTIFY_ENUM_DIR",
    0x00010001: "DBG_EXCEPTION_HANDLED",
    0x40000000: "STATUS_OBJECT_NAME_EXISTS",
    0x40000003: "STATUS_BREAKPOINT",
    0x40000004: "STATUS_SINGLE_STEP",
    0x40010003: "DBG_TERMINATE_THREAD",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000003: "STATUS_INVALID_INFO_CLASS",
    0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000000E: "STATUS_NO_SUCH_DEVICE",
    0xC000000F: "STATUS_NO_SUCH_FILE",
    0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
    0xC0000011: "STATUS_END_OF_FILE",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC000001C: "STATUS_CONFLICTING_ADDRESSES",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC000002B: "STATUS_PAGING_FILE_QUOTA",
    0xC0000033: "STATUS_OBJECT_NAME_INVALID",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC000003B: "STATUS_OBJECT_PATH_SYNTAX_BAD",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC0000056: "STATUS_DELETE_PENDING",
    0xC000007A: "STATUS_PROCEDURE_NOT_FOUND",
    0xC0000098: "STATUS_FILE_IS_A_DIRECTORY",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC00000A0: "STATUS_MEDIA_WRITE_PROTECTED",
    0xC00000A5: "STATUS_BAD_IMPERSONATION_LEVEL",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000C0: "STATUS_DEVICE_DOES_NOT_EXIST",
    0xC00000D0: "STATUS_FILE_CLOSED",
    0xC00000E5: "STATUS_INTERNAL_ERROR",
    0xC0000120: "STATUS_CANCELLED",
    0xC0000185: "STATUS_IO_DEVICE_ERROR",
    0xC0000225: "STATUS_NOT_FOUND",
}

# ── IRP_MJ codes ─────────────────────────────────────────────────────────
IRP_MJ_CODES = {
    0x00: "IRP_MJ_CREATE", 0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE", 0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE", 0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION", 0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA", 0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION", 0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0C: "IRP_MJ_DIRECTORY_CONTROL", 0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0E: "IRP_MJ_DEVICE_CONTROL", 0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN", 0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP", 0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY", 0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER", 0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE", 0x19: "IRP_MJ_QUERY_QUOTA",
    0x1A: "IRP_MJ_SET_QUOTA", 0x1B: "IRP_MJ_PNP",
}

# ── Well-known structure offsets for Win2000 SP4 (x86) ───────────────────
DRIVER_OBJECT_FIELDS = {
    0x00: ("CSHORT", "Type"), 0x02: ("CSHORT", "Size"),
    0x04: ("PDEVICE_OBJECT", "DeviceObject"), 0x08: ("ULONG", "Flags"),
    0x0C: ("PVOID", "DriverStart"), 0x10: ("ULONG", "DriverSize"),
    0x14: ("PVOID", "DriverSection"), 0x18: ("PDRIVER_EXTENSION", "DriverExtension"),
    0x1C: ("UNICODE_STRING", "DriverName"), 0x24: ("PUNICODE_STRING", "HardwareDatabase"),
    0x28: ("PFAST_IO_DISPATCH", "FastIoDispatch"), 0x2C: ("PDRIVER_INITIALIZE", "DriverInit"),
    0x30: ("PDRIVER_STARTIO", "DriverStartIo"), 0x34: ("PDRIVER_UNLOAD", "DriverUnload"),
}
for _mj_idx in range(0x1C):
    _off = 0x38 + _mj_idx * 4
    _name = IRP_MJ_CODES.get(_mj_idx, f"IRP_MJ_{_mj_idx}")
    DRIVER_OBJECT_FIELDS[_off] = ("PDRIVER_DISPATCH", f"MajorFunction[{_name}]")

DEVICE_OBJECT_FIELDS = {
    0x00: ("CSHORT", "Type"), 0x02: ("USHORT", "Size"),
    0x04: ("LONG", "ReferenceCount"), 0x08: ("PDRIVER_OBJECT", "DriverObject"),
    0x0C: ("PDEVICE_OBJECT", "NextDevice"), 0x10: ("PDEVICE_OBJECT", "AttachedDevice"),
    0x14: ("PIRP", "CurrentIrp"), 0x18: ("PIO_TIMER", "Timer"),
    0x1C: ("ULONG", "Flags"), 0x20: ("ULONG", "Characteristics"),
    0x24: ("PVPB", "Vpb"), 0x28: ("PVOID", "DeviceExtension"),
    0x2C: ("DEVICE_TYPE", "DeviceType"), 0x30: ("CCHAR", "StackSize"),
}

IRP_FIELDS = {
    0x00: ("CSHORT", "Type"), 0x02: ("USHORT", "Size"),
    0x04: ("PMDL", "MdlAddress"), 0x08: ("ULONG", "Flags"),
    0x0C: ("PVOID", "AssociatedIrp.SystemBuffer"),
    0x18: ("LIST_ENTRY", "ThreadListEntry"),
    0x20: ("IO_STATUS_BLOCK", "IoStatus"), 0x24: ("IO_STATUS_BLOCK", "IoStatus.Information"),
    0x28: ("KPROCESSOR_MODE", "RequestorMode"), 0x29: ("BOOLEAN", "PendingReturned"),
    0x2A: ("CHAR", "StackCount"), 0x2B: ("CHAR", "CurrentLocation"),
    0x2C: ("BOOLEAN", "Cancel"), 0x2D: ("KIRQL", "CancelIrql"),
    0x30: ("PDRIVER_CANCEL", "CancelRoutine"), 0x34: ("PVOID", "UserBuffer"),
    0x3C: ("PVOID", "Tail.Overlay.DriverContext[0]"),
    0x44: ("PETHREAD", "Tail.Overlay.Thread"),
    0x60: ("PIO_STACK_LOCATION", "Tail.Overlay.CurrentStackLocation"),
}

IO_STACK_LOCATION_FIELDS = {
    0x00: ("UCHAR", "MajorFunction"), 0x01: ("UCHAR", "MinorFunction"),
    0x02: ("UCHAR", "Flags"), 0x03: ("UCHAR", "Control"),
    0x04: ("ULONG", "Parameters"),
    0x14: ("PDEVICE_OBJECT", "DeviceObject"), 0x18: ("PFILE_OBJECT", "FileObject"),
    0x1C: ("PIO_COMPLETION_ROUTINE", "CompletionRoutine"), 0x20: ("PVOID", "Context"),
}

FILE_OBJECT_FIELDS = {
    0x00: ("CSHORT", "Type"), 0x02: ("CSHORT", "Size"),
    0x04: ("PDEVICE_OBJECT", "DeviceObject"), 0x08: ("PVPB", "Vpb"),
    0x0C: ("PVOID", "FsContext"), 0x10: ("PVOID", "FsContext2"),
    0x14: ("PSECTION_OBJECT_POINTERS", "SectionObjectPointer"),
    0x18: ("PVOID", "PrivateCacheMap"), 0x1C: ("NTSTATUS", "FinalStatus"),
    0x20: ("PVOID", "RelatedFileObject"),
    0x24: ("UNICODE_STRING", "FileName"), 0x2C: ("LARGE_INTEGER", "CurrentByteOffset"),
    0x34: ("ULONG", "Waiters"), 0x38: ("ULONG", "Busy"),
    0x3C: ("PVOID", "LastLock"), 0x40: ("KEVENT", "Lock"),
    0x50: ("KEVENT", "Event"), 0x60: ("PIO_COMPLETION_CONTEXT", "CompletionContext"),
}

SECTION_OBJECT_POINTERS_FIELDS = {
    0x00: ("PVOID", "DataSectionObject"),
    0x04: ("PVOID", "SharedCacheMap"),
    0x08: ("PVOID", "ImageSectionObject"),
}

SHARED_CACHE_MAP_FIELDS = {
    0x00: ("CSHORT", "NodeTypeCode"), 0x02: ("CSHORT", "NodeByteSize"),
    0x04: ("ULONG", "OpenCount"), 0x08: ("LARGE_INTEGER", "FileSize"),
    0x10: ("LIST_ENTRY", "BcbList"), 0x18: ("LARGE_INTEGER", "SectionSize"),
    0x20: ("LARGE_INTEGER", "ValidDataLength"), 0x28: ("LARGE_INTEGER", "ValidDataGoal"),
    0x30: ("PVACB", "InitialVacbs[0]"), 0x34: ("PVACB", "InitialVacbs[1]"),
    0x38: ("PVACB", "InitialVacbs[2]"), 0x3C: ("PVACB", "InitialVacbs[3]"),
    0x40: ("PVACB*", "Vacbs"), 0x44: ("PFILE_OBJECT", "FileObject"),
    0x48: ("PVACB", "ActiveVacb"), 0x4C: ("PVOID", "NeedToZero"),
    0x50: ("ULONG", "NeedToZeroPage"), 0x54: ("KSPIN_LOCK", "ActiveVacbSpinLock"),
    0x58: ("ULONG", "VacbActiveCount"), 0x5C: ("ULONG", "DirtyPages"),
    0x60: ("LIST_ENTRY", "SharedCacheMapLinks"), 0x68: ("ULONG", "Flags"),
    0x6C: ("NTSTATUS", "Status"), 0x70: ("PMBCB", "Mbcb"),
    0x74: ("PVOID", "Section"), 0x78: ("PKEVENT", "CreateEvent"),
    0x7C: ("PKEVENT", "WaitOnActiveCount"),
    0x80: ("ULONG", "PagesToWrite"), 0x88: ("LARGE_INTEGER", "BeyondLastFlush"),
    0x90: ("PCACHE_MANAGER_CALLBACKS", "Callbacks"),
    0x94: ("PVOID", "LazyWriteContext"),
    0x98: ("LIST_ENTRY", "PrivateList"),
    0xA0: ("PVOID", "LogHandle"), 0xA4: ("PFLUSH_TO_LSN", "FlushToLsnRoutine"),
    0xA8: ("ULONG", "DirtyPageThreshold"), 0xAC: ("ULONG", "LazyWritePassCount"),
    0xB0: ("PCACHE_UNINITIALIZE_EVENT", "UninitializeEvent"),
    0xB4: ("PVACB", "NeedToZeroVacb"),
    0xB8: ("KSPIN_LOCK", "BcbSpinLock"), 0xBC: ("PVOID", "Reserved"),
    0xC0: ("LIST_ENTRY", "PrivateCacheMap"),
    0xD0: ("PPRIVATE_CACHE_MAP", "PrivateCacheMapList"),
}

PRIVATE_CACHE_MAP_FIELDS = {
    0x00: ("CSHORT", "NodeTypeCode"), 0x02: ("CSHORT", "NodeByteSize"),
    0x04: ("PSHARED_CACHE_MAP", "SharedCacheMap"),
    0x08: ("ULONG", "FileOffset1"), 0x0C: ("ULONG", "BeyondLastByte1"),
    0x10: ("ULONG", "FileOffset2"), 0x14: ("ULONG", "BeyondLastByte2"),
    0x18: ("ULONG", "ReadAheadOffset"), 0x1C: ("ULONG", "ReadAheadLength[0]"),
    0x20: ("ULONG", "ReadAheadLength[1]"), 0x24: ("KSPIN_LOCK", "ReadAheadSpinLock"),
    0x28: ("LIST_ENTRY", "PrivateLinks"),
}

CC_FILE_SIZES_FIELDS = {
    0x00: ("LARGE_INTEGER", "AllocationSize"),
    0x08: ("LARGE_INTEGER", "FileSize"),
    0x10: ("LARGE_INTEGER", "ValidDataLength"),
}

KNOWN_STRUCTURES = {
    "DRIVER_OBJECT": DRIVER_OBJECT_FIELDS,
    "DEVICE_OBJECT": DEVICE_OBJECT_FIELDS,
    "IRP": IRP_FIELDS,
    "IO_STACK_LOCATION": IO_STACK_LOCATION_FIELDS,
    "FILE_OBJECT": FILE_OBJECT_FIELDS,
    "SECTION_OBJECT_POINTERS": SECTION_OBJECT_POINTERS_FIELDS,
    "SHARED_CACHE_MAP": SHARED_CACHE_MAP_FIELDS,
    "PRIVATE_CACHE_MAP": PRIVATE_CACHE_MAP_FIELDS,
    "CC_FILE_SIZES": CC_FILE_SIZES_FIELDS,
}

# ── Known kernel APIs with parameter info ────────────────────────────────
KERNEL_API_SIGNATURES = {
    "IoCallDriver":        ("NTSTATUS", [("PDEVICE_OBJECT", "DeviceObject"), ("PIRP", "Irp")]),
    "IofCallDriver":       ("NTSTATUS", [("PDEVICE_OBJECT", "DeviceObject"), ("PIRP", "Irp")]),
    "IoCompleteRequest":   ("VOID", [("PIRP", "Irp"), ("CCHAR", "PriorityBoost")]),
    "IofCompleteRequest":  ("VOID", [("PIRP", "Irp"), ("CCHAR", "PriorityBoost")]),
    "IoCreateDevice":      ("NTSTATUS", [("PDRIVER_OBJECT", "DriverObject"), ("ULONG", "DeviceExtensionSize"),
                             ("PUNICODE_STRING", "DeviceName"), ("DEVICE_TYPE", "DeviceType"),
                             ("ULONG", "DeviceCharacteristics"), ("BOOLEAN", "Exclusive"),
                             ("PDEVICE_OBJECT*", "DeviceObject")]),
    "IoDeleteDevice":      ("VOID", [("PDEVICE_OBJECT", "DeviceObject")]),
    "IoCreateSymbolicLink": ("NTSTATUS", [("PUNICODE_STRING", "SymbolicLinkName"), ("PUNICODE_STRING", "DeviceName")]),
    "IoDeleteSymbolicLink": ("NTSTATUS", [("PUNICODE_STRING", "SymbolicLinkName")]),
    "IoAttachDeviceToDeviceStack": ("PDEVICE_OBJECT", [("PDEVICE_OBJECT", "SourceDevice"),
                                    ("PDEVICE_OBJECT", "TargetDevice")]),
    "IoDetachDevice":      ("VOID", [("PDEVICE_OBJECT", "TargetDevice")]),
    "IoMarkIrpPending":    ("VOID", [("PIRP", "Irp")]),
    "IoSkipCurrentIrpStackLocation": ("VOID", [("PIRP", "Irp")]),
    "IoCopyCurrentIrpStackLocationToNext": ("VOID", [("PIRP", "Irp")]),
    "PoCallDriver":        ("NTSTATUS", [("PDEVICE_OBJECT", "DeviceObject"), ("PIRP", "Irp")]),
    "PoStartNextPowerIrp": ("VOID", [("PIRP", "Irp")]),
    "ExAllocatePool":      ("PVOID", [("POOL_TYPE", "PoolType"), ("SIZE_T", "NumberOfBytes")]),
    "ExAllocatePoolWithTag": ("PVOID", [("POOL_TYPE", "PoolType"), ("SIZE_T", "NumberOfBytes"), ("ULONG", "Tag")]),
    "ExFreePool":          ("VOID", [("PVOID", "P")]),
    "ExFreePoolWithTag":   ("VOID", [("PVOID", "P"), ("ULONG", "Tag")]),
    "KeAcquireSpinLock":   ("VOID", [("PKSPIN_LOCK", "SpinLock"), ("PKIRQL", "OldIrql")]),
    "KeReleaseSpinLock":   ("VOID", [("PKSPIN_LOCK", "SpinLock"), ("KIRQL", "NewIrql")]),
    "KeRaiseIrql":         ("VOID", [("KIRQL", "NewIrql"), ("PKIRQL", "OldIrql")]),
    "KeLowerIrql":         ("VOID", [("KIRQL", "NewIrql")]),
    "KeWaitForSingleObject": ("NTSTATUS", [("PVOID", "Object"), ("KWAIT_REASON", "WaitReason"),
                              ("KPROCESSOR_MODE", "WaitMode"), ("BOOLEAN", "Alertable"),
                              ("PLARGE_INTEGER", "Timeout")]),
    "KeSetEvent":          ("LONG", [("PRKEVENT", "Event"), ("KPRIORITY", "Increment"), ("BOOLEAN", "Wait")]),
    "KeInitializeEvent":   ("VOID", [("PRKEVENT", "Event"), ("EVENT_TYPE", "Type"), ("BOOLEAN", "State")]),
    "KeInitializeSpinLock": ("VOID", [("PKSPIN_LOCK", "SpinLock")]),
    "KeInitializeTimer":   ("VOID", [("PKTIMER", "Timer")]),
    "KeInitializeDpc":     ("VOID", [("PRKDPC", "Dpc"), ("PKDEFERRED_ROUTINE", "DeferredRoutine"), ("PVOID", "DeferredContext")]),
    "ObReferenceObjectByHandle": ("NTSTATUS", [("HANDLE", "Handle"), ("ACCESS_MASK", "DesiredAccess"),
                                   ("POBJECT_TYPE", "ObjectType"), ("KPROCESSOR_MODE", "AccessMode"),
                                   ("PVOID*", "Object"), ("POBJECT_HANDLE_INFORMATION", "HandleInfo")]),
    "ObDereferenceObject": ("VOID", [("PVOID", "Object")]),
    "RtlInitUnicodeString": ("VOID", [("PUNICODE_STRING", "DestinationString"), ("PCWSTR", "SourceString")]),
    "RtlCopyMemory":       ("VOID", [("PVOID", "Destination"), ("PVOID", "Source"), ("SIZE_T", "Length")]),
    "RtlZeroMemory":       ("VOID", [("PVOID", "Destination"), ("SIZE_T", "Length")]),
    "MmGetSystemAddressForMdlSafe": ("PVOID", [("PMDL", "Mdl"), ("MM_PAGE_PRIORITY", "Priority")]),
    "ZwClose":             ("NTSTATUS", [("HANDLE", "Handle")]),
    "ZwCreateFile":        ("NTSTATUS", [("PHANDLE", "FileHandle"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes"), ("PIO_STATUS_BLOCK", "IoStatusBlock"),
                             ("PLARGE_INTEGER", "AllocationSize"), ("ULONG", "FileAttributes"),
                             ("ULONG", "ShareAccess"), ("ULONG", "CreateDisposition"),
                             ("ULONG", "CreateOptions"), ("PVOID", "EaBuffer"), ("ULONG", "EaLength")]),
    "ZwOpenKey":           ("NTSTATUS", [("PHANDLE", "KeyHandle"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes")]),
    "NtCreateFile":        ("NTSTATUS", [("PHANDLE", "FileHandle"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes"), ("PIO_STATUS_BLOCK", "IoStatusBlock"),
                             ("PLARGE_INTEGER", "AllocationSize"), ("ULONG", "FileAttributes"),
                             ("ULONG", "ShareAccess"), ("ULONG", "CreateDisposition"),
                             ("ULONG", "CreateOptions"), ("PVOID", "EaBuffer"), ("ULONG", "EaLength")]),
    "PsCreateSystemThread": ("NTSTATUS", [("PHANDLE", "ThreadHandle"), ("ULONG", "DesiredAccess"),
                              ("POBJECT_ATTRIBUTES", "ObjectAttributes"), ("HANDLE", "ProcessHandle"),
                              ("PCLIENT_ID", "ClientId"), ("PKSTART_ROUTINE", "StartRoutine"), ("PVOID", "StartContext")]),
    "PsTerminateSystemThread": ("NTSTATUS", [("NTSTATUS", "ExitStatus")]),
    "IoGetCurrentProcess": ("PEPROCESS", []),
    "IoCreateFile":        ("NTSTATUS", [("PHANDLE", "FileHandle"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes"), ("PIO_STATUS_BLOCK", "IoStatusBlock"),
                             ("PLARGE_INTEGER", "AllocationSize"), ("ULONG", "FileAttributes"),
                             ("ULONG", "ShareAccess"), ("ULONG", "CreateDisposition"),
                             ("ULONG", "CreateOptions"), ("PVOID", "EaBuffer"), ("ULONG", "EaLength"),
                             ("CREATE_FILE_TYPE", "CreateFileType"), ("PVOID", "InternalParameters"),
                             ("ULONG", "Options")]),
    "NtOpenFile":          ("NTSTATUS", [("PHANDLE", "FileHandle"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes"), ("PIO_STATUS_BLOCK", "IoStatusBlock"),
                             ("ULONG", "ShareAccess"), ("ULONG", "OpenOptions")]),
    "NtClose":             ("NTSTATUS", [("HANDLE", "Handle")]),
    "NtReadFile":          ("NTSTATUS", [("HANDLE", "FileHandle"), ("HANDLE", "Event"),
                             ("PIO_APC_ROUTINE", "ApcRoutine"), ("PVOID", "ApcContext"),
                             ("PIO_STATUS_BLOCK", "IoStatusBlock"), ("PVOID", "Buffer"),
                             ("ULONG", "Length"), ("PLARGE_INTEGER", "ByteOffset"), ("PULONG", "Key")]),
    "NtWriteFile":         ("NTSTATUS", [("HANDLE", "FileHandle"), ("HANDLE", "Event"),
                             ("PIO_APC_ROUTINE", "ApcRoutine"), ("PVOID", "ApcContext"),
                             ("PIO_STATUS_BLOCK", "IoStatusBlock"), ("PVOID", "Buffer"),
                             ("ULONG", "Length"), ("PLARGE_INTEGER", "ByteOffset"), ("PULONG", "Key")]),
    "NtDeviceIoControlFile": ("NTSTATUS", [("HANDLE", "FileHandle"), ("HANDLE", "Event"),
                             ("PIO_APC_ROUTINE", "ApcRoutine"), ("PVOID", "ApcContext"),
                             ("PIO_STATUS_BLOCK", "IoStatusBlock"), ("ULONG", "IoControlCode"),
                             ("PVOID", "InputBuffer"), ("ULONG", "InputBufferLength"),
                             ("PVOID", "OutputBuffer"), ("ULONG", "OutputBufferLength")]),
    "NtQueryInformationFile": ("NTSTATUS", [("HANDLE", "FileHandle"),
                             ("PIO_STATUS_BLOCK", "IoStatusBlock"), ("PVOID", "FileInformation"),
                             ("ULONG", "Length"), ("FILE_INFORMATION_CLASS", "FileInformationClass")]),
    "NtSetInformationFile": ("NTSTATUS", [("HANDLE", "FileHandle"),
                             ("PIO_STATUS_BLOCK", "IoStatusBlock"), ("PVOID", "FileInformation"),
                             ("ULONG", "Length"), ("FILE_INFORMATION_CLASS", "FileInformationClass")]),
    "NtQuerySystemInformation": ("NTSTATUS", [("SYSTEM_INFORMATION_CLASS", "SystemInformationClass"),
                             ("PVOID", "SystemInformation"), ("ULONG", "SystemInformationLength"),
                             ("PULONG", "ReturnLength")]),
    "NtQueryInformationProcess": ("NTSTATUS", [("HANDLE", "ProcessHandle"),
                             ("PROCESSINFOCLASS", "ProcessInformationClass"),
                             ("PVOID", "ProcessInformation"), ("ULONG", "ProcessInformationLength"),
                             ("PULONG", "ReturnLength")]),
    "NtQueryInformationThread": ("NTSTATUS", [("HANDLE", "ThreadHandle"),
                             ("THREADINFOCLASS", "ThreadInformationClass"),
                             ("PVOID", "ThreadInformation"), ("ULONG", "ThreadInformationLength"),
                             ("PULONG", "ReturnLength")]),
    "NtAllocateVirtualMemory": ("NTSTATUS", [("HANDLE", "ProcessHandle"),
                             ("PVOID*", "BaseAddress"), ("ULONG_PTR", "ZeroBits"),
                             ("PSIZE_T", "RegionSize"), ("ULONG", "AllocationType"),
                             ("ULONG", "Protect")]),
    "NtFreeVirtualMemory": ("NTSTATUS", [("HANDLE", "ProcessHandle"),
                             ("PVOID*", "BaseAddress"), ("PSIZE_T", "RegionSize"),
                             ("ULONG", "FreeType")]),
    "NtOpenKey":           ("NTSTATUS", [("PHANDLE", "KeyHandle"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes")]),
    "NtQueryValueKey":     ("NTSTATUS", [("HANDLE", "KeyHandle"), ("PUNICODE_STRING", "ValueName"),
                             ("KEY_VALUE_INFORMATION_CLASS", "KeyValueInformationClass"),
                             ("PVOID", "KeyValueInformation"), ("ULONG", "Length"),
                             ("PULONG", "ResultLength")]),
    "NtSetValueKey":       ("NTSTATUS", [("HANDLE", "KeyHandle"), ("PUNICODE_STRING", "ValueName"),
                             ("ULONG", "TitleIndex"), ("ULONG", "Type"),
                             ("PVOID", "Data"), ("ULONG", "DataSize")]),
    "MmMapIoSpace":        ("PVOID", [("PHYSICAL_ADDRESS", "PhysicalAddress"), ("SIZE_T", "NumberOfBytes"),
                             ("MEMORY_CACHING_TYPE", "CacheType")]),
    "MmUnmapIoSpace":      ("VOID", [("PVOID", "BaseAddress"), ("SIZE_T", "NumberOfBytes")]),
    "IoAllocateIrp":       ("PIRP", [("CCHAR", "StackSize"), ("BOOLEAN", "ChargeQuota")]),
    "IoFreeIrp":           ("VOID", [("PIRP", "Irp")]),
    "IoGetDeviceObjectPointer": ("NTSTATUS", [("PUNICODE_STRING", "ObjectName"),
                             ("ACCESS_MASK", "DesiredAccess"), ("PFILE_OBJECT*", "FileObject"),
                             ("PDEVICE_OBJECT*", "DeviceObject")]),
    "KeInitializeMutex":   ("VOID", [("PRKMUTEX", "Mutex"), ("ULONG", "Level")]),
    "KeReleaseMutex":      ("LONG", [("PRKMUTEX", "Mutex"), ("BOOLEAN", "Wait")]),
    "KeDelayExecutionThread": ("NTSTATUS", [("KPROCESSOR_MODE", "WaitMode"),
                             ("BOOLEAN", "Alertable"), ("PLARGE_INTEGER", "Interval")]),
    "DbgPrint":            ("ULONG", [("PCSTR", "Format")]),
    # Cache manager (Cc*) APIs
    "CcInitializeCacheMap": ("VOID", [("PFILE_OBJECT", "FileObject"), ("PCC_FILE_SIZES", "FileSizes"),
                             ("BOOLEAN", "PinAccess"), ("PCACHE_MANAGER_CALLBACKS", "Callbacks"),
                             ("PVOID", "LazyWriteContext")]),
    "CcUninitializeCacheMap": ("BOOLEAN", [("PFILE_OBJECT", "FileObject"),
                             ("PLARGE_INTEGER", "TruncateSize"), ("PCACHE_UNINITIALIZE_EVENT", "UninitializeEvent")]),
    "CcSetFileSizes":      ("VOID", [("PFILE_OBJECT", "FileObject"), ("PCC_FILE_SIZES", "FileSizes")]),
    "CcCopyRead":          ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("BOOLEAN", "Wait"), ("PVOID", "Buffer"),
                             ("PIO_STATUS_BLOCK", "IoStatus")]),
    "CcCopyWrite":         ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("BOOLEAN", "Wait"), ("PVOID", "Buffer")]),
    "CcMdlRead":           ("VOID", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("PMDL*", "MdlChain"), ("PIO_STATUS_BLOCK", "IoStatus")]),
    "CcMdlReadComplete":   ("VOID", [("PFILE_OBJECT", "FileObject"), ("PMDL", "MdlChain")]),
    "CcMdlWriteComplete":  ("VOID", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("PMDL", "MdlChain")]),
    "CcPrepareMdlWrite":   ("VOID", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("PMDL*", "MdlChain"), ("PIO_STATUS_BLOCK", "IoStatus")]),
    "CcFlushCache":        ("VOID", [("PSECTION_OBJECT_POINTERS", "SectionObjectPointers"),
                             ("PLARGE_INTEGER", "FileOffset"), ("ULONG", "Length"),
                             ("PIO_STATUS_BLOCK", "IoStatus")]),
    "CcPurgeCacheSection":  ("BOOLEAN", [("PSECTION_OBJECT_POINTERS", "SectionObjectPointers"),
                             ("PLARGE_INTEGER", "FileOffset"), ("ULONG", "Length"),
                             ("BOOLEAN", "UninitializeCacheMaps")]),
    "CcMapData":           ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("BOOLEAN", "Wait"), ("PVOID*", "Bcb"),
                             ("PVOID*", "Buffer")]),
    "CcPinRead":           ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("ULONG", "Flags"), ("PVOID*", "Bcb"),
                             ("PVOID*", "Buffer")]),
    "CcPinMappedData":     ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("ULONG", "Flags"), ("PVOID*", "Bcb")]),
    "CcPreparePinWrite":   ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length"), ("BOOLEAN", "Zero"), ("ULONG", "Flags"),
                             ("PVOID*", "Bcb"), ("PVOID*", "Buffer")]),
    "CcUnpinData":         ("VOID", [("PVOID", "Bcb")]),
    "CcSetDirtyPinnedData": ("VOID", [("PVOID", "Bcb"), ("PLARGE_INTEGER", "Lsn")]),
    "CcRepinBcb":          ("VOID", [("PVOID", "Bcb")]),
    "CcUnpinRepinnedBcb":  ("VOID", [("PVOID", "Bcb"), ("BOOLEAN", "WriteThrough"),
                             ("PIO_STATUS_BLOCK", "IoStatus")]),
    "CcGetFileObjectFromSectionPtrs": ("PFILE_OBJECT", [("PSECTION_OBJECT_POINTERS", "SectionObjectPointers")]),
    "CcGetFileObjectFromBcb": ("PFILE_OBJECT", [("PVOID", "Bcb")]),
    "CcSetAdditionalCacheAttributes": ("VOID", [("PFILE_OBJECT", "FileObject"),
                             ("BOOLEAN", "DisableReadAhead"), ("BOOLEAN", "DisableWriteBehind")]),
    "CcSetLogHandleForFile": ("VOID", [("PFILE_OBJECT", "FileObject"), ("PVOID", "LogHandle"),
                             ("PFLUSH_TO_LSN", "FlushToLsnRoutine")]),
    "CcGetDirtyPages":     ("LARGE_INTEGER", [("PVOID", "LogHandle"),
                             ("PDIRTY_PAGE_ROUTINE", "DirtyPageRoutine"), ("PVOID", "Context1"),
                             ("PVOID", "Context2")]),
    "CcIsThereDirtyData":  ("BOOLEAN", [("PVPB", "Vpb")]),
    "CcZeroData":          ("BOOLEAN", [("PFILE_OBJECT", "FileObject"),
                             ("PLARGE_INTEGER", "StartOffset"), ("PLARGE_INTEGER", "EndOffset"),
                             ("BOOLEAN", "Wait")]),
    "CcCanIWrite":         ("BOOLEAN", [("PFILE_OBJECT", "FileObject"), ("ULONG", "BytesToWrite"),
                             ("BOOLEAN", "Wait"), ("BOOLEAN", "Retrying")]),
    "CcDeferWrite":        ("VOID", [("PFILE_OBJECT", "FileObject"), ("PCC_POST_DEFERRED_WRITE", "PostRoutine"),
                             ("PVOID", "Context1"), ("PVOID", "Context2"),
                             ("ULONG", "BytesToWrite"), ("BOOLEAN", "Retrying")]),
    "CcFastCopyRead":      ("VOID", [("PFILE_OBJECT", "FileObject"), ("ULONG", "FileOffset"),
                             ("ULONG", "Length"), ("ULONG", "PageCount"), ("PVOID", "Buffer"),
                             ("PIO_STATUS_BLOCK", "IoStatus")]),
    "CcFastCopyWrite":     ("VOID", [("PFILE_OBJECT", "FileObject"), ("ULONG", "FileOffset"),
                             ("ULONG", "Length"), ("PVOID", "Buffer")]),
    "CcScheduleReadAhead": ("VOID", [("PFILE_OBJECT", "FileObject"), ("PLARGE_INTEGER", "FileOffset"),
                             ("ULONG", "Length")]),
    # Mm section/cache APIs
    "MmCreateSection":     ("NTSTATUS", [("PVOID*", "SectionObject"), ("ACCESS_MASK", "DesiredAccess"),
                             ("POBJECT_ATTRIBUTES", "ObjectAttributes"), ("PLARGE_INTEGER", "InputMaximumSize"),
                             ("ULONG", "SectionPageProtection"), ("ULONG", "AllocationAttributes"),
                             ("HANDLE", "FileHandle")]),
    "MmDisableModifiedWriteOfSection": ("BOOLEAN", [("PSECTION_OBJECT_POINTERS", "SectionObjectPointers")]),
    "MmFlushImageSection":  ("BOOLEAN", [("PSECTION_OBJECT_POINTERS", "SectionObjectPointers"),
                             ("MMFLUSH_TYPE", "FlushType")]),
    # FsRtl helpers commonly used with Cc*
    "FsRtlNormalizeNtstatus": ("NTSTATUS", [("NTSTATUS", "Exception"), ("NTSTATUS", "GenericException")]),
    "ExRaiseStatus":       ("VOID", [("NTSTATUS", "Status")]),
    "ObDeleteCapturedInsertInfo": ("VOID", [("PVOID", "Object")]),
    "KfRaiseIrql":         ("KIRQL", [("KIRQL", "NewIrql")]),
    "KfLowerIrql":         ("VOID", [("KIRQL", "NewIrql")]),
}

POOL_TYPES = {0: "NonPagedPool", 1: "PagedPool", 2: "NonPagedPoolMustSucceed",
              4: "NonPagedPoolCacheAligned", 5: "PagedPoolCacheAligned"}

IRQL_LEVELS = {0: "PASSIVE_LEVEL", 1: "APC_LEVEL", 2: "DISPATCH_LEVEL",
               27: "PROFILE_LEVEL", 28: "CLOCK1_LEVEL", 29: "CLOCK2_LEVEL",
               30: "IPI_LEVEL", 31: "HIGH_LEVEL"}

DEVICE_TYPES = {
    0x01: "FILE_DEVICE_BEEP", 0x02: "FILE_DEVICE_CD_ROM",
    0x07: "FILE_DEVICE_DISK", 0x08: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x09: "FILE_DEVICE_FILE_SYSTEM", 0x0E: "FILE_DEVICE_DEVICE_CONTROL",
    0x12: "FILE_DEVICE_NETWORK", 0x15: "FILE_DEVICE_NULL",
    0x22: "FILE_DEVICE_UNKNOWN", 0x8000: "FILE_DEVICE_CUSTOM_START",
}

CTL_CODE_METHODS = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT", 2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass
class StackVar:
    offset: int
    size: int
    name: str
    var_type: str
    accesses: int = 0
    struct_type: str = ""


@dataclass
class DecompiledLine:
    address: int
    indent: int
    code: str
    comment: str = ""
    is_label: bool = False


@dataclass
class BasicBlock:
    start_addr: int
    instructions: list = field(default_factory=list)
    successors: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)
    is_loop_header: bool = False


@dataclass
class FunctionInfo:
    name: str
    address: int
    end_address: int = 0
    return_type: str = "NTSTATUS"
    calling_convention: str = "stdcall"
    params: list = field(default_factory=list)
    locals: list = field(default_factory=list)
    stack_frame_size: int = 0
    lines: list = field(default_factory=list)
    is_driver_entry: bool = False
    is_dispatch_routine: bool = False
    detected_patterns: list = field(default_factory=list)
    called_apis: list = field(default_factory=list)
    struct_accesses: dict = field(default_factory=dict)


# ── Helpers ──────────────────────────────────────────────────────────────

def _get_cs32():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def _rva_to_offset(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None


def _resolve_constant(val):
    """Conservative constant resolution — only resolves unambiguous values.
    Small integers (0-0xFF) are NOT resolved because they collide across
    NTSTATUS, POOL_TYPE, IRQL, DEVICE_TYPE, booleans, sizes, etc.
    """
    # NTSTATUS: only resolve severity-flagged codes (info/warning/error)
    # which are unambiguous (>= 0x40000000)
    if val >= 0x40000000 and val in NTSTATUS_CODES:
        return NTSTATUS_CODES[val]
    # STATUS_TIMEOUT (0x102), STATUS_PENDING (0x103) etc. are fairly unique
    if 0x100 <= val <= 0xFFFF and val in NTSTATUS_CODES:
        return NTSTATUS_CODES[val]
    # DBG_EXCEPTION_HANDLED (0x00010001) is unique
    if val == 0x00010001 and val in NTSTATUS_CODES:
        return NTSTATUS_CODES[val]
    # DEVICE_TYPES: only values >= 0x08 are unique enough (avoid 1,2,7)
    if val >= 0x08 and val in DEVICE_TYPES:
        return DEVICE_TYPES[val]
    return None


# Map parameter type names to constant tables for context-aware resolution
_PARAM_TYPE_TABLES = {
    'POOL_TYPE': POOL_TYPES,
    'KIRQL': IRQL_LEVELS,
    'DEVICE_TYPE': DEVICE_TYPES,
    'NTSTATUS': NTSTATUS_CODES,
}


def _resolve_typed_constant(val, param_type):
    """Resolve a constant using the parameter's declared type from API signatures."""
    ptype = param_type.upper()
    for key, table in _PARAM_TYPE_TABLES.items():
        if key in ptype and val in table:
            return table[val]
    return _resolve_constant(val)


def _format_hex(val):
    name = _resolve_constant(val)
    if name:
        return name
    if val > 0xFFFF:
        return f"0x{val:08X}"
    elif val > 9:
        return f"0x{val:X}"
    return str(val)


def _decode_pool_tag(val):
    try:
        b = struct.pack('<I', val & 0xFFFFFFFF)
        if all(0x20 <= c < 0x7F for c in b):
            return b.decode('ascii')
    except Exception:
        pass
    return None


def _decode_ioctl(code):
    device = (code >> 16) & 0xFFFF
    func = (code >> 2) & 0xFFF
    method = code & 3
    access = (code >> 14) & 3
    dev_name = DEVICE_TYPES.get(device, f"0x{device:X}")
    meth_name = CTL_CODE_METHODS.get(method, str(method))
    return f"CTL_CODE({dev_name}, 0x{func:X}, {meth_name}, access={access})"


def _build_import_map(pe):
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports[imp.address] = imp.name.decode('ascii', errors='replace')
    return imports


def _build_export_rva_map(pe):
    exports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.address:
                exports[exp.address] = exp.name.decode('ascii', errors='replace')
    return exports


def _extract_strings(pe, min_len=4):
    strings_map = {}
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        sname = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if sname not in ('.rdata', '.data', '.rsrc', 'INIT', 'PAGE', '.text'):
            continue
        try:
            data = section.get_data()
        except Exception:
            continue
        va_start = base + section.VirtualAddress
        for m in re.finditer(rb'[\x20-\x7e]{4,128}\x00', data):
            s = m.group()[:-1].decode('ascii', errors='replace')
            strings_map[va_start + m.start()] = s
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,128}\x00\x00', data):
            try:
                s = m.group().decode('utf-16-le').rstrip('\x00')
                if s and len(s) >= min_len:
                    strings_map[va_start + m.start()] = f'L"{s}"'
            except Exception:
                pass
    return strings_map


# ══════════════════════════════════════════════════════════════════════════
#  Function Boundary Detector (works without symbols)
# ══════════════════════════════════════════════════════════════════════════

class FunctionFinder:
    PROLOGUES = [
        b'\x8B\xFF\x55\x8B\xEC',  # hotpatch: mov edi,edi; push ebp; mov ebp,esp
        b'\x55\x8B\xEC',          # push ebp; mov ebp, esp
        b'\x55\x89\xE5',          # push ebp; mov ebp, esp (GCC)
    ]

    def __init__(self, pe):
        self.pe = pe
        self.base = pe.OPTIONAL_HEADER.ImageBase

    def find_functions(self, section_name=None):
        funcs = []
        for section in self.pe.sections:
            sname = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if section_name and sname != section_name:
                continue
            if not (section.Characteristics & 0x20000000):
                continue
            data = section.get_data()
            va_base = self.base + section.VirtualAddress
            i = 0
            while i < len(data) - 8:
                found = False
                for pro in self.PROLOGUES:
                    if data[i:i+len(pro)] == pro:
                        if i == 0 or data[i-1] in (0xC3, 0xCC, 0x90, 0xC2, 0xCB):
                            funcs.append(va_base + i)
                            found = True
                            break
                        if i >= 3 and data[i-3] == 0xC2:
                            funcs.append(va_base + i)
                            found = True
                            break
                if found:
                    i += 4
                else:
                    i += 1
        funcs.sort()
        result = []
        for idx, va in enumerate(funcs):
            size = (funcs[idx + 1] - va) if idx + 1 < len(funcs) else 4096
            result.append((va, min(size, 65536)))
        return result


# ══════════════════════════════════════════════════════════════════════════
#  Register Tracker
# ══════════════════════════════════════════════════════════════════════════

class RegisterTracker:
    def __init__(self):
        self.regs = {}
        self.stack_args = []
        self.type_hints = {}

    def reset(self):
        self.regs.clear()
        self.stack_args.clear()
        self.type_hints.clear()

    def track_mov(self, dst, src, src_value=None):
        if src_value is not None:
            self.regs[dst] = src_value
        elif src in self.regs:
            self.regs[dst] = self.regs[src]
        if src in self.type_hints:
            self.type_hints[dst] = self.type_hints[src]

    def track_push(self, operand, value=None, raw_int=None):
        self.stack_args.append((operand, value, raw_int))

    def consume_call_args(self, n_args):
        args = []
        for _ in range(min(n_args, len(self.stack_args))):
            args.append(self.stack_args.pop())
        return args

    def peek_call_args(self, n_args):
        count = min(n_args, len(self.stack_args))
        return list(reversed(self.stack_args[-count:]))


# ══════════════════════════════════════════════════════════════════════════
#  Structure / Driver Pattern Recognition
# ══════════════════════════════════════════════════════════════════════════

def _detect_driver_entry(instructions):
    mj_assigns = 0
    for insn in instructions:
        if insn.mnemonic == 'mov':
            m = re.search(r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
            if m:
                try:
                    off = int(m.group(2), 16)
                    if 0x38 <= off <= 0x38 + 0x1B * 4 and (off - 0x38) % 4 == 0:
                        mj_assigns += 1
                except ValueError:
                    pass
    return mj_assigns >= 2


def _detect_dispatch_routine(instructions, param_count):
    if param_count != 2:
        return False
    for insn in instructions:
        m = re.search(r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+)\]', insn.op_str)
        if m:
            try:
                off = int(m.group(2), 16)
                if off in IRP_FIELDS:
                    return True
            except ValueError:
                pass
    return False


def _detect_loops(blocks_dict):
    loops = []
    for addr, block in blocks_dict.items():
        for succ_addr in block.successors:
            if succ_addr in blocks_dict and succ_addr <= addr:
                body = set()
                for a in blocks_dict:
                    if succ_addr <= a <= addr:
                        body.add(a)
                loops.append((succ_addr, body))
                blocks_dict[succ_addr].is_loop_header = True
    return loops


def _detect_switch(instructions):
    switches = []
    for i in range(len(instructions) - 2):
        insn = instructions[i]
        if insn.mnemonic == 'cmp' and i + 2 < len(instructions):
            next1 = instructions[i + 1]
            next2 = instructions[i + 2]
            if next1.mnemonic == 'ja' and next2.mnemonic == 'jmp':
                m = re.match(r'(\w+),\s*(0x[0-9a-fA-F]+|\d+)', insn.op_str)
                if m:
                    try:
                        n = int(m.group(2), 16) if '0x' in m.group(2) else int(m.group(2))
                        switches.append({'addr': insn.address, 'reg': m.group(1),
                                        'n_cases': n + 1})
                    except (ValueError, IndexError):
                        pass
    return switches


# ══════════════════════════════════════════════════════════════════════════
#  Core Decompiler
# ══════════════════════════════════════════════════════════════════════════

class X86Decompiler:
    def __init__(self, pe_path=None, symbols=None):
        self.md = _get_cs32()
        self.image_base = 0
        self.imports = {}
        self.exports_rva = {}
        self.symbols = symbols or {}
        self.strings = {}
        self.pe_path = pe_path
        self.tracker = RegisterTracker()

        if pe_path:
            pe = pefile.PE(pe_path, fast_load=False)
            self.image_base = pe.OPTIONAL_HEADER.ImageBase
            self.imports = _build_import_map(pe)
            self.exports_rva = _build_export_rva_map(pe)
            self.strings = _extract_strings(pe)
            pe.close()

    def decompile_function(self, code_bytes, start_va, func_name=None, max_insns=5000):
        info = FunctionInfo(
            name=func_name or f"sub_{start_va:08X}",
            address=start_va,
        )
        instructions = list(self.md.disasm(code_bytes, start_va))
        if not instructions:
            info.lines.append(DecompiledLine(start_va, 0, "// Empty function"))
            return info

        trimmed = self._trim_function(instructions, max_insns)
        if trimmed:
            info.end_address = trimmed[-1].address + trimmed[-1].size

        self._analyze_stack_frame(trimmed, info)
        self._detect_convention(trimmed, info)
        self._detect_driver_patterns(trimmed, info)
        self._track_api_calls(trimmed, info)
        self._infer_types(info)

        blocks_dict = self._build_cfg(trimmed)
        loops = _detect_loops(blocks_dict)
        switches = _detect_switch(trimmed)

        if loops:
            info.detected_patterns.append(f"loops:{len(loops)}")
        if switches:
            info.detected_patterns.append(f"switch:{len(switches)}")

        self._generate_pseudocode(blocks_dict, loops, switches, info)
        return info

    def decompile_from_pe(self, pe_path, func_name_or_rva, max_bytes=65536):
        pe = pefile.PE(pe_path, fast_load=False)
        target_rva = None
        display_name = None

        if isinstance(func_name_or_rva, int):
            target_rva = func_name_or_rva
            display_name = self.symbols.get(self.image_base + target_rva,
                                            f"sub_{self.image_base + target_rva:08X}")
        else:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name and exp.name.decode('ascii', errors='replace') == func_name_or_rva:
                        target_rva = exp.address
                        display_name = func_name_or_rva
                        break

        if target_rva is None:
            pe.close()
            return None

        try:
            code = pe.get_data(target_rva, max_bytes)
        except pefile.PEFormatError:
            pe.close()
            return None
        va = target_rva + pe.OPTIONAL_HEADER.ImageBase
        pe.close()

        return self.decompile_function(code, va, display_name)

    def discover_and_decompile(self, pe_path, max_funcs=200):
        pe = pefile.PE(pe_path, fast_load=False)
        finder = FunctionFinder(pe)
        found = finder.find_functions()

        # Also include exported functions
        export_rvas = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.address:
                    export_rvas.add(exp.address)

        pe.close()

        results = {}
        count = 0
        for va, est_size in found:
            if count >= max_funcs:
                break
            rva = va - self.image_base
            finfo = self.decompile_from_pe(pe_path, rva, max_bytes=est_size)
            if finfo:
                results[finfo.name] = finfo
                count += 1

        return results

    # ── Trimming ─────────────────────────────────────────────────────────

    def _trim_function(self, instructions, max_insns):
        result = []
        ret_count = 0
        nop_run = 0
        for i, insn in enumerate(instructions):
            if i >= max_insns:
                break
            if insn.mnemonic == 'int3':
                nop_run += 1
                if nop_run >= 2:
                    break
                continue
            if insn.mnemonic == 'nop':
                nop_run += 1
                if nop_run >= 4:
                    break
                continue
            nop_run = 0
            result.append(insn)
            if insn.group(CS_GRP_RET):
                ret_count += 1
                j = i + 1
                while j < len(instructions) and instructions[j].mnemonic in ('nop', 'int3'):
                    j += 1
                if j < len(instructions):
                    nx = instructions[j]
                    if (nx.mnemonic == 'push' and 'ebp' in nx.op_str) or \
                       (nx.mnemonic == 'mov' and nx.op_str == 'edi, edi'):
                        break
                if ret_count >= 8:
                    break
        return result

    # ── Stack frame ──────────────────────────────────────────────────────

    def _analyze_stack_frame(self, instructions, info):
        frame_size = 0
        has_frame = False
        for idx, insn in enumerate(instructions[:5]):
            if insn.mnemonic == 'push' and 'ebp' in insn.op_str:
                if idx + 1 < len(instructions):
                    nx = instructions[idx + 1]
                    if nx.mnemonic == 'mov' and 'ebp, esp' in nx.op_str:
                        has_frame = True
                        break
            if insn.mnemonic == 'mov' and 'edi, edi' in insn.op_str:
                continue

        if has_frame:
            for insn in instructions[:10]:
                if insn.mnemonic == 'sub' and 'esp' in insn.op_str:
                    parts = insn.op_str.split(',')
                    if len(parts) == 2:
                        v = parts[1].strip()
                        try:
                            frame_size = int(v, 16) if v.startswith('0x') else int(v)
                        except ValueError:
                            pass
                    break

        info.stack_frame_size = frame_size

        local_offsets = set()
        param_offsets = set()
        for insn in instructions:
            for m in re.finditer(r'\[ebp\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', insn.op_str):
                sign, val_str = m.group(1), m.group(2)
                try:
                    offset = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                except ValueError:
                    continue
                if sign == '-':
                    local_offsets.add(offset)
                elif offset >= 8:
                    param_offsets.add(offset)

        for idx2, off in enumerate(sorted(local_offsets)):
            info.locals.append(StackVar(
                offset=-off, size=4,
                name=f"local_{idx2:X}",
                var_type=self._guess_local_type(instructions, off),
            ))

        for off in sorted(param_offsets):
            pnum = (off - 8) // 4
            info.params.append(StackVar(
                offset=off, size=4,
                name=f"param_{pnum}", var_type="PVOID",
            ))

    def _guess_local_type(self, instructions, ebp_offset):
        hex_off = f"0x{ebp_offset:x}"
        for insn in instructions:
            if hex_off not in insn.op_str and str(ebp_offset) not in insn.op_str:
                continue
            if insn.mnemonic in ('cmp', 'test'):
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    v = parts[1].strip()
                    try:
                        val = int(v, 16) if v.startswith('0x') else int(v)
                        if val in NTSTATUS_CODES:
                            return "NTSTATUS"
                    except ValueError:
                        pass
                return "ULONG"
            if insn.mnemonic == 'lea':
                return "PVOID"
        return "ULONG"

    # ── Convention ───────────────────────────────────────────────────────

    def _detect_convention(self, instructions, info):
        for insn in instructions:
            if insn.group(CS_GRP_RET):
                if insn.mnemonic == 'ret' and insn.op_str:
                    try:
                        v = insn.op_str.strip()
                        cleanup = int(v, 16) if v.startswith('0x') else int(v)
                        info.calling_convention = "stdcall"
                        expected = cleanup // 4
                        while len(info.params) < expected:
                            info.params.append(StackVar(
                                offset=8 + len(info.params) * 4, size=4,
                                name=f"param_{len(info.params)}", var_type="PVOID",
                            ))
                    except ValueError:
                        pass
                    return
                elif insn.mnemonic == 'ret':
                    if not info.params:
                        info.calling_convention = "cdecl"
                    return

    # ── Driver patterns ──────────────────────────────────────────────────

    def _detect_driver_patterns(self, instructions, info):
        # Skip DriverEntry heuristic if the function has a known API signature
        # (e.g. Cc* cache manager functions have large struct offsets that
        # falsely match the MajorFunction table heuristic)
        if info.name not in KERNEL_API_SIGNATURES and _detect_driver_entry(instructions):
            info.is_driver_entry = True
            info.detected_patterns.append("DriverEntry")
            info.return_type = "NTSTATUS"
            if len(info.params) >= 1:
                info.params[0].name = "DriverObject"
                info.params[0].var_type = "PDRIVER_OBJECT"
                info.params[0].struct_type = "DRIVER_OBJECT"
            if len(info.params) >= 2:
                info.params[1].name = "RegistryPath"
                info.params[1].var_type = "PUNICODE_STRING"

        if _detect_dispatch_routine(instructions, len(info.params)):
            info.is_dispatch_routine = True
            info.detected_patterns.append("IRP_dispatch")
            info.return_type = "NTSTATUS"
            if len(info.params) >= 1:
                info.params[0].name = "DeviceObject"
                info.params[0].var_type = "PDEVICE_OBJECT"
                info.params[0].struct_type = "DEVICE_OBJECT"
            if len(info.params) >= 2:
                info.params[1].name = "Irp"
                info.params[1].var_type = "PIRP"
                info.params[1].struct_type = "IRP"

        # Detect AddDevice
        creates = attaches = False
        for insn in instructions:
            if insn.group(CS_GRP_CALL):
                name = self._try_resolve_call(insn)
                if name:
                    if 'IoCreateDevice' in name:
                        creates = True
                    if 'IoAttachDeviceToDeviceStack' in name:
                        attaches = True
        if creates and attaches and len(info.params) == 2:
            info.detected_patterns.append("AddDevice")
            if len(info.params) >= 1:
                info.params[0].name = "DriverObject"
                info.params[0].var_type = "PDRIVER_OBJECT"
            if len(info.params) >= 2:
                info.params[1].name = "PhysicalDeviceObject"
                info.params[1].var_type = "PDEVICE_OBJECT"

    def _try_resolve_call(self, insn):
        if insn.operands and insn.operands[0].type == CS_OP_IMM:
            return self._resolve_address(insn.operands[0].imm)
        m = re.search(r'\[(0x[0-9a-fA-F]+)\]', insn.op_str)
        if m:
            addr_val = int(m.group(1), 16)
            if addr_val in self.imports:
                return self.imports[addr_val]
        return None

    # ── API tracking ─────────────────────────────────────────────────────

    def _track_api_calls(self, instructions, info):
        for insn in instructions:
            if insn.group(CS_GRP_CALL):
                name = self._try_resolve_call(insn)
                if name and not name.startswith('sub_') and not name.startswith('loc_'):
                    info.called_apis.append(name)

    # ── Type inference ───────────────────────────────────────────────────

    def _infer_types(self, info):
        # If the function being decompiled has a known signature, apply it
        sig = KERNEL_API_SIGNATURES.get(info.name)
        if sig:
            ret_type, params = sig
            info.return_type = ret_type
            # Clear any wrongly-detected driver patterns
            if info.is_driver_entry and info.name != 'DriverEntry':
                info.is_driver_entry = False
                if 'DriverEntry' in info.detected_patterns:
                    info.detected_patterns.remove('DriverEntry')
            if info.is_dispatch_routine:
                info.is_dispatch_routine = False
                if 'IRP_dispatch' in info.detected_patterns:
                    info.detected_patterns.remove('IRP_dispatch')
            # Rename parameters to match the known signature
            for i, (ptype, pname) in enumerate(params):
                if i < len(info.params):
                    info.params[i].var_type = ptype
                    info.params[i].name = pname
                    info.params[i].struct_type = ''  # clear wrong struct
                    # Set correct struct_type for known pointer types
                    stype = ptype.lstrip('P').rstrip('*')
                    if stype in KNOWN_STRUCTURES:
                        info.params[i].struct_type = stype
                else:
                    p = StackVar(
                        offset=8 + i * 4, size=4,
                        name=pname, var_type=ptype,
                    )
                    stype = ptype.lstrip('P').rstrip('*')
                    if stype in KNOWN_STRUCTURES:
                        p.struct_type = stype
                    info.params.append(p)
            return

        for api in info.called_apis:
            if 'CompleteRequest' in api:
                info.return_type = "NTSTATUS"
                break
            if 'ExAllocatePool' in api:
                info.return_type = "PVOID"
                break
            if 'PsTerminateSystemThread' in api:
                info.return_type = "VOID"
                break

    # ── CFG ──────────────────────────────────────────────────────────────

    def _build_cfg(self, instructions):
        if not instructions:
            return {}

        leaders = {instructions[0].address}
        for insn in instructions:
            if insn.group(CS_GRP_JUMP):
                if insn.operands and insn.operands[0].type == CS_OP_IMM:
                    leaders.add(insn.operands[0].imm)
                leaders.add(insn.address + insn.size)

        blocks = {}
        leader_list = sorted(leaders)
        for insn in instructions:
            block_start = instructions[0].address
            for l in leader_list:
                if l <= insn.address:
                    block_start = l
                else:
                    break
            if block_start not in blocks:
                blocks[block_start] = BasicBlock(start_addr=block_start)
            blocks[block_start].instructions.append(insn)

        for addr, block in blocks.items():
            if not block.instructions:
                continue
            last = block.instructions[-1]
            if last.group(CS_GRP_RET):
                pass
            elif last.group(CS_GRP_JUMP):
                if last.operands and last.operands[0].type == CS_OP_IMM:
                    t = last.operands[0].imm
                    if t in blocks:
                        block.successors.append(t)
                if last.mnemonic != 'jmp':
                    fall = last.address + last.size
                    if fall in blocks:
                        block.successors.append(fall)
            else:
                fall = last.address + last.size
                if fall in blocks:
                    block.successors.append(fall)

        for addr, block in blocks.items():
            for s in block.successors:
                if s in blocks:
                    blocks[s].predecessors.append(addr)
        return blocks

    # ── Pseudocode generation ────────────────────────────────────────────

    def _generate_pseudocode(self, blocks_dict, loops, switches, info):
        lines = info.lines
        indent = 1
        label_targets = set()

        for addr, block in blocks_dict.items():
            for s in block.successors:
                if s != addr + sum(i.size for i in block.instructions):
                    label_targets.add(s)

        loop_headers = {h for h, _ in loops}
        self.tracker.reset()
        # Track indices of push-comment lines so calls can remove them
        self._push_line_indices = []

        for block_addr in sorted(blocks_dict.keys()):
            block = blocks_dict[block_addr]
            if block_addr in loop_headers:
                lines.append(DecompiledLine(block_addr, indent, "while (TRUE) {", comment="loop"))
                indent += 1

            for insn in block.instructions:
                if insn.address in label_targets:
                    lines.append(DecompiledLine(insn.address, 0, f"loc_{insn.address:08X}:", is_label=True))
                line = self._translate_instruction(insn, info, indent, loop_headers)
                if line:
                    if isinstance(line, list):
                        lines.extend(line)
                    else:
                        lines.append(line)

    # ── Instruction translation ──────────────────────────────────────────

    def _translate_instruction(self, insn, info, indent, loop_headers):
        m = insn.mnemonic
        op = insn.op_str
        addr = insn.address

        # Skip prologue/epilogue
        if m == 'push' and op == 'ebp':
            return None
        if m == 'mov' and op in ('ebp, esp', 'edi, edi', 'esp, ebp'):
            return None
        if m == 'sub' and op.startswith('esp,'):
            return None
        if m == 'pop' and op == 'ebp':
            return None
        if m in ('leave', 'nop'):
            return None
        # Skip callee-saved push/pop
        if m == 'push' and op in ('esi', 'edi', 'ebx'):
            return None
        if m == 'pop' and op in ('esi', 'edi', 'ebx'):
            return None

        # ── Push (argument) ──────────────────────────────────────────────
        if m == 'push':
            val = self._resolve_operand(op, info)
            # Store raw integer value for later typed resolution in API calls
            raw_int = None
            op_stripped = op.strip()
            if re.match(r'^-?0x[0-9a-fA-F]+$', op_stripped) or re.match(r'^-?\d+$', op_stripped):
                try:
                    raw_int = int(op_stripped, 16) if '0x' in op_stripped else int(op_stripped)
                    raw_int = raw_int & 0xFFFFFFFF
                except ValueError:
                    pass
            self.tracker.track_push(val, raw_int=raw_int)
            # Pool tag detection
            if re.match(r'^0x[0-9a-fA-F]+$', op.strip()):
                try:
                    nv = int(op.strip(), 16)
                    tag = _decode_pool_tag(nv)
                    if tag:
                        line = DecompiledLine(addr, indent, f"// push '{tag}'", comment=f"tag 0x{nv:08X}")
                        self._push_line_indices.append(len(info.lines))
                        return line
                except ValueError:
                    pass
            line = DecompiledLine(addr, indent, f"// push {val}", comment="arg")
            self._push_line_indices.append(len(info.lines))
            return line

        # ── MOV ──────────────────────────────────────────────────────────
        if m == 'mov':
            dst, src = self._split_ops(op)
            dst_c = self._resolve_operand(dst, info)
            src_c = self._resolve_operand(src, info)
            self.tracker.track_mov(dst.strip(), src.strip())
            sc = self._check_struct_field(op, info)
            return DecompiledLine(addr, indent, f"{dst_c} = {src_c};", comment=sc)

        # ── LEA ──────────────────────────────────────────────────────────
        if m == 'lea':
            dst, src = self._split_ops(op)
            dst_c = self._resolve_operand(dst, info)
            src_c = self._resolve_operand(src, info, lea=True)
            return DecompiledLine(addr, indent, f"{dst_c} = &{src_c};")

        # ── Arithmetic ───────────────────────────────────────────────────
        if m == 'add':
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} += {self._resolve_operand(src, info)};")
        if m == 'sub':
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} -= {self._resolve_operand(src, info)};")
        if m == 'inc':
            return DecompiledLine(addr, indent, f"{self._resolve_operand(op, info)}++;")
        if m == 'dec':
            return DecompiledLine(addr, indent, f"{self._resolve_operand(op, info)}--;")
        if m == 'neg':
            v = self._resolve_operand(op, info)
            return DecompiledLine(addr, indent, f"{v} = -{v};")
        if m == 'not':
            v = self._resolve_operand(op, info)
            return DecompiledLine(addr, indent, f"{v} = ~{v};")
        if m == 'imul':
            parts = op.split(',')
            if len(parts) == 3:
                d, a, b = [self._resolve_operand(p.strip(), info) for p in parts]
                return DecompiledLine(addr, indent, f"{d} = {a} * {b};")
            elif len(parts) == 2:
                d, s = [self._resolve_operand(p.strip(), info) for p in parts]
                return DecompiledLine(addr, indent, f"{d} *= {s};")
            return DecompiledLine(addr, indent, f"eax *= {self._resolve_operand(op, info)};")
        if m in ('div', 'idiv'):
            d = self._resolve_operand(op, info)
            return DecompiledLine(addr, indent, f"eax = edx:eax / {d}; edx = edx:eax % {d};", comment=m)
        if m == 'cdq':
            return DecompiledLine(addr, indent, "edx = (eax < 0) ? -1 : 0;", comment="sign-extend")

        # ── Bitwise ──────────────────────────────────────────────────────
        if m == 'and':
            dst, src = self._split_ops(op)
            if dst.strip() == src.strip():
                return DecompiledLine(addr, indent, f"// test {self._resolve_operand(dst, info)}")
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} &= {self._resolve_operand(src, info)};")
        if m == 'or':
            dst, src = self._split_ops(op)
            if dst.strip() == src.strip():
                return DecompiledLine(addr, indent, f"// test {self._resolve_operand(dst, info)}")
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} |= {self._resolve_operand(src, info)};")
        if m == 'xor':
            dst, src = self._split_ops(op)
            if dst.strip() == src.strip():
                return DecompiledLine(addr, indent, f"{self._resolve_operand(dst, info)} = 0;", comment="xor reg,reg")
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} ^= {self._resolve_operand(src, info)};")
        if m in ('shl', 'sal'):
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} <<= {self._resolve_operand(src, info)};")
        if m in ('shr', 'sar'):
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} >>= {self._resolve_operand(src, info)};")
        if m in ('rol', 'ror'):
            dst, src = self._split_ops(op)
            fn = "_rotl" if m == 'rol' else "_rotr"
            d = self._resolve_operand(dst, info)
            return DecompiledLine(addr, indent, f"{d} = {fn}({d}, {self._resolve_operand(src, info)});")
        if m == 'bswap':
            v = self._resolve_operand(op, info)
            return DecompiledLine(addr, indent, f"{v} = _byteswap_ulong({v});")

        # ── Compare / Test ───────────────────────────────────────────────
        if m == 'cmp':
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"// if ({self._resolve_operand(dst, info)} ??? {self._resolve_operand(src, info)})", comment="cmp")
        if m == 'test':
            dst, src = self._split_ops(op)
            dc = self._resolve_operand(dst, info)
            sc = self._resolve_operand(src, info)
            if dst.strip() == src.strip():
                return DecompiledLine(addr, indent, f"// if ({dc} == 0)", comment="test")
            return DecompiledLine(addr, indent, f"// if ({dc} & {sc})", comment="test")

        # ── Conditional jumps ────────────────────────────────────────────
        if m.startswith('j') and insn.group(CS_GRP_JUMP):
            return self._translate_jump(insn, info, indent, loop_headers)

        # ── CALL ─────────────────────────────────────────────────────────
        if m == 'call':
            return self._translate_call(insn, info, indent)

        # ── RET ──────────────────────────────────────────────────────────
        if m in ('ret', 'retn'):
            c = f"cleanup {op} bytes" if op else ""
            return DecompiledLine(addr, indent, "return eax;", comment=c)

        # ── String ops ───────────────────────────────────────────────────
        if m.startswith('rep '):
            inner = m[4:]
            if inner in ('stosb', 'stosd', 'stosw'):
                return DecompiledLine(addr, indent, "memset(edi, eax, ecx);", comment=m)
            if inner in ('movsb', 'movsd', 'movsw'):
                return DecompiledLine(addr, indent, "memcpy(edi, esi, ecx);", comment=m)
            if inner in ('scasb', 'scasd'):
                return DecompiledLine(addr, indent, "ecx = scan(edi, eax, ecx);", comment=m)
            if inner in ('cmpsb', 'cmpsd'):
                return DecompiledLine(addr, indent, "result = memcmp(esi, edi, ecx);", comment=m)
        if m in ('stosb', 'stosd', 'movsb', 'movsd', 'lodsb', 'lodsd'):
            return DecompiledLine(addr, indent, f"__asm {{ {m} }};")

        # ── MOVZX / MOVSX ───────────────────────────────────────────────
        if m == 'movzx':
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} = (ULONG){self._resolve_operand(src, info)};", comment="zero-ext")
        if m == 'movsx':
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"{self._resolve_operand(dst, info)} = (LONG){self._resolve_operand(src, info)};", comment="sign-ext")

        # ── XCHG / CMPXCHG ──────────────────────────────────────────────
        if m == 'xchg':
            dst, src = self._split_ops(op)
            return DecompiledLine(addr, indent,
                f"XCHG({self._resolve_operand(dst, info)}, {self._resolve_operand(src, info)});")
        if m == 'cmpxchg':
            dst, src = self._split_ops(op)
            d = self._resolve_operand(dst, info)
            s = self._resolve_operand(src, info)
            return DecompiledLine(addr, indent,
                f"if ({d} == eax) {d} = {s}; else eax = {d};", comment="atomic CAS")

        # ── Set / CMov ───────────────────────────────────────────────────
        if m.startswith('cmov'):
            dst, src = self._split_ops(op)
            cond = self._cond_str(m[4:])
            return DecompiledLine(addr, indent,
                f"if ({cond}) {self._resolve_operand(dst, info)} = {self._resolve_operand(src, info)};")
        if m.startswith('set'):
            v = self._resolve_operand(op, info)
            cond = self._cond_str(m[3:])
            return DecompiledLine(addr, indent, f"{v} = ({cond}) ? 1 : 0;")

        # ── INT ──────────────────────────────────────────────────────────
        if m == 'int':
            if '0x2e' in op.lower():
                return DecompiledLine(addr, indent, "/* int 0x2E: NT syscall */;")
            if '3' in op:
                return DecompiledLine(addr, indent, "DbgBreakPoint();")
            return DecompiledLine(addr, indent, f"__asm {{ int {op} }};")
        if m == 'sysenter':
            return DecompiledLine(addr, indent, "/* sysenter: fast syscall */;")
        if m == 'cli':
            return DecompiledLine(addr, indent, "_disable();", comment="clear interrupts")
        if m == 'sti':
            return DecompiledLine(addr, indent, "_enable();", comment="set interrupts")
        if m == 'hlt':
            return DecompiledLine(addr, indent, "__halt();")

        # Lock prefix
        if m.startswith('lock '):
            return DecompiledLine(addr, indent, f"__asm {{ {m} {op} }};", comment="atomic")

        # FPU
        if m.startswith('f'):
            return DecompiledLine(addr, indent, f"__asm {{ {m} {op} }};", comment="FPU")

        # Default
        return DecompiledLine(addr, indent, f"__asm {{ {m} {op} }};")

    # ── Jump translation ─────────────────────────────────────────────────

    def _translate_jump(self, insn, info, indent, loop_headers):
        m = insn.mnemonic
        target = None
        if insn.operands and insn.operands[0].type == CS_OP_IMM:
            target = insn.operands[0].imm
        if target is None:
            return DecompiledLine(insn.address, indent,
                f"goto *{self._resolve_operand(insn.op_str, info)};", comment="indirect")

        # Back-edge → continue
        if target in loop_headers and target <= insn.address:
            if m == 'jmp':
                return DecompiledLine(insn.address, indent, "continue;",
                                     comment=f"loop 0x{target:08X}")
            return DecompiledLine(insn.address, indent,
                f"if ({self._cond_str(m[1:])}) continue;", comment=f"loop 0x{target:08X}")

        label = self._resolve_address(target)
        if m == 'jmp':
            return DecompiledLine(insn.address, indent, f"goto {label};")
        return DecompiledLine(insn.address, indent,
            f"if ({self._cond_str(m[1:])}) goto {label};", comment=m)

    def _cond_str(self, suffix):
        cm = {
            'e': '==', 'z': '==', 'ne': '!=', 'nz': '!=',
            'g': '> (signed)', 'nle': '> (signed)', 'ge': '>= (signed)', 'nl': '>= (signed)',
            'l': '< (signed)', 'nge': '< (signed)', 'le': '<= (signed)', 'ng': '<= (signed)',
            'a': '> (unsigned)', 'nbe': '> (unsigned)', 'ae': '>= (unsigned)', 'nb': '>= (unsigned)', 'nc': '>= (unsigned)',
            'b': '< (unsigned)', 'nae': '< (unsigned)', 'c': '< (unsigned)',
            'be': '<= (unsigned)', 'na': '<= (unsigned)',
            's': 'negative', 'ns': 'non-negative', 'o': 'overflow', 'no': '!overflow',
            'ecxz': 'ecx == 0',
        }
        return cm.get(suffix, suffix)

    # ── Call translation ─────────────────────────────────────────────────

    def _translate_call(self, insn, info, indent):
        func_name = self._try_resolve_call(insn) or f"sub_{insn.address:08X}"
        sig = KERNEL_API_SIGNATURES.get(func_name)

        if sig:
            ret_type, params = sig
            n = len(params)
            pushed = self.tracker.peek_call_args(n)
            args = []
            for i, (pt, pn) in enumerate(params):
                if i < len(pushed):
                    arg_str = str(pushed[i][0])
                    # Re-resolve numeric args using the declared parameter type
                    raw_int = pushed[i][2] if len(pushed[i]) > 2 else None
                    if raw_int is not None:
                        typed_name = _resolve_typed_constant(raw_int, pt)
                        if typed_name:
                            arg_str = typed_name
                    args.append(arg_str)
                else:
                    args.append(f"/* {pt} {pn} */")
            self.tracker.consume_call_args(n)
            # Remove consumed push-comment lines from output
            self._remove_push_lines(info, n)
            call = f"{func_name}({', '.join(args)})"
            if ret_type != "VOID":
                return DecompiledLine(insn.address, indent, f"eax = {call};", comment=f"-> {ret_type}")
            return DecompiledLine(insn.address, indent, f"{call};")

        # Unknown function — still collect pushed args
        n_pushed = len(self.tracker.stack_args)
        if n_pushed > 0:
            pushed = self.tracker.peek_call_args(n_pushed)
            args = [str(p[0]) for p in pushed]
            self.tracker.consume_call_args(n_pushed)
            self._remove_push_lines(info, n_pushed)
            call = f"{func_name}({', '.join(args)})"
        else:
            call = f"{func_name}()"

        is_import = not func_name.startswith('sub_')
        return DecompiledLine(insn.address, indent, f"eax = {call};",
                             comment="imported" if is_import else "")

    def _remove_push_lines(self, info, n_args):
        """Remove the last n_args push-comment lines from info.lines."""
        to_remove = min(n_args, len(self._push_line_indices))
        indices = self._push_line_indices[-to_remove:]
        self._push_line_indices = self._push_line_indices[:-to_remove]
        # Mark lines as None (removing by index shifting is complex)
        for idx in indices:
            if idx < len(info.lines):
                info.lines[idx] = None

    # ── Struct field check ───────────────────────────────────────────────

    def _check_struct_field(self, op_str, info):
        m = re.search(r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+)\]', op_str)
        if not m:
            return ""
        reg = m.group(1).lower()
        # Skip stack frame registers — these are params/locals, not struct ptrs
        if reg in ('ebp', 'esp', 'rbp', 'rsp'):
            return ""
        try:
            offset = int(m.group(2), 16)
        except ValueError:
            return ""
        # Check parameters with known struct types first (high confidence)
        for p in info.params:
            if p.struct_type:
                fields = KNOWN_STRUCTURES.get(p.struct_type, {})
                if offset in fields:
                    ct, fn = fields[offset]
                    return f"{p.name}->{fn} ({ct})"
        # Check register-to-struct tracking from data flow
        if hasattr(info, 'reg_structs') and reg in info.reg_structs:
            stype = info.reg_structs[reg]
            fields = KNOWN_STRUCTURES.get(stype, {})
            if offset in fields:
                ct, fn = fields[offset]
                return f"{stype}->{fn} ({ct})"
        return ""

    # ── Operand resolution ───────────────────────────────────────────────

    def _resolve_operand(self, op_str, info, lea=False):
        op = op_str.strip()
        if re.match(r'^(e[a-z]{2}|[a-d][hlx]|[a-d]l|[a-d]h|[re]?[sb]p|[re]?[sd]i)$', op):
            return op
        if re.match(r'^-?0x[0-9a-fA-F]+$', op) or re.match(r'^-?\d+$', op):
            try:
                val = int(op, 16) if '0x' in op else int(op)
                uval = val & 0xFFFFFFFF
                named = _resolve_constant(uval)
                if named:
                    return named
                if uval in self.strings:
                    s = self.strings[uval]
                    return s if s.startswith('L"') else f'"{s}"'
                if uval > 0x00010000 and (uval >> 16) in DEVICE_TYPES:
                    return _decode_ioctl(uval)
                return _format_hex(uval)
            except ValueError:
                return op

        # [ebp - N] → local
        ml = re.match(r'.*\[ebp\s*-\s*(0x[0-9a-fA-F]+|\d+)\]', op)
        if ml:
            try:
                off = int(ml.group(1), 16) if '0x' in ml.group(1) else int(ml.group(1))
                for v in info.locals:
                    if v.offset == -off:
                        v.accesses += 1
                        return f"&{v.name}" if lea else v.name
                return f"&local_{off:X}" if lea else f"local_{off:X}"
            except ValueError:
                pass

        # [ebp + N] → param
        mp = re.match(r'.*\[ebp\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', op)
        if mp:
            try:
                off = int(mp.group(1), 16) if '0x' in mp.group(1) else int(mp.group(1))
                if off >= 8:
                    for p in info.params:
                        if p.offset == off:
                            p.accesses += 1
                            return p.name
                    return f"param_{(off-8)//4}"
            except ValueError:
                pass

        # [esp + N]
        me = re.match(r'.*\[esp\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', op)
        if me:
            try:
                off = int(me.group(1), 16) if '0x' in me.group(1) else int(me.group(1))
                return f"&stack_{off:X}" if lea else f"stack_{off:X}"
            except ValueError:
                pass

        # [reg + offset] with struct resolution
        mro = re.match(r'.*\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', op)
        if mro:
            reg = mro.group(1)
            try:
                off = int(mro.group(2), 16) if '0x' in mro.group(2) else int(mro.group(2))
                for p in info.params:
                    if p.struct_type:
                        fields = KNOWN_STRUCTURES.get(p.struct_type, {})
                        if off in fields:
                            _, fn = fields[off]
                            return f"&{p.name}->{fn}" if lea else f"{p.name}->{fn}"
                return f"({reg} + {_format_hex(off)})" if lea else f"*({reg} + {_format_hex(off)})"
            except ValueError:
                pass

        # [reg - offset]
        mrs = re.match(r'.*\[(\w+)\s*-\s*(0x[0-9a-fA-F]+|\d+)\]', op)
        if mrs:
            reg = mrs.group(1)
            try:
                off = int(mrs.group(2), 16) if '0x' in mrs.group(2) else int(mrs.group(2))
                return f"({reg} - {_format_hex(off)})" if lea else f"*({reg} - {_format_hex(off)})"
            except ValueError:
                pass

        # [reg*scale + base]
        ms = re.match(r'.*\[(\w+)\s*\*\s*(\d)\s*\+\s*(0x[0-9a-fA-F]+)\]', op)
        if ms:
            return f"&jump_table[{ms.group(1)}]" if lea else f"jump_table[{ms.group(1)}]"

        # [reg]
        md = re.match(r'.*\[(\w+)\]', op)
        if md:
            reg = md.group(1)
            if re.match(r'^0x', reg):
                try:
                    av = int(reg, 16)
                    if av in self.imports:
                        return self.imports[av]
                except ValueError:
                    pass
            return reg if lea else f"*{reg}"

        # Size prefixes
        for pfx in ('dword ptr', 'word ptr', 'byte ptr', 'qword ptr'):
            if pfx in op:
                inner = op.replace(pfx, '').strip()
                r = self._resolve_operand(inner, info, lea)
                if pfx == 'word ptr' and not lea:
                    return f"*(WORD*)({r})"
                if pfx == 'byte ptr' and not lea:
                    return f"*(BYTE*)({r})"
                return r

        return op

    def _split_ops(self, op_str):
        depth = 0
        for i, ch in enumerate(op_str):
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
            elif ch == ',' and depth == 0:
                return op_str[:i], op_str[i + 1:]
        return op_str, ""

    def _resolve_address(self, addr):
        if addr in self.symbols:
            return self.symbols[addr]
        if addr in self.imports:
            return self.imports[addr]
        rva = addr - self.image_base
        if rva in self.exports_rva:
            return self.exports_rva[rva]
        if addr in self.strings:
            return f'/* "{self.strings[addr]}" */'
        # Near-miss symbol lookup: call targets sometimes hit a 2-byte
        # hot-patch prologue (mov edi, edi) just before the real entry
        if self.symbols:
            for delta in (1, 2, -1, -2):
                near = addr + delta
                if near in self.symbols:
                    return self.symbols[near]
        return f"loc_{addr:08X}"


# ══════════════════════════════════════════════════════════════════════════
#  High-level API
# ══════════════════════════════════════════════════════════════════════════

def decompile(pe_path, func_name_or_rva, symbols=None, expand_calls=False):
    dec = X86Decompiler(pe_path, symbols)
    info = dec.decompile_from_pe(pe_path, func_name_or_rva)
    if info is None:
        return None
    result = format_pseudocode(info)

    if expand_calls and info.called_apis:
        # Inline-expand any called functions that are exports in the same PE
        expanded = []
        for api_name in sorted(set(info.called_apis)):
            # Try to decompile it from the same PE (internal exports only)
            sub_info = dec.decompile_from_pe(pe_path, api_name)
            if sub_info:
                expanded.append(f"\n{'─'*60}")
                expanded.append(f"/* ── Expanded: {api_name} (called by {info.name}) ── */")
                expanded.append(format_pseudocode(sub_info))
        if expanded:
            result += "\n" + "\n".join(expanded)

    return result


def decompile_no_symbols(pe_path, max_funcs=50):
    dec = X86Decompiler(pe_path)
    results = {}
    infos = dec.discover_and_decompile(pe_path, max_funcs=max_funcs)
    for name, finfo in infos.items():
        results[name] = format_pseudocode(finfo)
    return results


def format_pseudocode(info):
    lines = []
    lines.append("/*")
    lines.append(f" * Decompiled: {info.name}")
    lines.append(f" * Address:    0x{info.address:08X}")
    if info.end_address:
        lines.append(f" * Size:       0x{info.end_address - info.address:X} bytes")
    lines.append(f" * Convention: {info.calling_convention}")
    lines.append(f" * Stack frame: 0x{info.stack_frame_size:X} bytes")
    if info.detected_patterns:
        lines.append(f" * Patterns:   {', '.join(info.detected_patterns)}")
    if info.called_apis:
        lines.append(f" * APIs called: {', '.join(sorted(set(info.called_apis)))}")
    lines.append(" */")
    lines.append("")

    param_strs = [f"{p.var_type} {p.name}" for p in info.params] or ["VOID"]
    proto = f"{info.return_type} {info.calling_convention.upper()} {info.name}("
    if len(param_strs) <= 3:
        lines.append(proto + ", ".join(param_strs) + ")")
    else:
        lines.append(proto)
        for i, ps in enumerate(param_strs):
            comma = "," if i < len(param_strs) - 1 else ")"
            lines.append(f"    {ps}{comma}")

    lines.append("{")
    if info.locals:
        for v in info.locals:
            sc = f"  /* {v.struct_type} */" if v.struct_type else ""
            lines.append(f"    {v.var_type} {v.name};{sc}")
        lines.append("")

    for dl in info.lines:
        if dl is None:
            continue
        ind = "    " * max(dl.indent, 1)
        if dl.is_label:
            lines.append(f"\n{dl.code}")
        elif dl.comment:
            lines.append(f"{ind}{dl.code:<60s} /* {dl.comment} */")
        else:
            lines.append(f"{ind}{dl.code}")

    lines.append("}")
    return "\n".join(lines)


def batch_decompile(pe_path, func_names=None, symbols=None, max_funcs=100):
    pe = pefile.PE(pe_path, fast_load=False)
    if func_names is None:
        func_names = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    func_names.append(exp.name.decode('ascii', errors='replace'))
    pe.close()

    dec = X86Decompiler(pe_path, symbols)
    results = {}
    for i, name in enumerate(func_names):
        if i >= max_funcs:
            break
        finfo = dec.decompile_from_pe(pe_path, name)
        if finfo:
            results[name] = format_pseudocode(finfo)
    return results
