#ifndef _PEB_WIN2K_H
#define _PEB_WIN2K_H

/* PEB - Windows 2000 SP4 */
/* Total size: 0x1E8 (488 bytes) */
typedef struct _PEB {
    BOOLEAN                                  InheritedAddressSpace;  /* offset 0x000, size 0x1 */
    BOOLEAN                                  ReadImageFileExecOptions;  /* offset 0x001, size 0x1 */
    BOOLEAN                                  BeingDebugged;  /* offset 0x002, size 0x1 */
    BOOLEAN                                  SpareBool;  /* offset 0x003, size 0x1 */
    HANDLE                                   Mutant;  /* offset 0x004, size 0x4 */
    PVOID                                    ImageBaseAddress;  /* offset 0x008, size 0x4 */
    PPEB_LDR_DATA                            Ldr;  /* offset 0x00C, size 0x4 */
    PRTL_USER_PROCESS_PARAMETERS             ProcessParameters;  /* offset 0x010, size 0x4 */
    PVOID                                    SubSystemData;  /* offset 0x014, size 0x4 */
    PVOID                                    ProcessHeap;  /* offset 0x018, size 0x4 */
    PRTL_CRITICAL_SECTION                    FastPebLock;  /* offset 0x01C, size 0x4 */
    PVOID                                    FastPebLockRoutine;  /* offset 0x020, size 0x4 */
    PVOID                                    FastPebUnlockRoutine;  /* offset 0x024, size 0x4 */
    ULONG                                    EnvironmentUpdateCount;  /* offset 0x028, size 0x4 */
    PVOID                                    KernelCallbackTable;  /* offset 0x02C, size 0x4 */
    ULONG                                    SystemReserved;  /* offset 0x030, size 0x4 */
    ULONG                                    AtlThunkSListPtr32;  /* offset 0x034, size 0x4 */
    PPEB_FREE_BLOCK                          FreeList;  /* offset 0x038, size 0x4 */
    ULONG                                    TlsExpansionCounter;  /* offset 0x03C, size 0x4 */
    PVOID                                    TlsBitmap;  /* offset 0x040, size 0x4 */
    ULONG[2]                                 TlsBitmapBits[2];  /* offset 0x044, size 0x8 */
    PVOID                                    ReadOnlySharedMemoryBase;  /* offset 0x04C, size 0x4 */
    PVOID                                    ReadOnlySharedMemoryHeap;  /* offset 0x050, size 0x4 */
    PPVOID                                   ReadOnlyStaticServerData;  /* offset 0x054, size 0x4 */
    PVOID                                    AnsiCodePageData;  /* offset 0x058, size 0x4 */
    PVOID                                    OemCodePageData;  /* offset 0x05C, size 0x4 */
    PVOID                                    UnicodeCaseTableData;  /* offset 0x060, size 0x4 */
    ULONG                                    NumberOfProcessors;  /* offset 0x064, size 0x4 */
    ULONG                                    NtGlobalFlag;  /* offset 0x068, size 0x4 */
    UCHAR _padding_06C[4];  /* offset 0x06C */
    LARGE_INTEGER                            CriticalSectionTimeout;  /* offset 0x070, size 0x8 */
    ULONG                                    HeapSegmentReserve;  /* offset 0x078, size 0x4 */
    ULONG                                    HeapSegmentCommit;  /* offset 0x07C, size 0x4 */
    ULONG                                    HeapDeCommitTotalFreeThreshold;  /* offset 0x080, size 0x4 */
    ULONG                                    HeapDeCommitFreeBlockThreshold;  /* offset 0x084, size 0x4 */
    ULONG                                    NumberOfHeaps;  /* offset 0x088, size 0x4 */
    ULONG                                    MaximumNumberOfHeaps;  /* offset 0x08C, size 0x4 */
    PPVOID                                   ProcessHeaps;  /* offset 0x090, size 0x4 */
    PVOID                                    GdiSharedHandleTable;  /* offset 0x094, size 0x4 */
    PVOID                                    ProcessStarterHelper;  /* offset 0x098, size 0x4 */
    ULONG                                    GdiDCAttributeList;  /* offset 0x09C, size 0x4 */
    PVOID                                    LoaderLock;  /* offset 0x0A0, size 0x4 */
    ULONG                                    OSMajorVersion;  /* offset 0x0A4, size 0x4 */
    ULONG                                    OSMinorVersion;  /* offset 0x0A8, size 0x4 */
    USHORT                                   OSBuildNumber;  /* offset 0x0AC, size 0x2 */
    USHORT                                   OSCSDVersion;  /* offset 0x0AE, size 0x2 */
    ULONG                                    OSPlatformId;  /* offset 0x0B0, size 0x4 */
    ULONG                                    ImageSubsystem;  /* offset 0x0B4, size 0x4 */
    ULONG                                    ImageSubsystemMajorVersion;  /* offset 0x0B8, size 0x4 */
    ULONG                                    ImageSubsystemMinorVersion;  /* offset 0x0BC, size 0x4 */
    ULONG                                    ImageProcessAffinityMask;  /* offset 0x0C0, size 0x4 */
    ULONG[34]                                GdiHandleBuffer[34];  /* offset 0x0C4, size 0x88 */
    PVOID                                    PostProcessInitRoutine;  /* offset 0x14C, size 0x4 */
    PVOID                                    TlsExpansionBitmap;  /* offset 0x150, size 0x4 */
    ULONG[32]                                TlsExpansionBitmapBits[32];  /* offset 0x154, size 0x80 */
    ULONG                                    SessionId;  /* offset 0x1D4, size 0x4 */
    ULARGE_INTEGER                           AppCompatFlags;  /* offset 0x1D8, size 0x8 */
    ULARGE_INTEGER                           AppCompatFlagsUser;  /* offset 0x1E0, size 0x8 */
} PEB, *PPEB;

#endif /* _PEB_WIN2K_H */
