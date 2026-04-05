#ifndef _TEB_WIN2K_H
#define _TEB_WIN2K_H

/* TEB - Windows 2000 SP4 */
/* Total size: 0xF88 (3976 bytes) */
typedef struct _TEB {
    NT_TIB                                   NtTib;  /* offset 0x000, size 0x1C */
    PVOID                                    EnvironmentPointer;  /* offset 0x01C, size 0x4 */
    CLIENT_ID                                ClientId;  /* offset 0x020, size 0x8 */
    PVOID                                    ActiveRpcHandle;  /* offset 0x028, size 0x4 */
    PVOID                                    ThreadLocalStoragePointer;  /* offset 0x02C, size 0x4 */
    PPEB                                     ProcessEnvironmentBlock;  /* offset 0x030, size 0x4 */
    ULONG                                    LastErrorValue;  /* offset 0x034, size 0x4 */
    ULONG                                    CountOfOwnedCriticalSections;  /* offset 0x038, size 0x4 */
    PVOID                                    CsrClientThread;  /* offset 0x03C, size 0x4 */
    PVOID                                    Win32ThreadInfo;  /* offset 0x040, size 0x4 */
    ULONG[26]                                User32Reserved[26];  /* offset 0x044, size 0x68 */
    ULONG[5]                                 UserReserved[5];  /* offset 0x0AC, size 0x14 */
    PVOID                                    WOW32Reserved;  /* offset 0x0C0, size 0x4 */
    LCID                                     CurrentLocale;  /* offset 0x0C4, size 0x4 */
    ULONG                                    FpSoftwareStatusRegister;  /* offset 0x0C8, size 0x4 */
    PVOID[54]                                SystemReserved1[54];  /* offset 0x0CC, size 0xD8 */
    NTSTATUS                                 ExceptionCode;  /* offset 0x1A4, size 0x4 */
    PVOID                                    ActivationContextStack;  /* offset 0x1A8, size 0x4 */
    UCHAR[24]                                SpareBytes1[24];  /* offset 0x1AC, size 0x18 */
    ULONG                                    GdiTebBatch_Offset;  /* offset 0x1C4, size 0x4 */
    UCHAR _padding_1C8[1300];  /* offset 0x1C8 */
    HANDLE                                   RealClientId_UniqueProcess;  /* offset 0x6DC, size 0x4 */
    HANDLE                                   RealClientId_UniqueThread;  /* offset 0x6E0, size 0x4 */
    PVOID                                    GdiCachedProcessHandle;  /* offset 0x6E4, size 0x4 */
    ULONG                                    GdiClientPID;  /* offset 0x6E8, size 0x4 */
    ULONG                                    GdiClientTID;  /* offset 0x6EC, size 0x4 */
    PVOID                                    GdiThreadLocalInfo;  /* offset 0x6F0, size 0x4 */
    ULONG[62]                                Win32ClientInfo[62];  /* offset 0x6F4, size 0xF8 */
    PVOID[233]                               glDispatchTable[233];  /* offset 0x7EC, size 0x3A4 */
    ULONG[29]                                glReserved1[29];  /* offset 0xB68, size 0x74 */
    PVOID                                    glReserved2;  /* offset 0xBDC, size 0x4 */
    PVOID                                    glSectionInfo;  /* offset 0xBE0, size 0x4 */
    PVOID                                    glSection;  /* offset 0xBE4, size 0x4 */
    PVOID                                    glTable;  /* offset 0xBE8, size 0x4 */
    PVOID                                    glCurrentRC;  /* offset 0xBEC, size 0x4 */
    PVOID                                    glContext;  /* offset 0xBF0, size 0x4 */
    NTSTATUS                                 LastStatusValue;  /* offset 0xBF4, size 0x4 */
    UNICODE_STRING                           StaticUnicodeString;  /* offset 0xBF8, size 0x8 */
    WCHAR[261]                               StaticUnicodeBuffer[261];  /* offset 0xC00, size 0x20A */
    UCHAR _padding_E0A[2];  /* offset 0xE0A */
    PVOID                                    DeallocationStack;  /* offset 0xE0C, size 0x4 */
    PVOID[64]                                TlsSlots[64];  /* offset 0xE10, size 0x100 */
    LIST_ENTRY                               TlsLinks;  /* offset 0xF10, size 0x8 */
    PVOID                                    Vdm;  /* offset 0xF18, size 0x4 */
    PVOID                                    ReservedForNtRpc;  /* offset 0xF1C, size 0x4 */
    PVOID[2]                                 DbgSsReserved[2];  /* offset 0xF20, size 0x8 */
} TEB, *PTEB;

#endif /* _TEB_WIN2K_H */
