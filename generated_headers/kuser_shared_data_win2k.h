#ifndef _KUSER_SHARED_DATA_WIN2K_H
#define _KUSER_SHARED_DATA_WIN2K_H

/* KUSER_SHARED_DATA - Windows 2000 SP4 */
/* Total size: 0x300 (768 bytes) */
typedef struct _KUSER_SHARED_DATA {
    ULONG                                    TickCountLow;  /* offset 0x000, size 0x4 */
    ULONG                                    TickCountMultiplier;  /* offset 0x004, size 0x4 */
    KSYSTEM_TIME                             InterruptTime;  /* offset 0x008, size 0x8 */
    UCHAR _padding_010[4];  /* offset 0x010 */
    KSYSTEM_TIME                             SystemTime;  /* offset 0x014, size 0x8 */
    UCHAR _padding_01C[4];  /* offset 0x01C */
    KSYSTEM_TIME                             TimeZoneBias;  /* offset 0x020, size 0x8 */
    UCHAR _padding_028[4];  /* offset 0x028 */
    USHORT                                   ImageNumberLow;  /* offset 0x02C, size 0x2 */
    USHORT                                   ImageNumberHigh;  /* offset 0x02E, size 0x2 */
    WCHAR[260]                               NtSystemRoot[260];  /* offset 0x030, size 0x208 */
    ULONG                                    MaxStackTraceDepth;  /* offset 0x238, size 0x4 */
    ULONG                                    CryptoExponent;  /* offset 0x23C, size 0x4 */
    ULONG                                    TimeZoneId;  /* offset 0x240, size 0x4 */
    ULONG[8]                                 Reserved2[8];  /* offset 0x244, size 0x4 */
    UCHAR _padding_248[28];  /* offset 0x248 */
    NT_PRODUCT_TYPE                          NtProductType;  /* offset 0x264, size 0x4 */
    BOOLEAN                                  ProductTypeIsValid;  /* offset 0x268, size 0x1 */
    UCHAR _padding_269[3];  /* offset 0x269 */
    ULONG                                    NtMajorVersion;  /* offset 0x26C, size 0x4 */
    ULONG                                    NtMinorVersion;  /* offset 0x270, size 0x4 */
    BOOLEAN[64]                              ProcessorFeatures[64];  /* offset 0x274, size 0x40 */
    ULONG                                    Reserved1;  /* offset 0x2B4, size 0x4 */
    ULONG                                    Reserved3;  /* offset 0x2B8, size 0x4 */
    ULONG                                    TimeSlip;  /* offset 0x2BC, size 0x4 */
    ALTERNATIVE_ARCHITECTURE_TYPE            AlternativeArchitecture;  /* offset 0x2C0, size 0x4 */
    UCHAR _padding_2C4[4];  /* offset 0x2C4 */
    LARGE_INTEGER                            SystemExpirationDate;  /* offset 0x2C8, size 0x8 */
    ULONG                                    SuiteMask;  /* offset 0x2D0, size 0x4 */
    BOOLEAN                                  KdDebuggerEnabled;  /* offset 0x2D4, size 0x1 */
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

#endif /* _KUSER_SHARED_DATA_WIN2K_H */
