#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <ctype.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <intrin.h>
#include "IndirectSyscall.h"

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)


// String Hashing algorithm
#define INITIAL_SEED	7
UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		CHAR c = String[Index++];

		c = (CHAR)tolower((unsigned char)c);

		Hash += (UINT8)c;
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))


PSYSCALL_TABLE InitSyscallTable(void)
{
	PSYSCALL_TABLE Table = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSCALL_TABLE));

	if (Table == NULL)
		return NULL;

	Table->TableHead = NULL;

	return Table;
}

// Adds a syscall entry struct to the table
BOOL AddSyscallTableEntry(PSYSCALL_TABLE Table, PVOID SyscallFuncAddr, PVOID SyscallInstrAddr, UINT32 SysHash, WORD SyscallSsn) {

	if (Table == NULL || SyscallFuncAddr == NULL || SysHash == 0 || SyscallSsn == 0 || SyscallInstrAddr == NULL) {
		return FALSE;
	}

	// Create the new syscall entry
	PSYSCALL_TABLE_ENTRY NewSyscall = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSCALL_TABLE_ENTRY));
	if (NewSyscall == NULL)
		return FALSE;

	NewSyscall->Hash = SysHash;
	NewSyscall->pFuncAddress = SyscallFuncAddr;
	NewSyscall->pInstrAddress = SyscallInstrAddr;
	NewSyscall->SyscallSsn = SyscallSsn;
	NewSyscall->NextSyscall = NULL;

	if (Table->TableHead == NULL)
	{
		Table->TableHead = NewSyscall;
		return TRUE;
	}

	PSYSCALL_TABLE_ENTRY CurrSyscall = Table->TableHead;
	while (CurrSyscall->NextSyscall != NULL)
	{
		CurrSyscall = CurrSyscall->NextSyscall;
	}

	CurrSyscall->NextSyscall = NewSyscall;
	return TRUE;
}

// Find and creates new syscall entry for a given syscall
BOOL CreateSyscallEntry(UINT32 SyscallNameHash, PSYSCALL_TABLE Table) {

	HMODULE hModule = GetModuleHandleW(L"NTDLL.DLL");
	PVOID SyscallFuncAddress = NULL, SyscallInstrAddress = NULL;
	WORD SyscallSsn;

	if (hModule == NULL || SyscallNameHash == NULL || Table == NULL)
		return NULL;

	// Getting NTDLL export table and functions name,ordinal and address arrays
	PBYTE pDllBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pDllBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pDllBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pDllBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD FunctionNameArray = (PDWORD)(pDllBase + pImgExportDir->AddressOfNames);
	PWORD FunctionOrdinalArray = (PWORD)(pDllBase + pImgExportDir->AddressOfNameOrdinals);
	PDWORD FunctionAddressArray = (PDWORD)(pDllBase + pImgExportDir->AddressOfFunctions);

	// finding the wanted syscall by its hash
	for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {

		CHAR* pFunctionName = (CHAR*)(pDllBase + FunctionNameArray[i]);
		PVOID pFunctionAddress = (PVOID)(pDllBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (SyscallNameHash == HASHA(pFunctionName)) {
			SyscallFuncAddress = pFunctionAddress;

			DWORD offset = 0; // offset in the syscall function if it has been hooked
			BOOL foundInstr = FALSE, foundSsn = FALSE;

			while (offset <= 0xF8 && !(foundInstr && foundSsn)) {

				// check if ret, in this case we are also probably too far
				if (*((PBYTE)pFunctionAddress + offset) == 0xc3) {
					return FALSE;
				}

				// check if syscall
				if (*((PBYTE)pFunctionAddress + offset) == 0x0f && *((PBYTE)pFunctionAddress + offset + 1) == 0x05) {
					SyscallInstrAddress = (PBYTE)pFunctionAddress + offset;
					foundInstr = TRUE;
				}

				// First opcodes should be :
				// MOV R10, RCX
				// MOV EAX, <syscall>
				if (*((PBYTE)pFunctionAddress + offset) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + offset) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + offset) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + offset) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + offset) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + offset) == 0x00) {

					BYTE high = *((PBYTE)pFunctionAddress + 5 + offset);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + offset);

					SyscallSsn = (high << 8) | low;
					foundSsn = TRUE;
				}
				offset++;
			}

			// We couldnt find the correct SSN or syscall instruction address
			if (!foundInstr || !foundSsn)
				return FALSE;

			printf("[+] Found %s with SSN %u at %p\n", pFunctionName, SyscallSsn, SyscallFuncAddress);

			if (!AddSyscallTableEntry(Table, SyscallFuncAddress, SyscallInstrAddress, SyscallNameHash, SyscallSsn))
				return FALSE;

			return TRUE;
		}
	}
	return FALSE;
}

// Gets an entry from the table by hash
PSYSCALL_TABLE_ENTRY GetSyscallEntry(PSYSCALL_TABLE Table, UINT32 SyscallHash) {
	PSYSCALL_TABLE_ENTRY CurrSyscall = Table->TableHead;
	while (CurrSyscall != NULL) {
		if (CurrSyscall->Hash == SyscallHash) {
			return CurrSyscall;
		}
		CurrSyscall = CurrSyscall->NextSyscall;
	}
	return NULL;
}

// The extrnal assembly function 
extern NTSTATUS DynamicSyscallDispatcher(CALL_CONTEXT* Context, SYSCALL_TABLE_ENTRY* SyscallTarget);

// The main function that preforms indirect syscall calling
NTSTATUS IndirectSyscall(PSYSCALL_TABLE Table, UINT32 SyscallHash, CALL_CONTEXT* ctx) {
	PSYSCALL_TABLE_ENTRY SyscallEntry = GetSyscallEntry(Table, SyscallHash);
	if (SyscallEntry == NULL) {
		printf("[x] Couldnt find the Syscall entry");
		return FALSE;
	}

	NTSTATUS status = DynamicSyscallDispatcher(ctx, SyscallEntry);
	return status;
}

void PrintSyscallTable(PSYSCALL_TABLE Table)
{
	if (Table == NULL)
	{
		printf("[-] Table is NULL\n");
		return;
	}

	PSYSCALL_TABLE_ENTRY Current = Table->TableHead;
	int Index = 0;

	printf("\n========== SYSCALL TABLE ==========\n");

	while (Current != NULL)
	{
		printf("\n[Entry %d]\n", Index);
		printf("  Address      : %p\n", (void*)Current);
		printf("  FuncAddress  : %p\n", Current->pFuncAddress);
		printf("  InstrAddress : %p\n", Current->pInstrAddress);
		printf("  Hash         : 0x%08X\n", Current->Hash);
		printf("  Syscall SSN  : %u\n", (unsigned int)Current->SyscallSsn);
		printf("  Next         : %p\n", (void*)Current->NextSyscall);

		Current = Current->NextSyscall;
		Index++;
	}

	printf("\n===================================\n");
}


VOID DebugPrint(PCALL_CONTEXT Ctx)
{
	if (Ctx == NULL)
	{
		printf("[-] CALL_CONTEXT is NULL\n");
		return;
	}

	printf("\n========== CALL CONTEXT ==========\n");
	printf("ArgumentCount: %lu\n", (unsigned long)Ctx->ArgumentCount);

	if (Ctx->ArgumentCount > 16)
	{
		printf("[-] Invalid ArgumentCount: %lu\n",
			(unsigned long)Ctx->ArgumentCount);
		return;
	}

	for (DWORD i = 0; i < Ctx->ArgumentCount; i++)
	{
		printf("Argument[%lu]: 0x%016llX\n",
			(unsigned long)i,
			(unsigned long long)Ctx->Arguments[i]);
	}

	printf("==================================\n");
}

void FreeSyscallTable(PSYSCALL_TABLE Table)
{
	if (Table == NULL) return;

	PSYSCALL_TABLE_ENTRY cur = Table->TableHead;
	while (cur) {
		PSYSCALL_TABLE_ENTRY nxt = cur->NextSyscall;
		HeapFree(GetProcessHeap(), 0, cur);
		cur = nxt;
	}
	HeapFree(GetProcessHeap(), 0, Table);
}

void IndirectClose(PSYSCALL_TABLE Table, HANDLE h)
{
	if (h == NULL) return;

	CALL_CONTEXT ctx = { 0 };
	ctx.ArgumentCount = 1;
	ctx.Arguments[0] = (UINT64)h;
	IndirectSyscall(Table, HASHA("NtClose"), &ctx);
}
