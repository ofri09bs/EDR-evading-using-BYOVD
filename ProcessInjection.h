#ifndef PROCESS_INJECTION_H
#define PROCESS_INJECTION_H

#include <Windows.h>

#define SE_DEBUG_PRIVILEGE      20L   // LUID { LowPart=20, HighPart=0 }

BOOL IsSystemProcess(HANDLE hProcess);
int writeDLLToFile(const char* dllPath, unsigned char* dllPayload, size_t dllSize);
int locateTarget(const char* targetProcName);
char* getUserName();
int setDebugPrivileges();
int injectProcess(DWORD targetPID, const char* dllPath);


#endif // !PROCESS_INJECTION_H

