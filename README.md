## **⚠️ DISCLAIMER: EDUCATIONAL PURPOSE ONLY ⚠️**
This repository is intended for educational purposes only. The techniques demonstrated here are meant to help security professionals understand and defend against malicious activities. Unauthorized use of these techniques on systems you do not own or have explicit permission to test is illegal and unethical. Always ensure you have proper authorization before conducting any security testing.

# Overview
This project focuses on multi-layered EDR evasion across both kernel-mode (Ring 0) and userland (Ring 3) using a **BYOVD (Bring Your Own Vulnerable Driver)** approach.

Rather than terminating security processes—which immediately triggers tamper protection and alerts security monitors—this project focuses on **blinding** the EDR. By cutting off kernel telemetry sources and bypassing userland API hooks, the security agent remains loaded, signed, and seemingly healthy while generating zero alerts.

This is achieved through three main techniques:
1. **Callback Redirecting** (Kernel)
2. **ETW-TI Nulling** (Kernel)
3. **Indirect Syscalls** (Userland)

## Architecture
The architecture is built around exploiting `RTCore64.sys` (**CVE-2019-16098**), a legitimate, digitally signed driver that exposes arbitrary kernel memory read/write primitives via `DeviceIoControl`. 

Once the driver and payload DLL are dropped from a byte array to disk and the driver is loaded into Ring 0, the program defeats KASLR by leaking the `ntoskrnl.exe` base address and executes the blinding routines before injecting a reverse shell DLL into a `SYSTEM`-privileged `svchost.exe` process.

### 1. Kernel R/W Primitive & The 4-Byte Constraint
The vulnerable driver exposes three primary IOCTLs:
* `0x80002048` — Read primitive
* `0x8000204c` — Write primitive
* `0x80002030` - Read any MSR

**Constraint:** These IOCTLs only allow reading and writing up to **4 bytes (`DWORD`)** per call, whereas x64 kernel pointers are **8 bytes (`QWORD`)**. Overwriting an 8-byte pointer in two separate 4-byte writes introduces a critical race condition: if the kernel invokes the pointer between the first and second write, it will dereference a half-written address and cause a BSOD. All kernel patches in this project are specifically designed to operate within a single 4-byte write operation.

### 2. Callback Redirecting
Windows maintains three fixed-size arrays in the `.data` section of `ntoskrnl.exe` to notify registered kernel drivers about system events:
* `PspCreateProcessNotifyRoutine` (Process creation/termination)
* `PspCreateThreadNotifyRoutine` (Thread creation/termination)
* `PspLoadImageNotifyRoutine` (DLL/EXE image loads)

Each entry in these arrays points to an undocumented `_EX_CALLBACK_ROUTINE_BLOCK` structure:

| Offset | Field | Description |
| :--- | :--- | :--- |
| `+0x00` | `RundownRef` | Reference count + flag bits |
| `+0x08` | `Function` | Actual callback function pointer |
| `+0x10` | `Context` | Context parameter (usually NULL) |

Instead of zeroing out the `Function` pointer (which causes a BSOD when called), we redirect it to a `xor eax, eax; ret` gadget so the callback immediately returns `STATUS_SUCCESS` without executing the EDR's inspection logic.

**The Patching Process:**
1. Iterate through the callback arrays and extract each `Function` address.
2. Traverse `PsLoadedModuleList` to verify whether the function belongs to a known EDR driver (`FnAddress >= DllBase && FnAddress < DllBase + DllImageSize`), ensuring critical OS callbacks remain untouched.
3. Verify that the target EDR callback and the `xor eax, eax; ret` gadget share the upper 4 bytes of their 64-bit virtual address.
4. Overwrite only the lower 4 bytes of the `Function` pointer in a single atomic IOCTL write.

### 3. ETW-TI Nulling
`Microsoft-Windows-Threat-Intelligence` (ETW-TI) is the kernel sensor responsible for reporting behavioral telemetry (such as remote memory allocation, cross-process writes, and thread hijacking) to userland EDR agents.

The kernel emits these events through the global handle `EtwThreatIntProvRegHandle`, which follows this internal pointer chain:
* `EtwThreatIntProvRegHandle` ➔ `_ETW_REG_ENTRY` (`+0x20 GuidEntry`) ➔ `_ETW_GUID_ENTRY` (`+0x60 ProviderEnableInfo`) ➔ `EnableMask` (1 Byte).

Before emitting an event, the dispatcher checks the `EnableMask` field. To avoid the 8-byte pointer race condition on the global handle itself:
1. Traverse the pointer chain starting from `EtwThreatIntProvRegHandle`.
2. Validate the provider's GUID to ensure offsets have not shifted across Windows builds.
3. Zero out the `EnableMask` byte, cleanly disabling the entire TI provider.
4. Read back the memory address to confirm the patch landed before proceeding to injection.

### 4. Indirect Syscalls & Payload Execution
To bypass userland hooks placed on `ntdll.dll` during the injection phase, the loader uses **Indirect Syscalls** ([detailed repo here](https://github.com/ofri09bs/Indirect-Syscall-Injection)). By preparing the parameters and SSN in registers and jumping directly to the `syscall` instruction address inside `ntdll.dll`, execution appears to originate legitimately from `ntdll.dll`.

With both kernel callbacks/ETW-TI blinded and userland hooks bypassed, the loader escalates to `SeDebugPrivilege` and injects the payload DLL ([detailed repo here](https://github.com/ofri09bs/DLL-Injection)) into `svchost.exe`.
