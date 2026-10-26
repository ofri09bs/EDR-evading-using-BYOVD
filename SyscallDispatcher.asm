.code

DynamicSyscallDispatcher PROC
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15

    ; RCX = CALL_CONTEXT*
    ; RDX = SYSCALL_TABLE_ENTRY*

    ; Load SSN and syscall instruction address
    movzx eax, word ptr [rdx + 14h]   ; SyscallSsn
    mov r11, qword ptr [rdx + 8h]     ; pInstrAddress

    ; Load ArgumentCount correctly (offset 0x00)
    mov r12d, dword ptr [rcx + 0h]
    cmp r12d, 4
    jle AllocateSimpleStack

    ; Dynamic stack for >4 arguments
    mov r13d, r12d
    sub r13d, 4
    mov r14d, r13d
    shl r14d, 3
    add r14d, 40                      ; 32 shadow + 8 padding
    sub rsp, r14
    and rsp, 0FFFFFFFFFFFFFFF0h

    lea r14, [rcx + 28h]              ; Arguments[4] (correct offset)
    lea r15, [rsp + 20h]              ; 5th arg goes at RSP+0x20 before call
CopyArgsLoop:
    mov r10, qword ptr [r14]
    mov qword ptr [r15], r10
    add r14, 8
    add r15, 8
    dec r13d
    jnz CopyArgsLoop
    jmp SetRegisters                  ; skip simple allocation

AllocateSimpleStack:
    sub rsp, 32
    and rsp, 0FFFFFFFFFFFFFFF0h

SetRegisters:
    ; Correct argument offsets
    mov r10, qword ptr [rcx + 8h]     ; Arg1 -> R10
    mov rdx, qword ptr [rcx + 10h]    ; Arg2 -> RDX
    mov r8,  qword ptr [rcx + 18h]    ; Arg3 -> R8
    mov r9,  qword ptr [rcx + 20h]    ; Arg4 -> R9

    call r11

    ; Epilogue
    lea rsp, [rbp - 20h]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

DynamicSyscallDispatcher ENDP

END