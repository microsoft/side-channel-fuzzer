.intel_syntax noprefix
.section .data.main
.function_main_0:
    mov rax, 0x11
    mov qword ptr [r14 + 0x100], rax
    .macro.switch.actor2.function_a2_0:

# entered from actor2: both loads must read main's data area
.macro.fault_handler:
    mov rbx, qword ptr [r14 + 0x100]
    mov rcx, qword ptr [rsp]
    nop

.section .data.actor2
.function_a2_0:
    mov qword ptr [r14 + 0x100], 0x22
    ud2

.section .data.main
.test_case_exit:
