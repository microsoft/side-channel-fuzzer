/// File: Configuration and use of Intel VMX
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/io.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/tlbflush.h>
#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "fault_handler.h"
#include "main.h"
#include "page_tables_guest.h"
#include "special_registers.h"
#include "vmx.h"
#include "vmx_config.h"

// NOLINTBEGIN(readability-function-size)
// NOLINTBEGIN(readability-function-cognitive-complexity)
// Justification: these functions directly follow VMX implementation steps as per Intel SDM;
// therefore, they are allowed to be complex

#define CHECK_VMFAIL(src)                                                                          \
    ASSERT(err_inv == 0, src);                                                                     \
    ASSERT(err_val == 0, src);

bool vmx_is_on = false;     // global
uint64_t *vmcs_hpas = NULL; // global

static bool orig_vmxon_state = false;
static uint64_t orig_vmcs_ptr = 0;

static void *vmxon_page_hva = NULL;
static uint64_t vmxon_page_hpa = 0;

static vmcs_t *vmcss = NULL;

static uint64_t supported_vmcs_pin_ctrl = 0;
static uint64_t supported_vmcs_primary_ctrl = 0;
static uint64_t supported_vmcs_secondary_ctrl = 0;

static int set_vmcs_guest_state(void);
static int set_vmcs_host_state(void);
static int set_vmcs_exec_control(int actor_id);
static int set_vmcs_exit_control(void);
static int set_vmcs_entry_control(void);
static int make_vmcs_launched(int actor_id);
static void print_vmlaunch_error_info(int err_inv, int err_val, int actor_id);

// =================================================================================================
// Error decoding
// =================================================================================================
static const char *vmx_instruction_error_to_str[] = {
    "Unknown error: 0",
    "VMXERR_VMCALL_IN_VMX_ROOT_OPERATION",
    "VMXERR_VMCLEAR_INVALID_ADDRESS",
    "VMXERR_VMCLEAR_VMXON_POINTER",
    "VMXERR_VMLAUNCH_NONCLEAR_VMCS",
    "VMXERR_VMRESUME_NONLAUNCHED_VMCS",
    "VMXERR_VMRESUME_AFTER_VMXOFF",
    "VMXERR_ENTRY_INVALID_CONTROL_FIELD",
    "VMXERR_ENTRY_INVALID_HOST_STATE_FIELD",
    "VMXERR_VMPTRLD_INVALID_ADDRESS",
    "VMXERR_VMPTRLD_VMXON_POINTER",
    "VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID",
    "VMXERR_UNSUPPORTED_VMCS_COMPONENT",
    "VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT",
    "VMXERR_VMXON_IN_VMX_ROOT_OPERATION",
    "VMXERR_ENTRY_INVALID_EXECUTIVE_VMCS_POINTER",
    "VMXERR_ENTRY_NONLAUNCHED_EXECUTIVE_VMCS",
    "VMXERR_ENTRY_EXECUTIVE_VMCS_POINTER_NOT_VMXON_POINTER",
    "VMXERR_VMCALL_NONCLEAR_VMCS",
    "VMXERR_VMCALL_INVALID_VM_EXIT_CONTROL_FIELDS",
    "VMXERR_VMCALL_INCORRECT_MSEG_REVISION_ID",
    "VMXERR_VMXOFF_UNDER_DUAL_MONITOR_TREATMENT_OF_SMIS_AND_SMM",
    "VMXERR_VMCALL_INVALID_SMM_MONITOR_FEATURES",
    "VMXERR_ENTRY_INVALID_VM_EXECUTION_CONTROL_FIELDS_IN_EXECUTIVE_VMCS",
    "VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS",
    "VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID",
    NULL};

typedef struct {
    uint16_t basic_exit_reason;
    const char *str;
} vmx_basic_exit_reason_t;

static vmx_basic_exit_reason_t vmx_basic_exit_reason_to_str[] = {VMX_EXIT_REASONS, {0, NULL}};

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Runs VMXON and indicates whether it failed
/// @param err_inv Set if VMXOFF failed due to VMfailInvalid
/// @param err_val Set if VMXOFF failed due to VMfailValid
static inline void vmxon(uint64_t phys, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmxon %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(phys)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

/// @brief Runs VMXOFF and indicates whether it failed
/// @param err_inv Set if VMXOFF failed due to VMfailInvalid
/// @param err_val Set if VMXOFF failed due to VMfailValid
static inline void vmxoff(uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmxoff; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

static inline void vmptrst(uint64_t *dest, uint8_t *err_inv, uint8_t *err_val)
{
    uint64_t tmp = 0;
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmptrst %[tmp]; setc %[inval]; setz %[val]\n"
                         : [tmp] "=m"(tmp), [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *dest = tmp;
    *err_inv = inv;
    *err_val = val;
}

static inline void vmptrld(uint64_t vmcs_hpa, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmptrld %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

static inline void vmclear(uint64_t vmcs_hpa, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    __asm__ __volatile__("vmclear %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

static inline void vmread(uint64_t field, uint64_t *dest, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, val = 0;
    uint64_t dest_local = 0;
    __asm__ __volatile__("vmread %[field], %[dest]; setc %[inval]; setz %[val]\n"
                         : [dest] "=rm"(dest_local), [val] "=rm"(val), [inval] "=rm"(inv)
                         : [field] "r"(field)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
    *dest = dest_local;
}

static inline void vmwrite(uint64_t field, uint64_t value, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv = 0, valid = 0;
    __asm__ __volatile__("vmwrite %[value], %[field]; setc %[inval]; setz %[valid]\n"
                         : [valid] "=rm"(valid), [inval] "=rm"(inv)
                         : [field] "r"(field), [value] "rm"(value)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = valid;
}
#define CHECKED_VMWRITE(field, value)                                                              \
    {                                                                                              \
        vmwrite(field, value, &err_inv, &err_val);                                                 \
        CHECK_VMFAIL("CHECKED_VMWRITE");                                                           \
    }

static int check_vmx_controls(uint32_t options, uint32_t msr)
{
    uint64_t msr_value = rdmsr64(msr);
    uint32_t mask_low = msr_value & 0xFFFFFFFF; // 1 low bits indicate must-one
    uint32_t mask_high = msr_value >> 32;       // zero high bits indicate must-zero

    if ((~options & mask_low) || (options & ~mask_high)) {
        PRINT_ERR("VMX MSR 0x%x: bits not supported (value 0x%x, mask l-0x%x h-0x%x)\n", msr,
                  options, mask_low, mask_high);
        return -1;
    }

    return 0;
}

#define VMWRITE_GUEST_SEGMENT(segment, selector, base, limit, ar)                                  \
    {                                                                                              \
        CHECKED_VMWRITE(GUEST_##segment##_SELECTOR, selector);                                     \
        CHECKED_VMWRITE(GUEST_##segment##_BASE, base);                                             \
        CHECKED_VMWRITE(GUEST_##segment##_LIMIT, limit);                                           \
        CHECKED_VMWRITE(GUEST_##segment##_AR_BYTES, ar);                                           \
    }

// =================================================================================================
// VMX management interface
// (functions exposed to the rest of the executor)
// =================================================================================================

/// @brief Check whether the target CPU is compatible with our implementation of VMX management
/// @return 0 is compatible, -1 otherwise
int vmx_check_cpu_compatibility(void)
{
    uint64_t msr_value = 0;

    // Check if VMX is supported
    ASSERT_MSG(cpu_has(cpuinfo, X86_FEATURE_VMX), "vmx_check_cpu_compatibility",
               "VMX is not supported on this CPU");

    // Control registers
    uint64_t cr0 = read_cr0();
    uint64_t cr4 = __read_cr4();
    uint64_t efer = rdmsr64(MSR_EFER);
    ASSERT((cr0 & X86_CR0_PE) != 0, "set_vmcs_guest_state");
    ASSERT((cr0 & X86_CR0_PG) != 0, "set_vmcs_guest_state");
    ASSERT((cr4 & X86_CR4_PAE) != 0, "set_vmcs_guest_state");
    ASSERT((efer & EFER_LME) != 0, "set_vmcs_guest_state");
    ASSERT((efer & EFER_LMA) != 0, "set_vmcs_guest_state");

    // True controls are usable
    msr_value = rdmsr64(MSR_IA32_VMX_BASIC);
    ASSERT((msr_value & VMX_BASIC_TRUE_CTLS) != 0, "vmx_check_cpu_compatibility");

    // Pin-based controls
    supported_vmcs_pin_ctrl = rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    ASSERT((supported_vmcs_pin_ctrl & MUST_CLEAR_PIN_BASED_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Primary processor-based controls
    supported_vmcs_primary_ctrl = rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    ASSERT((supported_vmcs_primary_ctrl & MUST_CLEAR_PRIMARY_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Secondary
    supported_vmcs_secondary_ctrl = rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS2);
    ASSERT((supported_vmcs_secondary_ctrl & MUST_CLEAR_SECONDARY_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Exit/entry
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_EXIT_CTLS);
    ASSERT((msr_value & MUST_CLEAR_EXIT_CTRL) == 0, "vmx_check_cpu_compatibility");
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    ASSERT((msr_value & MUST_CLEAR_ENTRY_CTRL) == 0, "vmx_check_cpu_compatibility");

    return 0;
}

/// @brief Enable VMX operation and do VMXON
/// @return 0 on success, negative error code on failure
int start_vmx_operation(void)
{
    uint8_t err_inv = 0, err_val = 0;

    orig_vmxon_state = ((orig_special_registers_state->cr4 & X86_CR4_VMXE) != 0);
    unsigned long cr4 = __read_cr4();
    unsigned long cr0 = read_cr0();

    if (!orig_vmxon_state) {
        // Note: registers are already configured in special_registers.c:set_msrs_for_vmx

        // Check SDM 24.8 "restrictions on VMX operation" and 24.7 "Enabling and entering VMX"
        ASSERT(((cr0 & rdmsr64(MSR_IA32_VMX_CR0_FIXED1)) | rdmsr64(MSR_IA32_VMX_CR0_FIXED0)) == cr0,
               "start_vmx_operation");
        ASSERT((cr4 | X86_CR4_VMXE) == cr4, "start_vmx_operation");

        // Configure IA32_FEATURE_CONTROL MSR to allow VMXON
        //   Bit 0: Lock bit. If clear, VMXON causes a #GP.
        //   Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
        //          outside of SMX causes a #GP.
        uint64_t feature_control = rdmsr64(MSR_FEATURE_CONTROL);
        uint64_t required = FEATURE_VMX_ENABLED_OUTSIDE_SMX | FEATURE_CTL_LOCKED;
        if ((feature_control & required) != required)
            wrmsr64(MSR_FEATURE_CONTROL, feature_control | required);

        // Prepare VMXON region:
        // (source: SDM, 25.11.5 VMXON Region)
        // - Write the revision identifier into bits 30:0, and clear bit 31
        memset(vmxon_page_hva, 0, VMXON_SIZE);
        ((vmxon_region_t *)vmxon_page_hva)->revision_id = rdmsr64(MSR_IA32_VMX_BASIC);
        ((vmxon_region_t *)vmxon_page_hva)->reserved_31 = 0;

        // Run VMXON
        vmxon(vmxon_page_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("vmx_start_operation");
    }

    vmx_is_on = true;
    return 0;
}

/// @brief Disable VMX operation and do VMXOFF
/// Should never fail as this function can be used in exception handlers;
/// instead, it will print warning upon error.
/// @return void
void stop_vmx_operation(void)
{
    // PRINT_ERR("Stopping VMX operation\n");
    uint8_t err_inv = 0, err_val = 0;

    // Run VMXOFF
    if (vmx_is_on && !orig_vmxon_state) {
        // Flush all EPT TLB entries before vmxoff to ensure no stale EPT translations remain
        uint64_t invept_desc[2] = {0, 0};
        asm volatile("invept %0, %1" : : "m"(invept_desc), "r"(2ULL) : "cc", "memory");

        vmxoff(&err_inv, &err_val);
        orig_vmxon_state = false;
    }

    vmx_is_on = false;
    if (err_inv || err_val)
        PRINT_ERRS("stop_vmx_operation", "Exited with VMfailInvalid=%d, VMfailValid=%d\n", err_inv,
                   err_val);
}

/// @brief Restore the VMCS state that was active when we started
/// @param void
/// @return 0 on success, negative error code on failure
int store_orig_vmcs_state(void)
{
    if (!orig_vmxon_state)
        return 0; // VMX was not in use when we started; nothing to store

    uint8_t err_inv = 0, err_val = 0;
    vmptrst(&orig_vmcs_ptr, &err_inv, &err_val);
    CHECK_VMFAIL("store_orig_vmcs_state");
    return 0;
}

/// @brief VMCLEAR every VMCS used by the test case
/// Leaving a launched VMCS current would let the processor keep cached in-processor state for it,
/// which the SDM requires to be flushed before the VMCS is reused or used on another CPU.
/// @return void
void clear_vmcs_state(void)
{
    uint8_t err_inv = 0, err_val = 0;

    if (!vmx_is_on || !vmcs_hpas)
        return;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        if (actors[actor_id].mode != MODE_GUEST || vmcs_hpas[actor_id] == 0)
            continue;

        vmclear(vmcs_hpas[actor_id], &err_inv, &err_val);
        if (err_inv || err_val)
            PRINT_ERRS("clear_vmcs_state", "Exited with VMfailInvalid=%d, VMfailValid=%d\n",
                       err_inv, err_val);
    }
}

/// @brief Restore the VMCS state that was active when we started
/// Should never fail as this function can be used in exception handlers;
/// instead, it prints warnings upon errors.
/// @return void
void restore_orig_vmcs_state(void)
{
    uint8_t err_inv = 0, err_val = 0;
    if (!orig_vmxon_state || orig_vmcs_ptr == 0xFFFFFFFFFFFFFFFF)
        return;

    if (!vmx_is_on) {
        PRINT_ERR("ERROR: attempting to restore VMX state while VMX is not on\n");
        return;
    }

    if (!orig_vmcs_ptr) {
        PRINT_ERR("ERROR: attempting to restore VMX state but no state was stored\n");
        return;
    }

    vmptrld(orig_vmcs_ptr, &err_inv, &err_val);
    if (err_inv || err_val)
        PRINT_ERRS("restore_orig_vmcs_state", "Exited with VMfailInvalid=%d, VMfailValid=%d\n",
                   err_inv, err_val);
}

int set_vmcs_state(void)
{
    int err = 0;
    uint8_t err_inv = 0, err_val = 0;

    ASSERT(n_actors <= MAX_ACTORS, "set_vmcs_state:n_actors exceeds MAX_ACTORS");

    // initialize VMCSs for all guest actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        vmcs_t *vmcs_hva = &vmcss[actor_id];
        uint64_t vmcs_hpa = vmalloc_to_phys(vmcs_hva);
        ASSERT(vmcs_hpa != 0, "set_vmcs_state:vmalloc_to_phys");
        vmcs_hpas[actor_id] = vmcs_hpa;

        // initialize VMCS revision identifier
        memset(vmcs_hva, 0, VMCS_SIZE);
        vmcs_hva->revision_id = rdmsr64(MSR_IA32_VMX_BASIC);
        vmcs_hva->abort_indicator = 0;

        // load VMCS
        vmclear(vmcs_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("set_vmcs_state:vmclear");

        vmptrld(vmcs_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("set_vmcs_state:vmptrld");

        // set VMCS fields
        err = set_vmcs_guest_state();
        CHECK_ERR("set_vmcs_guest_state");

        err = set_vmcs_host_state();
        CHECK_ERR("set_vmcs_host_state");

        err = set_vmcs_exec_control(actor_id);
        CHECK_ERR("set_vmcs_exec_control");

        err = set_vmcs_exit_control();
        CHECK_ERR("set_vmcs_exit_control");

        err = set_vmcs_entry_control();
        CHECK_ERR("set_vmcs_entry_control");

        err = make_vmcs_launched(actor_id);
        CHECK_ERR("set_vmcs_state:make_vmcs_launched");
    }

    return 0;
}

static int set_vmcs_guest_state(void)
{
    uint8_t err_inv = 0, err_val = 0;
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

    // SDM 25.4 Guest-State Area
    // - Control registers
    uint64_t cr0 = (read_cr0() | MUST_SET_BITS_CR0_VMX_GUEST) & ~MUST_CLEAR_BITS_CR0_VMX_GUEST;
    uint64_t cr4 = (__read_cr4() | MUST_SET_BITS_CR4_VMX_GUEST) & ~MUST_CLEAR_BITS_CR4_VMX_GUEST;
    CHECKED_VMWRITE(GUEST_CR0, cr0);
    CHECKED_VMWRITE(GUEST_CR3, (uint64_t)&guest_p_memory->guest_page_tables.l4[0]);
    CHECKED_VMWRITE(GUEST_CR4, cr4);

    // - Debug register
    CHECKED_VMWRITE(GUEST_DR7, 0x400);

    // - RSP, RIP, and RFLAGS
    // (see also make_vmcs_launched)
    CHECKED_VMWRITE(GUEST_RSP, (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(GUEST_RIP, (uint64_t)&guest_v_memory->vmlaunch_page[0]);
    CHECKED_VMWRITE(GUEST_RFLAGS, (X86_EFLAGS_FIXED));

    // - Segments (values mainly based on https://www.sandpile.org/x86/initial.htm)
    VMWRITE_GUEST_SEGMENT(CS, 0x10, 0, 0xFFFF, 0xa09B);
    VMWRITE_GUEST_SEGMENT(SS, 0x20, 0, 0xFFFF, 0xc093);
    VMWRITE_GUEST_SEGMENT(DS, 0, 0, 0xFFFF, 0x10000); // 0xc093
    VMWRITE_GUEST_SEGMENT(ES, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(FS, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(GS, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(LDTR, 0, 0, 0xFFFF, 0x10000); // 0xc082);
    VMWRITE_GUEST_SEGMENT(TR, 0, 0, 0xFFFF, 0x8b);

    // - GDTR and IDTR (left empty for the time being; attempt to use will cause VM exit)
    CHECKED_VMWRITE(GUEST_GDTR_BASE, (uint64_t)&guest_v_memory->gdt);
    CHECKED_VMWRITE(GUEST_GDTR_LIMIT, 0xFFFF);
    CHECKED_VMWRITE(GUEST_IDTR_BASE, 0);
    CHECKED_VMWRITE(GUEST_IDTR_LIMIT, 0xFFFF);

    // - MSRs
    CHECKED_VMWRITE(GUEST_IA32_DEBUGCTL, 0);
    CHECKED_VMWRITE(GUEST_SYSENTER_CS, 0x10);
    CHECKED_VMWRITE(GUEST_SYSENTER_ESP,
                    (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(GUEST_SYSENTER_EIP, (uint64_t)&guest_v_memory->code.section[0]);

    ASSERT((VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL & MUST_CLEAR_ENTRY_CTRL) != 0,
           "set_vmcs_guest_state");
    ASSERT((VM_ENTRY_LOAD_IA32_PAT & MUST_CLEAR_ENTRY_CTRL) != 0, "set_vmcs_guest_state");
    ASSERT((VM_ENTRY_LOAD_IA32_EFER & MUST_CLEAR_ENTRY_CTRL) != 0, "set_vmcs_guest_state");

    // SDM 25.4.2 Guest Non-Register State
    CHECKED_VMWRITE(GUEST_ACTIVITY_STATE, 0);
    CHECKED_VMWRITE(GUEST_INTERRUPTIBILITY_INFO, 0b1000); // block NMI
    CHECKED_VMWRITE(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    CHECKED_VMWRITE(VMCS_LINK_POINTER, -1LL);
    CHECKED_VMWRITE(VMX_PREEMPTION_TIMER_VALUE, 0xFFFF); // FIXME: make configurable

    return 0;
}

static int set_vmcs_host_state(void)
{
    uint8_t err_inv = 0, err_val = 0;

    // get TR, GDTR, IDTR and LDTR bases (will be necessary later, in several places)
    uint64_t tr = 0, ldtr = 0;
    struct desc_ptr gdtr, idtr;
    asm volatile("str %[tr]\n"
                 "sgdt %[gdtr]\n"
                 "sidt %[idtr]\n"
                 "sldt %[ldtr]\n"
                 : [tr] "=r"(tr), [gdtr] "=m"(gdtr), [idtr] "=m"(idtr), [ldtr] "=r"(ldtr)
                 :
                 : "memory");
    struct ldttss_desc *tr_register = (struct ldttss_desc *)(gdtr.address + tr);
    uint64_t tr_base = ((uint64_t)tr_register->base0 | ((tr_register->base1) << 16) |
                        ((tr_register->base2) << 24) | ((uint64_t)tr_register->base3 << 32));

    // SDM 25.5 Host-State Area
    // - Control registers
    CHECKED_VMWRITE(HOST_CR0, read_cr0());
    CHECKED_VMWRITE(HOST_CR3, __read_cr3());
    CHECKED_VMWRITE(HOST_CR4, __read_cr4());

    // - RSP and RIP
    // set later (make_vmcs_launched)

    // - Segment selectors
    CHECKED_VMWRITE(HOST_CS_SELECTOR, __KERNEL_CS);
    CHECKED_VMWRITE(HOST_SS_SELECTOR, __KERNEL_DS);
    CHECKED_VMWRITE(HOST_DS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_ES_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_FS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_GS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_TR_SELECTOR, tr);

    // - Segment bases
    CHECKED_VMWRITE(HOST_FS_BASE, rdmsr64(MSR_FS_BASE));
    CHECKED_VMWRITE(HOST_GS_BASE, rdmsr64(MSR_GS_BASE));
    CHECKED_VMWRITE(HOST_TR_BASE, tr_base);
    CHECKED_VMWRITE(HOST_GDTR_BASE, gdtr.address);
    CHECKED_VMWRITE(HOST_IDTR_BASE, test_case_idtr.address);

    // - MSRs
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));
    CHECKED_VMWRITE(HOST_IA32_EFER, rdmsr64(MSR_EFER));

    ASSERT((VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL & MUST_CLEAR_EXIT_CTRL) != 0, "set_vmcs_host_state");
    ASSERT((VM_EXIT_LOAD_IA32_PAT & MUST_CLEAR_EXIT_CTRL) != 0, "set_vmcs_host_state");
    return 0;
}

static int set_vmcs_exec_control(int actor_id)
{
    // int err = 0;
    uint8_t err_inv = 0, err_val = 0;

    // SDM 25.6.1 Pin-Based VM-Execution Controls
    uint32_t pin_based_vm_exec_control = MUST_SET_PIN_BASED_VM_EXEC_CONTROL |
                                         (rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(pin_based_vm_exec_control, MSR_IA32_VMX_TRUE_PINBASED_CTLS))
        return -1;
    CHECKED_VMWRITE(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control);

    // SDM 25.6.2 Processor-Based VM-Execution Controls
    // - primary
    uint32_t primary_vm_exec_control = MUST_SET_PRIMARY_VM_EXEC_CONTROL |
                                       (rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(primary_vm_exec_control, MSR_IA32_VMX_TRUE_PROCBASED_CTLS))
        return -1;
    CHECKED_VMWRITE(CPU_BASED_VM_EXEC_CONTROL, primary_vm_exec_control);

    // - secondary
    uint32_t secondary_vm_exec_control = MUST_SET_SECONDARY_VM_EXEC_CONTROL |
                                         (rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS2) & 0xFFFFFFFFULL);
    if (check_vmx_controls(secondary_vm_exec_control, MSR_IA32_VMX_PROCBASED_CTLS2))
        return -1;
    CHECKED_VMWRITE(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control);

    // SDM 25.6.3 Exception Bitmap
    CHECKED_VMWRITE(EXCEPTION_BITMAP, DEFAULT_EXCEPTION_BITMAP);

    // SDM 25.6.4 I/O-Bitmap Addresses
    ASSERT((CPU_BASED_USE_IO_BITMAPS & primary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.5 Time-Stamp Counter Offset and Multiplier
    ASSERT((CPU_BASED_USE_TSC_OFFSETTING & primary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.6 Guest/Host Masks and Read Shadows for CR0 and CR4
    uint64_t cr0 = read_cr0();
    uint64_t cr4 = __read_cr4();
    CHECKED_VMWRITE(CR0_GUEST_HOST_MASK, cr0);
    CHECKED_VMWRITE(CR4_GUEST_HOST_MASK, cr4);
    CHECKED_VMWRITE(CR0_READ_SHADOW, cr0);
    CHECKED_VMWRITE(CR4_READ_SHADOW, cr4);

    // SDM 25.6.7 CR3-Target Controls
    CHECKED_VMWRITE(CR3_TARGET_COUNT, 0);

    // SDM 25.6.8 Controls for APIC Virtualization
    ASSERT((SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES & secondary_vm_exec_control) == 0,
           "set_vmcs_exec_control");

    // SDM 25.6.9 MSR-Bitmap Address
    ASSERT((CPU_BASED_USE_MSR_BITMAPS & primary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.10 Executive-VMCS Pointer
    // (no idea, leaving it blank for the time being)

    // SDM 25.6.11 Extended-Page-Table Pointer (EPTP)
    CHECKED_VMWRITE(EPT_POINTER, ((uint64_t *)ept_ptr)[actor_id]);

    // SDM 25.6.12 Virtual-Processor Identifier (VPID)
    ASSERT((SECONDARY_EXEC_ENABLE_VPID & secondary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.13 Controls for PAUSE-Loop Exiting
    // not implemented

    // SDM 25.6.14 VM-Functions
    ASSERT((SECONDARY_EXEC_ENABLE_VMFUNC & secondary_vm_exec_control) == 0,
           "set_vmcs_exec_control");

    // SDM 25.6.15 VMCS Shadowing Bitmap Addresses
    ASSERT((SECONDARY_EXEC_SHADOW_VMCS & secondary_vm_exec_control) == 0, "set_vmcs_exec_control");

    // SDM 25.6.16 ENCLS-Exiting Bitmap
    if (supported_vmcs_secondary_ctrl & SECONDARY_EXEC_ENCLS_EXITING) {
        ASSERT((SECONDARY_EXEC_ENCLS_EXITING & secondary_vm_exec_control) != 0,
               "set_vmcs_exec_control");
        CHECKED_VMWRITE(ENCLS_EXITING_BITMAP, 0x0FFFFFFFFFFFFFFFULL);
    }

    // Misc. features (25.6.14--23) are disabled
    return 0;
}

static int set_vmcs_exit_control(void)
{
    uint8_t err_inv = 0, err_val = 0;

    uint64_t exit_ctls =
        MUST_SET_EXIT_CTRL | (rdmsr64(MSR_IA32_VMX_TRUE_EXIT_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(exit_ctls, MSR_IA32_VMX_TRUE_EXIT_CTLS))
        return -1;
    CHECKED_VMWRITE(VM_EXIT_CONTROLS, exit_ctls);

    // SDM 25.7.2 VM-Exit Controls for MSRs
    CHECKED_VMWRITE(VM_EXIT_MSR_STORE_COUNT, 0);
    CHECKED_VMWRITE(VM_EXIT_MSR_LOAD_COUNT, 0);
    return 0;
}

static int set_vmcs_entry_control(void)
{
    uint8_t err_inv = 0, err_val = 0;

    uint64_t entry_ctls =
        MUST_SET_ENTRY_CTRL | (rdmsr64(MSR_IA32_VMX_TRUE_ENTRY_CTLS) & 0xFFFFFFFFULL);
    if (check_vmx_controls(entry_ctls, MSR_IA32_VMX_TRUE_ENTRY_CTLS))
        return -1;
    CHECKED_VMWRITE(VM_ENTRY_CONTROLS, entry_ctls);

    // SDM 25.8.2 VM-Entry Controls for MSRs
    CHECKED_VMWRITE(VM_ENTRY_MSR_LOAD_COUNT, 0);

    // SDM 25.8.3 VM-Entry Controls for Event Injection
    CHECKED_VMWRITE(VM_ENTRY_INTR_INFO_FIELD, 0);

    return 0;
}

static int make_vmcs_launched(int actor_id)
{
    uint8_t err_inv = 0, err_val = 0;

    // 1. Load VMCS
    uint64_t vmcs_hpa = vmcs_hpas[actor_id];
    vmptrld(vmcs_hpa, &err_inv, &err_val);
    CHECK_VMFAIL("make_vmcs_launched:vmptrld");

    // 2. Launch VM
    //
    // Note 1: HOST_RIP and HOST_RSP must be set in assembly to capture the correct
    // return address and stack pointer for VM exit. After VM exit, guest may have
    // modified any general-purpose registers, so we clobber all caller-saved regs.
    //
    // Note 2: If vmlaunch succeeds, it transfers control to guest and the setc/setz
    // instructions are skipped. On VM exit, we return to label 1 with err flags = 0.
    // If vmlaunch fails, setc/setz execute and we jump to label 1 with error flags set.
    asm volatile(""
                 "xor %[inval], %[inval]\n"
                 "xor %[val], %[val]\n"
                 "lea 1f(%%rip), %%rax\n"
                 "mov %[host_rip], %%rcx\n"
                 "vmwrite %%rax, %%rcx\n"
                 "mov %%rsp, %%rax\n"
                 "mov %[host_rsp], %%rcx\n"
                 "vmwrite %%rax, %%rcx\n"
                 "vmlaunch\n"
                 "setc %[inval]\n"
                 "setz %[val]\n"
                 "1:\n"
                 : [val] "+rm"(err_val), [inval] "+rm"(err_inv)
                 : [host_rip] "i"((uint64_t)HOST_RIP), [host_rsp] "i"((uint64_t)HOST_RSP)
                 : "cc", "memory", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");

    // 3. If vmlaunch failed, print error info
    if (err_inv || err_val) {
        print_vmlaunch_error_info(err_inv, err_val, actor_id);
    }
    CHECK_VMFAIL("make_vmcs_launched:vmlaunch");

    // 4. Check that the launch was successful (abort indicator check)
    ASSERT(vmcss[actor_id].abort_indicator == 0, "make_vmcs_launched:abort_indicator");
    uint64_t exit_reason = 0;
    vmread(VM_EXIT_REASON, &exit_reason, &err_inv, &err_val);
    CHECK_VMFAIL("make_vmcs_launched:VM_EXIT_REASON");
    // Expected exit reasons after initial vmlaunch: VMCALL (guest code) or timeout
    ASSERT((exit_reason == EXIT_REASON_VMCALL || exit_reason == EXIT_REASON_PREEMPTION_TIMER),
           "make_vmcs_launched:unexpected exit reason");

    // 5. Finalize VMCS fields
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    CHECKED_VMWRITE(GUEST_RIP, (uint64_t)&guest_v_memory->code.section[0]);
    CHECKED_VMWRITE(GUEST_RSP, (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(HOST_RIP, (uint64_t)fault_handler);
    CHECKED_VMWRITE(HOST_RSP, (uint64_t)&sandbox->data[0].main_area[LOCAL_RSP_OFFSET]);

    return 0;
}

static void print_vmlaunch_error_info(int err_inv, int err_val, int actor_id)
{
    PRINT_ERR("vmlaunch failed: VMfailInvalid=%d, VMfailValid=%d\n", err_inv, err_val);
    if (err_val) {
        uint64_t instr_error = 0;
        uint8_t tmp_inv = 0, tmp_val = 0;
        vmread(VM_INSTRUCTION_ERROR, &instr_error, &tmp_inv, &tmp_val);
        PRINT_ERR("VM_INSTRUCTION_ERROR: %llu\n", instr_error);
        if (instr_error > 0 && instr_error < 26)
            PRINT_ERR("  decoded: %s\n", vmx_instruction_error_to_str[instr_error]);
    }
    PRINT_ERR("VMCS abort indicator: %d\n", vmcss[actor_id].abort_indicator);
}

int print_vmx_exit_info(void)
{
    uint8_t err_inv = 0, err_val = 0;
    uint64_t value = 0;

    // Abort reasons
    PRINT_ERR("VMX Abort indicators:\n");
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        if (actors[actor_id].mode == MODE_GUEST)
            PRINT_ERR("  actor 0x%x: %d\n", actor_id, vmcss[actor_id].abort_indicator);
    }

    // VM exit reason
    PRINT_ERR("VMXC exit info:\n");
    vmread(VM_EXIT_REASON, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_REASON");
    PRINT_ERR("  VM exit reason: 0x%llx\n", value);
    if (value != 0) {
        uint16_t basic_reason = value & 0xFFFF;
        char *exit_type = NULL;
        if (value & (1ULL << 31))
            exit_type = "entry";
        else
            exit_type = "exit";

        for (int i = 0; vmx_basic_exit_reason_to_str[i].str != NULL; i++) {
            if (basic_reason == vmx_basic_exit_reason_to_str[i].basic_exit_reason) {
                PRINT_ERR("    decoded: %s [%s]\n", vmx_basic_exit_reason_to_str[i].str, exit_type);
                break;
            }
        }
    }

    vmread(EXIT_QUALIFICATION, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:EXIT_QUALIFICATION");
    PRINT_ERR("  Exit qualification: 0x%llx\n", value);

    vmread(GUEST_LINEAR_ADDRESS, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:GUEST_LINEAR_ADDRESS");
    PRINT_ERR("  Guest linear address: 0x%llx\n", value);

    vmread(GUEST_PHYSICAL_ADDRESS, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:GUEST_PHYSICAL_ADDRESS");
    PRINT_ERR("  Guest physical address: 0x%llx\n", value);

    vmread(VM_EXIT_INTR_INFO, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INTR_INFO");
    PRINT_ERR("  VM exit interrupt info: 0x%llx\n", value);

    vmread(VM_EXIT_INTR_ERROR_CODE, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INTR_ERROR_CODE");
    PRINT_ERR("  VM exit interrupt error code: 0x%llx\n", value);

    vmread(IDT_VECTORING_INFO_FIELD, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:IDT_VECTORING_INFO_FIELD");
    PRINT_ERR("  IDT vectoring info field: 0x%llx\n", value);

    vmread(IDT_VECTORING_ERROR_CODE, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:IDT_VECTORING_ERROR_CODE");
    PRINT_ERR("  IDT vectoring error code: 0x%llx\n", value);

    vmread(VM_EXIT_INSTRUCTION_LEN, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INSTRUCTION_LEN");
    PRINT_ERR("  VM exit instruction length: 0x%llx\n", value);

    vmread(VMX_INSTRUCTION_INFO, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VMX_INSTRUCTION_INFO");
    PRINT_ERR("  VM exit instruction info: 0x%llx\n", value);

    vmread(VM_INSTRUCTION_ERROR, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_INSTRUCTION_ERROR");
    PRINT_ERR("  VM exit instruction error: 0x%llx\n", value);
    if (value > 0 && value < 22)
        PRINT_ERR("    decoded: %s\n", vmx_instruction_error_to_str[value]);

    return 0;
}

// =================================================================================================
int init_vmx(void)
{
    int err = 0;

    // check that the hw-specific region sizes match our constants
    size_t vmxon_size = (rdmsr64(MSR_IA32_VMX_BASIC) >> 32) & 0xFFF;
    ASSERT(vmxon_size <= VMXON_SIZE, "init_vmx");

    // VMX host data structures
    vmxon_page_hva = CHECKED_ZALLOC(VMXON_SIZE);
    vmxon_page_hpa = virt_to_phys(vmxon_page_hva);
    ASSERT((vmxon_page_hpa & 0xFFF) == 0, "init_vmx"); // VMXON region must be 4KB-aligned

    // VMCS
    vmcss = CHECKED_VMALLOC(MAX_ACTORS * VMCS_SIZE);
    vmcs_hpas = CHECKED_ZALLOC(sizeof(uint64_t) * MAX_ACTORS);

    return err;
}

void free_vmx(void)
{
    SAFE_FREE(vmxon_page_hva);
    SAFE_VFREE(vmcss);
    SAFE_FREE(vmcs_hpas);
}

// NOLINTEND(readability-function-cognitive-complexity)
// NOLINTEND(readability-function-size)
