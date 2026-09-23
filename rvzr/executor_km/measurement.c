/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"
#include <asm/processor.h>

#include "code_loader.h"
#include "data_loader.h"
#include "input_parser.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"
#include "page_tables_guest.h"
#include "page_tables_host.h"
#include "perf_counters.h"
#include "special_registers.h"

#ifdef ARCH_X86_64
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/spec-ctrl.h>

#include "svm.h"
#include "vmx.h"
#elif defined(ARCH_ARM)

#endif

measurement_t *measurements = NULL; // global

int run_experiment_outer(void); // inline asm label defined in <arch>/fault_handler.c

// =================================================================================================
// Local shortcut functions
// =================================================================================================

/// @brief Flushes the microarchitectural state
/// @param void
/// @return 0 on success, -1 on failure
static inline int uarch_flush(void)
{
#if VENDOR_ID == VENDOR_INTEL_ // Intel
    static const u16 ds = __KERNEL_DS;
    asm volatile("verw %[ds]" : : [ds] "m"(ds) : "cc");
#ifndef VMBUILD
    wrmsr64(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
#endif
    asm volatile("wbinvd\n" : : :);
    asm volatile("lfence\n" : : :);
#elif VENDOR_ID == VENDOR_AMD_ // AMD
    asm volatile("wbinvd\n" : : :);
    asm volatile("lfence\n" : : :);
    // TBD
#endif
    return 0;
}

/// @brief Check if entry page of the test case is valid (present and executable)
/// @param void
/// @return 0 if the entry page is valid, -1 otherwise
static int check_test_case_entry(void)
{
    pte_t *tc_pte = get_pte((uint64_t)loaded_test_case_entry);
    if (!tc_pte || !pte_present(*tc_pte)) {
        return -1;
    }
#ifdef ARCH_X86_64
    if (!pte_exec(*tc_pte)) {
        return -1;
    }
#endif

    return 0;
}

/// @brief Checks the measurement status for corruption
/// @param status The measurement status structure to check
/// @return 0 on valid (non-corrupted) measurement, -1 on corrupted measurement
static int check_measurement_status(measurement_status_t *status)
{
    if (status->measurement_state != STATUS_ENDED) {
        switch (status->measurement_state) {
        case STATUS_UNINITIALIZED:
            PRINT_WARNS("run_experiment",
                        "Corrupted measurement: measurement_start macro was not executed, state=%d",
                        status->measurement_state);
            break;
        case STATUS_STARTED:
            PRINT_WARNS("run_experiment",
                        "Corrupted measurement: measurement_end macro was not executed, state=%d",
                        status->measurement_state);
            break;
        default:
            PRINT_WARNS("run_experiment", "Corrupted measurement: unknown state, state=%d",
                        status->measurement_state);
        }
        return -1;
    }

    if (status->smi_count != 0) {
        PRINT_WARNS("run_experiment", "Corrupted measurement: SMI detected, count=%d",
                    status->smi_count);
        return -1;
    }

    return 0;
}

/// @brief Check if the executor is ready to start measurements, and perform the necessary
///        setup of the CPU to ensure that the test case can be executed. Note that this function
///        only partially configures the CPU, and more will be done in set_execution_environment
/// @param irq_flags The flags to store the interrupt state
/// @return 0 on success, -1 on failure
static int pre_run(unsigned long *irq_flags)
{
    int err = 0;

    // check that all main data structures were allocated
    ASSERT(loaded_test_case_entry, "trace_test_case");
    ASSERT(check_test_case_entry() == 0, "trace_test_case");
    ASSERT(inputs, "trace_test_case");
    ASSERT(inputs->metadata, "trace_test_case");
    ASSERT(inputs->data, "trace_test_case");

    // Configure performance counters
    err |= pfc_configure();
    CHECK_ERR("trace_test_case:pfc_configure");

    // Enable FPU - just in case, we might use it within the test case
#ifdef ARCH_X86_64
    kernel_fpu_begin();
#endif

    // Prevent preemption
    get_cpu();

    unsigned long flags;
    raw_local_irq_save(flags);
    *irq_flags = flags;

    return err;
}

/// @brief Cleanup after the test case execution by undoing the changes made in pre_run
/// @param irq_flags The flags to restore the interrupt state
/// @return void
static inline void post_run(unsigned long *irq_flags)
{
#if VENDOR_ID == VENDOR_AMD_
    asm volatile("stgi\n"); // enable interrupts in case they were disabled
#endif
    unsigned long flags = *irq_flags;
    raw_local_irq_restore(flags);

    put_cpu();

#ifdef ARCH_X86_64
    kernel_fpu_end();
#endif
}

// =================================================================================================
// CPU state management
// =================================================================================================
/// @brief Stores the current state of the CPU and re-configures it for the test case execution
/// @param void
/// @return 0 on success, -1 on failure
static int set_execution_environment(void)
{
    int err = 0;
    err = set_special_registers();
    CHECK_ERR("set_execution_environment:set_special_registers");

    // If necessary, enable VM operation
#ifdef ARCH_X86_64
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            err = start_vmx_operation();
            CHECK_ERR("set_execution_environment:start_vmx_operation");

            err = store_orig_vmcs_state();
            CHECK_ERR("set_execution_environment:store_orig_vmcs_state");

            err = set_vmcs_state();
            CHECK_ERR("set_execution_environment:set_vmcs_state");
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            err = start_svm_operation();
            CHECK_ERR("set_execution_environment:start_svm_operation");

            err = store_orig_vmcb_state();
            CHECK_ERR("set_execution_environment:store_orig_vmcb_state");

            err = set_vmcb_state();
            CHECK_ERR("set_execution_environment:set_vmcb_state");
        }
    }
#endif
    return 0;
}

/// @brief Restores the CPU state to the state before the test case execution. This function is
/// written in a fail-safe manner, so that it can be called in fault handlers.
/// @param void
void recover_orig_state(void)
{
    // restore VMX state
#ifdef ARCH_X86_64
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            // if (vmx_is_on)
            //     print_vmx_exit_info(); // uncomment to debug VMX exits
            clear_vmcs_state();
            restore_orig_vmcs_state();
            stop_vmx_operation();
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            // if (svm_is_on)
            //     print_svm_exit_info(); // uncomment to debug SVM exits
            restore_orig_vmcb_state();
            stop_svm_operation();
        }
    }
#endif

    restore_faulty_page_permissions();
    restore_special_registers();
    restore_orig_sandbox_page_tables();
}

// =================================================================================================
// Measurement loop: trace_test_case -> run_experiment_outer -> run_experiment
// =================================================================================================

/// @brief Run a complete measurement experiment: setup the execution environment and execute
///        the loaded test case for each inputs, storing the resulting hardware traces and PFC
///        readings in the global `measurements` array
/// @param void
/// @return 0 on success, -1 on error
int run_experiment(void)
{
    int err = 0;

    // allocate and map memory for the test case
    err = set_sandbox_page_tables();
    if (err)
        goto cleanup;

    // configure the CPU (and anything else necessary) to prepare for the test case execution
    err = set_execution_environment();
    if (err)
        goto cleanup;

    // Zero-initialize the region of memory used by Prime+Probe
    if (!quick_and_dirty_mode)
        memset(&sandbox->util->l1d_priming_area[0], 0, L1D_PRIMING_AREA_SIZE * sizeof(char));

    // Try to reset the uarch state
    // (we do it here because from this point on the execution is expected to be deterministic
    // and depend solely on the test case and the input to it)
    if (pre_run_flush == 1 && !quick_and_dirty_mode)
        uarch_flush();

    long rounds = (long)n_inputs;
    for (long i = -uarch_reset_rounds; i < rounds; i++) {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;

        // Prepare sandbox
        load_sandbox_data(i_);
        set_faulty_page_permissions();

        // Catch all exceptions
        set_inner_fault_handlers();

        // Execute
        char *main_data = &sandbox->data[0].main_area[0];
        err = ((int (*)(char *))loaded_test_case_entry)(main_data);

        // Restore the original fault handlers and sandbox state
        unset_inner_fault_handlers();
        restore_faulty_page_permissions();
        if (err) // Note: this check HAS to be after IDT/PT reset to avoid corrupting system state
            goto cleanup;

        // Store the measurement
        measurement_t result = sandbox->util->vars.latest_measurement;
        measurements[i_].htrace[0] = result.htrace[0];
        memcpy(measurements[i_].pfc_reading, result.pfc_reading, sizeof(uint64_t) * NUM_PFC);

        // Post-process the measurement
        // (only in normal, non-debug non-warmup runs)
        if (i >= 0 && !dbg_gpr_mode) {
            // Check for measurement corruption
            if (check_measurement_status(&result.status) != 0)
                // Note: we intentionally do not set the `err` variable upon corruption, because
                // corruptions are expected to happen every once in a while because of SMIs,
                // and thus we want to handle them gracefully
                goto cleanup;

            // If the measurement is valid, set the upper bit of htrace
            // to distinguish correct htraces from corrupted ones
            measurements[i_].htrace[0] |= 1ULL << 63;
        }
    }

cleanup:
    if (err)
        measurements[0].htrace[0] = 0; // communicate the error up to executor.py
    recover_orig_state();
    CHECK_ERR("run_experiment:cleanup");
    return err;
}

/// @brief The outermost wrapper for the test case execution. Sets up performance counters,
///        configures the CPU, disables interrupts, and calls enter_unsafe_bubble
/// @param void
/// @return 0 on success, -1 on failure
int trace_test_case(void)
{
    int err = 0;
    unsigned long irq_flags = 0;

    err = alloc_measurements();
    CHECK_ERR("alloc_measurements");

    err = pre_run(&irq_flags);
    CHECK_ERR("trace_test_case:pre_run");

    if (n_inputs) {
        err |= run_experiment_outer();
    }

    post_run(&irq_flags);
    CHECK_ERR("trace_test_case:cleanup");

    return err;
}

// =================================================================================================
// Constructor and destructor + initialization
// =================================================================================================
int alloc_measurements(void)
{
    static int old_n_inputs = 0;
    if (n_inputs <= old_n_inputs)
        return 0;
    old_n_inputs = n_inputs;

    SAFE_VFREE(measurements);
    measurements = CHECKED_VMALLOC(n_inputs * sizeof(measurement_t));
    memset(measurements, 0, n_inputs * sizeof(measurement_t));
    return 0;
}

int init_measurements(void)
{
    measurements = CHECKED_VMALLOC(sizeof(measurement_t));
    return 0;
}

/// Destructor for the measurement module
///
void free_measurements(void) { SAFE_VFREE(measurements); }
