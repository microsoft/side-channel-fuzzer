///
/// File: Class responsible for instrumenting instructions
///       in the target application with a call to a dispatch function.
///       The function, in turn, calls service classes (e.g., Tracer, Speculator, etc)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <memory>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_tools.h>
#include <drmgr.h>
#include <drsyms.h>
#include <drwrap.h>

#include "cli.hpp"
#include "dispatcher.hpp"
#include "factory.hpp"
#include "observables.hpp"
#include "types/decoder.hpp"
#include "util.hpp"

using std::string;

/// Defined by model.cpp, used by instrumentation callbacks.
extern std::unique_ptr<Dispatcher> glob_dispatcher; // NOLINT

// =================================================================================================
// Debug Helpers
// =================================================================================================

/// @brief Print the name of the current function for a given PC at the given level of nesting.
static void print_func_name(app_pc pc, unsigned int spec_level, unsigned int function_level)
{
    const unsigned int max_func_level = 30;
    const unsigned int prefix_len =
        function_level < max_func_level ? function_level : max_func_level;
    module_data_t *mod = dr_lookup_module(pc);
    if (mod != nullptr) {
        drsym_info_t sym_info;
        const uint8_t NAME_MAX_SIZE = 255;
        std::array<char, NAME_MAX_SIZE> name{};

        sym_info.struct_size = sizeof(sym_info);
        sym_info.name = name.begin();
        sym_info.name_size = sizeof(name);
        sym_info.file = nullptr; // We don't need the source file name here

        // Print prefix
        for (int i = 0; i < prefix_len; i++)
            dr_printf("    ");
        if (spec_level == 0)
            dr_printf("[SEQ]");
        else
            dr_printf("[SPEC]");
        // Print function name
        const size_t offset = pc - mod->start;
        if (drsym_lookup_address(mod->full_path, offset, &sym_info, DRSYM_DEFAULT_FLAGS) ==
            DRSYM_SUCCESS) {
            dr_printf("%p: %s\n", pc, sym_info.name);
        } else {
            dr_printf("PC %p (module %s) - symbol not found\n", pc, dr_module_preferred_name(mod));
        }
        dr_free_module_data(mod);
    }
}

static unsigned int function_level = 0;
static unsigned int n_instr = 0;
static bool transition = false;

/// @brief Very heavy instrumentation that prints the current function for each
/// PC -- use only for debugging!
static void dbg_print_function(uint64_t opcode, app_pc pc, unsigned int spec_level)
{
    if (spec_level == 0) {
        // Found call: up a level
        if (opcode == OP_call || opcode == OP_call_ind || opcode == OP_call_far ||
            opcode == OP_call_far_ind) {
            transition = true;
            print_func_name(pc, spec_level, function_level);
            function_level++;
            return;
        }
        // Found ret: down a level
        if (opcode == OP_ret || opcode == OP_ret_far || opcode == OP_iret) {
            transition = true;
            dr_printf("[omitted %d]\n", n_instr);
            n_instr = 0;
            print_func_name(pc, spec_level, function_level);
            function_level--;
            return;
        }
    }

    if (transition) {
        // Previous inst was a call or a ret.
        print_func_name(pc, spec_level, function_level);
        transition = false;
    }
    n_instr++;
}

/// @brief Print state name.
static const char *to_string(const dispatcher_state_t &state)
{
    switch (state) {
    case OFF:
        return "OFF";
    case INSTRUMENTED:
        return "INSTRUMENTED";
    case ON:
        return "ON";
    case PAUSED:
        return "PAUSED";
    }
    return "UNKNOWN";
}

/// @brief Print event name.
static const char *to_string(const dispatcher_event_t &event)
{
    switch (event) {
    case EV_ENTRY_REACHED:
        return "EV_ENTRY_REACHED";
    case EV_ENTRY:
        return "EV_ENTRY";
    case EV_PAUSE:
        return "EV_PAUSE";
    case EV_RESUME:
        return "EV_RESUME";
    case EV_EXIT:
        return "EV_EXIT";
    }
    return "UNKNOWN";
}

/// @brief Debug function, used to detect invalid modifications of MC
static inline uint64_t mc_fingerprint(const dr_mcontext_t *mc)
{
    return mc->xax ^ mc->xbx ^ mc->xcx ^ mc->xdx ^ mc->xsi ^ mc->xdi ^ mc->xbp ^ mc->xsp ^ mc->r8 ^
           mc->r9 ^ mc->r10 ^ mc->r11 ^ mc->r12 ^ mc->r13 ^ mc->r14 ^ mc->r15 ^ mc->xflags ^
           (uint64_t)mc->pc;
}

// =================================================================================================
// Instrumentation Callbacks
// =================================================================================================

/// @brief Helper function to get the return address of the current function
static app_pc get_return_address()
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    return *((app_pc *)mc.xsp);
}

/// @brief Helper function to cause a speculation rollback
static void rollback(Dispatcher *dispatcher)
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    // Perform rollback
    const pc_t newpc = dispatcher->speculator->rollback(&mc);
    mc.pc = (byte *)newpc;
    dr_redirect_execution(&mc);
}

/// @brief Callback function called upon entering the instrumented function
static void entry_callback()
{
    Dispatcher *dispatcher = glob_dispatcher.get();
    DR_ASSERT_MSG(dispatcher != nullptr, "[ERROR] glob_dispatcher is null\n");
    DR_ASSERT_MSG(not dispatcher->speculator->in_speculation,
                  "[ERROR] Entering instrumented function during speculation!\n");

    if (not dispatcher->has_exit_pc()) {
        // Register the return address of the instrumented function, to know when to stop the
        // instrumentation
        dispatcher->register_exit_pc(get_return_address());
    }
    // Advance state machine
    dispatcher->handle_event(dispatcher_event_t::EV_ENTRY);
    // Flush DynamoRIO's code cache. This is necessary to ensure that the instrumentation is applied
    // to all instructions in the instrumented function, including those that have already been
    // cached by DynamoRIO before we registered the entry callback.
    flush_bb_cache();
}

/// @brief Callback function called upon entering an ignored function
/// @note In principle we could just check if the current PC is inside the set of
///       pause PCs in the dispatch callback, as we do with exit_pc and resume_pc,
///       however (1) the pause pcs are known statically (while resume_pc depends
///       on the caller of the pause function) and (2) we don't want pay a std::set
///       lookup on every instruction.
static void pause_callback()
{
    Dispatcher *dispatcher = glob_dispatcher.get();
    DR_ASSERT_MSG(dispatcher != nullptr, "[ERROR] glob_dispatcher is null\n");
    // Rollback speculation if we're speculatively entering a pause function
    if (dispatcher->speculator->in_speculation) {
        rollback(dispatcher);
        return; // unreachable
    }
    // Advance state machine
    auto next_state = dispatcher->handle_event(dispatcher_event_t::EV_PAUSE);
    // Register the return address of this function, to know when to resume the instrumentation.
    // Ignore nested pauses.
    if (next_state.has_value()) {
        DR_ASSERT_MSG(next_state.value() == dispatcher_state_t::PAUSED,
                      "Invalid transition from PAUSED\n");
        dispatcher->register_resume_pc(get_return_address());
    }
}

/// @brief Dispatch function that calls the per-instruction functions in the service modules
/// @param mc Machine context of the current instruction
/// @param bundle The bundle of service modules to be called
/// @param instr Observables of the current instruction
/// @return The PC of the next instruction to be executed (if redirection is necessary);
///         otherwise, 0 (zero)
static pc_t instruction_dispatch(dr_mcontext_t *mc, void *dc, const Dispatcher *dispatcher,
                                 instr_obs_t instr)
{
    const unsigned int nesting_level = dispatcher->speculator->get_nesting_level();
    dispatcher->logger->log_instruction(instr, mc, nesting_level);
    dispatcher->taint_tracker->track_instruction(instr, mc, dc);
    dispatcher->tracer->observe_instruction(instr, mc, dc, nesting_level);
    const pc_t next_pc = dispatcher->speculator->handle_instruction(instr, mc, dc);
    return next_pc;
}

/// @brief Dispatch function that calls the per-memory-access functions in the service modules
/// @param drcontext
/// @param mc
/// @param bundle
/// @param pc
/// @return The PC of the next instruction to be executed (if redirection is necessary);
///         otherwise, 0 (zero)
static pc_t mem_access_dispatch(void *dc, dr_mcontext_t *mc, const Dispatcher *dispatcher, pc_t pc)
{
    // Decode the instruction using the shared cache to extract its memory references
    instr_t *instr = dispatcher->decoder->get_decoded_instr(dc, (byte *)pc);

    // Identify the size of the memory reference
    // (assumed that all memory references for the instruction are of the same size)
    const uint64_t size = instr_memory_reference_size(instr);

    // Loop over all memory operands and call service modules for each
    uint index = 0;
    bool is_write = false;
    app_pc addr = nullptr;
    while (instr_compute_address_ex(instr, mc, index, &addr, &is_write)) {
        dispatcher->logger->log_mem_access(is_write, addr, size);
        dispatcher->taint_tracker->track_memory_access(is_write, (void *)addr, size);
        dispatcher->tracer->observe_mem_access(is_write, addr, size);
        if (not dispatcher->speculator->handle_mem_access(is_write, (void *)addr, size)) {
            return dispatcher->speculator->rollback(mc);
        }

        index++;
    }

    return 0;
}

/// @brief Callback function called for every instruction in the instrumented function
/// @param bundle The bundle of service modules to be called
/// @param opcode The opcode of the instruction
/// @param pc The program counter (address) of the instruction
/// @param has_mem_ref Flag indicating whether the instruction has a memory reference
static void dispatch_callback(uint64_t opcode, uint64_t pc, uint64_t has_mem_ref)
{
    Dispatcher *dispatcher = glob_dispatcher.get();
    DR_ASSERT_MSG(dispatcher != nullptr, "[ERROR] glob_dispatcher is null\n");

    // check special PCs
    if (dispatcher->is_exit_pc((app_pc)pc)) {
        // don't exit speculatively from the instrumented function
        if (dispatcher->speculator->in_speculation) {
            rollback(dispatcher);
            return; // unreachable
        }
        dispatcher->handle_event(dispatcher_event_t::EV_EXIT);
    } else if (dispatcher->is_resume_pc((app_pc)pc)) {
        dispatcher->handle_event(dispatcher_event_t::EV_RESUME);
    }

    // don't do anything id we're OFF or PAUSED
    if (not dispatcher->is_instrumentation_on())
        return;
    // dbg_print_function(opcode, (app_pc)pc, dispatcher->speculator->get_nesting_level());

    // get current context
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);
    const uint64_t mc_before = mc_fingerprint(&mc);

    // create an instruction instance for the current instruction
    const instr_obs_t instr = {
        .opcode = opcode,
        .pc = (pc_t)pc,
        .has_mem_access = (bool)has_mem_ref,
    };

    // pass down to instruction dispatch functions and redirect execution if needed
    pc_t next_pc = instruction_dispatch(&mc, drcontext, dispatcher, instr);
    if (next_pc != 0) {
        mc.pc = (byte *)next_pc;
        dr_redirect_execution(&mc);
        return; // unreachable
    }
    // skip mem dispatch if the instruction doesn't access memory
    if (has_mem_ref == 0) {
        DR_ASSERT_MSG(mc_before == mc_fingerprint(&mc),
                      "[ERROR] Machine context modified by instruction dispatch functions\n");
        return;
    }

    // pass down to memory access dispatch functions and redirect execution if needed
    next_pc = mem_access_dispatch(drcontext, &mc, dispatcher, instr.pc);
    if (next_pc != 0) {
        mc.pc = (byte *)next_pc;
        dr_redirect_execution(&mc);
        return; // unreachable
    }
    DR_ASSERT_MSG(mc_before == mc_fingerprint(&mc),
                  "[ERROR] Machine context modified by instruction dispatch functions\n");
}

// =================================================================================================
// Instrumentation-time Methods
// =================================================================================================

bool Dispatcher::instrument(void *drcontext, instrlist_t *bb, instr_t *instr)
{
    app_pc cur_pc = instr_get_app_pc(instr);
    bool instrumented = false;

    // Entry reached
    if (entry_pc.has_value() and cur_pc == entry_pc.value()) {
        handle_event(dispatcher_event_t::EV_ENTRY_REACHED);
        instrument_entry(drcontext, bb, instr);
        instrumented = true;
    }

    if (state >= dispatcher_state_t::INSTRUMENTED) {
        // Pause pc reached
        if (pause_pcs.find(cur_pc) != pause_pcs.end()) {
            instrument_pause(drcontext, bb, instr);
            instrumented = true;
        }
        // Standard instruction dispatcher
        instrumented = instrument_instruction(drcontext, bb, instr);
    }

    return instrumented;
}

bool Dispatcher::instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr) const
{
    // Get a pointer to the instruction's original form (pre event_bb_app2app call)
    instr_t *org_instr = drmgr_orig_app_instr_for_fetch(drcontext);
    if (org_instr == nullptr) { // DR tell us that this instruction should be skipped
        return false;
    }

    // Get instruction parameters
    const opnd_t opcode = OPND_CREATE_INT64(instr_get_opcode(org_instr));
    const opnd_t pc_op = OPND_CREATE_INTPTR(instr_get_app_pc(org_instr));
    const opnd_t has_mem_ref =
        OPND_CREATE_INT64(instr_reads_memory(org_instr) or instr_writes_memory(org_instr));

    // Add a clean call to the dispatch callback, which will forward the call to the service
    // modules
    const int dispatch_callback_nargs = 3;
    dr_insert_clean_call(drcontext, bb, instr, (void *)dispatch_callback, false,
                         dispatch_callback_nargs, opcode, pc_op, has_mem_ref);

    return true;
}

void Dispatcher::instrument_entry(void *drcontext, instrlist_t *bb, instr_t *instr) const
{
    // dr_printf("[DISPATCHER] Instrumenting ENTRY function\n");
    dr_insert_clean_call(drcontext, bb, instr, (void *)entry_callback, false, 0);
}

void Dispatcher::instrument_pause(void *drcontext, instrlist_t *bb, instr_t *instr) const
{
    // dr_printf("[DISPATCHER] Instrumenting PAUSE function\n");
    dr_insert_clean_call(drcontext, bb, instr, (void *)pause_callback, false, 0);
}

// =================================================================================================
// State Machine Management
// =================================================================================================

// Helpers to manage service modules
void Dispatcher::turn_on_instrumentation() const
{
    taint_tracker->enable();
    tracer->enable();
    speculator->enable();
}
void Dispatcher::turn_off_instrumentation() const
{
    taint_tracker->disable();
    tracer->disable();
    speculator->disable();
}

// State machine transitions
void Dispatcher::start_tracing()
{
    turn_on_instrumentation();
    trace_active = true;
}
void Dispatcher::pause() { turn_off_instrumentation(); }
void Dispatcher::resume()
{
    resume_pc = std::nullopt;
    turn_on_instrumentation();
}
void Dispatcher::stop()
{
    exit_pc = std::nullopt;
    // Emit the end-of-trace marker for the input that just finished executing and turn the
    // service modules off. The next input re-arms them via start_tracing(). When tracing multiple
    // inputs in a single process (e.g., the Revizor adapter), this is what separates the traces.
    finalize_trace();
}
void Dispatcher::finalize_trace()
{
    if (not trace_active) {
        return;
    }
    taint_tracker->finalize();
    tracer->finalize();
    speculator->disable();
    trace_active = false;
}
void Dispatcher::finalize()
{
    // Sanity check against state-machine logic bugs: reaching finalize() while still ON means
    // event_exit() failed to dispatch EV_EXIT despite instrumentation being on. OFF (normal exit),
    // INSTRUMENTED (entry PC discovered but never executed), and PAUSED (exited inside an ignored
    // function) are all legitimate terminal states; only ON is invalid.
    DR_ASSERT_MSG(state != dispatcher_state_t::ON, "[ERROR] Finalizing while instrumentation on.");
    // Finalize any trace still in progress (e.g., the instrumented function was entered but never
    // architecturally exited). This is a no-op if stop() already finalized the last trace.
    finalize_trace();
    state = dispatcher_state_t::OFF;
}

// State machine implementation
std::optional<dispatcher_state_t> Dispatcher::handle_event(dispatcher_event_t event)
{
    // dr_printf("[DISPATCHER] Received event %s in state %s\n", to_string(event),
    // to_string(state));

    switch (event) {
    case dispatcher_event_t::EV_ENTRY_REACHED:
        if (state == dispatcher_state_t::OFF) {
            // dr_printf("[DISPATCHER] State Machine Transition: OFF → INSTRUMENTED\n");
            state = dispatcher_state_t::INSTRUMENTED;
            return state;
        } else {
            dr_fprintf(STDERR, "ASSERT FAILURE: Received EV_ENTRY_REACHED in wrong state\n");
        }
        break;

    case dispatcher_event_t::EV_ENTRY:
        if (state == dispatcher_state_t::INSTRUMENTED) {
            // dr_printf("[DISPATCHER] State Machine Transition: INSTRUMENTED → ON\n");
            start_tracing();
            state = dispatcher_state_t::ON;
            return state;
        } else {
            dr_fprintf(STDERR, "ASSERT FAILURE: Received EV_ENTRY in wrong state\n");
        }
        break;

    case dispatcher_event_t::EV_PAUSE:
        if (state == dispatcher_state_t::ON) {
            // dr_printf("[DISPATCHER] State Machine Transition: ON → PAUSED\n");
            pause();
            state = dispatcher_state_t::PAUSED;
            return state;
        }
        break;

    case dispatcher_event_t::EV_RESUME:
        if (state == dispatcher_state_t::PAUSED) {
            // dr_printf("[DISPATCHER] State Machine Transition: PAUSED → ON\n");
            resume();
            state = dispatcher_state_t::ON;
            return state;
        }
        break;

    case dispatcher_event_t::EV_EXIT:
        // We can encounter the exit event both in ON and PAUSED states, depending on whether the
        // exit function is an architectural exit or an exception.
        if (state == dispatcher_state_t::ON or state == dispatcher_state_t::PAUSED) {
            // dr_printf("[DISPATCHER] State Machine Transition: %s → OFF\n", to_string(state));
            stop();
            state = dispatcher_state_t::OFF;
            return state;
        } else {
            DR_ASSERT_MSG(false, "[ERROR] Received EV_EXIT in wrong state\n");
        }
        break;

    default:
        DR_ASSERT_MSG(false, "[ERROR] Invalid event\n");
        break;
    }

    return std::nullopt; // no transition
}

bool Dispatcher::handle_exception(void *drcontext, dr_siginfo_t *siginfo)
{
    logger->log_exception(siginfo);
    // Exceptions on speculative paths are handled by the speculator.
    const bool redirected = speculator->handle_exception(drcontext, siginfo);
    if (redirected)
        return true; // intercepted

    // Architectural exceptions are forwarded to the program
    dr_printf("[XCPT] Dispatcher::handle_exception: exception on a non-speculative path\n");
    tracer->observe_exception(siginfo);
    // Stop instrumentation.
    handle_event(dispatcher_event_t::EV_EXIT);
    return false; // not intercepted, let the program fail
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
Dispatcher::Dispatcher(cli_args_t *cli_args)
{
    // Create service modules
    logger = create_logger(cli_args->debug_output, cli_args->log_level, cli_args->print_dbg_trace);
    decoder = std::make_unique<Decoder>();
    taint_tracker = create_taint_tracker(cli_args->enable_taint_tracker, cli_args->taint_output,
                                         *logger, *decoder);
    tracer = create_tracer(cli_args->tracer_type, cli_args->trace_output, *logger, *taint_tracker,
                           *decoder, cli_args->print_trace);
    speculator = create_speculator(cli_args->speculator_type, cli_args->max_nesting,
                                   cli_args->max_spec_window, *logger, *taint_tracker, *decoder,
                                   cli_args->poison_value);
}

Dispatcher::~Dispatcher()
{
    logger.reset();
    decoder.reset();
    tracer.reset();
    speculator.reset();
    taint_tracker.reset();
}
