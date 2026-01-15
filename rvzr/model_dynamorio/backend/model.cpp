///
/// File: DynamoRIO client entry point and instrumentation orchestrator
///
/// This file implements the main DynamoRIO client (dr_client_main) and coordinates
/// the instrumentation lifecycle. The file is responsible for detecting when to start/stop
/// instrumentation of the target function based on its name. It also registers event callbacks
/// for module loading, basic block transformation, and instruction-level instrumentation.
/// The callbacks transfer control to the Dispatcher class, which manages the rest of
/// the model's logic.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_tools.h>
#include <drmgr.h>
#include <drsyms.h>
#include <drutil.h>
#include <drwrap.h>
#include <drx.h>

#include "cli.hpp"
#include "dispatcher.hpp"
#include "factory.hpp"
#include "util.hpp"

using std::size_t;
using std::string;

/// @brief Pointer to the dispatcher instance;
/// @note We have to use a global pointer to share state (tracer, speculator, state of the
///       instrumentation) with the callbacks. This is the reason for NOLINT as well.
std::unique_ptr<Dispatcher> glob_dispatcher = nullptr; // NOLINT

namespace dr_model
{

static void dr_model_del() noexcept;

// =================================================================================================
// State machine of instrumentation
// =================================================================================================

/// @brief Class holding information about the function to instrument and managing the state of the
/// instrumentation process.
class InstrumentationStateMachine
{
  public:
    InstrumentationStateMachine(std::string name_) : name(std::move(name_)) {}
    ~InstrumentationStateMachine() = default;
    InstrumentationStateMachine(const InstrumentationStateMachine &) = delete;
    InstrumentationStateMachine &operator=(const InstrumentationStateMachine &) = delete;
    InstrumentationStateMachine(InstrumentationStateMachine &&) = delete;
    InstrumentationStateMachine &operator=(InstrumentationStateMachine &&) = delete;

    /// @brief Name of the function to instrument
    std::string name;

    /// @brief Whether DynamoRIO is currently executing inside the instrumented function.
    bool in_function = false;

    void register_entry_pc(app_pc pc)
    {
        DR_ASSERT_MSG(not entry_found, "Function entry pc already registered");
        entry_pc = pc;
        entry_found = true;
    }

    bool is_entry_pc(byte const *pc) const { return entry_found and pc == entry_pc; }

    void register_exit_pc(app_pc pc)
    {
        DR_ASSERT_MSG(not exit_found, "Function exit pc already registered");
        exit_pc = pc;
        exit_found = true;
    }

    bool is_exit_pc(byte const *pc) const { return exit_found and pc == exit_pc; }

    /// @return true on first call (to trigger code cache flush, which will cause re-execution),
    ///         false afterwards
    bool start_instrumentation(void *drcontext)
    {
        DR_ASSERT_MSG(in_function == false,
                      "[ERROR] Recursive calls to the instrumented function are not supported.");
        in_function = true;

        // Flush all code cache: we might want to instrument basic blocks that have already
        // been translated (e.g. libc)
        if (not entry_flush_done) {
            flush_bb_cache();
            entry_flush_done = true;
            in_function = false;

            // quick return: the flush will cause a re-instrumentation, so this function will be
            // called again immediately after this return
            return true;
        }

        // If this is the first time we instrument the function, we need to initialize the
        // dispatcher and store the function's return address for later instrumentation.
        if (not glob_dispatcher->is_initialized) {
            glob_dispatcher->start();
        } else {
            glob_dispatcher->restart();
        }

        // Also, if this is the first time we instrument the function, we have to
        // identify the exit pc by inspecting the return address on the stack
        // (we assume that the function is always called from the same location, hence
        // this is done only once)
        if (not exit_found) {
            dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
            dr_get_mcontext(drcontext, &mc);
            exit_found = true;
            exit_pc = *((app_pc *)mc.xsp);
        }
        return false;
    }

    void end_instrumentation(void *drcontext, instrlist_t *bb, instr_t *instr)
    {
        DR_ASSERT_MSG(in_function == true,
                      "[ERROR] Found function exit pc while not in the function.");
        in_function = false;
        glob_dispatcher->instrument_exit(drcontext, bb, instr);
    }

  private:
    /// @brief First pc executed when entering the instrumented function. This is populated
    /// dynamically by `event_module_load` based on symbol resolution.
    app_pc entry_pc = nullptr;
    /// @brief Whether the function entry point has been found.
    bool entry_found = false;
    /// @brief The first time the entry point is executed, we flush the code cache, but only once.
    /// This flag tracks whether we already did it.
    bool entry_flush_done = false;
    /// @brief First pc executed after the instrumented function. This is populated dynamically once
    /// we reach a call to the instrumented function by inspecting the return address on the stack.
    app_pc exit_pc = nullptr;
    /// @brief Whether the function exit point has been found at least once.
    /// @note Currently we assume that the exit point is always the same, that is the function
    ///       is always called by the same instruction.
    bool exit_found = false;
};

/// @brief State machine instance
/// @note We have to use a global pointer since it is the only way to make it accessible from
///       DynamoRIO callbacks. This is the reason for NOLINT as well.
static std::unique_ptr<InstrumentationStateMachine> instrumentation_state_machine = nullptr;

// =================================================================================================
// Memory layout tracking
// =================================================================================================
class MemoryLayout
{
  public:
    MemoryLayout(std::string mappings_file_) : mappings_file(std::move(mappings_file_))
    {
        // Ensure the file is empty at the beginning
        std::ofstream stream;
        stream.open(mappings_file, std::ios::out | std::ios::trunc);
        stream.close();
    }
    ~MemoryLayout() = default;
    MemoryLayout(const MemoryLayout &) = delete;
    MemoryLayout &operator=(const MemoryLayout &) = delete;
    MemoryLayout(MemoryLayout &&) = delete;
    MemoryLayout &operator=(MemoryLayout &&) = delete;

    /// @brief Records the mapping of a module.
    void record_module_mapping(const char *module_name, app_pc start_address)
    {
        module_mappings.emplace_back(module_name, reinterpret_cast<std::uintptr_t>(start_address));
    }

    /// @brief Store the recorded module mappings to file.
    void store_mappings() const
    {
        std::ofstream stream;
        stream.open(mappings_file, std::ios::out);
        for (const auto &mapping : module_mappings) {
            stream << mapping.first << " 0x" << std::hex << mapping.second << std::dec << "\n";
        }
        stream.close();
    }

  private:
    /// @brief Storage for module mappings when --store-mappings is enabled.
    /// @note Stores pairs of (module_name, start_address).
    std::vector<std::pair<std::string, std::uintptr_t>> module_mappings;
    /// @brief Output file path for module mappings. Empty if not enabled.
    std::string mappings_file;
};

/// @brief Global instance of MemoryLayout to manage memory layout information during tracing.
static std::unique_ptr<MemoryLayout> memory_layout = nullptr;

// =================================================================================================
// Event callbacks
// =================================================================================================

/// @brief Callback executed before loading a module.
///        This callback is responsible for detecting the presence of the function to instrument.
///        It checks if the module being loaded contains the function to instrument, and if so,
///        communicates its address to Dispatcher, so that is knows when
///        to start the instrumentation (see `event_instrumentation_start`).
/// @param unused
/// @param module_ Pointer to the module data
/// @param unused
/// @return void
static void event_module_load(void * /*drcontext*/, const module_data_t *module_, bool /*loaded*/)
{
    // Record module mapping if store-mappings is enabled
    if (memory_layout != nullptr) {
        memory_layout->record_module_mapping(module_->full_path, module_->start);
    }

    size_t offset = 0;
    const char *symbol = instrumentation_state_machine->name.c_str();
    const drsym_error_t sym_res =
        drsym_lookup_symbol(module_->full_path, symbol, &offset, DRSYM_DEMANGLE);
    if (sym_res == DRSYM_SUCCESS) {
        instrumentation_state_machine->register_entry_pc(module_->start + offset);
    }
}

/// @brief Callback executed at the first instrumentation stage:
///        application-to-application transformation.
///        The implementation expands string ops and scatter/gather
///        into a sequence of normal memory references.
/// @param drcontext The drcontext of the current thread
/// @param unused
/// @param bb The basic block to be transformed
/// @param unused
/// @param unused
/// @return BB emitted state (dr_emit_flags_t)
static dr_emit_flags_t event_bb_app2app(void *drcontext, void * /*tag*/, instrlist_t *bb,
                                        bool /*for_trace*/, bool /*translating*/)
{
    bool err = false;
    err |= !drutil_expand_rep_string(drcontext, bb);
    err |= !drx_expand_scatter_gather(drcontext, bb, nullptr);
    if (err) {
        dr_printf("ERROR: failed to expand string ops or scatter/gather\n");
        dr_abort();
    }
    return DR_EMIT_DEFAULT;
}

/// @brief Callback executed at the third instrumentation stage: instrumentation insertion.
///        The implementation invokes the Dispatcher::instrument_instruction method for every
///        (post-expanded) instruction in the basic block.
/// @param drcontext The drcontext of the current thread
/// @param unused
/// @param bb Parent basic block
/// @param instr The instruction to instrument
/// @param unused
/// @param unused
/// @param unused
/// @return BB emitted state (dr_emit_flags_t)
static dr_emit_flags_t event_bb_instrumentation(void *drcontext, void * /*tag*/, instrlist_t *bb,
                                                instr_t *instr, bool /*for_trace*/,
                                                bool /*translating*/, void * /*user_data*/)
{
    // disassemble_with_info(drcontext, instr_get_app_pc(org_instr), STDOUT, true, true);
    app_pc instr_pc = instr_get_app_pc(instr);

    if (instrumentation_state_machine->is_entry_pc(instr_pc)) {
        const bool triggers_reexecute =
            instrumentation_state_machine->start_instrumentation(drcontext);
        if (triggers_reexecute) {
            // start_instrumentation triggered a code cache flush, so we return early to re-execute
            return DR_EMIT_DEFAULT;
        }
        // no return here: this is the first instruction of the target function,
        // so we still need to instrument it as all other instructions
    }

    if (instrumentation_state_machine->is_exit_pc(instr_pc)) {
        // We found the end pc: add the corresponding callback
        instrumentation_state_machine->end_instrumentation(drcontext, bb, instr);

        // return early: this instruction is already outside the instrumented function (it's
        // the first instruction after the return), so we don't need to instrument it
        return DR_EMIT_DEFAULT;
    }

    // Add a clean call to the dispatch callback, which will forward the call to the service
    // modules
    return glob_dispatcher->instrument_instruction(drcontext, bb, instr);
}

/// @brief Callback executed upon exceptions
/// @param drcontext The drcontext of the current thread
/// @param excpt Pointer to the exception data
/// @return whether the signal should be redirected or delivered to the application
static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    if (glob_dispatcher->handle_exception(drcontext, siginfo)) {
        return DR_SIGNAL_REDIRECT;
    }

    // Continue with the default exception handling if no redirection happened
    return DR_SIGNAL_DELIVER;
}

/// @brief Callback executed before exiting the application.
/// @return void
static void event_exit()
{
    // There is a possibility that the tracing process has not been finalized
    // because the traced function has not been called
    glob_dispatcher->finalize();

    // Make sure we've sent all the collected data
    fflush(stdout);

    // Write module mappings to file if enabled
    if (memory_layout != nullptr) {
        memory_layout->store_mappings();
    }

    // Delete the dispatcher
    glob_dispatcher.reset();

    // Close the DR extensions
    dr_model_del();
}

// =================================================================================================
// Model constructor and destructor
// =================================================================================================

/// @brief Constructor of the DR model.
///        The function initializes the DR extensions and registers callbacks.
/// @return void
/// @throw std::runtime_error if any of the DR extensions fails to start
static void dr_model_init()
{
    // Start DR extensions
    if (!drmgr_init())
        throw std::runtime_error("ERROR: failed to start drmgr\n");
    if (!drutil_init())
        throw std::runtime_error("ERROR: failed to start drutil\n");
    if (!drx_init())
        throw std::runtime_error("ERROR: failed to start drx\n");
    if (!drwrap_init())
        throw std::runtime_error("ERROR: failed to start drwrap\n");
    if (drsym_init(0) != DRSYM_SUCCESS)
        throw std::runtime_error("ERROR: failed to start drsym\n");

    // Register callbacks
    if (!drmgr_register_module_load_event(event_module_load))
        throw std::runtime_error("ERROR: failed to register a callback\n");
    if (!drmgr_register_bb_app2app_event(event_bb_app2app, nullptr))
        throw std::runtime_error("ERROR: failed to register a callback\n");
    if (!drmgr_register_bb_instrumentation_event(nullptr, event_bb_instrumentation, nullptr))
        throw std::runtime_error("ERROR: failed to register a callback\n");

    drmgr_register_signal_event(event_signal);
    dr_register_exit_event(event_exit);
}

/// @brief Destructor of the DR model.
///        The function unregisters callbacks and closes the DR extensions.
/// @return void
void dr_model_del() noexcept
{
    drmgr_unregister_module_load_event(event_module_load);
    drmgr_unregister_bb_app2app_event(event_bb_app2app);
    drmgr_unregister_bb_insertion_event(event_bb_instrumentation);

    drsym_exit();
    drwrap_exit();
    drx_exit();
    drutil_exit();
    drmgr_exit();

    instrumentation_state_machine.reset();
}

} // namespace dr_model

// =================================================================================================
// Model entry point
// =================================================================================================

/// @brief Entry point of the DR model.
///        The function initializes the dispatcher, registers callbacks,
///        and starts the DR extensions.
/// @param _ Unused
/// @param argc Number of CLI arguments
/// @param argv CLI arguments
/// @return void
DR_EXPORT void dr_client_main(client_id_t /* client_id */, int argc, const char **argv)
{
    // Parse CLI arguments
    cli_args_t parsed_args = {};
    parse_cli(argc, argv, parsed_args);

    // Special cases:
    if (parsed_args.list_tracers) {
        for (const auto &tracer_name : get_tracer_list()) {
            dr_printf("%s\n", tracer_name.c_str());
        }
        return;
    }
    if (parsed_args.list_speculators) {
        for (const auto &speculator_name : get_speculator_list()) {
            dr_printf("%s\n", speculator_name.c_str());
        }
        return;
    }

    // Create a dispatcher instance
    glob_dispatcher = std::make_unique<Dispatcher>(&parsed_args);

    // Set the target function
    dr_model::instrumentation_state_machine =
        std::make_unique<dr_model::InstrumentationStateMachine>(parsed_args.instrumented_func);

    // Set up memory layout tracking if --store-mappings is enabled
    if (not parsed_args.mappings_file.empty()) {
        dr_model::memory_layout =
            std::make_unique<dr_model::MemoryLayout>(parsed_args.mappings_file);
    }

    // Initialize the DR model
    dr_model::dr_model_init();
}
