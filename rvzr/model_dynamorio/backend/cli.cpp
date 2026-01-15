///
/// File: Dr. Model Command Line Interface
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cstdint>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_tools.h>
#include <droption.h>

#include "cli.hpp"
#include "factory.hpp"

using std::string;

using dynamorio::droption::DROPTION_SCOPE_CLIENT;
using dynamorio::droption::droption_t;

static bool validate_tracer(cli_args_t *parsed_args);
static bool validate_speculator(cli_args_t *parsed_args);
static bool validate_taint_tracker(cli_args_t *parsed_args);

static const int max_reasonable_nesting = 100;
static const int max_reasonable_spec_window = 1000;

// =================================================================================================
// List of options
// =================================================================================================
namespace
{
// clang-format off
// General Configuration

// Mode selector: standalone vs serving as a backend for rvzr
const droption_t<string> op_mode(DROPTION_SCOPE_CLIENT,
                        "mode", "standalone",
                        "Mode of operation: standalone or rvzr",
                        "Mode of operation: "
                        "standalone (default) or rvzr (used as a backend for rvzr)");

// Tracer Configuration
const droption_t<string> op_tracer_name(DROPTION_SCOPE_CLIENT,
                        "tracer", "ct",
                        "Type of the tracer; equivalent to the observation clause of a contract",
                        "Type of the tracer; equivalent to the observation clause of a contract");
const droption_t<string> op_instrumented_func(DROPTION_SCOPE_CLIENT,
                        "instrumented-func", "__libc_start_main",
                        "Name of the function to instrument.",
                        "Name of the function to instrument.");
const droption_t<string> op_trace_output(DROPTION_SCOPE_CLIENT,
                        "trace-output", "rvzr_trace.dat",
                        "Where to save the trace (in binary format).",
                        "Where to save the trace (in binary format).");
const droption_t<bool>  op_print_trace(DROPTION_SCOPE_CLIENT,
                        "print-trace", false,
                        "Dump trace entries to STDOUT while they are being produced.",
                        "Dump trace entries to STDOUT while they are being produced.");

// Debugging
const droption_t<int>    op_log_level(DROPTION_SCOPE_CLIENT,
                        "log-level", 0,
                        "Verbosity level of the debug logger (0 = disabled).",
                        "Verbosity level of the debug logger (0 = disabled).");
const droption_t<string> op_debug_output(DROPTION_SCOPE_CLIENT,
                        "debug-trace-output", "rvzr_dbg_trace.dat",
                        "Where to save the debug log (in binary format).",
                        "Where to save the debug log (in binary format).");
const droption_t<bool>   op_print_dbg_trace(DROPTION_SCOPE_CLIENT,
                        "print-debug-trace", false,
                        "Dump log entries to STDOUT while they are being produced.",
                        "Dump log entries to STDOUT while they are being produced.");

// Speculator Configuration
const droption_t<string> op_speculator_name(DROPTION_SCOPE_CLIENT,
                        "speculator", "seq",
                        "Type of the speculator; equivalent to the execution clause of a contract",
                        "Type of the speculator; equivalent to the execution clause of a contract");
const droption_t<int>    op_max_nesting(DROPTION_SCOPE_CLIENT,
                        "max-nesting", 1,
                        "Maximum number of nested speculations.",
                        "Maximum number of nested speculations.");
const droption_t<int>    op_max_spec_window(DROPTION_SCOPE_CLIENT,
                        "max-spec-window", 250,
                        "Maximum number of speculative instructions.",
                        "Maximum number of speculative instructions.");
const droption_t<uint64_t> op_poison_value(DROPTION_SCOPE_CLIENT,
                        "poison-value", 0,
                        "Value to forward on speculative faulty loads. If 0, speculative loads cause a rollback.",
                        "Value to forward on speculative faulty loads. If 0, speculative loads cause a rollback.");

// Taint Tracker Configuration
const droption_t<bool>   op_enable_taint_tracker(DROPTION_SCOPE_CLIENT,
                        "enable-taint-tracker", false,
                        "Enable the taint tracker for contract-based input generation.",
                        "Enable the taint tracker for contract-based input generation.");
const droption_t<string> op_taint_output(DROPTION_SCOPE_CLIENT,
                        "taint-output", "",
                        "Where to save the taint information (in binary format).",
                        "Where to save the taint information (in binary format).");

// Listing Options
const droption_t<bool> op_list_tracers(DROPTION_SCOPE_CLIENT,
                        "list-tracers", false,
                        "List all available tracers (aka, observation clauses).",
                        "List all available tracers (aka, observation clauses).");
const droption_t<bool> op_list_speculators(DROPTION_SCOPE_CLIENT,
                        "list-speculators", false,
                        "List all available speculators (aka execution clauses).",
                        "List all available speculators (aka execution clauses).");

// Module Mapping Output
const droption_t<string> op_store_mappings(DROPTION_SCOPE_CLIENT,
                        "store-mappings", "",
                        "File to store loaded module addresses.",
                        "File to store loaded module addresses. "
                        "When set, records start addresses of all loaded modules and saves them on exit.");
// clang-format on
} // namespace

// =================================================================================================
// CLI parser
// =================================================================================================
void parse_cli(int argc, const char **argv, DR_PARAM_OUT cli_args_t &parsed_args)
{
    // Parse the arguments using DynamoRIO's droption parser
    string err_msg;
    const bool parsed = dynamorio::droption::droption_parser_t::parse_argv(
        DROPTION_SCOPE_CLIENT, argc, argv, &err_msg, nullptr);

    // Print error message and abort if the arguments cannot be parsed
    if (not parsed) {
        dr_printf("Error parsing arguments: %s\n", err_msg.c_str());
        dr_printf(
            "Usage: %s\n",
            dynamorio::droption::droption_parser_t::usage_long(DROPTION_SCOPE_CLIENT).c_str());
        dr_abort();
    }

    // Select overall mode
    const std::string mode_str = op_mode.get_value();
    if (mode_str == "standalone") {
        parsed_args.mode = Mode::STANDALONE;
    } else if (mode_str == "rvzr") {
        parsed_args.mode = Mode::RVZR_BACKEND;
    } else {
        dr_printf("Invalid mode: %s\n", mode_str.c_str());
        dr_abort();
    }

    // Set the parsed arguments
    parsed_args.tracer_type = op_tracer_name.get_value();
    parsed_args.instrumented_func = op_instrumented_func.get_value();
    parsed_args.trace_output = op_trace_output.get_value();
    parsed_args.print_trace = op_print_trace.get_value();
    parsed_args.log_level = op_log_level.get_value();
    parsed_args.debug_output = op_debug_output.get_value();
    parsed_args.print_dbg_trace = op_print_dbg_trace.get_value();
    parsed_args.speculator_type = op_speculator_name.get_value();
    parsed_args.max_nesting = op_max_nesting.get_value();
    parsed_args.max_spec_window = op_max_spec_window.get_value();
    parsed_args.enable_taint_tracker = op_enable_taint_tracker.get_value();
    parsed_args.taint_output = op_taint_output.get_value();
    parsed_args.list_tracers = op_list_tracers.get_value();
    parsed_args.list_speculators = op_list_speculators.get_value();
    parsed_args.mappings_file = op_store_mappings.get_value();
    uint64_t poison_value = op_poison_value.get_value();
    if (poison_value == 0) {
        parsed_args.poison_value = {};
    } else {
        parsed_args.poison_value = poison_value;
    }

    // Check values
    if (not validate_tracer(&parsed_args)) {
        dr_abort();
    }
    if (not validate_speculator(&parsed_args)) {
        dr_abort();
    }
    if (not validate_taint_tracker(&parsed_args)) {
        dr_abort();
    }
}

// =================================================================================================
// Validators
// =================================================================================================
bool validate_tracer(cli_args_t *parsed_args)
{
    // Check if the tracer type is supported
    auto tracer_names = get_tracer_list();
    auto match = std::find(tracer_names.begin(), tracer_names.end(), parsed_args->tracer_type);
    if (match == tracer_names.end()) {
        dr_printf("Invalid tracer type: %s\n", parsed_args->tracer_type.c_str());
        dr_printf("Available tracers: [ ");
        for (const auto &tracer : tracer_names) {
            dr_printf("%s, ", tracer.c_str());
        }
        dr_printf("]\n");
        return false;
    }

    return true;
}

bool validate_speculator(cli_args_t *parsed_args)
{
    // Check if the speculator type is supported
    auto speculator_names = get_speculator_list();
    auto match =
        std::find(speculator_names.begin(), speculator_names.end(), parsed_args->speculator_type);
    if (match == speculator_names.end()) {
        dr_printf("Invalid speculator type: %s\n", parsed_args->speculator_type.c_str());
        dr_printf("Available speculators: [ ");
        for (const auto &spec : speculator_names) {
            dr_printf("%s, ", spec.c_str());
        }
        dr_printf("]\n");
        return false;
    }

    // Check if the maximum nesting level is valid
    // - Negative or zero values have no meaning;
    // - Anything greater than 100 is unrealistic on modern hardware
    if (parsed_args->max_nesting <= 0) {
        dr_printf("Invalid maximum nesting level: %d\n", parsed_args->max_nesting);
        dr_printf("Maximum nesting level must be greater than 0.\n");
        return false;
    }
    if (parsed_args->max_nesting > max_reasonable_nesting) {
        dr_printf("Invalid maximum nesting level: %d\n", parsed_args->max_nesting);
        dr_printf("Maximum nesting level must be less than or equal to 100.\n");
        return false;
    }

    // Check if the maximum speculation window is valid
    // - Negative or zero values have no meaning;
    // - Anything greater than 1000 is unrealistic on modern hardware
    if (parsed_args->max_spec_window <= 0) {
        dr_printf("Invalid maximum speculation window: %d\n", parsed_args->max_spec_window);
        dr_printf("Maximum speculation window must be greater than 0.\n");
        return false;
    }
    if (parsed_args->max_spec_window > max_reasonable_spec_window) {
        dr_printf("Invalid maximum speculation window: %d\n", parsed_args->max_spec_window);
        dr_printf("Maximum speculation window must be less than or equal to 1000.\n");
        return false;
    }

    return true;
}

static bool validate_taint_tracker(cli_args_t *parsed_args)
{
    // Taint tracker is only available for backend mode
    if (parsed_args->enable_taint_tracker and parsed_args->mode != Mode::RVZR_BACKEND) {
        dr_printf(
            "Taint tracker can only be enabled when the model is used as a backend for rvzr.\n");
        return false;
    }

    // If the taint tracker is enabled, check that the output path is valid
    if (parsed_args->enable_taint_tracker) {
        if (parsed_args->taint_output.empty()) {
            dr_printf(
                "Taint tracker output path cannot be empty when the taint tracker is enabled.\n");
            return false;
        }
    }

    return true;
}
