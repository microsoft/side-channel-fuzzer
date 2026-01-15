///
/// File: Header for the Command Line Interface (cli.cpp)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <dr_defines.h> // DR_PARAM_OUT

enum class Mode : uint8_t {
    STANDALONE,
    RVZR_BACKEND,
};

struct cli_args_t {
    Mode mode;
    std::string tracer_type;
    std::string instrumented_func;
    std::string trace_output;
    bool print_trace;
    int log_level;
    std::string debug_output;
    bool print_dbg_trace;
    std::string speculator_type;
    int max_nesting;
    int max_spec_window;
    bool enable_taint_tracker;
    std::string taint_output;
    bool list_tracers;
    bool list_speculators;
    std::optional<uint64_t> poison_value;
    std::string mappings_file;
};

/// @brief Parse the command line arguments
/// @param argc Standard argument count
/// @param argv Standard argument vector
/// @param parsed_args Output structure with the parsed arguments
/// @return void
/// @exception dr_abort() if the arguments cannot be parsed
void parse_cli(int argc, const char **argv, DR_PARAM_OUT cli_args_t &parsed_args);
