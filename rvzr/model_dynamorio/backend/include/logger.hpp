///
/// File: The Logger centralizes the collection of debug traces from different components
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

#include <dr_defines.h>
#include <dr_events.h>

#include "observables.hpp"
#include "types/debug_trace.hpp"
#include "types/file_buffer.hpp"

// =================================================================================================
// Class Definition
// =================================================================================================

/// @brief The Logger centralizes the collection of debug traces from different components
class Logger
{
  public:
    /// @brief Verbosity level of the logger
    enum log_level_t : uint8_t {
        LOG_NONE = 0,         // Disabled
        LOG_INSTRUCTIONS = 1, // Report PC, registers, memory operations and exceptions
        LOG_SPEC = 2,         // Also report rollbacks and checkpoints
        LOG_DISASM = 3,       // Also report module_name+offset of each instruction
        LOG_MAX = 4,
    };

    /// @param logs_path Path of the file where to dump the binary logs
    /// @param log_level Verbosity level of the logger
    /// @param print If true, every debug entry will be printed to STDOUT when inserted
    Logger(const std::string &logs_path, log_level_t log_level, bool print);
    ~Logger();
    Logger(const Logger &) = delete;
    Logger(Logger &&) = delete;
    Logger &operator=(const Logger &) = delete;
    Logger &operator=(Logger &&) = delete;

    /// @return true if logging is enabled
    [[nodiscard]] bool is_enabled() const { return log_level > LOG_NONE; }
    /// @brief close the file that backs the logger
    void close();
    /// @return the path of the file where the logs are dumped to
    [[nodiscard]] const std::string &get_filename() const;

    /// @brief log the PC and registers of the current instruction, and whether it is speculative
    void log_instruction(instr_obs_t instr, dr_mcontext_t *mc, unsigned int nesting_level);
    /// @brief log a memory operation, including the value that is currently stored at the address
    void log_mem_access(bool is_write, void *address, uint64_t size);
    /// @brief log an exception
    void log_exception(dr_siginfo_t *siginfo);
    /// @brief log a checkpoint that marks a new speculative window
    void log_checkpoint(pc_t rollback_pc, uint64_t cur_window_size, size_t cur_store_log_size);
    /// @brief log a rollback that marks the end of the current speculative window
    void log_rollback(unsigned nesting, pc_t rollback_pc);
    /// @brief log a store that is executed to restore the memory state during a rollback
    void log_rollback_store(uint64_t addr, uint64_t val, size_t size, uint64_t nesting_level);
    /// @brief log end of trace
    void log_eot();

  private:
    /// @param the actual log, implemented as a file-backed buffer
    FileBackedBuf<debug_trace_entry_t> log;
    /// @param verbosity level of the logger
    const log_level_t log_level;
    /// @param current nesting level of speculation
    uint8_t cur_nesting_level;
};
