///
/// File: Abstract Model TracerABC
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_ir_instr.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include <drmgr.h>
#include <drreg.h>
#include <drvector.h>

#include "observables.hpp"
#include "tracer_abc.hpp"
#include "types/input_taint.hpp"
#include "types/trace.hpp"

using std::string;

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
TracerABC::TracerABC(const std::string &out_path, Logger &logger, TaintTracker &taint_tracker,
                     Decoder &decoder, bool print)
    : logger(logger), taint_tracker(taint_tracker), decoder(decoder), trace(print)
{
    // Initialize trace buffers
    trace.open(out_path);
}

TracerABC::~TracerABC()
{
    if (not tracing_finalized) {
        finalize();
    }
    trace.clear();
    if (logger.is_enabled()) {
        logger.close();
    }
}

// =================================================================================================
// Public Methods
// =================================================================================================
void TracerABC::enable()
{
    tracing_on = true;
    tracing_finalized = false;
}

void TracerABC::finalize()
{
    if (tracing_finalized) {
        return;
    }

    // Push the end-of-trace marker and flush the remaining entries.
    trace.push_back({.type = trace_entry_type_t::ENTRY_EOT});
    trace.flush();

    // Print the trace buffers
    if (logger.is_enabled()) {
        logger.log_eot();
    }

    // Reset tracing flags
    tracing_on = false;
    tracing_finalized = true;
}

void TracerABC::observe_instruction(instr_obs_t /*instr*/, dr_mcontext_t * /*mc*/, void * /*dc*/)
{
    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool /*is_write*/, void * /*address*/, uint64_t /*size*/)
{
    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_exception(dr_siginfo_t *siginfo) const
{
    if (not tracing_on) {
        return;
    }

    trace.push_back({.addr = (pc_t)siginfo->access_address,
                     .size = (uint16_t)siginfo->sig,
                     .type = trace_entry_type_t::ENTRY_EXCEPTION});
}

void TracerABC::record_pc(instr_obs_t instr)
{
    taint_tracker.taint(taint_entry_type_t::TAINT_ENTRY_PC);

    const trace_entry_t entry = {
        .addr = instr.pc,
        .size = 0,
        .type = trace_entry_type_t::ENTRY_PC,
    };
    trace.push_back(entry);
}

void TracerABC::record_mem_access(bool is_write, void *address, uint64_t size)
{
    taint_tracker.taint(taint_entry_type_t::TAINT_ENTRY_MEM);

    const trace_entry_t entry = {
        .addr = reinterpret_cast<uint64_t>(address),
        .size = (uint16_t)size,
        .type = (is_write) ? trace_entry_type_t::ENTRY_WRITE : trace_entry_type_t::ENTRY_READ,
    };
    trace.push_back(entry);
}
