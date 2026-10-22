///
/// File: Taint Tracker class
///
/// Performs backward taint analysis during DynamoRIO instrumentation to identify which parts
/// of the test input (registers and memory) influence contract trace observations. Tracks data
/// dependencies through instruction execution, supporting speculative execution via checkpoint/
/// rollback. Used to implement `trace_test_case_with_taints` interface in the DR Model backend,
/// and is therefore tightly coupled with rvzr's InputTaint class.
///
/// The module should only be used when the model is running in `rvzr` mode.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "taint_tracker.hpp"

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_set>

#include <dr_api.h>        // NOLINT
#include <dr_ir_instr.h>   // NOLINT
#include <dr_ir_opcodes.h> // NOLINT
#include <dr_ir_opnd.h>    // NOLINT
#include <dr_ir_utils.h>   // NOLINT

// End-of-taint marker written to taint output file
const uint64_t EOT_MARKER = -1ULL;

// Maximum register ID used by DynamoRIO (register IDs are < 256)
// Used to distinguish register labels from memory address labels
const unsigned MAX_REG_ID = 255;

// Memory tracking granularity and alignment
const uint64_t MEM_TRACKING_GRANULARITY = 8; // Track memory at 8-byte granularity
const uint64_t QWORD_ALIGN_MASK = ~0x7ULL;   // Mask for 8-byte alignment (0xFFFFFFFFFFFFFFF8)
const uint64_t SIMD_REGISTER_SIZE = 32;      // XMM/YMM aliases share a 256-bit dependency label

/// @brief Mapping between DynamoRIO EFLAGS bits and our register IDs
struct FlagMapping {
    uint read_flag;
    uint write_flag;
    reg_id_t reg_id;
};

/// @brief Table of all tracked flags
/// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
static const FlagMapping FLAG_MAPPINGS[] = {
    {EFLAGS_READ_CF, EFLAGS_WRITE_CF, DR_FLAG_CF}, {EFLAGS_READ_PF, EFLAGS_WRITE_PF, DR_FLAG_PF},
    {EFLAGS_READ_AF, EFLAGS_WRITE_AF, DR_FLAG_AF}, {EFLAGS_READ_ZF, EFLAGS_WRITE_ZF, DR_FLAG_ZF},
    {EFLAGS_READ_SF, EFLAGS_WRITE_SF, DR_FLAG_SF}, {EFLAGS_READ_OF, EFLAGS_WRITE_OF, DR_FLAG_OF},
    {EFLAGS_READ_DF, EFLAGS_WRITE_DF, DR_FLAG_DF},
};

/// @brief Set of opcodes that override dependencies (MOV and LEA variants)
static const std::unordered_set<int> OVERRIDE_OPCODES = {
    OP_mov_ld, OP_mov_st, OP_mov_imm, OP_mov_priv, OP_movd,  OP_movq,
    OP_movs,   OP_movsx,  OP_movzx,   OP_movsxd,   OP_movbe, OP_lea,
};

// =================================================================================================
// Helper Functions
// =================================================================================================

/// @brief Normalize GPRs to 64 bits and SIMD aliases to their shared YMM register
/// @param reg The register ID
/// @return Normalized register ID
static inline reg_id_t normalize_reg(reg_id_t reg)
{
    // For GPRs, normalize to 64-bit version
    if (reg_is_gpr(reg)) {
        return reg_resize_to_opsz(reg, OPSZ_8);
    }
    if (reg_is_strictly_xmm(reg) || reg_is_strictly_ymm(reg)) {
        return reg_resize_to_opsz(reg, OPSZ_32);
    }
    return reg;
}

static inline void track_operand(const bool is_src, const opnd_t opnd,
                                 struct TrackedInstruction *tracked_inst)
{
    // Process register operands
    if (opnd_is_reg(opnd)) {
        const reg_id_t reg = normalize_reg(opnd_get_reg(opnd));
        if (reg == DR_REG_NULL) {
            return;
        }
        if (is_src) {
            tracked_inst->src_regs.insert(reg);
        } else {
            tracked_inst->dest_regs.insert(reg);
        }
        return;
    }

    // Non-memory non-register - ignore
    if (not opnd_is_memory_reference(opnd)) {
        return;
    }

    // Base + displacement memory reference
    if (opnd_is_base_disp(opnd)) {
        const reg_id_t base = opnd_get_base(opnd);
        const reg_id_t index = opnd_get_index(opnd);
        if (base != DR_REG_NULL) {
            tracked_inst->mem_address_regs.insert(normalize_reg(base));
        }
        if (index != DR_REG_NULL) {
            tracked_inst->mem_address_regs.insert(normalize_reg(index));
        }
        return;
    }

    // Base-only memory reference
    const reg_id_t base = opnd_get_base(opnd);
    if (base != DR_REG_NULL) {
        tracked_inst->mem_address_regs.insert(normalize_reg(base));
    }
}

static inline void track_flags(const uint eflags, struct TrackedInstruction *tracked_inst)
{
    // Process each flag in the mapping table
    for (const auto &mapping : FLAG_MAPPINGS) {
        if ((eflags & mapping.read_flag) != 0) {
            tracked_inst->src_regs.insert(mapping.reg_id);
        }
        if ((eflags & mapping.write_flag) != 0) {
            tracked_inst->dest_regs.insert(mapping.reg_id);
        }
    }
}

/// @brief Convert DynamoRIO register ID to the encoding expected by rvzr (hardcoded mapping)
/// @param reg
/// @return rvzr register ID
static RVZRRegId dr_reg_id_to_rvzr_reg_id(reg_id_t reg)
{
    // These IDs must match the offsets in the sandbox, as defined in docs/devel/
    switch (reg) {
    case DR_REG_RAX:
        return RVZRRegId::RVZR_REG_RAX;
    case DR_REG_RBX:
        return RVZRRegId::RVZR_REG_RBX;
    case DR_REG_RCX:
        return RVZRRegId::RVZR_REG_RCX;
    case DR_REG_RDX:
        return RVZRRegId::RVZR_REG_RDX;
    case DR_REG_RSI:
        return RVZRRegId::RVZR_REG_RSI;
    case DR_REG_RDI:
        return RVZRRegId::RVZR_REG_RDI;
    case DR_REG_XMM0:
    case DR_REG_YMM0:
        return RVZRRegId::RVZR_REG_XMM0;
    case DR_REG_XMM1:
    case DR_REG_YMM1:
        return RVZRRegId::RVZR_REG_XMM1;
    case DR_REG_XMM2:
    case DR_REG_YMM2:
        return RVZRRegId::RVZR_REG_XMM2;
    case DR_REG_XMM3:
    case DR_REG_YMM3:
        return RVZRRegId::RVZR_REG_XMM3;
    case DR_REG_XMM4:
    case DR_REG_YMM4:
        return RVZRRegId::RVZR_REG_XMM4;
    case DR_REG_XMM5:
    case DR_REG_YMM5:
        return RVZRRegId::RVZR_REG_XMM5;
    case DR_REG_XMM6:
    case DR_REG_YMM6:
        return RVZRRegId::RVZR_REG_XMM6;
    case DR_REG_XMM7:
    case DR_REG_YMM7:
        return RVZRRegId::RVZR_REG_XMM7;
    case DR_FLAG_AF:
    case DR_FLAG_CF:
    case DR_FLAG_DF:
    case DR_FLAG_OF:
    case DR_FLAG_PF:
    case DR_FLAG_SF:
    case DR_FLAG_ZF:
        // All tainted flags map to a single taint ID
        return RVZRRegId::RVZR_REG_FLAGS;
    default:
        // The rest of the registers are not used by rvzr; if they get tainted, this is
        // an artifact of the adaptor, and they should be ignored.
        return RVZRRegId::RVZR_REG_IGNORED;
    }
}

/// @brief Check if an instruction is a 64+ bit MOV-like instruction that overrides dependencies
/// @param tracked_inst The tracked instruction to check
/// @param decoder Decoder for instruction analysis
/// @return true if the instruction overrides dependencies
static bool is_override_instruction(const TrackedInstruction *tracked_inst, Decoder *decoder)
{
    // Only MOV and LEA opcodes override dependencies
    auto opcode = static_cast<int>(tracked_inst->instr_obs.opcode);
    if (OVERRIDE_OPCODES.find(opcode) == OVERRIDE_OPCODES.end()) {
        return false;
    }

    // Skip instructions with more than one destination operand
    if (tracked_inst->dest_regs.size() != 1) {
        return false;
    }

    // SIMD labels include upper lanes preserved by partial writes, so retain their dependencies.
    const reg_id_t dest_reg = *tracked_inst->dest_regs.begin();
    if (reg_is_gpr(dest_reg)) {
        instr_t *instr =
            decoder->get_decoded_instr(tracked_inst->dc, (byte *)tracked_inst->instr_obs.pc);
        const int size = opnd_get_size(instr_get_dst(instr, 0));
        return size == OPSZ_8;
    }
    return false;
}

/// @brief Heuristic to determine if a label represents a register or memory address
/// @param label The label to check
/// @return true if label likely represents a register, false if likely a memory address
/// @note DynamoRIO register IDs are < 256, while memory addresses are much larger.
///       May incorrectly classify low memory addresses (e.g., NULL page) as registers,
///       but this is rare and only affects performance, not correctness.
static bool label_is_reg(tracked_label_t label) { return label <= MAX_REG_ID; }

// =================================================================================================
// Public Methods
// =================================================================================================
void TaintTracker::enable()
{
    DR_ASSERT(not tracking_in_progress);
    dependencies.reg.clear();
    dependencies.mem.clear();
    checkpoints.clear();
    tainted_labels.clear();
    pending_taint.clear();
    current_instruction.reset();
    enabled = true;
    tracking_in_progress = true;
    sandbox_base = 0; // Will be set on first instruction
}

void TaintTracker::disable() { enabled = false; }

void TaintTracker::finalize()
{
    if (current_instruction != nullptr) {
        finalize_instruction();
    }

    store_taints();
    enabled = false;
    tracking_in_progress = false;
}

void TaintTracker::checkpoint(bool include_current_inst)
{
    if (not enabled)
        return;

    if (include_current_inst && current_instruction != nullptr) {
        finalize_instruction();
    }

    // Deep copy the dependencies
    checkpoints.push_back(dependencies);
}

void TaintTracker::rollback()
{
    if (not enabled)
        return;
    DR_ASSERT_MSG(not checkpoints.empty(), "TaintTracker::rollback: no checkpoints to rollback");

    if (current_instruction != nullptr) {
        finalize_instruction();
    }

    // Restore dependencies from the last checkpoint
    dependencies = checkpoints.back();
    checkpoints.pop_back();
}

void TaintTracker::track_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    if (not enabled)
        return;

    // Capture sandbox base from R14 on first instruction
    if (sandbox_base == 0 && mc != nullptr) {
        sandbox_base = mc->r14;
    }

    // Finalize the previous instruction
    if (current_instruction != nullptr) {
        finalize_instruction();
    }
    // dr_printf("--------------------------------\n");

    // Create a new tracked instruction
    current_instruction = std::make_unique<TrackedInstruction>();
    current_instruction->instr_obs = instr;
    current_instruction->dc = dc;

    // Parse the instruction operands
    parse_instruction_operands(current_instruction.get());

    // Reset pending taint
    pending_taint.clear();
}

void TaintTracker::track_memory_access(bool is_write, void *address, uint64_t size)
{
    if (not enabled)
        return;
    DR_ASSERT_MSG(current_instruction != nullptr,
                  "TaintTracker::track_memory_access called before track_instruction");

    // The following logic records the memory address into the list of
    // source/destination memory operands
    // The challenge here is that we track memory at 8-byte granularity, and a memory access
    // may span multiple 8-byte blocks (e.g., a YMM store of 32 bytes).

    // 1. Identify the range of 8-byte blocks accessed
    auto addr = (uint64_t)address;
    const uint64_t end_addr = addr + (size - 1);
    const uint64_t range_start = addr & QWORD_ALIGN_MASK;
    const uint64_t range_end = end_addr & QWORD_ALIGN_MASK;

    // 2. Identify whether it's a read or write, and add to the appropriate set
    std::set<tracked_mem_label_t> *updated_set =
        is_write ? &current_instruction->dest_mems : &current_instruction->src_mems;

    // 3. Add all addresses to tracking
    for (uint64_t i = range_start; i <= range_end; i += MEM_TRACKING_GRANULARITY) {
        updated_set->insert(i);
    }
}

void TaintTracker::taint(taint_entry_type_t value_type)
{
    if (not enabled)
        return;
    if (current_instruction == nullptr)
        return;

    switch (value_type) {
    case taint_entry_type_t::TAINT_ENTRY_PC:
        // For PC: if the instruction is a control-flow instruction, taint RIP
        {
            instr_t *instr = decoder.get_decoded_instr(current_instruction->dc,
                                                       (byte *)current_instruction->instr_obs.pc);
            if ((instr_is_cbr(instr) || instr_is_ubr(instr))) {
                pending_taint.insert(static_cast<tracked_label_t>(DR_REG_RIP));
            }
        }
        break;

    case taint_entry_type_t::TAINT_ENTRY_MEM:
        // For MEM: taint memory address registers
        {
            for (const auto &reg : current_instruction->mem_address_regs) {
                pending_taint.insert(static_cast<tracked_label_t>(reg));
            }
        }
        break;

    case taint_entry_type_t::TAINT_ENTRY_EOT:
        // End of trace - do nothing
        break;
    }
}

void TaintTracker::finalize_instruction()
{
    DR_ASSERT_MSG(current_instruction != nullptr,
                  "TaintTracker::finalize_instruction called before track_instruction");

    // Extract dependencies of the tracked instruction
    add_dependencies(current_instruction.get());

    // Update taints - propagate dependencies to tainted labels
    for (const auto &label : pending_taint) {
        std::set<tracked_label_t> tainted_values;

        // Check if label is a memory address (high bit set or > max register ID)
        // Register IDs are typically small (< 256), memory addresses are large
        if (label_is_reg(label)) {
            auto it = dependencies.reg.find(static_cast<tracker_reg_label_t>(label));
            if (it != dependencies.reg.end()) {
                tainted_values = it->second;
            } else {
                tainted_values.insert(label);
            }
        } else {
            auto it = dependencies.mem.find(label);
            if (it != dependencies.mem.end()) {
                tainted_values = it->second;
            } else {
                tainted_values.insert(label);
            }
        }

        tainted_labels.insert(tainted_values.begin(), tainted_values.end());
    }
    dbg_print_taints();

    // Clear dependencies of overwritten registers
    // NOTE: this must be done *after* the taint update, or the taints will be lost
    // dbg_print_dependencies();
    remove_overwritten_dependencies(current_instruction.get());
    dbg_print_dependencies();

    // Reset the instruction
    current_instruction.reset();
}

// =================================================================================================
// Private Methods
// =================================================================================================

void TaintTracker::parse_instruction_operands(TrackedInstruction *tracked_inst)
{
    // Decode the instruction from PC (using cache for efficiency)
    instr_t *instr =
        decoder.get_decoded_instr(tracked_inst->dc, (byte *)tracked_inst->instr_obs.pc);

    // Process destination operands
    const int num_dsts = instr_num_dsts(instr);
    for (int i = 0; i < num_dsts; i++) {
        const opnd_t opnd = instr_get_dst(instr, i);
        track_operand(false, opnd, tracked_inst);
    }

    // Process source operands
    const int num_srcs = instr_num_srcs(instr);
    for (int i = 0; i < num_srcs; i++) {
        const opnd_t opnd = instr_get_src(instr, i);
        track_operand(true, opnd, tracked_inst);
    }

    // Check for implicit EFLAGS operands (DynamoRIO doesn't include them in explicit operands)
    const uint eflags = instr_get_eflags(instr, DR_QUERY_DEFAULT);
    track_flags(eflags, tracked_inst);

    // Check for implicit RIP operand (for control-flow instructions)
    if (instr_is_cbr(instr) || instr_is_ubr(instr)) {
        tracked_inst->dest_regs.insert(DR_REG_RIP);
    }
}

std::set<tracked_label_t>
TaintTracker::collect_source_dependencies(const TrackedInstruction *tracked_inst) const
{
    std::set<tracked_label_t> src_dependencies;

    // Collect dependencies from source registers
    for (const auto &reg : tracked_inst->src_regs) {
        auto it = dependencies.reg.find(reg);
        if (it != dependencies.reg.end()) {
            src_dependencies.insert(it->second.begin(), it->second.end());
        } else {
            src_dependencies.insert(static_cast<tracked_label_t>(reg));
        }
    }

    // Collect dependencies from source memory locations
    for (const auto &addr : tracked_inst->src_mems) {
        auto it = dependencies.mem.find(addr);
        if (it != dependencies.mem.end()) {
            src_dependencies.insert(it->second.begin(), it->second.end());
        } else {
            src_dependencies.insert(addr);
        }
    }

    // Collect dependencies from memory address registers
    for (const auto &reg : tracked_inst->mem_address_regs) {
        auto it = dependencies.reg.find(reg);
        if (it != dependencies.reg.end()) {
            src_dependencies.insert(it->second.begin(), it->second.end());
        } else {
            src_dependencies.insert(static_cast<tracked_label_t>(reg));
        }
    }

    return src_dependencies;
}

template <typename LabelT>
void TaintTracker::propagate_dependencies_to_dest(
    LabelT dest_label, const std::set<tracked_label_t> &src_dependencies,
    std::map<LabelT, std::set<tracked_label_t>> &dep_map)
{
    // If destination already has dependencies, merge with source dependencies
    if (dep_map.find(dest_label) != dep_map.end()) {
        dep_map[dest_label].insert(src_dependencies.begin(), src_dependencies.end());
    } else {
        // Create new dependency entry with source dependencies
        dep_map[dest_label] = src_dependencies;
        // Add the destination itself to its own dependencies
        dep_map[dest_label].insert(static_cast<tracked_label_t>(dest_label));
    }
}

// Explicit template instantiations
template void TaintTracker::propagate_dependencies_to_dest(
    tracker_reg_label_t, const std::set<tracked_label_t> &,
    std::map<tracker_reg_label_t, std::set<tracked_label_t>> &);
template void TaintTracker::propagate_dependencies_to_dest(
    tracked_mem_label_t, const std::set<tracked_label_t> &,
    std::map<tracked_mem_label_t, std::set<tracked_label_t>> &);

void TaintTracker::add_dependencies(const TrackedInstruction *tracked_inst)
{
    // Get dependencies of the source operands
    const std::set<tracked_label_t> src_dependencies = collect_source_dependencies(tracked_inst);

    // Propagate source dependencies to destination registers
    for (const auto &reg : tracked_inst->dest_regs) {
        propagate_dependencies_to_dest(reg, src_dependencies, dependencies.reg);
    }

    // Propagate source dependencies to destination memory locations
    for (const auto &mem : tracked_inst->dest_mems) {
        propagate_dependencies_to_dest(mem, src_dependencies, dependencies.mem);
    }
}

void TaintTracker::remove_overwritten_dependencies(const TrackedInstruction *tracked_inst)
{
    // Check if this is a MOV or LEA instruction that overrides previous dependencies
    if (not is_override_instruction(tracked_inst, &decoder)) {
        return;
    }

    // Get source dependencies (reuse helper to avoid duplication)
    // Note: We only need src_regs and src_mems here, not mem_address_regs,
    // but including them doesn't affect correctness and keeps code simple
    std::set<tracked_label_t> src_dependencies = collect_source_dependencies(tracked_inst);

    // Remove dependencies that are not in source dependencies
    const tracker_reg_label_t dest_reg = *tracked_inst->dest_regs.begin();
    auto it = dependencies.reg.find(dest_reg);
    if (it != dependencies.reg.end()) {
        auto &deps = it->second;
        for (auto dep_it = deps.begin(); dep_it != deps.end();) {
            if (src_dependencies.find(*dep_it) == src_dependencies.end()) {
                dep_it = deps.erase(dep_it);
            } else {
                ++dep_it;
            }
        }
    }
}

void TaintTracker::store_taints()
{
    DR_ASSERT_MSG(stream.is_open(), "TaintTracker::store_taints: output stream is not open");

    // Write all collected labels to the output file
    for (const auto &label : tainted_labels) {
        uint64_t value = 0;
        uint64_t size = MEM_TRACKING_GRANULARITY;
        if (label_is_reg(label)) {
            const auto dr_reg_id = static_cast<reg_id_t>(label);
            const RVZRRegId reg_id = dr_reg_id_to_rvzr_reg_id(dr_reg_id);
            if (reg_id == RVZRRegId::RVZR_REG_IGNORED) {
                continue; // Do not store taints of ignored registers
            }
            value = static_cast<uint64_t>(reg_id);
            if (reg_is_xmm(dr_reg_id) || reg_is_ymm(dr_reg_id)) {
                size = SIMD_REGISTER_SIZE;
            }
        } else {
            // Memory address: convert from absolute to sandbox-relative
            DR_ASSERT_MSG(sandbox_base != 0,
                          "TaintTracker::store_taints: sandbox_base not initialized");
            value = label - sandbox_base;
        }

        // Each output entry protects one qword of the input during boosting.
        for (uint64_t offset = 0; offset < size; offset += MEM_TRACKING_GRANULARITY) {
            const uint64_t entry = value + offset;
            stream.write(reinterpret_cast<const char *>(&entry), sizeof(entry));
        }
    }

    // Write end-of-taint marker
    auto eot = EOT_MARKER;
    stream.write(reinterpret_cast<const char *>(&eot), sizeof(uint64_t));

    // NOTE: the file is not closed here as more taints may be added later if we
    // are tracing multiple inputs; the stream is closed in the destructor
}

void TaintTracker::dbg_print_taints()
{
    dr_printf("[TAINT] Tainted labels after instruction:\n");
    for (const auto &label : tainted_labels) {
        dr_printf("  Tainted label: %lx\n", label);
    }
}

void TaintTracker::dbg_print_dependencies()
{
    dr_printf("[TAINT] Dependencies after instruction:\n");
    for (const auto &reg_dep : dependencies.reg) {
        dr_printf("  Reg 0x%2lx depends on: ", reg_dep.first);
        for (const auto &dep : reg_dep.second) {
            dr_printf("0x%lx ", dep);
        }
        dr_printf("\n");
    }
    for (const auto &mem_dep : dependencies.mem) {
        dr_printf("  Mem 0x%lx depends on: ", mem_dep.first);
        for (const auto &dep : mem_dep.second) {
            dr_printf("0x%lx ", dep);
        }
        dr_printf("\n");
    }
    dr_printf("------------------------------------------------\n");
}
