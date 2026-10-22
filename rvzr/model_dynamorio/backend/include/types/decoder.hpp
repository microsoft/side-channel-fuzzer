///
/// File: Instruction Decoder
///       Decodes and caches DynamoRIO instructions to avoid redundant decoding
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <unordered_map>

#include <dr_api.h>      // NOLINT
#include <dr_ir_instr.h> // NOLINT
#include <dr_ir_utils.h> // NOLINT

/// @brief Cached entry containing decoded instruction and next PC
struct CachedInstr {
    instr_noalloc_t instr;
    byte *next_pc;
};

/// @brief Decoder for DynamoRIO instructions with caching
///
/// This class decodes instructions and caches them indexed by their program counter (PC).
/// Instructions are stored as instr_noalloc_t objects, which handle their own cleanup
/// automatically, eliminating the need for manual memory management.
/// The cache also stores the next PC (address after the instruction) for efficient
/// sequential access.
///
/// Usage:
///   Decoder decoder;
///   instr_t *instr = decoder.get_decoded_instr(drcontext, pc);
///   byte *next_pc = decoder.get_next_pc(drcontext, pc);
///   decoder.clear(); // Clear when done
class Decoder
{
  public:
    Decoder() = default;
    ~Decoder() { clear(); }

    // Delete copy/move constructors and assignment operators
    Decoder(const Decoder &) = delete;
    Decoder &operator=(const Decoder &) = delete;
    Decoder(Decoder &&) = delete;
    Decoder &operator=(Decoder &&) = delete;

    /// @brief Get a decoded instruction from cache or decode and cache it
    /// @param drcontext DynamoRIO context
    /// @param pc Program counter of the instruction
    /// @return Pointer to the decoded instruction
    /// @throw dr_abort if decoding fails
    instr_t *get_decoded_instr(void *drcontext, byte *pc)
    {
        // NOLINTNEXTLINE(misc-const-correctness) ; False Positive
        CachedInstr &cached_entry = cache_access(drcontext, pc);
        instr_noalloc_t *noalloc = &cached_entry.instr;
        return instr_from_noalloc(noalloc);
    }

    /// @brief Get the next PC (address after the instruction) from cache or decode and cache it
    /// @param drcontext DynamoRIO context
    /// @param pc Program counter of the instruction
    /// @return The next PC (address immediately following the instruction)
    /// @throw dr_abort if decoding fails
    byte *get_next_pc(void *drcontext, byte *pc)
    {
        const CachedInstr &cached_entry = cache_access(drcontext, pc);
        return cached_entry.next_pc;
    }

    /// @brief Clear the instruction cache
    void clear()
    {
        // Note: instr_noalloc_t destructor handles cleanup automatically
        cache.clear();
    }

    /// @brief Get the number of cached instructions
    /// @return Number of cached instructions
    [[nodiscard]] size_t size() const { return cache.size(); }

    /// @brief Check if the cache is empty
    /// @return True if cache is empty
    [[nodiscard]] bool empty() const { return cache.empty(); }

  private:
    /// @brief Cache of decoded instructions and their next PCs, indexed by PC
    std::unordered_map<byte *, CachedInstr> cache;

    /// @brief Access cached entry by PC. If not present, creates a new entry.
    /// @param pc Program counter of the instruction
    /// @return Reference to the cached instruction entry
    CachedInstr &cache_access(void *drcontext, byte *pc)
    {
        // Cache hit
        auto it = cache.find(pc);
        if (it != cache.end()) {
            return it->second;
        }

        // Cache miss - create new entry
        CachedInstr &cached_entry = cache[pc];
        instr_noalloc_init(drcontext, &cached_entry.instr);
        instr_t *instr = instr_from_noalloc(&cached_entry.instr);

        byte *next_pc = decode(drcontext, pc, instr);
        if (next_pc == nullptr) {
            // Decode failed - remove from cache and abort
            cache.erase(pc);
            dr_printf("[ERROR] Decoder: Failed to decode instruction at PC %p\n", (void *)pc);
            dr_abort();
        }

        // MOVNTDQA is a load; normalize DynamoRIO's reversed memory/register operands.
        if (instr_get_opcode(instr) == OP_movntdqa && instr_num_srcs(instr) == 1 &&
            instr_num_dsts(instr) == 1 && opnd_is_memory_reference(instr_get_dst(instr, 0))) {
            const opnd_t memory = instr_get_dst(instr, 0);
            const opnd_t reg = instr_get_src(instr, 0);
            instr_set_src(instr, 0, memory);
            instr_set_dst(instr, 0, reg);
        }

        // Cache the next_pc
        cached_entry.next_pc = next_pc;

        return cached_entry;
    }
};
