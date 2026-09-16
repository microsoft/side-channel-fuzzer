/// File: Multiple variants of test case entry and exit points, for ARM64 architecture
///      used exclusively by code_loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "code_loader.h"
#include "macro_expansion.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "fault_handler.h"

#ifdef ARCH_X86_64
#include "x86/entry_exit_points.h"
#elif defined(ARCH_ARM)
#include "arm64/entry_exit_points.h"
#endif

// =================================================================================================
// Local constants and declarations
// =================================================================================================

#define PER_SECTION_ALLOC_SIZE (MAX_EXPANDED_SECTION_SIZE + MAX_EXPANDED_MACROS_SIZE)
#define MAX_TEMPLATE_SIZE      0x1000 // for sanity checking

uint8_t *loaded_test_case_entry = NULL; // global

static int load_section_main(void);
static int load_section(uint64_t section_id);
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id);
static int expand_section(uint64_t section_id, uint8_t *dest, uint8_t *macros_dest,
                          size_t *size_section, size_t *size_macros);

// =================================================================================================
// Code Loader logic
// =================================================================================================
int load_sandbox_code(void)
{
    int err = 0;
    ASSERT(sandbox->code != NULL, "load_sandbox_code");

    // Re-initialize the code area with NOPs
    reset_code_area();

    // Load the code for each section
    for (int section_id = 0; section_id < n_actors; section_id++) {
        if (section_id == 0)
            err |= load_section_main();
        else
            err |= load_section(section_id);
    }

    // TODO: on arm64, the I-cache is not coherent with the stores above; the code area requires
    //       cache maintenance (dc cvau; dsb ish; ic ivau; dsb ish; isb) before it is executed
    return err;
}

static int load_section(uint64_t section_id)
{
    uint8_t *section = sandbox->code[section_id].section;
    uint8_t *macros = sandbox->code[section_id].macros;
    size_t size_section = 0, size_macros = 0;
    int err = expand_section(section_id, section, macros, &size_section, &size_macros);
    CHECK_ERR("load_section");

    return 0;
}

static int load_section_main(void)
{
    int err = 0;

    ASSERT(test_case->metadata[0].owner == 0, "load_section_main");
    uint8_t *dest = (uint8_t *)&sandbox->code[0].section;
    uint8_t *macro_dest = sandbox->code[0].macros;

    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_cursor = 0;

    // reset globals
    fault_handler = NULL;
    loaded_test_case_entry = NULL;

    // select a template based on the debug mode
    uint8_t *src = (dbg_gpr_mode) ? (uint8_t *)main_segment_template_dbg_gpr
                                  : (uint8_t *)main_segment_template;

    // skip instructions inserted by the compiler and start at the TEMPLATE_START marker
    for (;; src_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_START");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_START)
            break;
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // copy the first part of the template
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_INSERT_TC");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_INSERT_TC)
            break;
        dest[dest_cursor] = src[src_cursor];
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // notify Macro Loader about the prologue size of the main section
    set_main_prologue_size(dest_cursor);

    // copy the test case into the template and expand macros
    size_t size_section = 0, size_macros = 0;
    err = expand_section(0, &dest[dest_cursor], macro_dest, &size_section, &size_macros);
    CHECK_ERR("load_section_main");
    dest_cursor += size_section;
    macros_cursor += size_macros;

    // set fault handler if the test case does not already declare an explicit one
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; EXCEPTION_LANDING");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_DEFAULT_EXCEPTION_LANDING) {

            // if the test case has an explicit fault handler, we just skip the macro
            // and leave the 8 NOP bytes for compatibility
            if (test_case->features.has_explicit_fault_handler) {
                dest_cursor += MACRO_PLACEHOLDER_SIZE;
                break;
            }

            // set the fault handler to the default one (end of the main actor)
            fault_handler = (char *)&dest[dest_cursor];

            // expand the macro for the default fault handler
            tc_symbol_entry_t measurement_end = (tc_symbol_entry_t){
                .id = MACRO_FAULT_HANDLER_WITH_MEASUREMENT, .offset = 0, .owner = 0, .args = 0};
            size_macros = 0;
            err = expand_macro(&measurement_end, &dest[dest_cursor], &macro_dest[macros_cursor],
                               &size_macros);
            CHECK_ERR("load_section_main");

            macros_cursor += size_macros;
            dest_cursor += MACRO_PLACEHOLDER_SIZE;
            break;
        }
        dest[dest_cursor] = src[src_cursor];
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // write the rest of the template
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main: TEMPLATE_END");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_END)
            break;
        dest[dest_cursor] = src[src_cursor];
    }
    ASSERT(dest_cursor < MAX_EXPANDED_SECTION_SIZE, "load_section_main");

    loaded_test_case_entry = dest;
    return 0;
}

/// @brief Get the first macro in a section
/// @param section_id ID of the section
/// @return Pointer to the first macro in the section, or NULL if there are no macros
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id)
{
    tc_symbol_entry_t *entry = test_case->symbol_table;
    tc_symbol_entry_t *end = entry + (test_case->symbol_table_size / sizeof(*entry));
    while (entry->owner != section_id || entry->id == 0) {
        entry++;
        if (entry >= end)
            return NULL;
    }
    return entry;
}

/// @brief Expand a section and its macros into destination buffers
/// @param[in] section_id ID of the section to expand
/// @param[in] dest Destination address for the expanded section code
/// @param[in] macros_dest Destination address for the expanded macros
/// @param[out] size_section Size of the expanded section
/// @param[out] size_macros Size of the expanded macros
/// @return 0 on success, -1 on failure
static int expand_section(uint64_t section_id, uint8_t *dest, uint8_t *macros_dest,
                          size_t *size_section, size_t *size_macros)
{
    int err = 0;
    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_cursor = 0;

    // get the unexpanded section
    uint8_t *section = test_case->sections[section_id].code;
    size_t section_size = test_case->metadata[section_id].size;
    ASSERT(section_size <= MAX_SECTION_SIZE, "expand_section");

    // get the first macro in the section
    tc_symbol_entry_t *macro = get_section_macros_start(section_id);

    // If there are no macros to expand, just copy the code
    if (macro == NULL) {
        memcpy(dest, section, section_size);
        *size_section = section_size;
        *size_macros = 0;
        return 0;
    }

    // Otherwise, expand macros by iterating over the section and calling expand_macro
    // whenever we encounter a macro placeholder
    for (src_cursor = 0; src_cursor < section_size; src_cursor++, dest_cursor++) {
        // if a byte is *not* a macro placeholder, just copy it
        if (macro == NULL || src_cursor != macro->offset) {
            dest[dest_cursor] = section[src_cursor];
            continue;
        }
        // PRINT_ERR("macro id: %d, macro owner: %d, macro args: %d, offset: %d\n", macro->id,
        //   macro->owner, macro->args, macro->offset);

        // if we're here, we have a macro placeholder
        ASSERT(macro->owner == section_id, "expand_section");
        ASSERT(macro->id != 0, "expand_section");

        // expand the macro into the destination buffers
        size_t macro_size = 0;
        err = expand_macro(macro, &dest[dest_cursor], &macros_dest[macros_cursor], &macro_size);
        CHECK_ERR("expand_section");

        // move the cursors
        src_cursor += MACRO_PLACEHOLDER_SIZE - 1;  // -1 because it will be incremented in the loop
        dest_cursor += MACRO_PLACEHOLDER_SIZE - 1; // -1 because it will be incremented in the loop
        macros_cursor += macro_size;
        macro++;

        // if we're done with macros in this section, set the macro pointer to NULL
        if (macro->owner != section_id)
            macro = NULL;
    }

    // ensure that we did not have an overrun
    ASSERT(src_cursor == section_size, "expand_section");

    *size_section = dest_cursor;
    *size_macros = macros_cursor;
    return 0;
}

// =================================================================================================
int init_code_loader(void)
{
    // NOTE: we assume the sandbox is already allocated by sandbox_manager
    return 0;
}

void free_code_loader(void) {}
