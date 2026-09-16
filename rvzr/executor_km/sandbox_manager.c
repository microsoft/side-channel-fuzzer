/// File: Sandbox memory management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "actor.h"
#include "code_loader.h" // loaded_test_case_entry
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "page_tables_guest.h"
#include "page_tables_host.h"

sandbox_t *sandbox = NULL; // global

// Util+Data allocation state (alloc_pages + vmap)
static struct {
    void *vaddr_unaligned;    // vmap'd virtual address (unaligned)
    void *vaddr_aligned;      // aligned to 2-page boundary
    struct page **page_array; // array of page pointers for vmap
    int num_pages;            // number of pages allocated
} util_data = {NULL, NULL, NULL, 0};

static void *code = NULL;

/// @brief Free util_data allocation (vmap + physical pages)
static void safe_free_util_data(void)
{
    if (util_data.vaddr_unaligned) {
        vunmap(util_data.vaddr_unaligned);
        util_data.vaddr_unaligned = NULL;
        util_data.vaddr_aligned = NULL;
    }
    if (util_data.page_array) {
        int order = get_order(util_data.num_pages * PAGE_SIZE);
        __free_pages(util_data.page_array[0], order);
        kfree(util_data.page_array);
        util_data.page_array = NULL;
    }
}

/// @brief Free code allocation (vmalloc)
static void safe_free_code(void)
{
    SAFE_VFREE(code);
    loaded_test_case_entry = NULL;
}

/// @brief Initialize sandbox pointers after allocation
/// @return 0 on success, -ENOMEM on failure
static int init_sandbox_pointers(void)
{
    if (!sandbox) {
        sandbox = CHECKED_MALLOC(sizeof(sandbox_t));
    }
    sandbox->data = (actor_data_t *)((unsigned long)util_data.vaddr_aligned + sizeof(util_t));
    sandbox->code = (actor_code_t *)code;
    sandbox->util = (util_t *)util_data.vaddr_aligned;
    loaded_test_case_entry = code;
    return 0;
}

/// @brief Allocate memory for the Util and Data areas of the sandbox
/// @details
/// Constraints:
/// 1. Physical Continuity - Prime+Probe attacks require contiguous physical pages for PIPT caches
/// 2. 4KB Page Tables - Executor must manipulate individual PTEs (impossible with huge pages)
/// 3. 8KB Alignment - Memory must be aligned to 2-page boundary
///
/// Solution: alloc_pages() + vmap()
/// - cannot use kmalloc: physically contiguous BUT uses huge pages in direct mapping
/// - cannot use vmalloc: uses 4KB PTEs BUT not physically contiguous
/// - solution -> alloc_pages + vmap: physically contiguous AND creates new 4KB page tables
///
/// @param n_actors Number of actors
/// @return 0 on success, -ENOMEM on failure
static int allocate_util_and_data(size_t n_actors)
{
    safe_free_util_data();

    // calculate required memory sizes
    const size_t util_mem_size = sizeof(util_t);
    const size_t data_mem_size = n_actors * sizeof(actor_data_t);
    const size_t mem_size = util_mem_size + data_mem_size;
    size_t alloc_size = mem_size + 0x1000; // add 4KB to ensure we can align to 8KB boundary
    util_data.num_pages = (alloc_size + PAGE_SIZE - 1) / PAGE_SIZE;
    int order = get_order(alloc_size);

    // allocate physical pages
    struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!page) {
        PRINT_ERR("Error allocating util_and_data pages\n");
        return -ENOMEM;
    }

    // map the pages into kernel virtual address space
    util_data.page_array = kmalloc(util_data.num_pages * sizeof(struct page *), GFP_KERNEL);
    if (!util_data.page_array) {
        __free_pages(page, order);
        PRINT_ERR("Error allocating page array\n");
        return -ENOMEM;
    }

    for (int i = 0; i < util_data.num_pages; i++) {
        util_data.page_array[i] = page + i;
    }

    util_data.vaddr_unaligned =
        vmap(util_data.page_array, util_data.num_pages, VM_MAP, PAGE_KERNEL);
    if (!util_data.vaddr_unaligned) {
        kfree(util_data.page_array);
        __free_pages(page, order);
        util_data.page_array = NULL;
        PRINT_ERR("Error mapping util_and_data pages\n");
        return -ENOMEM;
    }

    // Align to 2-page (8KB) boundary
    unsigned long addr = (unsigned long)util_data.vaddr_unaligned;
    util_data.vaddr_aligned = (void *)ALIGN(addr, 0x2000);

    return 0;
}

/// @brief Allocate memory for the Code area of the sandbox
/// @details
/// Constraints:
/// 1. Executable - the area holds the test case, which is executed in place
/// 2. 4KB Page Tables - Executor must manipulate individual PTEs (impossible with huge pages)
///
/// Solution: vmalloc() + clearing the NX bit in the resulting PTEs
/// - cannot use the direct mapping of the pages: it is non-executable and uses huge pages
/// - cannot use set_memory_x() to make the area executable: not exported to modules since 5.4
/// - cannot request an executable mapping from vmap() either: it forces NX onto the requested
///   protection flags
///
/// @param n_actors Number of actors (each gets its own code area)
/// @return 0 on success, error code on failure
static int allocate_code(size_t n_actors)
{
    safe_free_code();

    const size_t code_size = n_actors * sizeof(actor_code_t);
    code = CHECKED_VMALLOC(code_size);

    int err = set_code_area_executable((uint64_t)code, DIV_ROUND_UP(code_size, PAGE_SIZE));
    if (err) {
        safe_free_code();
        return err;
    }

    reset_code_area();
    return 0;
}

/// @brief Clears out the code area from previous executions and fills the area with NOPs
/// @param void
/// @return void
void reset_code_area(void)
{
    // fill the code area with NOPs
#if defined(ARCH_X86_64)
    memset(code, 0x90, sizeof(actor_code_t) * n_actors);
#elif defined(ARCH_ARM)
    for (int i = 0; i < n_actors * sizeof(actor_code_t) / 4; i += 1)
        ((uint32_t *)code)[i] = 0xd503201f;
#endif

    // initialize the main section with a single ret instruction
#if defined(ARCH_X86_64)
    ((uint8_t *)code)[0] = '\xC3';
#elif defined(ARCH_ARM)
    ((uint32_t *)code)[0] = 0xd65f03c0;
#endif
}

int allocate_sandbox(void)
{
    int err = 0;
    static int old_n_actors = 1;

    // Allocate sandbox in host memory
    if (old_n_actors < n_actors) {
        err = allocate_util_and_data(n_actors);
        CHECK_ERR("allocate_util_and_data");

        err = allocate_code(n_actors);
        CHECK_ERR("allocate_code");

        err = init_sandbox_pointers();
        CHECK_ERR("init_sandbox_pointers");
    }

    // Make sure that everything is property initialized
    memset(util_data.vaddr_aligned, 0, sizeof(util_t) + n_actors * sizeof(actor_data_t));

    err = cache_host_pteps();
    CHECK_ERR("cache_host_pteps");

    // when necessary, map the sandbox into guest memory and allocate VM management data structures
    if (test_case->features.includes_vm_actors) {
        err = allocate_guest_page_tables();
        CHECK_ERR("allocate_guest_page_tables");

        err = map_sandbox_to_guest_memory();
        CHECK_ERR("map_sandbox_to_guest_memory");
    }
    old_n_actors = n_actors;

    return err;
}

/// @brief Returns the number of pages allocated for the sandbox, including util area, code and data
/// @param void
/// @return number of pages; -1 on error
int get_sandbox_size_pages(void)
{
    if (!sandbox)
        return -1;

    return DIV_ROUND_UP(sizeof(util_t), PAGE_SIZE) +
           DIV_ROUND_UP(sizeof(actor_data_t) * n_actors, PAGE_SIZE) +
           DIV_ROUND_UP(sizeof(actor_code_t) * n_actors, PAGE_SIZE);
}

/// @brief Sets PTE values for the sandbox based on the current test case configuration
/// @param void
/// @return 0 on success; -1 on error
int set_sandbox_page_tables(void)
{
    int err = store_orig_host_permissions();
    CHECK_ERR("store_orig_host_permissions");

    if (test_case->features.includes_user_actors) {
        err = set_user_pages();
        CHECK_ERR("set_user_pages");
    }
    return 0;
}

void restore_orig_sandbox_page_tables(void) { restore_orig_host_permissions(); }

/// @brief Fast modification of the faulty page PTE; sets the permissions according to
/// actor_t->data_permissions
void set_faulty_page_permissions(void)
{
    set_faulty_page_host_permissions();
    set_faulty_page_guest_permissions();
    set_faulty_page_ept_permissions();
}

/// @brief Fast recovery of original permissions of the faulty page PTE
void restore_faulty_page_permissions(void)
{
    restore_faulty_page_host_permissions();
    restore_faulty_page_guest_permissions();
    restore_faulty_page_ept_permissions();
}

// =================================================================================================
int init_sandbox_manager(void)
{
    int err = allocate_util_and_data(1);
    CHECK_ERR("allocate_util_and_data");

    err = allocate_code(1);
    CHECK_ERR("allocate_code");

    err = init_sandbox_pointers();
    CHECK_ERR("init_sandbox_pointers");

    // ensure that the main_area of the first actor is aligned as expected
    int offset = (unsigned long)sandbox->data[0].main_area % 0x2000;
    ASSERT(offset == 0, "init_sandbox_manager");

    // self-test: To enable offset-based accesses in assembly code, we have to hardcode
    //            the layout of the data structures in sandbox_constants.h;
    //            This naturally creates a risk of mismatches, so we perform sanity checks here
    //            to ensure that the layout is as expected.
    util_t *util = sandbox->util;
    ASSERT(&util->l1d_priming_area[0] - (uint8_t *)util == L1D_PRIMING_OFFSET, "init_sandbox");
    ASSERT((uint8_t *)&util->vars.stored_rsp - (uint8_t *)util == STORED_RSP_OFFSET,
           "init_sandbox");
    ASSERT((uint8_t *)&util->vars.latest_measurement - (uint8_t *)util == MEASUREMENT_OFFSET,
           "init_sandbox");
    actor_data_t *data = &sandbox->data[0];
    ASSERT(&data->main_area[0] - (uint8_t *)util == UTIL_REL_TO_MAIN, "init_sandbox");
    ASSERT(&data->main_area[0] - &data->macro_stack[64] == MACRO_STACK_TOP_OFFSET, "init_sandbox");
    ASSERT(&data->faulty_area[0] - &data->main_area[0] == FAULTY_AREA_OFFSET, "init_sandbox");
    ASSERT(&data->reg_init_area[0] - &data->main_area[0] == REG_INIT_OFFSET, "init_sandbox");
    ASSERT(&data->overflow_pad[0] - &data->main_area[0] == OVERFLOW_PAD_OFFSET, "init_sandbox");
    ASSERT(sizeof(measurement_t) == MEASUREMENT_SIZE, "init_sandbox");

    return 0;
}

void free_sandbox_manager(void)
{
    safe_free_util_data();
    safe_free_code();
    free_guest_page_tables();
}
