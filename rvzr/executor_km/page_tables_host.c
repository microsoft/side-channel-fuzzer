/// File:
///  - Page Table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "actor.h"
#include "hardware_desc.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "page_tables_common.h"
#include "page_tables_host.h"

#if defined(ARCH_X86_64)
#include <asm/pgtable_types.h> // _PAGE_PSE
#include <asm/special_insns.h> // read_cr3_pa()
#elif defined(ARCH_ARM)
#include <asm/pgtable-hwdef.h> // PUD_TYPE_TABLE, PMD_TYPE_TABLE
#endif

#if defined(ARCH_X86_64)
#define IS_PUD_LEAF(pud) ((pud_val(pud) & _PAGE_PSE) != 0)
#define IS_PMD_LEAF(pmd) ((pmd_val(pmd) & _PAGE_PSE) != 0)
#elif defined(ARCH_ARM)
#define IS_PUD_LEAF(pud) ((pud_val(pud) & PUD_TYPE_MASK) != PUD_TYPE_TABLE)
#define IS_PMD_LEAF(pmd) ((pmd_val(pmd) & PMD_TYPE_MASK) != PMD_TYPE_TABLE)
#endif

sandbox_pteps_t *sandbox_pteps;

static sandbox_ptes_t *orig_ptes;
static pte_t_ *faulty_ptes = NULL;

// =================================================================================================
// Kernel top-level page-table base resolution
//
// `get_pte()` walks the kernel/vmalloc half of the address space and therefore
// needs the kernel's top-level page-table (pgd) base. How that base is obtained
// — and whether it can be cached — differs fundamentally between the two
// supported architectures.
//
// We intentionally avoid reading symbols like `swapper_pg_dir` / `init_mm` via
// kallsyms: kernels built with CONFIG_KALLSYMS_ALL=n do not expose data
// symbols to modules, and the layout of `struct mm_struct` is not part of any
// stable ABI either.
// =================================================================================================

#if defined(ARCH_ARM)
// On arm64 the CPU consults two separate registers for translation: TTBR0_EL1
// for user VAs and TTBR1_EL1 for kernel/vmalloc VAs. TTBR1_EL1 is installed
// once at boot to point at `swapper_pg_dir`, a statically allocated page that
// lives for the lifetime of the system and is never replaced on context switch
// (only TTBR0_EL1 changes). So the value is stable and safe to cache.
static pgd_t *arm64_kernel_pgd = NULL;

static int init_kernel_pgd_base(void)
{
    unsigned long ttbr1;
    phys_addr_t pa;

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    // Reverse the kernel's `phys_to_ttbr` encoding. With FEAT_LPA active
    // (CONFIG_ARM64_PA_BITS_52), PA[51:48] is packed into TTBR[5:2] while
    // PA[47:12] remains in TTBR[47:12]. Otherwise the PA sits in [47:12]
    // directly.
#ifdef CONFIG_ARM64_PA_BITS_52
    pa = (ttbr1 & GENMASK_ULL(47, PAGE_SHIFT)) | ((ttbr1 & GENMASK_ULL(5, 2)) << 46);
#else
    pa = ttbr1 & GENMASK_ULL(47, PAGE_SHIFT);
#endif

    arm64_kernel_pgd = (pgd_t *)phys_to_virt(pa);
    if (!arm64_kernel_pgd) {
        PRINT_ERR("init_kernel_pgd_base: failed to decode TTBR1_EL1=0x%lx\n", ttbr1);
        return -ENODEV;
    }
    return 0;
}

static inline pgd_t *get_kernel_pgd_base(void) { return arm64_kernel_pgd; }

#elif defined(ARCH_X86_64)
// On x86_64 there is no dedicated kernel page-table register: a single CR3
// holds the pgd for *both* halves of the address space, and it is reloaded on
// every context switch to point at the currently scheduled task's `mm->pgd`.
// Two consequences:
//
//   1. Lifetime: the pgd page is owned by some task's mm_struct. When that
//      task exits and its last mm reference drops, `pgd_free()` returns the
//      page to the allocator. A pointer captured at `init_module()` time
//      would dangle — typically the insmod task itself exits shortly after
//      loading the module.
//   2. Identity: which pgd is active depends on the task scheduled on the
//      CPU at call time, so a single cached pointer cannot represent "the"
//      kernel pgd.
//
// Reading CR3 on every call sidesteps both: the kernel keeps the upper-half
// (kernel/vmalloc) entries of every pgd synchronized, so walking whichever
// pgd is live yields the correct PTE for a kernel VA regardless of context.
static inline int init_kernel_pgd_base(void) { return 0; }

static inline pgd_t *get_kernel_pgd_base(void) { return (pgd_t *)__va(read_cr3_pa()); }

#else
#error "Unsupported architecture: cannot determine kernel pgd base"
#endif

/// @brief Walk the kernel page tables for a kernel/vmalloc VA and return a
///        pointer to its leaf PTE.
///
/// The returned pointer aliases the live page-table entry; writes through
/// it modify the mapping directly and the caller is responsible for any
/// required TLB invalidation.
///
/// @param hva  Kernel VA to translate. Must lie in the vmalloc or direct-map
///             (kmalloc) range; other addresses are rejected.
/// @return Pointer to the leaf PTE, or NULL if the address is out of range,
///         the pgd base is uninitialized, or the walk hits an unmapped or
///         malformed entry.
pte_t *get_pte(uint64_t hva)
{
    pgd_t *pgd_base;

    // Make sure we are in vmalloc area
    if (!is_vmalloc_addr((void *)hva) && !virt_addr_valid((void *)hva)) {
        PRINT_ERR("get_pte: address not in vmalloc or kmalloc area");
        return NULL;
    }

    pgd_base = get_kernel_pgd_base();
    if (!pgd_base) {
        PRINT_ERR("get_pte: kernel pgd base not initialized");
        return NULL;
    }

    // Do a page walk
    // - Level 0
    pgd_t *pgdp = pgd_offset_pgd(pgd_base, hva);
    pgd_t pgd = READ_ONCE(*pgdp);
    if (pgd_none(pgd)) {
        PRINT_ERR("get_pte: pgd_none");
        return NULL;
    }

    // - Level 1
    p4d_t *p4dp = p4d_offset(pgdp, hva);
    p4d_t p4d = READ_ONCE(*p4dp);
    if (p4d_none(p4d)) {
        PRINT_ERR("get_pte: p4d_none");
        return NULL;
    }

    // - Level 2
    pud_t *pudp = pud_offset(p4dp, hva);
    pud_t pud = READ_ONCE(*pudp);
    if (pud_none(pud)) {
        PRINT_ERR("get_pte: pud_none");
        return NULL;
    }
    // Reject huge (1 GiB) leaf mappings: descending past a block entry would
    // synthesize a bogus PMD pointer.
    if (IS_PUD_LEAF(pud)) {
        PRINT_ERR("get_pte: pud is a huge (1 GiB) leaf mapping\n");
        return NULL;
    }
    if (pud_bad(pud)) {
        PRINT_ERR("get_pte: pud_bad");
        return NULL;
    }

    // - Level 3
    pmd_t *pmdp = pmd_offset(pudp, hva);
    pmd_t pmd = READ_ONCE(*pmdp);
    if (pmd_none(pmd)) {
        PRINT_ERR("get_pte: pmd_none");
        return NULL;
    }
    // Reject large (2 MiB) leaf mappings.
    if (IS_PMD_LEAF(pmd)) {
        PRINT_ERR("get_pte: pmd is a large (2 MiB) leaf mapping\n");
        return NULL;
    }
    if (pmd_bad(pmd)) {
        PRINT_ERR("get_pte: pmd_bad");
        return NULL;
    }

    // - Level 4 (leaf)
    pte_t *pte = pte_offset_kernel(pmdp, hva);
    ASSERT_ENULL(pte_present(*pte), "get_pte");

    return pte;
}

// =================================================================================================
// Manipulation of Host Page Tables
// =================================================================================================
/// @brief Make the sandbox code area executable by clearing the no-execute bit in its PTEs.
/// @details The kernel functions that would normally do this (set_memory_x) are not exported to
/// modules, and vmap() forces the no-execute bit onto the requested protection flags, so the
/// executor manipulates the PTEs directly.
/// @param base_va Base virtual address of the code area
/// @param n_pages Number of pages in the code area
/// @return 0 on success, negative errno if a PTE is missing or the update did not take effect
int set_code_area_executable(uint64_t base_va, size_t n_pages)
{
    for (size_t i = 0; i < n_pages; i++) {
        uint64_t va = base_va + i * PAGE_SIZE;
        pte_t *ptep = get_pte(va);
        if (!ptep) {
            PRINT_ERR("set_code_area_executable: no PTE for code page %zu\n", i);
            return -ENODEV;
        }

        pte_t_ *pte = (pte_t_ *)&ptep->pte;
#if defined(ARCH_X86_64)
        pte->execute_disable = 0;
#elif defined(ARCH_ARM)
        pte->privileged_execute_never = 0;
#endif
        // a local invalidation is sufficient because the VA range is freshly allocated, hence no
        // other CPU can have cached a translation for it
        native_page_invalidate(va);

        // sanity check: re-read the entry to confirm that the update took effect
        uint64_t updated = READ_ONCE(ptep->pte);
        pte_t_ *check = (pte_t_ *)&updated;
#if defined(ARCH_X86_64)
        bool executable = !check->execute_disable;
#elif defined(ARCH_ARM)
        bool executable = !check->privileged_execute_never;
#endif
        if (!executable) {
            PRINT_ERR("set_code_area_executable: code page %zu (VA 0x%llx) is not executable\n", i,
                      va);
            return -ENODEV;
        }
    }
    return 0;
}

/// @brief Cache the PTE pointers for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
int cache_host_pteps(void)
{
    ASSERT(sandbox_pteps != NULL, "cache_host_pteps");
    ASSERT(sandbox != NULL, "cache_host_pteps");

    static int old_n_actors = 1;
    if (n_actors > old_n_actors) {
        SAFE_FREE(sandbox_pteps->data_pteps);
        SAFE_FREE(sandbox_pteps->code_pteps);
        sandbox_pteps->data_pteps =
            CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_ *));
        sandbox_pteps->code_pteps =
            CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_ *));
    }
    old_n_actors = n_actors;

    // cache the PTE pointers for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        uint64_t va = (uint64_t)sandbox->util + i * PAGE_SIZE;
        pte_t *ptep = get_pte(va);
        ASSERT(ptep != NULL, "cache_host_pteps");
        sandbox_pteps->util_pteps[i] = (pte_t_ *)&ptep->pte;
    }

    // cache the PTE pointers for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // cache the PTE pointers for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            uint64_t va = ((uint64_t)&sandbox->data[actor_id]) + i * PAGE_SIZE;
            pte_t *ptep = get_pte(va);
            ASSERT(ptep != NULL, "cache_host_pteps");
            sandbox_pteps->data_pteps[actor_id * N_DATA_PAGES_PER_ACTOR + i] = (pte_t_ *)&ptep->pte;
        }
        // cache the PTE pointers for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            uint64_t va = ((uint64_t)&sandbox->code[actor_id]) + i * PAGE_SIZE;
            pte_t *ptep = get_pte(va);
            ASSERT(ptep != NULL, "cache_host_pteps");
            sandbox_pteps->code_pteps[actor_id * N_CODE_PAGES_PER_ACTOR + i] = (pte_t_ *)&ptep->pte;
        }
    }
    return 0;
}

/// @brief Preserve the original PTEs for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
int store_orig_host_permissions(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "store_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "store_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "store_orig_host_permissions");

    static int old_n_actors = 1;
    if (n_actors > old_n_actors) {
        SAFE_FREE(orig_ptes->data_ptes);
        SAFE_FREE(orig_ptes->code_ptes);
        orig_ptes->data_ptes = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_));
        orig_ptes->code_ptes = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_));

        SAFE_FREE(faulty_ptes);
        faulty_ptes = CHECKED_ZALLOC(sizeof(pte_t_) * n_actors);
    }
    old_n_actors = n_actors;

    // save the original PTEs for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        orig_ptes->util_ptes[i] = *sandbox_pteps->util_pteps[i];
    }

    // save the original PTEs for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // save the original PTEs for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            orig_ptes->data_ptes[page_id] = *sandbox_pteps->data_pteps[page_id];
        }
        // save the original PTEs for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            orig_ptes->code_ptes[page_id] = *sandbox_pteps->code_pteps[page_id];
        }
    }
    return 0;
}

/// @brief A shortcut to restore the original PTEs for a single page.
/// @param ptep
/// @param old_pte
/// @param vaddr
static void restore_pte(pte_t_ *ptep, pte_t_ old_pte, uint64_t vaddr)
{
    uint64_t curr_pte_val = *(uint64_t *)ptep;
    uint64_t old_pte_val = *(uint64_t *)&old_pte;

    if (curr_pte_val != old_pte_val) {
        *ptep = old_pte;
        native_page_invalidate(vaddr);
    }
}

/// @brief Restore the original PTEs for all sandbox pages.
/// @param void
/// @return
int restore_orig_host_permissions(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "restore_orig_host_permissions");

    // restore the original PTEs for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        restore_pte(sandbox_pteps->util_pteps[i], orig_ptes->util_ptes[i],
                    (uint64_t)sandbox->util + i * PAGE_SIZE);
    }

    // restore the original PTEs for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // restore the original PTEs for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            restore_pte(sandbox_pteps->data_pteps[page_id], orig_ptes->data_ptes[page_id],
                        (uint64_t)&sandbox->data[actor_id] + i * PAGE_SIZE);
        }
        // restore the original PTEs for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            restore_pte(sandbox_pteps->code_pteps[page_id], orig_ptes->code_ptes[page_id],
                        (uint64_t)&sandbox->code[actor_id] + i * PAGE_SIZE);
        }
    }
    return 0;
}

/// @brief Configures the page table entries for those sandbox pages that are mapped into
/// user-type actors
/// @param void
/// @return 0 on success, -1 on failure
int set_user_pages(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "restore_orig_host_permissions");

    // enable user access to util pages so that the actors can store measurement results
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        set_user_bit(sandbox_pteps->util_pteps[i]);
        native_page_invalidate((uint64_t)sandbox->util + i * PAGE_SIZE);
    }

    // enable user access to code and data pages of the sandbox that belong to user actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-user actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->pl != PL_USER) {
            continue;
        }

        // configure PTEs for each area of the actor sandbox
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            set_user_bit(sandbox_pteps->data_pteps[page_id]);
            native_page_invalidate((uint64_t)&sandbox->data[actor_id] + i * PAGE_SIZE);
        }
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            set_user_bit(sandbox_pteps->code_pteps[page_id]);
            native_page_invalidate((uint64_t)&sandbox->code[actor_id] + i * PAGE_SIZE);
        }
    }

    return 0;
}

/// @brief Fast modification of the faulty page host PTE; sets the permissions according to
/// actor_t->data_permissions
/// @param void
void set_faulty_page_host_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        uint64_t pte_mask = actors[actor_id].data_permissions;
        uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_PTE_BITS;

        int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
        faulty_ptes[actor_id] = *ptep;
        uint64_t org_value = *(uint64_t *)ptep;
        uint64_t pte = (org_value | mask_set) & mask_clear;
        // PRINT_ERR("set_faulty_page_host_permissions: actor %d, pte 0x%llx -> 0x%llx", actor_id,
        //   org_value, pte);

        if (pte != org_value) {
            *(uint64_t *)ptep = pte;
            native_page_invalidate((uint64_t)&sandbox->data[actor_id] + FAULTY_PAGE_ID * PAGE_SIZE);
        }
    }
}

/// @brief Fast recovery of original permissions of the faulty page host PTE
/// @param void
void restore_faulty_page_host_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        *sandbox_pteps->data_pteps[page_id] = faulty_ptes[actor_id];
        native_page_invalidate((uint64_t)&sandbox->data[actor_id] + FAULTY_PAGE_ID * PAGE_SIZE);
    }
}

// =================================================================================================
// Self-tests
// =================================================================================================
/// @brief Verify get_pte() can walk the kernel page tables for a
/// known-mapped vmalloc VA. Catches a misconfigured kernel pgd base at
/// module-load time rather than crashing inside get_pte() on the first
/// sandbox allocation.
/// @return 0 on success, negative errno on failure
static int self_test_page_walk(void)
{
    void *probe_va = vmalloc(PAGE_SIZE);
    if (!probe_va) {
        PRINT_ERR("self_test_page_walk: probe vmalloc failed\n");
        return -ENOMEM;
    }
    pte_t *probe = get_pte((uint64_t)probe_va);
    vfree(probe_va);
    if (!probe) {
        PRINT_ERR("self_test_page_walk: page-table walk failed\n");
        return -ENODEV;
    }
    return 0;
}

// =================================================================================================
// Constructor/destructor
// =================================================================================================
int init_page_table_manager(void)
{
    int err = init_kernel_pgd_base();
    if (err)
        return err;

    orig_ptes = CHECKED_ZALLOC(sizeof(sandbox_ptes_t));
    orig_ptes->data_ptes = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * sizeof(pte_t_));
    orig_ptes->code_ptes = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * sizeof(pte_t_));
    orig_ptes->util_ptes = CHECKED_ZALLOC(N_UTIL_PAGES * sizeof(pte_t_));

    sandbox_pteps = CHECKED_ZALLOC(sizeof(sandbox_pteps_t));
    sandbox_pteps->data_pteps = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * sizeof(pte_t_ *));
    sandbox_pteps->code_pteps = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * sizeof(pte_t_ *));
    sandbox_pteps->util_pteps = CHECKED_ZALLOC(N_UTIL_PAGES * sizeof(pte_t_ *));

    faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_));

    err = self_test_page_walk();
    if (err) {
        free_page_table_manager();
        return err;
    }
    return 0;
}

void free_page_table_manager(void)
{
    // Tolerate partial initialization: init_page_table_manager() may have
    // failed mid-way, leaving some pointers NULL
    if (sandbox_pteps) {
        SAFE_FREE(sandbox_pteps->data_pteps);
        SAFE_FREE(sandbox_pteps->code_pteps);
        SAFE_FREE(sandbox_pteps->util_pteps);
        SAFE_FREE(sandbox_pteps);
    }

    if (orig_ptes) {
        SAFE_FREE(orig_ptes->data_ptes);
        SAFE_FREE(orig_ptes->code_ptes);
        SAFE_FREE(orig_ptes->util_ptes);
        SAFE_FREE(orig_ptes);
    }

    SAFE_FREE(faulty_ptes);
}
