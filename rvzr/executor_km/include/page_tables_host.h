/// File: Header for page table functions
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLE_H_
#define _PAGE_TABLE_H_

#include "page_tables_common.h"
#include <linux/kernel.h>

typedef struct {
    pte_t_ *data_ptes;
    pte_t_ *code_ptes;
    pte_t_ *util_ptes;
} sandbox_ptes_t;

typedef struct {
    pte_t_ **data_pteps;
    pte_t_ **code_pteps;
    pte_t_ **util_pteps;
} sandbox_pteps_t;

extern sandbox_pteps_t *sandbox_pteps;

pte_t *get_pte(uint64_t hva);

int set_code_area_executable(uint64_t base_va, size_t n_pages);

int cache_host_pteps(void);
int store_orig_host_permissions(void);
int restore_orig_host_permissions(void);

int set_user_pages(void);
void set_faulty_page_host_permissions(void);
void restore_faulty_page_host_permissions(void);

int init_page_table_manager(void);
void free_page_table_manager(void);

#endif // _PAGE_TABLE_H_
