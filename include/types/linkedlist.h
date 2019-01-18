#pragma once

#include <stdlib.h>

#include "misc/mem.h"

typedef struct ll_node {
    struct ll_node *prev;
    struct ll_node *next;
    void *ptr;
} ll_node_t;

typedef struct ll_list {
    ll_node_t *head; // head is always a placeholder
    ll_node_t *tail;
    size_t count;
} ll_t;


ll_t * ll_new();
void ll_free(ll_t *ll);

ll_node_t * ll_insert_after(ll_t *ll, ll_node_t *prev, void *ptr) ;
void * ll_remove(ll_t *ll, ll_node_t *node);

ll_node_t * ll_push(ll_t *ll, void *ptr);
void * ll_pop(ll_t *ll);

ll_node_t * ll_unshift(ll_t *ll, void *ptr);
void * ll_shift(ll_t *ll);

typedef int (*pf_ll_enumerator)(ll_t *ll, size_t offset, ll_node_t *node, void *arg, void **result);
void * ll_enumerate(ll_t *ll, pf_ll_enumerator fn, void *arg);
