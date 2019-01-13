#include "types/linkedlist.h"

// for node

static ll_node_t * ll_node_new(void *ptr) {
    ll_node_t *node = MALLOC(ll_node_t, 1);
    node->prev = node->next = NULL;
    node->ptr = ptr;
    return node;
}

static void ll_node_free(ll_node_t *node) {
    free(node);
}

// for list

ll_t * ll_new() {
    ll_t *ll = MALLOC(ll_t, 1);
    ll_node_t *ph = ll_node_new(NULL);
    ll->head = ll->tail = ph;
    ll->count = 0;
    return ll;
}

void ll_free(ll_t *ll) {
    ll_node_t *prev, *node;
    node = ll->head;
    while (node) {
        prev = node;
        ll_node_free(node);
        node = prev->next;
    }
    free(ll);
}

static void ll_add_after(ll_node_t *prev, ll_node_t *node) {
    if (!prev || !node) return;
    
    ll_node_t *next = prev->next;
    prev->next = node;
    node->prev = prev;
    node->next = next;
    if (next) next->prev = node;
}

static void ll_add_before(ll_node_t *next, ll_node_t *node) {
    if (!next || !node) return;
    
    ll_node_t *prev = next->prev;
    if (prev) prev->next = node;
    node->prev = prev;
    node->next = next;
    next->prev = node;
}

ll_node_t * ll_insert_after(ll_t *ll, ll_node_t *prev, void *ptr) {
    if (!prev) return NULL;
    
    ll_node_t *node = ll_node_new(ptr);
    ll_add_after(prev, node);
    if (ll->tail == prev) ll->tail = node;
    ll->count++;
    return node;
}

void * ll_remove(ll_t *ll, ll_node_t *node) {
    if (!node || ll->head == node) return NULL;

    ll_node_t *prev = node->prev;
    ll_node_t *next = node->next;
    if (prev) prev->next = next;
    if (next) next->prev = prev;
    if (ll->tail == node) ll->tail = prev;
    ll->count--;

    void *ptr = node->ptr;
    ll_node_free(node);
    return ptr;
}

ll_node_t * ll_push(ll_t *ll, void *ptr) {
    return ll_insert_after(ll, ll->tail, ptr);
}

void * ll_pop(ll_t *ll) {
    return ll_remove(ll, ll->tail);
}

ll_node_t * ll_unshift(ll_t*ll, void *ptr) {
    return ll_insert_after(ll, ll->head, ptr);
}

void * ll_shift(ll_t *ll) {
    return ll_remove(ll, ll->head->next);
}

typedef int (*pfn_ll_enumerator)(ll_t *ll, size_t offset, void *ptr, void *arg, void **result);

void * ll_enumerate(ll_t *ll, pfn_ll_enumerator fn, void *arg) {
    void *result = NULL;
    int interrupted;
    size_t offset = 0;
    ll_node_t *node = ll->head->next;
    while (node) {
        interrupted = fn(ll, offset, node->ptr, arg, &result);
        if (interrupted || result) break;

        offset++;
        node = node->next;
    }
    return result;
}
