#include "loaded-image.h"

struct loaded_image_enumerate_params {
    int (*cmp)(image_info_t *image, void *value);
    void *value;
};

size_t nb_loaded_image;
ll_t *loaded_image_ll;

static void __attribute__((constructor)) init_image_ll() {
    if (!loaded_image_ll)
        loaded_image_ll = ll_new();
}

static int cmp_by_address(image_info_t *image, void *another) {
    return image == another;
}

static int cmp_by_filename(image_info_t *image, void *name) {
    return bstrcmp(image->filename, (PBSTR)name);
}

static int cmp_by_exportname(image_info_t *image, void *name) {
    return bstrcmp(image->exportname, (PBSTR)name);
}

static int loaded_dll_enumerator(ll_t *ll, size_t offset, ll_node_t *node, void *arg, OUT void **pret) {
    image_info_t *image = (image_info_t *)node->ptr;
    struct loaded_image_enumerate_params *args = (struct loaded_image_enumerate_params *)arg;
    if (args->cmp(image, args->value) == 0) {
        *((ll_node_t **)pret) = node;
        return 1;
    }
    return 0;
}

static ll_node_t * find_loaded_dll_by_address(image_info_t *image) {
    if (!image) return NULL;
    struct loaded_image_enumerate_params args = {
        .cmp = cmp_by_address,
        .value = image
    };
    ll_node_t *node = ll_enumerate(loaded_image_ll, loaded_dll_enumerator, &args);
    return node;
}

image_info_t * find_loaded_dll_by_filename(PBSTR name) {
    if (!name) return NULL;
    struct loaded_image_enumerate_params args = {
        .cmp = cmp_by_filename,
        .value = name
    };
    ll_node_t *node = ll_enumerate(loaded_image_ll, loaded_dll_enumerator, &args);
    return (image_info_t *)node->ptr;
}

image_info_t * find_loaded_dll_by_exportname(PBSTR name) {
    if (!name) return NULL;
    struct loaded_image_enumerate_params args = {
        .cmp = cmp_by_exportname,
        .value = name
    };
    ll_node_t *node = ll_enumerate(loaded_image_ll, loaded_dll_enumerator, &args);
    return (image_info_t *)node->ptr;
}

void add_loaded_dll(image_info_t *image) {
    ll_push(loaded_image_ll, image);
}

void remove_loaded_dll(image_info_t *image) {
    ll_node_t *node = find_loaded_dll_by_address(image);
    if (node) ll_remove(loaded_image_ll, node);
}
