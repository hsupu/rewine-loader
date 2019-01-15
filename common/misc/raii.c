#include "misc/raii.h"
#include "misc/raii-fd.h"
#include "misc/raii-mem.h"
#include "misc/raii-mmap.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

void __cleanup_fd(int *fd) {
    if (*fd)
        close(*fd);
}

void __cleanup_mem(void *p) {
    if (*(void **)p)
        free(*(void **)p);
}

void __cleanup_mmap_info(mmap_info_t *info) {
    if (info->addr)
        munmap(info->addr, info->size);
}
