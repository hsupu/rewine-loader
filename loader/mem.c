#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mem.h"
#include "misc/mem.h"
#include "types/mmap.h"

extern long page_size;
extern unsigned long page_mask;

static const DWORD sector_mask = 0x1ff; // 511

static int fd_zero = -1;

static void __attribute__((constructor)) init_page_mask() {
    if (!page_mask)
        page_mask = sysconf(_SC_PAGESIZE) - 1;
}

int mmap_pe_file(int fd, OUT mmap_info_t **out_mi) {
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) < 0) {
        return 1;
    }
    off_t offset = 0;
    size_t size = fd_stat.st_size;
    void *address = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
    if (address == MAP_FAILED) {
        return 2;
    }
    mmap_info_t *mi = rewine_mmap_new(offset, size, address);
    if (!mi) {
        return 3;
    }
    *out_mi = mi;
    return 0;
}

static int init_fd_zero() {
    if (fd_zero < 0)
        fd_zero = open("/dev/zero", O_RDWR);
    return fd_zero < 0 ? -1 : 0;
}

int mmap_zero(PVOID fixed_base, size_t size, OUT mmap_info_t **out_mi) {
    if (init_fd_zero()) {
        return 1;
    }
    int mmap_flags = MAP_PRIVATE;
    if (fixed_base) mmap_flags |= MAP_FIXED;
    off_t offset = 0;
    void *address = mmap(fixed_base, size, PROT_READ | PROT_WRITE | PROT_EXEC, mmap_flags, fd_zero, offset);
    if (address == MAP_FAILED) {
        return 2;
    }
    mmap_info_t *mi = rewine_mmap_new(offset, size, address);
    if (!mi) {
        return 3;
    }
    *out_mi = mi;
    return 0;
}

int set_mmap_protect(PIMAGE_SECTION_HEADER section, mmap_info_t *section_map) {
    DWORD section_charact = section->Characteristics;
    int prot = PROT_NONE;
    if (section_charact & IMAGE_SCN_MEM_READ) prot |= PROT_READ;
    if (section_charact & IMAGE_SCN_MEM_WRITE) prot |= PROT_WRITE;
    if (section_charact & IMAGE_SCN_MEM_EXECUTE) prot |= PROT_EXEC;
    return mprotect(section_map->address, section_map->size, prot);
}

DWORD align_to(UINT_PTR addr, DWORD size, DWORD mask) {
    return (DWORD)(((size) + (addr & mask) + mask) & ~mask);
}

DWORD align_to_page(UINT_PTR addr, DWORD size) {
    return align_to(addr, size, page_mask);
}

DWORD align_to_sector(UINT_PTR addr, DWORD size) {
    return align_to(addr, size, sector_mask);
}
