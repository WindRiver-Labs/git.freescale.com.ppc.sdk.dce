#ifndef _VFIO_UTILS_H_
#define _VFIO_UTILS_H_

#include <stdint.h>

int vfio_setup(const char *drpc);

void* vfio_setup_dma(uint64_t dma_size);
#define vfio_cleanup_dma(p)

#define PORTAL_MEM_CENA 0
#define PORTAL_MEM_CINH 1
void* vfio_map_portal_mem(const char* device, int memtype);

int vfio_dma_map_area(uint64_t vaddr, uint64_t offset, ssize_t size);

void vfio_force_rescan(void);

int vfio_bind_container(const char *dprc);

int vfio_unbind_container(const char *dprc);

int vfio_destroy_container(const char *dprc);

#endif
