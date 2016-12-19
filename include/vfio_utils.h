#ifndef _VFIO_UTILS_H_
#define _VFIO_UTILS_H_

#include "qbman_portal.h"
#include <stdint.h>

int vfio_setup(const char *drpc, int *vfio_fd, int *vfio_group_fd);

void* vfio_setup_dma(int vfio_fd, uint64_t dma_size);
int vfio_cleanup_dma(int vfio_fd, void *vaddr, uint64_t dma_size);

#define PORTAL_MEM_CENA 0
#define PORTAL_MEM_CINH 1
void* vfio_map_portal_mem(const char* device, int memtype, int vfio_fd, int vfio_group_fd);

int vfio_dma_map_area(uint64_t vaddr, uint64_t offset, ssize_t size, int vfio_fd);

void vfio_force_rescan(void);

int vfio_bind_container(const char *dprc);

int vfio_unbind_container(const char *dprc);

int vfio_destroy_container(const char *dprc);

int vfio_disable_regions(int vfio_fd, int device_fd, int* ird_evend_fd);

int vfio_enable_regions(int vfio_fd, int device_fd, int* ird_evend_fd);

int vfio_disable_dpio_interrupt(struct qbman_swp *swp, int vfio_group_fd, int vfio_fd, int *ird_evend_fd, pthread_t *intr_thread);

int vfio_enable_dpio_interrupt(struct qbman_swp *swp, int dpio_id, int vfio_group_fd, int vfio_fd, int *ird_evend_fd, pthread_t *intr_thread, void *(*handle_dpio_interrupts) (void *));

void vfio_destroy(int *vfio_fd, int *vfio_group_fd);

#endif
