#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <stdlib.h>
#include <linux/vfio.h>
#include <sys/mman.h>

#include "vfio_utils.h"

int vfio_fd, vfio_group_fd;
static int vfio_group_id;

int vfio_setup(const char *dprc)
{
	char dprc_path[100];
	char vfio_group_path[100];
	ssize_t linksize=0;
	struct vfio_group_status group_status =
		{ .argsz = sizeof(group_status) };

	vfio_fd = open("/dev/vfio/vfio", O_RDWR);
	if (vfio_fd < 0) {
		perror("VFIO open failed: ");
		return -1;
	}


	sprintf(dprc_path, "/sys/bus/fsl-mc/devices/%s/iommu_group", dprc);
	linksize = readlink(dprc_path, vfio_group_path, 100-1);
	if (linksize < 0) {
		printf("Failed to readlink %s\n", dprc_path);
		return -1;
	}
	vfio_group_path[linksize] = 0;
	vfio_group_id = atoi(basename(vfio_group_path));
	printf("VFIO group ID is %d\n", vfio_group_id);
	sprintf(vfio_group_path, "/dev/vfio/%d", vfio_group_id);
	vfio_group_fd = open(vfio_group_path, O_RDWR);
	if (vfio_group_id < 0) {
		perror("VFIO group open failed: ");
		return -1;
	}

	ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		printf("Group status not viable\n");
		return -1;
	}


	/* Add the group to the container */
        if(ioctl(vfio_group_fd, VFIO_GROUP_SET_CONTAINER, &vfio_fd)) {
		perror("VFIO_GROUP_SET_CONTAINER failed : ");
		return -1;
	}

	/* Enable the IOMMU model we want */
	if (ioctl(vfio_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU)) {
		perror("VFIO_SET_IOMMU failed : ");
		return -1;
	}
	vfio_force_rescan();

	return 0;
}

void* vfio_setup_dma(uint64_t dma_size)
{
	struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };
	int ret;

	/* Allocate some space and setup a DMA mapping */
        dma_map.vaddr = (unsigned long) mmap(0, dma_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!dma_map.vaddr) {
		perror("mmap failed : ");
		return NULL;
	}
	printf("Got address %p\n", (void*) dma_map.vaddr);
	dma_map.size = dma_size;
	dma_map.iova = dma_map.vaddr; /* 1MB starting at 0x0 from device view */
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret) {
		perror("DMA map ioctl failed: ");
		return NULL;
	}
	printf("Mapped %lu bytes at vaddr %p\n", dma_size,
	       (void*)dma_map.vaddr);
	return (void*) dma_map.vaddr;
}

#define PORTAL_SIZE  4096
void *vfio_map_portal_mem(const char *deviceid, int mem_type)
{
	void *vaddr;
	int device;
	struct vfio_region_info reg = { .argsz = sizeof(reg) };

	device = ioctl(vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, deviceid);
	if (device < 0) {
		perror("VFIO_GROUP_GET_DEVICE_FD failed: ");
		return NULL;
	}
	reg.index = mem_type;
	if (ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &reg) != 0) {
		perror("VFIO_DEVICE_GET_REGION_INFO failed: ");
		return NULL;
	}
        vaddr =  mmap(0, reg.size,
		      PROT_READ | PROT_WRITE,
		      MAP_SHARED,
		      device, reg.offset);
	if (vaddr == (void*) -1) {
		perror("portal mmap failed : ");
		return NULL;
	}
	if (mem_type == PORTAL_MEM_CENA) {
		// Stashing work around
		// TOOO: check version - not needed on rev 2
		vfio_dma_map_area((uint64_t) vaddr, reg.offset, reg.size);
	}
	return vaddr;
}

int vfio_dma_map_area(uint64_t vaddr, uint64_t offset, ssize_t size)
{
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE
	};
	int ret;

	dma_map.vaddr = vaddr;
	dma_map.size = size;
	dma_map.iova = offset;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	ret = ioctl(vfio_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret) {
		perror("DMA map ioctl failed: ");
		return -1;
	}
	return ret;
}


void vfio_force_rescan(void)
{
	if (system("echo 1 > /sys/bus/fsl-mc/rescan")) {
		perror("Rescan failed: ");
	}
}

int vfio_bind_container(const char *dprc)
{
	char override_cmd[100];
	char bind_cmd[100];

	sprintf(override_cmd, "echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/%s/driver_override", dprc);
	sprintf(bind_cmd, "echo %s > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind", dprc);
	if (system(override_cmd))
		return -1;
	if (system(bind_cmd))
		return -1;
	return 0;
}

int vfio_unbind_container(const char *dprc)
{
	char override_cmd[100];
	char bind_cmd[100];

	sprintf(override_cmd, "echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/%s/driver_override", dprc);
	sprintf(bind_cmd, "echo %s > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/unbind", dprc);
	if (system(override_cmd))
		return -1;
	if (system(bind_cmd))
		return -1;
	return 0;
}

int vfio_destroy_container(const char *dprc)
{
	char override_cmd[100];
	char bind_cmd[100];

	sprintf(override_cmd, "echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/%s/driver_override", dprc);
	sprintf(bind_cmd, "restool dpio destroy %s", dprc);
	if (system(override_cmd))
		return -1;
	if (system(bind_cmd))
		return -1;
	return 0;
}

