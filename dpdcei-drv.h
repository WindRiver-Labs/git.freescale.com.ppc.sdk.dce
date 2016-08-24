/* Copyright 2014 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __DPDCEI_DRV_H
#define __DPDCEI_DRV_H

#define cpumask_t int

struct device {
	int dev;
};

#include "compat.h"
#include "fsl_dprc.h"
#include "fsl_dpaa2_io.h"
#include <pthread.h>
#include <stdatomic.h>
#include "dpdcei.h"
#include "dce-fcr.h"

/**
 * struct fsl_mc_device - MC object device object
 * @dev: Linux driver model device object
 * @dma_mask: Default DMA mask
 * @flags: MC object device flags
 * @icid: Isolation context ID for the device
 * @mc_handle: MC handle for the corresponding MC object opened
 * @mc_io: Pointer to MC IO object assigned to this device or
 * NULL if none.
 * @obj_desc: MC description of the DPAA device
 * @regions: pointer to array of MMIO region entries
 * @irqs: pointer to array of pointers to interrupts allocated to this device
 * @resource: generic resource associated with this MC object device, if any.
 * @driver_override: Driver name to force a match
 *
 * Generic device object for MC object devices that are "attached" to a
 * MC bus.
 *
 * NOTES:
 * - For a non-DPRC object its icid is the same as its parent DPRC's icid.
 * - The SMMU notifier callback gets invoked after device_add() has been
 *   called for an MC object device, but before the device-specific probe
 *   callback gets called.
 * - DP_OBJ_DPRC objects are the only MC objects that have built-in MC
 *   portals. For all other MC objects, their device drivers are responsible for
 *   allocating MC portals for them by calling fsl_mc_portal_allocate().
 * - Some types of MC objects (e.g., DP_OBJ_DPBP, DP_OBJ_DPCON) are
 *   treated as resources that can be allocated/deallocated from the
 *   corresponding resource pool in the object's parent DPRC, using the
 *   fsl_mc_object_allocate()/fsl_mc_object_free() functions. These MC objects
 *   are known as "allocatable" objects. For them, the corresponding
 *   fsl_mc_device's 'resource' points to the associated resource object.
 *   For MC objects that are not allocatable (e.g., DP_OBJ_DPRC, DP_OBJ_DPNI),
 *   'resource' is NULL.
 */
struct fsl_mc_device {
	struct device dev;
	uint64_t dma_mask;
	uint16_t flags;
	uint16_t icid;
	uint16_t mc_handle;
	struct fsl_mc_io *mc_io;
	struct dprc_obj_desc obj_desc;
	struct resource *regions;
	struct fsl_mc_device_irq **irqs;
	struct fsl_mc_resource *resource;
	const char *driver_override;
};

struct dpdcei_priv {
	struct fsl_mc_device *dpdcei_dev;
	struct dpaa2_io *dpio_service;
	struct dpdcei_attr dpdcei_attrs;
	uint32_t rx_fqid;
	uint32_t tx_fqid;

	/* dpio services */
	struct dpaa2_io *dpio_p;
	struct dpaa2_io_notification_ctx notif_ctx_rx;
	struct dpaa2_io_store *rx_store;

	/* dma memory for flow */
	struct kmem_cache *slab_fcr;

	atomic_int frames_in_flight;

	/* hash index to flow */
	pthread_mutex_t table_lock;
	size_t flow_table_size;
	void **flow_lookup_table;

	/*
	 * Multi threaded work queue used to defer the work to be
	 * done when an asynchronous responses are received
	 */
	struct workqueue_struct *async_resp_wq;
};

/* Hack to get access to device */
struct fsl_mc_device *get_compression_device(void);
struct fsl_mc_device *get_decompression_device(void);

struct flc_dma {
	void *virt;
	dma_addr_t phys;
	size_t len;
};

struct dce_flow {
	/* the callback to be invoked when the respose arrives */
	void (*cb)(struct dce_flow *, uint32_t cmd, const struct qbman_fd *fd);
	struct fsl_mc_device *ls_dev;

	/* flow memory: both virtual and dma memory */
	struct flc_dma flc;
	atomic_int frames_in_flight;
	/* key used to lookup flow in flow table */
	uint32_t key;
};

int dce_flow_create(struct fsl_mc_device *dev, struct dce_flow *flow);
int dce_flow_destroy(struct dce_flow *flow);

int enqueue_fd(struct dce_flow *flow, struct qbman_fd *fd);
int enqueue_nop(struct dce_flow *flow);
int enqueue_cic(struct dce_flow *flow);

#endif
