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

#include <compat.h>
#include <fsl_qbman_base.h>
#include <fsl_dpdcei.h>
#include <fsl_dpaa2_io.h>
#include "dce-fcr.h"

struct dpdcei_priv {
	struct fsl_mc_io *mc_dev;
	uint16_t token;
	struct dpaa2_io *dpio_service;
	struct dpdcei_attr dpdcei_attrs;
	u32 rx_fqid;
	u32 tx_fqid;

	/* dpio services */
	struct dpaa2_io *dpio_p;
	struct dpaa2_io_notification_ctx notif_ctx_rx;
	struct dpaa2_io_store *rx_store;

	atomic_t frames_in_flight;

	/* hash index to flow */
	spinlock_t table_lock;
	size_t flow_table_size;
	void **flow_lookup_table;
};

/* Hack to get access to device */
struct dpdcei_priv *get_compression_device(void);
struct dpdcei_priv *get_decompression_device(void);

struct flc_dma {
	void *virt;
	dma_addr_t phys;
	size_t len;
};

struct dce_flow {
	/* the callback to be invoked when the respose arrives */
	void (*cb)(struct dce_flow *, u32 cmd, const struct qbman_fd *fd);
	struct dpdcei_priv *device;

	/* flow memory: both virtual and dma memory */
	struct flc_dma flc;
	atomic_t frames_in_flight;
	/* key used to lookup flow in flow table */
	u32 key;
};

int dce_flow_create(struct dpdcei_priv *dev, struct dce_flow *flow);
int dce_flow_destroy(struct dce_flow *flow);

int enqueue_fd(struct dce_flow *flow, struct qbman_fd *fd);
int enqueue_nop(struct dce_flow *flow);
int enqueue_cic(struct dce_flow *flow);

#endif
