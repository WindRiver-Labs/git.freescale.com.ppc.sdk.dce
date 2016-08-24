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

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include "compat.h"
#include "fsl_qbman_base.h"
#include "dpdcei.h"
#include "dpdcei-cmd.h"
#include "fsl_dprc.h"
#include "dpdcei-drv.h"
#include "dce-private.h"

#include "dce-fd-frc.h"

#define LDPAA_DCE_DESCRIPTION "Freescale LDPAA DCE Driver"

#define DQ_STORE_SIZE	16

#define CONFIG_FSL_DCE_FLOW_LIMIT 65535


static void *dev_get_drvdata(struct device *dev)
{
	return dev;
}

static int setup_flow_lookup_table(struct fsl_mc_device *ls_dev,
					struct dpdcei_priv *priv)
{
	pthread_mutex_init(&priv->table_lock, NULL /* default */);
	priv->flow_table_size = CONFIG_FSL_DCE_FLOW_LIMIT;
	priv->flow_lookup_table = malloc((priv->flow_table_size *
				sizeof(void *)));
	if (!priv->flow_lookup_table)
		return -ENOMEM;
	memset(priv->flow_lookup_table, 0,
			priv->flow_table_size * sizeof(void *));
	return 0;
}

static int find_empty_flow_table_entry(uint32_t *entry, struct dce_flow *flow)
{
	uint32_t i;
	struct device *dev = &flow->ls_dev->dev;
	struct dpdcei_priv *priv;

	priv = dev_get_drvdata(dev);

	pthread_mutex_lock(&priv->table_lock);
	for (i = 1; i < priv->flow_table_size; i++) {
		if (priv->flow_lookup_table[i] == NULL) {
			*entry = i;
			priv->flow_lookup_table[i] = flow;
			pthread_mutex_unlock(&priv->table_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&priv->table_lock);
	return -ENOMEM;
}

static void clear_flow_table_entry(struct dce_flow *flow, uint32_t entry)
{
	struct device *dev = &flow->ls_dev->dev;
	struct dpdcei_priv *priv;

	priv = dev_get_drvdata(dev);
	pthread_mutex_lock(&priv->table_lock);
	BUG_ON(entry >= priv->flow_table_size);
	priv->flow_lookup_table[entry] = NULL;
	pthread_mutex_unlock(&priv->table_lock);
}

/* hack to get handle */
static struct fsl_mc_device *compression;
static struct fsl_mc_device *decompression;

struct fsl_mc_device *get_compression_device(void)
{
	return compression;
}

struct fsl_mc_device *get_decompression_device(void)
{
	return decompression;
}

int dce_flow_create(struct fsl_mc_device *ls_dev, struct dce_flow *flow)
{
	int err;

	/* associate flow to device */
	flow->ls_dev = ls_dev;

	flow->flc.len = sizeof(struct fcr);
	flow->flc.virt = vfio_alloc(sizeof(struct fcr), FCR_ALIGN);
	if (!flow->flc.virt) {
		err = -ENOMEM;
		goto err_fcr_alloc;
	}

	err = find_empty_flow_table_entry(&flow->key, flow);
	if (err) {
		pr_err("DCE Hash table full\n");
		goto err_get_table_entry;
	}
	/* set the next_flc to myself, but virtual address */
	fcr_set_next_flc(flow->flc.virt, (uint64_t)flow);
	atomic_store(&flow->frames_in_flight, 0);
	return 0;

err_get_table_entry:
	vfio_free(flow->flc.virt);
err_fcr_alloc:
	return err;
}

int dce_flow_destroy(struct dce_flow *flow)
{
	flow->flc.phys = 0;
	flow->flc.len = 0;

	clear_flow_table_entry(flow, flow->key);
	vfio_free(flow->flc.virt);
	flow->flc.virt = NULL;
	return 0;
}

int enqueue_fd(struct dce_flow *flow, struct qbman_fd *fd)
{
	struct device *dev = &flow->ls_dev->dev;
	struct dpdcei_priv *priv;
	enum dce_cmd cmd = fd_frc_get_cmd((struct fd_attr *)fd);
	int err = 0;

	priv = dev_get_drvdata(dev);

	/* set the FD[FLC] "flow context pointer" to input flow address */

	/* TODO: update what stashing control is added */
	fd_attr_set_flc_64((struct fd_attr *)fd, (dma_addr_t)flow->flc.virt);

	switch (cmd) {
	case DCE_CMD_NOP:
		fd_frc_set_nop_token((struct fd_attr *)fd, flow->key);
		break;
	case DCE_CMD_CTX_INVALIDATE:
		fd_frc_set_cic_token((struct fd_attr *)fd, flow->key);
		break;
	case DCE_CMD_PROCESS:
		break;
	default:
		pr_err("DCE: Unsupported dce command %d\n", cmd);
		BUG();
		return -EINVAL;
	}

	/* advance head now since consumer can be called during enqueue */
	atomic_fetch_add(&priv->frames_in_flight, 1);
	atomic_fetch_add(&flow->frames_in_flight, 1);

	err = dpaa2_io_service_enqueue_fq(priv->dpio_p, priv->tx_fqid, fd);
	if (err < 0) {
		pr_err("DCE: error enqueueing Tx frame\n");
		atomic_fetch_sub(&priv->frames_in_flight, 1);
		atomic_fetch_sub(&flow->frames_in_flight, 1);
	}
	return err;
}

int enqueue_nop(struct dce_flow *flow)
{
	struct qbman_fd fd;

	memset(&fd, 0, sizeof(fd));
	/* setup FD as a NOP command */
	fd_frc_set_cmd((struct fd_attr *)&fd, DCE_CMD_NOP);

	return enqueue_fd(flow, &fd);
}

int enqueue_cic(struct dce_flow *flow)
{
	struct qbman_fd fd;

	memset(&fd, 0, sizeof(fd));
	/* setup FD as a CIC command */
	fd_frc_set_cmd((struct fd_attr *)&fd, DCE_CMD_CTX_INVALIDATE);

	return enqueue_fd(flow, &fd);
}

static const char *engine_to_str(enum dpdcei_engine engine)
{
	if (engine == DPDCEI_ENGINE_COMPRESSION)
		return "COMPRESSION";
	else if (engine == DPDCEI_ENGINE_DECOMPRESSION)
		return "DECOMPRESSION";
	else
		return "UNKNOWN";
}

/*****************************************************************************/
/* all input to be enqueued is stored in a circular ring */

/* DCE responses control block */
struct dce_response_cb {
	struct work_struct async_response_work; /* Asynchronous resposne work */
	struct dpaa2_io_notification_ctx *ctx;
};

static int dpaa2_dce_pull_dequeue_rx(struct dpdcei_priv *priv)
{
	int err = 0;
	int is_last = 0;
	struct qbman_dq *dq;
	const struct qbman_fd *fd;
	struct dce_flow *flow;
	uint32_t key;

	do {
		err = dpaa2_io_service_pull_fq(priv->dpio_p, priv->rx_fqid,
					      priv->rx_store);
	} while (err);

	while (!is_last) {
		enum dce_cmd cmd;

		do {
			dq = dpaa2_io_store_next(priv->rx_store, &is_last);
		} while (!is_last && !dq);
		if (!dq) {
			pr_err("DCE: FQID returned no valid frames!\n");
			break;
		}

		/* Obtain FD and process it */
		fd = qbman_dq_fd(dq);
		/* We are already CPU-affine, and since we aren't going
		 * to start more than one Rx thread per CPU, we're
		 * good enough for now.
		 */
		cmd = fd_frc_get_cmd((struct fd_attr *)fd);
		flow = (struct dce_flow *)fd_attr_get_flc_64(
						(struct fd_attr *)fd);

		switch (cmd) {
		case DCE_CMD_NOP:
			key = fd_frc_get_nop_token((struct fd_attr *)fd);
			flow = priv->flow_lookup_table[key];
			flow->cb(flow, cmd, fd);
			break;
		case DCE_CMD_CTX_INVALIDATE:
			key = fd_frc_get_cic_token((struct fd_attr *)fd);
			flow = priv->flow_lookup_table[key];
			flow->cb(flow, cmd, fd);
			break;
		case DCE_CMD_PROCESS:
			flow->cb(flow, cmd, fd);
			break;

		default:
			pr_err("DCE: Unsupported DCE CMD %d\n", cmd);
		}

		atomic_fetch_sub(&priv->frames_in_flight, 1);
		atomic_fetch_sub(&flow->frames_in_flight, 1);
	}
	return 0;
}

static void dequeue_rx_work_func(struct work_struct *work)
{
	struct dce_response_cb *ent;
	struct dpdcei_priv *priv;

	ent = container_of(work, struct dce_response_cb, async_response_work);
	priv = container_of(ent->ctx, struct dpdcei_priv, notif_ctx_rx);
	dpaa2_dce_pull_dequeue_rx(priv);
	dpaa2_io_service_rearm(priv->dpio_p, ent->ctx);
}

static void fqdan_cb_rx(struct dpaa2_io_notification_ctx *ctx)
{
	struct dpdcei_priv *priv = container_of(ctx, struct dpdcei_priv,
						   notif_ctx_rx);
	struct dce_response_cb *work;

	work = vfio_alloc(sizeof(*work), 0 /* any alignment */);
	INIT_WORK(&work->async_response_work, dequeue_rx_work_func);
	work->ctx = ctx;
	queue_work(priv->async_resp_wq, &work->async_response_work);
}

static int dpdcei_dpio_service_setup(struct dpdcei_priv *priv)
{
	int err;
	priv->notif_ctx_rx.desired_cpu = -1;
	priv->notif_ctx_rx.cb = fqdan_cb_rx;
	priv->notif_ctx_rx.id = priv->rx_fqid;
	err = dpaa2_io_service_register(priv->dpio_p, &priv->notif_ctx_rx);
	if (err) {
		pr_err("DCE: Rx notif register failed 0x%x\n", err);
		return err;
	}
	return 0;
}

static int dpdcei_dpio_service_teardown(struct dpdcei_priv *priv)
{
	int err;

	/* Deregister notification callbacks */
	err = dpaa2_io_service_deregister(priv->dpio_p, &priv->notif_ctx_rx);
	if (err) {
		pr_err("DCE: dpdcei_dpio_service_teardown failed 0x%x\n", err);
		return err;
	}
	return 0;
}

static int dpdcei_bind_dpio(struct dpdcei_priv *priv,
				struct fsl_mc_io *mc_io, uint16_t dpdcei_handle)
{
	int err;
	struct dpdcei_rx_queue_cfg rx_queue_cfg;

	/* Configure the Tx queue to generate FQDANs */
	rx_queue_cfg.options = DPDCEI_QUEUE_OPT_USER_CTX |
				DPDCEI_QUEUE_OPT_DEST;
	rx_queue_cfg.user_ctx = priv->notif_ctx_rx.qman64;
	rx_queue_cfg.dest_cfg.dest_type = DPDCEI_DEST_DPIO;
	rx_queue_cfg.dest_cfg.dest_id = priv->notif_ctx_rx.dpio_id;
	/* TODO: dpio could have 2 or 8 WQ need to query dpio perhaps
	 *	hard code it to 1 for now */
	rx_queue_cfg.dest_cfg.priority = 0;
	err = dpdcei_set_rx_queue(mc_io, dpdcei_handle, &rx_queue_cfg);
	if (err) {
		pr_err("DCE: dpdcei_set_rx_flow() failed\n");
		return err;
	}

	return 0;
}

static int dpdcei_unbind_dpio(struct dpdcei_priv *priv,
				struct fsl_mc_io *mc_io,
				uint16_t dpdcei_handle)
{
	int err;

	err = dpdcei_reset(mc_io, dpdcei_handle);
	if (err) {
		pr_err("DCE: dpdcei_reset failed\n");
		return err;
	}
	priv->notif_ctx_rx.qman64 = 0;
	priv->notif_ctx_rx.dpio_id = 0;

	return 0;
}

static int dpaa2_dce_alloc_store(struct dpdcei_priv *priv)
{
	struct device *dev = &priv->dpdcei_dev->dev;

	priv->rx_store = dpaa2_io_store_create(DQ_STORE_SIZE, dev);
	if (!priv->rx_store) {
		pr_err("DCE: dpaa2_io_store_create() failed\n");
		return -ENOMEM;
	}
	return 0;
}

static void dpaa2_dce_free_store(struct dpdcei_priv *priv)
{
	dpaa2_io_store_destroy(priv->rx_store);
}

/**
 * fsl_mc_portal_allocate - Allocates an MC portal
 *
 * @mc_dev: MC device for which the MC portal is to be allocated
 * @mc_io_flags: Flags for the fsl_mc_io object that wraps the allocated
 * MC portal.
 * @new_mc_io: Pointer to area where the pointer to the fsl_mc_io object
 * that wraps the allocated MC portal is to be returned
 *
 * This function allocates an MC portal from the device's parent DPRC,
 * from the corresponding MC bus' pool of MC portals and wraps
 * it in a new fsl_mc_io object. If 'mc_dev' is a DPRC itself, the
 * portal is allocated from its own MC bus.
 */
int fsl_mc_portal_allocate(struct fsl_mc_device *mc_dev,
					uint16_t mc_io_flags,
					struct fsl_mc_io **new_mc_io)
{
	struct fsl_mc_device *mc_bus_dev;
	struct fsl_mc_bus *mc_bus;
	dma_addr_t mc_portal_phys_addr;
	size_t mc_portal_size;
	struct fsl_mc_device *dpmcp_dev;
	int error = -EINVAL;
	struct fsl_mc_resource *resource = NULL;
	struct fsl_mc_io *mc_io = NULL;

	if (!mc_dev) {
		if (WARN_ON(!fsl_mc_bus_type.dev_root))
			return error;

		mc_bus_dev = to_fsl_mc_device(fsl_mc_bus_type.dev_root);
	} else if (mc_dev->flags & FSL_MC_IS_DPRC) {
		mc_bus_dev = mc_dev;
	} else {
		if (WARN_ON(mc_dev->dev.parent->bus != &fsl_mc_bus_type))
			return error;

		mc_bus_dev = to_fsl_mc_device(mc_dev->dev.parent);
	}

	mc_bus = to_fsl_mc_bus(mc_bus_dev);
	*new_mc_io = NULL;
	error = fsl_mc_resource_allocate(mc_bus, FSL_MC_POOL_DPMCP, &resource);
	if (error < 0)
		return error;

	error = -EINVAL;
	dpmcp_dev = resource->data;
	if (WARN_ON(!dpmcp_dev ||
		    strcmp(dpmcp_dev->obj_desc.type, "dpmcp") != 0))
		goto error_cleanup_resource;

	if (dpmcp_dev->obj_desc.ver_major < DPMCP_MIN_VER_MAJOR ||
	    (dpmcp_dev->obj_desc.ver_major == DPMCP_MIN_VER_MAJOR &&
	     dpmcp_dev->obj_desc.ver_minor < DPMCP_MIN_VER_MINOR)) {
		pr_err("DCE: Version %d.%d of DPMCP not supported.\n",
			dpmcp_dev->obj_desc.ver_major,
			dpmcp_dev->obj_desc.ver_minor);
		error = -EINVAL;
		goto error_cleanup_resource;
	}

	if (WARN_ON(dpmcp_dev->obj_desc.region_count == 0))
		goto error_cleanup_resource;

	mc_portal_phys_addr = dpmcp_dev->regions[0].start;
	mc_portal_size = dpmcp_dev->regions[0].end -
			 dpmcp_dev->regions[0].start + 1;

	if (WARN_ON(mc_portal_size != mc_bus_dev->mc_io->portal_size))
		goto error_cleanup_resource;

	error = fsl_create_mc_io(&mc_bus_dev->dev,
				 mc_portal_phys_addr,
				 mc_portal_size, dpmcp_dev,
				 mc_io_flags, &mc_io);
	if (error < 0)
		goto error_cleanup_resource;

	*new_mc_io = mc_io;
	return 0;

error_cleanup_resource:
	fsl_mc_resource_free(resource);
	return error;
}

static int dpaa2_dpdcei_probe(struct fsl_mc_device *ls_dev)
{
	struct dpdcei_priv *priv = NULL;
	struct device *dev = &ls_dev->dev;
	struct dpdcei_rx_queue_attr rx_attr;
	struct dpdcei_tx_queue_attr tx_attr;
	struct dpaa2_io *dpio_s;
	int err = 0;

	memset(&rx_attr, 0, sizeof(rx_attr));
	memset(&tx_attr, 0, sizeof(tx_attr));

	priv = vfio_alloc(sizeof(*priv), 0 /* any alignment */);
	if (!priv) {
		err = -ENOMEM;
		goto err_priv_alloc;
	}
	dev_set_drvdata(dev, priv);
	priv->dpdcei_dev = ls_dev;

	/* initialize lookup table */
	setup_flow_lookup_table(ls_dev, priv);

	/* Get dpio default service */
	dpio_s = dpaa2_io_default_service();
	if (!dpio_s) {
		pr_err("DCE: Cannot get dpio service\n");
		goto err_get_dpio_service;
	}

	err = dpaa2_io_service_get_persistent(dpio_s, -1, &priv->dpio_p);
	if (err) {
		pr_err("DCE: Cannot get dpio object\n");
		goto err_get_dpio;
	}

	/* done with service */
	dpaa2_io_down(dpio_s);

	/* in flight ring initialization */
	atomic_store(&priv->frames_in_flight, 0);

	/*
	 * Create work queue to defer work when asynchronous responses are
	 * received
	 */

	/* TODO: confirm value is of wq flags being used */
	priv->async_resp_wq = alloc_workqueue("dce_async_resp_wq",
			WQ_UNBOUND | WQ_MEM_RECLAIM, WQ_MAX_ACTIVE);
	if (!priv->async_resp_wq) {
		pr_err("DCE: Cannot allocate response work queue\n");
		err = -ENOSPC;
		goto err_alloc_wq;
	}

	priv->slab_fcr = NULL;
	err = fsl_mc_portal_allocate(ls_dev, 0, &ls_dev->mc_io);
	if (err) {
		pr_err("DCE: MC portal allocation failed\n");
		goto err_mcportal;
	}

	/* get a handle for the DPDCEI this interface is associated with */
	err = dpdcei_open(ls_dev->mc_io, ls_dev->obj_desc.id,
			&ls_dev->mc_handle);
	if (err) {
		pr_err("DCE: dpdcei_open() failed\n");
		goto err_open;
	}

	err = dpdcei_get_attributes(ls_dev->mc_io, ls_dev->mc_handle,
				&priv->dpdcei_attrs);
	if (err) {
		pr_err("DCE: dpdcei_get_attributes() failed %d\n", err);
		goto err_get_attr;
	}

	if (priv->dpdcei_attrs.version.major > DPDCEI_VER_MAJOR) {
		pr_err("DCE: DPDCEI major version mismatch\n"
			     " found %u.%u, supported version is %u.%u\n",
				priv->dpdcei_attrs.version.major,
				priv->dpdcei_attrs.version.minor,
				DPDCEI_VER_MAJOR,
				DPDCEI_VER_MINOR);
	} else if (priv->dpdcei_attrs.version.minor > DPDCEI_VER_MINOR) {
		pr_err("DCE: DPDCEI minor version mismatch\n"
			     " found %u.%u, supported version is %u.%u\n",
				priv->dpdcei_attrs.version.major,
				priv->dpdcei_attrs.version.minor,
				DPDCEI_VER_MAJOR,
				DPDCEI_VER_MINOR);
	}

	pr_info("DPDCEI: id=%d, engine=%s\n", priv->dpdcei_attrs.id,
		engine_to_str(priv->dpdcei_attrs.engine));

	/* Only support one compression and decompression device */
	if ((priv->dpdcei_attrs.engine == DPDCEI_ENGINE_COMPRESSION) &&
			(compression != NULL)) {
		pr_err("DCE: Compression device already present\n");
		goto err_get_attr;
	} else if ((priv->dpdcei_attrs.engine == DPDCEI_ENGINE_DECOMPRESSION)
			 && (decompression != NULL)) {
		pr_err("DCE: Decompression device already present\n");
		goto err_get_attr;
	}

	err = dpdcei_get_rx_queue(ls_dev->mc_io, ls_dev->mc_handle, &rx_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_get_attr;
	}

	priv->rx_fqid = rx_attr.fqid;

	err = dpdcei_get_tx_queue(ls_dev->mc_io, ls_dev->mc_handle, &tx_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_get_attr;
	}
	priv->tx_fqid = tx_attr.fqid;

	/* dpio store */
	err = dpaa2_dce_alloc_store(priv);
	if (err)
		goto err_get_attr;

	/* dpio services */
	err = dpdcei_dpio_service_setup(priv);
	if (err)
		goto err_dpio_setup;

	/* DPDCEI binding to DPIO */
	err = dpdcei_bind_dpio(priv, ls_dev->mc_io, ls_dev->mc_handle);
	if (err) {
		pr_err("DCE: Error dpdcei bind %d\n", err);
		goto err_bind;
	}

	/* Enable the device */
	err = dpdcei_enable(ls_dev->mc_io, ls_dev->mc_handle);
	if (err) {
		pr_err("DCE: dpdcei_enable failed %d\n", err);
		goto err_enable;
	}

	if (priv->dpdcei_attrs.engine == DPDCEI_ENGINE_COMPRESSION)
		compression = ls_dev;
	else
		decompression = ls_dev;

	return 0;
err_enable:
	dpdcei_unbind_dpio(priv, ls_dev->mc_io, ls_dev->mc_handle);
err_bind:
	dpdcei_dpio_service_teardown(priv);
err_dpio_setup:
	dpaa2_dce_free_store(priv);
err_get_attr:
	dpdcei_close(ls_dev->mc_io, ls_dev->mc_handle);
err_open:
	fsl_mc_portal_free(ls_dev->mc_io);
err_mcportal:
	destroy_workqueue(priv->async_resp_wq);
err_alloc_wq:
	dpaa2_io_down(priv->dpio_p);
err_get_dpio:
	dpaa2_io_down(dpio_s);
err_get_dpio_service:
	dev_set_drvdata(dev, NULL);
	vfio_free(priv);
err_priv_alloc:
	return err;
}

static int dpaa2_dpdcei_remove(struct fsl_mc_device *ls_dev)
{
	struct device *dev;
	struct dpdcei_priv *priv;
	int err;

	dev = &ls_dev->dev;
	priv = dev_get_drvdata(dev);

	/* TODO: need to quiesce the device */
	if (atomic_read(&priv->frames_in_flight)) {
		pr_info("Frames still in flight\n");
		return -EBUSY;
	}

	/* disable the device */
	err = dpdcei_disable(ls_dev->mc_io, ls_dev->mc_handle);
	if (err) {
		pr_err("DCE: dpdcei_disable failed %d\n", err);
		goto err_disable;
	}

	/* DPDCEI unbinding to DPIO */
	err = dpdcei_unbind_dpio(priv, ls_dev->mc_io, ls_dev->mc_handle);
	if (err) {
		pr_err("DCE: Error dpdcei unbind 0x%x\n", err);
		goto err_unbind;
	}

	/* dpio service teardown */
	err = dpdcei_dpio_service_teardown(priv);
	if (err) {
		pr_err("DCE: Error dpdcei service teardown 0x%x\n", err);
		goto err_service_teardown;
	}

	dpaa2_dce_free_store(priv);

	err = dpdcei_close(ls_dev->mc_io, ls_dev->mc_handle);
	if (err) {
		pr_err("DCE: Error dpdcei close 0x%x\n", err);
		goto err_dpdcei_close;
	}

	fsl_mc_portal_free(ls_dev->mc_io);

	ls_dev->mc_io = NULL;

	destroy_workqueue(priv->async_resp_wq);

	dpaa2_io_down(priv->dpio_p);

	/* Only support one compression and decompression device */
	if (priv->dpdcei_attrs.engine == DPDCEI_ENGINE_COMPRESSION)
		compression = NULL;
	else if (priv->dpdcei_attrs.engine == DPDCEI_ENGINE_DECOMPRESSION)
		decompression = NULL;
	dev_set_drvdata(dev, NULL);
	vfio_free(priv);
	return 0;

err_dpdcei_close:
	/* todo: allocate store */
err_service_teardown:
	/* todo: rebind dpio */
err_unbind:
	dpdcei_enable(ls_dev->mc_io, ls_dev->mc_handle);
err_disable:
	return err;
}
