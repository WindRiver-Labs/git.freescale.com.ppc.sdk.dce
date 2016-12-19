/* Copyright (c) 2016, Freescale Semiconductor
 * All rights reserved.
 *
 * BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Freescale Semiconductor nor the
 *        names of its contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 *
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

#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <compat.h>

#include <fsl_mc_cmd.h>
#include <fsl_mc_sys.h>
#include <fsl_dprc.h>
#include <fsl_dpdcei.h>
#include <fsl_dpdcei_cmd.h>
#include <fsl_qbman_base.h>
#include <fsl_dpaa2_io.h>
#include <vfio_utils.h>
#include <qbman_portal.h>
#include "dpdcei-drv.h"
#include "dce-private.h"

#include "dce-fd-frc.h"

#define LDPAA_DCE_DESCRIPTION "Freescale LDPAA DCE Driver"

#define DQ_STORE_SIZE 8192

#define CONFIG_FSL_DCE_FLOW_LIMIT 65535

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION(LDPAA_DCE_DESCRIPTION);

static int setup_flow_lookup_table(struct fsl_mc_io *mc_io __maybe_unused,
					struct dpdcei_priv *priv)
{
	priv->flow_table_size = CONFIG_FSL_DCE_FLOW_LIMIT;
	priv->flow_lookup_table = malloc((priv->flow_table_size *
				sizeof(void *)));
	spin_lock_init(&priv->table_lock);
	if (!priv->flow_lookup_table)
		return -ENOMEM;
	memset(priv->flow_lookup_table, 0,
			priv->flow_table_size * sizeof(void *));
	return 0;
}

static int find_empty_flow_table_entry(u32 *entry, struct dce_flow *flow)
{
	u32 i;
	struct dpdcei_priv *priv = flow->device;

	spin_lock(&priv->table_lock);
	for (i = 1; i < priv->flow_table_size; i++) {
		if (priv->flow_lookup_table[i] == NULL) {
			*entry = i;
			priv->flow_lookup_table[i] = flow;
			spin_unlock(&priv->table_lock);
			return 0;
		}
	}
	spin_unlock(&priv->table_lock);
	return -ENOMEM;
}

static void clear_flow_table_entry(struct dce_flow *flow, u32 entry)
{
	struct dpdcei_priv *priv = flow->device;

	spin_lock(&priv->table_lock);
	BUG_ON(entry >= priv->flow_table_size);
	priv->flow_lookup_table[entry] = NULL;
	spin_unlock(&priv->table_lock);
}

/* shared (de)comp devices */
static struct dpdcei_priv *compression;
static struct dpdcei_priv *decompression;

static int __cold dpdcei_drv_setup(int *vfio_fd, int *dpdcei_drv_setup);

struct dpdcei_priv *get_compression_device(int *vfio_fd, int *vfio_group_fd)
{
	if (!compression)
		dpdcei_drv_setup(vfio_fd, vfio_group_fd);
	return compression;
}
EXPORT_SYMBOL(get_compression_device);

struct dpdcei_priv *get_decompression_device(int *vfio_fd, int *vfio_group_fd)
{
	if (!decompression)
		dpdcei_drv_setup(vfio_fd, vfio_group_fd);
	return decompression;
}
EXPORT_SYMBOL(get_decompression_device);

int dce_flow_create(int vfio_fd, struct dpdcei_priv *device, struct dce_flow *flow)
{
	int err;

	if (!device) {
		pr_err("Null device passed to %s\n", __func__);
		return -EINVAL;
	}

	/* associate flow to device */
	flow->device = device;

	/* Setup dma memory for the flow */
	flow->mem.addr = vfio_setup_dma(vfio_fd, MAX_RESOURCE_IN_FLIGHT);
	if (!flow->mem.addr) {
		err = -ENOMEM;
		goto err_dma_mem_setup;
	}
	flow->mem.sz = MAX_RESOURCE_IN_FLIGHT;
	dma_mem_allocator_init(&flow->mem);

	flow->flc.len = sizeof(struct fcr);
	flow->flc.virt = dma_mem_memalign(&flow->mem, FCR_ALIGN,
					sizeof(struct fcr));
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
	atomic_set(&flow->frames_in_flight, 0);
	return 0;

err_get_table_entry:
	dma_mem_free(&flow->mem, flow->flc.virt);
err_fcr_alloc:
	vfio_cleanup_dma(vfio_fd, flow->mem.addr, flow->mem.sz);
err_dma_mem_setup:
	return err;
}
EXPORT_SYMBOL(dce_flow_create);

int dce_flow_destroy(int vfio_fd, struct dce_flow *flow)
{
	flow->flc.phys = 0;
	flow->flc.len = 0;

	clear_flow_table_entry(flow, flow->key);
	dma_mem_free(&flow->mem, flow->flc.virt);
	flow->flc.virt = NULL;
	vfio_cleanup_dma(vfio_fd, flow->mem.addr, flow->mem.sz);
	flow->mem.addr = NULL;
	return 0;
}
EXPORT_SYMBOL(dce_flow_destroy);

int enqueue_fd(struct dce_flow *flow, struct dpaa2_fd *fd)
{
	struct dpdcei_priv *priv = flow->device;
	enum dce_cmd cmd = fd_frc_get_cmd((struct fd_attr *)fd);
	int err = 0;

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
	atomic_inc(&priv->frames_in_flight);
	atomic_inc(&flow->frames_in_flight);

	err = dpaa2_io_service_enqueue_fq(priv->dpio_p, priv->tx_fqid, fd);
	if (err < 0) {
		pr_err("DCE: error enqueueing Tx frame\n");
		atomic_dec(&priv->frames_in_flight);
		atomic_dec(&flow->frames_in_flight);
	}
	return err;
}
EXPORT_SYMBOL(enqueue_fd);

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

static int dpaa2_dce_pull_dequeue_rx(struct dpdcei_priv *priv)
{
	int err = 0;
	int is_last = 0;
	struct dpaa2_dq *dq;
	const struct dpaa2_fd *fd;
	struct dce_flow *flow;
	u32 key;

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
		fd = dpaa2_dq_fd(dq);
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

		atomic_dec(&priv->frames_in_flight);
		atomic_dec(&flow->frames_in_flight);
	}
	return 0;
}

static void fqdan_cb_rx(struct dpaa2_io_notification_ctx *ctx)
{
	struct dpdcei_priv *priv = container_of(ctx, struct dpdcei_priv,
						   notif_ctx_rx);

	dpaa2_dce_pull_dequeue_rx(priv);
	dpaa2_io_service_rearm(priv->dpio_p, ctx);
}

static int __cold dpdcei_dpio_service_setup(struct dpdcei_priv *priv)
{
	int err;

	/* Register notification callbacks */
	priv->notif_ctx_rx.is_cdan = 0;
	priv->notif_ctx_rx.desired_cpu = -1;
	priv->notif_ctx_rx.cb = fqdan_cb_rx;
	priv->notif_ctx_rx.id = priv->rx_fqid;
	err = dpaa2_io_service_register(priv->dpio_p, &priv->notif_ctx_rx);
	if (err) {
		pr_err("Rx notif register failed 0x%x\n", err);
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
		pr_err("dpdcei_dpio_service_teardown failed 0x%x\n", err);
		return err;
	}
	return 0;
}

static int __cold dpdcei_bind_dpio(struct dpdcei_priv *priv,
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
	err = dpdcei_set_rx_queue(mc_io, dpdcei_handle, priv->token,
			&rx_queue_cfg);
	if (err) {
		pr_err("dpdcei_set_rx_flow() failed\n");
		return err;
	}

	return 0;
}

static int __cold dpdcei_unbind_dpio(struct dpdcei_priv *priv,
				struct fsl_mc_io *mc_io,
				uint16_t dpdcei_handle)
{
	int err;

	err = dpdcei_reset(mc_io, dpdcei_handle, priv->token);
	if (err) {
		pr_err("dpdcei_reset failed\n");
		return err;
	}
	priv->notif_ctx_rx.qman64 = 0;
	priv->notif_ctx_rx.dpio_id = 0;

	return 0;
}

static int dpaa2_dce_alloc_store(int vfio_fd, struct dpdcei_priv *priv)
{
	priv->rx_store = dpaa2_io_store_create(vfio_fd, DQ_STORE_SIZE, NULL);
	if (!priv->rx_store) {
		pr_err("dpaa2_io_store_create() failed\n");
		return -ENOMEM;
	}
	return 0;
}

static void dpaa2_dce_free_store(struct dpdcei_priv *priv)
{
	dpaa2_io_store_destroy(priv->rx_store);
}

#define DPRC_CFG_OPT_TOPOLOGY_CHANGES_ALLOWED   0x00000008
#define ROOT_DPRC 1

#define DPRC_GET_ICID_FROM_POOL         (uint16_t)(~(0))
#define DPRC_GET_PORTAL_ID_FROM_POOL    (int)(~(0))

static void appease_mc(struct fsl_mc_io *mc_io, int *vfio_fd, int *vfio_group_fd, int dprc_id, int dpio_id);

static __cold struct dpdcei_priv *dpdcei_setup(struct fsl_mc_io *mc_io,
						struct dpaa2_io *dpio_p,
						int dprc_id,
						uint16_t root_dprc_token,
						int dpio_id,
						int vfio_fd,
						int engine)
{
	struct dprc_res_req res_req;
	struct dpdcei_priv *priv = NULL;
	struct dpdcei_rx_queue_attr rx_attr;
	struct dpdcei_tx_queue_attr tx_attr;
	struct dpdcei_cfg cfg;
	int err = 0;

	if (engine != DPDCEI_ENGINE_COMPRESSION &&
			engine != DPDCEI_ENGINE_DECOMPRESSION) {
		pr_err("Bad DPDCEI engine selection\n");
		return NULL;
	}

	memset(&rx_attr, 0, sizeof(rx_attr));
	memset(&tx_attr, 0, sizeof(tx_attr));

	priv = malloc(sizeof(*priv));
	if (!priv) {
		pr_err("Unable to allocate memory for dpdcei setup\n");
		goto err_priv_alloc;
	}

	/* initialize lookup table */
	setup_flow_lookup_table(mc_io, priv);

	/* in flight ring initialization */
	atomic_set(&priv->frames_in_flight, 0);

	/* get a handle for the DPDCEI this interface is associated with */
	cfg = (struct dpdcei_cfg){.engine = engine, .priority = 1};
	err = dpdcei_create(mc_io, MC_CMD_FLAG_PRI, &cfg, &priv->token);
	if (err) {
		pr_err("DCE: dpdcei_create() failed\n");
		goto err_open;
	}

	err = dpdcei_get_attributes(mc_io, MC_CMD_FLAG_PRI, priv->token,
				&priv->dpdcei_attrs);
	if (err) {
		pr_err("DCE: dpdcei_get_attributes() failed %d\n", err);
		goto err_get_attr;
	}

	/* just make sure it is closed? */
	err = dpdcei_close(mc_io, MC_CMD_FLAG_PRI, priv->token);
	vfio_force_rescan();

	/* Associate dpdcei with dprc */
	strcpy(res_req.type, "dpdcei");
	res_req.num = 1;
	res_req.options = DPRC_RES_REQ_OPT_EXPLICIT | DPRC_RES_REQ_OPT_PLUGGED;
	res_req.id_base_align = priv->dpdcei_attrs.id;
	err = dprc_assign(mc_io, MC_CMD_FLAG_PRI, root_dprc_token, dprc_id,
								&res_req);
	if (err) {
		pr_err("dprc_assign failed with error code %d\n", err);
		goto err_get_attr;
	}

	vfio_force_rescan();
	err = dpdcei_open(mc_io, MC_CMD_FLAG_PRI, priv->dpdcei_attrs.id,
								&priv->token);
	if (err) {
		pr_err("dpdcei_open failed with error code %d\n", err);
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

	err = dpdcei_get_rx_queue(mc_io, MC_CMD_FLAG_PRI, priv->token,
			&rx_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_get_attr;
	}

	priv->rx_fqid = rx_attr.fqid;

	err = dpdcei_get_tx_queue(mc_io, MC_CMD_FLAG_PRI, priv->token,
			&tx_attr);
	if (err) {
		pr_err("DCE: dpdcei_get_rx_queue() failed %d\n", err);
		goto err_get_attr;
	}
	priv->tx_fqid = tx_attr.fqid;

	/* dpio store */
	err = dpaa2_dce_alloc_store(vfio_fd, priv);
	if (err)
		goto err_get_attr;

	priv->dpio_p = dpio_p;

	/* dpio services */
	err = dpdcei_dpio_service_setup(priv);
	if (err)
		goto err_dpio_setup;

	if (priv->notif_ctx_rx.dpio_id != dpio_id) {
		pr_err("discrepancy between expected and observed dpio id. Applying workaround\n");
		priv->notif_ctx_rx.dpio_id = dpio_id;
	}

	/* DPDCEI binding to DPIO */
	err = dpdcei_bind_dpio(priv, mc_io, priv->token);
	if (err) {
		pr_err("DCE: Error dpdcei bind %d\n", err);
		goto err_bind;
	}

	/* Enable the device */
	err = dpdcei_enable(mc_io, MC_CMD_FLAG_PRI, priv->token);
	if (err) {
		pr_err("DCE: dpdcei_enable failed %d\n", err);
		goto err_enable;
	}

	return priv;
err_enable:
	dpdcei_unbind_dpio(priv, mc_io, priv->token);
err_bind:
	dpdcei_dpio_service_teardown(priv);
err_dpio_setup:
	dpaa2_dce_free_store(priv);
err_get_attr:
	dpdcei_close(mc_io, MC_CMD_FLAG_PRI, priv->token);
err_open:
	free(priv);
err_priv_alloc:
	return NULL;
}

/* DPIO creation move to application */
#define FIRST_DPIO_STASH 4
static int dpaa2_io_get_dpio(int *rc_id, int *dpio_id, unsigned int *qbman_version)
{
        struct dprc_res_req res_req;
        int root_container_id=1;
        uint16_t token_dprc[2];
        struct dprc_cfg cfg_dprc;
        char id_str_dprc[20];
        int created_dprc_id;
        uint64_t child_portal_paddr;

        struct fsl_mc_io mc_io;
        uint16_t token_dpio;
        struct dpio_cfg cfg_dpio;
        char id_str_dpio[20];
        struct dpio_attr attr_dpio;

        /* MC */
        if(mc_io_init(&mc_io))
                return -1;
        if(dprc_open(&mc_io,0, root_container_id, &token_dprc[0]))
                return -1;

        /* RC */
        cfg_dprc.icid = DPRC_GET_ICID_FROM_POOL;
        cfg_dprc.portal_id = DPRC_GET_PORTAL_ID_FROM_POOL;
        cfg_dprc.options = DPRC_CFG_OPT_TOPOLOGY_CHANGES_ALLOWED;
        strncpy(cfg_dprc.label, "dprc", 16);
        if(dprc_create_container(&mc_io,0, token_dprc[0], &cfg_dprc, &created_dprc_id, &child_portal_paddr))
                return -1;
        sprintf(id_str_dprc, "dprc.%i", created_dprc_id);
        printf("Created DPRC: %x\n", created_dprc_id);

        if(dprc_open(&mc_io,0, created_dprc_id, &token_dprc[1]))
                return -1;
        vfio_force_rescan();

        /* DPIO */
        cfg_dpio.channel_mode =1; cfg_dpio.num_priorities =8;
        if(dpio_create(&mc_io,0, &cfg_dpio, &token_dpio))
                return -1;
        vfio_force_rescan();
        if(dpio_get_attributes(&mc_io,0, token_dpio, &attr_dpio))
                return -1;
        if(dpio_close(&mc_io,0, token_dpio))
                return -1;
        vfio_force_rescan();
        strcpy(res_req.type, "dpio"); res_req.num =1; res_req.options =DPRC_RES_REQ_OPT_EXPLICIT | DPRC_RES_REQ_OPT_PLUGGED;

        res_req.id_base_align =attr_dpio.id;
        if(dprc_assign(&mc_io,0, token_dprc[0], created_dprc_id, &res_req))
                return -1;
        vfio_force_rescan();
        if(dpio_open(&mc_io,0, attr_dpio.id, &token_dpio))
                return -1;
        if(dpio_set_stashing_destination(&mc_io,0, token_dpio, FIRST_DPIO_STASH))
                return -1;
        sprintf(id_str_dpio, "dpio.%i", attr_dpio.id);
        printf("Created: %s\n", id_str_dpio);

        *dpio_id = attr_dpio.id;
        *rc_id = created_dprc_id;
        *qbman_version = attr_dpio.qbman_version;

        return 0;
}


static DEFINE_SPINLOCK(driver_lock);

static void reaper(int piper[2]);

#define NUM_RESOURCES 4

static int __cold dpdcei_drv_setup(int *vfio_fd, int *vfio_group_fd)
{
	struct fsl_mc_io *mc_io;
	struct dpaa2_io *dpio_p;
	int dprc_id, dpio_id;
	uint16_t root_dprc_token;
	int piper[2];
	int buff[NUM_RESOURCES];
	unsigned int qbman_version;
	int err = 0;

	spin_lock(&driver_lock);
	if (compression && decompression) {
		spin_unlock(&driver_lock);
		return 0;
	}

	/* it should never be that we have one engine and not the other */
	assert(!compression && !decompression);

	err = pipe(piper);
	if (err)
		pr_err("Could not create pipe for child process\n");

	switch (fork()) {
	case -1:
		pr_err("failed to create resource cleanup process\n");
		break;
	case 0: /* cleanup process */
		close(piper[1]); /* child only reads */
		reaper(piper);
		assert(false); /* Should never be reached */
		break;
	default:
		close(piper[0]); /* parent only writes */
		break;
	}

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io) {
		err = -ENOMEM;
		goto err_mc_io_alloc;
	}
	err = mc_io_init(mc_io);
	if (err)
		goto err_mc_io_init;

	err = dpaa2_io_get_dpio(&dprc_id, &dpio_id, &qbman_version);
	if (err)
		goto err_mc_io_init;

	appease_mc(mc_io, vfio_fd, vfio_group_fd, dprc_id, dpio_id);

	/* Get dpio */
	dpio_p = dpaa2_io_create(dpio_id, *vfio_fd, *vfio_group_fd, qbman_version);

	err = dprc_open(mc_io, MC_CMD_FLAG_PRI, ROOT_DPRC, &root_dprc_token);
	if (err)
		pr_err("dprc_open() failed to open the root container\n");

	compression = dpdcei_setup(mc_io, dpio_p, dprc_id, root_dprc_token,
					dpio_id, *vfio_fd, DPDCEI_ENGINE_COMPRESSION);
	if (!compression) {
		pr_err("Failed to setup compression dpdcei\n");
		err = -EACCES;
		goto err_comp_setup;
	}

	decompression = dpdcei_setup(mc_io, dpio_p, dprc_id, root_dprc_token,
					dpio_id, *vfio_fd, DPDCEI_ENGINE_DECOMPRESSION);
	if (!decompression) {
		pr_err("Failed to setup decompression dpdcei\n");
		err = -EACCES;
		goto err_decomp_setup;
	}

	/* Send resources information to child for cleanup */

	buff[0] = dprc_id;
	buff[1] = compression->dpdcei_attrs.id;
	buff[2] = decompression->dpdcei_attrs.id;
	buff[3] = compression->dpio_p->swp_desc.idx;
	err = write(piper[1], (char *)buff, sizeof(buff));
	if (err != sizeof(buff))
		pr_err("write faild\n");

err_decomp_setup:
	/* TODO: dpdcei_cleanup(compression); */
err_comp_setup:
	mc_io_cleanup(mc_io);
err_mc_io_init:
	free(mc_io);
err_mc_io_alloc:
	spin_unlock(&driver_lock);
	return err;
}

static struct qbman_swp *dpio_swp;

static void appease_mc(struct fsl_mc_io *mc_io, int *vfio_fd, int *vfio_group_fd, int dprc_id, int dpio_id)
{
	char dpio_id_str[50];
	char dprc_id_str[50];
	uint16_t dprc_token, dpio_token;
	struct qbman_swp_desc desc_swp;
	int err;

	/* ***************************************** RC  */
	assert(!dprc_open(mc_io, 0, dprc_id, &dprc_token));
	snprintf(dprc_id_str, sizeof(dprc_id_str), "dprc.%i", dprc_id);
	vfio_force_rescan();
	/* ***************************************** IO #1 */
	assert(!dpio_open(mc_io, 0, dpio_id, &dpio_token));
	vfio_force_rescan();
	snprintf(dpio_id_str, sizeof(dpio_id_str), "dpio.%d", dpio_id);

	err = vfio_bind_container(dprc_id_str);
	if (err) {
		pr_err("vfio_bind_container() failed\n");
		abort();
	}
	err = vfio_setup(dprc_id_str, vfio_fd, vfio_group_fd);
	if (err) {
		pr_err("vfio_setup\n");
		abort();
	}

	vfio_force_rescan();

	/* ***************************************** ENABLE IO */
	assert(!dpio_enable(mc_io, 0, dpio_token));

	desc_swp.cena_bar = 0;
	desc_swp.cinh_bar = vfio_map_portal_mem(dpio_id_str, PORTAL_MEM_CINH, *vfio_fd, *vfio_group_fd);
	assert(desc_swp.cinh_bar);

	desc_swp.idx = dpio_id;
	desc_swp.eqcr_mode = qman_eqcr_vb_array;
	desc_swp.irq = -1;
	desc_swp.qman_version = QMAN_REV_4000;
	dpio_swp = qbman_swp_init(&desc_swp);
	qbman_swp_finish(dpio_swp);
}

void dpdcei_drv_cleanup(int vfio_fd, int vfio_group_fd)
{
	int err;
	struct fsl_mc_io *mc_io;
	uint16_t temp_token;

	spin_lock(&driver_lock);
	if (!compression || !decompression) {
		spin_unlock(&driver_lock);
		return;
	}
	assert(compression && decompression);

	dpaa2_io_destroy(vfio_fd, vfio_group_fd);

	mc_io = malloc(sizeof(struct fsl_mc_io));
	if (!mc_io) {
		pr_err("Could not malloc mem for mc_io in %s\n", __func__);
		goto err_mc_io_alloc;
	}

	err = mc_io_init(mc_io);
	if (err) {
		pr_err("error %d in %s in attempt to mc_io_init\n",
				err, __func__);
		goto err_mc_io_init;
	}

	err = dpdcei_open(mc_io, MC_CMD_FLAG_PRI, compression->dpdcei_attrs.id,
							&compression->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_open(comp)\n",
				err, __func__);

	err = dpdcei_disable(mc_io, MC_CMD_FLAG_PRI, compression->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_disable(comp)\n",
				err, __func__);

	err = dpdcei_close(mc_io, MC_CMD_FLAG_PRI, compression->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_close(comp)\n",
				err, __func__);

	err = dpdcei_open(mc_io, MC_CMD_FLAG_PRI,
			decompression->dpdcei_attrs.id, &decompression->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_open(decomp)\n",
				err, __func__);

	err = dpdcei_disable(mc_io, MC_CMD_FLAG_PRI, decompression->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_disable(decomp)\n",
				err, __func__);

	err = dpdcei_close(mc_io, MC_CMD_FLAG_PRI, decompression->token);
	if (err)
		pr_err("error %d in %s in attempt to dpdcei_close(decomp)\n",
				err, __func__);

	err = dpio_open(mc_io, MC_CMD_FLAG_PRI,
			compression->dpio_p->swp_desc.idx, &temp_token);
	if (err)
		pr_err("error %d in %s in attempt to dpio_open()\n",
				err, __func__);

	err = dpio_disable(mc_io, MC_CMD_FLAG_PRI, temp_token);
	if (err)
		pr_err("error %d in %s in attempt to dpio_disable()\n",
				err, __func__);

	err = dpio_close(mc_io, MC_CMD_FLAG_PRI, temp_token);
	if (err)
		pr_err("error %d in %s in attempt to dpio_close()\n",
				err, __func__);

	mc_io_cleanup(mc_io);

	vfio_force_rescan();
	close(vfio_group_fd);
	close(vfio_fd);

err_mc_io_init:
	free(mc_io);
err_mc_io_alloc:
	spin_unlock(&driver_lock);
}
EXPORT_SYMBOL(dpdcei_drv_cleanup);

static sem_t dce_finished_wait;

static void parent_dead_signal_handler(int signal)
{
	assert(signal == SIGHUP);
	sem_post(&dce_finished_wait);
}

static void reaper(int piper[2])
{
	struct sigaction act;
	int dprc_id, dpio_id, comp_dpdcei_id, decomp_dpdcei_id;
	char dprc_str[50];
	char restool_cmd[200];
	int buff[NUM_RESOURCES];
	int err;

	memset (&act, 0, sizeof (act));
	sem_init(&dce_finished_wait, 0, 0);
	act.sa_handler = parent_dead_signal_handler;
	if (sigaction(SIGHUP, &act, NULL) < 0) {
		perror ("failed to setup DCE resources cleanup process\n");
		exit (-1);
	}
	/* Setup signal when parent dies */
	prctl(PR_SET_PDEATHSIG, SIGHUP);

	/* Put child process in its own group to ignore ^C & other signals */
	setpgid(0 /* get my pid */, 0 /* make my own group id */);

	/* Wait for kernel to send us SIGHUP. We registered to get this signal
	 * if our parent dies */
	sem_wait(&dce_finished_wait);

	/* Read resource information from parent */
	err = read(piper[0], (char *)buff, sizeof(buff));
	if (err != sizeof(buff))
		pr_err("read faild\n");

	dprc_id = buff[0];
	comp_dpdcei_id = buff[1];
	decomp_dpdcei_id = buff[2];
	dpio_id = buff[3];

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dprc assign dprc.%d --object=%s.%d --plugged=0",
		dprc_id, "dpdcei", comp_dpdcei_id);
	if (system(restool_cmd))
		pr_err("restool unplug comp dpdcei failed\n");

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dprc assign dprc.%d --object=%s.%d --plugged=0",
		dprc_id, "dpdcei", decomp_dpdcei_id);
	if (system(restool_cmd))
		pr_err("restool unplug decomp dpdcei failed\n");

	snprintf(dprc_str, sizeof(dprc_str), "dprc.%d",
			dprc_id);
	err = vfio_unbind_container(dprc_str);
	if (err)
		pr_err("vfio_unbind_container failed for %s\n", dprc_str);

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dprc assign dprc.%d --object=%s.%d --plugged=0",
		dprc_id, "dpio", dpio_id);
	if (system(restool_cmd))
		pr_err("restool unplug decomp dpdcei failed\n");

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dpdcei destroy dpdcei.%d",
		comp_dpdcei_id);
	if (system(restool_cmd))
		pr_err("restool destroy comp dpdcei failed\n");

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dpdcei destroy dpdcei.%d",
		decomp_dpdcei_id);
	if (system(restool_cmd))
		pr_err("restool destroy decomp dpdcei failed\n");

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dpio destroy dpio.%d", dpio_id);
	if (system(restool_cmd))
		pr_err("restool destroy dpio failed\n");

	snprintf(restool_cmd, sizeof(restool_cmd),
		"restool dprc destroy dprc.%d", dprc_id);
	if (system(restool_cmd))
		pr_err("restool destroy dprc failed\n");

	exit(EXIT_SUCCESS);
}
