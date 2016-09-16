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
//#include <linux/init.h>
//#include <linux/module.h>
//#include <linux/platform_device.h>
//#include <linux/interrupt.h>
//#include <linux/dma-mapping.h>
//#include <linux/slab.h>
//#include "mc.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <stdlib.h>

#include "fsl_mc_cmd.h"
#include "fsl_dpci.h"
#include "fsl_dpio.h"
#include "fsl_dprc.h"
#include "fsl_mc_sys.h"
#include "fsl_dpmng.h"
#include "vfio_utils.h"
#include "allocator.h"
#include "qbman_portal.h"

#include "fsl_qbman_portal.h"
#include "fsl_dpaa2_io.h"
#include "fsl_dpio.h"
#include "fsl_qbman_base.h"
#include "qbman_debug.h"
#include "needToFix.h"
#include "compat.h"
#include <pthread.h>

#define PTR_ALIGN(p, a)            ((typeof(p))ALIGN((unsigned long)(p), (a)))
#define FIRST_DPIO_STASH 4

extern struct dpaa2_io *devObjPtr;

static pthread_t process_interrupt_thread;
uint32_t count_interrupt=0;
struct dpaa2_io *obj;
static struct dpaa2_io_desc *desc;

#ifdef toto
struct dpaa2_io_store {
	unsigned int max;
	dma_addr_t paddr;
	struct dpaa2_dq *vaddr;
	void *alloced_addr; /* unaligned value from kmalloc() */
	unsigned int idx; /* position of the next-to-be-returned entry */
	struct qbman_swp *swp; /* portal used to issue VDQCR */
	struct device *dev; /* device used for DMA mapping */
};
#endif

/* keep a per cpu array of DPIOs for fast access */
static struct dpaa2_io *dpio_by_cpu[NR_CPUS];
static struct list_head dpio_list = LIST_HEAD_INIT(dpio_list);
static DEFINE_SPINLOCK(dpio_list_lock) ;

/**********************/
/* Internal functions */
/**********************/
#include <sched.h>
static inline struct dpaa2_io *service_select_by_cpu(struct dpaa2_io *d,
						     int cpu)
{
	if (d)
		return d;
	/* If cpu==-1, choose the current cpu, with no guarantees about
	 * potentially being migrated away.
	 */
	if (unlikely(cpu < 0))
		cpu = sched_getcpu();

	/* If a specific cpu was requested, pick it up immediately */
	return dpio_by_cpu[cpu];
}

static inline struct dpaa2_io *service_select(struct dpaa2_io *d)
{
	if (d)
		return d;
	spin_lock(&dpio_list_lock);
	d = list_entry(dpio_list.next, struct dpaa2_io, node);
	list_del(&d->node);
	list_add_tail(&d->node, &dpio_list);
	spin_unlock(&dpio_list_lock);

	return d;
}


/**********************/
/* Exported functions */
/**********************/

static struct dprc_res_req res_req;
static int root_container_id=1;
static uint16_t token_dprc[2];
static struct dprc_connection_cfg cfg_c_dprc;
static struct dprc_cfg cfg_dprc; 
char *id_str_dprc[20];
int created_dprc_id;
static uint64_t child_portal_paddr;


static struct fsl_mc_io mc_io;
static uint16_t token_dpio;
static struct dpio_cfg cfg_dpio;
static struct dpio_attr attr_dpio;
static char *id_str_dpio[20];

int dpaa2_io_get_dpio(int *rcId, int *dpioId) {
	// MC
	assert(!mc_io_init(&mc_io));
        assert(!dprc_open(&mc_io,NULL, root_container_id, &token_dprc[0]));

        // RC
        cfg_dprc.icid = DPRC_GET_ICID_FROM_POOL;
        cfg_dprc.portal_id = DPRC_GET_PORTAL_ID_FROM_POOL;
        cfg_dprc.options = DPRC_CFG_OPT_TOPOLOGY_CHANGES_ALLOWED;
        strncpy(cfg_dprc.label, "dprc", 16);
        assert(!dprc_create_container(&mc_io,NULL, token_dprc[0], &cfg_dprc, &created_dprc_id, &child_portal_paddr));
        sprintf(id_str_dprc, "dprc.%i", created_dprc_id);
        printf("Created DPRC: %x\n", created_dprc_id);

        assert(!dprc_open(&mc_io,NULL, created_dprc_id, &token_dprc[1]));
        vfio_force_rescan();

	// DPIO
        cfg_dpio.channel_mode =1; cfg_dpio.num_priorities =8;
        assert(!dpio_create(&mc_io,NULL, &cfg_dpio, &token_dpio));
        vfio_force_rescan();
        assert(!dpio_get_attributes(&mc_io,NULL, token_dpio, &attr_dpio));
        assert(!dpio_close(&mc_io,NULL, token_dpio));
        vfio_force_rescan();
        strcpy(res_req.type, "dpio"); res_req.num =1; res_req.options =DPRC_RES_REQ_OPT_EXPLICIT | DPRC_RES_REQ_OPT_PLUGGED;

        res_req.id_base_align =attr_dpio.id;
        assert(!dprc_assign(&mc_io,NULL, token_dprc[0], created_dprc_id, &res_req));
        vfio_force_rescan();
        assert(!dpio_open(&mc_io,NULL, attr_dpio.id, &token_dpio));
        assert(!dpio_set_stashing_destination(&mc_io,NULL, token_dpio, FIRST_DPIO_STASH));
        sprintf(id_str_dpio, "dpio.%i", attr_dpio.id);
        printf("Created: %s\n", id_str_dpio);

	*dpioId = attr_dpio.id;
	*rcId = created_dprc_id;

	return attr_dpio.id;
}

void *process_interrupt(void *not_used)
{
	printf("Polling for interrupt\n");
	while(1){
		sleep(0.1);
		if(qbman_swp_interrupt_read_status(obj->swp)) {
			printf("Processing interrupt\n");
			fflush(0);
			sleep(1);
			dpaa2_io_irq(obj);
			count_interrupt++;
		}
	}
}

/**
 * dpaa2_io_create() - create a dpaa2_io object.
 * @desc: the dpaa2_io descriptor
 *
 * Activates a "struct dpaa2_io" corresponding to the given config of an actual
 * DPIO object. This handle can be used on it's own (like a one-portal "DPIO
 * service") or later be added to a service-type "struct dpaa2_io" object. Note,
 * the information required on 'cfg' is copied so the caller is free to do as
 * they wish with the input parameter upon return.
 *
 * Return a valid dpaa2_io object for success, or NULL for failure.
 */
struct dpaa2_io *dpaa2_io_create()//const struct dpaa2_io_desc *desc)
{
	if (!desc)
		desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return NULL;

	/* non-zero iff the DPIO has a channel */
	desc->receives_notifications=0;
	/* ignored unless 'receives_notifications'. Non-zero iff the channel has
	 * 8 priority WQs, otherwise the channel has 2.
	 */
	desc->has_8prio=0;
	/* the cpu index that at least interrupt handlers will execute on. */
	desc->cpu=sched_getcpu();
	/* Caller-provided flags, determined by bus-scanning and/or creation of
	 * DPIO objects via MC commands.
	 */
	desc->regs_cena=0;
	desc->regs_cinh=0;
	desc->dpio_id=0;
	desc->qman_version=QMAN_REV_4000;

	if (!obj)
		obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;

	atomic_set(&obj->refs, 1);
	obj->swp_desc.cena_bar = vfio_map_portal_mem(id_str_dpio, PORTAL_MEM_CENA);
	assert(obj->swp_desc.cena_bar);
	obj->swp_desc.cinh_bar = vfio_map_portal_mem(id_str_dpio, PORTAL_MEM_CINH);
	assert(obj->swp_desc.cinh_bar);
	obj->swp_desc.idx = attr_dpio.id;
	obj->swp_desc.eqcr_mode = qman_eqcr_vb_ring;
	obj->swp_desc.irq = -1;
	obj->swp_desc.qman_version = QMAN_REV_4000;
	obj->swp = qbman_swp_init(&(obj->swp_desc));

	if (!obj->swp) {
		kfree(obj);
		return NULL;
	}
	INIT_LIST_HEAD(&obj->node);
	spin_lock_init(&obj->lock_mgmt_cmd);
	spin_lock_init(&obj->lock_notifications);
	INIT_LIST_HEAD(&obj->notifications);

// This will cause: [ 1092.125040] arm-smmu 5000000.iommu: Unhandled context fault: iova=0x06030040, fsynr=0x12, cb=0
	/* For now only enable DQRR interrupts */
//	qbman_swp_interrupt_set_trigger(obj->swp, QBMAN_SWP_INTERRUPT_DQRI);

	qbman_swp_interrupt_clear_status(obj->swp, 0xffffffff);
	if (obj->dpio_desc.receives_notifications)
		qbman_swp_push_set(obj->swp, 0, 1);

	spin_lock(&dpio_list_lock);
	list_add_tail(&obj->node, &dpio_list);
	if (desc->cpu != -1 && !dpio_by_cpu[desc->cpu])
		dpio_by_cpu[desc->cpu] = obj;
	spin_unlock(&dpio_list_lock);

	if(pthread_create(&process_interrupt_thread, NULL, &process_interrupt, NULL)) {
		kfree(obj);
		return NULL;
	}

	return obj;
}
EXPORT_SYMBOL(dpaa2_io_create);

/**
 * dpaa2_io_down() - release the dpaa2_io object.
 * @d: the dpaa2_io object to be released.
 *
 * The "struct dpaa2_io" type can represent an individual DPIO object (as
 * described by "struct dpaa2_io_desc") or an instance of a "DPIO service",
 * which can be used to group/encapsulate multiple DPIO objects. In all cases,
 * each handle obtained should be released using this function.
 */
void dpaa2_io_down(struct dpaa2_io *d)
{
	if (!atomic_dec_and_test(&d->refs))
		return;
	kfree(d);
}
EXPORT_SYMBOL(dpaa2_io_down);

/**
 * dpaa2_io_get_descriptor() - Get the DPIO descriptor of the given DPIO object.
 * @obj: the given DPIO object.
 * @desc: the returned DPIO descriptor.
 *
 * This function will return failure if the given dpaa2_io struct represents a
 * service rather than an individual DPIO object, otherwise it returns zero and
 * the given 'cfg' structure is filled in.
 *
 * Return 0 for success, or -EINVAL for failure.
 */
int dpaa2_io_get_descriptor(struct dpaa2_io *obj, struct dpaa2_io_desc *desc)
{
	*desc = obj->dpio_desc;
	return 0;
}
EXPORT_SYMBOL(dpaa2_io_get_descriptor);

#define DPAA_POLL_MAX 32

/**
 * dpaa2_io_irq() - Process any notifications and h/w-initiated events that are
 * irq-driven.
 * @obj: the given DPIO object.
 *
 * Obligatory for DPIO objects that have dpaa2_io_desc::has_irq non-zero.
 *
 * Return IRQ_HANDLED for success, or -EINVAL for failure.
 */
int dpaa2_io_irq(struct dpaa2_io *obj)
{
	const struct dpaa2_dq *dq;
	int max = 0;
	struct qbman_swp *swp;
	u32 status;

	swp = obj->swp;
	status = qbman_swp_interrupt_read_status(swp);
	if (!status)
		return NULL;//IRQ_NONE;

	swp = obj->swp;
	dq = qbman_swp_dqrr_next(swp);
printf("qbman_swp_dqrr_next()\n");
	while (dq) {
printf("qbman_result_is_SCN()\n");
		if (qbman_result_is_SCN(dq)) {
			struct dpaa2_io_notification_ctx *ctx;
			u64 q64;

			q64 = qbman_result_SCN_ctx(dq);
			ctx = (void *)q64;
			ctx->cb(ctx);
		} else {
			pr_crit("Unrecognised/ignored DQRR entry\n");
		}
		qbman_swp_dqrr_consume(swp, dq);
		++max;
		if (max > DPAA_POLL_MAX)
			goto done;
		dq = qbman_swp_dqrr_next(swp);
	}
done:
	qbman_swp_interrupt_clear_status(swp, status);
	qbman_swp_interrupt_set_inhibit(swp, 0);
	return IRQ_HANDLED;
}
EXPORT_SYMBOL(dpaa2_io_irq);

/**
 * dpaa2_io_service_register() - Prepare for servicing of FQDAN or CDAN
 * notifications on the given DPIO service.
 * @service: the given DPIO service.
 * @ctx: the notification context.
 *
 * The MC command to attach the caller's DPNI/DPCON/DPAI device to a
 * DPIO object is performed after this function is called. In that way, (a) the
 * DPIO service is "ready" to handle a notification arrival (which might happen
 * before the "attach" command to MC has returned control of execution back to
 * the caller), and (b) the DPIO service can provide back to the caller the
 * 'dpio_id' and 'qman64' parameters that it should pass along in the MC command
 * in order for the DPNI/DPCON/DPAI resources to be configured to produce the
 * right notification fields to the DPIO service.
 *
 * Return 0 for success, or -ENODEV for failure.
 */
int dpaa2_io_service_register(struct dpaa2_io *d,
			      struct dpaa2_io_notification_ctx *ctx)
{
	unsigned long irqflags;

	d = service_select_by_cpu(d, ctx->desired_cpu);
	if (!d)
		return -ENODEV;
	ctx->dpio_id = d->dpio_desc.dpio_id;
	ctx->qman64 = (u64)ctx;
	ctx->dpio_private = d;
	pthread_mutex_lock(&d->lock_notifications);
	list_add(&ctx->node, &d->notifications);
	pthread_mutex_unlock(&d->lock_notifications);

	if (ctx->is_cdan)
		/* Enable the generation of CDAN notifications */
		qbman_swp_CDAN_set_context_enable(d->swp,
						  (u16)ctx->id,
						  ctx->qman64);
	return 0;
}
EXPORT_SYMBOL(dpaa2_io_service_register);

/**
 * dpaa2_io_service_deregister - The opposite of 'register'.
 * @service: the given DPIO service.
 * @ctx: the notification context.
 *
 * Note that 'register' should be called *before*
 * making the MC call to attach the notification-producing device to the
 * notification-handling DPIO service, the 'unregister' function should be
 * called *after* making the MC call to detach the notification-producing
 * device.
 *
 * Return 0 for success.
 */
int dpaa2_io_service_deregister(struct dpaa2_io *service,
				struct dpaa2_io_notification_ctx *ctx)
{
	struct dpaa2_io *d = ctx->dpio_private;
	unsigned long irqflags;

	if (ctx->is_cdan)
		qbman_swp_CDAN_disable(d->swp, (u16)ctx->id);
	pthread_mutex_lock(&d->lock_notifications);
	list_del(&ctx->node);
	pthread_mutex_unlock(&d->lock_notifications);
	return 0;
}
EXPORT_SYMBOL(dpaa2_io_service_deregister);

/**
 * dpaa2_io_service_rearm() - Rearm the notification for the given DPIO service.
 * @service: the given DPIO service.
 * @ctx: the notification context.
 *
 * Once a FQDAN/CDAN has been produced, the corresponding FQ/channel is
 * considered "disarmed". Ie. the user can issue pull dequeue operations on that
 * traffic source for as long as it likes. Eventually it may wish to "rearm"
 * that source to allow it to produce another FQDAN/CDAN, that's what this
 * function achieves.
 *
 * Return 0 for success, or -ENODEV if no service available, -EBUSY/-EIO for not
 * being able to implement the rearm the notifiaton due to setting CDAN or
 * scheduling fq.
 */
int dpaa2_io_service_rearm(struct dpaa2_io *d,
			   struct dpaa2_io_notification_ctx *ctx)
{
	unsigned long irqflags;
	int err;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	if (ctx->is_cdan)
		err = qbman_swp_CDAN_enable(d->swp, (u16)ctx->id);
	else
		err = qbman_swp_fq_schedule(d->swp, ctx->id);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_rearm);

/**
 * dpaa2_io_from_registration() - Get the DPIO object from the given
 * notification context.
 * @ctx: the given notifiation context.
 * @ret: the returned DPIO object.
 *
 * Like 'dpaa2_io_service_get_persistent()' (see below), except that the
 * returned handle is not selected based on a 'cpu' argument, but is the same
 * DPIO object that the given notification context is registered against. The
 * returned handle carries a reference count, so a corresponding dpaa2_io_down()
 * would be required when the reference is no longer needed.
 *
 * Return 0 for success, or -EINVAL for failure.
 */
int dpaa2_io_from_registration(struct dpaa2_io_notification_ctx *ctx,
			       struct dpaa2_io **io)
{
	struct dpaa2_io_notification_ctx *tmp;
	struct dpaa2_io *d = ctx->dpio_private;
	unsigned long irqflags;
	int ret = 0;

	/*
	 * Iterate the notifications associated with 'd' looking for a match. If
	 * not, we've been passed an unregistered ctx!
	 */
	pthread_mutex_lock(&d->lock_notifications);
	list_for_each_entry(tmp, &d->notifications, node)
		if (tmp == ctx)
			goto found;
	ret = -EINVAL;
found:
	pthread_mutex_unlock(&d->lock_notifications);
	if (!ret) {
		atomic_inc(&d->refs);
		*io = d;
	}
	return ret;
}
EXPORT_SYMBOL(dpaa2_io_from_registration);

/**
 * dpaa2_io_service_pull_fq() - pull dequeue functions from a fq.
 * @d: the given DPIO service.
 * @fqid: the given frame queue id.
 * @s: the dpaa2_io_store object for the result.
 *
 * To support DCA/order-preservation, it will be necessary to support an
 * alternative form, because they must ultimately dequeue to DQRR rather than a
 * user-supplied dpaa2_io_store. Furthermore, those dequeue results will
 * "complete" using a caller-provided callback (from DQRR processing) rather
 * than the caller explicitly looking at their dpaa2_io_store for results. Eg.
 * the alternative form will likely take a callback parameter rather than a
 * store parameter. Ignoring it for now to keep the picture clearer.
 *
 * Return 0 for success, or error code for failure.
 */
int dpaa2_io_service_pull_fq(struct dpaa2_io *d, u32 fqid,
			     struct dpaa2_io_store *s)
{
	struct qbman_pull_desc pd;
	int err=0;

	qbman_pull_desc_clear(&pd);
	qbman_pull_desc_set_storage(&pd, s->vaddr, s->paddr, 1);
	qbman_pull_desc_set_numframes(&pd, (u8)s->max);
	qbman_pull_desc_set_fq(&pd, fqid);
	d = service_select(d);
	if (!d)
		return -ENODEV;
	s->swp = d->swp;
	err = qbman_swp_pull(d->swp, &pd);
	if (err)
		s->swp = NULL;
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_pull_fq);

/**
 * dpaa2_io_service_pull_channel() - pull dequeue functions from a channel.
 * @d: the given DPIO service.
 * @channelid: the given channel id.
 * @s: the dpaa2_io_store object for the result.
 *
 * To support DCA/order-preservation, it will be necessary to support an
 * alternative form, because they must ultimately dequeue to DQRR rather than a
 * user-supplied dpaa2_io_store. Furthermore, those dequeue results will
 * "complete" using a caller-provided callback (from DQRR processing) rather
 * than the caller explicitly looking at their dpaa2_io_store for results. Eg.
 * the alternative form will likely take a callback parameter rather than a
 * store parameter. Ignoring it for now to keep the picture clearer.
 *
 * Return 0 for success, or error code for failure.
 */
int dpaa2_io_service_pull_channel(struct dpaa2_io *d, u32 channelid,
				  struct dpaa2_io_store *s)
{
	struct qbman_pull_desc pd;
	int err;

	qbman_pull_desc_clear(&pd);
	qbman_pull_desc_set_storage(&pd, s->vaddr, s->paddr, 1);
	qbman_pull_desc_set_numframes(&pd, (u8)s->max);
	qbman_pull_desc_set_channel(&pd, channelid, qbman_pull_type_prio);
	d = service_select(d);
	if (!d)
		return -ENODEV;
	s->swp = d->swp;
	err = qbman_swp_pull(d->swp, &pd);
	if (err)
		s->swp = NULL;
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_pull_channel);

/**
 * dpaa2_io_service_enqueue_fq() - Enqueue a frame to a frame queue.
 * @d: the given DPIO service.
 * @fqid: the given frame queue id.
 * @fd: the frame descriptor which is enqueued.
 *
 * This definition bypasses some features that are not expected to be priority-1
 * features, and may not be needed at all via current assumptions (QBMan's
 * feature set is wider than the MC object model is intendeding to support,
 * initially at least). Plus, keeping them out (for now) keeps the API view
 * simpler. Missing features are;
 *  - enqueue confirmation (results DMA'd back to the user)
 *  - ORP
 *  - DCA/order-preservation (see note in "pull dequeues")
 *  - enqueue consumption interrupts
 *
 * Return 0 for successful enqueue, or -EBUSY if the enqueue ring is not ready,
 * or -ENODEV if there is no dpio service.
 */
int dpaa2_io_service_enqueue_fq(struct dpaa2_io *d,
				u32 fqid,
				const struct dpaa2_fd *fd)
{
	struct qbman_eq_desc ed;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	qbman_eq_desc_clear(&ed);
	qbman_eq_desc_set_no_orp(&ed, 0);
	qbman_eq_desc_set_fq(&ed, fqid);
	return qbman_swp_enqueue(d->swp, &ed, fd);
}
EXPORT_SYMBOL(dpaa2_io_service_enqueue_fq);

/**
 * dpaa2_io_service_enqueue_qd() - Enqueue a frame to a QD.
 * @d: the given DPIO service.
 * @qdid: the given queuing destination id.
 * @prio: the given queuing priority.
 * @qdbin: the given queuing destination bin.
 * @fd: the frame descriptor which is enqueued.
 *
 * This definition bypasses some features that are not expected to be priority-1
 * features, and may not be needed at all via current assumptions (QBMan's
 * feature set is wider than the MC object model is intendeding to support,
 * initially at least). Plus, keeping them out (for now) keeps the API view
 * simpler. Missing features are;
 *  - enqueue confirmation (results DMA'd back to the user)
 *  - ORP
 *  - DCA/order-preservation (see note in "pull dequeues")
 *  - enqueue consumption interrupts
 *
 * Return 0 for successful enqueue, or -EBUSY if the enqueue ring is not ready,
 * or -ENODEV if there is no dpio service.
 */
int dpaa2_io_service_enqueue_qd(struct dpaa2_io *d,
				u32 qdid, u8 prio, u16 qdbin,
				const struct dpaa2_fd *fd)
{
	struct qbman_eq_desc ed;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	qbman_eq_desc_clear(&ed);
	qbman_eq_desc_set_no_orp(&ed, 0);
	qbman_eq_desc_set_qd(&ed, qdid, qdbin, prio);
	return qbman_swp_enqueue(d->swp, &ed, fd);
}
EXPORT_SYMBOL(dpaa2_io_service_enqueue_qd);

/**
 * dpaa2_io_service_release() - Release buffers to a buffer pool.
 * @d: the given DPIO object.
 * @bpid: the buffer pool id.
 * @buffers: the buffers to be released.
 * @num_buffers: the number of the buffers to be released.
 *
 * Return 0 for success, and negative error code for failure.
 */
int dpaa2_io_service_release(struct dpaa2_io *d,
			     u32 bpid,
			     const u64 *buffers,
			     unsigned int num_buffers)
{
	struct qbman_release_desc rd;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	qbman_release_desc_clear(&rd);
	qbman_release_desc_set_bpid(&rd, bpid);
	return qbman_swp_release(d->swp, &rd, buffers, num_buffers);
}
EXPORT_SYMBOL(dpaa2_io_service_release);

/**
 * dpaa2_io_service_acquire() - Acquire buffers from a buffer pool.
 * @d: the given DPIO object.
 * @bpid: the buffer pool id.
 * @buffers: the buffer addresses for acquired buffers.
 * @num_buffers: the expected number of the buffers to acquire.
 *
 * Return a negative error code if the command failed, otherwise it returns
 * the number of buffers acquired, which may be less than the number requested.
 * Eg. if the buffer pool is empty, this will return zero.
 */
int dpaa2_io_service_acquire(struct dpaa2_io *d,
			     u32 bpid,
			     u64 *buffers,
			     unsigned int num_buffers)
{
	unsigned long irqflags;
	int err;

	d = service_select(d);
	if (!d)
		return -ENODEV;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	err = qbman_swp_acquire(d->swp, bpid, buffers, num_buffers);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	return err;
}
EXPORT_SYMBOL(dpaa2_io_service_acquire);

/**
 * dpaa2_io_store_create() - Create the dma memory storage for dequeue
 * result.
 * @max_frames: the maximum number of dequeued result for frames, must be <= 16.
 * @dev: the device to allow mapping/unmapping the DMAable region.
 *
 * Constructor - max_frames must be <= 16. The user provides the
 * device struct to allow mapping/unmapping of the DMAable region. Area for
 * storage will be allocated during create. The size of this storage is
 * "max_frames*sizeof(struct dpaa2_dq)". The 'dpaa2_io_store' returned is a
 * wrapper structure allocated within the DPIO code, which owns and manages
 * allocated store.
 *
 * Return dpaa2_io_store struct for successfuly created storage memory, or NULL
 * if not getting the stroage for dequeue result in create API.
 */
struct dpaa2_io_store *dpaa2_io_store_create(unsigned int max_frames,
					     struct device *dev)
{
	struct dpaa2_io_store *ret;
	size_t size;

	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return NULL;
	ret->max = max_frames;
	size = max_frames * sizeof(struct dpaa2_dq);

	ret->vaddr = vfio_setup_dma(size);
	ret->paddr = ret->vaddr;

	ret->idx = 0;
	ret->dev = dev;
	return ret;
}
EXPORT_SYMBOL(dpaa2_io_store_create);

/**
 * dpaa2_io_store_destroy() - Destroy the dma memory storage for dequeue
 * result.
 * @s: the storage memory to be destroyed.
 *
 * Frees to specified storage memory.
 */
void dpaa2_io_store_destroy(struct dpaa2_io_store *s)
{
//	No way to destroy vfio_setup_dma?
//	dma_unmap_single(s->dev, s->paddr, sizeof(struct dpaa2_dq) * s->max,
//			 DMA_FROM_DEVICE);
//	kfree(s->alloced_addr);
//	kfree(s);
}
EXPORT_SYMBOL(dpaa2_io_store_destroy);

/**
 * dpaa2_io_store_next() - Determine when the next dequeue result is available.
 * @s: the dpaa2_io_store object.
 * @is_last: indicate whether this is the last frame in the pull command.
 *
 * Once dpaa2_io_store has been passed to a function that performs dequeues to
 * it, like dpaa2_ni_rx(), this function can be used to determine when the next
 * frame result is available. Once this function returns non-NULL, a subsequent
 * call to it will try to find the *next* dequeue result.
 *
 * Note that if a pull-dequeue has a null result because the target FQ/channel
 * was empty, then this function will return NULL rather than expect the caller
 * to always check for this on his own side. As such, "is_last" can be used to
 * differentiate between "end-of-empty-dequeue" and "still-waiting".
 *
 * Return dequeue result for a valid dequeue result, or NULL for empty dequeue.
 */
struct dpaa2_dq *dpaa2_io_store_next(struct dpaa2_io_store *s, int *is_last)
{
	int match;
	struct dpaa2_dq *ret = &s->vaddr[s->idx];

	match = qbman_result_has_new_result(s->swp, ret);
	if (!match) {
		*is_last = 0;
		return NULL;
	}
	s->idx++;
	if (dpaa2_dq_is_pull_complete(ret)) {
		*is_last = 1;
		s->idx = 0;
		/*
		 * If we get an empty dequeue result to terminate a zero-results
		 * vdqcr, return NULL to the caller rather than expecting him to
		 * check non-NULL results every time.
		 */
		if (!(qbman_result_DQ_flags(ret) & DPAA2_DQ_STAT_VALIDFRAME))
			ret = NULL;
	} else {
		*is_last = 0;
	}
	return ret;
}
EXPORT_SYMBOL(dpaa2_io_store_next);

int dpaa2_io_query_fq_count(struct dpaa2_io *d, u32 fqid, u32 *fcnt, u32 *bcnt)
{
	struct qbman_attr state;
	struct qbman_swp *swp;
	unsigned long irqflags;
	int ret;

	d = service_select(d);
	if (!d)
		return -ENODEV;

	swp = d->swp;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	ret = qbman_fq_query_state(swp, fqid, &state);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	if (ret)
		return ret;
        *fcnt = qbman_fq_state_frame_count(&state);
        *bcnt = qbman_fq_state_byte_count(&state);

	return 0;
}
EXPORT_SYMBOL(dpaa2_io_query_fq_count);

int dpaa2_io_query_bp_count(struct dpaa2_io *d, u32 bpid, u32 *num)
{
	struct qbman_attr state;
	struct qbman_swp *swp;
	unsigned long irqflags;
	int ret;

	d = service_select(d);
	if (!d)
		return -ENODEV;

	swp = d->swp;
	pthread_mutex_lock(&d->lock_mgmt_cmd);
	ret = qbman_bp_query(swp, bpid, &state);
	pthread_mutex_unlock(&d->lock_mgmt_cmd);
	if (ret)
		return ret;
	*num = qbman_bp_info_num_free_bufs(&state);

	return 0;
}
EXPORT_SYMBOL(dpaa2_io_query_bp_count);

