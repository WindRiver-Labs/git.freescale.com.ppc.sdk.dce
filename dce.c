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

#include "dce-scf-compression.h"
#include "dce-scf-decompression.h"
#include "dce.h"
/* #define debug */

MODULE_AUTHOR("Freescale Semicondictor, Inc");
MODULE_DESCRIPTION("DCE API");
MODULE_LICENSE("Dual BSD/GPL");

/* dma memories that need to be allocated
 *	memory		size			alignment_req
 *
 *	pending_out_ptr	comp: 8202B		none (64B optimal)
 *	pending_out_ptr	decomp: 28k (1024 * 28)	none (64B optimal)
 *	history_ptr	comp: 4096		64B
 *	history_ptr	decomp: 32768		64B
 *	decomp_ctx_ptr	decomp only 256B	none
 *	extra_ptr	extra_limit defines the length for decompression.
 *			no alignment requirements.
 */


/* an internal structure that contains information per DCE interaction, this
 * structure is necessary because if the API is used asynchronously the response
 * comes back on the same frame that was sent. If the same frame struct is used
 * for different transactions with DCE then there is a chance that the second
 * response will overwrite the information written by the first */
struct work_unit {
	union store {
		/* faster if aligned */
		struct dpaa2_fd fd_list_store[3] __aligned(64);
		struct {
			struct dpaa2_fd output_fd;
			struct dpaa2_fd input_fd;
			struct dpaa2_fd scf_fd;
			void *context;
		};
	} store;
	struct scf_c_cfg scf_result __aligned(64); /* must 64 byte align */
	struct dpaa2_fd fd_list;
};

/* trigger_user_callback - takes the information from the callbacks and
 * `massages' the data into user friendly format */
/* TODO: make sure to mention that fd must be completely clean*/
static void trigger_user_callback(struct dce_session *session,
				  struct dpaa2_fd const *fd)
{
	union store *store = (void *)dpaa2_fd_get_addr(fd);
	struct work_unit *work_unit =
		container_of(store, struct work_unit, store);
	uint8_t status = fd_frc_get_status((struct fd_attr *)fd);
	size_t input_consumed;

#ifdef debug
	pr_info("dce: callback work_unit %p", work_unit);
	pretty_print_fd((struct fd_attr *)fd);
	pretty_print_fle_n((struct fle_attr *)store->fd_list_store, 3);
#endif
	switch (status) {
	case OUTPUT_BLOCKED_SUSPEND:
	case ACQUIRE_DATA_BUFFER_DENIED_SUSPEND:
	case ACQUIRE_TABLE_BUFFER_DENIED_SUSPEND:
	case MEMBER_END_SUSPEND:
	case Z_BLOCK_SUSPEND:
	case OLL_REACHED_DISCARD:
		input_consumed = scf_c_result_get_bytes_processed(
				(struct scf_c_result *)
				&work_unit->scf_result);
		break;
	case FULLY_PROCESSED:
	case STREAM_END:
		input_consumed = dpaa2_fd_get_len(&store->input_fd);
		break;
	default:
		/* some other unexpected type of suspend, no input
		 * processed */
		input_consumed = 0;
	}
	if (session->callback_frame) {
		session->callback_frame(session, status, &store->input_fd,
					&store->output_fd, input_consumed,
					store->context);
	} else {
		size_t output_produced = dpaa2_fd_get_len(&store->output_fd);
		dma_addr_t output = dpaa2_fd_get_addr(&store->output_fd);
		dma_addr_t input = dpaa2_fd_get_addr(&store->input_fd);

		session->callback_data(session, status, input, output,
				       input_consumed, output_produced,
				       store->context);
	}
	dma_mem_free(&session->flow.mem, container_of(store, struct work_unit,
								store));
}

/* internal_callback - this is the callback that gets triggered by the DCE flow.
 *
 * This simple callback does simple checking the calls a function to trigger the
 * user callback if all checks were passed */
static void internal_callback(struct dce_flow *flow, u32 cmd,
			    const struct dpaa2_fd *fd)
{
	struct dce_session *session = container_of(flow,
						   struct dce_session,
						   flow);
	switch ((enum dce_cmd)cmd) {
	case DCE_CMD_NOP:
		pr_info("Received unexpected NOP response in DCE API\n");
		assert(false); /* it is unexpected that the DCE API will send
				* a NOP command, so we should never be here */
		break;
	case DCE_CMD_CTX_INVALIDATE:
		pr_info("Received unexpected context invalidate in DCE API\n");
		assert(false); /* we should never be here */
		break;
	case DCE_CMD_PROCESS:
#ifdef debug
		pr_info("Received callback for DCE process command\n");
#endif
		trigger_user_callback(session, fd);
		break;
	default:
		pr_info("Unknown cmd %d\n", cmd);
		break;
	}
}

#define COMP_PENDING_OUTPUT_SZ 8202
#define DECOMP_PENDING_OUTPUT_SZ (24 * 1024)
#define PENDING_OUTPUT_ALIGN 64
#define COMP_HISTORY_SZ (4 * 1024)
#define DECOMP_HISTORY_SZ (32 * 1024)
#define HISTORY_ALIGN 64
#define DECOMP_CONTEXT_SZ 256
#define DECOMP_CONTEXT_ALIGN 64

static void free_dce_internals(struct dce_session *session)
{
	struct dma_mem *mem = &session->flow.mem;

	if (session->pending_output.vaddr)
		dma_mem_free(mem, session->pending_output.vaddr);
	if (session->history.vaddr)
		dma_mem_free(mem, session->history.vaddr);
	if (session->decomp_context.vaddr)
		dma_mem_free(mem, session->decomp_context.vaddr);

	session->pending_output.vaddr = session->history.vaddr =
		session->decomp_context.vaddr = NULL;
	session->pending_output.paddr = session->history.paddr =
		session->decomp_context.paddr = 0;
	session->pending_output.len = session->history.len =
		session->decomp_context.len = 0;
}

static int alloc_dce_internals(struct dce_session *session)
{
	struct dma_mem *mem = &session->flow.mem;

	if (session->engine == DCE_COMPRESSION) {
		session->pending_output.len = COMP_PENDING_OUTPUT_SZ;
		session->pending_output.vaddr = dma_mem_memalign(mem,
			PENDING_OUTPUT_ALIGN, session->pending_output.len);
		session->history.len = COMP_HISTORY_SZ;
		session->history.vaddr = dma_mem_memalign(mem,
			 HISTORY_ALIGN, session->history.len);
	} else if (session->engine == DCE_DECOMPRESSION) {
		session->pending_output.len = DECOMP_PENDING_OUTPUT_SZ;
		session->pending_output.vaddr = dma_mem_memalign(mem,
				PENDING_OUTPUT_ALIGN,
				session->pending_output.len);
		session->history.len = DECOMP_HISTORY_SZ;
		session->history.vaddr = dma_mem_memalign(mem,
			HISTORY_ALIGN, session->history.len);
		session->decomp_context.len = DECOMP_CONTEXT_SZ;
		session->decomp_context.vaddr = dma_mem_memalign(mem,
			DECOMP_CONTEXT_ALIGN, session->decomp_context.len);
	}
	if (!session->pending_output.vaddr || !session->history.vaddr ||
			(!session->decomp_context.vaddr &&
			 (session->engine == DCE_DECOMPRESSION))) {
		free_dce_internals(session);
		return -ENOMEM;
	}
	memset(session->pending_output.vaddr, 0, session->pending_output.len);
	memset(session->history.vaddr, 0, session->history.len);
	if (session->decomp_context.vaddr)
		memset(session->decomp_context.vaddr, 0,
				session->decomp_context.len);
	return 0;
}

int dce_session_create(int *vfio_fd, int *vfio_group_fd, struct dce_session *session,
		       struct dce_session_params *params)
{
	struct dpdcei_priv *device;
	/* We do not create the session struct here to allow our user to nest
	 * the session struct in their own structures and recover the container
	 * of the session using container_of() */

	int ret;

	/* We must make clear the session struct here. The session has many
	 * pointers, other functions will assume they are valid if they are not
	 * cleared and attempt to use them */
	*session = (struct dce_session){0};

	/* get (de)compression device */
	if (params->engine == DCE_COMPRESSION)
		device = get_compression_device(vfio_fd, vfio_group_fd);
	else if (params->engine == DCE_DECOMPRESSION)
		device = get_decompression_device(vfio_fd, vfio_group_fd);
	else
		return -EINVAL;

	if (!device)
		return -EBUSY;

	ret = dce_flow_create(*vfio_fd, device, &session->flow);
	if (ret)
		return -EBUSY;
	/* No need to configure the flow context record, because the first frame
	 * will carry an SCR with the correct configuration and DCE will update
	 * the FCR to match */

	ret = alloc_dce_internals(session);
	if (ret)
		goto fail_dce_internals;

	/* FIXME: Must handle gz_header if it is present here */
	session->flow.cb = internal_callback;
	session->engine = params->engine;
	session->paradigm = params->paradigm;
	session->compression_format = params->compression_format;
	session->compression_effort = params->compression_effort;
	session->buffer_pool_id = params->buffer_pool_id;
	session->buffer_pool_id2 = params->buffer_pool_id2;
	session->release_buffers = params->release_buffers;
	session->encode_base_64 = params->encode_base_64;
	session->callback_frame = params->callback_frame;
	session->callback_data = params->callback_data;

	/* Handle gzip header */
	if (session->compression_format == DCE_SESSION_CF_GZIP) {
		if (params->gz_header)
			session->gz_header = params->gz_header;
	}
	return 0;

fail_dce_internals:
	dce_flow_destroy(*vfio_fd, &session->flow);
	return ret;
}
EXPORT_SYMBOL(dce_session_create);

int dce_session_destroy(int *vfio_fd, struct dce_session *session)
{
	/* Attempt to destroy the session while frames in flight */
	if (atomic_read(&session->flow.frames_in_flight))
		return -EACCES;
	free_dce_internals(session);
	dce_flow_destroy(*vfio_fd, &session->flow);
	return 0;
}
EXPORT_SYMBOL(dce_session_destroy);

int dce_process_frame(struct dce_session *session,
		      struct dpaa2_fd *input_fd,
		      struct dpaa2_fd *output_fd,
		      enum dce_flush_parameter flush,
		      bool initial_frame,
		      bool recycled_frame,
		      void *context)
{
	struct dce_flow *flow = &session->flow;
	struct work_unit *work_unit = dma_mem_memalign(&session->flow.mem, 64,
						sizeof(struct work_unit));
	struct dpaa2_fd *fd_list;
	struct dpaa2_fd *scf_fd;
	int ret;

#ifdef debug
	pr_info("dce: work_unit %p\n", work_unit);
#endif

	/* if BMan support is enabled and this is the first frame then we need
	 * to do some setup of the SCF. Currently BMan does not function */
	/* dma_condition(session, work_unit); */

	/* Must copy the frames over. No way around it because the frames have
	 * to be stored in a contiguous frame list */
	work_unit->store.input_fd = *input_fd;
	work_unit->store.output_fd = *output_fd;

	/* reorient the pointers in my stack to point to the copy for
	 * convenience in later usage */
	input_fd = &work_unit->store.input_fd;
	output_fd = &work_unit->store.output_fd;

	/* do the same for our scf_fd and the fd_list */
	fd_list = &work_unit->fd_list;
	scf_fd = &work_unit->store.scf_fd;

	/* we only need to do setup work for the SCF because the input and
	 * output were passed in with correct setup by our caller */

	/* SCF */
	dpaa2_sg_set_final((struct dpaa2_sg_entry *)scf_fd, 1);
	dpaa2_fd_set_addr(scf_fd, (dma_addr_t) &work_unit->scf_result);
	dpaa2_fd_set_len(scf_fd, sizeof(struct scf_c_cfg));
	/* Set to recycle or truncate mode, don't need to do this every time for
	 * statefull sessions. dont need to do it at all for stateless sessions.
	 * Doing it every time for now. pmode 1 = truncate, 0 = recycle */
	if (session->paradigm == DCE_SESSION_STATEFUL_RECYCLE)
		scf_c_cfg_set_pmode((struct scf_c_cfg *)&work_unit->scf_result,
				false);
	else
		scf_c_cfg_set_pmode((struct scf_c_cfg *)&work_unit->scf_result,
				true);

	/* FD */
	dpaa2_fd_set_len(fd_list, dpaa2_fd_get_len(input_fd));
	dpaa2_fd_set_format(fd_list, dpaa2_fd_list);
	dpaa2_fd_set_addr(fd_list, (dma_addr_t)work_unit->store.fd_list_store);
	fd_frc_set_ce((struct fd_attr *)fd_list, session->compression_effort);
	/* hardware bug requires the SCR flush to occur every time */
	fd_frc_set_scrf((struct fd_attr *)fd_list, true);
	fd_frc_set_sf((struct fd_attr *)fd_list, !!session->paradigm);
	fd_frc_set_cf((struct fd_attr *)fd_list, (enum dce_comp_fmt)
			session->compression_format);
	fd_frc_set_recycle((struct fd_attr *)fd_list, recycled_frame);
	fd_frc_set_initial((struct fd_attr *)fd_list, initial_frame);
	fd_frc_set_z_flush((struct fd_attr *)fd_list, flush);
	if (initial_frame) {
		/* FIXME: CM and FLG should be setup differently for GZIP */
		u8 CM, FLG;

		fd_frc_set_uspc((struct fd_attr *)fd_list, true);
		fd_frc_set_uhc((struct fd_attr *)fd_list, true);

		CM = 0x48; /* 8 means Deflate and 4 means a 4 KB compression
			      window these are the only values allowed in DCE */

		FLG = 0x4B; /* 0b_01_0_01011, 01 is the approximate compression
			       effort, the 0 after indicates no dictionary, the
			       01011 is the checksum for CM and FLG and must
			       make CM_FLG a 16 bit number divisible by 31 */
		scf_c_cfg_set_cm((struct scf_c_cfg *)&work_unit->scf_result,
									    CM);
		scf_c_cfg_set_flg((struct scf_c_cfg *)&work_unit->scf_result,
				FLG);
		scf_c_cfg_set_next_flc(
			(struct scf_c_cfg *)&work_unit->scf_result,
			(uint64_t)flow);
		if (session->engine == DCE_COMPRESSION) {
			scf_c_cfg_set_pending_output_ptr(
				(struct scf_c_cfg *)&work_unit->scf_result,
				(dma_addr_t)session->pending_output.vaddr);
			scf_c_cfg_set_history_ptr(
				(struct scf_c_cfg *)&work_unit->scf_result,
				(dma_addr_t)session->history.vaddr);
		} else if (session->engine == DCE_DECOMPRESSION) {
			scf_d_cfg_set_pending_output_ptr(
				(struct scf_d_cfg *)&work_unit->scf_result,
				(dma_addr_t)session->pending_output.vaddr);
			scf_d_cfg_set_history_ptr(
				(struct scf_d_cfg *)&work_unit->scf_result,
				(dma_addr_t)session->history.vaddr);
			scf_d_cfg_set_decomp_ctx_ptr(
				(struct scf_d_cfg *)&work_unit->scf_result,
				(dma_addr_t)session->decomp_context.vaddr);
		} else {
			ret = -EINVAL;
			goto fail;
		}
	} else {
		fd_frc_set_uspc((struct fd_attr *)fd_list, false);
		fd_frc_set_uhc((struct fd_attr *)fd_list, false);
	}

	/* Set caller context */
	work_unit->store.context = context;

#ifdef debug
	pr_info("dce: Before enqueue\n");
	pretty_print_fd((struct fd_attr *)fd_list);
	pretty_print_fle_n(
		(struct fle_attr *)&work_unit->store.fd_list_store[0], 3);

	hexdump(fd_list, sizeof(*fd_list));
	hexdump(work_unit->store.fd_list_store,
			sizeof(work_unit->store.fd_list_store[0])*3);
#endif

	/* enqueue request */
	ret = enqueue_fd(flow, fd_list);
	if (ret)
		goto fail;

	return 0;

fail:
	return ret;
}
EXPORT_SYMBOL(dce_process_frame);

#define EMPTY_DPAA_FD {.words = {0, 0, 0, 0, 0, 0, 0, 0} }

int dce_process_data(struct dce_session *session,
		     dma_addr_t input,
		     dma_addr_t output,
		     size_t input_len,
		     size_t output_len,
		     enum dce_flush_parameter flush,
		     bool initial_frame,
		     bool recycled_frame,
		     void *context)
{
	struct dpaa2_fd input_fd = EMPTY_DPAA_FD,
		output_fd = EMPTY_DPAA_FD;

	/* Input fd setup */
	dpaa2_fd_set_addr(&input_fd, input);
	dpaa2_fd_set_len(&input_fd, input_len);

	/* Output fd setup */
	dpaa2_fd_set_addr(&output_fd, output);
	dpaa2_fd_set_len(&output_fd, output_len);

	return dce_process_frame(session, &input_fd, &output_fd, flush,
				 initial_frame, recycled_frame, context);
}
EXPORT_SYMBOL(dce_process_data);

