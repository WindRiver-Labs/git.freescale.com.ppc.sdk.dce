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

#include <linux/kernel.h>
#include <semaphore.h>
#include <compat.h>
#include "dce.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include <vfio_utils.h>
#include <allocator.h>
#include "basic_dce.h"

struct dma_item {
	void *vaddr;
	struct dpaa2_fd fd;
	size_t size;
};

struct dce_ioctl_process {
	enum dce_engine dce_mode;
	dma_addr_t input;
	dma_addr_t output;
	size_t input_len;
	size_t output_len;
};

struct work_unit {
	uint8_t status;
	size_t output_produced;
	volatile int done;
	struct dce_session *session;
	dma_addr_t input;
	dma_addr_t output;
	size_t input_consumed;
	sem_t reply_wait;
};

static struct dce_session comp_session;
static struct dce_session decomp_session;

/* Track number of users of this driver and do not delete info prematurely */
static atomic_t users;

static volatile int dce = -1;

#define wake_up(x) sem_post(x)

static void dce_callback(struct dce_session *session,
			uint8_t status,
			dma_addr_t input,
			dma_addr_t output,
			size_t input_consumed,
			size_t output_produced,
			void *context)
{
	struct work_unit *work_unit = context;

	work_unit->input = input;
	work_unit->output = output;
	work_unit->input_consumed = input_consumed;
	work_unit->session = session;
	work_unit->status = status;
	work_unit->output_produced = output_produced;
	work_unit->done = true;
	wake_up(&work_unit->reply_wait);
}

static struct dma_mem *dce_mem;
int exit_vfio_fd;
int exit_vfio_group_fd;

static void cleanup_dce(void)
{
	int ret;

	/* We have to cleanup, but can only do cleanup once because resources
	 * are shared between threads */
	if (!atomic_dec_and_test(&users))
		return;

	ret = dce_session_destroy(&exit_vfio_fd, &comp_session);
	if (ret)
		pr_err("Failed to close DCE compress session. ret = %d", ret);
	ret = dce_session_destroy(&exit_vfio_fd, &decomp_session);
	if (ret)
		pr_err("Failed to close DCE decompress session. ret = %d", ret);

	vfio_cleanup_dma(exit_vfio_fd, dce_mem->addr, dce_mem->sz);
	free(dce_mem);

	dpdcei_drv_cleanup(exit_vfio_fd, exit_vfio_group_fd);
}

static int setup_dce(int *vfio_fd, int *vfio_group_fd)
{
	struct dce_session_params params = {
		.engine = DCE_COMPRESSION,
		.paradigm = DCE_SESSION_STATELESS,
		.compression_format = DCE_SESSION_CF_ZLIB,
		.compression_effort = DCE_SESSION_CE_BEST_POSSIBLE,
		/* gz_header not used in ZLIB format mode */
		/* buffer_pool_id not used */
		/* buffer_pool_id2 not used */
		/* release_buffers not used */
		/* encode_base_64 not used */
		/* callback_frame not used, will use callback_data instead */
		.callback_data = dce_callback
	};
	int ret;

	if (atomic_read(&users) > 0)
		return 0; /* No need to do anything, someone else did setup */

	ret = dce_session_create(vfio_fd, vfio_group_fd, &comp_session, &params);
	if (ret)
		return ret;

	params.engine = DCE_DECOMPRESSION;
	ret = dce_session_create(vfio_fd, vfio_group_fd, &decomp_session, &params);
	if (ret)
		goto err_decomp_session_create;

	dce_mem = malloc(sizeof(*dce_mem));
	if (!dce_mem) {
		ret = -ENOMEM;
		goto err_dce_mem_alloc;
	}
	dce_mem->addr = vfio_setup_dma(*vfio_fd, DCE_VFIO_CACHE_SZ);
	if (!dce_mem->addr) {
		ret = -ENOMEM;
		goto err_dce_mem_dma;
	}
	dce_mem->sz = DCE_VFIO_CACHE_SZ;
	dma_mem_allocator_init(dce_mem);

	exit_vfio_fd = *vfio_fd;
	exit_vfio_group_fd = *vfio_group_fd;
	ret = atexit(cleanup_dce);
	if (ret)
		goto err_dce_cleanup;

	atomic_inc(&users);

	return 0;

err_dce_cleanup:
	vfio_cleanup_dma(*vfio_fd, dce_mem->addr, dce_mem->sz);
err_dce_mem_dma:
	free(dce_mem);
err_dce_mem_alloc:
	dce_session_destroy(vfio_fd, &decomp_session);
err_decomp_session_create:
	dce_session_destroy(vfio_fd, &comp_session);
	return ret;
}

#define wait_event(x, c) \
do { \
	sem_wait(x); \
	assert(c); \
} while (0)

int basic_dce_process_data(enum dce_engine dce_mode,
		dma_addr_t input,
		dma_addr_t output,
		size_t input_len,
		size_t output_len,
		size_t *output_produced)
{
	struct work_unit work_unit;
	struct dce_session *session;
	int ret = -ENOMEM, busy_count = 0;

	session = dce_mode == DCE_COMPRESSION ?
			&comp_session : &decomp_session;

try_again:
	work_unit.done = false;
	sem_init(&work_unit.reply_wait, 0, 0);
	ret = dce_process_data(session,
		     input,
		     output,
		     input_len,
		     output_len,
		     DCE_Z_FINISH,
		     1, /* Initial */
		     0, /* Recycle */
		     &work_unit);
	if (ret == -EBUSY && busy_count++ < 10)
		goto try_again;
	if (ret) {
		pr_err("dce_process_data() return error code %d\n", ret);
		goto err_enqueue;
	}

	wait_event(&work_unit.reply_wait, work_unit.done); /* wait callback */
	if (work_unit.status == OUTPUT_BLOCKED_DISCARD) {
		pr_err("The output buffer supplied was too small\n");
		ret = work_unit.status;
		goto err_timedout;
	} else if (work_unit.status == INPUT_STARVED) {
		/* The user should only send in a complete DEFLATE stream for
		 * decompression. A complete stream is all output produced from
		 * the first deflate() call to the final deflate(Z_FINISH) call
		 * that returns STREAM_END status. If basic_dce_process_data is
		 * used in the compression stage, then every call to
		 * basic_dce_process_data() creates a complete DEFLATE stream */
		pr_err("Attempted to decompress a fraction of a DEFLATE stream\n");
		ret = work_unit.status;
	} else if (work_unit.status != STREAM_END) {
		pr_err("Unexpected DCE status %s 0x%x\n",
				dce_status_string(work_unit.status),
				work_unit.status);
		ret = work_unit.status;
		goto err_timedout;
	}

err_timedout:
	*output_produced = work_unit.output_produced;
err_enqueue:
	return ret;
}

dma_addr_t dce_alloc(int *vfio_fd, int *vfio_group_fd, size_t sz)
{
	int ret;

	if (dce < 0) {
		/* no one initialized the dce yet. Attempt initialize */
		ret = setup_dce(vfio_fd, vfio_group_fd);
		if (ret < 0) {
			/* maybe a different pthread already opened it. Take a
			 * pause and check again */
			/* ret = pthread_yield(); */
			printf("attempt to open dce returned error code %d\n",
					ret);
			if (dce < 0)
				/* no one was able to open the dce */
				return (dma_addr_t)NULL;
		} else {
			dce = ret;
		}
	}

	return (dma_addr_t)dma_mem_memalign(dce_mem, 0 /* no align */, sz);
}

void dce_free(dma_addr_t p)
{
	dma_mem_free(dce_mem, (void *)p);
}
