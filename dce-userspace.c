/* Copyright (c) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
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

static int setup_dce(void)
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

	atomic_inc(&users);
	if (atomic_read(&users) > 1)
		return 0; /* No need to do anything, someone else did setup */

	ret = dce_session_create(&comp_session, &params);
	if (ret) {
		atomic_dec(&users);
		return -EACCES;
	}

	params.engine = DCE_DECOMPRESSION;
	ret = dce_session_create(&decomp_session, &params);
	if (ret) {
		dce_session_destroy(&comp_session);
		atomic_dec(&users);
		return -EACCES;
	}
	return 0;
}

static int cleanup_dce(void)
{
	int ret;

	ret = dce_session_destroy(&comp_session);
	if (ret)
		pr_err("Failed to close DCE compress session. ret = %d", ret);
	ret = dce_session_destroy(&decomp_session);
	if (ret)
		pr_err("Failed to close DCE decompress session. ret = %d", ret);
	return 0;
}



#define wait_event(x, c) \
do { \
	sem_wait(x); \
	assert(c); \
} while(0)

int bdce_process_data(enum dce_engine dce_mode,
		dma_addr_t input,
		dma_addr_t output,
		size_t input_len,
		size_t output_len,
		size_t *output_produced)
{
	struct work_unit work_unit;
	struct dce_session *session;
	int ret = -ENOMEM, busy_count = 0;
	unsigned long timeout;

	if (dce < 0) {
		/* no one initialized the dce yet. Attempt initialize */
		ret = setup_dce();
		if (ret < 0) {
			/* maybe a different pthread already opened it. Take a
			 * pause and check again */
			/* ret = pthread_yield(); */
			printf("attempt to open dce returned errno code %d\n",
					ret);
			if (dce < 0)
				/* no one was able to open the dce */
				return -ret;
		} else {
			dce = ret;
		}
	}

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
#if 0
	timeout = wait_event_timeout(work_unit.reply_wait, work_unit.done,
				msecs_to_jiffies(3500));
	if (!timeout) {
		pr_err("Error, didn't get expected callback\n");
		goto err_timedout;
	}
#endif
	if (work_unit.status == OUTPUT_BLOCKED_DISCARD) {
		pr_err("The output buffer supplied was too small\n");
		ret = work_unit.status;
		goto err_timedout;
	} else if (work_unit.status != STREAM_END) {
		pr_err("Unexpected DCE status 0x%x\n", work_unit.status);
		ret = work_unit.status;
		goto err_timedout;
	}

err_timedout:
	*output_produced = work_unit.output_produced;
err_enqueue:
	return ret;
}
