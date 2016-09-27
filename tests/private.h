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

#include "dce-test-data.h"
#include "../basic_dce.h"

static int dbg_lvl;

#ifndef debug
#define debug(level, fmt, args...) \
({ \
	/* use printf instead of pr_err and pr_info because they do not \
	 * print from threads other than main */ \
	if (level <= dbg_lvl) { \
		printf("Worker %s: ", GET_THREAD_NAME()); \
		printf(fmt, ##args); \
	} \
})
#endif

#define SOFT_ASSERT
#ifdef SOFT_ASSERT
#define ASSERT(condition) \
do { \
	fflush(stdout); \
	fflush(stderr); \
	if (!(condition)) { \
		printf("SCREAM! %s,%s,%s,line=%d, %s\n", #condition, \
			__FILE__, __func__, __LINE__, \
			GET_THREAD_NAME()); \
	} \
	fflush(stderr); \
	fflush(stdout); \
} while(0)
#else /* SOFT_ASSERT */
#define ASSERT(condition) \
do { \
	fflush(stdout); \
	fflush(stderr); \
	assert(condition); \
} while(0)
#endif /* SOFT_ASSERT */

#define GET_THREAD_NAME() \
({ \
	/* 16 bytes including \0 is specified max Linux thread name */ \
	static __thread char __thread_name[16]; \
	int __err; \
	__err = pthread_getname_np(pthread_self(), __thread_name, \
			sizeof(__thread_name)); \
	if (__err) { \
		sprintf(__thread_name, strerror(__err)); \
	} \
	__thread_name; \
})

static inline uint64_t read_cntvct(void)
{
	uint64_t ret;
	uint64_t ret_new, timeout = 200;

	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret));
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	while (ret != ret_new && timeout--) {
		ret = ret_new;
		asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	}
	assert(timeout || ret == ret_new);
	return ret;
}
