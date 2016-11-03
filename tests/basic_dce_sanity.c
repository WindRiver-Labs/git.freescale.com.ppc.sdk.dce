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

#include <compat.h>
#include "dce-test-data.h"
#include "../basic_dce.h"
#include "private.h"

struct chunk {
	dma_addr_t addr;
	size_t size;
	struct list_head node;
};

struct work_context {
	pthread_t pid;
	struct list_head *chunk_list;
	FILE *out_file;
	enum dce_engine mode;
	size_t total_in;
	size_t total_out;
	int idx;
	int ret;
};

static int bad_parse;

static unsigned long get_ularg(const char *s, const char *pref)
{
	char *endptr;
	unsigned long ularg = strtoul(s, &endptr, 0 /* AUTO_DETECT_BASE */);

	bad_parse = 0;
	if ((endptr == s) || (*endptr != '\0')) {
		pr_err("Invalid %s%s\n", pref, s);
		bad_parse = 1;
	} else if (ularg == ULONG_MAX) {
		pr_err("Out of range %s%s\n", pref, s);
		bad_parse = 1;
	}
	return ularg;
}

static size_t chunk_size = 16 * 1024;

static void sync_all(void);

static void *worker_func(void *__context)
{
	struct work_context *context = __context;
	char thread_name[16];
	size_t output_sz, output_produced;
	dma_addr_t output;
	struct chunk *chunk;
	int vfio_fd, vfio_group_fd;
	int ret;

	snprintf(thread_name, sizeof(thread_name), "%d", context->idx);
	pthread_setname_np(context->pid, thread_name);
	debug(3, "Worker %d at start line\n", context->idx);

	output_sz = context->mode == DCE_COMPRESSION ? chunk_size * 2 :
							chunk_size * 15;
	output = dce_alloc(&vfio_fd, &vfio_group_fd, output_sz);
	if (!output) {
		pr_err("Could not allocate dma memory for output\n");
		pthread_exit(NULL);
	}
	context->total_in = 0;
	context->total_out = 0;

	/* Compression */
	sync_all(); /* Wait at the start line */
	list_for_each_entry(chunk, context->chunk_list, node) {
		ret = basic_dce_process_data(context->mode,
				chunk->addr,
				output,
				chunk->size,
				output_sz,
				&output_produced);
		if (ret) {
			debug(1, "DCE returned error code %d\n", ret);
			context->ret = ret;
			pthread_exit(NULL);
		}
		context->total_in += chunk->size;
		context->total_out += output_produced;
		fwrite((void *)output, output_produced, 1 /* only 1 item to write */,
				context->out_file);

		debug(3, "Compressed %zu bytes into %zu bytes\n",
				chunk->size, output_produced);
	}
	pthread_exit(NULL);
	ASSERT(0); /* Should not be reached */

}

/* Barrier used by tests running across all threads */
static pthread_barrier_t barr;

static void sync_all(void)
{
	pthread_barrier_wait(&barr);
}

static const char STR_help[] = "--help";
static const char STR_in[] = "--in=";
static const char STR_mode[] = "--mode=";
static const char STR_chunk_size[] = "--chunk-size=";
static const char STR_num_threads[] = "--num-threads=";
static const char STR_debug[] = "-d";

static const char STR_usage[] =
"basic_dce_sanity is an internal developer tool. It writes the output of the\n"
"DCE opration to files named <path>_out. <path> is given in --in=<path>\n"
"\n"
"Usage:\n"
"    basic_dce_sanity --in=<path> [options]\n"
"Options:\n"
"    --in=<path>     Path to input file\n"
"    --mode=<mode>   comp or decomp\n"
"    --chunk-size=<size> Chunk size to send to DCE per transaction\n"
"    --num-threads=<num> Number of parallel users of DCE\n"
"    -d [debug_level] debug prints based on level where -d 1 is the lowest\n"
"    --help          see this message\n";

static void usage(void)
{
	pr_info(STR_usage);
}

#define NEXT_ARG() (argv++, --argc)

int main(int argc, char *argv[])
{
	FILE *input_file = NULL;
	char *file_path;
	unsigned int num_chunks = 0;
	unsigned int num_threads = 10;
	enum dce_engine dce_mode = DCE_COMPRESSION;
	LIST_HEAD(chunk_list);
	struct chunk *chunk, *t_chunk;
	uint64_t start, end;
	struct work_context *contexts;
	int ret, i;
	char *endptr;
	int vfio_fd, vfio_group_fd;;

	/* process command line args */
	while (NEXT_ARG()) {
		if (!strncmp(*argv, STR_help, strlen(STR_help))) {
			usage();
			exit(EXIT_SUCCESS);
		} else if (!strncmp(*argv, STR_in, strlen(STR_in))) {
			file_path = &(*argv)[strlen(STR_in)];
			input_file = fopen(file_path, "r");
			if (!input_file) {
				pr_err("Unable to open input file %s\n",
						&(*argv)[strlen(STR_in)]);
				exit(EXIT_FAILURE);
			}
		} else if (!strncmp(*argv, STR_mode, strlen(STR_mode))) {
			if (!strncmp(&(*argv)[strlen(STR_mode)], "comp",
						strlen("comp")))
				dce_mode = DCE_COMPRESSION;
			else if (!strncmp(&(*argv)[strlen(STR_mode)], "decomp",
						strlen("decomp")))
				dce_mode = DCE_DECOMPRESSION;
		} else if (!strncmp(*argv, STR_chunk_size,
					strlen(STR_chunk_size))) {
			chunk_size = get_ularg(&(*argv)[strlen(STR_chunk_size)],
						STR_chunk_size);
		} else if (!strncmp(*argv, STR_num_threads,
					strlen(STR_num_threads))) {
			num_threads =
				get_ularg(&(*argv)[strlen(STR_num_threads)],
						STR_num_threads);
		} else if (!strncmp(*argv, STR_debug, strlen(STR_debug))) {
			if (NEXT_ARG()) {
				dbg_lvl = strtoul(*argv, &endptr,
					0 /*AUTO_DETECT_BASE*/);
				if (dbg_lvl == 0 && endptr == *argv) {
					dbg_lvl = 1;
					argv--; argc++;
				}
			} else {
				/* add 1 to argc to prevent while loop from
				 * getting -1  if this was the last arg */
				argc++;
				dbg_lvl = 1;
			}
		} else {
			pr_err("Unrecognised argument '%s'\n"
				"use --help to see usage \n", *argv);
			exit(EXIT_FAILURE);
		}

		if (bad_parse) {
			pr_err("Bad option argument. Use --help to see usage\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Prepare input data list */
	if (input_file) {
		/* Get input data from sample data file */
		uint8_t *buf;
		size_t bytes_in;

		buf = malloc(chunk_size);
		if (!buf) {
			pr_err("Could not allocate buffer for reading file\n");
			exit(EXIT_FAILURE);
		}
		while ((bytes_in = fread(buf, 1, chunk_size, input_file)) > 0) {
			struct chunk *new_chunk = malloc(sizeof(struct chunk));

			new_chunk->addr = dce_alloc(&vfio_fd, &vfio_group_fd, bytes_in);
			if (!new_chunk->addr) {
				pr_err("Unable to allocate dma memory for DCE\n");
				exit(EXIT_FAILURE);
			}
			memcpy((void *)new_chunk->addr, buf, bytes_in);
			new_chunk->size = bytes_in;
			list_add_tail(&new_chunk->node, &chunk_list);
			num_chunks++;
		}
		free(buf);
		fclose(input_file);
	} else {
		pr_err("This test requires an input file\n");
		exit(EXIT_FAILURE);
	}

	debug(1, "Number of testing threads %u\n", num_threads);
	debug(2, "Initialize barrier for sync_all()\n");
	/* num_threads + main thread all block on thread barrier */
	ret = pthread_barrier_init(&barr, NULL, num_threads + 1);
	if (ret != 0) {
		fprintf(stderr, "Failed to init barrier\n");
		goto fail_multi_thread;
	}

	debug(1, "Create the threads\n");
	contexts = malloc(num_threads * sizeof(struct work_context));
	if (!contexts) {
		ret = -1;
		pr_err("Failed to alloc memory for thread args\n");
		goto fail_contexts_alloc;
	}
	memset(contexts, 0, num_threads * sizeof(struct work_context));
	for (i = 0; i < (signed)num_threads; i++) {
		char thread_file_path[200];

		contexts[i].chunk_list = &chunk_list;
		contexts[i].out_file = NULL;
		contexts[i].mode = dce_mode;
		contexts[i].idx = i;

		/* Prepare output files */
		snprintf(thread_file_path, sizeof(thread_file_path),
				"%s_out_%d", file_path, i);

		contexts[i].out_file = fopen(thread_file_path, "w");
		if(!contexts[i].out_file) {
			pr_err("Failed to create output file %d\n", i);
			goto fail_context_file_open;
		}

		ret = pthread_create(&contexts[i].pid, NULL, worker_func,
				&contexts[i]);
		if (ret) {
			pr_err("pthread_create failed with err code %d\n",
					ret);
			goto fail_create_threads;
		}
	}
	/* Wait for all threads to sleep on starting line */
	usleep(100000);
	debug(1, "Catch their exit\n");
	start = read_cntvct();
	sync_all();
	for (i = 0; i < (signed)num_threads; i++) {
		struct work_context *context = &contexts[i];
		unsigned long timeout = 0;

		ret = pthread_join(context->pid, NULL /* no need retval */);
		if (ret) {
			/* Leak, but warn */
			printf("Failed to join thread %d. %s\n", context->idx,
					strerror(ret));
		}
		/* calculate time based on last thread to finish line */
		end = read_cntvct();
		if (timeout != 0)
			/* Leak, but warn */
			pr_err("Received signal while waiting for worker %d to finish\n",
					context->idx);
		if (context->ret)
			pr_err("Worker %d finished with error status %d\n",
					context->idx, context->ret);
	}
	if (end <= start)
		pr_err("Time corruption detected. end = %lu start = %lu\n",
							end, start);
	free(contexts);
	pr_info("Successfully wrote output files. Test passed\n");

fail_create_threads:
fail_context_file_open:
	for (i = 0; i < (signed)num_threads; i++)
		if (contexts[i].out_file)
			fclose(contexts[i].out_file);
fail_contexts_alloc:
	pthread_barrier_destroy(&barr);
fail_multi_thread:
	list_for_each_entry_safe(chunk, t_chunk, &chunk_list, node) {
		list_del(&chunk->node);
		dce_free(chunk->addr);
		free(chunk);
	}
	return ret;
}
