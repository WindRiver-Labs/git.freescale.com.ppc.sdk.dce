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


#ifndef __BASIC_DCE_H
#define __BASIC_DCE_H

#include "dce.h"

/* this allocator is currently a place holder for a more efficient allocator
 * that will eliminate the need for copying input data to a kmalloc buf */
void *dce_alloc(size_t sz);
#define dce_free(x)

/**
 * dce_process_data() - Compress or decompress arbitrary data asynchronously
 * @session:	Pointer to a session struct on which to send (de)compress
 *		requests
 * @input:	DMA address to input data, can be NULL if final input was
 *		passed in the previous process calls
 * @output:	DMA address to output buffer, must not be NULL
 * @input_len:	Size of the data for input
 * @output_len:	Size of the output buffer available
 * @output_produced: Pointer to size_t in which the number of bytes produced by
 *		DCE is to be returned
 *
 * Return:	0 on success, dce -error code otherwise
 *
 */
int bdce_process_data(enum dce_engine dce_mode,
		dma_addr_t input,
		dma_addr_t output,
		size_t input_len,
		size_t output_len,
		size_t *output_produced);


#endif /* __BASIC_DCE_H */
