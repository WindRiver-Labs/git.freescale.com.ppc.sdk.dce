/* Copyright (C) 2015 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include <stdint.h>
#include "compat.h"
#include "dce-fd-frc.h"
#include "dce-attr-encoder-decoder.h"

/* DCE_CODE (word_offset, lsb_offset, bit_width) */

/* CMD field */
static struct dce_attr_code code_fd_frc_cmd = DCE_CODE(4, 29, 3);

/* NOP */
static struct dce_attr_code code_fd_frc_nop_token = DCE_CODE(4, 0, 29);

/* ICID Scope Flush */
static struct dce_attr_code code_fd_frc_icid_scope_token = DCE_CODE(4, 0, 29);

/* Context Invalidate */
static struct dce_attr_code code_fd_frc_cic_token = DCE_CODE(4, 0, 29);

/* FQID Scope Flush */
static struct dce_attr_code code_fd_frc_fqflush_token = DCE_CODE(4, 0, 29);

/* PROCESS Request */
static struct dce_attr_code code_fd_frc_scus = DCE_CODE(4, 8, 2);
static struct dce_attr_code code_fd_frc_usdc = DCE_CODE(4, 10, 1);
static struct dce_attr_code code_fd_frc_uspc = DCE_CODE(4, 11, 1);
static struct dce_attr_code code_fd_frc_uhc = DCE_CODE(4, 12, 1);
static struct dce_attr_code code_fd_frc_ce = DCE_CODE(4, 13, 2);
static struct dce_attr_code code_fd_frc_cf = DCE_CODE(4, 16, 2);
static struct dce_attr_code code_fd_frc_b64 = DCE_CODE(4, 18, 1);
static struct dce_attr_code code_fd_frc_rb = DCE_CODE(4, 19, 1);
static struct dce_attr_code code_fd_frc_initial = DCE_CODE(4, 20, 1);
static struct dce_attr_code code_fd_frc_recycle = DCE_CODE(4, 21, 1);
static struct dce_attr_code code_fd_frc_scrf = DCE_CODE(4, 22, 1);
static struct dce_attr_code code_fd_frc_z_flush = DCE_CODE(4, 23, 3);
static struct dce_attr_code code_fd_frc_sf = DCE_CODE(4, 28, 1);

/* PROCESS Response */
static struct dce_attr_code code_fd_frc_status = DCE_CODE(4, 0, 8);
static struct dce_attr_code code_fd_frc_stream_end = DCE_CODE(4, 15, 1);

void fd_frc_set_cmd(struct fd_attr *d, enum dce_cmd cmd)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_cmd, cl, cmd);
}

enum dce_cmd fd_frc_get_cmd(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_cmd, cl);
}

void fd_frc_set_nop_token(struct fd_attr *d, uint32_t token)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_nop_token, cl, token);

}

uint32_t fd_frc_get_nop_token(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_nop_token, cl);
}

void fd_frc_set_icid_scope_token(struct fd_attr *d, uint32_t token)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_icid_scope_token, cl, token);
}

uint32_t fd_frc_get_icid_scope_token(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_icid_scope_token, cl);
}

void fd_frc_set_cic_token(struct fd_attr *d, uint32_t token)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_cic_token, cl, token);
}

uint32_t fd_frc_get_cic_token(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_cic_token, cl);
}

void fd_frc_set_fqflush_token(struct fd_attr *d, uint32_t token)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_fqflush_token, cl, token);
}

uint32_t fd_frc_get_fqflush_token(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_fqflush_token, cl);
}


enum dce_status fd_frc_get_status(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_status, cl);
}

void fd_frc_set_scus(struct fd_attr *d, enum dce_scus scus)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_scus, cl, scus);
}

enum dce_scus fd_frc_get_scus(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_scus, cl);
}

void fd_frc_set_usdc(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_usdc, cl, !!enable);
}

int fd_frc_get_usdc(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_usdc, cl);
}

void fd_frc_set_uspc(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_uspc, cl, !!enable);
}

int fd_frc_get_uspc(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_uspc, cl);
}

void fd_frc_set_uhc(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_uhc, cl, !!enable);
}

int fd_frc_get_uhc(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_uhc, cl);
}

void fd_frc_set_ce(struct fd_attr *d, enum dce_comp_effort ce)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_ce, cl, ce);
}

enum dce_comp_effort fd_frc_get_ce(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_ce, cl);
}

void fd_frc_set_cf(struct fd_attr *d, enum dce_comp_fmt cf)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_cf, cl, cf);
}

enum dce_comp_fmt fd_frc_get_cf(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_cf, cl);
}

void fd_frc_set_b64(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_b64, cl, !!enable);
}

int fd_frc_get_b64(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_b64, cl);
}

void fd_frc_set_rb(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_rb, cl, !!enable);
}

int fd_frc_get_rb(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_rb, cl);
}

void fd_frc_set_initial(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_initial, cl, !!enable);
}

int fd_frc_get_initial(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_initial, cl);
}

void fd_frc_set_recycle(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_recycle, cl, !!enable);
}

int fd_frc_get_recycle(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_recycle, cl);
}

void fd_frc_set_scrf(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_scrf, cl, !!enable);
}

int fd_frc_get_scrf(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_scrf, cl);
}

void fd_frc_set_z_flush(struct fd_attr *d, enum dce_z_flush flush)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_z_flush, cl, flush);
}

enum dce_z_flush fd_frc_get_z_flush(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_z_flush, cl);
}

void fd_frc_set_sf(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_sf, cl, !!enable);
}

int fd_frc_get_sf(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_sf, cl);
}

void fd_frc_set_se(struct fd_attr *d, int enable)
{
	uint32_t *cl = dce_cl(d);

	dce_attr_code_encode(&code_fd_frc_stream_end, cl, !!enable);
}

int fd_frc_get_se(struct fd_attr *d)
{
	uint32_t *cl = dce_cl(d);

	return dce_attr_code_decode(&code_fd_frc_stream_end, cl);
}


