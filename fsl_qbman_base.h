/* Copyright (C) 2014 Freescale Semiconductor, Inc.
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
#ifndef _FSL_QBMAN_BASE_H
#define _FSL_QBMAN_BASE_H

#define dma_addr_t uint64_t

/**
 * DOC: QBMan basic structures
 *
 * The QBMan block descriptor, software portal descriptor and Frame descriptor
 * are defined here.
 *
 */

/**
 * struct qbman_block_desc - qbman block descriptor structure
 * @ccsr_reg_bar: CCSR register map.
 * @irq_rerr: Recoverable error interrupt line.
 * @irq_nrerr: Non-recoverable error interrupt line
 *
 * Descriptor for a QBMan instance on the SoC. On partitions/targets that do not
 * control this QBMan instance, these values may simply be place-holders. The
 * idea is simply that we be able to distinguish between them, eg. so that SWP
 * descriptors can identify which QBMan instance they belong to.
 */
struct qbman_block_desc {
	void *ccsr_reg_bar;
	int irq_rerr;
	int irq_nrerr;
};

enum qbman_eqcr_mode {
	qman_eqcr_vb_ring = 2, /* Valid bit, with eqcr in ring mode */
	qman_eqcr_vb_array, /* Valid bit, with eqcr in array mode */
};

/**
 * struct qbman_swp_desc - qbman software portal descriptor structure
 * @block: The QBMan instance.
 * @cena_bar: Cache-enabled portal register map.
 * @cinh_bar: Cache-inhibited portal register map.
 * @irq: -1 if unused (or unassigned)
 * @idx: SWPs within a QBMan are indexed. -1 if opaque to the user.
 * @qman_version: the qman version.
 * @eqcr_mode: Select the eqcr mode, currently only valid bit ring mode and
 * valid bit array mode are supported.
 *
 * Descriptor for a QBMan software portal, expressed in terms that make sense to
 * the user context. Ie. on MC, this information is likely to be true-physical,
 * and instantiated statically at compile-time. On GPP, this information is
 * likely to be obtained via "discovery" over a partition's "MC bus"
 * (ie. in response to a MC portal command), and would take into account any
 * virtualisation of the GPP user's address space and/or interrupt numbering.
 */
struct qbman_swp_desc {
	const struct qbman_block_desc *block;
	uint8_t *cena_bar;
	uint8_t *cinh_bar;
	int irq;
	int idx;
	uint32_t qman_version;
	enum qbman_eqcr_mode eqcr_mode;
};

/* Driver object for managing a QBMan portal */
struct qbman_swp;

/**
 * struct qbman_fd - basci structure for qbman frame descriptor
 * @words: for easier/faster copying the whole FD structure.
 * @addr_lo: the lower 32 bits of the address in FD.
 * @addr_hi: the upper 32 bits of the address in FD.
 * @len: the length field in FD.
 * @bpid_offset: represent the bpid and offset fields in FD. offset in
 * the MS 16 bits, BPID in the LS 16 bits.
 * @frc: frame context
 * @ctrl: the 32bit control bits including dd, sc,... va, err.
 * @flc_lo: the lower 32bit of flow context.
 * @flc_hi: the upper 32bits of flow context.
 *
 * Place-holder for FDs, we represent it via the simplest form that we need for
 * now. Different overlays may be needed to support different options, etc. (It
 * is impractical to define One True Struct, because the resulting encoding
 * routines (lots of read-modify-writes) would be worst-case performance whether
 * or not circumstances required them.)
 *
 * Note, as with all data-structures exchanged between software and hardware (be
 * they located in the portal register map or DMA'd to and from main-memory),
 * the driver ensures that the caller of the driver API sees the data-structures
 * in host-endianness. "struct qbman_fd" is no exception. The 32-bit words
 * contained within this structure are represented in host-endianness, even if
 * hardware always treats them as little-endian. As such, if any of these fields
 * are interpreted in a binary (rather than numerical) fashion by hardware
 * blocks (eg. accelerators), then the user should be careful. We illustrate
 * with an example;
 *
 * Suppose the desired behaviour of an accelerator is controlled by the "frc"
 * field of the FDs that are sent to it. Suppose also that the behaviour desired
 * by the user corresponds to an "frc" value which is expressed as the literal
 * sequence of bytes 0xfe, 0xed, 0xab, and 0xba. So "frc" should be the 32-bit
 * value in which 0xfe is the first byte and 0xba is the last byte, and as
 * hardware is little-endian, this amounts to a 32-bit "value" of 0xbaabedfe. If
 * the software is little-endian also, this can simply be achieved by setting
 * frc=0xbaabedfe. On the other hand, if software is big-endian, it should set
 * frc=0xfeedabba! The best away of avoiding trouble with this sort of thing is
 * to treat the 32-bit words as numerical values, in which the offset of a field
 * from the beginning of the first byte (as required or generated by hardware)
 * is numerically encoded by a left-shift (ie. by raising the field to a
 * corresponding power of 2).  Ie. in the current example, software could set
 * "frc" in the following way, and it would work correctly on both little-endian
 * and big-endian operation;
 *    fd.frc = (0xfe << 0) | (0xed << 8) | (0xab << 16) | (0xba << 24);
 */
struct qbman_fd {
	union {
		uint32_t words[8];
		struct qbman_fd_simple {
			uint32_t addr_lo;
			uint32_t addr_hi;
			uint32_t len;
			uint32_t bpid_offset;
			uint32_t frc;
			uint32_t ctrl;
			uint32_t flc_lo;
			uint32_t flc_hi;
		} simple;
	};
};

enum qbman_fd_format {
	qbman_fd_single = 0,
	qbman_fd_list,
	qbman_fd_sg
};

/**
 * qbman_fd_get_addr() - get the addr field of frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the address in the frame descriptor.
 */
static inline dma_addr_t qbman_fd_get_addr(const struct qbman_fd *fd)
{
	return (dma_addr_t)((((uint64_t)fd->simple.addr_hi) << 32)
				+ fd->simple.addr_lo);
}

/**
 * qbman_fd_set_addr() - Set the addr field of frame descriptor
 * @fd: the given frame descriptor.
 * @addr: the address needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_addr(struct qbman_fd *fd, dma_addr_t addr)
{
	fd->simple.addr_hi = upper_32_bits(addr);
	fd->simple.addr_lo = lower_32_bits(addr);
}

/**
 * qbman_fd_get_frc() - Get the frame context in the frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the frame context field in the frame descriptor.
 */
static inline uint32_t qbman_fd_get_frc(const struct qbman_fd *fd)
{
	return fd->simple.frc;
}

/**
 * qbman_fd_set_frc() - Set the frame context in the frame descriptor
 * @fd: the given frame descriptor.
 * @frc: the frame context needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_frc(struct qbman_fd *fd, uint32_t frc)
{
	fd->simple.frc = frc;
}

/**
 * qbman_fd_get_flc() - Get the flow context in the frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the flow context in the frame descriptor.
 */
static inline dma_addr_t qbman_fd_get_flc(const struct qbman_fd *fd)
{
	return (dma_addr_t)((((uint64_t)fd->simple.flc_hi) << 32) +
			    fd->simple.flc_lo);
}

/**
 * qbman_fd_set_flc() - Set the flow context field of frame descriptor
 * @fd: the given frame descriptor.
 * @flc_addr: the flow context needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_flc(struct qbman_fd *fd,  dma_addr_t flc_addr)
{
	fd->simple.flc_hi = upper_32_bits(flc_addr);
	fd->simple.flc_lo = lower_32_bits(flc_addr);
}

/**
 * qbman_fd_get_len() - Get the length in the frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the length field in the frame descriptor.
 */
static inline uint32_t qbman_fd_get_len(const struct qbman_fd *fd)
{
	return fd->simple.len;
}

/**
 * qbman_fd_set_len() - Set the length field of frame descriptor
 * @fd: the given frame descriptor.
 * @len: the length needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_len(struct qbman_fd *fd, uint32_t len)
{
	fd->simple.len = len;
}

/**
 * qbman_fd_get_offset() - Get the offset field in the frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the offset.
 */
static inline uint16_t qbman_fd_get_offset(const struct qbman_fd *fd)
{
	return (uint16_t)(fd->simple.bpid_offset >> 16) & 0x0FFF;
}

/**
 * qbman_fd_set_offset() - Set the offset field of frame descriptor
 *
 * @fd: the given frame descriptor.
 * @offset: the offset needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_offset(struct qbman_fd *fd, uint16_t offset)
{
	fd->simple.bpid_offset &= 0xF000FFFF;
	fd->simple.bpid_offset |= (uint32_t)offset << 16;
}

/**
 * qbman_fd_get_format() - Get the format field in the frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the format.
 */
static inline enum qbman_fd_format qbman_fd_get_format(
						const struct qbman_fd *fd)
{
	return (enum qbman_fd_format)((fd->simple.bpid_offset >> 28) & 0x3);
}

/**
 * qbman_fd_set_format() - Set the format field of frame descriptor
 *
 * @fd: the given frame descriptor.
 * @format: the format needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_format(struct qbman_fd *fd,
				       enum qbman_fd_format format)
{
	fd->simple.bpid_offset &= 0xCFFFFFFF;
	fd->simple.bpid_offset |= (uint32_t)format << 28;
}

/**
 * qbman_fd_get_bpid() - Get the bpid field in the frame descriptor
 * @fd: the given frame descriptor.
 *
 * Return the bpid.
 */
static inline uint16_t qbman_fd_get_bpid(const struct qbman_fd *fd)
{
	return (uint16_t)(fd->simple.bpid_offset & 0xFFFF);
}

/**
 * qbman_fd_set_bpid() - Set the bpid field of frame descriptor
 *
 * @fd: the given frame descriptor.
 * @bpid: the bpid needs to be set in frame descriptor.
 */
static inline void qbman_fd_set_bpid(struct qbman_fd *fd, uint16_t bpid)
{
	fd->simple.bpid_offset &= 0xFFFF0000;
	fd->simple.bpid_offset |= (uint32_t)bpid;
}

/**
 * struct qbman_sg_entry - the scatter-gathering structure
 * @addr_lo: the lower 32bit of address
 * @addr_hi: the upper 32bit of address
 * @len: the length in this sg entry.
 * @bpid_offset: offset in the MS 16 bits, BPID in the LS 16 bits.
 */
struct qbman_sg_entry {
	uint32_t addr_lo;
	uint32_t addr_hi;
	uint32_t len;
	uint32_t bpid_offset;
};

enum qbman_sg_format {
	qbman_sg_single = 0,
	qbman_sg_frame_data,
	qbman_sg_sgt_ext
};

/**
 * qbman_sg_get_addr() - Get the address from SG entry
 * @sg: the given scatter-gathering object.
 *
 * Return the address.
 */
static inline dma_addr_t qbman_sg_get_addr(const struct qbman_sg_entry *sg)
{
	return (dma_addr_t)((((uint64_t)sg->addr_hi) << 32) + sg->addr_lo);
}

/**
 * qbman_sg_set_addr() - Set the address in SG entry
 * @sg: the given scatter-gathering object.
 * @addr: the address to be set.
 */
static inline void qbman_sg_set_addr(struct qbman_sg_entry *sg, dma_addr_t addr)
{
	sg->addr_hi = upper_32_bits(addr);
	sg->addr_lo = lower_32_bits(addr);
}


static inline int qbman_sg_short_len(const struct qbman_sg_entry *sg)
{
	return (sg->bpid_offset >> 30) & 0x1;
}

/**
 * qbman_sg_get_len() - Get the length in SG entry
 * @sg: the given scatter-gathering object.
 *
 * Return the length.
 */
static inline uint32_t qbman_sg_get_len(const struct qbman_sg_entry *sg)
{
	if (qbman_sg_short_len(sg))
		return sg->len & 0x1FFFF;
	return sg->len;
}

/**
 * qbman_sg_set_len() - Set the length in SG entry
 * @sg: the given scatter-gathering object.
 * @len: the length to be set.
 */
static inline void qbman_sg_set_len(struct qbman_sg_entry *sg, uint32_t len)
{
	sg->len = len;
}

/**
 * qbman_sg_get_offset() - Get the offset in SG entry
 * @sg: the given scatter-gathering object.
 *
 * Return the offset.
 */
static inline uint16_t qbman_sg_get_offset(const struct qbman_sg_entry *sg)
{
	return (uint16_t)(sg->bpid_offset >> 16) & 0x0FFF;
}

/**
 * qbman_sg_set_offset() - Set the offset in SG entry
 * @sg: the given scatter-gathering object.
 * @offset: the offset to be set.
 */
static inline void qbman_sg_set_offset(struct qbman_sg_entry *sg,
				       uint16_t offset)
{
	sg->bpid_offset &= 0xF000FFFF;
	sg->bpid_offset |= (uint32_t)offset << 16;
}

/**
 * qbman_sg_get_format() - Get the SG format in SG entry
 * @sg: the given scatter-gathering object.
 *
 * Return the format.
 */
static inline enum qbman_sg_format
	qbman_sg_get_format(const struct qbman_sg_entry *sg)
{
	return (enum qbman_sg_format)((sg->bpid_offset >> 28) & 0x3);
}

/**
 * qbman_sg_set_format() - Set the SG format in SG entry
 * @sg: the given scatter-gathering object.
 * @format: the format to be set.
 */
static inline void qbman_sg_set_format(struct qbman_sg_entry *sg,
				       enum qbman_sg_format format)
{
	sg->bpid_offset &= 0xCFFFFFFF;
	sg->bpid_offset |= (uint32_t)format << 28;
}

/**
 * qbman_sg_get_bpid() - Get the buffer pool id in SG entry
 * @sg: the given scatter-gathering object.
 *
 * Return the bpid.
 */
static inline uint16_t qbman_sg_get_bpid(const struct qbman_sg_entry *sg)
{
	return (uint16_t)(sg->bpid_offset & 0x3FFF);
}

/**
 * qbman_sg_set_bpid() - Set the buffer pool id in SG entry
 * @sg: the given scatter-gathering object.
 * @bpid: the bpid to be set.
 */
static inline void qbman_sg_set_bpid(struct qbman_sg_entry *sg, uint16_t bpid)
{
	sg->bpid_offset &= 0xFFFFC000;
	sg->bpid_offset |= (uint32_t)bpid;
}

/**
 * qbman_sg_is_final() - Check final bit in SG entry
 * @sg: the given scatter-gathering object.
 *
 * Return bool.
 */
static inline int qbman_sg_is_final(const struct qbman_sg_entry *sg)
{
	return !!(sg->bpid_offset >> 31);
}

/**
 * qbman_sg_set_final() - Set the final bit in SG entry
 * @sg: the given scatter-gathering object.
 * @final: the final boolean to be set.
 */
static inline void qbman_sg_set_final(struct qbman_sg_entry *sg, int final)
{
	sg->bpid_offset &= 0x7FFFFFFF;
	sg->bpid_offset |= (uint32_t)final << 31;
}

/* Endianness conversion helper functions
 * The accelerator drivers which construct / read scatter gather entries
 * need to call these in order to account for endianness mismatches between
 * hardware and cpu
 */
#ifdef __BIG_ENDIAN
/**
 * qbman_sg_cpu_to_le() - convert scatter gather entry from native cpu
 * format little endian format.
 * @sg: the given scatter gather entry.
 */
static inline void qbman_sg_cpu_to_le(struct qbman_sg_entry *sg)
{
	uint32_t *p = (uint32_t *)sg;
	unsigned int i;

	for (i = 0; i < sizeof(*sg) / sizeof(uint32_t); i++)
		cpu_to_le32s(p++);
}

/**
 * qbman_sg_le_to_cpu() - convert scatter gather entry from little endian
 * format to native cpu format.
 * @sg: the given scatter gather entry.
 */
static inline void qbman_sg_le_to_cpu(struct qbman_sg_entry *sg)
{
	uint32_t *p = (uint32_t *)sg;
	unsigned int i;

	for (i = 0; i < sizeof(*sg) / sizeof(uint32_t); i++)
		le32_to_cpus(p++);
}
#else
#define qbman_sg_cpu_to_le(sg)
#define qbman_sg_le_to_cpu(sg)
#endif /* __BIG_ENDIAN */


/**
 * struct qbman_fl_entry - structure for frame list entry.
 * @addr_lo: the lower 32bit of address
 * @addr_hi: the upper 32bit of address
 * @len: the length in this sg entry.
 * @bpid_offset: offset in the MS 16 bits, BPID in the LS 16 bits.
 * @frc: frame context
 * @ctrl: the 32bit control bits including dd, sc,... va, err.
 * @flc_lo: the lower 32bit of flow context.
 * @flc_hi: the upper 32bits of flow context.
 *
 * Frame List Entry (FLE)
 * Identical to qbman_fd.simple layout, but some bits are different
 */
struct qbman_fl_entry {
	uint32_t addr_lo;
	uint32_t addr_hi;
	uint32_t len;
	uint32_t bpid_offset;
	uint32_t frc;
	uint32_t ctrl;
	uint32_t flc_lo;
	uint32_t flc_hi;
};

enum qbman_fl_format {
	qbman_fl_single = 0,
	qbman_fl_res,
	qbman_fl_sg
};

/**
 * qbman_fl_get_addr() - Get address in the frame list entry
 * @fle: the given frame list entry.
 *
 * Return address for the get function.
 */
static inline dma_addr_t qbman_fl_get_addr(const struct qbman_fl_entry *fle)
{
	return (dma_addr_t)((((uint64_t)fle->addr_hi) << 32) + fle->addr_lo);
}

/**
 * qbman_fl_set_addr() - Set the address in the frame list entry
 * @fle: the given frame list entry.
 * @addr: the address needs to be set.
 *
 */
static inline void qbman_fl_set_addr(struct qbman_fl_entry *fle,
				     dma_addr_t addr)
{
	fle->addr_hi = upper_32_bits(addr);
	fle->addr_lo = lower_32_bits(addr);
}

/**
 * qbman_fl_get_flc() - Get the flow context in the frame list entry
 * @fle: the given frame list entry.
 *
 * Return flow context for the get function.
 */
static inline dma_addr_t qbman_fl_get_flc(const struct qbman_fl_entry *fle)
{
	return (dma_addr_t)((((uint64_t)fle->flc_hi) << 32) + fle->flc_lo);
}

/**
 * qbman_fl_set_flc() - Set the flow context in the frame list entry
 * @fle: the given frame list entry.
 * @flc_addr: the flow context address needs to be set.
 *
 */
static inline void qbman_fl_set_flc(struct qbman_fl_entry *fle,
				    dma_addr_t flc_addr)
{
	fle->flc_hi = upper_32_bits(flc_addr);
	fle->flc_lo = lower_32_bits(flc_addr);
}

/**
 * qbman_fl_get_len() - Get the length in the frame list entry
 * @fle: the given frame list entry.
 *
 * Return length for the get function.
 */
static inline uint32_t qbman_fl_get_len(const struct qbman_fl_entry *fle)
{
	return fle->len;
}

/**
 * qbman_fl_set_len() - Set the length in the frame list entry
 * @fle: the given frame list entry.
 * @len: the length needs to be set.
 *
 */
static inline void qbman_fl_set_len(struct qbman_fl_entry *fle, uint32_t len)
{
	fle->len = len;
}

/**
 * qbman_fl_get_offset() - Get/Set the offset in the frame list entry
 * @fle: the given frame list entry.
 *
 * Return offset for the get function.
 */
static inline uint16_t qbman_fl_get_offset(const struct qbman_fl_entry *fle)
{
	return (uint16_t)(fle->bpid_offset >> 16) & 0x0FFF;
}

/**
 * qbman_fl_set_offset() - Set the offset in the frame list entry
 * @fle: the given frame list entry.
 * @offset: the offset needs to be set.
 *
 */
static inline void qbman_fl_set_offset(struct qbman_fl_entry *fle,
				       uint16_t offset)
{
	fle->bpid_offset &= 0xF000FFFF;
	fle->bpid_offset |= (uint32_t)(offset & 0x0FFF) << 16;
}

/**
 * qbman_fl_get_format() - Get the format in the frame list entry
 * @fle: the given frame list entry.
 *
 * Return frame list format for the get function.
 */
static inline enum qbman_fl_format qbman_fl_get_format(
	const struct qbman_fl_entry *fle)
{
	return (enum qbman_fl_format)((fle->bpid_offset >> 28) & 0x3);
}

/**
 * qbman_fl_set_format() - Set the format in the frame list entry
 * @fle: the given frame list entry.
 * @format: the frame list format needs to be set.
 *
 */
static inline void qbman_fl_set_format(struct qbman_fl_entry *fle,
				       enum qbman_fl_format format)
{
	fle->bpid_offset &= 0xCFFFFFFF;
	fle->bpid_offset |= (uint32_t)(format & 0x3) << 28;
}

/**
 * qbman_fl_get_bpid() - Get the buffer pool id in the frame list entry
 * @fle: the given frame list entry.
 *
 * Return bpid for the get function.
 */
static inline uint16_t qbman_fl_get_bpid(const struct qbman_fl_entry *fle)
{
	return (uint16_t)(fle->bpid_offset & 0x3FFF);
}

/**
 * qbman_fl_set_bpid() - Set the buffer pool id in the frame list entry
 * @fle: the given frame list entry.
 * @bpid: the buffer pool id needs to be set.
 *
 */
static inline void qbman_fl_set_bpid(struct qbman_fl_entry *fle, uint16_t bpid)
{
	fle->bpid_offset &= 0xFFFFC000;
	fle->bpid_offset |= (uint32_t)bpid;
}

/** qbman_fl_is_final() - check the final bit is set or not in the frame list.
 * @fle: the given frame list entry.
 *
 * Return final bit settting.
 */
static inline int qbman_fl_is_final(const struct qbman_fl_entry *fle)
{
	return !!(fle->bpid_offset >> 31);
}

/**
 * qbman_fl_set_final() - Set the final bit in the frame list entry
 * @fle: the given frame list entry.
 * @final: the final bit needs to be set.
 *
 */
static inline void qbman_fl_set_final(struct qbman_fl_entry *fle, int final)
{
	fle->bpid_offset &= 0x7FFFFFFF;
	fle->bpid_offset |= (uint32_t)final << 31;
}

/**
 * struct qbman_dq - the qman result structure
 * @dont_manipulate_directly: the 16 32bit data to represent the whole
 * possible qman dequeue result.
 *
 * When frames are dequeued, the FDs show up inside "dequeue" result structures
 * (if at all, not all dequeue results contain valid FDs). This structure type
 * is intentionally defined without internal detail, and the only reason it
 * isn't declared opaquely (without size) is to allow the user to provide
 * suitably-sized (and aligned) memory for these entries.
 */
struct qbman_dq {
	uint32_t dont_manipulate_directly[16];
};

/* Parsing frame dequeue results */
/* FQ empty */
#define QBMAN_DQ_STAT_FQEMPTY       0x80
/* FQ held active */
#define QBMAN_DQ_STAT_HELDACTIVE    0x40
/* FQ force eligible */
#define QBMAN_DQ_STAT_FORCEELIGIBLE 0x20
/* Valid frame */
#define QBMAN_DQ_STAT_VALIDFRAME    0x10
/* FQ ODP enable */
#define QBMAN_DQ_STAT_ODPVALID      0x04
/* Volatile dequeue */
#define QBMAN_DQ_STAT_VOLATILE      0x02
/* volatile dequeue command is expired */
#define QBMAN_DQ_STAT_EXPIRED       0x01

/**
 * qbman_dq_flags() - Get the stat field of dequeue response
 * @dq: the dequeue result.
 */
uint32_t qbman_dq_flags(const struct qbman_dq *dq);

/**
 * qbman_dq_is_pull() - Check whether the dq response is from a pull
 * command.
 * @dq: the dequeue result.
 *
 * Return 1 for volatile(pull) dequeue, 0 for static dequeue.
 */
static inline int qbman_dq_is_pull(const struct qbman_dq *dq)
{
	return (int)(qbman_dq_flags(dq) & QBMAN_DQ_STAT_VOLATILE);
}

/**
 * qbman_dq_is_pull_complete() - Check whether the pull command is completed.
 * @dq: the dequeue result.
 *
 * Return boolean.
 */
static inline int qbman_dq_is_pull_complete(
					const struct qbman_dq *dq)
{
	return (int)(qbman_dq_flags(dq) & QBMAN_DQ_STAT_EXPIRED);
}

/**
 * qbman_dq_seqnum() - Get the seqnum field in dequeue response
 * seqnum is valid only if VALIDFRAME flag is TRUE
 * @dq: the dequeue result.
 *
 * Return seqnum.
 */
uint16_t qbman_dq_seqnum(const struct qbman_dq *dq);

/**
 * qbman_dq_odpid() - Get the seqnum field in dequeue response
 * odpid is valid only if ODPVAILD flag is TRUE.
 * @dq: the dequeue result.
 *
 * Return odpid.
 */
uint16_t qbman_dq_odpid(const struct qbman_dq *dq);

/**
 * qbman_dq_fqid() - Get the fqid in dequeue response
 * @dq: the dequeue result.
 *
 * Return fqid.
 */
uint32_t qbman_dq_fqid(const struct qbman_dq *dq);

/**
 * qbman_dq_byte_count() - Get the byte count in dequeue response
 * @dq: the dequeue result.
 *
 * Return the byte count remaining in the FQ.
 */
uint32_t qbman_dq_byte_count(const struct qbman_dq *dq);

/**
 * qbman_dq_frame_count() - Get the frame count in dequeue response
 * @dq: the dequeue result.
 *
 * Return the frame count remaining in the FQ.
 */
uint32_t qbman_dq_frame_count(const struct qbman_dq *dq);

/**
 * qbman_dq_fd_ctx() - Get the frame queue context in dequeue response
 * @dq: the dequeue result.
 *
 * Return the frame queue context.
 */
uint64_t qbman_dq_fqd_ctx(const struct qbman_dq *dq);

/**
 * qbman_dq_fd() - Get the frame descriptor in dequeue response
 * @dq: the dequeue result.
 *
 * Return the frame descriptor.
 */
const struct qbman_fd *qbman_dq_fd(const struct qbman_dq *dq);

#endif /* !_FSL_QBMAN_BASE_H */
