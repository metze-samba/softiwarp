/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2017, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/llist.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>
#include <linux/cpu.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"

#include <linux/kthread.h>

static bool zcopy_tx = false;
module_param(zcopy_tx, bool, 0644);
MODULE_PARM_DESC(zcopy_tx, "Zero copy user data transmit if possible");

static int gso_seg_limit;
module_param(gso_seg_limit, int, 0644);
MODULE_PARM_DESC(gso_seg_limit, "Limit TCP GSO to value if set\n");

static inline int siw_crc_txhdr(struct siw_iwarp_tx *ctx)
{
	crypto_shash_init(ctx->mpa_crc_hd);
	return siw_crc_array(ctx->mpa_crc_hd, (u8 *)&ctx->pkt,
			     ctx->ctrl_len);
}

#define MAX_HDR_INLINE					\
	(((uint32_t)(sizeof(struct siw_rreq_pkt) -	\
	sizeof(struct iwarp_send))) & 0xF8)

static inline struct page *siw_get_pblpage(struct siw_mr *mr,
					   u64 addr, int *idx)
{
	struct siw_pbl *pbl = mr->pbl;
	u64 offset = addr - mr->mem.va;
	u64 paddr = siw_pbl_get_buffer(pbl, offset, NULL, idx);

	if (paddr)
		return virt_to_page(paddr);
	return NULL;
}

/*
 * Copy short payload at provided destination address and
 * update address pointer to the address behind data
 * including potential padding
 */
static int siw_try_1seg(struct siw_iwarp_tx *c_tx, char *payload)
{
	struct siw_wqe *wqe = &c_tx->wqe_active;
	struct siw_sge *sge = &wqe->sqe.sge[0];
	u32 bytes = sge->length;

	if (bytes > MAX_HDR_INLINE || wqe->sqe.num_sge != 1)
		return -1;

	if (bytes == 0)
		return 0;

	if (tx_flags(wqe) & SIW_WQE_INLINE)
		memcpy(payload, &wqe->sqe.sge[1], bytes);
	else {
		struct siw_mr *mr = siw_mem2mr(wqe->mem[0].obj);

		if (!mr->mem_obj) /* Kernel client using kva */
			memcpy(payload, (void *)sge->laddr, bytes);
		else if (c_tx->in_syscall) {
			if (copy_from_user(payload,
					   (void *)sge->laddr,
					   bytes)) {
				WARN_ON(1);
				return -1;
			}
		} else {
			unsigned int off = sge->laddr & ~PAGE_MASK;
			struct page *p;
			char *buffer;
			int pbl_idx = 0;

			if (!mr->mem.is_pbl)
				p = siw_get_upage(mr->umem, sge->laddr);
			else
				p = siw_get_pblpage(mr, sge->laddr, &pbl_idx);

			BUG_ON(!p);

			buffer = kmap_atomic(p);

			if (likely(PAGE_SIZE - off >= bytes)) {
				memcpy(payload, buffer + off, bytes);
				kunmap_atomic(buffer);
			} else {
				unsigned long part = bytes - (PAGE_SIZE - off);

				memcpy(payload, buffer + off, part);
				kunmap_atomic(buffer);
				payload += part;

				if (!mr->mem.is_pbl)
					p = siw_get_upage(mr->umem,
							  sge->laddr + part);
				else
					p = siw_get_pblpage(mr,
							    sge->laddr + part,
							    &pbl_idx);
				BUG_ON(!p);

				buffer = kmap_atomic(p);
				memcpy(payload, buffer, bytes - part);
				kunmap_atomic(buffer);
			}
		}
	}
	return (int)bytes;
}

#define PKT_FRAGMENTED 1
#define PKT_COMPLETE 0

/*
 * siw_qp_prepare_tx()
 *
 * Prepare tx state for sending out one fpdu. Builds complete pkt
 * if no user data or only immediate data are present.
 *
 * returns PKT_COMPLETE if complete pkt built, PKT_FRAGMENTED otherwise.
 */
static int siw_qp_prepare_tx(struct siw_iwarp_tx *c_tx)
{
	struct siw_wqe		*wqe = &c_tx->wqe_active;
	char			*crc = NULL;
	int			data = 0;

	switch (tx_type(wqe)) {

	case SIW_OP_READ:
	case SIW_OP_READ_LOCAL_INV:
		memcpy(&c_tx->pkt.ctrl,
		       &iwarp_pktinfo[RDMAP_RDMA_READ_REQ].ctrl,
		       sizeof(struct iwarp_ctrl));

		c_tx->pkt.rreq.rsvd = 0;
		c_tx->pkt.rreq.ddp_qn = htonl(RDMAP_UNTAGGED_QN_RDMA_READ);
		c_tx->pkt.rreq.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]);
		c_tx->pkt.rreq.ddp_mo = 0;
		c_tx->pkt.rreq.sink_stag = htonl(wqe->sqe.sge[0].lkey);
		c_tx->pkt.rreq.sink_to =
			cpu_to_be64(wqe->sqe.sge[0].laddr); /* abs addr! */
		c_tx->pkt.rreq.source_stag = htonl(wqe->sqe.rkey);
		c_tx->pkt.rreq.source_to = cpu_to_be64(wqe->sqe.raddr);
		c_tx->pkt.rreq.read_size = htonl(wqe->sqe.sge[0].length);

		c_tx->ctrl_len = sizeof(struct iwarp_rdma_rreq);
		crc = (char *)&c_tx->pkt.rreq_pkt.crc;
		break;

	case SIW_OP_SEND:
		if (tx_flags(wqe) & SIW_WQE_SOLICITED)
			memcpy(&c_tx->pkt.ctrl,
			       &iwarp_pktinfo[RDMAP_SEND_SE].ctrl,
			       sizeof(struct iwarp_ctrl));
		else
			memcpy(&c_tx->pkt.ctrl,
			       &iwarp_pktinfo[RDMAP_SEND].ctrl,
			       sizeof(struct iwarp_ctrl));

		c_tx->pkt.send.ddp_qn = RDMAP_UNTAGGED_QN_SEND;
		c_tx->pkt.send.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]);
		c_tx->pkt.send.ddp_mo = 0;

		c_tx->pkt.send_inv.inval_stag = 0;

		c_tx->ctrl_len = sizeof(struct iwarp_send);

		crc = (char *)&c_tx->pkt.send_pkt.crc;
		data = siw_try_1seg(c_tx, crc);
		break;

	case SIW_OP_SEND_REMOTE_INV:
		if (tx_flags(wqe) & SIW_WQE_SOLICITED)
			memcpy(&c_tx->pkt.ctrl,
			       &iwarp_pktinfo[RDMAP_SEND_SE_INVAL].ctrl,
			       sizeof(struct iwarp_ctrl));
		else
			memcpy(&c_tx->pkt.ctrl,
			       &iwarp_pktinfo[RDMAP_SEND_INVAL].ctrl,
			       sizeof(struct iwarp_ctrl));

		c_tx->pkt.send.ddp_qn = RDMAP_UNTAGGED_QN_SEND;
		c_tx->pkt.send.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]);
		c_tx->pkt.send.ddp_mo = 0;

		c_tx->pkt.send_inv.inval_stag = cpu_to_be32(wqe->sqe.rkey);

		c_tx->ctrl_len = sizeof(struct iwarp_send_inv);

		crc = (char *)&c_tx->pkt.send_pkt.crc;
		data = siw_try_1seg(c_tx, crc);
		break;

	case SIW_OP_WRITE:
		memcpy(&c_tx->pkt.ctrl, &iwarp_pktinfo[RDMAP_RDMA_WRITE].ctrl,
		       sizeof(struct iwarp_ctrl));

		c_tx->pkt.rwrite.sink_stag = htonl(wqe->sqe.rkey);
		c_tx->pkt.rwrite.sink_to = cpu_to_be64(wqe->sqe.raddr);
		c_tx->ctrl_len = sizeof(struct iwarp_rdma_write);

		crc = (char *)&c_tx->pkt.write_pkt.crc;
		data = siw_try_1seg(c_tx, crc);
		break;

	case SIW_OP_READ_RESPONSE:
		memcpy(&c_tx->pkt.ctrl,
		       &iwarp_pktinfo[RDMAP_RDMA_READ_RESP].ctrl,
		       sizeof(struct iwarp_ctrl));

		/* NBO */
		c_tx->pkt.rresp.sink_stag = cpu_to_be32(wqe->sqe.rkey);
		c_tx->pkt.rresp.sink_to = cpu_to_be64(wqe->sqe.raddr);

		c_tx->ctrl_len = sizeof(struct iwarp_rdma_rresp);

		crc = (char *)&c_tx->pkt.write_pkt.crc;
		data = siw_try_1seg(c_tx, crc);
		break;

	default:
		dprint(DBG_ON, "Unsupported WQE type %d\n", tx_type(wqe));
		BUG();
		break;
	}
	c_tx->ctrl_sent = 0;

	if (data >= 0) {
		if (data > 0) {
			wqe->processed = data;

			c_tx->pkt.ctrl.mpa_len =
				htons(c_tx->ctrl_len + data - MPA_HDR_SIZE);

			/* compute eventual pad */
			data += -(int)data & 0x3;
			/* point CRC after data or pad */
			crc += data;
			c_tx->ctrl_len += data;

			if (!(c_tx->pkt.ctrl.ddp_rdmap_ctrl & DDP_FLAG_TAGGED))
				c_tx->pkt.c_untagged.ddp_mo = 0;
			else
				c_tx->pkt.c_tagged.ddp_to =
				    cpu_to_be64(wqe->sqe.raddr);
		}

		*(u32 *)crc = 0;
		/*
		 * Do complete CRC if enabled and short packet
		 */
		if (c_tx->mpa_crc_hd) {
			if (siw_crc_txhdr(c_tx) != 0)
				return -EINVAL;
			crypto_shash_final(c_tx->mpa_crc_hd, (u8 *)crc);
		}
		c_tx->ctrl_len += MPA_CRC_SIZE;

		return PKT_COMPLETE;
	}
	c_tx->ctrl_len += MPA_CRC_SIZE;
	c_tx->sge_idx = 0;
	c_tx->sge_off = 0;
	c_tx->pbl_idx = 0;

	/*
	 * Allow direct sending out of user buffer if WR is non signalled
	 * and payload is over threshold and no CRC is enabled.
	 * Per RDMA verbs, the application should not change the send buffer
	 * until the work completed. In iWarp, work completion is only
	 * local delivery to TCP. TCP may reuse the buffer for
	 * retransmission. Changing unsent data also breaks the CRC,
	 * if applied.
	 */
	if (zcopy_tx
	    && wqe->bytes > SENDPAGE_THRESH
	    && !(tx_flags(wqe) & SIW_WQE_SIGNALLED)
	    && tx_type(wqe) != SIW_OP_READ
	    && tx_type(wqe) != SIW_OP_READ_LOCAL_INV)
		c_tx->use_sendpage = 1;
	else
		c_tx->use_sendpage = 0;

	return PKT_FRAGMENTED;
}

/*
 * Send out one complete control type FPDU, or header of FPDU carrying
 * data. Used for fixed sized packets like Read.Requests or zero length
 * SENDs, WRITEs, READ.Responses, or header only.
 */
static inline int siw_tx_ctrl(struct siw_iwarp_tx *c_tx, struct socket *s,
			      int flags)
{
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov = {
		.iov_base = (char *)&c_tx->pkt.ctrl + c_tx->ctrl_sent,
		.iov_len = c_tx->ctrl_len - c_tx->ctrl_sent};

	int rv = kernel_sendmsg(s, &msg, &iov, 1,
				c_tx->ctrl_len - c_tx->ctrl_sent);

	dprint(DBG_TX, " (QP%d): op=%d, %d of %d sent (%d)\n",
		TX_QPID(c_tx), __rdmap_opcode(&c_tx->pkt.ctrl),
		c_tx->ctrl_sent + rv, c_tx->ctrl_len, rv);

	if (rv >= 0) {
		c_tx->ctrl_sent += rv;

		if (c_tx->ctrl_sent == c_tx->ctrl_len) {
			siw_dprint_hdr(&c_tx->pkt.hdr, TX_QPID(c_tx),
					"HDR/CTRL sent");
			rv = 0;
		} else if (c_tx->ctrl_sent < c_tx->ctrl_len)
			rv = -EAGAIN;
		else
			BUG();
	}
	return rv;
}

/*
 * use way more efficient do_tcp_sendpages() if
 * exported by kernel.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
#define TCP_SENDPAGES_EXPORTED
#endif

/*
 * 0copy TCP transmit interface:  Push page array page by page,
 * or use do_tcp_sendpages, if exported.
 *
 * Using sendpage to push page by page appears to be less efficient
 * than using sendmsg, even if data are copied.
 *
 * A general performance limitation might be the extra four bytes
 * trailer checksum segment to be pushed after user data.
 */
static int siw_tcp_sendpages(struct socket *s, struct page **page,
			     int offset, size_t size)
{
	int i = 0, rv = 0;
#ifdef TCP_SENDPAGES_EXPORTED
	int sent = 0, flags = MSG_MORE|MSG_DONTWAIT|MSG_SENDPAGE_NOTLAST;
	struct sock *sk = s->sk;

	while (size) {
		size_t bytes = min_t(size_t, PAGE_SIZE - offset, size);

		if (size + offset <= PAGE_SIZE)
	       		flags = MSG_MORE|MSG_DONTWAIT;

		tcp_rate_check_app_limited(sk);
try_page_again:
		lock_sock(sk);
		rv = do_tcp_sendpages(sk, page[i], offset, bytes, flags);
		release_sock(sk);

		if (rv > 0) {
			size -= rv;
			sent += rv;
			if (rv != bytes) {
				offset += rv;
				bytes -= rv;
				goto try_page_again;
			}
			offset = 0;
		} else {
			if (rv  == -EAGAIN || rv == 0)
				break;
			return rv;
		}
		i++;
	}
	return sent;
#else
	size_t todo = size;

	for (i = 0; size > 0; i++) {
		size_t bytes = min_t(size_t, PAGE_SIZE - offset, size);

		rv = s->ops->sendpage(s, page[i], offset, bytes,
				      MSG_MORE|MSG_DONTWAIT);
		if (rv <= 0)
			break;

		size -= rv;

		if (rv != bytes)
			break;

		offset = 0;
	}
	if (rv >= 0 || rv == -EAGAIN)
		rv = todo - size;
	return rv;
#endif
}

/*
 * siw_0copy_tx()
 *
 * Pushes list of pages to TCP socket. If pages from multiple
 * SGE's, all referenced pages of each SGE are pushed in one
 * shot.
 */
static int siw_0copy_tx(struct socket *s, struct page **page,
			struct siw_sge *sge, unsigned int offset,
			unsigned int size)
{
	int i = 0, sent = 0, rv;
	int sge_bytes = min(sge->length - offset, size);

	offset  = (sge->laddr + offset) & ~PAGE_MASK;

	while (sent != size) {

		rv = siw_tcp_sendpages(s, &page[i], offset, sge_bytes);
		if (rv >= 0) {
			sent += rv;
			if (size == sent || sge_bytes > rv)
				break;

			i += PAGE_ALIGN(sge_bytes + offset) >> PAGE_SHIFT;
			sge++;
			sge_bytes = min(sge->length, size - sent);
			offset = sge->laddr & ~PAGE_MASK;
		} else {
			sent = rv;
			break;
		}
	}
	return sent;
}

#define MAX_TRAILER (MPA_CRC_SIZE + 4)

/*
 * siw_tx_hdt() tries to push a complete packet to TCP where all
 * packet fragments are referenced by the elements of one iovec.
 * For the data portion, each involved page must be referenced by
 * one extra element. All sge's data can be non-aligned to page
 * boundaries. Two more elements are referencing iWARP header
 * and trailer:
 * MAX_ARRAY = 64KB/PAGE_SIZE + 1 + (2 * (SIW_MAX_SGE - 1) + HDR + TRL
 */
#define MAX_ARRAY ((0xffff / PAGE_SIZE) + 1 + (2 * (SIW_MAX_SGE - 1) + 2))

/*
 * Write out iov referencing hdr, data and trailer of current FPDU.
 * Update transmit state dependent on write return status
 */
static int siw_tx_hdt(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	struct siw_wqe		*wqe = &c_tx->wqe_active;
	struct siw_sge		*sge = &wqe->sqe.sge[c_tx->sge_idx],
				*first_sge = sge;
	union siw_mem_resolved	*mem = &wqe->mem[c_tx->sge_idx];
	struct siw_mr		*mr = NULL;

	struct kvec		iov[MAX_ARRAY];
	struct page		*page_array[MAX_ARRAY];
	struct msghdr		msg = {.msg_flags = MSG_DONTWAIT|MSG_EOR};

	int			seg = 0, do_crc = c_tx->do_crc, is_kva = 0, rv;
	unsigned int		data_len = c_tx->bytes_unsent,
				hdr_len = 0,
				trl_len = 0,
				sge_off = c_tx->sge_off,
				sge_idx = c_tx->sge_idx,
				pbl_idx = c_tx->pbl_idx;

	if (c_tx->state == SIW_SEND_HDR) {
		if (c_tx->use_sendpage) {
			rv = siw_tx_ctrl(c_tx, s, MSG_DONTWAIT|MSG_MORE);
			if (rv)
				goto done;

			c_tx->state = SIW_SEND_DATA;
		} else {
			iov[0].iov_base =
				(char *)&c_tx->pkt.ctrl + c_tx->ctrl_sent;
			iov[0].iov_len = hdr_len =
				c_tx->ctrl_len - c_tx->ctrl_sent;
			seg = 1;
			siw_dprint_hdr(&c_tx->pkt.hdr, TX_QPID(c_tx),
					"HDR to send");
		}
	}

	wqe->processed += data_len;

	while (data_len) { /* walk the list of SGE's */
		unsigned int	sge_len = min(sge->length - sge_off, data_len);
		unsigned int	fp_off = (sge->laddr + sge_off) & ~PAGE_MASK;

		BUG_ON(!sge_len);

		if (!(tx_flags(wqe) & SIW_WQE_INLINE)) {
			mr = siw_mem2mr(mem->obj);
			if (!mr->mem_obj)
				is_kva = 1;
		} else
			is_kva = 1;

		if (is_kva && !c_tx->use_sendpage) {
			/*
			 * tx from kernel virtual address: either inline data
			 * or memory region with assigned kernel buffer
			 */
			iov[seg].iov_base = (void *)(sge->laddr + sge_off);
			iov[seg].iov_len = sge_len;

			if (do_crc)
				siw_crc_array(c_tx->mpa_crc_hd,
					      iov[seg].iov_base, sge_len);
			sge_off += sge_len;
			data_len -= sge_len;
			seg++;
			goto sge_done;
		}

		while (sge_len) {
			size_t plen = min((int)PAGE_SIZE - fp_off, sge_len);

			BUG_ON(plen <= 0);
			if (!is_kva) {
				struct page *p;

				if (mr->mem.is_pbl)
					p = siw_get_pblpage(mr,
						sge->laddr + sge_off,
						&pbl_idx);
				else
					p = siw_get_upage(mr->umem, sge->laddr
							  + sge_off);
				BUG_ON(!p);
				page_array[seg] = p;

				if (!c_tx->use_sendpage) {
					iov[seg].iov_base = kmap(p) + fp_off;
					iov[seg].iov_len = plen;
				}
				if (do_crc)
					siw_crc_page(c_tx->mpa_crc_hd, p,
						     fp_off, plen);
			} else {
				u64 pa = ((sge->laddr + sge_off) & PAGE_MASK);

				page_array[seg] = virt_to_page(pa);
				if (do_crc)
					siw_crc_array(c_tx->mpa_crc_hd,
						(void *)(sge->laddr + sge_off),
						plen);
			}

			sge_len -= plen;
			sge_off += plen;
			data_len -= plen;
			fp_off = 0;

			if (++seg > (int)MAX_ARRAY) {
				dprint(DBG_ON, "(QP%d): Too many fragments\n",
				       TX_QPID(c_tx));
				if (!is_kva && !c_tx->use_sendpage) {
					int i = (hdr_len > 0) ? 1 : 0;

					seg--;
					while (i < seg)
						kunmap(page_array[i++]);
				}
				wqe->processed -= c_tx->bytes_unsent;
				rv = -EMSGSIZE;
				goto done_crc;
			}
		}
sge_done:
		/* Update SGE variables at end of SGE */
		if (sge_off == sge->length &&
		    (data_len != 0 || wqe->processed < wqe->bytes)) {
			sge_idx++;
			sge++;
			mem++;
			sge_off = 0;
		}
	}
	/* trailer */
	if (likely(c_tx->state != SIW_SEND_TRAILER)) {
		iov[seg].iov_base = &c_tx->trailer.pad[4 - c_tx->pad];
		iov[seg].iov_len = trl_len = MAX_TRAILER - (4 - c_tx->pad);
	} else {
		iov[seg].iov_base = &c_tx->trailer.pad[c_tx->ctrl_sent];
		iov[seg].iov_len = trl_len = MAX_TRAILER - c_tx->ctrl_sent;
	}

	if (c_tx->pad) {
		*(u32 *)c_tx->trailer.pad = 0;
		if (do_crc)
			siw_crc_array(c_tx->mpa_crc_hd,
				      (u8 *)&c_tx->trailer.crc - c_tx->pad,
				      c_tx->pad);
	}
	if (!c_tx->mpa_crc_hd)
		c_tx->trailer.crc = 0;
	else if (do_crc)
		crypto_shash_final(c_tx->mpa_crc_hd,
				   (u8 *)&c_tx->trailer.crc);

	data_len = c_tx->bytes_unsent;

	if (c_tx->use_sendpage) {
		rv = siw_0copy_tx(s, page_array, first_sge, c_tx->sge_off,
				  data_len);
		if (rv == data_len) {
			rv = kernel_sendmsg(s, &msg, &iov[seg], 1, trl_len);
			if (rv > 0)
				rv += data_len;
			else
				rv = data_len;
		}
	} else {
		rv = kernel_sendmsg(s, &msg, iov, seg + 1,
				    hdr_len + data_len + trl_len);
		if (!is_kva) {
			int i = (hdr_len > 0) ? 1 : 0;

			while (i < seg)
				kunmap(page_array[i++]);
		}
		dprint(DBG_HDR, " QP[%d]: sendmsg rv = %d\n", TX_QPID(c_tx),
			rv);
	}
	if (rv < (int)hdr_len) {
		/* Not even complete hdr pushed or negative rv */
		wqe->processed -= data_len;
		if (rv >= 0) {
			c_tx->ctrl_sent += rv;
			rv = -EAGAIN;
		}
		goto done_crc;
	}

	rv -= hdr_len;

	if (rv >= (int)data_len) {
		/* all user data pushed to TCP or no data to push */
		if (data_len > 0 && wqe->processed < wqe->bytes) {
			/* Save the current state for next tx */
			c_tx->sge_idx = sge_idx;
			c_tx->sge_off = sge_off;
			c_tx->pbl_idx = pbl_idx;
		}
		rv -= data_len;

		if (rv == trl_len) /* all pushed */
			rv = 0;
		else {
			c_tx->state = SIW_SEND_TRAILER;
			c_tx->ctrl_len = MAX_TRAILER;
			c_tx->ctrl_sent = rv + 4 - c_tx->pad;
			c_tx->bytes_unsent = 0;
			rv = -EAGAIN;
		}

	} else if (data_len > 0) {
		/* Maybe some user data pushed to TCP */
		c_tx->state = SIW_SEND_DATA;
		wqe->processed -= data_len - rv;

		if (rv) {
			/*
			 * Some bytes out. Recompute tx state based
			 * on old state and bytes pushed
			 */
			unsigned int sge_unsent;

			c_tx->bytes_unsent -= rv;
			sge = &wqe->sqe.sge[c_tx->sge_idx];
			sge_unsent = sge->length - c_tx->sge_off;

			while (sge_unsent <= rv) {
				rv -= sge_unsent;
				c_tx->sge_idx++;
				c_tx->sge_off = 0;
				sge++;
				sge_unsent = sge->length;
			}
			c_tx->sge_off += rv;
			BUG_ON(c_tx->sge_off >= sge->length);
		}
		rv = -EAGAIN;
	}
done_crc:
	c_tx->do_crc = 0;
done:
	return rv;
}

static void siw_update_tcpseg(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	struct tcp_sock *tp = tcp_sk(s->sk);

	if (tp->gso_segs) {
		if (gso_seg_limit == 0)
			c_tx->tcp_seglen =
				tp->mss_cache * tp->gso_segs;
		else
			c_tx->tcp_seglen = tp->mss_cache *
				min_t(unsigned int, gso_seg_limit,
				      tp->gso_segs);
	} else
		c_tx->tcp_seglen = tp->mss_cache;
}

/*
 * siw_unseg_txlen()
 *
 * Compute complete tcp payload len if packet would not
 * get fragmented
 */
static inline int siw_unseg_txlen(struct siw_iwarp_tx *c_tx)
{
	int pad = c_tx->bytes_unsent ? -c_tx->bytes_unsent & 0x3 : 0;

	return c_tx->bytes_unsent + c_tx->ctrl_len + pad + MPA_CRC_SIZE;
}


/*
 * siw_prepare_fpdu()
 *
 * Prepares transmit context to send out one FPDU if FPDU will contain
 * user data and user data are not immediate data.
 * Computes maximum FPDU length to fill up TCP MSS if possible.
 *
 * @qp:		QP from which to transmit
 * @wqe:	Current WQE causing transmission
 *
 * TODO: Take into account real available sendspace on socket
 *       to avoid header misalignment due to send pausing within
 *       fpdu transmission
 */
static void siw_prepare_fpdu(struct siw_qp *qp, struct siw_wqe *wqe)
{
	struct siw_iwarp_tx	*c_tx  = &qp->tx_ctx;
	int data_len;

	/*
	 * TODO: TCP Fragmentation dynamics needs for further investigation.
	 *	 Resuming SQ processing may start with full-sized packet
	 *	 or short packet which resets MSG_MORE and thus helps
	 *	 to synchronize.
	 *	 This version resumes with short packet.
	 */
	c_tx->ctrl_len = iwarp_pktinfo[__rdmap_opcode(&c_tx->pkt.ctrl)].hdr_len;
	c_tx->ctrl_sent = 0;

	/*
	 * Update target buffer offset if any
	 */
	if (!(c_tx->pkt.ctrl.ddp_rdmap_ctrl & DDP_FLAG_TAGGED))
		/* Untagged message */
		c_tx->pkt.c_untagged.ddp_mo = cpu_to_be32(wqe->processed);
	else	/* Tagged message */
		c_tx->pkt.c_tagged.ddp_to =
		    cpu_to_be64(wqe->sqe.raddr + wqe->processed);

	data_len = wqe->bytes - wqe->processed;
	if (data_len + c_tx->ctrl_len + MPA_CRC_SIZE > c_tx->tcp_seglen) {
		/* Trim DDP payload to fit into current TCP segment */
		data_len = c_tx->tcp_seglen - (c_tx->ctrl_len + MPA_CRC_SIZE);
		c_tx->pkt.ctrl.ddp_rdmap_ctrl &= ~DDP_FLAG_LAST;
		c_tx->pad = 0;
	} else {
		c_tx->pkt.ctrl.ddp_rdmap_ctrl |= DDP_FLAG_LAST;
		c_tx->pad = -data_len & 0x3;
	}
	c_tx->bytes_unsent = data_len;

	c_tx->pkt.ctrl.mpa_len =
		htons(c_tx->ctrl_len + data_len - MPA_HDR_SIZE);

	/*
	 * Init MPA CRC computation
	 */
	if (c_tx->mpa_crc_hd) {
		siw_crc_txhdr(c_tx);
		c_tx->do_crc = 1;
	}
}

/*
 * siw_check_sgl_tx()
 *
 * Check permissions for a list of SGE's (SGL).
 * A successful check will have all memory referenced
 * for transmission resolved and assigned to the WQE.
 *
 * @pd:		Protection Domain SGL should belong to
 * @wqe:	WQE to be checked
 * @perms:	requested access permissions
 *
 */

int siw_check_sgl_tx(struct siw_pd *pd, struct siw_wqe *wqe,
		     enum siw_access_flags perms)
{
	struct siw_sge		*sge = &wqe->sqe.sge[0];
	union siw_mem_resolved	*mem = &wqe->mem[0];
	int	num_sge = wqe->sqe.num_sge,
		len = 0;

	dprint(DBG_WR, "(PD%d): Enter\n", OBJ_ID(pd));

	if (unlikely(num_sge > SIW_MAX_SGE))
		return -EINVAL;

	while (num_sge-- > 0) {
		dprint(DBG_WR, "(PD%d): perms=0x%x, len=%d, sge->len=%d\n",
			OBJ_ID(pd), perms, len, sge->length);
		/*
		 * rdma verbs: do not check stag for a zero length sge
		 */
		if (sge->length &&
		    siw_check_sge(pd, sge, mem, perms, 0, sge->length) != 0) {
			len = -EINVAL;
			break;
		}
		len += sge->length;
		sge++;
		mem++;
	}
	return len;
}

/*
 * siw_qp_sq_proc_tx()
 *
 * Process one WQE which needs transmission on the wire.
 */
static int siw_qp_sq_proc_tx(struct siw_qp *qp, struct siw_wqe *wqe)
{
	struct siw_iwarp_tx	*c_tx = &qp->tx_ctx;
	struct socket		*s = qp->attrs.llp_stream_handle;
	int			rv = 0,
				burst_len = qp->tx_ctx.burst;

	if (unlikely(wqe->wr_status == SIW_WR_IDLE))
		return 0;

	if (!burst_len)
		burst_len = SQ_USER_MAXBURST;

	if (wqe->wr_status == SIW_WR_QUEUED) {
		if (!(wqe->sqe.flags & SIW_WQE_INLINE)) {
			if (tx_type(wqe) == SIW_OP_READ_RESPONSE)
				wqe->sqe.num_sge = 1;

			if (tx_type(wqe) != SIW_OP_READ &&
			    tx_type(wqe) != SIW_OP_READ_LOCAL_INV) {
				/*
				 * Reference memory to be tx'd
				 */
				rv = siw_check_sgl_tx(qp->pd, wqe,
						      SIW_MEM_LREAD);
				if (rv < 0)
					goto tx_done;

				wqe->bytes = rv;
			} else
				wqe->bytes = 0;
		} else {
			wqe->bytes = wqe->sqe.sge[0].length;
			if (!qp->kernel_verbs) {
				if (wqe->bytes > SIW_MAX_INLINE)
					return -EINVAL;
				wqe->sqe.sge[0].laddr = (u64)&wqe->sqe.sge[1];
			}
		}
		wqe->wr_status = SIW_WR_INPROGRESS;
		wqe->processed = 0;

		siw_update_tcpseg(c_tx, s);

		rv = siw_qp_prepare_tx(c_tx);
		if (rv == PKT_FRAGMENTED) {
			c_tx->state = SIW_SEND_HDR;
			siw_prepare_fpdu(qp, wqe);
		} else if (rv == PKT_COMPLETE)
			c_tx->state = SIW_SEND_SHORT_FPDU;
		else
			goto tx_done;
	}

next_segment:
	dprint(DBG_WR|DBG_TX,
		" QP(%d): WR type %d, state %d, data %u, sent %u, id %llx\n",
		QP_ID(qp), tx_type(wqe), wqe->wr_status, wqe->bytes,
		wqe->processed, wqe->sqe.id);

	if (--burst_len == 0) {
		rv = -EINPROGRESS;
		goto tx_done;
	}
	if (c_tx->state == SIW_SEND_SHORT_FPDU) {
		enum siw_opcode tx_type = tx_type(wqe);

		/*
		 * Always end current TCP segment (no MSG_MORE flag):
		 * trying to fill segment would result in excessive delay.
		 */
		rv = siw_tx_ctrl(c_tx, s, MSG_DONTWAIT);

		if (!rv && tx_type != SIW_OP_READ &&
		    tx_type != SIW_OP_READ_LOCAL_INV)
			wqe->processed = wqe->bytes;

		goto tx_done;

	} else
		rv = siw_tx_hdt(c_tx, s);

	if (!rv) {
		/*
		 * One segment sent. Processing completed if last
		 * segment, Do next segment otherwise.
		 */
		if (unlikely(c_tx->tx_suspend)) {
			/*
			 * Verbs, 6.4.: Try stopping sending after a full
			 * DDP segment if the connection goes down
			 * (== peer halfclose)
			 */
			rv = -ECONNABORTED;
			goto tx_done;
		}
		if (c_tx->pkt.ctrl.ddp_rdmap_ctrl & DDP_FLAG_LAST) {
			dprint(DBG_TX, "(QP%d): WR completed\n", QP_ID(qp));
			goto tx_done;
		}
		c_tx->state = SIW_SEND_HDR;

		siw_update_tcpseg(c_tx, s);

		siw_prepare_fpdu(qp, wqe);
		goto next_segment;
	}
tx_done:
	qp->tx_ctx.burst = burst_len;
	return rv;
}

static int siw_fastreg_mr(struct siw_pd *pd, struct siw_sqe *sqe)
{
	struct siw_mem *mem = siw_mem_id2obj(pd->hdr.sdev, sqe->rkey >> 8);
	struct siw_mr *mr;
	int rv = 0;

	dprint(DBG_MM, ": STag %u (%x) Enter\n", sqe->rkey >> 8, sqe->rkey);

	if (!mem) {
		dprint(DBG_ON, ": STag %u unknown\n", sqe->rkey >> 8);
		return -EINVAL;
	}
	mr = siw_mem2mr(mem);
	if (&mr->ofa_mr != (void *)sqe->ofa_mr) {
		dprint(DBG_ON, ": STag %u: unexpected MR\n", sqe->rkey >> 8);
		rv = -EINVAL;
		goto out;
	}
	if (mr->pd != pd) {
		dprint(DBG_ON, ": PD mismatch: %p != %p\n", mr->pd, pd);
		rv = -EINVAL;
		goto out;
	}
	if (mem->stag_valid) {
		dprint(DBG_ON, ": STag already valid: %u\n",
			sqe->rkey >> 8);
		rv = -EINVAL;
		goto out;
	}
	mem->perms = sqe->access;
	mem->stag_valid = 1;
	dprint(DBG_MM, ": STag now valid: %u\n", sqe->rkey >> 8);
out:
	siw_mem_put(mem);
	return rv;
}

static int siw_qp_sq_proc_local(struct siw_qp *qp, struct siw_wqe *wqe)
{
	int rv;

	switch (tx_type(wqe)) {

	case SIW_OP_REG_MR:
		rv = siw_fastreg_mr(qp->pd, &wqe->sqe);
		break;

	case SIW_OP_INVAL_STAG:
		rv = siw_invalidate_stag(qp->pd, wqe->sqe.rkey);
		break;

	default:
		rv = -EINVAL;
	}
	return rv;
}


/*
 * siw_qp_sq_process()
 *
 * Core TX path routine for RDMAP/DDP/MPA using a TCP kernel socket.
 * Sends RDMAP payload for the current SQ WR @wqe of @qp in one or more
 * MPA FPDUs, each containing a DDP segment.
 *
 * SQ processing may occur in user context as a result of posting
 * new WQE's or from siw_sq_work_handler() context. Processing in
 * user context is limited to non-kernel verbs users.
 *
 * SQ processing may get paused anytime, possibly in the middle of a WR
 * or FPDU, if insufficient send space is available. SQ processing
 * gets resumed from siw_sq_work_handler(), if send space becomes
 * available again.
 *
 * Must be called with the QP state read-locked.
 *
 * TODO:
 * To be solved more seriously: an outbound RREQ can be satisfied
 * by the corresponding RRESP _before_ it gets assigned to the ORQ.
 * This happens regularly in RDMA READ via loopback case. Since both
 * outbound RREQ and inbound RRESP can be handled by the same CPU
 * locking the ORQ is dead-lock prone and thus not an option.
 * Tentatively, the RREQ gets assigned to the ORQ _before_ being
 * sent (and pulled back in case of send failure).
 */
int siw_qp_sq_process(struct siw_qp *qp)
{
	struct siw_wqe		*wqe = tx_wqe(qp);
	enum siw_opcode		tx_type;
	unsigned long		flags;
	int			rv = 0;

	wait_event(qp->tx_ctx.waitq, !atomic_read(&qp->tx_ctx.in_use));

	if (atomic_inc_return(&qp->tx_ctx.in_use) > 1) {
		pr_warn("SIW: QP[%d] already active\n", QP_ID(qp));
		goto done;
	}
next_wqe:
	/*
	 * Stop QP processing if SQ state changed
	 */
	if (unlikely(qp->tx_ctx.tx_suspend)) {
		dprint(DBG_WR|DBG_TX, "(QP%d): tx suspend\n", QP_ID(qp));
		goto done;
	}
	tx_type = tx_type(wqe);

	if (tx_type <= SIW_OP_READ_RESPONSE)
		rv = siw_qp_sq_proc_tx(qp, wqe);
	else
		rv = siw_qp_sq_proc_local(qp, wqe);

	if (!rv) {
		/*
		 * WQE processing done
		 */
		switch (tx_type) {

		case SIW_OP_SEND:
		case SIW_OP_SEND_REMOTE_INV:
		case SIW_OP_WRITE:
			siw_wqe_put_mem(wqe, tx_type);
		case SIW_OP_INVAL_STAG:
		case SIW_OP_REG_MR:
			if (tx_flags(wqe) & SIW_WQE_SIGNALLED)
				siw_sqe_complete(qp, &wqe->sqe, wqe->bytes,
						 SIW_WC_SUCCESS);
			break;

		case SIW_OP_READ:
		case SIW_OP_READ_LOCAL_INV:
			/*
			 * already enqueued to ORQ queue
			 */
			break;

		case SIW_OP_READ_RESPONSE:
			siw_wqe_put_mem(wqe, tx_type);
			break;

		default:
			BUG();
		}

		spin_lock_irqsave(&qp->sq_lock, flags);
		wqe->wr_status = SIW_WR_IDLE;
		rv = siw_activate_tx(qp);
		spin_unlock_irqrestore(&qp->sq_lock, flags);

		if (unlikely(rv <= 0))
			goto done;

		goto next_wqe;

	} else if (rv == -EAGAIN) {
		dprint(DBG_WR|DBG_TX,
			"(QP%d): SQ paused: hd/tr %d of %d, data %d\n",
			QP_ID(qp), qp->tx_ctx.ctrl_sent, qp->tx_ctx.ctrl_len,
			qp->tx_ctx.bytes_unsent);
		rv = 0;
		goto done;
	} else if (rv == -EINPROGRESS) {
		siw_sq_start(qp);
		rv = 0;
		goto done;
	} else {
		/*
		 * WQE processing failed.
		 * Verbs 8.3.2:
		 * o It turns any WQE into a signalled WQE.
		 * o Local catastrophic error must be surfaced
		 * o QP must be moved into Terminate state: done by code
		 *   doing socket state change processing
		 *
		 * o TODO: Termination message must be sent.
		 * o TODO: Implement more precise work completion errors,
		 *         see enum ib_wc_status in ib_verbs.h
		 */
		dprint(DBG_ON, " (QP%d): WQE type %d processing failed: %d\n",
				QP_ID(qp), tx_type(wqe), rv);

		spin_lock_irqsave(&qp->sq_lock, flags);
		/*
		 * RREQ may have already been completed by inbound RRESP!
		 */
		if (tx_type == SIW_OP_READ ||
		    tx_type == SIW_OP_READ_LOCAL_INV) {
			/* Cleanup pending entry in ORQ */
			qp->orq_put--;
			qp->orq[qp->orq_put % qp->attrs.orq_size].flags = 0;
		}
		spin_unlock_irqrestore(&qp->sq_lock, flags);
		/*
		 * immediately suspends further TX processing
		 */
		if (!qp->tx_ctx.tx_suspend)
			siw_qp_cm_drop(qp, 0);

		switch (tx_type) {

		case SIW_OP_SEND:
		case SIW_OP_SEND_REMOTE_INV:
		case SIW_OP_SEND_WITH_IMM:
		case SIW_OP_WRITE:
		case SIW_OP_READ:
		case SIW_OP_READ_LOCAL_INV:
			siw_wqe_put_mem(wqe, tx_type);
		case SIW_OP_INVAL_STAG:
		case SIW_OP_REG_MR:
			siw_sqe_complete(qp, &wqe->sqe, wqe->bytes,
					 SIW_WC_LOC_QP_OP_ERR);

			siw_qp_event(qp, IB_EVENT_QP_FATAL);

			break;

		case SIW_OP_READ_RESPONSE:
			dprint(DBG_WR|DBG_TX|DBG_ON,
				"(QP%d): Processing RRESPONSE failed: %d\n",
				QP_ID(qp), rv);

			siw_qp_event(qp, IB_EVENT_QP_REQ_ERR);

			siw_wqe_put_mem(wqe, SIW_OP_READ_RESPONSE);

			break;

		default:
			BUG();
		}
		wqe->wr_status = SIW_WR_IDLE;
	}
done:
	atomic_dec(&qp->tx_ctx.in_use);
	wake_up(&qp->tx_ctx.waitq);

	return rv;
}

static void siw_sq_resume(struct siw_qp *qp)
{

	if (down_read_trylock(&qp->state_lock)) {
		if (likely(qp->attrs.state == SIW_QP_STATE_RTS &&
			!qp->tx_ctx.tx_suspend)) {

			int rv = siw_qp_sq_process(qp);

			up_read(&qp->state_lock);

			if (unlikely(rv < 0)) {
				pr_info("QP[%d]: SQ task failed: %d\n",
					QP_ID(qp), rv);
				if (!qp->tx_ctx.tx_suspend)
					siw_qp_cm_drop(qp, 0);
			}
		} else
			up_read(&qp->state_lock);
	} else
		pr_info("QP[%d]: Resume SQ while QP locked\n", QP_ID(qp));

	siw_qp_put(qp);
}

struct tx_task_t {
	struct llist_head active;
	wait_queue_head_t waiting;
};

DEFINE_PER_CPU(struct tx_task_t, tx_task_g);
extern struct task_struct *qp_tx_thread[];

void siw_stop_tx_thread(int nr_cpu)
{
	kthread_stop(qp_tx_thread[nr_cpu]);
	wake_up(&per_cpu(tx_task_g, nr_cpu).waiting);
}

int siw_run_sq(void *data)
{
	const int nr_cpu = (unsigned int)(long)data;
	struct llist_node *active;
	struct siw_qp *qp;
	struct tx_task_t *tx_task = &per_cpu(tx_task_g, nr_cpu);

	init_llist_head(&tx_task->active);
	init_waitqueue_head(&tx_task->waiting);

	pr_info("Started siw TX thread on CPU %u\n", nr_cpu);

	while (1) {
		struct llist_node *fifo_list = NULL;

		wait_event_interruptible(tx_task->waiting,
					 !llist_empty(&tx_task->active) ||
					 kthread_should_stop());

		if (kthread_should_stop())
			break;

		active = llist_del_all(&tx_task->active);
		/*
		 * llist_del_all returns a list with newest entry first.
		 * Re-order list for fairness among QP's.
		 */
		while (active) {
			struct llist_node *tmp = active;

			active = llist_next(active);
			tmp->next = fifo_list;
			fifo_list = tmp;
		}
		while (fifo_list) {
			qp = container_of(fifo_list, struct siw_qp, tx_list);
			fifo_list = llist_next(fifo_list);
			qp->tx_list.next = NULL;

			siw_sq_resume(qp);
		}
	}
	active = llist_del_all(&tx_task->active);
	if (active != NULL) {
		llist_for_each_entry(qp, active, tx_list) {
			qp->tx_list.next = NULL;
			siw_sq_resume(qp);
		}
	}
	pr_info("Stopped siw TX thread on CPU %u\n", nr_cpu);
	return 0;
}

int siw_sq_start(struct siw_qp *qp)
{
	int cpu = qp->cpu;

	if (tx_wqe(qp)->wr_status == SIW_WR_IDLE)
		goto out;

	dprint(DBG_TX|DBG_OBJ, "(qp%d)\n", QP_ID(qp));

	if (!cpu_online(cpu) || qp_tx_thread[cpu] == NULL)
		cpu = default_tx_cpu;

	if (unlikely(cpu < 0)) {
		WARN_ON(1);
		goto out;
	}
	if (!llist_empty(&per_cpu(tx_task_g, cpu).active)) {
		int new_cpu;

		for_each_online_cpu(new_cpu) {
			if (qp_tx_thread[new_cpu] != NULL &&
			    llist_empty(&per_cpu(tx_task_g, new_cpu).active)) {
				cpu = new_cpu;
				qp->cpu = new_cpu;
				break;
			}
		}
	}

	siw_qp_get(qp);
	llist_add(&qp->tx_list, &per_cpu(tx_task_g, cpu).active);

	wake_up(&per_cpu(tx_task_g, cpu).waiting);
out:
	return 0;
}
