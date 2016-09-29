/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
 *
 * Copyright (c) 2008-2016, IBM Corporation
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
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"


#if DPRINT_MASK > 0
static char siw_qp_state_to_string[SIW_QP_STATE_COUNT][sizeof "TERMINATE"] = {
	[SIW_QP_STATE_IDLE]		= "IDLE",
	[SIW_QP_STATE_RTR]		= "RTR",
	[SIW_QP_STATE_RTS]		= "RTS",
	[SIW_QP_STATE_CLOSING]		= "CLOSING",
	[SIW_QP_STATE_TERMINATE]	= "TERMINATE",
	[SIW_QP_STATE_ERROR]		= "ERROR",
	[SIW_QP_STATE_MORIBUND]		= "MORIBUND",
	[SIW_QP_STATE_UNDEF]		= "UNDEF"
};
#endif

/*
 * iWARP (RDMAP, DDP and MPA) parameters as well as Softiwarp settings on a
 * per-RDMAP message basis. Please keep order of initializer. All MPA len
 * is initialized to minimum packet size.
 */
struct iwarp_msg_info iwarp_pktinfo[RDMAP_TERMINATE + 1] = { {
	.hdr_len = sizeof(struct iwarp_rdma_write),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_write) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_TAGGED | DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_WRITE),
	.proc_data = siw_proc_write
},
{
	.hdr_len = sizeof(struct iwarp_rdma_rreq),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_rreq) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_READ_REQ),
	.proc_data = siw_proc_rreq
},
{
	.hdr_len = sizeof(struct iwarp_rdma_rresp),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_rresp) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_TAGGED | DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_READ_RESP),
	.proc_data = siw_proc_rresp
},
{
	.hdr_len = sizeof(struct iwarp_send),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND),
	.proc_data = siw_proc_send
},
{
	.hdr_len = sizeof(struct iwarp_send_inv),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send_inv) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_INVAL),
	.proc_data = siw_proc_unsupp
},
{
	.hdr_len = sizeof(struct iwarp_send),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_SE),
	.proc_data = siw_proc_send
},
{
	.hdr_len = sizeof(struct iwarp_send_inv),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send_inv) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_SE_INVAL),
	.proc_data = siw_proc_unsupp
},
{
	.hdr_len = sizeof(struct iwarp_terminate),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_terminate) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_TERMINATE),
	.proc_data = siw_proc_terminate
} };

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
static void siw_qp_llp_data_ready(struct sock *sk, int flags)
#else
static void siw_qp_llp_data_ready(struct sock *sk)
#endif
{
	struct siw_qp		*qp;

	read_lock(&sk->sk_callback_lock);

	if (unlikely(!sk->sk_user_data || !sk_to_qp(sk))) {
		dprint(DBG_ON, " No QP: %p\n", sk->sk_user_data);
		goto done;
	}
	qp = sk_to_qp(sk);

	if (likely(!qp->rx_ctx.rx_suspend &&
		   down_read_trylock(&qp->state_lock))) {
		read_descriptor_t rd_desc = {.arg.data = qp, .count = 1};

		dprint(DBG_SK|DBG_RX, "(QP%d): "
			"state (before tcp_read_sock)=%d\n",
			QP_ID(qp), qp->attrs.state);

		if (likely(qp->attrs.state == SIW_QP_STATE_RTS))
			/*
			 * Implements data receive operation during
			 * socket callback. TCP gracefully catches
			 * the case where there is nothing to receive
			 * (not calling siw_tcp_rx_data() then).
			 */
			tcp_read_sock(sk, &rd_desc, siw_tcp_rx_data);

		dprint(DBG_SK|DBG_RX, "(QP%d): "
			"state (after tcp_read_sock)=%d\n",
			QP_ID(qp), qp->attrs.state);

		up_read(&qp->state_lock);
	} else {
		dprint(DBG_SK|DBG_RX, "(QP%d): "
			"Unable to RX: rx_suspend: %d\n",
			QP_ID(qp), qp->rx_ctx.rx_suspend);
	}
done:
	read_unlock(&sk->sk_callback_lock);
}


void siw_qp_llp_close(struct siw_qp *qp)
{
	dprint(DBG_CM, "(QP%d): Enter: SIW QP state = %s, cep=0x%p\n",
		QP_ID(qp), siw_qp_state_to_string[qp->attrs.state],
		qp->cep);

	down_write(&qp->state_lock);

	dprint(DBG_CM, "(QP%d): state locked\n", QP_ID(qp));

	qp->rx_ctx.rx_suspend = 1;
	qp->tx_ctx.tx_suspend = 1;
	qp->attrs.llp_stream_handle = NULL;

	switch (qp->attrs.state) {

	case SIW_QP_STATE_RTS:
	case SIW_QP_STATE_RTR:
	case SIW_QP_STATE_IDLE:
	case SIW_QP_STATE_TERMINATE:

		qp->attrs.state = SIW_QP_STATE_ERROR;

		break;
	/*
	 * SIW_QP_STATE_CLOSING:
	 *
	 * This is a forced close. shall the QP be moved to
	 * ERROR or IDLE ?
	 */
	case SIW_QP_STATE_CLOSING:
		if (tx_wqe(qp)->wr_status == SR_WR_IDLE)
			qp->attrs.state = SIW_QP_STATE_ERROR;
		else
			qp->attrs.state = SIW_QP_STATE_IDLE;

		break;

	default:
		dprint(DBG_CM, " No state transition needed: %d\n",
			qp->attrs.state);
		break;
	}
	siw_sq_flush(qp);
	siw_rq_flush(qp);

	/*
	 * dereference closing CEP
	 */
	if (qp->cep) {
		siw_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);
	dprint(DBG_CM, "(QP%d): Exit: SIW QP state = %s, cep=0x%p\n",
		QP_ID(qp), siw_qp_state_to_string[qp->attrs.state],
		qp->cep);
}


/*
 * socket callback routine informing about newly available send space.
 * Function schedules SQ work for processing SQ items.
 */
static void siw_qp_llp_write_space(struct sock *sk)
{
	struct siw_qp	*qp = sk_to_qp(sk);

	/*
	 * TODO:
	 * Resemble sk_stream_write_space() logic for iWARP constraints:
	 * Clear SOCK_NOSPACE only if sendspace may hold some reasonable
	 * sized FPDU.
	 */
#ifdef SIW_TX_FULLSEGS
	struct socket *sock = sk->sk_socket;
	if (sk_stream_wspace(sk) >= (int)qp->tx_ctx.fpdu_len && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);
		siw_sq_queue_work(qp);
	}
#else
	sk_stream_write_space(sk);

	if (!test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
		siw_sq_queue_work(qp);
#endif
}

static void siw_qp_socket_assoc(struct socket *s, struct siw_qp *qp)
{
	struct sock *sk = s->sk;

	write_lock_bh(&sk->sk_callback_lock);

	qp->attrs.llp_stream_handle = s;
	s->sk->sk_data_ready = siw_qp_llp_data_ready;
	s->sk->sk_write_space = siw_qp_llp_write_space;

	write_unlock_bh(&sk->sk_callback_lock);
}


static int siw_qp_readq_init(struct siw_qp *qp, int irq_size, int orq_size)
{
	dprint(DBG_CM|DBG_WR, "(QP%d): %d %d\n", QP_ID(qp), irq_size, orq_size);

	if (!irq_size)
		irq_size = 1;
	if (!orq_size)
		orq_size = 1;

	qp->attrs.irq_size = irq_size;
	qp->attrs.orq_size = orq_size;

	qp->irq = vmalloc(irq_size * sizeof(struct siw_sqe));
	if (!qp->irq) {
		dprint(DBG_ON, "(QP%d): Failed\n", QP_ID(qp));
		qp->attrs.irq_size = 0;
		return -ENOMEM;
	}
	qp->orq = vmalloc(orq_size * sizeof(struct siw_sqe));
	if (!qp->orq) {
		dprint(DBG_ON, "(QP%d): Failed\n", QP_ID(qp));
		qp->attrs.orq_size = 0;
		qp->attrs.irq_size = 0;
		vfree(qp->irq);
		return -ENOMEM;
	}
	memset(qp->irq, 0, irq_size * sizeof(struct siw_sqe));
	memset(qp->orq, 0, orq_size * sizeof(struct siw_sqe));

	return 0;
}


static void siw_send_terminate(struct siw_qp *qp)
{
	struct iwarp_terminate	pkt;

	memset(&pkt, 0, sizeof pkt);
	/*
	 * TODO: send TERMINATE
	 */
	dprint(DBG_CM, "(QP%d): Todo\n", QP_ID(qp));
}


static int siw_qp_enable_crc(struct siw_qp *qp)
{
	struct siw_iwarp_rx *c_rx = &qp->rx_ctx;
	struct siw_iwarp_tx *c_tx = &qp->tx_ctx;
	int rv = 0;

	c_tx->mpa_crc_hd.tfm = crypto_alloc_hash("crc32c", 0,
						 CRYPTO_ALG_ASYNC);
	if (IS_ERR(c_tx->mpa_crc_hd.tfm)) {
		rv = -PTR_ERR(c_tx->mpa_crc_hd.tfm);
		goto out;
	}
	c_rx->mpa_crc_hd.tfm = crypto_alloc_hash("crc32c", 0,
						 CRYPTO_ALG_ASYNC);
	if (IS_ERR(c_rx->mpa_crc_hd.tfm)) {
		rv = -PTR_ERR(c_rx->mpa_crc_hd.tfm);
		crypto_free_hash(c_tx->mpa_crc_hd.tfm);
	}
out:
	if (rv)
		dprint(DBG_ON, "(QP%d): Failed loading crc32c: error=%d.",
			QP_ID(qp), rv);
	else
		c_tx->crc_enabled = c_rx->crc_enabled = 1;

	return rv;
}


/*
 * caller holds qp->state_lock
 */
int
siw_qp_modify(struct siw_qp *qp, struct siw_qp_attrs *attrs,
	      enum siw_qp_attr_mask mask)
{
	int	drop_conn = 0, rv = 0;

	if (!mask)
		return 0;

	dprint(DBG_CM, "(QP%d)\n", QP_ID(qp));

	if (mask != SIW_QP_ATTR_STATE) {
		/*
		 * changes of qp attributes (maybe state, too)
		 */
		if (mask & SIW_QP_ATTR_ACCESS_FLAGS) {

			if (attrs->flags & SIW_RDMA_BIND_ENABLED)
				qp->attrs.flags |= SIW_RDMA_BIND_ENABLED;
			else
				qp->attrs.flags &= ~SIW_RDMA_BIND_ENABLED;

			if (attrs->flags & SIW_RDMA_WRITE_ENABLED)
				qp->attrs.flags |= SIW_RDMA_WRITE_ENABLED;
			else
				qp->attrs.flags &= ~SIW_RDMA_WRITE_ENABLED;

			if (attrs->flags & SIW_RDMA_READ_ENABLED)
				qp->attrs.flags |= SIW_RDMA_READ_ENABLED;
			else
				qp->attrs.flags &= ~SIW_RDMA_READ_ENABLED;

		}
		/*
		 * TODO: what else ??
		 */
	}
	if (!(mask & SIW_QP_ATTR_STATE))
		return 0;

	dprint(DBG_CM, "(QP%d): SIW QP state: %s => %s\n", QP_ID(qp),
		siw_qp_state_to_string[qp->attrs.state],
		siw_qp_state_to_string[attrs->state]);


	switch (qp->attrs.state) {

	case SIW_QP_STATE_IDLE:
	case SIW_QP_STATE_RTR:

		switch (attrs->state) {

		case SIW_QP_STATE_RTS:

			if (attrs->mpa.crc) {
				rv = siw_qp_enable_crc(qp);
				if (rv)
					break;
			}
			if (!(mask & SIW_QP_ATTR_LLP_HANDLE)) {
				dprint(DBG_ON, "(QP%d): socket?\n", QP_ID(qp));
				rv = -EINVAL;
				break;
			}
			if (!(mask & SIW_QP_ATTR_MPA)) {
				dprint(DBG_ON, "(QP%d): MPA?\n", QP_ID(qp));
				rv = -EINVAL;
				break;
			}
			dprint(DBG_CM, "(QP%d): Enter RTS: "
				"peer 0x%08x, local 0x%08x\n", QP_ID(qp),
				qp->cep->llp.raddr.sin_addr.s_addr,
				qp->cep->llp.laddr.sin_addr.s_addr);
			/*
			 * Initialize global iWARP TX state
			 */
			qp->tx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_SEND] = 0;
			qp->tx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ] = 0;
			qp->tx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_TERMINATE] = 0;

			/*
			 * Initialize global iWARP RX state
			 */
			qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_SEND] = 1;
			qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ] = 1;
			qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_TERMINATE] = 1;

			/*
			 * init IRD free queue, caller has already checked
			 * limits.
			 */
			rv = siw_qp_readq_init(qp, attrs->irq_size,
					       attrs->orq_size);
			if (rv)
				break;

			qp->attrs.mpa = attrs->mpa;
			/*
			 * move socket rx and tx under qp's control
			 */
			siw_qp_socket_assoc(attrs->llp_stream_handle, qp);

			qp->attrs.state = SIW_QP_STATE_RTS;
			/*
			 * set initial mss
			 */
			qp->tx_ctx.tcp_seglen =
				get_tcp_mss(attrs->llp_stream_handle->sk);

			break;

		case SIW_QP_STATE_ERROR:
			siw_rq_flush(qp);
			qp->attrs.state = SIW_QP_STATE_ERROR;
			if (qp->cep) {
				siw_cep_put(qp->cep);
				qp->cep = NULL;
			}
			break;

		case SIW_QP_STATE_RTR:
			/* ignore */
			break;

		default:
			dprint(DBG_CM,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case SIW_QP_STATE_RTS:

		switch (attrs->state) {

		case SIW_QP_STATE_CLOSING:
			/*
			 * Verbs: move to IDLE if SQ and ORQ are empty.
			 * Move to ERROR otherwise. But first of all we must
			 * close the connection. So we keep CLOSING or ERROR
			 * as a transient state, schedule connection drop work
			 * and wait for the socket state change upcall to
			 * come back closed.
			 */
			if (tx_wqe(qp)->wr_status == SR_WR_IDLE)
				qp->attrs.state = SIW_QP_STATE_CLOSING;
			else {
				qp->attrs.state = SIW_QP_STATE_ERROR;
				siw_sq_flush(qp);
			}
			siw_rq_flush(qp);

			drop_conn = 1;
			break;

		case SIW_QP_STATE_TERMINATE:
			qp->attrs.state = SIW_QP_STATE_TERMINATE;
			siw_send_terminate(qp);
			drop_conn = 1;

			break;

		case SIW_QP_STATE_ERROR:
			/*
			 * This is an emergency close.
			 *
			 * Any in progress transmit operation will get
			 * cancelled.
			 * This will likely result in a protocol failure,
			 * if a TX operation is in transit. The caller
			 * could unconditional wait to give the current
			 * operation a chance to complete.
			 * Esp., how to handle the non-empty IRQ case?
			 * The peer was asking for data transfer at a valid
			 * point in time.
			 */
			siw_sq_flush(qp);
			siw_rq_flush(qp);
			qp->attrs.state = SIW_QP_STATE_ERROR;
			drop_conn = 1;

			break;

		default:
			dprint(DBG_ON,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case SIW_QP_STATE_TERMINATE:

		switch (attrs->state) {

		case SIW_QP_STATE_ERROR:
			siw_rq_flush(qp);
			qp->attrs.state = SIW_QP_STATE_ERROR;

			if (tx_wqe(qp)->wr_status != SR_WR_IDLE)
				siw_sq_flush(qp);

			break;

		default:
			dprint(DBG_ON,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
		}
		break;

	case SIW_QP_STATE_CLOSING:

		switch (attrs->state) {

		case SIW_QP_STATE_IDLE:
			BUG_ON(tx_wqe(qp)->wr_status != SR_WR_IDLE);
			qp->attrs.state = SIW_QP_STATE_IDLE;

			break;

		case SIW_QP_STATE_CLOSING:
			/*
			 * The LLP may already moved the QP to closing
			 * due to graceful peer close init
			 */
			break;

		case SIW_QP_STATE_ERROR:
			/*
			 * QP was moved to CLOSING by LLP event
			 * not yet seen by user.
			 */
			qp->attrs.state = SIW_QP_STATE_ERROR;

			if (tx_wqe(qp)->wr_status != SR_WR_IDLE)
				siw_sq_flush(qp);

			siw_rq_flush(qp);

			break;

		default:
			dprint(DBG_CM,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			return -ECONNABORTED;
		}
		break;

	default:
		dprint(DBG_CM, " NOP: State: %d\n", qp->attrs.state);
		break;
	}
	if (drop_conn)
		siw_qp_cm_drop(qp, 0);

	return rv;
}

struct ib_qp *siw_get_ofaqp(struct ib_device *ofa_dev, int id)
{
	struct siw_qp *qp =  siw_qp_id2obj(siw_dev_ofa2siw(ofa_dev), id);

	dprint(DBG_OBJ, ": dev_name: %s, OFA QPID: %d, QP: %p\n",
		ofa_dev->name, id, qp);
	if (qp) {
		/*
		 * siw_qp_id2obj() increments object reference count
		 */
		siw_qp_put(qp);
		dprint(DBG_OBJ, " QPID: %d\n", QP_ID(qp));
		return &qp->ofa_qp;
	}
	return (struct ib_qp *)NULL;
}

/*
 * siw_check_mem()
 *
 * Check protection domain, STAG state, access permissions and
 * address range for memory object.
 *
 * @pd:		Protection Domain memory should belong to
 * @mem:	memory to be checked
 * @addr:	starting addr of mem
 * @perms:	requested access permissions
 * @len:	len of memory interval to be checked
 *
 */
int siw_check_mem(struct siw_pd *pd, struct siw_mem *mem, u64 addr,
		  enum siw_access_flags perms, int len)
{
	if (siw_mem2mr(mem)->pd != pd) {
		dprint(DBG_WR|DBG_ON, "(PD%d): PD mismatch %p : %p\n",
			OBJ_ID(pd),
			siw_mem2mr(mem)->pd, pd);

		return -EINVAL;
	}
	if (mem->stag_state == STAG_INVALID) {
		dprint(DBG_WR|DBG_ON, "(PD%d): STAG 0x%08x invalid\n",
			OBJ_ID(pd), OBJ_ID(mem));
		return -EPERM;
	}
	/*
	 * check access permissions
	 */
	if ((mem->perms & perms) < perms) {
		dprint(DBG_WR|DBG_ON, "(PD%d): "
			"INSUFFICIENT permissions 0x%08x : 0x%08x\n",
			OBJ_ID(pd), mem->perms, perms);
		return -EPERM;
	}
	/*
	 * Check address interval: we relax check to allow memory shrinked
	 * from the start address _after_ placing or fetching len bytes.
	 * TODO: this relaxation is probably overdone
	 */
	if (addr < mem->va || addr + len > mem->va + mem->len) {
		dprint(DBG_WR|DBG_ON, "(PD%d): MEM interval len %d "
			"[0x%016llx, 0x%016llx) out of bounds "
			"[0x%016llx, 0x%016llx) for LKey=0x%08x\n",
			OBJ_ID(pd), len, (unsigned long long)addr,
			(unsigned long long)(addr + len),
			(unsigned long long)mem->va,
			(unsigned long long)(mem->va + mem->len),
			OBJ_ID(mem));

		return -EINVAL;
	}
	return 0;
}

/*
 * siw_check_sge()
 *
 * Check SGE for access rights in given interval
 *
 * @pd:		Protection Domain memory should belong to
 * @sge:	SGE to be checked
 * @mem:	resulting memory reference if successful
 * @perms:	requested access permissions
 * @off:	starting offset in SGE
 * @len:	len of memory interval to be checked
 *
 * NOTE: Function references SGE's memory object (mem->obj)
 * if not yet done. New reference is kept if check went ok and
 * released if check failed. If mem->obj is already valid, no new
 * lookup is being done and mem is not released it check fails.
 */
int
siw_check_sge(struct siw_pd *pd, struct siw_sge *sge,
	      union siw_mem_resolved *mem, enum siw_access_flags perms,
	      u32 off, int len)
{
	struct siw_dev	*sdev = pd->hdr.sdev;
	int		new_ref = 0, rv = 0;

	if (len + off > sge->length) {
		rv = -EPERM;
		goto fail;
	}
	if (mem->obj == NULL) {
		mem->obj = siw_mem_id2obj(sdev, sge->lkey >> 8);
		if (mem->obj == NULL) {
			rv = -EINVAL;
			goto fail;
		}
		new_ref = 1;
	}

	rv = siw_check_mem(pd, mem->obj, sge->laddr + off, perms, len);
	if (rv)
		goto fail;

	return 0;

fail:
	if (new_ref) {
		siw_mem_put(mem->obj);
		mem->obj = NULL;
	}
	return rv;
}

void siw_read_to_orq(struct siw_sqe *rreq, struct siw_sqe *sqe)
{
	rreq->id = sqe->id;
	rreq->opcode = SIW_OP_READ;
	rreq->sge[0].laddr = sqe->sge[0].laddr;
	rreq->sge[0].length = sqe->sge[0].length;
	rreq->sge[0].lkey = sqe->sge[0].lkey;
	rreq->flags = sqe->flags | SIW_WQE_VALID;
	rreq->num_sge = 1;
}


/*
 * Must be called with SQ locked
 */
int siw_activate_tx(struct siw_qp *qp)
{
	struct siw_sqe	*sqe;
	struct siw_wqe	*wqe = tx_wqe(qp);
	int rv = 1;

	if (unlikely(wqe->wr_status != SR_WR_IDLE)) {
		WARN_ON(1);
		return -1;
	}
	/*
	 * This codes prefers pending READ Responses over SQ processing
	 */
	sqe = &qp->irq[qp->irq_get % qp->attrs.irq_size];

	if (sqe->flags & SIW_WQE_VALID) {
		memset(wqe->mem, 0, sizeof *wqe->mem * SIW_MAX_SGE);
		wqe->wr_status = SR_WR_QUEUED;

		/* start READ RESPONSE */
		wqe->sqe.opcode = SIW_OP_READ_RESPONSE;
		wqe->sqe.flags = 0;
		wqe->sqe.num_sge = 1;
		wqe->sqe.sge[0].length = sqe->sge[0].length;
		wqe->sqe.sge[0].laddr = sqe->sge[0].laddr;
		wqe->sqe.sge[0].lkey = sqe->sge[0].lkey;
		wqe->sqe.rkey = sqe->rkey;
		wqe->sqe.raddr = sqe->raddr;

		wqe->processed = 0;
		qp->irq_get++;
		set_mb(sqe->flags, 0);

		goto out;
	} 

	sqe = sq_get_next(qp);
	if (sqe) {
		unsigned long flags;

		memset(wqe->mem, 0, sizeof *wqe->mem * SIW_MAX_SGE);
		wqe->wr_status = SR_WR_QUEUED;

		/* First copy SQE to kernel private memory */
		memcpy(&wqe->sqe, sqe, sizeof *sqe);

		if (wqe->sqe.opcode > SIW_OP_SEND) {
			rv = -EINVAL;
			goto out;
		}

		if (wqe->sqe.flags & SIW_WQE_INLINE) {
			if (wqe->sqe.opcode != SIW_OP_SEND && 
			    wqe->sqe.opcode != SIW_OP_WRITE) {
				rv = -EINVAL;
				goto out;
			}
			if (wqe->sqe.sge[0].length > SIW_MAX_INLINE) {
				rv = -EINVAL;
				goto out;
			}
			wqe->sqe.sge[0].laddr = (u64)&wqe->sqe.sge[1];
			wqe->sqe.sge[0].lkey = 0;
			wqe->sqe.num_sge = 1;
		}
		
		if (wqe->sqe.flags & SIW_WQE_READ_FENCE) {
			/* Only WRITE and SEND can be READ fenced */
			if (unlikely(wqe->sqe.opcode != SIW_OP_WRITE &&
				     wqe->sqe.opcode != SIW_OP_SEND)) {
				pr_info("QP[%d]: cannot fence %d\n",
					QP_ID(qp), wqe->sqe.opcode);
				rv = -EINVAL;
				goto out;
			}
			lock_orq_rxsave(qp, flags);

			if (!siw_orq_empty(qp)) {
				qp->tx_ctx.orq_fence = 1;
				rv = 0;
			}
			unlock_orq_rxsave(qp, flags);

		} else if (wqe->sqe.opcode == SIW_OP_READ) {
			struct siw_sqe	*rreq;

			wqe->sqe.num_sge = 1;

			lock_orq_rxsave(qp, flags);

			rreq = orq_get_free(qp);
			if (rreq) {
				/*
				 * Make an immediate copy in ORQ to be ready
				 * to process loopback READ reply
				 */
				siw_read_to_orq(rreq, &wqe->sqe);
				qp->orq_put++;
			} else {
				qp->tx_ctx.orq_fence = 1;
				rv = 0;
			}
			unlock_orq_rxsave(qp, flags);
		}

		/* Clear SQE, can be re-used by application */
		set_mb(sqe->flags, 0);
		qp->sq_get++;
	} else
		rv = 0;
	
out:
	if (unlikely(rv < 0)) {
		pr_warn("QP[%d]: error %d in activate_tx\n", QP_ID(qp), rv);
		wqe->wr_status = SR_WR_IDLE;
	}
	return rv;
}

static const u32 crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static u32 crc32_calc_buffer(const u8 *buf, size_t size)
{
	const u8 *p;
	u32 crc;

	p = buf;
	crc = ~0U;

	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

int siw_crc_array(struct hash_desc *desc, u8 *start, size_t len)
{
	struct scatterlist sg;
	u32 crc;
len -= 4;
	dprint(DBG_CRC, ": calling crypto_hash_update() len=%zu\n", len);
	dprint_hex_dump(DBG_CRC, start, len);

	crc = crc32_calc_buffer(start, len);
	dprint(DBG_CRC, ": crc32_calc_buffer() len=%zu\n", len);
	dprint_hex_dump(DBG_CRC, (u8 *)&crc, 4);

	sg_init_one(&sg, start, len);
	return crypto_hash_update(desc, &sg, len);
}

int siw_crc_page(struct hash_desc *desc, struct page *p, int off, int len)
{
	int rv;
	struct scatterlist t_sg;

	dprint(DBG_CRC, "%s: calling crypto_hash_update()", __func__);
	//dprint_hex_dump(DBG_CRC, start, len);
	sg_init_table(&t_sg, 1);
	sg_set_page(&t_sg, p, len, off);
	rv = crypto_hash_update(desc, &t_sg, len);

	return rv;
}

static void siw_cq_notify(struct siw_cq *cq, u32 flags)
{
	u32 cq_notify;

	if (unlikely(!cq->ofa_cq.comp_handler))
		return;

	cq_notify = _load_shared(*cq->notify);

	if ((cq_notify & SIW_NOTIFY_NEXT_COMPLETION) || 
	    ((cq_notify & SIW_NOTIFY_SOLICITED) &&
	     (flags & SIW_WQE_SOLICITED))) {
		set_mb(*cq->notify, SIW_NOTIFY_NOT);
		(*cq->ofa_cq.comp_handler)(&cq->ofa_cq, cq->ofa_cq.cq_context);
	}
}

int siw_sqe_complete(struct siw_qp *qp, struct siw_sqe *sqe, u32 bytes,
		     enum siw_wc_status status)
{
	struct siw_cq *cq = qp->scq;
	struct siw_cqe *cqe;
	unsigned long flags;
	u32 idx;
	int rv = 0;

	if (cq) {
		u32 sqe_flags = sqe->flags;

		lock_cq_rxsave(cq, flags);

		idx = cq->cq_put % cq->num_cqe;
		cqe = &cq->queue[idx];

		if (!cqe->flags) {
			cqe->id = sqe->id;
			cqe->opcode = sqe->opcode;
			cqe->status = status;
			cqe->imm_data = 0;
			cqe->bytes = bytes;

			if (cq->kernel_verbs) {
				siw_qp_get(qp);
				cqe->qp = qp;
			} else
				cqe->qp_id = QP_ID(qp);

			set_mb(cqe->flags, SIW_WQE_VALID);
			set_mb(sqe->flags, 0);

			cq->cq_put++;
			unlock_cq_rxsave(cq, flags);
			siw_cq_notify(cq, sqe_flags);
		} else {
			unlock_cq_rxsave(cq, flags);
			rv = -ENOMEM;
			siw_cq_event(cq, IB_EVENT_CQ_ERR);
		}
	} else
		set_mb(sqe->flags, 0);

	return rv;
}

int siw_rqe_complete(struct siw_qp *qp, struct siw_rqe *rqe, u32 bytes,
		     enum siw_wc_status status)
{
	struct siw_cq *cq = qp->rcq;
	struct siw_cqe *cqe;
	unsigned long flags;
	u32 idx;
	int rv = 0;

	if (cq) {
		u32 rqe_flags = rqe->flags;

		lock_cq_rxsave(cq, flags);

		idx = cq->cq_put % cq->num_cqe;
		cqe = &cq->queue[idx];

		if (!cqe->flags) {
			cqe->id = rqe->id;
			cqe->opcode = SIW_OP_RECEIVE;
			cqe->status = status;
			cqe->imm_data = 0;
			cqe->bytes = bytes;

			if (cq->kernel_verbs) {
				siw_qp_get(qp);
				cqe->qp = qp;
			} else
				cqe->qp_id = QP_ID(qp);

			set_mb(cqe->flags, SIW_WQE_VALID);
			set_mb(rqe->flags, 0);

			cq->cq_put++;
			unlock_cq_rxsave(cq, flags);
			siw_cq_notify(cq, rqe_flags);
		} else {
			unlock_cq_rxsave(cq, flags);
			rv = -ENOMEM;
			siw_cq_event(cq, IB_EVENT_CQ_ERR);
		}
	} else
		set_mb(rqe->flags, 0);

	return rv;
}

/*
 * siw_sq_flush()
 *
 * Flush SQ and ORRQ entries to CQ.
 * IRRQ entries are silently dropped.
 *
 * TODO: Add termination code for in-progress WQE.
 * TODO: an in-progress WQE may have been partially
 *       processed. It should be enforced, that transmission
 *       of a started DDP segment must be completed if possible
 *       by any chance.
 *
 * Must be called with qp state write lock held.
 * Therefore, SQ and ORQ lock must not be taken.
 */
void siw_sq_flush(struct siw_qp *qp)
{
	struct siw_sqe	*sqe;
	struct siw_wqe	*wqe = tx_wqe(qp);
	unsigned long	flags;
	int		async_event = 0;

	dprint(DBG_OBJ|DBG_CM|DBG_WR, "(QP%d): Enter\n", QP_ID(qp));
	/*
	 * Start with completing any work currently on the ORQ
	 */
	lock_orq_rxsave(qp, flags);

	while (qp->attrs.orq_size) {
		sqe = &qp->orq[qp->orq_get % qp->attrs.orq_size];
		if (!sqe->flags)
			break;

		if (siw_sqe_complete(qp, sqe, 0,
				     SIW_WC_WR_FLUSH_ERR) != 0)
			break;

		qp->orq_get++;
	}
	unlock_orq_rxsave(qp, flags);
	/*
	 * Flush the in-progress wqe, if there.
	 */
	if (wqe->wr_status != SR_WR_IDLE) {
		/*
		 * TODO: Add iWARP Termination code
		 */
		dprint(DBG_WR,
			" (QP%d): Flush current WQE %p, type %d, status %d\n",
			QP_ID(qp), wqe, tx_type(wqe), wqe->wr_status);

		siw_wqe_put_mem(wqe, wqe->sqe.opcode);

		if (wqe->sqe.opcode != SIW_OP_READ_RESPONSE &&
		    (wqe->sqe.opcode != SIW_OP_READ ||
		     wqe->wr_status == SR_WR_QUEUED))
			/*
			 * An in-progress RREQUEST is already in
			 * the ORQ
			 */
			siw_sqe_complete(qp, &wqe->sqe, wqe->bytes,
					 SIW_WC_WR_FLUSH_ERR);

		wqe->wr_status = SR_WR_IDLE;
	}
	/*
	 * Flush the Send Queue
	 */
	while (qp->attrs.sq_size) {
		sqe = &qp->sendq[qp->sq_get % qp->attrs.sq_size];
		if (!sqe->flags)
			break;

		async_event = 1;
		if (siw_sqe_complete(qp, sqe, 0, SIW_WC_WR_FLUSH_ERR) != 0)
			/* Shall IB_EVENT_SQ_DRAINED be supressed ? */
			break;

		sqe->flags = 0;
		qp->sq_get++;
	}
	if (async_event)
		siw_qp_event(qp, IB_EVENT_SQ_DRAINED);
}

/*
 * siw_rq_flush()
 *
 * Flush recv queue entries to cq. An in-progress WQE may have some bytes
 * processed (wqe->processed).
 *
 * Must be called with qp state write lock held.
 * Therefore, RQ lock must not be taken.
 */
void siw_rq_flush(struct siw_qp *qp)
{
	struct siw_wqe		*wqe = rx_wqe(qp);

	dprint(DBG_OBJ|DBG_CM|DBG_WR, "(QP%d): Enter\n", QP_ID(qp));

	/*
	 * Flush an in-progess WQE if present
	 */
	if (wqe->wr_status != SR_WR_IDLE) {
		if (__rdmap_opcode(&qp->rx_ctx.hdr.ctrl) != RDMAP_RDMA_WRITE) {
			siw_wqe_put_mem(wqe, SIW_OP_RECEIVE);
			siw_rqe_complete(qp, &wqe->rqe, wqe->bytes,
					 SIW_WC_WR_FLUSH_ERR);
		} else
			siw_mem_put(rx_mem(qp));

		wqe->wr_status = SR_WR_IDLE;
	}

	while (qp->recvq && qp->attrs.rq_size) {
		struct siw_rqe *rqe =
			&qp->recvq[qp->rq_get % qp->attrs.rq_size];

		if (!rqe->flags)
			break;

		if (siw_rqe_complete(qp, rqe, 0, SIW_WC_WR_FLUSH_ERR) != 0)
			break;
		rqe->flags = 0;

		qp->rq_get++;
	}
}
