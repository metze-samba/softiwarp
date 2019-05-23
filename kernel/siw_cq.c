// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/list.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_cm.h"
#include "siw_debug.h"

static int map_wc_opcode[SIW_NUM_OPCODES] = {
	[SIW_OP_WRITE] = IB_WC_RDMA_WRITE,
	[SIW_OP_SEND] = IB_WC_SEND,
	[SIW_OP_SEND_WITH_IMM] = IB_WC_SEND,
	[SIW_OP_READ] = IB_WC_RDMA_READ,
	[SIW_OP_READ_LOCAL_INV] = IB_WC_RDMA_READ,
	[SIW_OP_COMP_AND_SWAP] = IB_WC_COMP_SWAP,
	[SIW_OP_FETCH_AND_ADD] = IB_WC_FETCH_ADD,
	[SIW_OP_INVAL_STAG] = IB_WC_LOCAL_INV,
	[SIW_OP_REG_MR] = IB_WC_REG_MR,
	[SIW_OP_RECEIVE] = IB_WC_RECV,
	[SIW_OP_READ_RESPONSE] = -1 /* not used */
};

static struct {
	enum siw_opcode siw;
	enum ib_wc_status ib;
} map_cqe_status[SIW_NUM_WC_STATUS] = {
	{ SIW_WC_SUCCESS, IB_WC_SUCCESS },
	{ SIW_WC_LOC_LEN_ERR, IB_WC_LOC_LEN_ERR },
	{ SIW_WC_LOC_PROT_ERR, IB_WC_LOC_PROT_ERR },
	{ SIW_WC_LOC_QP_OP_ERR, IB_WC_LOC_QP_OP_ERR },
	{ SIW_WC_WR_FLUSH_ERR, IB_WC_WR_FLUSH_ERR },
	{ SIW_WC_BAD_RESP_ERR, IB_WC_BAD_RESP_ERR },
	{ SIW_WC_LOC_ACCESS_ERR, IB_WC_LOC_ACCESS_ERR },
	{ SIW_WC_REM_ACCESS_ERR, IB_WC_REM_ACCESS_ERR },
	{ SIW_WC_REM_INV_REQ_ERR, IB_WC_REM_INV_REQ_ERR },
	{ SIW_WC_GENERAL_ERR, IB_WC_GENERAL_ERR }
};

/*
 * Reap one CQE from the CQ. Only used by kernel clients
 * during CQ normal operation. Might be called during CQ
 * flush for user mapped CQE array as well.
 */
int siw_reap_cqe(struct siw_cq *cq, struct ib_wc *wc)
{
	struct siw_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->lock, flags);

	cqe = &cq->queue[cq->cq_get % cq->num_cqe];
	if (READ_ONCE(cqe->flags) & SIW_WQE_VALID) {
		memset(wc, 0, sizeof(*wc));
		wc->wr_id = cqe->id;
		wc->status = map_cqe_status[cqe->status].ib;
		wc->opcode = map_wc_opcode[cqe->opcode];
		wc->byte_len = cqe->bytes;

		/*
		 * During CQ flush, also user land CQE's may get
		 * reaped here, which do not hold a QP reference
		 * and do not qualify for memory extension verbs.
		 */
		if (likely(cq->kernel_verbs)) {
			if (cqe->flags & SIW_WQE_REM_INVAL) {
				wc->ex.invalidate_rkey = cqe->inval_stag;
				wc->wc_flags = IB_WC_WITH_INVALIDATE;
			}
			wc->qp = cqe->base_qp;
			siw_dbg_cq(cq, "idx %u, type %d, flags %2x, id 0x%p\n",
				   cq->cq_get % cq->num_cqe, cqe->opcode,
				   cqe->flags, (void *)cqe->id);
		}
		WRITE_ONCE(cqe->flags, 0);
		cq->cq_get++;

		spin_unlock_irqrestore(&cq->lock, flags);

		return 1;
	}
	spin_unlock_irqrestore(&cq->lock, flags);

	return 0;
}

/*
 * siw_cq_flush()
 *
 * Flush all CQ elements.
 */
void siw_cq_flush(struct siw_cq *cq)
{
	struct ib_wc wc;

	siw_dbg_cq(cq, "enter\n");

	while (siw_reap_cqe(cq, &wc))
		;
}
