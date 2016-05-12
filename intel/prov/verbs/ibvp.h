/*
 * Copyright (c) 2015 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

/*
 * Kernel Fabric Interface (KFI) InfiniBand verbs provider.
 */

#ifndef _IBVP_H_
#define _IBVP_H_

/* hack to work around OFED 3.12-1 duplicate defs */
#define CONFIG_COMPAT_IS_KTHREAD
#include <linux/kthread.h>

#include "net/kfi/kfi_provider.h"
#include "net/kfi/debug.h"

#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_sa.h>

#include <net/kfi/fabric.h>
#include <net/kfi/fi_enosys.h>
#include <net/kfi/fi_atomic.h>
#include <net/kfi/fi_cm.h>
#include <net/kfi/fi_domain.h>
#include <net/kfi/fi_endpoint.h>
#include <net/kfi/fi_eq.h>
#include <net/kfi/fi_errno.h>
#include <net/kfi/fi_rma.h>
#include <net/kfi/fi_tagged.h>
#include <net/kfi/fi_trigger.h>
#include <net/kfi/fi_direct.h>

#define DRV_NAME		"kfip_ibverbs"
#define DRV_PFX			"[" DRV_NAME "] "

#define IBV_FABRIC_NAME		"InfiniBand"
#define IBV_PROVIDER_NAME	"ibverbs"
#define IBVP_VERSION_MAJOR	1
#define IBVP_VERSION_MINOR	0
#define IBV_PROTOCOL		1

#define IBV_MAX_MSG_SIZE	FI_FXR_MAX_MSG_SIZE
#define IBV_INJECT_SIZE		FI_FXR_INJECT_SIZE
#define IBV_TOTAL_BUFFERED_RECV	FI_FXR_TOTAL_BUFFERED_RECV
#define IBV_MR_KEY_SIZE		FI_FXR_MR_KEY_SIZE
#define IBV_CQ_DATA_SIZE	FI_FXR_CQ_DATA_SIZE

#define RDMA_MAX_RESP_RES	5
#define RDMA_MAX_INIT_DEPTH	5
#define RDMA_CONN_FLOW_CONTROL	1
#define RDMA_CONN_RETRY_COUNT	15
#define RDMA_CONN_RNR_RETRY	7

#define TIMEOUT			2000

#define SEND_WRS	10
#define RECV_WRS	10
#define DEF_SEND_SGE	1
#define DEF_RECV_SGE	1
#define DEF_INLINE_DATA 0

enum {
	DEBUG_CONNECT		= DEBUG_NEXT,
	DEBUG_MSG		= DEBUG_NEXT << 1,
};

#if 0	// XXX

struct fi_ib_fabric {
	struct fid_fabric	fabric_fid;
};

struct fi_ib_domain {
	struct fid_domain	domain_fid;
	struct ib_device	*device;
	struct ib_pd		*pd;
};

struct fi_ib_eq {
	struct fid_eq		eq_fid;
	struct fi_ib_fabric	*fab;
	struct ib_sge		sgl;
	uint64_t		flags;
	struct fi_eq_err_entry	err;
	wait_queue_head_t	sem;
	spinlock_t		lock;
	struct list_head	events;
};

struct fi_ib_cq {
	struct fid_cq		cq_fid;
	struct fi_ib_domain	*domain;
	struct fi_ib_ep		*ep;
	struct ib_cq		*cq;
	size_t			entry_size;
	uint64_t		flags;
	enum fi_cq_wait_cond	wait_cond;
	struct ib_wc		wc;
	wait_queue_head_t	sem;
	spinlock_t		lock;
	uint64_t		pending;
};

struct fi_ib_mem_desc {
	struct fid_mr		mr_fid;
	struct ib_mr		*mr;
	struct fi_ib_domain	*domain;
};

struct fi_ib_ep {
	struct fid_ep		ep_fid;
	struct list_head	node;
	struct rdma_cm_id	*id;
	enum conn_state		state;
	struct sockaddr_in	addr;
	struct fi_ib_eq		*eq;
	struct fi_ib_cq		*scq;
	struct fi_ib_cq		*rcq;
	struct fi_ib_domain	*domain;
	int			retry;
	int			inline_size;
	int			rx_wr_depth;
	int			tx_wr_depth;
	int			tx_sge_max;
	int			rx_sge_max;
	void			*context;
};

struct fi_ib_passive_ep {
	union {
	struct fid_pep		pep_fid;
	struct fid_ep		ep_fid;
	} u;
	struct list_head	node;
	struct rdma_cm_id	*id;
	enum conn_state		state;
	struct sockaddr_in	addr;
	struct fi_ib_eq		*eq;
};

struct fi_ib_event {
	struct list_head	node;
	struct rdma_cm_id	*id;
	struct rdma_cm_event	ev;
};

extern struct kmem_cache *rds_io_cachep;

static inline char *addr2str(struct sockaddr_in *dst)
{
	static char		addr[64];
	sprintf(addr, "%pI4:%d", &dst->sin_addr.s_addr, dst->sin_port);
	return addr;
}
#endif

int init_driver(void);
int cleanup_driver(void);

#if 0

int fi_ib_fabric(struct fi_fabric_attr *attr,
		 struct fid_fabric **fabric, void *context);

int fi_ib_ep_open(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep, void *context);
int fi_ib_msg_ep_reject(struct fid_pep *pep, fi_connreq_t connreq,
			const void *param, size_t paramlen);
int fi_ib_pendpoint(struct fid_fabric *fabric, struct fi_info *info,
		    struct fid_pep **pep, void *context);
int fi_ib_close(struct fid *fid);

int fi_ib_mr_reg(struct fid *fid, const void *buf, size_t len,
		 uint64_t access, uint64_t offset, uint64_t key,
		 uint64_t flags, struct fid_mr **mr, void *context);
int fi_ib_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		  struct fid_cq **cq, void *context);
int fi_ib_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		  struct fid_eq **eq, void *context);

void dump_addr(struct rdma_cm_id *id);
#endif

#endif /* _IBVP_H_ */
