/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2015 NetApp, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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

#ifndef _KFI_ENDPOINT_H_
#define _KFI_ENDPOINT_H_

#include <kfi_domain.h>

/*
 * Endpoint protocol
 * If two providers support the same protocol, then they shall interoperate
 * when the protocol capabilities match.
 */
enum {
	KFI_PROTO_UNSPEC,
	KFI_PROTO_RDMA_CM_IB_RC,
	KFI_PROTO_IWARP,
	KFI_PROTO_IB_UD,
	KFI_PROTO_PSMX,
	KFI_PROTO_UDP,
	KFI_PROTO_SOCK_TCP,
};

enum {
	KFI_ORDER_NONE = 0,
	KFI_ORDER_RAR = (1 << 0),
	KFI_ORDER_RAW = (1 << 1),
	KFI_ORDER_RAS = (1 << 2),
	KFI_ORDER_WAR = (1 << 3),
	KFI_ORDER_WAW = (1 << 4),
	KFI_ORDER_WAS = (1 << 5),
	KFI_ORDER_SAR = (1 << 6),
	KFI_ORDER_SAW = (1 << 7),
	KFI_ORDER_SAS = (1 << 8),
	KFI_ORDER_STRICT = 0x1FF,
	KFI_ORDER_DATA = (1 << 16),
};

struct kfi_tx_attr {
	uint64_t                caps;
	uint64_t                mode;
	uint64_t                op_flags;
	uint64_t                msg_order;
	uint64_t                comp_order;
	size_t                  inject_size;
	size_t                  size;
	size_t                  iov_limit;
	size_t                  rma_iov_limit;
};

struct kfi_rx_attr {
	uint64_t                caps;
	uint64_t                mode;
	uint64_t                op_flags;
	uint64_t                msg_order;
	uint64_t                comp_order;
	size_t                  total_buffered_recv;
	size_t                  size;
	size_t                  iov_limit;
};

struct kfi_ep_attr {
	uint32_t                protocol;
	uint32_t                protocol_version;
	size_t                  max_msg_size;
	size_t                  msg_prefix_size;
	size_t                  max_order_raw_size;
	size_t                  max_order_war_size;
	size_t                  max_order_waw_size;
	uint64_t                mem_tag_format;
	size_t                  tx_ctx_cnt;
	size_t                  rx_ctx_cnt;
};

struct kfi_ops_ep {
	ssize_t (*cancel)(kfid_t fid, void *context);
	int (*getopt)(kfid_t fid, int level, int optname, void *optval,
	                size_t *optlen);
	int (*setopt)(kfid_t fid, int level, int optname, const void *optval,
	                size_t optlen);
	int (*tx_ctx)(struct kfid_ep *sep, int index, struct kfi_tx_attr *attr,
	                struct kfid_ep **tx_ep, void *context);
	int (*rx_ctx)(struct kfid_ep *sep, int index, struct kfi_rx_attr *attr,
	                struct kfid_ep **rx_ep, void *context);
	ssize_t (*rx_size_left)(struct kfid_ep *ep);
	ssize_t (*tx_size_left)(struct kfid_ep *ep);
};

struct kfi_ops_cm;
struct kfi_ops_msg;
struct kfi_ops_rma;
struct kfi_ops_tagged;
struct kfi_ops_atomic;

/*
 * Calls which modify the properties of a endpoint (control, setopt, bind, ...)
 * must be serialized against all other operations.  Those calls may modify the
 * operations referenced by a endpoint in order to optimize the data transfer code
 * paths.
 *
 * A provider may allocate the minimal size structure needed to support the
 * ops requested by the user.
 */
struct kfid_ep {
	struct kfid             fid;
	struct kfi_ops_ep       *ops;
	struct kfi_ops_cm       *cm;
	struct kfi_ops_msg      *msg;
	struct kfi_ops_rma      *rma;
	struct kfi_ops_tagged   *tagged;
	struct kfi_ops_atomic   *atomic;
};

struct kfid_pep {
	struct kfid             fid;
	struct kfi_ops_ep       *ops;
	struct kfi_ops_cm       *cm;
};

static inline int
kfi_passive_ep(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_pep **pep, void *context)
{
	return fabric->ops->passive_ep(fabric, info, pep, context);
}

static inline int
kfi_endpoint(struct kfid_domain *domain, struct kfi_info *info,
                struct kfid_ep **ep, void *context)
{
	return domain->ops->endpoint(domain, info, ep, context);
}

static inline int
kfi_ep_bind(struct kfid_ep *ep, struct kfid *bfid, uint64_t flags)
{
	return ep->fid.ops->bind(&ep->fid, bfid, flags);
}

static inline int
kfi_pep_bind(struct kfid_pep *pep, struct kfid *bfid, uint64_t flags)
{
	return pep->fid.ops->bind(&pep->fid, bfid, flags);
}

static inline int
kfi_enable(struct kfid_ep *ep)
{
	return ep->fid.ops->control(&ep->fid, KFI_ENABLE, NULL);
}

static inline ssize_t
kfi_cancel(kfid_t fid, void *context)
{
	struct kfid_ep *ep = container_of(fid, struct kfid_ep, fid);
	return ep->ops->cancel(fid, context);
}

static inline int
kfi_setopt(kfid_t fid, int level, int optname, const void *optval, size_t optlen)
{
	struct kfid_ep *ep = container_of(fid, struct kfid_ep, fid);
	return ep->ops->setopt(fid, level, optname, optval, optlen);
}

static inline int
kfi_getopt(kfid_t fid, int level, int optname, void *optval, size_t *optlen)
{
	struct kfid_ep *ep = container_of(fid, struct kfid_ep, fid);
	return ep->ops->getopt(fid, level, optname, optval, optlen);
}

static inline int
kfi_tx_context(struct kfid_ep *ep, int index, struct kfi_tx_attr *attr,
                struct kfid_ep **tx_ep, void *context)
{
	return ep->ops->tx_ctx(ep, index, attr, tx_ep, context);
}

static inline int
kfi_rx_context(struct kfid_ep *ep, int index, struct kfi_rx_attr *attr,
                struct kfid_ep **rx_ep, void *context)
{
	return ep->ops->rx_ctx(ep, index, attr, rx_ep, context);
}

static inline ssize_t
kfi_rx_size_left(struct kfid_ep *ep)
{
	return ep->ops->rx_size_left(ep);
}

static inline ssize_t
kfi_tx_size_left(struct kfid_ep *ep)
{
	return ep->ops->tx_size_left(ep);
}

#endif
