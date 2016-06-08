/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
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

#include <linux/socket.h>
#include <kfi_fabric.h>
#include <kfi_domain.h>


struct kfi_msg {
	const struct iovec	*msg_iov;
	void			**desc;
	size_t			iov_count;
	kfi_addr_t		addr;
	void			*context;
	uint64_t		data;
};

/* Endpoint option levels */
enum {
	KFI_OPT_ENDPOINT
};

/* KFI_OPT_ENDPOINT option names */
enum {
	KFI_OPT_MIN_MULTI_RECV,		/* size_t */
};

struct kfi_ops_ep {
	size_t	size;
	ssize_t	(*cancel)(struct kfid *kfid, void *context);
	int	(*getopt)(struct kfid *kfid, int level, int optname,
			void *optval, size_t *optlen);
	int	(*setopt)(struct kfid *kfid, int level, int optname,
			const void *optval, size_t optlen);
	int	(*tx_ctx)(struct kfid_ep *sep, int index,
			struct kfi_tx_attr *attr, struct kfid_ep **tx_ep,
			void *context);
	int	(*rx_ctx)(struct kfid_ep *sep, int index,
			struct kfi_rx_attr *attr, struct kfid_ep **rx_ep,
			void *context);
	ssize_t (*rx_size_left)(struct kfid_ep *ep);
	ssize_t (*tx_size_left)(struct kfid_ep *ep);
};

struct kfi_ops_msg {
	size_t	size;
	ssize_t (*recv)(struct kfid_ep *ep, void *buf, size_t len, void *desc,
			kfi_addr_t src_addr, void *context);
	ssize_t (*recvv)(struct kfid_ep *ep, const struct iovec *iov,
			void **desc, size_t count, kfi_addr_t src_addr,
			void *context);
	ssize_t (*recvmsg)(struct kfid_ep *ep, const struct kfi_msg *msg,
			uint64_t flags);
	ssize_t (*send)(struct kfid_ep *ep, const void *buf, size_t len,
			void *desc, kfi_addr_t dest_addr, void *context);
	ssize_t (*sendv)(struct kfid_ep *ep, const struct iovec *iov,
			void **desc, size_t count, kfi_addr_t dest_addr,
			void *context);
	ssize_t (*sendmsg)(struct kfid_ep *ep, const struct kfi_msg *msg,
			uint64_t flags);
	ssize_t	(*inject)(struct kfid_ep *ep, const void *buf, size_t len,
			kfi_addr_t dest_addr);
	ssize_t (*senddata)(struct kfid_ep *ep, const void *buf, size_t len,
			void *desc, uint64_t data, kfi_addr_t dest_addr,
			void *context);
	ssize_t	(*injectdata)(struct kfid_ep *ep, const void *buf, size_t len,
			uint64_t data, kfi_addr_t dest_addr);
};

struct kfi_ops_cm;
struct kfi_ops_rma;
struct kfi_ops_tagged;
struct kfi_ops_atomic;
/* struct kfi_ops_collectives; */

/*
 * Calls which modify the properties of a endpoint (control, setopt, bind, ...)
 * must be serialized against all other operations.  Those calls may modify the
 * operations referenced by a endpoint in order to optimize the data transfer
 * code paths.
 *
 * A provider may allocate the minimal size structure needed to support the
 * ops requested by the user.
 */
struct kfid_ep {
	struct kfid		kfid;
	struct kfi_ops_ep	*ops;
	struct kfi_ops_cm	*cm;
	struct kfi_ops_msg	*msg;
	struct kfi_ops_rma	*rma;
	struct kfi_ops_tagged	*tagged;
	struct kfi_ops_atomic	*atomic;
};

struct kfid_pep {
	struct kfid		kfid;
	struct kfi_ops_ep	*ops;
	struct kfi_ops_cm	*cm;
};

struct kfid_stx {
	struct kfid		kfid;
	struct kfi_ops_ep	*ops;
};

#ifndef KFABRIC_DIRECT

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
kfi_scalable_ep(struct kfid_domain *domain, struct kfi_info *info,
		struct kfid_ep **sep, void *context)
{
	return domain->ops->scalable_ep(domain, info, sep, context);
}

static inline int
kfi_ep_bind(struct kfid_ep *ep, struct kfid *bkfid, uint64_t flags)
{
	return ep->kfid.ops->bind(&ep->kfid, bkfid, flags);
}

static inline int
kfi_pep_bind(struct kfid_pep *pep, struct kfid *bkfid, uint64_t flags)
{
	return pep->kfid.ops->bind(&pep->kfid, bkfid, flags);
}

static inline
int kfi_scalable_ep_bind(struct kfid_ep *sep, struct kfid *bkfid, uint64_t flags)
{
	return sep->kfid.ops->bind(&sep->kfid, bkfid, flags);
}

static inline int kfi_enable(struct kfid_ep *ep)
{
	return ep->kfid.ops->control(&ep->kfid, KFI_ENABLE, NULL);
}

static inline ssize_t kfi_cancel(struct kfid *kfid, void *context)
{
	struct kfid_ep *ep = container_of(kfid, struct kfid_ep, kfid);
	return ep->ops->cancel(kfid, context);
}

static inline int
kfi_setopt(struct kfid *kfid, int level, int optname, const void *optval,
	   size_t optlen)
{
	struct kfid_ep *ep = container_of(kfid, struct kfid_ep, kfid);
	return ep->ops->setopt(kfid, level, optname, optval, optlen);
}

static inline int
kfi_getopt(struct kfid *kfid, int level, int optname, void *optval,
	   size_t *optlen)
{
	struct kfid_ep *ep = container_of(kfid, struct kfid_ep, kfid);
	return ep->ops->getopt(kfid, level, optname, optval, optlen);
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

static inline int
kfi_stx_context(struct kfid_domain *domain, struct kfi_tx_attr *attr,
	        struct kfid_stx **stx, void *context)
{
	return domain->ops->stx_ctx(domain, attr, stx, context);
}

static inline int
kfi_srx_context(struct kfid_domain *domain, struct kfi_rx_attr *attr,
	        struct kfid_ep **rx_ep, void *context)
{
	return domain->ops->srx_ctx(domain, attr, rx_ep, context);
}

static inline ssize_t
kfi_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	 kfi_addr_t src_addr, void *context)
{
	return ep->msg->recv(ep, buf, len, desc, src_addr, context);
}

static inline ssize_t
kfi_recvv(struct kfid_ep *ep, const struct iovec *iov, void **desc,
	 size_t count, kfi_addr_t src_addr, void *context)
{
	return ep->msg->recvv(ep, iov, desc, count, src_addr, context);
}

static inline ssize_t
kfi_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	return ep->msg->recvmsg(ep, msg, flags);
}

static inline ssize_t
kfi_send(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	 kfi_addr_t dest_addr, void *context)
{
	return ep->msg->send(ep, buf, len, desc, dest_addr, context);
}

static inline ssize_t
kfi_sendv(struct kfid_ep *ep, const struct iovec *iov, void **desc,
	  size_t count, kfi_addr_t dest_addr, void *context)
{
	return ep->msg->sendv(ep, iov, desc, count, dest_addr, context);
}

static inline ssize_t
kfi_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	return ep->msg->sendmsg(ep, msg, flags);
}

static inline ssize_t
kfi_inject(struct kfid_ep *ep, const void *buf, size_t len,
	   kfi_addr_t dest_addr)
{
	return ep->msg->inject(ep, buf, len, dest_addr);
}

static inline ssize_t
kfi_senddata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
	     uint64_t data, kfi_addr_t dest_addr, void *context)
{
	return ep->msg->senddata(ep, buf, len, desc, data, dest_addr, context);
}

static inline ssize_t
kfi_injectdata(struct kfid_ep *ep, const void *buf, size_t len,
	       uint64_t data, kfi_addr_t dest_addr)
{
	return ep->msg->injectdata(ep, buf, len, data, dest_addr);
}

#else /* KFABRIC_DIRECT */
#include <kfi_direct_endpoint.h>
#endif

#endif /* _KFI_ENDPOINT_H_ */
