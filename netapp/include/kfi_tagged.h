/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2015 NetApp, Inc.  All rights reserved.
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

#ifndef _KFI_TAGGED_H_
#define _KFI_TAGGED_H_

#include <kfi_endpoint.h>

enum {
	KFI_DISCARD = (1ULL << 58),
	KFI_CLAIM = (1ULL << 59),
};

struct kfi_msg_tagged {
	const struct kvec       *msg_iov;
	void                    **desc;
	size_t                  iov_count;
	kfi_addr_t              addr;
	uint64_t                tag;
	uint64_t                ignore;
	void                    *context;
	uint64_t                data;
};

struct kfi_ops_tagged {
	ssize_t (*recv)(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	                        kfi_addr_t src_addr, uint64_t tag, uint64_t ignore,
	                        void *context);
	ssize_t (*recvv)(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	                        size_t count, kfi_addr_t src_addr, uint64_t tag,
	                        uint64_t ignore, void *context);
	ssize_t (*recvmsg)(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
	                        uint64_t flags);
	ssize_t (*send)(struct kfid_ep *ep, const void *buf, size_t len,
	                        void *desc, kfi_addr_t dest_addr, uint64_t tag,
	                        void *context);
	ssize_t (*sendv)(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	                        size_t count, kfi_addr_t dest_addr, uint64_t tag,
	                        void *context);
	ssize_t (*sendmsg)(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
	                        uint64_t flags);
	ssize_t (*inject)(struct kfid_ep *ep, const void *buf, size_t len,
	                        kfi_addr_t dest_addr, uint64_t tag);
	ssize_t (*senddata)(struct kfid_ep *ep, const void *buf, size_t len,
	                        void *desc, uint64_t data, kfi_addr_t dest_addr,
	                        uint64_t tag, void *context);
	ssize_t (*injectdata)(struct kfid_ep *ep, const void *buf, size_t len,
	                        uint64_t data, kfi_addr_t dest_addr, uint64_t tag);
};

static inline ssize_t
kfi_trecv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context)
{
	return ep->tagged->recv(ep, buf, len, desc, src_addr, tag, ignore,
	                       context);
}

static inline ssize_t
kfi_trecvv(struct kfid_ep *ep, const struct kvec *iov, void **desc, size_t count,
                kfi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context)
{
	return ep->tagged->recvv(ep, iov, desc, count, src_addr, tag, ignore,
	                       context);
}

static inline ssize_t
kfi_trecvmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg, uint64_t flags)
{
	return ep->tagged->recvmsg(ep, msg, flags);
}

static inline ssize_t
kfi_tsend(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                kfi_addr_t dest_addr, uint64_t tag, void *context)
{
	return ep->tagged->send(ep, buf, len, desc, dest_addr, tag, context);
}

static inline ssize_t
kfi_tsendv(struct kfid_ep *ep, const struct kvec *iov, void **desc, size_t count,
                kfi_addr_t dest_addr, uint64_t tag, void *context)
{
	return ep->tagged->sendv(ep, iov, desc, count, dest_addr,tag, context);
}

static inline ssize_t
kfi_tsendmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg, uint64_t flags)
{
	return ep->tagged->sendmsg(ep, msg, flags);
}

static inline ssize_t
kfi_tinject(struct kfid_ep *ep, const void *buf, size_t len, kfi_addr_t dest_addr,
                uint64_t tag)
{
	return ep->tagged->inject(ep, buf, len, dest_addr, tag);
}

static inline ssize_t
kfi_tsenddata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                uint64_t data, kfi_addr_t dest_addr, uint64_t tag, void *context)
{
	return ep->tagged->senddata(ep, buf, len, desc, data, dest_addr, tag,
	                       context);
}

static inline ssize_t
kfi_tinjectdata(struct kfid_ep *ep, const void *buf, size_t len, uint64_t data,
                kfi_addr_t dest_addr, uint64_t tag)
{
	return ep->tagged->injectdata(ep, buf, len, data, dest_addr, tag);
}

#endif
