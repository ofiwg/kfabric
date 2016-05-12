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

#ifndef _KFI_MSG_H_
#define _KFI_MSG_H_

#include <kfi_endpoint.h>

struct kfi_msg {
	const struct kvec       *msg_iov;
	void                    **desc;
	size_t                  iov_count;
	kfi_addr_t              addr;
	void                    *context;
	uint64_t                data;
};

struct kfi_ops_msg {
	ssize_t (*recv)(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	                kfi_addr_t src_addr, void *context);
	ssize_t (*recvv)(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	                size_t count, kfi_addr_t src_addr, void *context);
	ssize_t (*recvmsg)(struct kfid_ep *ep, const struct kfi_msg *msg,
	                uint64_t flags);
	ssize_t (*send)(struct kfid_ep *ep, const void *buf, size_t len,
	                void *desc, kfi_addr_t dest_addr, void *context);
	ssize_t (*sendv)(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	                size_t count, kfi_addr_t dest_addr, void *context);
	ssize_t (*sendmsg)(struct kfid_ep *ep, const struct kfi_msg *msg,
	                uint64_t flags);
	ssize_t (*inject)(struct kfid_ep *ep, const void *buf, size_t len,
	                kfi_addr_t dest_addr);
	ssize_t (*senddata)(struct kfid_ep *ep, const void *buf, size_t len,
	                void *desc, uint64_t data, kfi_addr_t dest_addr,
	                void *context);
	ssize_t (*injectdata)(struct kfid_ep *ep, const void *buf, size_t len,
	                uint64_t data, kfi_addr_t dest_addr);
};

static inline ssize_t
kfi_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, void *context)
{
	return ep->msg->recv(ep, buf, len, desc, src_addr, context);
}

static inline ssize_t
kfi_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc, size_t count,
                kfi_addr_t src_addr, void *context)
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
kfi_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc, size_t count,
                kfi_addr_t dest_addr, void *context)
{
	return ep->msg->sendv(ep, iov, desc, count, dest_addr, context);
}

static inline ssize_t
kfi_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	return ep->msg->sendmsg(ep, msg, flags);
}

static inline ssize_t
kfi_inject(struct kfid_ep *ep, const void *buf, size_t len, kfi_addr_t dest_addr)
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
kfi_injectdata(struct kfid_ep *ep, const void *buf, size_t len, uint64_t data,
                kfi_addr_t dest_addr)
{
	return ep->msg->injectdata(ep, buf, len, data, dest_addr);
}

#endif
