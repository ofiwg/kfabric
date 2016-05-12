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

#ifndef _KFI_RMA_H_
#define _KFI_RMA_H_

#include <kfi_endpoint.h>

struct kfi_rma_iov {
	uint64_t                addr;
	size_t                  len;
	uint64_t                key;
};

struct kfi_msg_rma {
	const struct kvec       *msg_iov;
	void                    **desc;
	size_t                  iov_count;
	kfi_addr_t              addr;
	const struct kfi_rma_iov *rma_iov;
	size_t                  rma_iov_count;
	void                    *context;
	uint64_t                data;
};

struct kfi_ops_rma {
	ssize_t (*read)(struct kfid_ep *ep, void *buf, size_t len, void *desc,
	                kfi_addr_t src_addr, uint64_t addr, uint64_t key,
	                void *context);
	ssize_t (*readv)(struct kfid_ep *ep, const struct kvec *iov, void **desc,
	                size_t count, kfi_addr_t src_addr, uint64_t addr,
	                uint64_t key, void *context);
	ssize_t (*readmsg)(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
	                uint64_t flags);
	ssize_t (*write)(struct kfid_ep *ep, const void *buf, size_t len,
	                void *desc, kfi_addr_t dest_addr, uint64_t addr,
	                uint64_t key, void *context);
	ssize_t (*writev)(struct kfid_ep *ep, const struct kvec *iov,
	                void **desc, size_t count, kfi_addr_t dest_addr,
	                uint64_t addr, uint64_t key, void *context);
	ssize_t (*writemsg)(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
	                uint64_t flags);
	ssize_t (*inject)(struct kfid_ep *ep, const void *buf, size_t len,
	                kfi_addr_t dest_addr, uint64_t addr, uint64_t key);
	ssize_t (*writedata)(struct kfid_ep *ep, const void *buf, size_t len,
	                void *desc, uint64_t data, kfi_addr_t dest_addr,
	                uint64_t addr, uint64_t key, void *context);
	ssize_t (*injectdata)(struct kfid_ep *ep, const void *buf, size_t len,
	                uint64_t data, kfi_addr_t dest_addr, uint64_t addr,
	                uint64_t key);
};

static inline ssize_t
kfi_read(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
	return ep->rma->read(ep, buf, len, desc, src_addr, addr, key, context);
}

static inline ssize_t
kfi_readv(struct kfid_ep *ep, const struct kvec *iov, void **desc, size_t count,
                kfi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
	return ep->rma->readv(ep, iov, desc, count, src_addr, addr, key, context);
}

static inline ssize_t
kfi_readmsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg, uint64_t flags)
{
	return ep->rma->readmsg(ep, msg, flags);
}

static inline ssize_t
kfi_write(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	return ep->rma->write(ep, buf, len, desc, dest_addr, addr, key, context);
}

static inline ssize_t
kfi_writev(struct kfid_ep *ep, const struct kvec *iov, void **desc, size_t count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	return ep->rma->writev(ep, iov, desc, count, dest_addr, addr, key,
	                       context);
}

static inline ssize_t
kfi_writemsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg, uint64_t flags)
{
	return ep->rma->writemsg(ep, msg, flags);
}

static inline ssize_t
kfi_inject_write(struct kfid_ep *ep, const void *buf, size_t len,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	return ep->rma->inject(ep, buf, len, dest_addr, addr, key);
}

static inline ssize_t
kfi_writedata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                uint64_t data, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                void *context)
{
	return ep->rma->writedata(ep, buf, len, desc,data, dest_addr, addr, key,
	                       context);
}

static inline ssize_t
kfi_inject_writedata(struct kfid_ep *ep, const void *buf, size_t len,
                uint64_t data, kfi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	return ep->rma->injectdata(ep, buf, len, data, dest_addr, addr, key);
}

#endif
