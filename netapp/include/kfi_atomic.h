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

#ifndef _KFI_ATOMIC_H_
#define _KFI_ATOMIC_H_

#include <kfi_endpoint.h>

enum kfi_datatype {
	KFI_INT8,
	KFI_UINT8,
	KFI_INT16,
	KFI_UINT16,
	KFI_INT32,
	KFI_UINT32,
	KFI_INT64,
	KFI_UINT64,
	KFI_FLOAT,
	KFI_DOUBLE,
	KFI_FLOAT_COMPLEX,
	KFI_DOUBLE_COMPLEX,
	KFI_LONG_DOUBLE,
	KFI_LONG_DOUBLE_COMPLEX,
	KFI_DATATYPE_LAST
};

enum kfi_op {
	KFI_MIN,
	KFI_MAX,
	KFI_SUM,
	KFI_PROD,
	KFI_LOR,
	KFI_LAND,
	KFI_BOR,
	KFI_BAND,
	KFI_LXOR,
	KFI_BXOR,
	KFI_ATOMIC_READ,
	KFI_ATOMIC_WRITE,
	KFI_CSWAP,
	KFI_CSWAP_NE,
	KFI_CSWAP_LE,
	KFI_CSWAP_LT,
	KFI_CSWAP_GE,
	KFI_CSWAP_GT,
	KFI_MSWAP,
	KFI_ATOMIC_OP_LAST
};

struct kfi_ioc {
	void                    *addr;
	size_t                  count;
};

struct kfi_rma_ioc {
	uint64_t                addr;
	size_t                  count;
	uint64_t                key;
};

struct kfi_msg_atomic {
	const struct kfi_ioc    *msg_iov;
	void                    **desc;
	size_t                  iov_count;
	kfi_addr_t              addr;
	const struct kfi_rma_ioc *rma_iov;
	size_t                  rma_iov_count;
	enum kfi_datatype       datatype;
	enum kfi_op             op;
	void                    *context;
	uint64_t                data;
};

struct kfi_ops_atomic {
	ssize_t (*write)(struct kfid_ep *ep, const void *buf, size_t count,
	                void *desc, kfi_addr_t dest_addr, uint64_t addr,
	                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
	                void *context);
	ssize_t (*writev)(struct kfid_ep *ep, const struct kfi_ioc *iov,
	                void **desc, size_t count, kfi_addr_t dest_addr,
	                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
	                enum kfi_op op, void *context);
	ssize_t (*writemsg)(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
	                uint64_t flags);
	ssize_t (*inject)(struct kfid_ep *ep, const void *buf, size_t count,
	                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	                enum kfi_datatype datatype, enum kfi_op op);

	ssize_t (*readwrite)(struct kfid_ep *ep, const void *buf, size_t count,
	                void *desc, void *result, void *result_desc,
	                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	                enum kfi_datatype datatype, enum kfi_op op, void *context);
	ssize_t (*readwritev)(struct kfid_ep *ep, const struct kfi_ioc *iov,
	                void **desc, size_t count, struct kfi_ioc *resultv,
	                void **result_desc, size_t result_count,
	                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
	                enum kfi_datatype datatype, enum kfi_op op, void *context);
	ssize_t (*readwritemsg)(struct kfid_ep *ep,
	                const struct kfi_msg_atomic *msg, struct kfi_ioc *resultv,
	                void **result_desc, size_t result_count, uint64_t flags);

	ssize_t (*compwrite)(struct kfid_ep *ep, const void *buf, size_t count,
	                void *desc, const void *compare, void *compare_desc,
	                void *result, void *result_desc, kfi_addr_t dest_addr,
	                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
	                enum kfi_op op, void *context);
	ssize_t (*compwritev)(struct kfid_ep *ep, const struct kfi_ioc *iov,
	                void **desc, size_t count, const struct kfi_ioc *comparev,
	                void **compare_desc, size_t compare_count,
	                struct kfi_ioc *resultv, void **result_desc,
	                size_t result_count, kfi_addr_t dest_addr, uint64_t addr,
	                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
	                void *context);
	ssize_t (*compwritemsg)(struct kfid_ep *ep,
	                const struct kfi_msg_atomic *msg,
	                const struct kfi_ioc *comparev, void **compare_desc,
	                size_t compare_count, struct kfi_ioc *resultv,
	                void **result_desc, size_t result_count, uint64_t flags);

	int (*writevalid)(struct kfid_ep *ep, enum kfi_datatype datatype,
	                enum kfi_op op, size_t *count);
	int (*readwritevalid)(struct kfid_ep *ep, enum kfi_datatype datatype,
	                enum kfi_op op, size_t *count);
	int (*compwritevalid)(struct kfid_ep *ep, enum kfi_datatype datatype,
	                enum kfi_op op, size_t *count);
};

static inline ssize_t
kfi_atomic(struct kfid_ep *ep, const void *buf, size_t count, void *desc,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	return ep->atomic->write(ep, buf, count, desc, dest_addr, addr, key,
	                       datatype, op, context);
}

static inline ssize_t
kfi_atomicv(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
                size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	return ep->atomic->writev(ep, iov, desc, count, dest_addr, addr, key,
	                       datatype, op, context);
}

static inline ssize_t
kfi_atomicmsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                uint64_t flags)
{
	return ep->atomic->writemsg(ep, msg, flags);
}

static inline ssize_t
kfi_inject_atomic(struct kfid_ep *ep, const void *buf, size_t count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op)
{
	return ep->atomic->inject(ep, buf, count, dest_addr, addr, key,
	                       datatype, op);
}

static inline ssize_t
kfi_fetch_atomic(struct kfid_ep *ep, const void *buf, size_t count, void *desc,
                void *result, void *result_desc, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
                enum kfi_op op, void *context)
{
	return ep->atomic->readwrite(ep, buf, count, desc, result, result_desc,
	                       dest_addr, addr, key, datatype, op, context);
}

static inline ssize_t
kfi_fetch_atomicv(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
                size_t count, struct kfi_ioc *resultv, void **result_desc,
                size_t result_count, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context)
{
	return ep->atomic->readwritev(ep, iov, desc, count, resultv, result_desc,
	                       result_count, dest_addr, addr, key, datatype, op,
	                       context);
}

static inline ssize_t
kfi_fetch_atomicmsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                struct kfi_ioc *resultv, void **result_desc,
                size_t result_count, uint64_t flags)
{
	return ep->atomic->readwritemsg(ep, msg, resultv, result_desc,
	                       result_count, flags);
}

static inline ssize_t
kfi_compare_atomic(struct kfid_ep *ep, const void *buf, size_t count, void *desc,
                const void *compare, void *compare_desc, void *result,
                void *result_desc, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context)
{
	return ep->atomic->compwrite(ep, buf, count, desc, compare, compare_desc,
	                       result, result_desc, dest_addr, addr, key,
	                       datatype, op, context);
}

static inline ssize_t
kfi_compare_atomicv(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
                size_t count, const struct kfi_ioc *comparev, void **compare_desc,
                size_t compare_count, struct kfi_ioc *resultv, void **result_desc,
                size_t result_count, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context)
{
	return ep->atomic->compwritev(ep, iov, desc, count, comparev,
	                       compare_desc, compare_count, resultv, result_desc,
	                       result_count, dest_addr, addr, key, datatype, op,
	                       context);
}

static inline ssize_t
kfi_compare_atomicmsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                const struct kfi_ioc *comparev, void **compare_desc,
                size_t compare_count, struct kfi_ioc *resultv,
                void **result_desc, size_t result_count, uint64_t flags)
{
	return ep->atomic->compwritemsg(ep, msg, comparev, compare_desc,
	                       compare_count, resultv, result_desc, result_count,
	                       flags);
}

static inline int
kfi_atomicvalid(struct kfid_ep *ep, enum kfi_datatype datatype, enum kfi_op op,
                size_t *count)
{
	return ep->atomic->writevalid(ep, datatype, op, count);
}

static inline int
kfi_fetch_atomicvalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	return ep->atomic->readwritevalid(ep, datatype, op, count);
}

static inline int
kfi_compare_atomicvalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	return ep->atomic->compwritevalid(ep, datatype, op, count);
}

#endif
