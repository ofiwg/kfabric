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

#ifndef _KFI_DOMAIN_H_
#define _KFI_DOMAIN_H_

#include <kfabric.h>

enum kfi_threading {
	KFI_THREAD_UNSPEC,
	KFI_THREAD_SAFE,
	KFI_THREAD_FID,
	KFI_THREAD_DOMAIN,
	KFI_THREAD_COMPLETION,
	KFI_THREAD_ENDPOINT,
};

enum kfi_progress {
	KFI_PROGRESS_UNSPEC,
	KFI_PROGRESS_AUTO,
	KFI_PROGRESS_MANUAL,
};

enum kfi_resource_mgmt {
	KFI_RM_UNSPEC,
	KFI_RM_DISABLED,
	KFI_RM_ENABLED,
};

struct kfi_domain_attr {
	struct kfid_domain      *domain;
	char                    *name;
	enum kfi_threading      threading;
	enum kfi_progress       control_progress;
	enum kfi_progress       data_progress;
	enum kfi_resource_mgmt  resource_mgmt;
	size_t                  mr_key_size;
	size_t                  cq_data_size;
	size_t                  cq_cnt;
	size_t                  ep_cnt;
	size_t                  tx_ctx_cnt;
	size_t                  rx_ctx_cnt;
	size_t                  max_ep_tx_ctx;
	size_t                  max_ep_rx_ctx;
};

struct kfi_mr_attr {
	const struct kvec       *mr_iov;
	struct kvec             *dma_iov;
	size_t                  iov_count;
	uint64_t                access;
	uint64_t                offset;
	uint64_t                requested_key;
	void                    *context;
};

struct kfi_ops_domain {
	int (*cq_open)(struct kfid_domain *domain, struct kfi_cq_attr *attr,
	                struct kfid_cq **cq, void *context);
	int (*endpoint)(struct kfid_domain *domain, struct kfi_info *info,
	                struct kfid_ep **ep, void *context);
};

struct kfi_ops_mr {
	int (*reg)(struct kfid *fid, const void *buf, size_t len,
	                uint64_t access, uint64_t offset, uint64_t requested_key,
	                uint64_t flags, struct kfid_mr **mr, void *context,
	                uint64_t *dma_addr);
	int (*regv)(struct kfid *fid, const struct kvec *iov, size_t count,
	                uint64_t access, uint64_t offset, uint64_t requested_key,
	                uint64_t flags, struct kfid_mr **mr, void *context);
	int (*regattr)(struct kfid *fid, const struct kfi_mr_attr *attr,
	                uint64_t flags, struct kfid_mr **mr);
};

struct kfid_mr {
	struct kfid             fid;
	void                    *mem_desc;
	uint64_t                key;
};

struct kfid_domain {
	struct kfid             fid;
	struct kfi_ops_domain   *ops;
	struct kfi_ops_mr       *mr;
};

static inline int
kfi_domain(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_domain **domain, void *context)
{
	return fabric->ops->domain(fabric, info, domain, context);
}

static inline int
kfi_domain_bind(struct kfid_domain *domain, struct kfid *fid, uint64_t flags)
{
	return domain->fid.ops->bind(&domain->fid, fid, flags);
}

static inline int
kfi_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
                struct kfid_cq **cq, void *context)
{
	return domain->ops->cq_open(domain, attr, cq, context);
}

static inline int
kfi_mr_reg(struct kfid_domain *domain, const void *buf, size_t len,
                uint64_t access, uint64_t offset, uint64_t requested_key,
                uint64_t flags, struct kfid_mr **mr, void *context,
                uint64_t *dma_addr)
{
	return domain->mr->reg(&domain->fid, buf, len, access, offset,
	                       requested_key, flags, mr, context, dma_addr);
}

static inline int
kfi_mr_regv(struct kfid_domain *domain, const struct kvec *iov, size_t count,
                uint64_t access, uint64_t offset, uint64_t requested_key,
                uint64_t flags, struct kfid_mr **mr, void *context)
{
	return domain->mr->regv(&domain->fid, iov, count, access, offset,
	                       requested_key, flags, mr, context);
}

static inline int
kfi_mr_regattr(struct kfid_domain *domain, const struct kfi_mr_attr *attr,
                uint64_t flags, struct kfid_mr **mr)
{
	return domain->mr->regattr(&domain->fid, attr, flags, mr);
}

static inline void *
kfi_mr_desc(struct kfid_mr *mr)
{
	return mr->mem_desc;
}

static inline uint64_t
kfi_mr_key(struct kfid_mr *mr)
{
	return mr->key;
}

static inline int
kfi_mr_bind(struct kfid_mr *mr, struct kfid *bfid, uint64_t flags)
{
	return mr->fid.ops->bind(&mr->fid, bfid, flags);
}

#endif /* _KFI_DOMAIN_H_ */
