/*
 * Copyright (c) 2015 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/errno.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "ibvp.h"

static int fi_ib_mr_close(struct fid *fid)
{
	int			ret;
	struct fi_ib_mem_desc	*md = (struct fi_ib_mem_desc *) fid;

	print_trace("in\n");

	ret = ib_dereg_mr(md->mr);
	if (ret)
		print_err("ib_dereg_mr returned %d\n", ret);

	return ret;
}

static struct fi_ops fi_ib_mr_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_ib_mr_close,
	.bind		= fi_no_bind,
	.control	= fi_no_control,
	.ops_open	= fi_no_ops_open,
};

int fi_ib_mr_reg(struct fid *fid, const void *buf, size_t len,
		uint64_t access, uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr, void *context)
{
	struct fid_domain	*domain = (struct fid_domain *)fid;
	struct fi_ib_mem_desc	*md;
	int			ret;

	print_trace("in\n");

	if (flags)
		return -FI_EBADFLAGS;

	md = kzalloc(sizeof(*md), GFP_KERNEL);
	if (!md) {
		print_err("kalloc failed!\n");
		return -FI_ENOMEM;
	}

	md->domain = (struct fi_ib_domain *) domain;

	md->mr_fid.fid.fclass = FI_CLASS_MR;
	md->mr_fid.fid.context = context;
	md->mr_fid.fid.ops = &fi_ib_mr_ops;

	md->mr = ib_get_dma_mr(md->domain->pd,
			       IB_ACCESS_LOCAL_WRITE
			       | IB_ACCESS_REMOTE_WRITE
			       | IB_ACCESS_REMOTE_READ);
	if (IS_ERR(md->mr)) {
		ret = PTR_ERR(md->mr);
		print_err("ib_get_dma_mr returned %d\n", ret);
		goto err;
	}

	md->mr_fid.mem_desc = (void *) (uintptr_t) md->mr->lkey;
	md->mr_fid.key = md->mr->rkey;

	*mr = &md->mr_fid;

	return 0;
err:
	kfree(md);

	return ret;
}
