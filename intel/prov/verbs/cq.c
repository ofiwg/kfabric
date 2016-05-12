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

static ssize_t
fi_ib_cq_readerr(struct fid_cq *_cq, struct fi_cq_err_entry *entry,
		uint64_t flags)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;

	print_trace("in\n");

	if (cq->wc.status == IB_WC_SUCCESS)
		return 0;

	entry->op_context	= (void *) (uintptr_t) cq->wc.wr_id;
	entry->flags		= 0;
	entry->err		= EIO;
	entry->prov_errno	= cq->wc.status;

	memcpy(&entry->err_data, &cq->wc.vendor_err, sizeof(cq->wc.vendor_err));

	cq->wc.status = 0;

	return sizeof(*entry);
}

static inline int
fi_ib_poll(struct fi_ib_cq *cq)
{
	int			ret;

	ret = ib_poll_cq(cq->cq, 1, &cq->wc);
	if (ret < 0)
		print_err("ib_poll_cq returned %d\n", ret);
	else if (!ret)
		ib_req_notify_cq(cq->cq, IB_CQ_NEXT_COMP);
	else if (cq->wc.status != IB_WC_SUCCESS)
		ret = -FI_EAVAIL;

	return ret;
}

static int cq_sread(struct fi_ib_cq *cq, size_t count, int timeout)
{
	ktime_t			t0 = ktime_get();
	ktime_t			t1 = ktime_add_ns(t0, timeout);

	print_trace("in\n");

	while (!cq->pending && ktime_compare(t0, t1) < 0) {
		msleep(100);
		t0 = ktime_get();
	}

	if (!cq->pending)
		return -FI_ETIMEDOUT;

	if (cq->pending < count)
		return cq->pending;

	return count;
}

static ssize_t
fi_ib_cq_read_context(struct fid_cq *_cq, void *buf, size_t count)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;
	struct fi_cq_entry	*entry = buf;
	ssize_t			ret = 0;
	int			i;
	int			cnt = 0;

	print_trace("in\n");

	if (cq->wc.status != IB_WC_SUCCESS)
		return -FI_EAVAIL;

	for (i = 0; i < count; i++) {
		ret = fi_ib_poll(cq);
		if (ret <= 0)
			break;

		entry->op_context = (void *) (uintptr_t) cq->wc.wr_id;

		entry++;
		cnt++;

		if (cq->pending)
			cq->pending--;
	}

	return cnt ?: ret;
}

static ssize_t
fi_ib_cq_read_msg(struct fid_cq *_cq, void *buf, size_t count)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;
	struct fi_cq_msg_entry	*entry = buf;
	ssize_t			ret = 0;
	int			i;
	int			cnt = 0;

	print_trace("in\n");

	if (cq->wc.status != IB_WC_SUCCESS)
		return -FI_EAVAIL;

	for (i = 0; i < count; i++) {
		ret = fi_ib_poll(cq);
		if (ret <= 0)
			break;

		entry->op_context	= (void *) (uintptr_t) cq->wc.wr_id;
		entry->flags		= (uint64_t) cq->wc.wc_flags;
		entry->len		= (uint64_t) cq->wc.byte_len;

		entry++;
		cnt++;

		if (cq->pending)
			cq->pending--;
	}

	return cnt ?: ret;
}

static ssize_t
fi_ib_cq_read_data(struct fid_cq *_cq, void *buf, size_t count)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;
	struct fi_cq_data_entry	*entry = buf;
	ssize_t			ret = 0;
	int			i;
	int			cnt = 0;

	print_trace("in\n");

	if (cq->wc.status != IB_WC_SUCCESS)
		return -FI_EAVAIL;

	for (i = 0; i < count; i++) {
		ret = fi_ib_poll(cq);
		if (ret <= 0)
			break;

		entry->op_context = (void *) (uintptr_t) cq->wc.wr_id;
		if (cq->wc.wc_flags & IB_WC_WITH_IMM) {
			entry->flags = FI_REMOTE_CQ_DATA;
			//entry->data = cq->wc.imm_data;
		} else {
			entry->flags = 0;
			entry->data = 0;
		}
		if (cq->wc.opcode & (IB_WC_RECV | IB_WC_RECV_RDMA_WITH_IMM))
			entry->len = cq->wc.byte_len;
		else
			entry->len = 0;

		entry++;
		cnt++;

		if (cq->pending)
			cq->pending--;
	}

	return cnt ?: ret;
}

static ssize_t
fi_ib_cq_sread_msg(struct fid_cq *_cq, void *buf, size_t count,
		   const void *cond, int timeout)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;
	int			ret;

	ret = cq_sread(cq, count, timeout);
	if (ret <= 0)
		return ret;

	count = ret;
	ret = fi_ib_cq_read_msg(_cq, buf, count);
	if (ret)
		return ret;

	return count;
}

static ssize_t
fi_ib_cq_sread_context(struct fid_cq *_cq, void *buf, size_t count,
		       const void *cond, int timeout)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;
	int			ret;

	ret = cq_sread(cq, count, timeout);
	if (ret <= 0)
		return ret;

	count = ret;
	ret = fi_ib_cq_read_context(_cq, buf, count);
	if (ret)
		return ret;

	return count;
}

static ssize_t
fi_ib_cq_sread_data(struct fid_cq *_cq, void *buf, size_t count,
		    const void *cond, int timeout)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) _cq;
	int			ret;

	ret = cq_sread(cq, count, timeout);
	if (ret <= 0)
		return ret;

	count = ret;
	ret = fi_ib_cq_read_data(_cq, buf, count);
	if (ret)
		return ret;

	return count;
}

static const char *
fi_ib_cq_strerror(struct fid_cq *_cq, int err, const void *data, char *buf,
		  size_t len)
{
	static char buffer[132];

	switch (err) {
	case -EIO:
		sprintf(buffer,"ib_provider error: Input/output error");
		break;
	case -ENODEV:
		sprintf(buffer,"ib_provider error: No Device");
		break;
	case -ENOENT:
		sprintf(buffer,"ib_provider error: No Entry");
		break;
	case -ENOTCONN:
		sprintf(buffer,"ib_provider error: Not Connected");
		break;
	case -ENOSYS:
		sprintf(buffer,"ib_provider error: Function Not Implemented");
		break;
	case -EINVAL:
		sprintf(buffer,"ib_provider error: Invalid Argument");
		break;
	case -ETIMEDOUT:
		sprintf(buffer,"ib_provider error: Timed Out");
		break;
	default:
		sprintf(buffer,"ib_provider error %d", err);
	}

	if (buf && len)
		strncpy(buf, buffer, len);

	return buffer;
}

static struct fi_ops_cq fi_ib_cq_context_ops = {
	.size		= sizeof(struct fi_ops_cq),
	.read		= fi_ib_cq_read_context,
	.readfrom	= fi_no_cq_readfrom,
	.readerr	= fi_ib_cq_readerr,
	.write		= fi_no_cq_write,
	.writeerr	= fi_no_cq_writeerr,
	.sread		= fi_ib_cq_sread_context,
	.strerror	= fi_ib_cq_strerror
};

static struct fi_ops_cq fi_ib_cq_msg_ops = {
	.size		= sizeof(struct fi_ops_cq),
	.read		= fi_ib_cq_read_msg,
	.readfrom	= fi_no_cq_readfrom,
	.readerr	= fi_ib_cq_readerr,
	.write		= fi_no_cq_write,
	.writeerr	= fi_no_cq_writeerr,
	.sread		= fi_ib_cq_sread_msg,
	.strerror	= fi_ib_cq_strerror
};

static struct fi_ops_cq fi_ib_cq_data_ops = {
	.size		= sizeof(struct fi_ops_cq),
	.read		= fi_ib_cq_read_data,
	.readfrom	= fi_no_cq_readfrom,
	.readerr	= fi_ib_cq_readerr,
	.write		= fi_no_cq_write,
	.writeerr	= fi_no_cq_writeerr,
	.sread		= fi_ib_cq_sread_data,
	.strerror	= fi_ib_cq_strerror
};

static int fi_ib_cq_control(struct fid *fid, int command, void *arg)
{
	print_trace("in\n");

	return -ENOSYS;
}

static int fi_ib_cq_close(struct fid *fid)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) fid;

	print_trace("in\n");

	if (cq->cq)
		ib_destroy_cq(cq->cq);

	kfree(cq);

	return 0;
}

static struct fi_ops fi_ib_cq_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_ib_cq_close,
	.bind		= fi_no_bind,
	.control	= fi_ib_cq_control,
	.ops_open	= fi_no_ops_open,
};

static void event_handler(struct ib_event *event, void *context)
{
	print_trace("in\n");
}

static void comp_handler(struct ib_cq *ibcq, void *context)
{
	struct fi_ib_cq		*cq = (struct fi_ib_cq *) context;

	ib_req_notify_cq(cq->cq, IB_CQ_NEXT_COMP);

	if (cq->wc.status == IB_WC_SUCCESS)
		cq->pending++;
	else
		print_err("cq->wc.status %d\n", cq->wc.status);
}

int fi_ib_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		  struct fid_cq **_cq, void *context)
{
	struct fi_ib_cq		*cq;
	int			ret;

	print_trace("in\n");

	cq = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!_cq)
		return -FI_ENOMEM;

	cq->domain = (struct fi_ib_domain *) domain;

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
		break;
	default:
		return -FI_ENOSYS;
	}

	cq->cq = ib_create_cq(cq->domain->device, comp_handler,
			      event_handler, cq,
			      (attr->size > 0 ? attr->size : 256),
				/* cq size default, use val from HCA query */
			      (attr->signaling_vector >= 0 ?
				attr->signaling_vector : 0));
	if (IS_ERR(cq->cq)) {
		ret = PTR_ERR(cq->cq);
		goto err2;
	}

	ib_req_notify_cq(cq->cq, IB_CQ_NEXT_COMP);

	cq->flags		|= attr->flags;
	cq->cq_fid.fid.fclass	= FI_CLASS_CQ;
	cq->cq_fid.fid.context	= context;
	cq->cq_fid.fid.ops	= &fi_ib_cq_fi_ops;

	switch (attr->format) {
		case FI_CQ_FORMAT_CONTEXT:
			cq->cq_fid.ops = &fi_ib_cq_context_ops;
			cq->entry_size = sizeof(struct fi_cq_entry);
			break;
		case FI_CQ_FORMAT_MSG:
			cq->cq_fid.ops = &fi_ib_cq_msg_ops;
			cq->entry_size = sizeof(struct fi_cq_msg_entry);
			break;
		case FI_CQ_FORMAT_DATA:
			cq->cq_fid.ops = &fi_ib_cq_data_ops;
			cq->entry_size = sizeof(struct fi_cq_data_entry);
			break;
		default:
			ret = -FI_ENOSYS;
			goto err3;
	}

	*_cq = &cq->cq_fid;

	return 0;

err3:
	ib_destroy_cq(cq->cq);
err2:
	kfree(cq);
	return ret;
}
