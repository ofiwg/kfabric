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
#include <linux/delay.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "ibvp.h"

#define LISTEN_BACKLOG		5

ssize_t
fi_ib_ep_recv(struct fid_ep *_ep, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_recv_wr	*bad;
	struct ib_recv_wr	wr;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	struct ib_sge		sge;
	int			ret;

	print_trace("in\n");

	dma_addr = ib_dma_map_single(dev, (void *) buf, len, DMA_FROM_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) len;
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	ret = ib_post_recv(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_recv returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_recvv(struct fid_ep *_ep, const struct iovec *iov, void **desc,
	       size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_recv_wr	wr;
	struct ib_recv_wr	*bad;
	struct ib_sge		*sge;
	size_t			i;
	int			ret;

	print_trace("in\n");

	sge = kzalloc(count * sizeof(struct ib_sge), GFP_KERNEL);
	if (!sge) {
		print_err("kalloc failed!\n");
		return -ENOMEM;
	}

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= sge;
	wr.num_sge	= (int) count;

	for (i = 0; i < count; i++) {
		sge[i].addr = (uintptr_t) iov[i].iov_base;
		sge[i].length = (uint32_t) iov[i].iov_len;
		sge[i].lkey = (uint32_t) (uintptr_t) desc[i];
	}

	ret = ib_post_recv(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_recv returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_send(struct fid_ep *_ep, const void *buf, size_t len,
	      void *desc, fi_addr_t dest_addr, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	int			ret;

	print_trace("in\n");

	dma_addr = ib_dma_map_single(dev, (void *) buf, len, DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) len;
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode	= IB_WR_SEND;

	wr.send_flags	= (len <= ep->inline_size) ? IB_SEND_INLINE : 0;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_senddata(struct fid_ep *_ep, const void *buf, size_t len,
		  void *desc, uint64_t data, fi_addr_t dest_addr, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	int			ret;

	print_trace("in\n");

	dma_addr = ib_dma_map_single(dev, (void *) buf, len, DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) len;
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode	= IB_WR_SEND_WITH_IMM;

	wr.send_flags	= (len <= ep->inline_size) ? IB_SEND_INLINE : 0;
	wr.ex.imm_data	= (uint32_t) data;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_sendv(struct fid_ep *_ep, const struct iovec *iov, void **desc,
	       size_t count, fi_addr_t dest_addr, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		*sge;
	int			ret;
	int			len = 0;
	int			i;

	print_trace("in\n");

	sge = kzalloc(count * sizeof(struct ib_sge), GFP_KERNEL);
	if (!sge) {
		print_err("kalloc failed!\n");
		return -ENOMEM;
	}

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= sge;
	wr.num_sge	= (int) count;

	wr.opcode	= IB_WR_SEND;

	for (i = 0; i < count; i++) {
		sge[i].addr   = (uintptr_t) iov[i].iov_base;
		sge[i].length = (uint32_t) iov[i].iov_len;
		sge[i].lkey   = (uint32_t) (uintptr_t) desc[i];
		len += iov[i].iov_len;
	}
	wr.send_flags = (len <= ep->inline_size) ? IB_SEND_INLINE : 0;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_sendmsg(struct fid_ep *_ep, const struct fi_msg *msg, uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		*sge;
	int			ret;
	int			len;
	int			i;

	print_trace("in\n");

	wr.wr_id	= (uintptr_t) msg->context;
	wr.num_sge	= msg->iov_count;
	wr.next		= NULL;

	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge) * msg->iov_count, GFP_KERNEL);
		if (!sge) {
			print_err("kalloc failed!\n");
			return -ENOMEM;
		}
		for (len = 0, i = 0; i < msg->iov_count; i++) {
			sge[i].addr   = (uintptr_t) msg->msg_iov[i].iov_base;
			sge[i].length = (uint32_t) msg->msg_iov[i].iov_len;
			sge[i].lkey   = (uint32_t) (uintptr_t) (msg->desc[i]);
			len += sge[i].length;
		}

		wr.sg_list    = sge;
		wr.send_flags = (len <= ep->inline_size) ? IB_SEND_INLINE : 0;
	} else
		wr.send_flags = 0;

	if (flags & FI_REMOTE_CQ_DATA) {
		wr.opcode	= IB_WR_SEND_WITH_IMM;
		wr.ex.imm_data	= (uint32_t) msg->data;
	} else
		wr.opcode	= IB_WR_SEND;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_recvmsg(struct fid_ep *_ep, const struct fi_msg *msg, uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_recv_wr	wr;
	struct ib_recv_wr	*bad;
	struct ib_sge		*sge = NULL;
	int			ret;
	int			i;

	print_trace("in\n");

	wr.wr_id	= (uintptr_t) msg->context;
	wr.next		= NULL;
	wr.num_sge	= msg->iov_count;

	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge) * msg->iov_count, GFP_KERNEL);
		if (!sge) {
			print_err("kalloc failed!\n");
			return -ENOMEM;
		}
		for (i = 0; i < msg->iov_count; i++) {
			sge[i].addr   = (uintptr_t) msg->msg_iov[i].iov_base;
			sge[i].length = (uint32_t) msg->msg_iov[i].iov_len;
			sge[i].lkey   = (uint32_t) (uintptr_t) (msg->desc[i]);
		}

	}
	wr.sg_list = sge;

	ret = ib_post_recv(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_recv returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_write(struct fid_ep *_ep, const void *buf, size_t len,
		   void *desc, fi_addr_t dest_addr, uint64_t addr,
		   uint64_t key, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	int			ret;

	print_trace("in\n");

	dma_addr = ib_dma_map_single(dev, (void *) buf, len, DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) len;
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode	= IB_WR_RDMA_WRITE;

	wr.send_flags	= (len <= ep->inline_size) ? IB_SEND_INLINE : 0;

	wr.wr.rdma.rkey		= (uint32_t) key;
	wr.wr.rdma.remote_addr	= addr;


	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("rdma_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_writev(struct fid_ep *_ep, const struct iovec *iov, void **desc,
		    size_t count, fi_addr_t dest_addr, uint64_t addr,
		    uint64_t key, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		*sge;
	int			ret;
	int			len = 0;
	int			i;

	print_trace("in\n");

	sge = kzalloc(count * sizeof(struct ib_sge), GFP_KERNEL);
	if (!sge) {
		print_err("kalloc failed!");
		return -ENOMEM;
	}

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= sge;
	wr.num_sge	= count;

	wr.opcode	= IB_WR_RDMA_WRITE;

	wr.wr.rdma.rkey		= (uint32_t) key;
	wr.wr.rdma.remote_addr	= addr;

	for (i = 0; i < count; i++) {
		sge[i].addr	= (uintptr_t) iov[i].iov_base;
		sge[i].length	= (uint32_t) iov[i].iov_len;
		sge[i].lkey	= (uint32_t) (uintptr_t) desc[i];
		len += iov[i].iov_len;
	}
	wr.send_flags = (len <= ep->inline_size) ? IB_SEND_INLINE : 0;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_writemsg(struct fid_ep *_ep, const struct fi_msg_rma *msg,
		      uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		*sge = NULL;
	int			ret;
	int			len;
	int			i;

	print_trace("in\n");

	wr.wr_id	= (uintptr_t) msg->context;
	wr.next		= NULL;
	wr.num_sge	= msg->iov_count;
	wr.send_flags	= 0;

	if (flags & FI_REMOTE_CQ_DATA) {
		wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data	= (uint32_t) msg->data;
	} else
		wr.opcode	= IB_WR_RDMA_WRITE;

	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge) * msg->iov_count, GFP_KERNEL);
		if (!sge) {
			print_err("kalloc failed!\n");
			return -ENOMEM;
		}

		for (len = 0, i = 0; i < msg->iov_count; i++) {
			sge[i].addr   = (uintptr_t) msg->msg_iov[i].iov_base;
			sge[i].length = (uint32_t) msg->msg_iov[i].iov_len;
			sge[i].lkey   = (uint32_t) (uintptr_t) (msg->desc[i]);
			len += sge[i].length;
		}

		wr.send_flags = (len <= ep->inline_size) ? IB_SEND_INLINE : 0;
	}
	wr.sg_list = sge;

	wr.wr.rdma.remote_addr	= msg->rma_iov->addr;
	wr.wr.rdma.rkey		= (uint32_t) msg->rma_iov->key;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_read(struct fid_ep *_ep, void *buf, size_t len, void *desc,
		  fi_addr_t src_addr, uint64_t addr, uint64_t key,
		  void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	int			ret;

	print_trace("in\n");

	dma_addr = ib_dma_map_single(dev, (void *) buf, len, DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) len;
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode	= IB_WR_RDMA_READ;

	wr.send_flags	= 0;

	wr.wr.rdma.remote_addr	= addr;
	wr.wr.rdma.rkey		= (uint32_t) key;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_readv(struct fid_ep *_ep, const struct iovec *iov, void **desc,
		   size_t count, fi_addr_t src_addr, uint64_t addr,
		   uint64_t key, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		*sge;
	int			ret;
	int			i;

	print_trace("in\n");

	sge = kzalloc(count * sizeof(struct ib_sge), GFP_KERNEL);
	if (!sge) {
		print_err("kalloc failed!\n");
		return -ENOMEM;
	}

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= sge;
	wr.num_sge	= count;

	wr.opcode	= IB_WR_RDMA_READ;

	wr.send_flags	= 0;

	wr.wr.rdma.rkey		= (uint32_t) key;
	wr.wr.rdma.remote_addr	= addr;

	for (i = 0; i < count; i++) {
		sge[i].addr   = (uintptr_t) iov[i].iov_base;
		sge[i].length = (uint32_t) iov[i].iov_len;
		sge[i].lkey   = (uint32_t) (uintptr_t) desc[i];
	}

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_readmsg(struct fid_ep *_ep, const struct fi_msg_rma *msg,
		     uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		*sge = NULL;
	int			ret;
	int			i;

	print_trace("in\n");

	wr.wr_id	= (uintptr_t) msg->context;
	wr.next		= NULL;
	wr.num_sge	= msg->iov_count;

	wr.opcode	= IB_WR_RDMA_READ;

	wr.send_flags	= 0;

	wr.wr.rdma.rkey		= (uint32_t) msg->rma_iov->key;
	wr.wr.rdma.remote_addr	= msg->rma_iov->addr;

	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge) * msg->iov_count, GFP_KERNEL);
		for (i = 0; i < msg->iov_count; i++) {
			sge[i].addr = (uintptr_t) msg->msg_iov[i].iov_base;
			sge[i].length = (uint32_t) msg->msg_iov[i].iov_len;
			sge[i].lkey = (uint32_t) (uintptr_t) (msg->desc[i]);
		}
	}
	wr.sg_list = sge;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_rma_writedata(struct fid_ep *_ep, const void *buf, size_t len,
		       void *desc, uint64_t data, fi_addr_t dest_addr,
		       uint64_t addr, uint64_t key, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	int			ret;

	print_trace("in\n");

	dma_addr = ib_dma_map_single(dev, (void *) buf, len, DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) len;
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;

	wr.send_flags	= (len <= ep->inline_size) ? IB_SEND_INLINE : 0;
	wr.ex.imm_data	= (uint32_t) data;

	wr.wr.rdma.remote_addr	= addr;
	wr.wr.rdma.rkey		= (uint32_t) key;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

static inline int valid_datatype(enum fi_datatype datatype)
{
	switch (datatype) {
	case FI_INT64:
	case FI_UINT64:
#if __BITS_PER_LONG == 64
	case FI_DOUBLE:
	case FI_FLOAT:
#endif
		return 0;
	default:
		return -FI_EINVAL;
	}
}

ssize_t
fi_ib_ep_atomic_write(struct fid_ep *_ep, const void *buf, size_t count,
		      void *desc, fi_addr_t dest_addr, uint64_t addr,
		      uint64_t key, enum fi_datatype datatype, enum fi_op op,
		      void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	struct ib_device	*dev = ep->id->device;
	u64			dma_addr;
	int			ret;

	print_trace("in\n");

	if (count != 1)
		return -FI_E2BIG;

	ret = valid_datatype(datatype);
	if (ret)
		return ret;

	switch (op) {
	case FI_ATOMIC_WRITE:
		wr.opcode			= IB_WR_RDMA_WRITE;
		wr.wr.rdma.remote_addr	= addr;
		wr.wr.rdma.rkey		= (uint32_t) (uintptr_t) key;
		break;
	default:
		return -ENOSYS;
	}

	dma_addr = ib_dma_map_single(dev, (void *) buf, sizeof(uint64_t),
				     DMA_TO_DEVICE);
	ret = ib_dma_mapping_error(dev, dma_addr);
	if (ret) {
		print_err("ib_dma_map_single returned %d\n", ret);
		return ret;
	}

	sge.addr	= (uintptr_t) dma_addr;
	sge.length	= (uint32_t) sizeof(uint64_t);
	sge.lkey	= (uint32_t) (uintptr_t) desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.send_flags = (sge.length <= ep->inline_size) ? IB_SEND_INLINE : 0;
	wr.send_flags |= IB_SEND_FENCE;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_atomic_writev(struct fid_ep *_ep, const struct fi_ioc *iov,
		       void **desc, size_t count, uint64_t addr,
		       fi_addr_t dest_addr, uint64_t key,
		       enum fi_datatype datatype, enum fi_op op, void *context)
{
	if (iov->count != 1)
		return -FI_E2BIG;

	return fi_ib_ep_atomic_write(_ep, iov->addr, count, desc[0],
			dest_addr, addr, key, datatype, op, context);
}

ssize_t
fi_ib_ep_atomic_writemsg(struct fid_ep *_ep, const struct fi_msg_atomic *msg,
			 uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	int			ret;

	print_trace("in\n");

	if (msg->iov_count != 1 || msg->msg_iov->count != 1)
		return -FI_E2BIG;

	ret = valid_datatype(msg->datatype);
	if (ret)
		return ret;

	if (msg->op != FI_ATOMIC_WRITE)
		return -ENOSYS;

	sge.addr	= (uintptr_t) msg->msg_iov->addr;
	sge.length	= (uint32_t) sizeof(uint64_t);
	sge.lkey	= (uint32_t) (uintptr_t) msg->desc[0];

	wr.wr_id	= (uintptr_t) msg->context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	if (flags & FI_REMOTE_CQ_DATA) {
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data = (uint32_t) msg->data;
	} else
		wr.opcode = IB_WR_RDMA_WRITE;

	wr.wr.rdma.remote_addr = msg->rma_iov->addr;
	wr.wr.rdma.rkey = (uint32_t) (uintptr_t) msg->rma_iov->key;

	wr.send_flags = (sge.length <= ep->inline_size) ? IB_SEND_INLINE : 0;
	wr.send_flags |= IB_SEND_FENCE;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_atomic_readwrite(struct fid_ep *_ep, const void *buf, size_t count,
			  void *desc, void *result, void *result_desc,
			  fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			  enum fi_datatype datatype,
			  enum fi_op op, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	int			ret;

	print_trace("in\n");

	if (count != 1)
		return -FI_E2BIG;

	ret = valid_datatype(datatype);
	if (ret)
		return ret;

	switch (op) {
	case FI_ATOMIC_READ:
		wr.opcode		 = IB_WR_RDMA_READ;
		wr.wr.rdma.remote_addr	 = addr;
		wr.wr.rdma.rkey		 = (uint32_t) (uintptr_t) key;
		break;
	case FI_SUM:
		wr.opcode		 = IB_WR_ATOMIC_FETCH_AND_ADD;
		wr.wr.atomic.remote_addr = addr;
		wr.wr.atomic.compare_add = (uintptr_t) buf;
		wr.wr.atomic.swap	 = 0;
		wr.wr.atomic.rkey	 = (uint32_t) (uintptr_t) key;
		break;
	default:
		return -ENOSYS;
	}

	sge.addr	= (uintptr_t) result;
	sge.length	= (uint32_t) sizeof(uint64_t);
	sge.lkey	= (uint32_t) (uintptr_t) result_desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.send_flags	= IB_SEND_FENCE;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_atomic_readwritev(struct fid_ep *_ep, const struct fi_ioc *iov,
			   void **desc, size_t count,
			   struct fi_ioc *resultv, void **result_desc,
			   size_t result_count, fi_addr_t dest_addr,
			   uint64_t addr, uint64_t key,
			   enum fi_datatype datatype,
			   enum fi_op op, void *context)
{
	if (iov->count != 1)
		return -FI_E2BIG;

	return fi_ib_ep_atomic_readwrite(_ep, iov->addr, count,
			desc[0], resultv->addr, result_desc[0],
			dest_addr, addr, key, datatype, op, context);
}

ssize_t
fi_ib_ep_atomic_readwritemsg(struct fid_ep *_ep,
			     const struct fi_msg_atomic *msg,
			     struct fi_ioc *resultv, void **result_desc,
			     size_t result_count, uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	int			ret;

	print_trace("in\n");

	if (msg->iov_count != 1 || msg->msg_iov->count != 1)
		return -FI_E2BIG;

	ret = valid_datatype(msg->datatype);
	if (ret)
		return ret;

	switch (msg->op) {
	case FI_ATOMIC_READ:
		wr.opcode = IB_WR_RDMA_READ;
		wr.wr.rdma.remote_addr = msg->rma_iov->addr;
		wr.wr.rdma.rkey = (uint32_t) (uintptr_t) msg->rma_iov->key;
		break;
	case FI_SUM:
		wr.opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
		wr.wr.atomic.remote_addr = msg->rma_iov->addr;
		wr.wr.atomic.compare_add = (uintptr_t) msg->addr;
		wr.wr.atomic.swap = 0;
		wr.wr.atomic.rkey = (uint32_t) (uintptr_t) msg->rma_iov->key;
		break;
	default:
		return -ENOSYS;
	}

	sge.addr	= (uintptr_t) resultv->addr;
	sge.length	= (uint32_t) sizeof(uint64_t);
	sge.lkey	= (uint32_t) (uintptr_t) result_desc[0];

	wr.wr_id	= (uintptr_t) msg->context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.send_flags	= IB_SEND_FENCE;

	if (flags & FI_REMOTE_CQ_DATA)
		wr.ex.imm_data = (uint32_t) msg->data;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_atomic_compwrite(struct fid_ep *_ep, const void *buf, size_t count,
			  void *desc, const void *compare,
			  void *compare_desc, void *result,
			  void *result_desc, fi_addr_t dest_addr,
			  uint64_t addr, uint64_t key,
			  enum fi_datatype datatype,
			  enum fi_op op, void *context)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	int			ret;

	print_trace("in\n");

	if (op != FI_CSWAP)
		return -ENOSYS;

	if (count != 1)
		return -FI_E2BIG;

	ret = valid_datatype(datatype);
	if (ret)
		return ret;

	sge.addr	= (uintptr_t) result;
	sge.length	= (uint32_t) sizeof(uint64_t);
	sge.lkey	= (uint32_t) (uintptr_t) result_desc;

	wr.wr_id	= (uintptr_t) context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode	= IB_WR_ATOMIC_CMP_AND_SWP;

	wr.send_flags	= IB_SEND_FENCE;

	wr.wr.atomic.remote_addr = addr;
	wr.wr.atomic.compare_add = (uintptr_t) compare;
	wr.wr.atomic.swap	 = (uintptr_t) buf;
	wr.wr.atomic.rkey	 = (uint32_t) (uintptr_t) key;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

ssize_t
fi_ib_ep_atomic_compwritev(struct fid_ep *_ep, const struct fi_ioc *iov,
			   void **desc, size_t count,
			   const struct fi_ioc *comparev,
			   void **compare_desc, size_t compare_count,
			   struct fi_ioc *resultv, void **result_desc,
			   size_t result_count, fi_addr_t dest_addr,
			   uint64_t addr, uint64_t key,
			   enum fi_datatype datatype,
			   enum fi_op op, void *context)
{
	if (iov->count != 1)
		return -FI_E2BIG;

	return fi_ib_ep_atomic_compwrite(_ep, iov->addr, count, desc[0],
			comparev->addr, compare_desc[0], resultv->addr,
			result_desc[0], dest_addr, addr, key, datatype,
			op, context);
}

ssize_t
fi_ib_ep_atomic_compwritemsg(struct fid_ep *_ep,
			     const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev,
			     void **compare_desc, size_t compare_count,
			     struct fi_ioc *resultv,
			     void **result_desc, size_t result_count,
			     uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct ib_send_wr	wr;
	struct ib_send_wr	*bad;
	struct ib_sge		sge;
	int			ret;

	print_trace("in\n");

	if (msg->op != FI_CSWAP)
		return -ENOSYS;

	if (msg->iov_count != 1 || msg->msg_iov->count != 1)
		return -FI_E2BIG;

	ret = valid_datatype(msg->datatype);
	if (ret)
		return ret;

	sge.addr	= (uintptr_t) resultv->addr;
	sge.length	= (uint32_t) sizeof(uint64_t);
	sge.lkey	= (uint32_t) (uintptr_t) result_desc[0];

	wr.wr_id	= (uintptr_t) msg->context;
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;

	wr.opcode = IB_WR_ATOMIC_CMP_AND_SWP;

	wr.send_flags	= IB_SEND_FENCE;

	if (flags & FI_REMOTE_CQ_DATA)
		wr.ex.imm_data = (uint32_t) msg->data;

	wr.wr.atomic.remote_addr = msg->rma_iov->addr;
	wr.wr.atomic.compare_add = (uintptr_t) comparev->addr;
	wr.wr.atomic.swap	 = (uintptr_t) msg->addr;
	wr.wr.atomic.rkey	 = (uint32_t) (uintptr_t) msg->rma_iov->key;

	ret = ib_post_send(ep->id->qp, &wr, &bad);
	if (ret)
		print_err("ib_post_send returned %d\n", ret);

	return ret;
}

int
fi_ib_ep_atomic_writevalid(struct fid_ep *_ep, enum fi_datatype datatype,
			   enum fi_op op, size_t *count)
{
	int			ret;

	switch (op) {
	case FI_ATOMIC_WRITE:
		break;
	default:
		return -FI_ENOSYS;
	}

	ret = valid_datatype(datatype);
	if (ret)
		return ret;

	if (count)
		*count = 1;

	return 0;
}

int
fi_ib_ep_atomic_readwritevalid(struct fid_ep *_ep, enum fi_datatype datatype,
			       enum fi_op op, size_t *count)
{
	int			ret;

	switch (op) {
	case FI_ATOMIC_READ:
	case FI_SUM:
		break;
	default:
		return -FI_ENOSYS;
	}

	ret = valid_datatype(datatype);
	if (ret)
		return ret;

	if (count)
		*count = 1;

	return 0;
}

int
fi_ib_ep_atomic_compwritevalid(struct fid_ep *_ep, enum fi_datatype datatype,
			       enum fi_op op, size_t *count)
{
	int			ret;

	if (op != FI_CSWAP)
		return -FI_ENOSYS;

	ret = valid_datatype(datatype);
	if (ret)
		return ret;

	if (count)
		*count = 1;

	return 0;
}
