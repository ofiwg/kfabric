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
#include <linux/kthread.h>
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

#define rdma_get_local_addr(id) &id->route.addr.src_addr
#define rdma_get_peer_addr(id)	&id->route.addr.dst_addr
#define rdma_get_transport(id)	id->route.addr.dev_addr.transport

static int sockaddr_len(struct sockaddr *addr)
{
	if (!addr)
		return 0;

	switch (addr->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
#if 0
	case AF_IB:
		return sizeof(struct sockaddr_ib);
#endif
	default:
		return 0;
	}
}

static struct fi_info *
cm_getinfo(struct fi_ib_fabric *fab, struct fi_ib_event *event)
{
	struct fi_info		*fi;
	struct rdma_cm_id	*id = event->id;
	struct sockaddr		*addr;
	int			len;

	print_trace("in\n");

	fi = kzalloc(sizeof(*fi), GFP_KERNEL);
	if (!fi)
		return NULL;
	fi->ep_attr = kzalloc(sizeof(*fi->ep_attr), GFP_KERNEL);
	if (!fi->ep_attr)
		goto err;
	fi->tx_attr = kzalloc(sizeof(*fi->tx_attr), GFP_KERNEL);
	if (!fi->tx_attr)
		goto err;
	fi->rx_attr = kzalloc(sizeof(*fi->rx_attr), GFP_KERNEL);
	if (!fi->rx_attr)
		goto err;
	fi->fabric_attr = kzalloc(sizeof(*fi->fabric_attr), GFP_KERNEL);
	if (!fi->fabric_attr)
		goto err;
	fi->domain_attr = kzalloc(sizeof(*fi->domain_attr), GFP_KERNEL);
	if (!fi->domain_attr)
		goto err;

	fi->ep_type = FI_EP_MSG;
	fi->caps  = FI_MSG | FI_RMA;
	if (rdma_get_transport(id) == RDMA_TRANSPORT_IWARP)
		fi->ep_attr->protocol = FI_PROTO_IWARP;
	else
		fi->ep_attr->protocol = FI_PROTO_RDMA_CM_IB_RC;

	addr = (struct sockaddr *) rdma_get_local_addr(id);
	len = sockaddr_len(addr);
	fi->src_addr = kzalloc(len, GFP_KERNEL);
	if (!fi->src_addr)
		goto err;
	memcpy(fi->src_addr, addr, len);
	fi->src_addrlen = len;

	addr = (struct sockaddr *) rdma_get_peer_addr(id);
	len = sockaddr_len(addr);
	fi->dest_addr = kzalloc(len, GFP_KERNEL);
	if (!fi->dest_addr)
		goto err;
	memcpy(fi->dest_addr, addr, len);
	fi->dest_addrlen = len;

	fi->fabric_attr->name = kstrdup("IBVERBS", GFP_KERNEL);
	if (!fi->fabric_attr->name)
		goto err;

	fi->fabric_attr->prov_name = kstrdup("KOFI_VERBS", GFP_KERNEL);
	if (!fi->fabric_attr->prov_name)
		goto err;

	fi->fabric_attr->prov_version = 1;

	fi->domain_attr->name = kstrdup(id->device->name, GFP_KERNEL);
	if (!fi->domain_attr->name)
		goto err;

	fi->connreq = (void*) id;

	return fi;
err:
	fi_freeinfo(fi);
	return NULL;
}

static ssize_t
cm_process_event(struct fi_ib_eq *eq, struct fi_ib_event *event,
		 uint32_t *fi_event, struct fi_eq_cm_entry *entry, size_t len)
{
	struct fid		*fid;
	struct rdma_cm_event	*cm_event = &event->ev;
	size_t			datalen;

	print_trace("in\n");

	fid = event->id->context;
	switch (cm_event->event) {
#if 0
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		return 0;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		return 0;
#endif
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		*fi_event = FI_CONNREQ;
		entry->info = cm_getinfo(eq->fab, event);
		if (!entry->info) {
			rdma_destroy_id(event->id);
			return 0;
		}
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		*fi_event = FI_CONNECTED;
		entry->info = NULL;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		*fi_event = FI_SHUTDOWN;
		entry->info = NULL;
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		eq->err.fid = fid;
		eq->err.err = cm_event->status;
		return -EIO;
	case RDMA_CM_EVENT_REJECTED:
		eq->err.fid = fid;
		eq->err.err = ECONNREFUSED;
		eq->err.prov_errno = cm_event->status;
		return -EIO;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		eq->err.fid = fid;
		eq->err.err = ENODEV;
		return -EIO;
	case RDMA_CM_EVENT_ADDR_CHANGE:
		eq->err.fid = fid;
		eq->err.err = EADDRNOTAVAIL;
		return -EIO;
	default:
		return 0;
	}

	entry->fid = fid;
	datalen = min( (len - sizeof(*entry)),
		      (size_t) cm_event->param.conn.private_data_len);
	if (datalen)
		memcpy(entry->data, cm_event->param.conn.private_data, datalen);
	return sizeof(*entry) + datalen;
}

static
int is_event_list_empty(struct fi_ib_eq *eq)
{
	int			ret;
	unsigned long		flags;

	spin_lock_irqsave(&eq->lock, flags);
	ret = list_empty(&eq->events);
	spin_unlock_irqrestore(&eq->lock, flags);

	return ret;
}

static int read_event(struct fi_ib_eq *eq, struct fi_eq_cm_entry *entry,
		      size_t len, int timeout)
{
	struct fi_ib_event	*ev;
	uint32_t		fi_event = 0;
	int			ret;
	unsigned long		flags;

	print_trace("in\n");

	if (is_event_list_empty(eq)) {
		if (!timeout) {
			ret = -ENOENT;
			goto out;
		}

		timeout /= 500;

		while (is_event_list_empty(eq) && timeout--) {
			wait_event_interruptible_timeout
				(eq->sem, !is_event_list_empty(eq), 500);
			if (kthread_should_stop()) {
				ret = -ESHUTDOWN;
				goto out;
			}
		}

		if (is_event_list_empty(eq)) {
			ret = -ETIMEDOUT;
			goto out;
		}
	}

	spin_lock_irqsave(&eq->lock, flags);
	ev = list_first_entry(&eq->events, typeof(*ev), node);
	list_del(&ev->node);
	spin_unlock_irqrestore(&eq->lock, flags);

	ret = cm_process_event(eq, ev, &fi_event, entry, len);
	if (ret > 0)
		return fi_event;
out:
	return ret;
}

static ssize_t
fi_ib_eq_readerr(struct fid_eq *_eq, struct fi_eq_err_entry *err, uint64_t flags)
{
	struct fi_ib_eq		*eq = (struct fi_ib_eq *) _eq;

	print_trace("in\n");

	if (!eq->err.err)
		return 0;

	*err = eq->err;
	eq->err.err = 0;
	return sizeof(*err);
}

static ssize_t fi_ib_eq_read(struct fid_eq *_eq, uint32_t *event, void *buf,
			     size_t len, uint64_t flags)
{
	struct fi_ib_eq		*eq = (struct fi_ib_eq *) _eq;
	struct fi_eq_cm_entry	*entry;
	int			ret;

	print_trace("in\n");

	entry = (struct fi_eq_cm_entry *) buf;

	ret = read_event(eq, entry, len, 0);
	if (ret < 0)
		return (ssize_t) ret;

	*event = ret;

	return len;
}

static ssize_t fi_ib_eq_sread(struct fid_eq *_eq, uint32_t *event, void *buf,
			      size_t len, int timeout, uint64_t flags)
{
	struct fi_ib_eq		*eq = (struct fi_ib_eq *) _eq;
	struct fi_eq_cm_entry	*entry;
	int			ret;

	print_trace("in\n");

	if (!timeout) {
		print_err("infinate timeout in kernel not allowed\n");
		return -EINVAL;
	}

	entry = (struct fi_eq_cm_entry *) buf;

	ret = read_event(eq, entry, len, timeout);
	if (ret < 0)
		return (ssize_t) ret;

	*event = ret;

	return len;
}

static const char *fi_ib_eq_strerror(struct fid_eq *eq, int prov_errno,
				     const void *data, char *buf, size_t len)
{
	static char buffer[132];

	switch (prov_errno) {
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
		sprintf(buffer,"ib_provider error %d", prov_errno);
	}

	if (buf && len)
		strncpy(buf, buffer, len);

	return buffer;
}

static struct fi_ops_eq fi_ib_eq_ops = {
	.size		= sizeof(struct fi_ops_eq),
	.read		= fi_ib_eq_read,
	.readerr	= fi_ib_eq_readerr,
	.write		= fi_no_eq_write,
	.sread		= fi_ib_eq_sread,
	.strerror	= fi_ib_eq_strerror,
};

static int fi_ib_eq_close(struct fid *fid)
{
	struct fi_ib_eq		*eq = (struct fi_ib_eq *) fid;
	struct fi_ib_event	*event, *next;

	list_for_each_entry_safe(event, next, &eq->events, node)
		kfree(event);

	kfree(eq);

	return 0;
}

static struct fi_ops fi_ib_eq_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_ib_eq_close,
	.bind		= fi_no_bind,
	.control	= fi_no_control,
	.ops_open	= fi_no_ops_open,
};

int fi_ib_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		  struct fid_eq **_eq, void *context)
{
	struct fi_ib_eq		*eq;

	eq = kzalloc(sizeof(*eq), GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eq->fab = (struct fi_ib_fabric *) fabric;

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
		break;
	default:
		return -EINVAL;
	}

	eq->flags		= attr->flags;
	eq->eq_fid.fid.fclass	= FI_CLASS_EQ;
	eq->eq_fid.fid.context	= context;
	eq->eq_fid.fid.ops	= &fi_ib_eq_fi_ops;
	eq->eq_fid.ops		= &fi_ib_eq_ops;

	init_waitqueue_head(&eq->sem);
	INIT_LIST_HEAD(&eq->events);

	*_eq = &eq->eq_fid;

	return 0;
}
