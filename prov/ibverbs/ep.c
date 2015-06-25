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
#include "send.h"

#define LISTEN_BACKLOG		5

void dump_addr(struct rdma_cm_id *id)
{
	print_dbg(" dev %s port %d\n", id->device->name, id->port_num);
	print_dbg(" src %s\n",
		  addr2str((struct sockaddr_in *)&id->route.addr.src_addr));
	print_dbg(" dst %s\n",
		  addr2str((struct sockaddr_in *)&id->route.addr.dst_addr));
}

/* Handle connection events and move the connection along */
static int listen_events(struct rdma_cm_id *id, struct rdma_cm_event *ev)
{
	struct fi_ib_passive_ep	*pep = id->context;
	struct fi_ib_eq		*eq = pep->eq;
	struct fi_ib_event	*event;
	unsigned long		flags;

	switch (ev->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		dprint(DEBUG_CONNECT, "CONNECT_REQUEST\n");
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		dprint(DEBUG_CONNECT, "ESTABLISHED\n");
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		dprint(DEBUG_CONNECT, "DISCONNECTED\n");
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		dprint(DEBUG_CONNECT, "DEVICE REMOVED\n");
		break;
	case RDMA_CM_EVENT_ADDR_CHANGE:
		dprint(DEBUG_CONNECT, "ADDRESS CHANGE\n");
		break;
	default:
		print_err("CM Event 0x%X status %d\n", ev->event, ev->status);
		dump_addr(id);
		break;
	}

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		print_err("kalloc failed!\n");
		return -ENOMEM;
	}

	event->id = id;
	event->ev = *ev;

	spin_lock_irqsave(&eq->lock, flags);
	list_add(&event->node, &eq->events);
	spin_unlock_irqrestore(&eq->lock, flags);

	wake_up_interruptible(&eq->sem);
	return 0;
}

/* Handle connection events and move the connection along */
static int cm_events(struct rdma_cm_id *id, struct rdma_cm_event *ev)
{
	struct fi_ib_ep		*ep = id->context;
	struct fi_ib_eq		*eq = ep->eq;
	struct fi_ib_event	*event;
	unsigned long		flags;

	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		dprint(DEBUG_CONNECT, "Address resolved\n");
		ep->state = STATE_ADDR_RESOLVED;
		goto out;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		dprint(DEBUG_CONNECT, "Route resolved\n");
		dump_addr(id);
		ep->state = STATE_ROUTE_RESOLVED;
		goto out;
	case RDMA_CM_EVENT_ESTABLISHED:
		dprint(DEBUG_CONNECT, "Connection Established\n");
		dump_addr(id);
		ep->state = STATE_CONNECTED;
		break;
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		print_err("Connection Response: status %d\n", ev->status);
		ep->state = STATE_ERROR;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		dprint(DEBUG_CONNECT, "Connection Disconnected\n");
		dump_addr(id);
		ep->state = STATE_NOT_CONNECTED;
		break;
	case RDMA_CM_EVENT_REJECTED:
		print_err("Connection Rejected\n");
		ep->state = STATE_ERROR;
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
		print_err("Address Error, status %d\n", ev->status);
		ep->state = STATE_ERROR;
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		print_err("Route Error, status %d\n", ev->status);
		ep->state = STATE_ERROR;
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
		print_err("Connect Error, status %d\n", ev->status);
		ep->state = STATE_ERROR;
		break;
	case RDMA_CM_EVENT_UNREACHABLE:
		print_err("Unreachable, status %d\n", ev->status);
		ep->state = STATE_ERROR;
		break;
	default:
		print_err("CM Event 0x%X status %d\n", ev->event, ev->status);
		dump_addr(id);
		ep->state = STATE_ERROR;
	}

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		print_err("kalloc failed!\n");
		return -ENOMEM;
	}

	event->id = id;
	event->ev = *ev;

	spin_lock_irqsave(&eq->lock, flags);
	list_add(&event->node, &eq->events);
	spin_unlock_irqrestore(&eq->lock, flags);
out:
	wake_up_interruptible(&eq->sem);
	return 0;
}

/* Wait until desired state is reached */
static int wait_for_state(struct fi_ib_ep *ep, int desired)
{
	struct fi_ib_eq		*eq = ep->eq;

	wait_event_interruptible_timeout(eq->sem,
		((ep->state == desired) || (ep->state < 0)), TIMEOUT);

	return (ep->state == desired) ? 0 : -ETIMEDOUT;
}

static int connect_to_server(struct fi_ib_ep *ep, struct sockaddr *dst,
			     struct rdma_conn_param *param)
{
	int			ret;
	struct rdma_cm_id	*id = ep->id;
	struct sockaddr_in	*dst_in = (struct sockaddr_in *) dst;
	char			tag[20];

	dprint(DEBUG_CONNECT, "Connecting to %s\n", addr2str(dst_in));

	ret = rdma_resolve_addr(id, NULL, dst, TIMEOUT);
	if (ret) {
		strcpy(tag, "rdma_resolve_addr");
		goto err;
	}

	dprint(DEBUG_CONNECT, "waiting for ADDR_RESOLVED\n");
	ret = wait_for_state(ep, STATE_ADDR_RESOLVED);
	if (ret)
		goto out;

	ret = rdma_resolve_route(id, TIMEOUT);
	if (ret) {
		strcpy(tag, "rdma_resolve_route");
		goto out;
	}

	dprint(DEBUG_CONNECT, "waiting for ROUTE_RESOLVED\n");
	ret = wait_for_state(ep, STATE_ROUTE_RESOLVED);
	if (ret)
		goto out;

	ret = rdma_connect(id, param);
	if (ret) {
		strcpy(tag, "rdma_connect");
		goto out;
	}

	schedule();
	return 0;

err:
	if (ret == -ETIMEDOUT) {
		print_dbg("%s timed out\n", tag);
		ep->state = STATE_TIMEDOUT;
	} else
		print_err("%s returned %d\n", tag, ret);

out:
	print_err("Failed to connect to %s\n", addr2str(dst_in));
	return ret;
}

static int create_qp(struct fi_ib_ep *ep)
{
	struct ib_qp_init_attr	attr = { 0 };
	int			ret;

	print_trace("in\n");

	if (!ep->scq || !ep->rcq)
		return -EINVAL;

	if (!ep->scq->cq || !ep->rcq->cq)
		return -EINVAL;

	attr.cap.max_send_wr	= ep->tx_wr_depth;
	attr.cap.max_recv_wr	= ep->rx_wr_depth;
	attr.cap.max_send_sge	= ep->tx_sge_max;
	attr.cap.max_recv_sge	= ep->rx_sge_max;
	attr.cap.max_inline_data = ep->inline_size;
	attr.qp_context		= ep;
	attr.send_cq		= ep->scq->cq;
	attr.recv_cq		= ep->rcq->cq;
	attr.srq		= NULL;
	attr.qp_type		= IB_QPT_RC;

	ret = rdma_create_qp(ep->id, ep->rcq->domain->pd, &attr);
	if (ret)
		print_err("rdma_create_qp returned %d\n", ret);

	return ret;
}

static struct fi_ops_msg fi_ib_ep_msg_ops = {
	.size		= sizeof(struct fi_ops_msg),
	.recv		= fi_ib_ep_recv,
	.recvv		= fi_ib_ep_recvv,
	.recvmsg	= fi_ib_ep_recvmsg,
	.send		= fi_ib_ep_send,
	.sendv		= fi_ib_ep_sendv,
	.sendmsg	= fi_ib_ep_sendmsg,
	.inject		= fi_no_msg_inject,
	.senddata	= fi_ib_ep_senddata
};

static struct fi_ops_rma fi_ib_ep_rma_ops = {
	.size		= sizeof(struct fi_ops_rma),
	.read		= fi_ib_ep_rma_read,
	.readv		= fi_ib_ep_rma_readv,
	.readmsg	= fi_ib_ep_rma_readmsg,
	.write		= fi_ib_ep_rma_write,
	.writev		= fi_ib_ep_rma_writev,
	.writemsg	= fi_ib_ep_rma_writemsg,
	.inject		= fi_no_rma_inject,
	.writedata	= fi_ib_ep_rma_writedata
};

static struct fi_ops_atomic fi_ib_ep_atomic_ops = {
	.size		= sizeof(struct fi_ops_atomic),
	.write		= fi_ib_ep_atomic_write,
	.writev		= fi_ib_ep_atomic_writev,
	.writemsg	= fi_ib_ep_atomic_writemsg,
	.readwrite	= fi_ib_ep_atomic_readwrite,
	.readwritev	= fi_ib_ep_atomic_readwritev,
	.readwritemsg	= fi_ib_ep_atomic_readwritemsg,
	.compwrite	= fi_ib_ep_atomic_compwrite,
	.compwritev	= fi_ib_ep_atomic_compwritev,
	.compwritemsg	= fi_ib_ep_atomic_compwritemsg,
	.writevalid	= fi_ib_ep_atomic_writevalid,
	.readwritevalid	= fi_ib_ep_atomic_readwritevalid,
	.compwritevalid	= fi_ib_ep_atomic_compwritevalid
};

static int fi_ib_ep_connect(struct fid_ep *_ep, const void *addr,
				const void *param, size_t paramlen)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct rdma_conn_param	conn_param = { 0 };
	struct sockaddr		*dst = (struct sockaddr *) addr;
	int			ret;

	print_trace("in\n");

	if (!ep->id->qp) {
		ret = _ep->fid.ops->control(&_ep->fid, FI_ENABLE, NULL);
		if (ret)
			return ret;
	}

	conn_param.private_data		= param;
	conn_param.private_data_len	= paramlen;
	conn_param.responder_resources	= RDMA_MAX_RESP_RES;
	conn_param.initiator_depth	= RDMA_MAX_INIT_DEPTH;
	conn_param.flow_control		= RDMA_CONN_FLOW_CONTROL;
	conn_param.retry_count		= RDMA_CONN_RETRY_COUNT;
	conn_param.rnr_retry_count	= RDMA_CONN_RNR_RETRY;

	ret = connect_to_server(ep, dst, &conn_param);
	if (ret)
		print_err("connect_to_server returned %d\n", ret);

	return ret;
}

static int fi_ib_ep_accept(struct fid_ep *_ep, const void *param,
			       size_t paramlen)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	struct rdma_conn_param	conn_param;
	int			ret;

	print_trace("in\n");

	if (!ep->id->qp) {
		ret = _ep->fid.ops->control(&_ep->fid, FI_ENABLE, NULL);
		if (ret)
			return ret;
	}

	memset(&conn_param, 0, sizeof(conn_param));

	conn_param.private_data		= param;
	conn_param.private_data_len	= paramlen;
	conn_param.responder_resources	= RDMA_MAX_RESP_RES;
	conn_param.initiator_depth	= RDMA_MAX_INIT_DEPTH;
	conn_param.flow_control		= RDMA_CONN_FLOW_CONTROL;
	conn_param.rnr_retry_count	= RDMA_CONN_RNR_RETRY;

	ret = rdma_accept(ep->id, &conn_param);
	if (ret)
		print_err("rdma_accept returned %d\n", ret);

	schedule();
	return ret;
}

int fi_ib_ep_reject(struct fid_pep *pep, fi_connreq_t connreq,
			const void *param, size_t paramlen)
{
	int			ret;

	print_trace("in\n");

	ret = rdma_reject((struct rdma_cm_id *)connreq, param,
				(uint8_t) paramlen);
	if (ret)
		print_err("rdma_reject returned %d\n", ret);

	schedule();
	return ret;
}

static int fi_ib_ep_shutdown(struct fid_ep *_ep, uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;
	int			ret;

	print_trace("in\n");

	ret = rdma_disconnect(ep->id);
	if (ret)
		print_err("rdma_disconnect returned %d\n", ret);
	else
		ret = wait_for_state(ep, STATE_NOT_CONNECTED);

	return ret;
}

static struct fi_ops_cm fi_ib_ep_cm_ops = {
	.size		= sizeof(struct fi_ops_cm),
	.getname	= NULL, /* TODO */
	.getpeer	= fi_no_getpeer,
	.connect	= fi_ib_ep_connect,
	.listen		= fi_no_listen,
	.accept		= fi_ib_ep_accept,
	.reject		= fi_no_reject,
	.shutdown	= fi_ib_ep_shutdown
};

static int
fi_ib_ep_getopt(struct fid *fid, int level, int optname,
		    void *optval, size_t *optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int
fi_ib_ep_setopt(struct fid *fid, int level, int optname,
		    const void *optval, size_t optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int fi_ib_ep_enable(struct fid_ep *_ep)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) _ep;

	print_trace("in\n");

	if (!ep->eq || !ep->id->device)
		return -FI_ENOEQ;

	return create_qp(ep);
}

static int fi_ib_ep_control(struct fid *fid, int command, void *arg)
{
        struct fid_ep *ep;

        switch (fid->fclass) {
        case FI_CLASS_EP:
                ep = container_of(fid, struct fid_ep, fid);
                switch (command) {
                case FI_ENABLE:
                        return fi_ib_ep_enable(ep);
                        break;
                default:
                        return -FI_ENOSYS;
                }
                break;
        default:
                return -FI_ENOSYS;
        }
}


static struct fi_ops_ep fi_ib_ep_base_ops = {
	.size		= sizeof(struct fi_ops_ep),
	.cancel		= fi_no_cancel,
	.getopt		= fi_ib_ep_getopt,
	.setopt		= fi_ib_ep_setopt,
};

static int fi_ib_ep_close(struct fid *fid)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) fid;

	print_trace("in\n");

	if (ep->id) {
		rdma_destroy_id(ep->id);
		ep->id = NULL;
	}

	kfree(ep);
	return 0;
}

static int fi_ib_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct fi_ib_ep		*ep = (struct fi_ib_ep *) fid;
	int			ret = -EINVAL;

	print_trace("in\n");

	if (bfid->fclass == FI_CLASS_EQ) {
		ret = 0;
		ep->eq = (struct fi_ib_eq *) bfid;
	} else if (bfid->fclass == FI_CLASS_CQ) {
		if (flags & FI_SEND) {
			ret = 0;
			ep->scq = (struct fi_ib_cq *) bfid;
		} else if (flags & FI_RECV) {
			ret = 0;
			ep->rcq = (struct fi_ib_cq *) bfid;
		}
	}

	return ret;
}

static struct fi_ops fi_ib_ep_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_ib_ep_close,
	.bind		= fi_ib_ep_bind,
	.control	= fi_ib_ep_control,
	.ops_open	= fi_no_ops_open
};

static int get_ep_info(struct fi_info *hints, struct fid *fid)
{
	struct rdma_cm_id	*id;
	int			ret;

	print_trace("in\n");

	if (fid->fclass == FI_CLASS_PEP) {
		struct fi_ib_passive_ep	*pep = (struct fi_ib_passive_ep *) fid;

		if (hints && hints->src_addrlen && hints->src_addr)
			memcpy(&pep->addr, hints->src_addr,
			       hints->src_addrlen);

		id = rdma_create_id(listen_events, pep, RDMA_PS_TCP, IB_QPT_RC);
		if (IS_ERR(id)) {
			ret = PTR_ERR(id);
			print_err("rdma_create_id returned %d\n", ret);
			return ret;
		}

		pep->id = id;

		ret = rdma_bind_addr(id, (struct sockaddr *) &pep->addr);
		if (ret)
			print_err("rdma_bind_addr returned %d\n", ret);
	} else {
		struct fi_ib_ep	*ep = (struct fi_ib_ep *) fid;

		ep->addr.sin_family = AF_INET;

		if (hints) {
			if (hints->src_addrlen && hints->src_addr)
				memcpy(&ep->addr, hints->src_addr,
				       hints->src_addrlen);
#if 0
			else if (hints->src_addrlen && hints->src_addr)
				ep->addr.sin_family =
					((struct sockaddr *)
						hints->dest_addr)->sa_family;
#endif
		}

		id = rdma_create_id(cm_events, ep, RDMA_PS_TCP, IB_QPT_RC);
		if (IS_ERR(id)) {
			ret = PTR_ERR(id);
			print_err("rdma_create_id returned %d\n", ret);
			return ret;
		}

		ep->id = id;

		ret = rdma_bind_addr(id, (struct sockaddr *) &ep->addr);
		if (ret)
			print_err("rdma_bind_addr returned %d\n", ret);
	}

	return ret;
}

int fi_ib_ep_open(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **_ep, void *context)
{
	struct fi_ib_ep		*ep;
	int			ret;

	print_trace("in\n");

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep)
		return -FI_ENOMEM;

	ep->ep_fid.fid.fclass	= FI_CLASS_EP;

	ep->tx_wr_depth = SEND_WRS;
	if (info->ep_attr && info->ep_attr->tx_ctx_cnt > 0)
		ep->tx_wr_depth = info->ep_attr->tx_ctx_cnt;

	ep->rx_wr_depth = RECV_WRS;
	if (info->ep_attr && info->ep_attr->rx_ctx_cnt > 0)
		ep->rx_wr_depth = info->ep_attr->rx_ctx_cnt;

	ep->tx_sge_max = DEF_SEND_SGE;
	if (info->tx_attr && info->tx_attr->iov_limit > 0)
		ep->tx_sge_max = info->tx_attr->iov_limit;

	ep->rx_sge_max = DEF_RECV_SGE;
	if (info->rx_attr && info->rx_attr->iov_limit > 0)
		ep->rx_sge_max = info->rx_attr->iov_limit;

	ep->inline_size = 0;	// depends on SGL max.
	if (info->tx_attr && info->tx_attr->inject_size > 0)
		ep->inline_size = info->tx_attr->inject_size;

	if (!info->connreq) {
		ret = get_ep_info(info, &ep->ep_fid.fid);
		if (ret)
			goto err;
	} else
		ep->id = (struct rdma_cm_id *) info->connreq;

	if (info->src_addrlen) {
		if (info->src_addrlen != sizeof(ep->addr))
			return -EINVAL;

		memcpy(&ep->addr, info->src_addr, sizeof(ep->addr));
	}

	ep->id->context		= ep;

	ep->ep_fid.fid.context	= context;
	ep->ep_fid.fid.ops	= &fi_ib_ep_ops;
	ep->ep_fid.ops		= &fi_ib_ep_base_ops;
	ep->ep_fid.msg		= &fi_ib_ep_msg_ops;
	ep->ep_fid.cm		= &fi_ib_ep_cm_ops;
	ep->ep_fid.rma		= &fi_ib_ep_rma_ops;
	ep->ep_fid.atomic	= &fi_ib_ep_atomic_ops;

	ep->domain = (struct fi_ib_domain *) domain;

	*_ep = &ep->ep_fid;

	return 0;
err:
	kfree(ep);
	return ret;
}

static int fi_ib_passive_ep_listen(struct fid_pep *_pep)
{
	struct fi_ib_passive_ep	*pep = (struct fi_ib_passive_ep *) _pep;
	struct rdma_cm_id	*id;
	int			ret;

	print_trace("in\n");

	id = pep->id;

	ret = rdma_listen(pep->id, LISTEN_BACKLOG);
	if (ret)
		print_err("rdma_listen returned %d\n", ret);

	schedule();
	return ret;
}

static struct fi_ops_cm fi_ib_passive_ep_cm_ops = {
	.size		= sizeof(struct fi_ops_cm),
	.getname	= NULL, /* TODO */
	.getpeer	= fi_no_getpeer,
	.connect	= fi_no_connect,
	.listen		= fi_ib_passive_ep_listen,
	.accept		= fi_no_accept,
	.reject		= fi_ib_ep_reject,
	.shutdown	= fi_no_shutdown,
};

static int fi_ib_passive_ep_bind(struct fid *fid, struct fid *bfid,
				 uint64_t flags)
{
	struct fi_ib_passive_ep	*pep = (struct fi_ib_passive_ep *) fid;

	print_trace("in\n");

	if (bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	pep->eq = (struct fi_ib_eq *) bfid;

	return 0;
}

static int fi_ib_passive_ep_close(struct fid *fid)
{
	struct fi_ib_passive_ep	*pep = (struct fi_ib_passive_ep *) fid;

	if (pep->id)
		rdma_destroy_id(pep->id);

	kfree(pep);
	return 0;
}

static struct fi_ops fi_ib_passive_ep_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_ib_passive_ep_close,
	.bind		= fi_ib_passive_ep_bind,
	.control	= fi_no_control,
	.ops_open	= fi_no_ops_open,
};

int fi_ib_pendpoint(struct fid_fabric *fabric, struct fi_info *info,
		    struct fid_pep **_pep, void *context)
{
	struct fi_ib_passive_ep	*pep;
	int			ret;

	pep = kzalloc(sizeof(*pep), GFP_KERNEL);
	if (!pep) {
		print_err("kalloc failed!\n");
		return -FI_ENOMEM;
	}

	pep->u.pep_fid.fid.fclass	= FI_CLASS_PEP;

	ret = get_ep_info(info, &pep->u.pep_fid.fid);
	if (ret)
		goto err;

	pep->id->context		= pep;

	pep->u.pep_fid.fid.context	= context;
	pep->u.pep_fid.fid.ops		= &fi_ib_passive_ep_ops;
	pep->u.pep_fid.cm		= &fi_ib_passive_ep_cm_ops;

	*_pep = &pep->u.pep_fid;
	return 0;
err:
	kfree(pep);
	return ret;
}
