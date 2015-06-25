/*
 * Copyright (c) 2015 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/delay.h>
#include <net/sock.h>

#include <net/kfi/fabric.h>
#include <net/kfi/fi_errno.h>
#include <net/kfi/fi_endpoint.h>
#include <net/kfi/fi_domain.h>
#include <net/kfi/fi_tagged.h>
#include <net/kfi/fi_cm.h>

#define DRV_NAME "kfit_ibv_svr"

#include <common.h>

#define CTIMEOUT	20000
#define TIMEOUT		4000	/* 4 seconds */
#define SREAD		0
#define EAGAIN_TRIES	8
#define EAGAIN_BAIL	2000
#define RX_POST_DEPTH	1
#define CONTEXT		(void *)(0xcafebabeL)
#define PDATA_SZ	40

static char *local_ipaddr = TEST_ADDR;
module_param(local_ipaddr, charp, 0000);
MODULE_PARM_DESC(local_ipaddr, " local ipoib IPv4 address");

static int msg_len = BUFFER_SIZE;
module_param(msg_len, int, S_IRUSR);
MODULE_PARM_DESC(msg_len, " msg size in bytes");

static int num_msgs = RX_POST_DEPTH;
module_param(num_msgs, int, S_IRUSR);
MODULE_PARM_DESC(num_msgs, " # of expected messages");

static int post_depth = RX_POST_DEPTH;
module_param(post_depth, int, S_IRUSR);
MODULE_PARM_DESC(post_depth, " # posted Rx buffers");

static int verify;
module_param(verify, int, S_IRUSR);
MODULE_PARM_DESC(verify, " 1: verify received data, 0: no verify");

int connected;

typedef struct {
	struct fi_context	context;
	struct fi_info		*prov;
	struct fid_fabric	*fabric;
	struct fid_domain	*domain;
	struct fid_ep		*ep;
	struct fid_pep		*pep;
	struct fid_eq		*eq;
	struct fid_cq		*scq;
	struct fid_cq		*rcq;
	struct fid_mr		*mr;
	char			*buf;
} simple_context_t;

simple_context_t *fi_to_simple_context(void *ctx)
{
	return container_of(ctx, simple_context_t, context);
}

int match_provider(struct fi_info **prov)
{
	struct fi_info		hints = { 0 };
	struct fi_fabric_attr	attr = { 0 };
	struct sockaddr_in	addr = { 0 };
	int			ret;

	print_trace("in\n");

	/* ibverbs matching provider */
	hints.ep_type		= FI_EP_MSG;
	hints.caps		= FI_MSG | FI_CANCEL | FI_SOURCE;
	hints.addr_format	= FI_SOCKADDR_IN;
	hints.src_addr		= &addr;
	hints.src_addrlen	= sizeof(addr);
	addr.sin_family		= AF_INET;
	addr.sin_port		= htons(TEST_PORT);

	ret = in4_pton(local_ipaddr, strlen(local_ipaddr),
			(u8 *)&addr.sin_addr.s_addr, '\0', NULL);
	if (ret != 1) {
		print_err("Err converting local IP address '%s'?\n",
			local_ipaddr);
		return -EINVAL;
	}

	hints.fabric_attr		= &attr;
	hints.fabric_attr->prov_name	= kstrdup("ibverbs", GFP_KERNEL);

	ret = fi_getinfo(FI_VERSION(1, 0), &hints, prov);
	if (ret) {
		print_err("ERR: fi_getinfo() '%s'\n", fi_strerror(ret));
		return ret;
	}

	if (!*prov) {
		print_err("No tag matching provider found\n");
		return -EINVAL;
	}

	if ((*prov)->fabric_attr) {
		dprint(DEBUG_CONNECT, "provider %s\n",
			(*prov)->fabric_attr->prov_name);
		dprint(DEBUG_CONNECT, "name %s\n", (*prov)->fabric_attr->name);
	}

	return 0;
}

int server_listen(struct fi_info *prov, simple_context_t *ctx)
{
	struct fi_eq_attr	eq_attr = { 0 };
	int			ret;

	print_trace("in\n");

	ret = fi_fabric(prov->fabric_attr, &ctx->fabric, NULL);
	if (ret) {
		print_err("fi_fabric returned %d\n", ret);
		ctx->fabric = NULL;
		return ret;
	}

	ret = fi_passive_ep(ctx->fabric, prov, &ctx->pep, CONTEXT);
	if (ret) {
		print_err("fi_endpoint returned %d\n", ret);
		ctx->ep = NULL;
		return ret;
	}

	ret = fi_eq_open(ctx->fabric, &eq_attr, &ctx->eq, NULL);
	if (ret) {
		print_err("fi_eq_open returned %d\n", ret);
		ctx->eq = NULL;
		return ret;
	}

	ret = fi_pep_bind(ctx->pep, &ctx->eq->fid, 0);
	if (ret) {
		print_err("fi_pep_open returned %d\n", ret);
		ctx->eq = NULL;
		return ret;
	}

	ret = fi_listen(ctx->pep);
	if (ret) {
		print_err("fi_eq_open returned %d\n", ret);
		ctx->eq = NULL;
		return ret;
	}

	return 0;
}

int wait_for_client(struct fi_info *prov, simple_context_t *ctx)
{
	struct fi_cq_attr	cq_attr = { 0 };
	char			ebuf[sizeof(struct fi_eq_cm_entry) + PDATA_SZ];
	struct fi_eq_cm_entry	*entry = (struct fi_eq_cm_entry *) ebuf;
	struct fi_info		*info;
	struct sockaddr_in	*addr, *paddr;
	ssize_t			n;
	uint32_t		event;
	int			ret;
	int			buf_len = msg_len * post_depth;
	char			*msg;
	int			post_cnt, j;

	print_trace("in\n");

	dprint(DEBUG_CONNECT, "Waiting for Client to connect\n");

	n = fi_eq_sread(ctx->eq, &event, entry, sizeof(ebuf), CTIMEOUT, 0);
	if (n < sizeof(*entry)) {
		int rc;
		struct fi_eq_err_entry eqe = { 0 };

		print_err("fi_eq_sread '%s'\n", fi_strerror((int)n));

		rc = fi_eq_readerr(ctx->eq, &eqe, 0);
		if (rc)
			print_err("fi_eq_readerr() returns %d '%s'\n",
				rc, fi_strerror(rc));
		else {
			char buf[64];

			print_err("fi_eq_readerr() prov_err '%s'(%d)\n",
				fi_eq_strerror(ctx->eq, eqe.prov_errno,
					eqe.err_data, buf, sizeof(buf)),
				eqe.prov_errno);
			print_err("fi_eq_readerr() err '%s'\n",
				fi_strerror(eqe.err));
		}
		return (int) n;
	}

	if (event != FI_CONNREQ) {
		print_err("unexpected event %d\n", event);
		return -FI_EOTHER;
	}

	if (n > sizeof(*entry)) {
		j = strncmp(entry->data, PRIVATE_DATA, sizeof(PRIVATE_DATA));
		if (j == 0) {
			/* length here is eq_sread buf len - sizeof(*eq). */
			print_msg("Private Data: '%s'\n", entry->data);
		} else
			print_msg("BAD private data != expected '%s'\n",
				PRIVATE_DATA);
	}

	if (entry->fid->context != CONTEXT) {
		print_err("entry->fid->context %lx != %lx\n",
			(ulong)(entry->fid->context), (ulong)CONTEXT);
	}

	info = entry->info;

	addr = (struct sockaddr_in *) info->src_addr;
	paddr = (struct sockaddr_in *) prov->src_addr;

	dprint(DEBUG_CONNECT, "info->src_addr %pI4:%hu\n",
		&addr->sin_addr.s_addr, ntohs(addr->sin_port));
	dprint(DEBUG_CONNECT, "prov->src_addr %pI4:%hu\n",
		&paddr->sin_addr.s_addr, ntohs(paddr->sin_port));

	*addr = *paddr;
	addr->sin_port = 0;

	ret = fi_domain(ctx->fabric, info, &ctx->domain, NULL);
	if (ret) {
		print_err("fi_domain returned %d\n", ret);
		ctx->domain = NULL;
		goto err;
	}

	/* set QP WR depth */
	info->ep_attr->tx_ctx_cnt = (size_t) (post_depth + 1);
	info->ep_attr->rx_ctx_cnt = (size_t) (post_depth + 1);

	/* set ScatterGather max depth */
	info->tx_attr->iov_limit = 1;
	info->rx_attr->iov_limit = 1;
	info->tx_attr->inject_size = 0; /* no INLINE support */

	ret = fi_endpoint(ctx->domain, info, &ctx->ep, entry->fid->context);
	if (ret) {
		print_err("fi_endpoint returned %d\n", ret);
		ctx->ep = NULL;
		goto err;
	}

	cq_attr.size		= post_depth * 2;
	cq_attr.flags		= FI_SEND;
	cq_attr.format		= FI_CQ_FORMAT_MSG;
	cq_attr.wait_obj	= FI_WAIT_NONE;
	cq_attr.wait_cond	= FI_CQ_COND_NONE;

	ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->scq, NULL);
	if (ret) {
		print_err("fi_cq_open returned %d\n", ret);
		ctx->scq = NULL;
		goto err;
	}
	cq_attr.flags		= FI_RECV;

	ret = fi_cq_open(ctx->domain, &cq_attr, &ctx->rcq, NULL);
	if (ret) {
		print_err("fi_cq_open returned %d\n", ret);
		ctx->rcq = NULL;
		goto err;
	}

	/* reuse eq from listen */
	ret = fi_ep_bind(ctx->ep, &ctx->eq->fid, 0);
	if (ret) {
		print_err("fi_ep_bind returned %d\n", ret);
		goto err;
	}

	ret = fi_ep_bind(ctx->ep, &ctx->scq->fid, FI_SEND);
	if (ret) {
		print_err("fi_ep_bind returned %d\n", ret);
		goto err;
	}

	ret = fi_ep_bind(ctx->ep, &ctx->rcq->fid, FI_RECV);
	if (ret) {
		print_err("fi_ep_bind returned %d\n", ret);
		goto err;
	}

	ret = fi_enable(ctx->ep);
	if (ret) {
		print_err("fi_enable returned %d\n", ret);
		goto err;
	}

	ctx->buf = kzalloc(buf_len, GFP_KERNEL);
	if (!ctx->buf) {
		print_err("kalloc failed!\n");
		ret = -ENOMEM;
		goto err;
	}

	ret = fi_mr_reg(ctx->domain, ctx->buf, buf_len, 0, 0, 0, 0,
			&ctx->mr, NULL);
	if (ret) {
		print_err("fi_mr_reg returned %d\n", ret);
		ctx->buf = ERR_PTR(-EFAULT);
		goto err;
	}

	post_cnt = (post_depth > num_msgs ? num_msgs : post_depth);

	for (msg = ctx->buf, j = 0; j < post_cnt; j++, msg += msg_len) {
		ret = fi_recv(ctx->ep, msg, msg_len, fi_mr_desc(ctx->mr),
			      0, msg);
		if (ret) {
			print_err("Err pre-posting (buf %d of %d) fi_recv "
				"ret(%d)\n", j+1, post_cnt, ret);
			goto err;
		}
	}
	dprint(DEBUG_CONNECT, "pre-posted %d Rx bufs\n", post_cnt);

	dprint(DEBUG_CONNECT, "fi_accept()ing\n");
	ret = fi_accept(ctx->ep, NULL, 0);
	if (ret) {
		print_err("fi_accept returned %d\n", ret);
		goto err;
	}

	dprint(DEBUG_CONNECT,
		"Connection accepted, waiting for Client to complete\n");

	n = fi_eq_sread(ctx->eq, &event, entry, sizeof(*entry), CTIMEOUT, 0);
	if (n != sizeof(*entry)) {
		print_err("fi_eq_sread %d\n", (int) n);
		return (int) n;
	}

	if (event != FI_CONNECTED) {
		print_err("unexpected event %d\n", event);
		return -FI_EOTHER;
	}

	if (entry->fid != &ctx->ep->fid) {
		print_err("fid %p != %p\n", entry->fid, &ctx->ep->fid);
		return -FI_EOTHER;
	}

	if (entry->fid->context != CONTEXT) {
		print_err("entry->fid->context %lx != %lx\n",
			(ulong)entry->fid->context, (ulong)CONTEXT);
	}
	connected++;
	dprint(DEBUG_CONNECT, "Server Connected\n");

	return 0;
err:
	fi_reject(ctx->pep, info->connreq, NULL, 0);

	return ret;
}

void server_disconnect(simple_context_t *ctx)
{
	int ret;

	print_trace("in\n");

	if (connected) {
		ret = fi_shutdown(ctx->ep, 0);
		if (ret)
			print_err("ERR: fi_shutdown() '%s'\n",
				fi_strerror(ret));
			connected = 0;
	}

	if (ctx->mr) {
		fi_close((struct fid *) ctx->mr);
		ctx->mr = NULL;
	}
	if (!IS_ERR(ctx->buf)) {
		kfree(ctx->buf);
		ctx->buf = NULL;
	}
	if (ctx->scq) {
		fi_close((struct fid *) ctx->scq);
		ctx->scq = NULL;
	}
	if (ctx->rcq) {
		fi_close((struct fid *) ctx->rcq);
		ctx->rcq = NULL;
	}
	if (ctx->eq) {
		fi_close((struct fid *) ctx->eq);
		ctx->eq = NULL;
	}
	if (ctx->pep) {
		fi_close((struct fid *) ctx->pep);
		ctx->ep = NULL;
	}
	if (ctx->ep) {
		fi_close((struct fid *) ctx->ep);
		ctx->ep = NULL;
	}
	if (ctx->domain) {
		fi_close((struct fid *) ctx->domain);
		ctx->domain = NULL;
	}
	if (ctx->fabric) {
		fi_close((struct fid *) ctx->fabric);
		ctx->fabric = NULL;
	}
}

simple_context_t	ctx;

int do_test(void)
{
	struct fi_cq_msg_entry	comp;
	int			ret;
	static char		buf[] = TEST_MESSAGE;
	int			len = (int) sizeof(buf);
	int			msg_cnt = num_msgs;
	int			received_buf_cnt = 0;
#if SREAD == 0
	int			eagain_cnt = EAGAIN_TRIES;
	char			*cq_read_style = "fi_cq_sread";
#else
	char			*cq_read_style = "fi_cq_read";
#endif

	print_msg("post_depth %d num_msgs %d msg_len %d SREAD[%d]\n",
		post_depth, num_msgs, msg_len, SREAD);

	/* post_depth receives were posted prior to fi_accept()ing the conn */
	while (msg_cnt && !kthread_should_stop()) {
#if SREAD
		ret = fi_cq_sread(ctx.rcq, (void *)&comp, 1, 0, TIMEOUT);
		if (ret == -ETIMEDOUT) {
			print_msg("%s(ETIMEDOUT) msg_cnt %d\n",
				cq_read_style, msg_cnt);
		}
		if (kthread_should_stop())
				return 0;
#else
		uint eagain_poll = 0;
		do {
			ret = fi_cq_read(ctx.rcq, (void *) &comp, 1);
			if (ret == 0 || ret == -EAGAIN) {
				if (++eagain_poll > EAGAIN_BAIL) {
					print_err("eagain_poll %d > "
						"EAGAIN_BAIL %d\n",
						eagain_poll, EAGAIN_BAIL);
					return -EINTR;
				}
				if (--eagain_cnt <= 0) {
					eagain_cnt = EAGAIN_TRIES;
					dprint(DEBUG_HIGH,
						"EAGAIN reschedule ret %d\n",
						ret);
					schedule();
				}
			}
			if (kthread_should_stop())
				return -EINTR;
		} while (ret == 0 || ret == -EAGAIN);
#endif
		if (ret < 0) {
			int rc;
			struct fi_cq_err_entry cqe = { 0 };

			print_err("%s returned %d\n", cq_read_style, ret);
			rc = fi_cq_readerr(ctx.rcq, &cqe, 0);
			if (rc)
				print_err("fi_cq_readerr() returns %d '%s'\n",
					rc, fi_strerror(rc));
			else {
				char buf[64];

				print_err("fi_cq_readerr() prov_err '%s'(%d)\n",
					fi_cq_strerror(ctx.rcq, cqe.prov_errno,
						cqe.err_data, buf, sizeof(buf)),
					cqe.prov_errno);
				print_err("fi_cq_readerr() err '%s'(%d)\n",
					fi_strerror(cqe.err), cqe.err);
			}
			return ret;
		}
		msg_cnt--;

		if (comp.len != msg_len)
			print_err("Bad data len, len(%ld) != expected(%d)\n",
				comp.len, msg_len);
		else if (verify) {
			sprintf(buf, TEST_MESSAGE, received_buf_cnt);
			if (strncmp(comp.op_context, buf, len))
				print_err("strcmp(expected\n'%s', got\n'%s')\n",
					buf, (char *)comp.op_context);
			else
				dprint(DEBUG_LOW, "Message %d of %d received\n",
					(num_msgs - msg_cnt), num_msgs);
			received_buf_cnt++;
		}

		if (msg_cnt > (post_depth - 1)) {
			/* repost buffer */
			ret = fi_recv(ctx.ep, comp.op_context, msg_len,
					fi_mr_desc(ctx.mr), 0, comp.op_context);
			if (ret) {
				print_err("fi_recv returned %d '%s'\n",
					ret, fi_strerror(ret));
				return ret;
			}
		}
	}
	print_msg("%d Message(s) Received Correctly\n", num_msgs);

	return num_msgs;
}

int create_connection(void)
{
	struct fi_info		*prov;
	int			ret = -1;

	print_trace("in\n");

	memset(&ctx, 0, sizeof(ctx));

	if (match_provider(&prov))
		goto err1;

	if (server_listen(prov, &ctx))
		goto err2;

	if (wait_for_client(prov, &ctx)) {
		server_disconnect(&ctx);
		goto err2;
	}

	fi_freeinfo(prov);

	return 0;

err2:
	fi_freeinfo(prov);
err1:
	return ret;
}

void destroy_connection(void)
{
	print_trace("in\n");
	server_disconnect(&ctx);
}

