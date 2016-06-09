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
#include <linux/sched.h>
#include <linux/delay.h>
#include <net/sock.h>

#include <kfabric.h>
#include <kfi_errno.h>
#include <kfi_endpoint.h>
#include <kfi_domain.h>
#include <kfi_tagged.h>
#include <kfi_cm.h>
#include <kfi_eq.h>

#include <common.h>

#define CTIMEOUT	20000
#define TIMEOUT		4000	/* 4 seconds */
#define SREAD		0
#define EAGAIN_TRIES	8
#define CONTEXT		(void *)(0xcafebabeL)
#define TX_POST_DEPTH	1

static char *local_ipaddr = TEST_ADDR;
module_param(local_ipaddr, charp, 0000);
MODULE_PARM_DESC(local_ipaddr, " local ipoib IPv4 address");

static char *svr_ipaddr = TEST_ADDR;
module_param(svr_ipaddr, charp, 0000);
MODULE_PARM_DESC(svr_ipaddr, " test server IPv4 address");

static int msg_len = BUFFER_SIZE;
module_param(msg_len, int, S_IRUSR);
MODULE_PARM_DESC(msg_len, " msg size in bytes");

static int num_msgs = 1;
module_param(num_msgs, int, S_IRUSR);
MODULE_PARM_DESC(num_msgs, " # of messages to send");

static int post_depth = TX_POST_DEPTH;
module_param(post_depth, int, S_IRUSR);
MODULE_PARM_DESC(post_depth, " # posted Tx buffers prior to reaping completions");

static int verify;
module_param(verify, int, S_IRUSR);
MODULE_PARM_DESC(verify, " output per message string data");

typedef struct {
	struct kfi_context	context;
	struct kfi_info		*prov;
	struct kfid_fabric	*fabric;
	struct kfid_domain	*domain;
	struct kfid_ep		*ep;
	struct kfid_eq		*eq;
	struct kfid_cq		*scq;
	struct kfid_cq		*rcq;
	struct kfid_mr		*mr;
	char			*buf;
} simple_context_t;

static simple_context_t		ctx;
static int			connected;

simple_context_t *kfi_to_simple_context(void *ctx)
{
	return container_of(ctx, simple_context_t, context);
}

int match_provider(struct kfi_info **prov)
{
	struct kfi_info		hints = { 0 };
	struct sockaddr_in	addr = { 0 };
	int			ret;

	/* ibverbs provider */
	hints.caps		= KFI_MSG | KFI_CANCEL | KFI_RECV;
	hints.addr_format	= KFI_SOCKADDR_IN;
	hints.src_addr		= &addr;
	hints.src_addrlen	= sizeof(addr);
	addr.sin_family		= AF_INET;
	addr.sin_port		= 0;

	ret = in4_pton(local_ipaddr, strlen(local_ipaddr),
			(u8 *)&addr.sin_addr.s_addr, '\0', NULL);
	if (ret != 1) {
		print_err("Err converting target server address '%s'?\n",
			svr_ipaddr);
		return -EINVAL;
	}

	ret = kfi_getinfo(KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION),
			  &hints, prov);
	if (ret) {
		print_err("ERR: kfi_getinfo() '%s'\n", kfi_strerror(ret));
		return ret;
	}

	if (!*prov) {
		print_err("No matching provider found?\n");
		return -EINVAL;
	}

	dprint(DEBUG_CONNECT, "provider %s\n", (*prov)->fabric_attr->prov_name);
	dprint(DEBUG_CONNECT, "name %s\n", (*prov)->fabric_attr->name);
	return 0;
}

int client_connect(struct kfi_info *prov, simple_context_t *ctx)
{
	struct kfi_eq_attr	eq_attr = { 0 };
	struct kfi_cq_attr	cq_attr = { 0 };
	struct sockaddr_in	addr = { 0 };
	int			ret;

	connected = 0;

	ret = kfi_fabric(prov->fabric_attr, &ctx->fabric, NULL);
	if (ret) {
		print_err("kfi_fabric returned %d\n", ret);
		ctx->fabric = NULL;
		return ret;
	}

	ret = kfi_domain(ctx->fabric, prov, &ctx->domain, NULL);
	if (ret) {
		print_err("kfi_fdomain returned %d\n", ret);
		ctx->domain = NULL;
		return ret;
	}

	/* set QP WR depth */
	prov->ep_attr->tx_ctx_cnt = (size_t) (post_depth + 1);
	prov->ep_attr->rx_ctx_cnt = (size_t) (post_depth + 1);

	/* set ScatterGather max depth */
	prov->tx_attr->iov_limit = 1;
	prov->rx_attr->iov_limit = 1;
	prov->tx_attr->inject_size = 0;	/* no INLINE support */

	ret = kfi_endpoint(ctx->domain, prov, &ctx->ep, CONTEXT);
	if (ret) {
		print_err("kfi_endpoint returned %d\n", ret);
		ctx->ep = NULL;
		return ret;
	}

	eq_attr.wait_obj	= KFI_WAIT_NONE;

	ret = kfi_eq_open(ctx->fabric, &eq_attr, &ctx->eq, NULL);
	if (ret) {
		print_err("kfi_eq_open returned %d\n", ret);
		ctx->eq = NULL;
		return ret;
	}

	cq_attr.size		= post_depth * 4;
	cq_attr.flags		= KFI_SEND;
	cq_attr.format		= KFI_CQ_FORMAT_MSG;
	cq_attr.wait_obj	= KFI_WAIT_NONE;
	cq_attr.wait_cond	= KFI_CQ_COND_NONE;

	ret = kfi_cq_open(ctx->domain, &cq_attr, &ctx->scq, NULL);
	if (ret) {
		print_err("kfi_cq_open returned %d\n", ret);
		ctx->scq = NULL;
		return ret;
	}

	cq_attr.flags		= KFI_RECV;

	ret = kfi_cq_open(ctx->domain, &cq_attr, &ctx->rcq, NULL);
	if (ret) {
		print_err("kfi_cq_open returned %d\n", ret);
		ctx->rcq = NULL;
		return ret;
	}

	ret = kfi_ep_bind(ctx->ep, &ctx->eq->fid, 0);
	if (ret) {
		print_err("kfi_ep_bind returned %d\n", ret);
		return ret;
	}

	ret = kfi_ep_bind(ctx->ep, &ctx->scq->fid, KFI_SEND);
	if (ret) {
		print_err("kfi_ep_bind returned %d\n", ret);
		return ret;
	}

	ret = kfi_ep_bind(ctx->ep, &ctx->rcq->fid, KFI_RECV);
	if (ret) {
		print_err("kfi_ep_bind returned %d\n", ret);
		return ret;
	}

	ret = kfi_enable(ctx->ep);
	if (ret) {
		print_err("kfi_enable returned %d\n", ret);
		return ret;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(TEST_PORT);
	ret = in4_pton(svr_ipaddr, strlen(svr_ipaddr),
			(u8 *)&addr.sin_addr.s_addr, '\0', NULL);
	if (ret != 1) {
		print_err("Err converting target server IP address '%s'?\n",
			svr_ipaddr);
		return -EINVAL;
	}

	ret = kfi_connect(ctx->ep, &addr, PRIVATE_DATA, sizeof(PRIVATE_DATA));
	if (ret) {
		print_err("kfi_connect returned %d\n", ret);
		return ret;
	}

	connected = 1;

	return 0;
}

void client_disconnect(simple_context_t *ctx)
{
	int ret;

	if (connected) {
		ret = kfi_shutdown(ctx->ep, 0);
		if (ret)
			print_err("ERR: kfi_shutdown() '%s'\n",
				kfi_strerror(ret));
		connected = 0;
	}

	if (ctx->mr) {
		kfi_close((struct kfid *) ctx->mr);
		ctx->mr = NULL;
	}
	if (!IS_ERR(ctx->buf)) {
		kfree(ctx->buf);
		ctx->buf = NULL;
	}
	if (ctx->rcq) {
		kfi_close((struct kfid *) ctx->rcq);
		ctx->rcq = NULL;
	}
	if (ctx->scq) {
		kfi_close((struct kfid *) ctx->scq);
		ctx->scq = NULL;
	}
	if (ctx->eq) {
		kfi_close((struct kfid *) ctx->eq);
		ctx->eq = NULL;
	}
	if (ctx->ep) {
		kfi_close((struct kfid *) ctx->ep);
		ctx->ep = NULL;
	}
	if (ctx->domain) {
		kfi_close((struct kfid *) ctx->domain);
		ctx->domain = NULL;
	}
	if (ctx->fabric) {
		kfi_close((struct kfid *) ctx->fabric);
		ctx->fabric = NULL;
	}
}

int do_test(void)
{
	struct kfi_cq_msg_entry	comp;
	int			len = msg_len * post_depth;
	int			msg_cnt = num_msgs;
	int			tx_bufs_sent = 0;
	int			ret;
	char			*mp;
	u64			time_elap;
#if SREAD == 0
	int			eagain_cnt = EAGAIN_TRIES;
#endif

	if (!ctx.buf) {
		ctx.buf = kmalloc(len, GFP_KERNEL);
		if (!ctx.buf) {
			print_err("kalloc failed!\n");
			return -ENOMEM;
		}

		ret = kfi_mr_reg(ctx.domain, ctx.buf, len, 0, 0, 0, 0,
				&ctx.mr, NULL, NULL);
		if (ret) {
			print_err("kfi_mr_reg returned %d\n", ret);
			kfree(ctx.buf);
			ctx.buf = ERR_PTR(-EFAULT);
			return ret;
		}
	} else if (IS_ERR(ctx.buf))
		return 0;

	print_msg("post_depth %d num_msgs %d msg_len %d SREAD[%d]\n",
		post_depth, num_msgs, msg_len, SREAD);

	print_dbg("ctx.buf %p '%s' len %ld msg_len %d\n",
		ctx.buf, ctx.buf, strlen(ctx.buf)+1, msg_len);

	time_elap = get_jiffies_64();

	for (mp = ctx.buf; msg_cnt > 0 && !kthread_should_stop(); ) {
		int post_cnt, cnt;

		post_cnt = (msg_cnt > post_depth ? post_depth : msg_cnt);

		for (cnt = 0, mp = ctx.buf; cnt < post_cnt;
			cnt++, mp += msg_len) {

			if (verify) {
				sprintf(mp, TEST_MESSAGE, tx_bufs_sent);
				tx_bufs_sent++;
			}

			ret = kfi_send(ctx.ep, mp, msg_len, kfi_mr_desc(ctx.mr),
					0, mp);
			if (ret) {
				print_err("kfi_send returned %d '%s'\n",
					ret, kfi_strerror(ret));
				return ret;
			}
			if (kthread_should_stop())
				return -EINTR;
		}

		/* reap completions */
		for (cnt = 0; cnt < post_cnt; cnt++) {
#if SREAD
			ret = kfi_cq_sread(ctx.scq, &comp, 1, 0, TIMEOUT);
			if (ret == -ETIMEDOUT) {
				print_msg("%s(ETIMEDOUT) cnt %d post_cnt %d "
					"msg_cnt %d\n", "kfi_cq_sread", cnt,
					post_cnt, msg_cnt);
			}
			if (kthread_should_stop())
				return -EINTR;
#else
			do {
				ret = kfi_cq_read(ctx.scq, &comp, 1);
				if (ret == 0 || ret == -EAGAIN) {
					if (--eagain_cnt <= 0) {
						dprint(DEBUG_HIGH,
							"%s(resched %d) cnt "
							"%d post_cnt %d\n",
							"kfi_cq_read", ret, cnt,
							post_cnt);
						eagain_cnt = EAGAIN_TRIES;
						schedule();
					}
				}
				if (kthread_should_stop())
					return -EINTR;
			} while (ret == 0 || ret == -EAGAIN);

#endif
			if (ret < 0) {
				struct kfi_cq_err_entry cqe = { 0 };
				int rc;

				rc = kfi_cq_readerr(ctx.scq, &cqe, 0);
				print_err("kfi_cq_read returned %d '%s'\n",
					ret, kfi_strerror(ret));
				if (rc) {
					char buf[64];

					print_err("kfi_cq_readerr() err '%s'(%d)"
						"\n", kfi_strerror(cqe.err),
						cqe.err);
					print_err("kfi_cq_readerr() prov_err "
						"'%s'(%d)\n",
						kfi_cq_strerror(ctx.scq,
							cqe.prov_errno,
							cqe.err_data, buf,
							sizeof(buf)),
						cqe.prov_errno);
				}
				return ret;
			}
			if (!ret)
				print_err("kfi_cq_sread no completion? ret %d\n",
					ret);
#if 0
			if ((char *)comp.op_context < (char *)ctx.buf ||
				(char *)comp.op_context >= (char *)
						&ctx.buf[msg_len*post_depth]) {

				print_err("cq.op_context(%p) not in range "
					"[ctx.buf(%p) ... &ctx.buf[%d](%p)]\n",
						(void *)comp.op_context,
						(void *)ctx.buf,
						msg_len,
						(void *)&ctx.buf[msg_len]);
			}
#endif
			if (verify)
				print_msg("Tx '%s'\n",
					(char *) comp.op_context);
		}
		msg_cnt -= post_cnt;
	}
	time_elap = get_jiffies_64() - time_elap;

#define AGIG (1024UL*1024UL*1024UL)
#define AMEG (1024UL*1024UL)
#define AKILO (1024UL)
	{
		struct timeval	tv;
		ulong		rate, rate_mod, bytes, units_of;
		char		units;

		jiffies_to_timeval(time_elap, &tv);

		bytes = (ulong) num_msgs * (ulong) msg_len;

		if (bytes >= AKILO && tv.tv_sec > 0) {
			rate = bytes / tv.tv_sec;
			rate_mod = bytes % tv.tv_sec;
			if (rate >= AGIG) {
				units = 'G';
				units_of = AGIG;
			} else if (rate >= AMEG) {
				units = 'M';
				units_of = AMEG;
			} else {
				units = 'K';
				units_of = AKILO;
			}
			rate /=  units_of;
		} else {
			rate = rate_mod = 0UL;
			units = ' ';
			units_of = 1UL;
		}

		print_info("Tx %d msgs (%lu.%lu%cB) @ ~%lu.%lu %cB/sec (%ld sec %ld "
			"usec)\n",
				num_msgs, (bytes/units_of), (bytes % units_of),
				units, rate, rate_mod, units,
				tv.tv_sec, tv.tv_usec);
	}

	return 0;
}

int create_connection(void)
{
	struct kfi_info		*prov;
	struct kfi_eq_cm_entry	entry;
	struct kfi_info		*info;
	ssize_t			n;
	uint32_t		event;
	int			ret = -1;

	memset(&ctx, 0, sizeof(ctx));

	if (match_provider(&prov))
		goto err1;

	if (client_connect(prov, &ctx))
		goto err2;

	dprint(DEBUG_CONNECT, "Waiting for Server to connect\n");

	n = kfi_eq_sread(ctx.eq, &event, &entry, sizeof(entry), CTIMEOUT, 0);
	if (n < sizeof(entry)) {
		struct kfi_eq_err_entry eqe;
		int rc;

		print_err("kfi_eq_sread '%s'(%d)\n", kfi_strerror(n), (int) n);
		rc = kfi_eq_readerr(ctx.eq, &eqe, 0);
		if (rc)
			print_err("kfi_eq_readerr() returns %d '%s'\n",
				rc, kfi_strerror(rc));
		else {
			char buf[64];

			print_err("kfi_eq_readerr() prov_err '%s'(%d)\n",
				kfi_eq_strerror(ctx.eq, eqe.prov_errno,
					eqe.err_data, buf, sizeof(buf)),
				eqe.prov_errno);
			print_err("kfi_eq_readerr() err '%s'(%d)\n",
					kfi_strerror(eqe.err), eqe.err);
		}

		return (int) n;
	}

	if (event != KFI_CONNECTED) {
		print_err("unexpected event %d\n", event);
		return -EIO;
	}

	/* same context specified in kfi_endpoint()? */
	if (entry.fid->context != CONTEXT) {
		print_err("entry.fid->context %lx != %lx\n",
			(ulong)entry.fid->context, (ulong)CONTEXT);
	}

	info = entry.info;

	dprint(DEBUG_CONNECT, "*** Client Connected\n");

	dprint(DEBUG_CONNECT, "Client private data(len %ld): '%s'\n",
		(n - sizeof(entry)), entry.data);

	return 0;
err2:
	client_disconnect(&ctx);
	kfi_freeinfo(prov);
err1:
	return ret;
}

void destroy_connection(void)
{
	(void) client_disconnect(&ctx);
}
