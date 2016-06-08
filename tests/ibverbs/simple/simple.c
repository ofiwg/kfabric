/*
 * Open Fabric Interface Test - Simple
 *
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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <kfabric.h>
#include <kfi_domain.h>
#include <kfi_eq.h>
#include <kfi_endpoint.h>
#include <kfi_cm.h>
#include <kfi_msg.h>
#include <kfi_rma.h>
#include <kfi_atomic.h>
#include <kfi_tagged.h>

MODULE_AUTHOR("Frank Yang, Chen Zhao");
MODULE_DESCRIPTION("Open Fabric Interface Tests - Simple");
MODULE_LICENSE("Dual BSD/GPL");

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "KFI_test(simple)"

#include <kfi_log.h>

/* Command line arguments */

static char role[10] = {0};
static char addr_str[INET_ADDRSTRLEN] = {0};
static int port = 0;
static bool server = false;
struct sockaddr sock_addr = {0};

module_param_string(role, role, sizeof(role), 0);
MODULE_PARM_DESC(role, "Module role: client or server.");
module_param_string(addr, addr_str, sizeof(addr_str), 0);
MODULE_PARM_DESC(role, "Server: listening address; Client: address to connect to.");
module_param(port, int, 0);
MODULE_PARM_DESC(port, "Server: listening port; Client: port to connect to.");

static int parse_module_arg(void);

/* Server and client threads */

struct task_struct *work_thread = NULL;
static int simple_server(void *data);
static int simple_client(void *data);

/* End point resources */

#define BUF_SIZE 262144
#define SND_SIZE 2048
#define RCV_SIZE 2048
#define DATA_SIZE (BUF_SIZE - SND_SIZE - RCV_SIZE)
#define IOV_NUM 4
#define SEG_SIZE (DATA_SIZE / IOV_NUM)

struct lcl_mem_ctx {
	void *snd_addr;
	void *snd_desc;
	size_t snd_len;
	void *rcv_addr;
	void *rcv_desc;
	size_t rcv_len;
	size_t iov_count;
	void *descv[IOV_NUM];
	struct kvec iov[IOV_NUM];
};

struct ep_ctx {
	bool connected;
	struct kfid_fabric *fab;
	struct kfid_domain *dom;
	struct kfid_ep *ep;
	struct kfid_eq *eq;
	struct kfid_mr *mr;
	struct kfid_cq *scq;
	struct kfid_cq *rcq;
	struct kfi_eq_attr eq_attr;
	struct kfi_cq_attr cq_attr;
	void * buf;
	uint64_t buf_dma;
	int buflen;
	struct lcl_mem_ctx lclmem;
	struct kfi_rma_iov rmtexp;
	struct kfi_rma_iov rmtmem;
};

struct lep_ctx {
	struct kfid_fabric *fab;
	struct kfid_pep *pep;
	struct kfid_eq *eq;
	struct kfi_eq_attr eq_attr;
};

/* Connection and resource management routines */

static int server_listen(struct lep_ctx *lctx);
static int server_connect(struct lep_ctx *lctx, struct ep_ctx *ctx);
static int client_connect(struct ep_ctx *ctx);
static void server_shutdown(struct lep_ctx *lctx, struct ep_ctx *ctx);
static void client_shutdown(struct ep_ctx *ctx);

static int setup_ctx(struct ep_ctx *ctx, struct kfi_info *fi);
static void free_ctx(struct ep_ctx *ctx);
static void free_lctx(struct lep_ctx *ctx);

/* Test case and helper routines */

#define MAX_TOKEN 10
static int send_msg(struct ep_ctx *ctx);
static int send_poison(struct ep_ctx *ctx);
static int recv_msg(struct ep_ctx *ctx);
static int prep_recv(struct ep_ctx *ctx);

static int testcase_send_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_send_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_sendv_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_sendv_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_senddata_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_senddata_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_write_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_write_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_writev_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_writev_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_writedata_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_writedata_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_read_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_read_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_readv_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_readv_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_atomic_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_atomic_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_fetch_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_fetch_server(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_compare_client(struct ep_ctx *ctx, unsigned char pattern);
static int testcase_compare_server(struct ep_ctx *ctx, unsigned char pattern);

/* Fabric info dump routines */

#define DUMP_SIZE 10000
static int dump_info(struct kfi_info *fi);

static int __init
kfi_test_simple_init(void)
{
	int ret = 0;

	if (( ret = parse_module_arg() )) {
		LOG_ERR("Argument parsing error.");
		goto err;
	}
	LOG_INFO("Module loaded. Role - %s; Address - %s; Port - %d.",
	         role, addr_str, port);

	work_thread = kthread_create(server ? simple_server : simple_client,
	                             NULL, "test (simple) thread");
	if (!IS_ERR(work_thread)) {
		wake_up_process(work_thread);
		LOG_INFO("Started work thread.");
	} else {
		ret = PTR_ERR(work_thread);
		LOG_ERR("Error starting work thread.");
		goto err;
	}
	return 0;

err:
	return ret;
}

static void __exit
kfi_test_simple_exit(void)
{
	int ret = 0;

	send_sig(SIGINT, work_thread, 1);
	if (( ret = kthread_stop(work_thread) )) {
		LOG_INFO("Stopped work thread.");
	} else {
		LOG_ERR("Stopped work thread, err code %d.", ret);
	}
	return;
}

static int
simple_server(void *data)
{
	struct ep_ctx ctx = {0};
	struct lep_ctx lctx = {0};
	unsigned char pattern = 0;
	int ret = 0;

	allow_signal(SIGINT);
	set_current_state(TASK_INTERRUPTIBLE);

	if (( ret = server_listen(&lctx) )) {
		goto exit;
	}
	if (( ret = server_connect(&lctx, &ctx) )) {
		goto exit;
	}

	/* Data operation. */
	pattern ++;
	if (( ret = testcase_send_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_sendv_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_senddata_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_write_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_writev_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_writedata_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_read_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_readv_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_atomic_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_fetch_server(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_compare_server(&ctx, pattern) )) {
		goto exit;
	}

exit:
	server_shutdown(&lctx, &ctx);
	LOG_INFO("Server resource cleaned up.");

	/* Wait for thread stop signal. */
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return ret;
}

static int
simple_client(void *data)
{
	struct ep_ctx ctx = {0};
	unsigned char pattern = 0;
	int ret = 0;

	allow_signal(SIGINT);
	set_current_state(TASK_INTERRUPTIBLE);

	if (( ret = client_connect(&ctx) )) {
		goto exit;
	}

	/* Data operation. */
	pattern ++;
	if (( ret = testcase_send_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_sendv_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_senddata_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_write_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_writev_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_writedata_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_read_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_readv_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_atomic_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_fetch_client(&ctx, pattern) )) {
		goto exit;
	}

	pattern ++;
	if (( ret = testcase_compare_client(&ctx, pattern) )) {
		goto exit;
	}

exit:
	client_shutdown(&ctx);
	LOG_INFO("Client resource cleaned up.");

	/* Wait for thread stop signal. */
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return ret;
}

static int
parse_module_arg(void)
{
	char *end = NULL;
	uint32_t addr = 0;

	if (!strcmp(role, "server")) {
		server = true;
	} else if (!strcmp(role, "client")) {
		server = false;
	} else {
		LOG_ERR("Invalid role - %s.", role);
		return -EINVAL;
	}

	if (port <= 0) {
		LOG_ERR("Invalid port - %d.", port);
		return -EINVAL;
	}

	if (!in4_pton(addr_str, -1, (u8*)&addr, -1, (const char**)&end)) {
		LOG_ERR("Invalid address - %s.", addr_str);
		return -EINVAL;
	}
	((struct sockaddr_in*)&sock_addr)->sin_family = AF_INET;
	((struct sockaddr_in*)&sock_addr)->sin_port = port;
	((struct sockaddr_in*)&sock_addr)->sin_addr.s_addr = addr;

	return 0;
}

static int
server_listen(struct lep_ctx *lctx)
{
	struct kfi_info hints = {0};
	struct kfi_info *lfi = NULL;
	int ret = 0;

	hints.src_addr = kmemdup(&sock_addr, sizeof(sock_addr), GFP_KERNEL);
	hints.src_addrlen = sizeof(sock_addr);
	if (!hints.src_addr) {
		LOG_ERR("Failed to allocate memory for socket address.");
		ret = -ENOMEM;
		goto exit;
	}

	LOG_INFO("Get info with following hints:");
	dump_info(&hints);
	ret = kfi_getinfo(0, &hints, &lfi);
	if (!ret) {
		LOG_INFO("Got fabric info.");
		LOG_INFO("KFI_INFO from provider %s version %d.%d:",
				lfi->fabric_attr->prov_name,
				KFI_MAJOR(lfi->fabric_attr->prov_version),
				KFI_MINOR(lfi->fabric_attr->prov_version));
		dump_info(lfi);
	} else {
		LOG_ERR("Failed to get fabric info.");
		goto exit;
	}

	if (( ret = kfi_fabric(lfi->fabric_attr, &lctx->fab, NULL) )) {
		LOG_ERR("Failed to create fabric.");
		goto exit;
	}
	if (( ret = kfi_passive_ep(lctx->fab, lfi, &lctx->pep, NULL) )) {
		LOG_ERR("Failed to create passive endpoint.");
		goto exit;
	}
	if (( ret = kfi_eq_open(lctx->fab, &lctx->eq_attr, &lctx->eq, NULL) )) {
		LOG_ERR("Failed to create listender event queue.");
		goto exit;
	}
	if (( ret = kfi_pep_bind(lctx->pep, &lctx->eq->fid, 0) )) {
		LOG_ERR("Failed to bind listender event queue to passive endpoint.");
		goto exit;
	}
	if (( ret = kfi_listen(lctx->pep) )) {
		LOG_ERR("Passive endpoint failed to start listening.");
		goto exit;
	}
	LOG_INFO("Passive endpoint listening.");

exit:
	if (lfi) {
		kfi_freeinfo(lfi);
	}
	return ret;
}

static int
server_connect(struct lep_ctx *lctx, struct ep_ctx *ctx)
{
	struct kfi_info *fi = NULL;
	struct kfi_eq_cm_entry *entry = NULL;
	uint32_t event = 0;
	int ret = 0;
	ssize_t rd = 0;

	entry = kzalloc(sizeof(struct kfi_eq_cm_entry) + sizeof(struct kfi_rma_iov),
	                GFP_KERNEL);
	if (!entry) {
		ret = -ENOMEM;
		LOG_ERR("Failed to allocate event entry.");
		goto exit;
	}
	rd = kfi_eq_sread(lctx->eq, &event, entry, sizeof(*entry) + sizeof(struct kfi_rma_iov), -1, 0);
	if (rd < sizeof(*entry)) {
		LOG_ERR("Failed to read event.");
		ret = (int)rd;
		goto exit;
	}
	if (event != KFI_CONNREQ) {
		LOG_ERR("Unexpected listener event.");
		ret = -EIO;
		goto exit;
	}
	fi = entry->info;
	LOG_INFO("Received connection request from %pI4.",
		&((struct sockaddr_in*)(fi->dest_addr))->sin_addr.s_addr);

	if (( ret = setup_ctx(ctx, fi) )) {
		LOG_ERR("Failed to set up endpoint context.");
		kfi_reject(lctx->pep, fi->handle, NULL, 0);
		goto exit;
	}
	ctx->rmtmem = *(struct kfi_rma_iov*)&entry->data;
	if (ctx->rmtmem.len != DATA_SIZE) {
		LOG_ERR("Invalid remote memory size.");
		ret = -EINVAL;
		kfi_reject(lctx->pep, fi->handle, NULL, 0);
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		kfi_reject(lctx->pep, fi->handle, NULL, 0);
		goto exit;
	}
	if (( ret = kfi_accept(ctx->ep, &ctx->rmtexp, sizeof(ctx->rmtexp)) )) {
		LOG_ERR("Failed to accept connection.");
		kfi_reject(lctx->pep, fi->handle, NULL, 0);
		goto exit;
	}
	rd = kfi_eq_sread(ctx->eq, &event, entry,
	                  sizeof(*entry) + sizeof(struct kfi_rma_iov), -1, 0);
	if (rd != sizeof(*entry)) {
		LOG_ERR("Failed to read event.");
		ret = (int)rd;
		goto exit;
	}
	if (event != KFI_CONNECTED) {
		LOG_ERR("Unable to establish connection.");
		ret = -EIO;
		goto exit;
	}
	ctx->connected = true;

	LOG_INFO("Connection established !");
exit:
	if (entry) {
		kfree(entry);
	}
	if (fi) {
		kfi_freeinfo(fi);
	}
	return ret;
}

static int
client_connect(struct ep_ctx *ctx)
{
	struct kfi_info hints = {0};
	struct kfi_info *fi = NULL;
	struct kfi_eq_cm_entry *entry = NULL;
	uint32_t event = 0;
	int ret = 0;
	ssize_t rd = 0;

	hints.dest_addr = kmemdup(&sock_addr, sizeof(sock_addr), GFP_KERNEL);
	hints.dest_addrlen = sizeof(sock_addr);
	if (!hints.dest_addr) {
		LOG_ERR("Failed to allocate memory for socket address.");
		ret = -ENOMEM;
		goto exit;
	}
	LOG_INFO("Get info with following hints:");
	dump_info(&hints);
	ret = kfi_getinfo(0, &hints, &fi);
	if (!ret) {
		LOG_INFO("KFI_INFO from provider %s version %d.%d:",
				fi->fabric_attr->prov_name,
				KFI_MAJOR(fi->fabric_attr->prov_version),
				KFI_MINOR(fi->fabric_attr->prov_version));
		dump_info(fi);
	} else {
		LOG_ERR("Failed to get fabric info.");
		goto exit;
	}

	if (( ret = setup_ctx(ctx, fi) )) {
		LOG_ERR("Failed to set up endpoint context.");
		goto exit;
	}
	LOG_INFO("Initiating connection.");
	if (( ret = kfi_connect(ctx->ep, NULL, &ctx->rmtexp, sizeof(ctx->rmtexp)) )) {
		LOG_ERR("Failed to initiate connection.");
		goto exit;
	}
	entry = kzalloc(sizeof(struct kfi_eq_cm_entry) + sizeof(struct kfi_rma_iov),
	                GFP_KERNEL);
	if (!entry) {
		ret = -ENOMEM;
		LOG_ERR("Failed to allocate event entry.");
		goto exit;
	}
	rd = kfi_eq_sread(ctx->eq, &event, entry, sizeof(*entry) + sizeof(struct kfi_rma_iov), -1, 0);
	if (rd < sizeof(struct kfi_eq_cm_entry *)) {
		LOG_ERR("Failed to read event.");
		ret = (int)rd;
		goto exit;
	}
	if (event != KFI_CONNECTED) {
		LOG_ERR("Unable to establish connection.");
		ret = -EIO;
		goto exit;
	}
	ctx->connected = true;

	ctx->rmtmem = *(struct kfi_rma_iov*)&entry->data;
	if (ctx->rmtmem.len != DATA_SIZE) {
		LOG_ERR("Invalid remote memory size.");
		ret = -EINVAL;
		goto exit;
	}
	LOG_INFO("Connection established !");

exit:
	if (entry) {
		kfree(entry);
	}
	if (fi) {
		kfi_freeinfo(fi);
	}
	return ret;
}

static void
server_shutdown(struct lep_ctx *lctx, struct ep_ctx *ctx)
{
	int ret = 0;

	if (ctx->connected) {
		ret = kfi_shutdown(ctx->ep, 0);
		if (!ret) {
			LOG_INFO("Connection shutdown.");
		} else {
			LOG_WARN("Connections shutdown error.");
		}
	}
	free_lctx(lctx);
	free_ctx(ctx);
	return;
}

static void
client_shutdown(struct ep_ctx *ctx)
{
	int ret = 0;

	if (ctx->connected) {
		ret = kfi_shutdown(ctx->ep, 0);
		if (!ret) {
			LOG_INFO("Connection shutdown.");
		} else {
			LOG_WARN("Connections shutdown error.");
		}
	}
	free_ctx(ctx);
	return;
}

static int
dump_info(struct kfi_info *fi)
{
	char *buf = NULL;

	buf = kmalloc(DUMP_SIZE, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate memory for fabric info dump.");
		return -ENOMEM;
	}

	if (fi) {
		snprintf(buf, DUMP_SIZE,
			"\n\tDumping KFI_INFO:\n"
			"\t\tCaps:\t\t\t\t%lx\n"
			"\t\tMode:\t\t\t\t%lx\n"
			"\t\tAddr_fmt:\t\t\t%x\n",
			(unsigned long)fi->caps,
			(unsigned long)fi->mode,
			fi->addr_format);
		if (fi->src_addrlen) {
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tSRC_ADDR:\t\t\t%pI4\n",
				&((struct sockaddr_in*)(fi->src_addr))->sin_addr.s_addr
			);
		}
		if (fi->dest_addrlen) {
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tDST_ADDR:\t\t\t%pI4\n",
				&((struct sockaddr_in*)(fi->dest_addr))->sin_addr.s_addr
			);
		}
		if (fi->fabric_attr) {
			struct kfi_fabric_attr *attr = fi->fabric_attr;
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tFabric Attributes:\n");
			if (attr->name) {
				snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
					"\t\t\tName:\t\t\t%s\n",
					attr->name);
			}
			if (attr->prov_name) {
				snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
					"\t\t\tProv_name:\t\t%s\n"
					"\t\t\tProv_ver:\t\t%d.%d\n",
					attr->prov_name,
					KFI_MAJOR(fi->fabric_attr->prov_version),
					KFI_MINOR(fi->fabric_attr->prov_version));
			}
		}
		if (fi->domain_attr) {
			struct kfi_domain_attr *attr = fi->domain_attr;
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tDomain Attributes:\n");
			if (attr->name) {
				snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
					"\t\t\tName:\t\t\t%s\n",
					attr->name);
			}
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\t\tThreading:\t\t%d\n"
				"\t\t\tCtrl progress:\t\t%d\n"
				"\t\t\tData progress:\t\t%d\n"
				"\t\t\tResoruce mgmt:\t\t%d\n"
				"\t\t\tMR key size:\t\t%u\n"
				"\t\t\tCQ data size:\t\t%u\n"
				"\t\t\tCQ count:\t\t%u\n"
				"\t\t\tEP count:\t\t%u\n"
				"\t\t\tTX ctx count:\t\t%u\n"
				"\t\t\tRX ctx count:\t\t%u\n"
				"\t\t\tMax TX per EP:\t\t%u\n"
				"\t\t\tMax RX per EP:\t\t%u\n",
				attr->threading,
				attr->control_progress,
				attr->data_progress,
				attr->resource_mgmt,
				(unsigned)attr->mr_key_size,
				(unsigned)attr->cq_data_size,
				(unsigned)attr->cq_cnt,
				(unsigned)attr->ep_cnt,
				(unsigned)attr->tx_ctx_cnt,
				(unsigned)attr->rx_ctx_cnt,
				(unsigned)attr->max_ep_tx_ctx,
				(unsigned)attr->max_ep_rx_ctx);
		}
		if (fi->ep_attr) {
			struct kfi_ep_attr *attr = fi->ep_attr;
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tEnd Point Attributes:\n"
				"\t\t\tProtocol:\t\t%u\n"
				"\t\t\tProtocol ver:\t\t%u\n"
				"\t\t\tMax msg size:\t\t%u\n"
				"\t\t\tMax msg prefix size:\t%u\n"
				"\t\t\tMax size (RAW):\t\t%u\n"
				"\t\t\tMax size (WAR):\t\t%u\n"
				"\t\t\tMax size (WAW):\t\t%u\n"
				"\t\t\tMem tag fmt:\t\t%lu\n"
				"\t\t\tTx ctx count:\t\t%u\n"
				"\t\t\tRx ctx count:\t\t%u\n",
				attr->protocol,
				attr->protocol_version,
				(unsigned)attr->max_msg_size,
				(unsigned)attr->msg_prefix_size,
				(unsigned)attr->max_order_raw_size,
				(unsigned)attr->max_order_war_size,
				(unsigned)attr->max_order_waw_size,
				(unsigned long)attr->mem_tag_format,
				(unsigned)attr->tx_ctx_cnt,
				(unsigned)attr->rx_ctx_cnt);
		}
		if (fi->tx_attr) {
			struct kfi_tx_attr *attr = fi->tx_attr;
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tTx Attributes:\n"
				"\t\t\tCaps:\t\t\t%lx\n"
				"\t\t\tMode:\t\t\t%lx\n"
				"\t\t\tOP flags:\t\t%lx\n"
				"\t\t\tMsg order:\t\t%lx\n"
				"\t\t\tComp order:\t\t%lx\n"
				"\t\t\tInject size:\t\t%u\n"
				"\t\t\tSize:\t\t\t%u\n"
				"\t\t\tIOV limit:\t\t%u\n"
				"\t\t\tRMA IOV limit:\t\t%u\n",
				(unsigned long)attr->caps,
				(unsigned long)attr->mode,
				(unsigned long)attr->op_flags,
				(unsigned long)attr->msg_order,
				(unsigned long)attr->comp_order,
				(unsigned)attr->inject_size,
				(unsigned)attr->size,
				(unsigned)attr->iov_limit,
				(unsigned)attr->rma_iov_limit);
		}
		if (fi->rx_attr) {
			struct kfi_rx_attr *attr = fi->rx_attr;
			snprintf(buf + strlen(buf), DUMP_SIZE - strlen(buf),
				"\t\tRx Attributes:\n"
				"\t\t\tCaps:\t\t\t%lx\n"
				"\t\t\tMode:\t\t\t%lx\n"
				"\t\t\tOP flags:\t\t%lx\n"
				"\t\t\tMsg order:\t\t%lx\n"
				"\t\t\tComp order:\t\t%lx\n"
				"\t\t\tBuffered recv:\t\t%u\n"
				"\t\t\tSize:\t\t\t%u\n"
				"\t\t\tIOV limit:\t\t\t%u\n",
				(unsigned long)attr->caps,
				(unsigned long)attr->mode,
				(unsigned long)attr->op_flags,
				(unsigned long)attr->msg_order,
				(unsigned long)attr->comp_order,
				(unsigned)attr->total_buffered_recv,
				(unsigned)attr->size,
				(unsigned)attr->iov_limit);
		}
		printk(KERN_INFO "%s", buf);
	}

	kfree(buf);
	return 0;
}

static int
setup_ctx(struct ep_ctx *ctx, struct kfi_info *fi)
{
	int ret = 0;
	int i = 0;
	char *cur = NULL;

	if (( ret = kfi_fabric(fi->fabric_attr, &ctx->fab, NULL) )) {
		LOG_ERR("Failed to create fabric.");
		goto err;
	}
	if (( ret = kfi_domain(ctx->fab, fi, &ctx->dom, NULL) )) {
		LOG_ERR("Failed to create domain.");
		goto err;
	}
	if (( ret = kfi_endpoint(ctx->dom, fi, &ctx->ep, NULL) )) {
		LOG_ERR("Failed to create endpoint.");
		goto err;
	}
	if (( ret = kfi_eq_open(ctx->fab, &ctx->eq_attr, &ctx->eq, NULL) )) {
		LOG_ERR("Failed to create event queue.");
		goto err;
	}
	if (( ret = kfi_ep_bind(ctx->ep, &ctx->eq->fid, 0) )) {
		LOG_ERR("Failed to bind event queue to endpoint.");
		goto err;
	}

	ctx->cq_attr.format = KFI_CQ_FORMAT_DATA;
	ctx->cq_attr.size = fi->tx_attr->size;
	if (( ret = kfi_cq_open(ctx->dom, &ctx->cq_attr, &ctx->scq, NULL) )) {
		LOG_ERR("Failed to create send completion queue.");
		goto err;
	}
	if (( ret = kfi_ep_bind(ctx->ep, &ctx->scq->fid, KFI_SEND) )) {
		LOG_ERR("Failed to bind send completion queue to endpoint.");
		goto err;
	}

	ctx->cq_attr.size = fi->rx_attr->size;
	if (( ret = kfi_cq_open(ctx->dom, &ctx->cq_attr, &ctx->rcq, NULL) )) {
		LOG_ERR("Failed to create recv completion queue.");
		goto err;
	}
	if (( ret = kfi_ep_bind(ctx->ep, &ctx->rcq->fid, KFI_RECV) )) {
		LOG_ERR("Failed to bind recv completion queue to endpoint.");
		goto err;
	}

	ctx->buflen = BUF_SIZE;
	ctx->buf = kzalloc(ctx->buflen, GFP_KERNEL);
	if (!ctx->buf) {
		LOG_ERR("Failed to allocate buffer.");
		ret = -ENOMEM;
		goto err;
	}

	if (( ret = kfi_mr_reg(ctx->dom, ctx->buf, ctx->buflen,
	                       KFI_REMOTE_READ | KFI_REMOTE_WRITE | KFI_READ | KFI_WRITE,
	                       0, 0, 0, &ctx->mr, NULL, &ctx->buf_dma) )) {
		LOG_ERR("Failed to register memory.");
		goto err;
	}

	cur = ctx->buf;
	ctx->lclmem.snd_addr = cur;
	ctx->lclmem.snd_desc = kfi_mr_desc(ctx->mr);
	ctx->lclmem.snd_len = SND_SIZE;

	cur += SND_SIZE;
	ctx->lclmem.rcv_addr = cur;
	ctx->lclmem.rcv_desc = kfi_mr_desc(ctx->mr);
	ctx->lclmem.rcv_len = RCV_SIZE;

	cur += RCV_SIZE;
	ctx->lclmem.iov_count = IOV_NUM;
	for (i = 0; i < IOV_NUM; i ++) {
		ctx->lclmem.descv[i] = kfi_mr_desc(ctx->mr);
		ctx->lclmem.iov[i].iov_base = cur;
		ctx->lclmem.iov[i].iov_len = SEG_SIZE;
		cur += SEG_SIZE;
	}

	ctx->rmtexp.addr = ctx->buf_dma + SND_SIZE + RCV_SIZE;
	ctx->rmtexp.len = DATA_SIZE;
	ctx->rmtexp.key = ctx->mr->key;

	LOG_INFO("Allocated buffer: addr 0x%p mapped 0x%llx size %d.",
	                ctx->buf, ctx->buf_dma, ctx->buflen);
	LOG_INFO("Export to remote node mapped 0x%llx key 0x%llx size %lu.",
	                ctx->rmtexp.addr, ctx->rmtexp.key, ctx->rmtexp.len);

	if (( ret = kfi_enable(ctx->ep) )) {
		LOG_ERR("Failed to activate endpoint.");
		goto err;
	}
	return ret;

err:
	return ret;
}

static void
free_ctx(struct ep_ctx *ctx)
{
	if (!ctx) {
		return;
	}
	if (ctx->ep) {
		kfi_close(&ctx->ep->fid);
		ctx->ep = NULL;
	}
	if (ctx->eq) {
		kfi_close(&ctx->eq->fid);
		ctx->eq = NULL;
	}
	if (ctx->scq) {
		kfi_close(&ctx->scq->fid);
		ctx->scq = NULL;
	}
	if (ctx->rcq) {
		kfi_close(&ctx->rcq->fid);
		ctx->rcq = NULL;
	}
	if (ctx->mr) {
		kfi_close(&ctx->mr->fid);
		ctx->mr = NULL;
	}
	if (ctx->dom) {
		kfi_close(&ctx->dom->fid);
		ctx->dom = NULL;
	}
	if (ctx->fab) {
		kfi_close(&ctx->fab->fid);
		ctx->fab = NULL;
	}
	if (ctx->buf) {
		kfree(ctx->buf);
		ctx->buf = NULL;
	}
	return;
}

static void
free_lctx(struct lep_ctx *lctx)
{
	if (!lctx) {
		return;
	}
	if (lctx->eq) {
		kfi_close(&lctx->eq->fid);
		lctx->eq = NULL;
	}
	if (lctx->pep) {
		kfi_close(&lctx->pep->fid);
		lctx->pep = NULL;
	}
	if (lctx->fab) {
		kfi_close(&lctx->fab->fid);
		lctx->fab = NULL;
	}
	return;
}

static int
_send_msg(struct ep_ctx *ctx, bool poison)
{
	static uint64_t token = 0;
	static void *cookie = NULL;
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	ssize_t rd = 0;
	int ret = 0;

	token ++;
	token %= MAX_TOKEN;
	if (!poison) {
		*(uint64_t *)(ctx->lclmem.snd_addr) = token;
	} else {
		*(uint64_t *)(ctx->lclmem.snd_addr) = MAX_TOKEN;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_send(ctx->ep, ctx->lclmem.snd_addr, ctx->lclmem.snd_len,
	                     ctx->lclmem.snd_desc, 0, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to send data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		goto exit;
	}
exit:
	return ret;
}

static int
send_msg(struct ep_ctx *ctx)
{
	return _send_msg(ctx, false);
}

static int
send_poison(struct ep_ctx *ctx)
{
	return _send_msg(ctx, true);
}

static int
recv_msg(struct ep_ctx *ctx)
{
	static uint64_t token = 0;
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	ssize_t rd = 0;
	int ret = 0;

	token ++;
	token %= MAX_TOKEN;
	rd = kfi_cq_sread(ctx->rcq, &wc, 1, NULL, 0);
	if (rd != 1) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->rcq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->rcq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	if (*(uint64_t *)(ctx->lclmem.rcv_addr) == MAX_TOKEN) {
		LOG_INFO("Received poison message, aborting test.");
		ret = -EIO;
		goto exit;
	}
	if (*(uint64_t *)(ctx->lclmem.rcv_addr) != token) {
		LOG_ERR("Token mismatch, received %llu, expecting %llu.",
		        *(uint64_t *)(ctx->lclmem.rcv_addr), token);
		ret = -EIO;
		goto exit;
	}
exit:
	return ret;
}

static int
prep_recv(struct ep_ctx *ctx)
{
	int ret = 0;

	if (( ret = kfi_recv(ctx->ep, ctx->lclmem.rcv_addr, ctx->lclmem.rcv_len,
	                     ctx->lclmem.rcv_desc, 0, NULL) )) {
		LOG_ERR("Failed to post receive descriptor.");
		goto exit;
	}
exit:
	return ret;
}

static int
testcase_send_client(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0;

	memset(ctx->lclmem.iov[0].iov_base, 0, ctx->lclmem.iov[0].iov_len);
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_recv(ctx->ep, ctx->lclmem.iov[0].iov_base,
	                     ctx->lclmem.iov[0].iov_len,
	                     ctx->lclmem.descv[0], 0, cookie) )) {
		LOG_ERR("Failed to post receive descriptor.");
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	rd = kfi_cq_sread(ctx->rcq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->rcq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->rcq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	check = (unsigned char*)(ctx->lclmem.iov[0].iov_base);
	for (i = 0; i < ctx->lclmem.iov[0].iov_len; i ++) {
		if (*check != pattern) {
			LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
				i, *check, pattern);
			LOG_INFO("Sendign poison message to abort tests.");
			(void)send_poison(ctx);
			ret = -EIO;
			goto exit;
		}
		check ++;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_send() / kfi_recv() pass.");
exit:
	return ret;
}

static int
testcase_send_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;

	memset(ctx->lclmem.iov[0].iov_base, (int)pattern, ctx->lclmem.iov[0].iov_len);

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_send(ctx->ep, ctx->lclmem.iov[0].iov_base,
	                     ctx->lclmem.iov[0].iov_len,
	                     ctx->lclmem.descv[0], 0, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_send() / kfi_recv() pass.");
exit:
	return ret;
}

static int
testcase_sendv_client(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0, j = 0;

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		memset(ctx->lclmem.iov[j].iov_base, 0, ctx->lclmem.iov[j].iov_len);
	}
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_recvv(ctx->ep, ctx->lclmem.iov, ctx->lclmem.descv,
		              ctx->lclmem.iov_count, 0, cookie) )) {
		LOG_ERR("Failed to post receive descriptor.");
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	rd = kfi_cq_sread(ctx->rcq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->rcq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->rcq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		check = (unsigned char*)(ctx->lclmem.iov[j].iov_base);
		for (i = 0; i < ctx->lclmem.iov[j].iov_len; i ++) {
			if (*check != (pattern + j)) {
				LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
					i, *check, (pattern + j));
				LOG_INFO("Sendign poison message to abort tests.");
				(void)send_poison(ctx);
				ret = -EIO;
				goto exit;
			}
			check ++;
		}
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_sendv() / kfi_recvv() pass.");
exit:
	return ret;
}

static int
testcase_sendv_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int j = 0;
	int ret = 0;

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		memset(ctx->lclmem.iov[j].iov_base, pattern+j, ctx->lclmem.iov[j].iov_len);
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_sendv(ctx->ep, ctx->lclmem.iov, ctx->lclmem.descv,
	                      ctx->lclmem.iov_count, 0, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_sendv() / kfi_recvv() pass.");
exit:
	return ret;
}

static int
testcase_senddata_client(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0;

	memset(ctx->lclmem.iov[0].iov_base, 0, ctx->lclmem.iov[0].iov_len);
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_recv(ctx->ep, ctx->lclmem.iov[0].iov_base,
	                     ctx->lclmem.iov[0].iov_len,
	                     ctx->lclmem.descv[0], 0, cookie) )) {
		LOG_ERR("Failed to post receive descriptor.");
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	rd = kfi_cq_sread(ctx->rcq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->rcq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->rcq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	if (wc.data != (pattern + 1)) {
		LOG_ERR("Immdiate data mismatch, received %llu, expecting %u.",
		        wc.data, (pattern + 1));
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}

	check = (unsigned char*)(ctx->lclmem.iov[0].iov_base);
	for (i = 0; i < ctx->lclmem.iov[0].iov_len; i ++) {
		if (*check != pattern) {
			LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
				i, *check, pattern);
			LOG_INFO("Sendign poison message to abort tests.");
			(void)send_poison(ctx);
			ret = -EIO;
			goto exit;
		}
		check ++;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_senddata() / kfi_recv() pass.");
exit:
	return ret;
}

static int
testcase_senddata_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;

	memset(ctx->lclmem.iov[0].iov_base, (int)pattern, ctx->lclmem.iov[0].iov_len);

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_senddata(ctx->ep, ctx->lclmem.iov[0].iov_base,
	                     ctx->lclmem.iov[0].iov_len,
	                     ctx->lclmem.descv[0], (pattern + 1), 0, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_senddata() / kfi_recv() pass.");
exit:
	return ret;
}

static int
testcase_write_client(struct ep_ctx *ctx, unsigned char pattern)
{
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0;

	memset(ctx->lclmem.iov[0].iov_base, 0, ctx->lclmem.iov[0].iov_len);
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	check = (unsigned char*)(ctx->lclmem.iov[0].iov_base);
	for (i = 0; i < ctx->lclmem.iov[0].iov_len; i ++) {
		if (*check != pattern) {
			LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
				i, *check, pattern);
			LOG_INFO("Sendign poison message to abort tests.");
			(void)send_poison(ctx);
			ret = -EIO;
			goto exit;
		}
		check ++;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_write() pass.");
exit:
	return ret;
}

static int
testcase_write_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;

	memset(ctx->lclmem.iov[0].iov_base, (int)pattern, ctx->lclmem.iov[0].iov_len);

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_write(ctx->ep, (const void*)ctx->lclmem.iov[0].iov_base,
	                ctx->lclmem.iov[0].iov_len, ctx->lclmem.descv[0], 0,
	                ctx->rmtmem.addr, ctx->rmtmem.key,
	                cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_write() pass.");
exit:
	return ret;
}

static int
testcase_writev_client(struct ep_ctx *ctx, unsigned char pattern)
{
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0, j = 0;

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		memset(ctx->lclmem.iov[j].iov_base, 0, ctx->lclmem.iov[j].iov_len);
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		check = (unsigned char*)(ctx->lclmem.iov[j].iov_base);
		for (i = 0; i < ctx->lclmem.iov[j].iov_len; i ++) {
			if (*check != pattern + j) {
				LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
					i, *check, pattern + j);
				LOG_INFO("Sendign poison message to abort tests.");
				(void)send_poison(ctx);
				ret = -EIO;
				goto exit;
			}
			check ++;
		}
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_writev() pass.");
exit:
	return ret;
}

static int
testcase_writev_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	int j = 0;

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		memset(ctx->lclmem.iov[j].iov_base, pattern + j, ctx->lclmem.iov[j].iov_len);
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_writev(ctx->ep, ctx->lclmem.iov, ctx->lclmem.descv,
	                ctx->lclmem.iov_count, 0, ctx->rmtmem.addr,
	                ctx->rmtmem.key, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_writev() pass.");
exit:
	return ret;
}

static int
testcase_writedata_client(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0;

	memset(ctx->lclmem.iov[0].iov_base, 0, ctx->lclmem.iov[0].iov_len);
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_recv(ctx->ep, ctx->lclmem.iov[1].iov_base,
	                     ctx->lclmem.iov[1].iov_len,
	                     ctx->lclmem.descv[1], 0, cookie) )) {
		LOG_ERR("Failed to post receive descriptor.");
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	rd = kfi_cq_sread(ctx->rcq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->rcq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->rcq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	if (wc.data != (pattern + 1)) {
		LOG_ERR("Immdiate data mismatch, received %llu, expecting %u.",
		        wc.data, (pattern + 1));
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}

	check = (unsigned char*)(ctx->lclmem.iov[0].iov_base);
	for (i = 0; i < ctx->lclmem.iov[0].iov_len; i ++) {
		if (*check != pattern) {
			LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
				i, *check, pattern);
			LOG_INFO("Sendign poison message to abort tests.");
			(void)send_poison(ctx);
			ret = -EIO;
			goto exit;
		}
		check ++;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_writedata() pass.");
exit:
	return ret;
}

static int
testcase_writedata_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;

	memset(ctx->lclmem.iov[0].iov_base, (int)pattern, ctx->lclmem.iov[0].iov_len);

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_writedata(ctx->ep, (const void*)ctx->lclmem.iov[0].iov_base,
	                ctx->lclmem.iov[0].iov_len, ctx->lclmem.descv[0], (pattern + 1),
	                0, ctx->rmtmem.addr, ctx->rmtmem.key,
	                cookie) )) {;
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_writedata() pass.");
exit:
	return ret;
}

static int
testcase_read_client(struct ep_ctx *ctx, unsigned char pattern)
{
	int ret = 0;

	memset(ctx->lclmem.iov[0].iov_base, (int)pattern, ctx->lclmem.iov[0].iov_len);
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_read() pass.");
exit:
	return ret;
}

static int
testcase_read_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0;

	memset(ctx->lclmem.iov[0].iov_base, 0, ctx->lclmem.iov[0].iov_len);

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_read(ctx->ep, ctx->lclmem.iov[0].iov_base,
	                ctx->lclmem.iov[0].iov_len, ctx->lclmem.descv[0], 0,
	                ctx->rmtmem.addr, ctx->rmtmem.key,
	                cookie) )) {;
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	check = (unsigned char*)(ctx->lclmem.iov[0].iov_base);
	for (i = 0; i < ctx->lclmem.iov[0].iov_len; i ++) {
		if (*check != pattern) {
			LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
				i, *check, pattern);
			LOG_INFO("Sendign poison message to abort tests.");
			(void)send_poison(ctx);
			ret = -EIO;
			goto exit;
		}
		check ++;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_read() pass.");
exit:
	return ret;
}

static int
testcase_readv_client(struct ep_ctx *ctx, unsigned char pattern)
{
	int ret = 0;
	int j = 0;

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		memset(ctx->lclmem.iov[j].iov_base, pattern + j, ctx->lclmem.iov[j].iov_len);
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_readv() pass.");
exit:
	return ret;
}

static int
testcase_readv_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	unsigned char *check = NULL;
	int i = 0, j = 0;

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		memset(ctx->lclmem.iov[j].iov_base, 0, ctx->lclmem.iov[j].iov_len);
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_readv(ctx->ep, ctx->lclmem.iov, ctx->lclmem.descv,
	                ctx->lclmem.iov_count, 0, ctx->rmtmem.addr,
	                ctx->rmtmem.key, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}

	for (j = 0; j < ctx->lclmem.iov_count; j ++) {
		check = (unsigned char*)(ctx->lclmem.iov[j].iov_base);
		for (i = 0; i < ctx->lclmem.iov[j].iov_len; i ++) {
			if (*check != pattern + j) {
				LOG_ERR("Data mismatch at byte %d, received %u, expecting %u.",
				        i, *check, pattern + j);
				LOG_INFO("Sendign poison message to abort tests.");
				(void)send_poison(ctx);
				ret = -EIO;
				goto exit;
			}
			check ++;
		}
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_readv() pass.");
exit:
	return ret;
}

static int
testcase_atomic_client(struct ep_ctx *ctx, unsigned char pattern)
{
	int ret = 0;
	uint64_t *check = NULL;

	memset(ctx->lclmem.iov[0].iov_base, 0, ctx->lclmem.iov[0].iov_len);
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	check = (uint64_t*)(ctx->lclmem.iov[0].iov_base);
	if (*check != (uint64_t)pattern) {
		LOG_ERR("Atomic data mismatch, received %llu, expecting %llu.",
			*check, (uint64_t)pattern);
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_atomic() pass.");
exit:
	return ret;
}

static int
testcase_atomic_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;

	*(uint64_t* )ctx->lclmem.iov[0].iov_base = (uint64_t)pattern;

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_atomic(ctx->ep, (const void*)ctx->lclmem.iov[0].iov_base,
	                1, ctx->lclmem.descv[0], 0, ctx->rmtmem.addr,
	                ctx->rmtmem.key, KFI_UINT64, KFI_ATOMIC_WRITE,
	                cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	LOG_INFO("Testing API kfi_atomic() pass.");
exit:
	return ret;
}

static int
testcase_fetch_client(struct ep_ctx *ctx, unsigned char pattern)
{
	uint64_t *check = NULL;
	int ret = 0;

	*(uint64_t *)ctx->lclmem.iov[0].iov_base = (uint64_t)pattern;
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	check = (uint64_t *)(ctx->lclmem.iov[0].iov_base);
	if (*check != (uint64_t)(pattern + pattern)) {
		LOG_ERR("Atomic data mismatch, received %llx, expecting %llx.",
			*check, (uint64_t)(pattern + pattern));
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}
	LOG_INFO("Testing API kfi_fetch_atomic() pass.");
exit:
	return ret;
}

static int
testcase_fetch_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	uint64_t *check = NULL;

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	*(uint64_t* )ctx->lclmem.iov[0].iov_base = 0;
	*(uint64_t* )ctx->lclmem.iov[1].iov_base = 0;
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_fetch_atomic(ctx->ep,
	                (const void*)ctx->lclmem.iov[0].iov_base, 1, ctx->lclmem.descv[0],
	                ctx->lclmem.iov[1].iov_base, ctx->lclmem.descv[1], 0,
	                ctx->rmtmem.addr, ctx->rmtmem.key,
	                KFI_UINT64, KFI_ATOMIC_READ, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	check = (uint64_t *)(ctx->lclmem.iov[1].iov_base);
	if (*check != (uint64_t)pattern) {
		LOG_ERR("Atomic data mismatch, received %llu, expecting %llu.",
			*check, (uint64_t)pattern);
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}

	*(uint64_t* )ctx->lclmem.iov[0].iov_base = (uint64_t)(pattern);
	*(uint64_t* )ctx->lclmem.iov[1].iov_base = 0;
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_fetch_atomic(ctx->ep,
	                (const void*)ctx->lclmem.iov[0].iov_base, 1, ctx->lclmem.descv[0],
	                ctx->lclmem.iov[1].iov_base, ctx->lclmem.descv[1], 0,
	                ctx->rmtmem.addr, ctx->rmtmem.key,
	                KFI_UINT64, KFI_SUM, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	check = (uint64_t *)(ctx->lclmem.iov[1].iov_base);
	if (*check != (uint64_t)pattern) {
		LOG_ERR("Atomic data mismatch, received %llu, expecting %llu.",
			*check, (uint64_t)pattern);
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}
	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}
	LOG_INFO("Testing API kfi_fetch_atomic() pass.");
exit:
	return ret;
}

static int
testcase_compare_client(struct ep_ctx *ctx, unsigned char pattern)
{
	uint64_t *check = NULL;
	int ret = 0;

	*(uint64_t *)ctx->lclmem.iov[0].iov_base = (uint64_t)pattern;
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}

	check = (uint64_t *)(ctx->lclmem.iov[0].iov_base);
	if (*check != (uint64_t)(pattern + 1)) {
		LOG_ERR("Atomic data mismatch, received %llx, expecting %llx.",
			*check, (uint64_t)(pattern + 1));
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}
	LOG_INFO("Testing API kfi_compare_atomic() pass.");
exit:
	return ret;
}

static int
testcase_compare_server(struct ep_ctx *ctx, unsigned char pattern)
{
	struct kfi_cq_data_entry wc = {};
	struct kfi_cq_err_entry cq_err = {};
	static void *cookie = NULL;
	ssize_t rd = 0;
	int ret = 0;
	uint64_t *check = NULL;

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}

	*(uint64_t* )ctx->lclmem.iov[0].iov_base = (pattern + 1);
	*(uint64_t* )ctx->lclmem.iov[1].iov_base = 0;
	*(uint64_t* )ctx->lclmem.iov[2].iov_base = pattern; /* compare */
	get_random_bytes(&cookie, sizeof(cookie));
	if (( ret = kfi_compare_atomic(ctx->ep,
	                (const void*)ctx->lclmem.iov[0].iov_base, 1, ctx->lclmem.descv[0],
	                ctx->lclmem.iov[2].iov_base, ctx->lclmem.descv[2],
	                ctx->lclmem.iov[1].iov_base, ctx->lclmem.descv[1], 0,
	                ctx->rmtmem.addr, ctx->rmtmem.key,
	                KFI_UINT64, KFI_CSWAP, cookie) )) {
		LOG_ERR("Failed to post send descriptor.");
		goto exit;
	}
	rd = kfi_cq_sread(ctx->scq, &wc, 1, NULL, 0);
	if (rd != 1 || (wc.op_context) != cookie) {
		LOG_ERR("Failed to receive data.");
		rd = kfi_cq_readerr(ctx->scq, &cq_err, 0);
		if (rd != sizeof(cq_err)) {
			LOG_ERR("Failed to retrieve CQ error.");
		} else {
			LOG_ERR("CQ Error %s (%d).",
			        kfi_cq_strerror(ctx->scq, cq_err.err,
			                        cq_err.err_data, NULL, 0),
			        cq_err.err);
		}
		ret = -EIO;
		goto exit;
	}
	check = (uint64_t *)(ctx->lclmem.iov[1].iov_base);
	if (*check != (uint64_t)pattern) {
		LOG_ERR("Atomic data mismatch, received %llu, expecting %llu.",
			*check, (uint64_t)pattern);
		LOG_INFO("Sendign poison message to abort tests.");
		(void)send_poison(ctx);
		ret = -EIO;
		goto exit;
	}

	if (( ret = send_msg(ctx) )) {
		goto exit;
	}

	if (( ret = recv_msg(ctx) )) {
		goto exit;
	}
	if (( ret = prep_recv(ctx) )) {
		goto exit;
	}
	LOG_INFO("Testing API kfi_compare_atomic() pass.");
exit:
	return ret;
}

module_init(kfi_test_simple_init);
module_exit(kfi_test_simple_exit);
