/*
 * Copyright (c) 2013-2015 Intel Corporation, Inc.  All rights reserved.
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
#include <linux/string.h>
#include <linux/inet.h>
#include <kfabric.h>
#include <kfi_domain.h>
#include <kfi_eq.h>
#include <kfi_prov.h>
#include <kfi_endpoint.h>
#include <kfi_cm.h>
#include <kfi_msg.h>
#include <kfi_rma.h>
#include <kfi_atomic.h>
#include <kfi_tagged.h>
#include <kfi_enosys.h>
#include <rdma/ib.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

MODULE_AUTHOR("Frank Yang, Chen Zhao");
MODULE_DESCRIPTION("Open Fabric Interface Verbs Provider");
MODULE_LICENSE("Dual BSD/GPL");

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "KFI_verbs"

#include <kfi_log.h>

enum {
	IBV_MAJOR_VERSION = KFI_MAJOR_VERSION,
	IBV_MINOR_VERSION = KFI_MINOR_VERSION,
};

#define VERBS_IB_PREFIX "IB-0x"
#define VERBS_IWARP_FABRIC "Ethernet-iWARP"

#define VERBS_CAPS (KFI_MSG | KFI_RMA | KFI_ATOMICS | KFI_READ | KFI_WRITE | \
                    KFI_SEND | KFI_RECV | KFI_REMOTE_READ | KFI_REMOTE_WRITE)
#define VERBS_MODE (KFI_LOCAL_MR)
#define VERBS_TX_OP_FLAGS (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)
#define VERBS_TX_OP_FLAGS_IWARP (KFI_COMPLETION)
#define VERBS_TX_MODE VERBS_MODE
#define VERBS_RX_MODE (KFI_LOCAL_MR | KFI_RX_CQ_DATA)
#define VERBS_MSG_ORDER (KFI_ORDER_RAR | KFI_ORDER_RAW | KFI_ORDER_RAS | \
                         KFI_ORDER_WAW | KFI_ORDER_WAS | KFI_ORDER_SAW | \
                         KFI_ORDER_SAS )

/* IB Verbs provider declarations */

struct kfi_ibv_device {
	struct list_head        list;
	struct ib_device        *device;
	struct kfi_info         *info;
};
static LIST_HEAD(ibv_dev_list);
static DEFINE_MUTEX(ibv_dev_mutex);

struct kfi_ibv_fabric {
	struct kfid_fabric      fabric_fid;
};

struct kfi_ibv_eq {
	struct kfid_eq          eq_fid;
	struct kfi_ibv_fabric   *fab;
	struct kfid             *ep_fid;
	uint64_t                flags;
	struct kfi_eq_err_entry err;
	struct mutex            mut;
	wait_queue_head_t       poll_wait;
	struct list_head        event_list;
};

struct kfi_ibv_event {
	struct list_head        list;
	struct rdma_cm_id       *id;
	struct rdma_cm_event    event;
};

struct kfi_ibv_pep {
	struct kfid_pep         pep_fid;
	struct kfi_ibv_fabric   *fab;
	struct rdma_cm_id       *id;
	struct kfi_ibv_eq       *eq;
	struct mutex            mut;
};

struct kfi_ibv_domain {
	struct kfid_domain      domain_fid;
	struct kfi_ibv_fabric   *fab;
	struct kfi_ibv_device   *dev;
	struct ib_pd            *pd;
};

struct kfi_ibv_cq {
	struct kfid_cq          cq_fid;
	struct kfi_ibv_domain   *domain;
	struct ib_cq            *cq;
	size_t                  entry_size;
	wait_queue_head_t       wait;
	bool                    new_entry;
	uint64_t                flags;
	struct ib_wc            wc;
	struct mutex            mut;
};

struct kfi_ibv_mem_desc {
	struct kfid_mr          mr_fid;
	struct ib_mr            *mr;
	struct kfi_ibv_domain   *domain;
	void                    *vaddr;
	uint64_t                dma_addr;
	size_t                  dma_len;
};

struct kfi_ibv_ep {
	struct kfid_ep          ep_fid;
	struct rdma_cm_id       *id;
	struct kfi_ibv_eq       *eq;
	struct kfi_ibv_cq       *rcq;
	struct kfi_ibv_cq       *scq;
	struct kfi_ibv_domain   *domain;
	struct kfi_tx_attr      *tx_attr;
	struct kfi_rx_attr      *rx_attr;
	uint64_t                ep_flags;
	struct mutex            mut;
	/* For resolving address and route */
	struct kfi_ibv_ep_conn {
		struct completion       addr_comp;
		struct completion       route_comp;
		struct completion       close_comp;
		int                     status;
	} conn;
	struct kfid             *handle;
};

struct kfi_ibv_connreq {
	struct kfid             handle;
	struct rdma_cm_id       *id;
	struct kfi_ibv_ep       *ep;
};

/* Default fabric info attributes for IB Verbs provider */

static const uint32_t def_tx_ctx_size = 384;
static const uint32_t def_rx_ctx_size = 384;
static const uint32_t def_tx_iov_limit = 4;
static const uint32_t def_rx_iov_limit = 4;
static const uint32_t def_inject_size = 0;

static const struct kfi_domain_attr verbs_domain_attr = {
	.threading              = KFI_THREAD_SAFE,
	.control_progress       = KFI_PROGRESS_AUTO,
	.data_progress          = KFI_PROGRESS_AUTO,
	.mr_key_size            = FIELD_SIZEOF(struct ib_sge, lkey),
	.cq_data_size           = FIELD_SIZEOF(struct ib_send_wr, ex.imm_data),
	.tx_ctx_cnt             = 1024,
	.rx_ctx_cnt             = 1024,
	.max_ep_tx_ctx          = 1,
	.max_ep_rx_ctx          = 1,
};

static const struct kfi_ep_attr verbs_ep_attr = {
	.protocol_version       = 1,
	.msg_prefix_size        = 0,
	.max_order_war_size     = 0,
	.mem_tag_format         = 0,
	.tx_ctx_cnt             = 1,
	.rx_ctx_cnt             = 1,
};

static const struct kfi_rx_attr verbs_rx_attr = {
	.caps                   = VERBS_CAPS,
	.mode                   = VERBS_RX_MODE,
	.msg_order              = VERBS_MSG_ORDER,
	.total_buffered_recv    = 0,
};

static const struct kfi_tx_attr verbs_tx_attr = {
	.caps                   = VERBS_CAPS,
	.mode                   = VERBS_TX_MODE,
	.op_flags               = VERBS_TX_OP_FLAGS,
	.msg_order              = VERBS_MSG_ORDER,
	.inject_size            = 0,
	.rma_iov_limit          = 1,
};

/* Default parameters for IB connection management */

static const int def_cm_to_ms = 2000;
static const u8 def_max_resp_res = 4;
static const u8 def_max_init_depth = 1;

/* Provider support ops */

static int kfi_ibv_getinfo(uint32_t version, struct kfi_info *hints,
                struct kfi_info **info);
static int kfi_ibv_fabric(struct kfi_fabric_attr *attr,
                struct kfid_fabric **fabric, void *context);
static void kfi_ibv_freeinfo(struct kfi_info *info);
static void kfi_ibv_cleanup(void);

static struct kfi_provider ibv_prov = {
	.name = "verbs",
	.version = KFI_VERSION(IBV_MAJOR_VERSION, IBV_MINOR_VERSION),
	.kfi_version = KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION),
	.kgetinfo = kfi_ibv_getinfo,
	.kfabric = kfi_ibv_fabric,
	.kfreeinfo = kfi_ibv_freeinfo,
	.cleanup = kfi_ibv_cleanup,
};

/* Fabric support ops */

static int kfi_ibv_domain(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_domain **domain, void *context);
static int kfi_ibv_passive_ep(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_pep **pep, void *context);
static int kfi_ibv_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
                struct kfid_eq **eq, void *context);

static struct kfi_ops_fabric kfi_ibv_fabric_ops = {
	.domain = kfi_ibv_domain,
	.passive_ep = kfi_ibv_passive_ep,
	.eq_open = kfi_ibv_eq_open,
};

static int kfi_ibv_fabric_close(kfid_t fid);

static struct kfi_ops kfi_ibv_fabric_fid_ops = {
	.close = kfi_ibv_fabric_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};

/* Domain support ops */

static int kfi_ibv_domain_close(kfid_t fid);

static struct kfi_ops kfi_ibv_domain_fid_ops = {
	.close = kfi_ibv_domain_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};

static int kfi_ibv_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
                struct kfid_cq **cq, void *context);
static int kfi_ibv_endpoint(struct kfid_domain *domain, struct kfi_info *info,
                struct kfid_ep **ep, void *context);

static struct kfi_ops_domain kfi_ibv_domain_ops = {
	.cq_open = kfi_ibv_cq_open,
	.endpoint = kfi_ibv_endpoint,
};

static int kfi_ibv_mr_reg(struct kfid *fid, const void *buf, size_t len,
                uint64_t access, uint64_t offset, uint64_t requested_key,
                uint64_t flags, struct kfid_mr **mr, void *context,
                uint64_t *dma_addr);

static struct kfi_ops_mr kfi_ibv_domain_mr_ops = {
	.reg = kfi_ibv_mr_reg,
	.regv = kfi_no_mr_regv,
	.regattr = kfi_no_mr_regattr,
};

static int kfi_ibv_mr_close(kfid_t fid);

static struct kfi_ops kfi_ibv_mr_fi_ops = {
	.close = kfi_ibv_mr_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};

/* EQ support ops */

static int kfi_ibv_eq_close(kfid_t fid);

static struct kfi_ops kfi_ibv_eq_fid_ops = {
	.close = kfi_ibv_eq_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};

static ssize_t kfi_ibv_eq_read(struct kfid_eq *eq, uint32_t *event, void *buf,
                size_t len, uint64_t flags);
static ssize_t kfi_ibv_eq_readerr(struct kfid_eq *eq,
                struct kfi_eq_err_entry *entry, uint64_t flags);
static ssize_t kfi_ibv_eq_sread(struct kfid_eq *eq, uint32_t *event, void *buf,
                size_t len, int timeout, uint64_t flags);
static const char * kfi_ibv_eq_strerror(struct kfid_eq *eq, int prov_errno,
                const void *err_data, char *buf, size_t len);

static struct kfi_ops_eq kfi_ibv_eq_ops = {
	.read = kfi_ibv_eq_read,
	.readerr = kfi_ibv_eq_readerr,
	.write = kfi_no_eq_write,
	.sread = kfi_ibv_eq_sread,
	.strerror = kfi_ibv_eq_strerror,
};

/* CQ support ops */

static int kfi_ibv_cq_close(kfid_t fid);

static struct kfi_ops kfi_ibv_cq_fid_ops = {
	.close = kfi_ibv_cq_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};

static ssize_t kfi_ibv_cq_read_context(struct kfid_cq *cq, void *buf,
                size_t count);
static ssize_t kfi_ibv_cq_readerr(struct kfid_cq *cq,
                struct kfi_cq_err_entry *entry, uint64_t flags);
static ssize_t kfi_ibv_cq_sread(struct kfid_cq *cq, void *buf, size_t count,
                const void *cond, int timeout);
static const char * kfi_ibv_cq_strerror(struct kfid_cq *eq, int prov_errno,
                const void *err_data, char *buf, size_t len);

static struct kfi_ops_cq kfi_ibv_cq_context_ops = {
	.read = kfi_ibv_cq_read_context,
	.readfrom = kfi_no_cq_readfrom,
	.readerr = kfi_ibv_cq_readerr,
	.sread = kfi_ibv_cq_sread,
	.sreadfrom = kfi_no_cq_sreadfrom,
	.signal = kfi_no_cq_signal,
	.strerror = kfi_ibv_cq_strerror,
};

static ssize_t kfi_ibv_cq_read_msg(struct kfid_cq *cq, void *buf, size_t count);

static struct kfi_ops_cq kfi_ibv_cq_msg_ops = {
	.read = kfi_ibv_cq_read_msg,
	.readfrom = kfi_no_cq_readfrom,
	.readerr = kfi_ibv_cq_readerr,
	.sread = kfi_ibv_cq_sread,
	.sreadfrom = kfi_no_cq_sreadfrom,
	.signal = kfi_no_cq_signal,
	.strerror = kfi_ibv_cq_strerror,
};

static ssize_t kfi_ibv_cq_read_data(struct kfid_cq *cq, void *buf, size_t count);

static struct kfi_ops_cq kfi_ibv_cq_data_ops = {
	.read = kfi_ibv_cq_read_data,
	.readfrom = kfi_no_cq_readfrom,
	.readerr = kfi_ibv_cq_readerr,
	.sread = kfi_ibv_cq_sread,
	.sreadfrom = kfi_no_cq_sreadfrom,
	.signal = kfi_no_cq_signal,
	.strerror = kfi_ibv_cq_strerror,
};

/* PEP support ops */

static int kfi_ibv_pep_close(kfid_t fid);
static int kfi_ibv_pep_bind(kfid_t fid, struct kfid *bfid, uint64_t flags);

static struct kfi_ops kfi_ibv_pep_fid_ops = {
	.close = kfi_ibv_pep_close,
	.bind = kfi_ibv_pep_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};

static struct kfi_ops_ep kfi_ibv_pep_ops = {
	.cancel = kfi_no_cancel,
	.getopt = kfi_no_getopt,
	.setopt = kfi_no_setopt,
	.tx_ctx = kfi_no_tx_ctx,
	.rx_ctx = kfi_no_rx_ctx,
	.rx_size_left = kfi_no_rx_size_left,
	.tx_size_left = kfi_no_tx_size_left,
};

static int kfi_ibv_pep_getname(kfid_t fid, void *addr, size_t *addrlen);
static int kfi_ibv_pep_listen(struct kfid_pep *pep);
static int kfi_ibv_pep_reject(struct kfid_pep *pep, kfid_t handle,
                const void *param, size_t paramlen);

static struct kfi_ops_cm kfi_ibv_pep_cm_ops = {
	.setname = kfi_no_setname,
	.getname = kfi_ibv_pep_getname,
	.getpeer = kfi_no_getpeer,
	.connect = kfi_no_connect,
	.listen = kfi_ibv_pep_listen,
	.accept = kfi_no_accept,
	.reject = kfi_ibv_pep_reject,
	.shutdown = kfi_no_shutdown,
};

/* EP support ops */

static int kfi_ibv_ep_close(kfid_t fid);
static int kfi_ibv_ep_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags);
static int kfi_ibv_ep_control(struct kfid *fid, int command, void *arg);

static struct kfi_ops kfi_ibv_ep_fid_ops = {
	.close = kfi_ibv_ep_close,
	.bind = kfi_ibv_ep_bind,
	.control = kfi_ibv_ep_control,
	.ops_open = kfi_no_ops_open,
};

static struct kfi_ops_ep kfi_ibv_ep_ops = {
	.cancel = kfi_no_cancel,
	.getopt = kfi_no_getopt,
	.setopt = kfi_no_setopt,
	.tx_ctx = kfi_no_tx_ctx,
	.rx_ctx = kfi_no_rx_ctx,
	.rx_size_left = kfi_no_rx_size_left,
	.tx_size_left = kfi_no_tx_size_left,
};

static int kfi_ibv_ep_getname(kfid_t fid, void *addr, size_t *addrlen);
static int kfi_ibv_ep_getpeer(struct kfid_ep *ep, void *addr, size_t *addrlen);
static int kfi_ibv_ep_connect(struct kfid_ep *ep, const void *addr,
                const void *param, size_t paramlen);
static int kfi_ibv_ep_accept(struct kfid_ep *ep, const void *param,
                size_t paramlen);
static int kfi_ibv_ep_shutdown(struct kfid_ep *ep, uint64_t flags);

static struct kfi_ops_cm kfi_ibv_ep_cm_ops = {
	.setname = kfi_no_setname,
	.getname = kfi_ibv_ep_getname,
	.getpeer = kfi_ibv_ep_getpeer,
	.connect = kfi_ibv_ep_connect,
	.listen = kfi_no_listen,
	.accept = kfi_ibv_ep_accept,
	.reject = kfi_no_reject,
	.shutdown = kfi_ibv_ep_shutdown,
};

static ssize_t kfi_ibv_ep_recv(struct kfid_ep *ep, void *buf, size_t len,
                void *desc, kfi_addr_t src_addr, void *context);
static ssize_t kfi_ibv_ep_recvv(struct kfid_ep *ep, const struct kvec *iov,
                void **desc, size_t count, kfi_addr_t src_addr, void *context);
static ssize_t kfi_ibv_ep_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg,
                uint64_t flags);
static ssize_t kfi_ibv_ep_send(struct kfid_ep *ep, const void *buf, size_t len,
                void *desc, kfi_addr_t dest_addr, void *context);
static ssize_t kfi_ibv_ep_sendv(struct kfid_ep *ep, const struct kvec *iov,
                void **desc, size_t count, kfi_addr_t dest_addr, void *context);
static ssize_t kfi_ibv_ep_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg,
                uint64_t flags);
static ssize_t kfi_ibv_ep_senddata(struct kfid_ep *ep, const void *buf,
                size_t len, void *desc, uint64_t data, kfi_addr_t dest_addr,
                void *context);

static struct kfi_ops_msg kfi_ibv_ep_msg_ops = {
	.recv = kfi_ibv_ep_recv,
	.recvv = kfi_ibv_ep_recvv,
	.recvmsg = kfi_ibv_ep_recvmsg,
	.send = kfi_ibv_ep_send,
	.sendv = kfi_ibv_ep_sendv,
	.sendmsg = kfi_ibv_ep_sendmsg,
	.inject = kfi_no_msg_inject,
	.senddata = kfi_ibv_ep_senddata,
	.injectdata = kfi_no_msg_injectdata,
};

static ssize_t kfi_ibv_ep_rma_read(struct kfid_ep *ep, void *buf, size_t len,
                void *desc, kfi_addr_t src_addr, uint64_t addr, uint64_t key,
                void *context);
static ssize_t kfi_ibv_ep_rma_readv(struct kfid_ep *ep, const struct kvec *iov,
                void **desc, size_t count, kfi_addr_t src_addr, uint64_t addr,
                uint64_t key, void *context);
static ssize_t kfi_ibv_ep_rma_readmsg(struct kfid_ep *ep,
                const struct kfi_msg_rma *msg, uint64_t flags);
static ssize_t kfi_ibv_ep_rma_write(struct kfid_ep *ep, const void *buf,
                size_t len, void *desc, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, void *context);
static ssize_t kfi_ibv_ep_rma_writev(struct kfid_ep *ep, const struct kvec *iov,
                void **desc, size_t count, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, void *context);
static ssize_t kfi_ibv_ep_rma_writemsg(struct kfid_ep *ep,
                const struct kfi_msg_rma *msg, uint64_t flags);
static ssize_t kfi_ibv_ep_rma_writedata(struct kfid_ep *ep, const void *buf,
                size_t len, void *desc, uint64_t data, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, void *context);

static struct kfi_ops_rma kfi_ibv_ep_rma_ops = {
	.read = kfi_ibv_ep_rma_read,
	.readv = kfi_ibv_ep_rma_readv,
	.readmsg = kfi_ibv_ep_rma_readmsg,
	.write = kfi_ibv_ep_rma_write,
	.writev = kfi_ibv_ep_rma_writev,
	.writemsg = kfi_ibv_ep_rma_writemsg,
	.inject = kfi_no_rma_inject,
	.writedata = kfi_ibv_ep_rma_writedata,
	.injectdata = kfi_no_rma_injectdata,
};

static ssize_t kfi_ibv_ep_atomic_write(struct kfid_ep *ep, const void *buf,
                size_t count, void *desc, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context);
static ssize_t kfi_ibv_ep_atomic_writev(struct kfid_ep *ep,
                const struct kfi_ioc *iov, void **desc, size_t count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context);
static ssize_t kfi_ibv_ep_atomic_writemsg(struct kfid_ep *ep,
                const struct kfi_msg_atomic *msg, uint64_t flags);
static ssize_t kfi_ibv_ep_atomic_readwrite(struct kfid_ep *ep, const void *buf,
                size_t count, void *desc, void *result, void *result_desc,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context);
static ssize_t kfi_ibv_ep_atomic_readwritev(struct kfid_ep *ep,
                const struct kfi_ioc *iov, void **desc, size_t count,
                struct kfi_ioc *resultv, void **result_desc, size_t result_count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context);
static ssize_t kfi_ibv_ep_atomic_readwritemsg(struct kfid_ep *ep,
                const struct kfi_msg_atomic *msg, struct kfi_ioc *resultv,
                void **result_desc, size_t result_count, uint64_t flags);
static ssize_t kfi_ibv_ep_atomic_compwrite(struct kfid_ep *ep, const void *buf,
                size_t count, void *desc, const void *compare, void *compare_desc,
                void *result, void *result_desc, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
                enum kfi_op op, void *context);
static ssize_t kfi_ibv_ep_atomic_compwritev(struct kfid_ep *ep,
                const struct kfi_ioc *iov, void **desc, size_t count,
                const struct kfi_ioc *comparev, void **compare_desc,
                size_t compare_count, struct kfi_ioc *resultv, void **result_desc,
                size_t result_count, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context);
static ssize_t kfi_ibv_ep_atomic_compwritemsg(struct kfid_ep *ep,
                const struct kfi_msg_atomic *msg, const struct kfi_ioc *comparev,
                void **compare_desc, size_t compare_count,
                struct kfi_ioc *resultv, void **result_desc, size_t result_count,
                uint64_t flags);
static int kfi_ibv_ep_atomic_writevalid(struct kfid_ep *ep,
                enum kfi_datatype datatype, enum kfi_op op, size_t *count);
static int kfi_ibv_ep_atomic_readwritevalid(struct kfid_ep *ep,
                enum kfi_datatype datatype, enum kfi_op op, size_t *count);
static int kfi_ibv_ep_atomic_compwritevalid(struct kfid_ep *ep,
                enum kfi_datatype datatype, enum kfi_op op, size_t *count);

static struct kfi_ops_atomic kfi_ibv_ep_atomic_ops = {
	.write = kfi_ibv_ep_atomic_write,
	.writev = kfi_ibv_ep_atomic_writev,
	.writemsg = kfi_ibv_ep_atomic_writemsg,
	.inject = kfi_no_atomic_inject,
	.readwrite = kfi_ibv_ep_atomic_readwrite,
	.readwritev = kfi_ibv_ep_atomic_readwritev,
	.readwritemsg = kfi_ibv_ep_atomic_readwritemsg,
	.compwrite = kfi_ibv_ep_atomic_compwrite,
	.compwritev = kfi_ibv_ep_atomic_compwritev,
	.compwritemsg = kfi_ibv_ep_atomic_compwritemsg,
	.writevalid = kfi_ibv_ep_atomic_writevalid,
	.readwritevalid = kfi_ibv_ep_atomic_readwritevalid,
	.compwritevalid = kfi_ibv_ep_atomic_compwritevalid,
};

static struct kfi_ops_tagged kfi_ibv_ep_tagged_ops = {
	.recv = kfi_no_tagged_recv,
	.recvv = kfi_no_tagged_recvv,
	.recvmsg = kfi_no_tagged_recvmsg,
	.send = kfi_no_tagged_send,
	.sendv = kfi_no_tagged_sendv,
	.sendmsg = kfi_no_tagged_sendmsg,
	.inject = kfi_no_tagged_inject,
	.senddata = kfi_no_tagged_senddata,
	.injectdata = kfi_no_tagged_injectdata,
};

/* Verb provider as an OFED client */

static void ib_kofi_add_one(struct ib_device *device);
static void ib_kofi_remove_one(struct ib_device *device);
static struct ib_client kofi_client = {
	.name   = "kofi",
	.add    = ib_kofi_add_one,
	.remove = ib_kofi_remove_one
};
static int kfi_ibv_cma_handler(struct rdma_cm_id *cma_id,
                struct rdma_cm_event *event);
static void kfi_ibv_qp_handler(struct ib_event *event, void *context);
static void kfi_ibv_cq_comp_handler(struct ib_cq *cq, void *context);
static void kfi_ibv_cq_event_handler(struct ib_event *event, void *context);

/* Helper routines */
static int kfi_ibv_get_info_dev(struct ib_device *device, struct kfi_info **info);
static struct kfi_ibv_device *kfi_ibv_find_dev(const char *fabric_name,
                const char *domain_name);
static struct kfi_info *kfi_ibv_find_info(const char *fabric_name,
                const char *domain_name);
static struct kfi_info * kfi_ibv_eq_cm_getinfo(struct kfi_ibv_event *event);
static int kfi_ibv_get_device_attrs(struct ib_device *device,
                struct kfi_info *info);
static int kfi_ibv_get_qp_cap(struct ib_device *device,
                struct ib_device_attr *device_attr, struct kfi_info *info);
static int kfi_ibv_create_id(const struct kfi_info *hints, struct rdma_cm_id **id,
                bool passive_ep);
static int kfi_ibv_check_hints(const struct kfi_info *hints,
                const struct kfi_info *info);
static void kfi_ibv_update_info(const struct kfi_info *hints,
                struct kfi_info *info);
static int kfi_ibv_check_fabric_attr(const struct kfi_fabric_attr *attr,
                const struct kfi_info *info);
static int kfi_ibv_check_domain_attr(const struct kfi_domain_attr *attr,
                const struct kfi_info *info);
static int kfi_ibv_check_ep_attr(const struct kfi_ep_attr *attr,
                const struct kfi_info *info);
static int kfi_ibv_check_rx_attr(const struct kfi_rx_attr *attr,
                const struct kfi_info *hints, const struct kfi_info *info);
static int kfi_ibv_check_tx_attr(const struct kfi_tx_attr *attr,
                const struct kfi_info *hints, const struct kfi_info *info);
static int kfi_ibv_copy_addr(void *dst_addr, size_t *dst_addrlen, void *src_addr);
static int kfi_ibv_sockaddr_len(struct sockaddr *addr);
static ssize_t kfi_ibv_eq_cm_process_event(struct kfi_ibv_eq *eq,
                struct kfi_ibv_event *cma_event, uint32_t *event,
                struct kfi_eq_cm_entry *entry, size_t len);
static int kfi_ibv_pep_unbind(kfid_t fid, struct kfid *bfid);
static int kfi_ibv_ep_unbind(kfid_t fid, struct kfid *bfid, uint64_t flags);
static const char * kstrerror(int errno);
static const char *ib_wc_status_str(enum ib_wc_status status);
static uint64_t kfi_ibv_comp_flags(struct ib_wc *wc);
static int kfi_ibv_fill_sge(void *addr, size_t len, void *desc, struct ib_sge *sge);

static int __init
kfi_ibv_init(void)
{
	int ret = 0;

	/* Register provider to KOFI framework */
	ret = kfi_provider_register(&ibv_prov);
	if (ret) {
		LOG_ERR("Failed to register provider.");
		goto err_prov;
	}

	/* Register KOFI to OFED as a client */
	ret = ib_register_client(&kofi_client);
	if (ret) {
		LOG_ERR("Failed register OFED client.");
		goto err_client;
	}

	return ret;

err_client:
	ib_unregister_client(&kofi_client);
err_prov:
	(void)kfi_provider_deregister(&ibv_prov);
	return ret;
}

static void __exit
kfi_ibv_exit(void)
{
	ib_unregister_client(&kofi_client);
	(void)kfi_provider_deregister(&ibv_prov);
	return;
}

static void
ib_kofi_add_one(struct ib_device *device)
{
	struct kfi_info *fi = NULL;
	struct kfi_ibv_device *dev = NULL;
	int ret = 0;

	if (!device) {
		return;
	}

	ret = kfi_ibv_get_info_dev(device, &fi);
	if (ret) {
		LOG_ERR("Failed obain fabric information for %s.",
		                device->name);
		goto err;
	}
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		LOG_ERR("Failed to allocate device context for %s.",
		                device->name);
		goto err;
	}
	INIT_LIST_HEAD(&dev->list);
	dev->device = device;
	dev->info = fi;

	mutex_lock(&ibv_dev_mutex);
	list_add_tail(&dev->list, &ibv_dev_list);
	mutex_unlock(&ibv_dev_mutex);

	LOG_INFO("Added device context for %s.", device->name);
	return;

err:
	kfi_deallocinfo(fi);
	return;
}

static void
ib_kofi_remove_one(struct ib_device *device)
{
	struct list_head *lh = NULL, *tmp = NULL;
	struct kfi_ibv_device *dev = NULL;

	if (!device) {
		return;
	}

	mutex_lock(&ibv_dev_mutex);
	list_for_each_safe(lh, tmp, &ibv_dev_list) {
		dev = list_entry(lh, typeof(*dev), list);
		if (dev->device == device) {
			list_del(&dev->list);
			kfi_deallocinfo(dev->info);
			kfree(dev);
			LOG_INFO("Removed device context for %s.", device->name);
		}
	}
	mutex_unlock(&ibv_dev_mutex);

	return;
}

static int
kfi_ibv_getinfo(uint32_t version, struct kfi_info *hints, struct kfi_info **info)
{
	struct list_head *lh = NULL;
	struct kfi_info *fi = NULL, *_fi = NULL, *tail = NULL, *check_info = NULL;
	struct kfi_ibv_device *dev = NULL;
	struct kfi_ibv_pep *pep = NULL;
	struct kfi_ibv_ep *ep = NULL;
	struct rdma_cm_id *id = NULL;
	int ret = 0;

	if (hints && hints->dest_addr) {
		ep = kzalloc(sizeof(*ep), GFP_KERNEL);
		if (!ep) {
			ret = -ENOMEM;
			goto err_cleanup;
		}
		kfi_init_id(&ep->ep_fid.fid);
		ep->ep_fid.fid.fclass = KFI_CLASS_EP;
		mutex_init(&ep->mut);
		init_completion(&ep->conn.addr_comp);
		init_completion(&ep->conn.route_comp);
		init_completion(&ep->conn.close_comp);
		ret = kfi_ibv_create_id(hints, &ep->id, false);
		id = ep->id;
	} else if (hints && hints->src_addr) {
		pep = kzalloc(sizeof(*pep), GFP_KERNEL);
		if (!pep) {
			ret = -ENOMEM;
			goto err_cleanup;
		}
		kfi_init_id(&pep->pep_fid.fid);
		pep->pep_fid.fid.fclass = KFI_CLASS_PEP;
		mutex_init(&pep->mut);
		ret = kfi_ibv_create_id(hints, &pep->id, true);
		id = pep->id;
	}

	if (ret){
		goto err_cleanup;
	}

	mutex_lock(&ibv_dev_mutex);
	if (list_empty(&ibv_dev_list)) {
		ret = -ENODATA;
		goto err_unlock;
	}
	if (id && id->device) {
		check_info = kfi_ibv_find_info(NULL, id->device->name);
		if (!check_info) {
			ret = -ENODATA;
			goto err_unlock;
		}
		ret = kfi_ibv_check_hints(hints, check_info);
		if (ret) {
			goto err_unlock;
		}
		if (!(fi = kfi_dupinfo(check_info))) {
			ret = -ENOMEM;
			goto err_unlock;
		}
		kfi_ibv_update_info(hints, fi);
	} else {
		list_for_each(lh, &ibv_dev_list) {
			dev = list_entry(lh, typeof(*dev), list);
			check_info = dev->info;
			if (hints) {
				ret = kfi_ibv_check_hints(hints, check_info);
				if (ret) {
					continue;
				}
			}
			if (!(_fi = kfi_dupinfo(check_info))) {
				ret = -ENOMEM;
				goto err_unlock;
			}
			if (!fi) {
				fi = _fi;
			}
			if (tail) {
				tail->next = _fi;
			} else {
				tail = _fi;
			}
			if (hints) {
				kfi_ibv_update_info(hints, _fi);
			}
		}
		if (!fi) {
			ret = -ENODATA;
			goto err_unlock;
		}
	}

	*info = fi;
	mutex_unlock(&ibv_dev_mutex);
	if (id) {
		rdma_destroy_id(id);
	}
	if (pep) {
		kfree(pep);
	}
	if (ep) {
		kfree(ep);
	}
	return ret;

err_unlock:
	mutex_unlock(&ibv_dev_mutex);
err_cleanup:
	kfi_deallocinfo(fi);
	if (id) {
		rdma_destroy_id(id);
	}
	if (pep) {
		kfree(pep);
	}
	if (ep) {
		kfree(ep);
	}
	return ret;
}

static int
kfi_ibv_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
                void *context)
{
	struct kfi_ibv_fabric *fab = NULL;
	struct kfi_info *info = NULL;
	int ret = 0;

	kfi_ref_provider(&ibv_prov);

	info = kfi_ibv_find_info(attr->name, NULL);
	if (!info) {
		ret = -ENODATA;
		goto err;
	}
	ret = kfi_ibv_check_fabric_attr(attr, info);
	if (ret) {
		goto err;
	}

	fab = kzalloc(sizeof(*fab), GFP_KERNEL);
	if (!fab) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&fab->fabric_fid.fid);
	fab->fabric_fid.fid.fclass = KFI_CLASS_FABRIC;
	fab->fabric_fid.fid.context = context;
	fab->fabric_fid.fid.ops = &kfi_ibv_fabric_fid_ops;
	fab->fabric_fid.ops = &kfi_ibv_fabric_ops;
	*fabric = &fab->fabric_fid;

	return ret;

err:
	kfi_deref_provider(&ibv_prov);
	return ret;
}

static void
kfi_ibv_freeinfo(struct kfi_info *info)
{
	return;
}

static void
kfi_ibv_cleanup(void)
{
	return;
}

static int
kfi_ibv_domain(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_domain **domain, void *context)
{
	struct kfi_ibv_domain *_domain = NULL;
	struct kfi_info *fi = NULL;
	int ret = 0;

	kfi_ref_id(&fabric->fid);

	fi = kfi_ibv_find_info(NULL, info->domain_attr->name);
	if (!fi) {
		ret = -EINVAL;
		goto err;
	}
	ret = kfi_ibv_check_domain_attr(info->domain_attr, fi);
	if (ret) {
		goto err;
	}

	_domain = kzalloc(sizeof(*_domain), GFP_KERNEL);
	if (!_domain) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&_domain->domain_fid.fid);
	_domain->dev = kfi_ibv_find_dev(NULL, info->domain_attr->name);
	if (!_domain->dev) {
		ret = -ENODEV;
		goto err;
	}
	_domain->fab = container_of(fabric, struct kfi_ibv_fabric, fabric_fid);
	_domain->domain_fid.fid.fclass = KFI_CLASS_DOMAIN;
	_domain->domain_fid.fid.context = context;
	_domain->domain_fid.fid.ops = &kfi_ibv_domain_fid_ops;
	_domain->domain_fid.ops = &kfi_ibv_domain_ops;
	_domain->domain_fid.mr = &kfi_ibv_domain_mr_ops;

	_domain->pd = ib_alloc_pd(_domain->dev->device);
	if (!_domain->pd) {
		ret = -EBUSY;
		goto err;
	}
	*domain = &_domain->domain_fid;

	return ret;

err:
	if (_domain) {
		kfree(_domain);
	}
	kfi_deref_id(&fabric->fid);
	return ret;
}

static int
kfi_ibv_passive_ep(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_pep **pep, void *context)
{
	struct kfi_ibv_pep *_pep = NULL;
	int ret = 0;

	kfi_ref_id(&fabric->fid);

	_pep = kzalloc(sizeof(*_pep), GFP_KERNEL);
	if (!_pep) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&_pep->pep_fid.fid);
	_pep->pep_fid.fid.fclass = KFI_CLASS_PEP;
	_pep->pep_fid.fid.context = context;
	_pep->pep_fid.fid.ops = &kfi_ibv_pep_fid_ops;
	mutex_init(&_pep->mut);
	_pep->fab = container_of(fabric, struct kfi_ibv_fabric, fabric_fid);
	_pep->pep_fid.ops = &kfi_ibv_pep_ops;
	_pep->pep_fid.cm = &kfi_ibv_pep_cm_ops;

	ret = kfi_ibv_create_id(info, &_pep->id, true);
	if (ret) {
		goto err;
	}
	*pep = &_pep->pep_fid;

	return ret;

err:
	if (_pep) {
		kfree(_pep);
	}
	kfi_deref_id(&fabric->fid);
	return ret;
}

static int
kfi_ibv_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
                struct kfid_eq **eq, void *context)
{
	struct kfi_ibv_eq *_eq = NULL;
	int ret = 0;

	kfi_ref_id(&fabric->fid);

	_eq = kzalloc(sizeof(*_eq), GFP_KERNEL);
	if (!_eq) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&_eq->eq_fid.fid);
	_eq->eq_fid.fid.fclass = KFI_CLASS_EQ;
	_eq->eq_fid.fid.context = context;
	_eq->eq_fid.fid.ops = &kfi_ibv_eq_fid_ops;
	_eq->eq_fid.ops = &kfi_ibv_eq_ops;
	mutex_init(&_eq->mut);
	INIT_LIST_HEAD(&_eq->event_list);
	init_waitqueue_head(&_eq->poll_wait);
	_eq->fab = container_of(fabric, struct kfi_ibv_fabric, fabric_fid);
	_eq->flags = attr->flags;
	*eq = &_eq->eq_fid;

	return ret;

err:
	kfi_deref_id(&fabric->fid);
	return ret;
}

static int
kfi_ibv_fabric_close(kfid_t fid)
{
	struct kfi_ibv_fabric *fab = NULL;

	fab = container_of(fid, struct kfi_ibv_fabric, fabric_fid.fid);
	kfi_close_id(fid);
	kfree(fab);
	kfi_deref_provider(&ibv_prov);
	return 0;
}

static int
kfi_ibv_domain_close(kfid_t fid)
{
	struct kfi_ibv_domain *domain = NULL;
	struct kfi_ibv_fabric *fab = NULL;
	int ret = 0;

	domain = container_of(fid, struct kfi_ibv_domain, domain_fid.fid);
	fab = domain->fab;
	if (domain->pd) {
		ret = ib_dealloc_pd(domain->pd);
		domain->pd = NULL;
	}
	kfi_close_id(fid);
	kfree(domain);
	kfi_deref_id(&fab->fabric_fid.fid);
	return ret;
}

static int
kfi_ibv_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
                struct kfid_cq **cq, void *context)
{
	struct kfi_ibv_cq *_cq = NULL;
	int ret = 0;

	kfi_ref_id(&domain->fid);

	_cq = kzalloc(sizeof(*_cq), GFP_KERNEL);
	if (!_cq) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&_cq->cq_fid.fid);
	_cq->cq_fid.fid.fclass = KFI_CLASS_CQ;
	_cq->cq_fid.fid.context = context;
	_cq->cq_fid.fid.ops = &kfi_ibv_cq_fid_ops;
	_cq->domain = container_of(domain, struct kfi_ibv_domain, domain_fid);
	_cq->flags |= attr->flags;
	mutex_init(&_cq->mut);
	init_waitqueue_head(&_cq->wait);

	switch (attr->format) {
	case KFI_CQ_FORMAT_CONTEXT:
		_cq->cq_fid.ops = &kfi_ibv_cq_context_ops;
		_cq->entry_size = sizeof(struct kfi_cq_entry);
		break;
	case KFI_CQ_FORMAT_MSG:
		_cq->cq_fid.ops = &kfi_ibv_cq_msg_ops;
		_cq->entry_size = sizeof(struct kfi_cq_msg_entry);
		break;
	case KFI_CQ_FORMAT_DATA:
		_cq->cq_fid.ops = &kfi_ibv_cq_data_ops;
		_cq->entry_size = sizeof(struct kfi_cq_data_entry);
		break;
	default:
		ret = -ENOSYS;
		goto err;
	}

	_cq->cq = ib_create_cq(_cq->domain->dev->device, kfi_ibv_cq_comp_handler,
		kfi_ibv_cq_event_handler, _cq, attr->size, attr->signaling_vector);
	if (IS_ERR(_cq->cq)) {
		ret = PTR_ERR(_cq->cq);
		goto err;
	}
	*cq = &_cq->cq_fid;
	return 0;

err:
	if (_cq) {
		kfree(_cq);
	}
	kfi_deref_id(&domain->fid);
	return ret;
}

static int
kfi_ibv_endpoint(struct kfid_domain *domain, struct kfi_info *info,
                struct kfid_ep **ep, void *context)
{
	struct kfi_ibv_domain *dom = NULL;
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_ibv_connreq *connreq = NULL;
	struct kfi_info *fi = NULL;
	int ret = 0;

	kfi_ref_id(&domain->fid);

	dom = container_of(domain, struct kfi_ibv_domain, domain_fid);
	if (info->domain_attr && info->domain_attr->name) {
		if (strcmp(dom->dev->device->name, info->domain_attr->name)) {
			ret = -EINVAL;
			goto err;
		}
	}
	fi = kfi_ibv_find_info(NULL, info->domain_attr->name);
	if (!fi) {
		ret = -EINVAL;
		goto err;
	}
	if (info->ep_attr) {
		ret = kfi_ibv_check_ep_attr(info->ep_attr, fi);
		if (ret) {
			goto err;
		}
	}
	if (info->tx_attr) {
		ret = kfi_ibv_check_tx_attr(info->tx_attr, info, fi);
		if (ret) {
			goto err;
		}
	}
	if (info->rx_attr) {
		ret = kfi_ibv_check_rx_attr(info->rx_attr, info, fi);
		if (ret) {
			goto err;
		}
	}

	_ep = kzalloc(sizeof(*_ep), GFP_KERNEL);
	if (!_ep) {
		ret = -ENOMEM;
		goto err;
	}
	_ep->tx_attr = kzalloc(sizeof(*_ep->tx_attr), GFP_KERNEL);
	_ep->rx_attr = kzalloc(sizeof(*_ep->rx_attr), GFP_KERNEL);
	if (!_ep->tx_attr || !_ep->rx_attr) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&_ep->ep_fid.fid);
	_ep->ep_fid.fid.fclass = KFI_CLASS_EP;
	_ep->ep_fid.fid.context = context;
	_ep->ep_fid.fid.ops = &kfi_ibv_ep_fid_ops;
	mutex_init(&_ep->mut);
	init_completion(&_ep->conn.addr_comp);
	init_completion(&_ep->conn.route_comp);
	init_completion(&_ep->conn.close_comp);
	_ep->domain = dom;
	_ep->ep_fid.ops = &kfi_ibv_ep_ops;
	_ep->ep_fid.cm = &kfi_ibv_ep_cm_ops;
	_ep->ep_fid.msg = &kfi_ibv_ep_msg_ops;
	_ep->ep_fid.rma = &kfi_ibv_ep_rma_ops;
	_ep->ep_fid.atomic = &kfi_ibv_ep_atomic_ops;
	_ep->ep_fid.tagged = &kfi_ibv_ep_tagged_ops;
	if (info->tx_attr) {
		*(_ep->tx_attr) = *(info->tx_attr);
	}
	if (info->rx_attr) {
		*(_ep->rx_attr) = *(info->rx_attr);
	}

	if (!info->handle) {
		ret = kfi_ibv_create_id(info, &_ep->id, false);
		if (ret) {
			goto err;
		}
	} else if (info->handle->fclass == KFI_CLASS_CONNREQ) {
		connreq = container_of(info->handle, struct kfi_ibv_connreq, handle);
		connreq->ep = _ep;
		kfi_ref_id(&_ep->ep_fid.fid);
		_ep->handle = info->handle;
		kfi_ref_id(info->handle);
		_ep->id = connreq->id;
		_ep->id->event_handler = kfi_ibv_cma_handler;
		_ep->id->context = &_ep->ep_fid.fid;
	} else {
		ret = -ENOSYS;
		goto err;
	}
	*ep = &_ep->ep_fid;

	return ret;

err:
	if (_ep) {
		if (_ep->tx_attr) {
			kfree(_ep->tx_attr);
		}
		if (_ep->rx_attr) {
			kfree(_ep->rx_attr);
		}
		kfree(_ep);
	}
	kfi_deref_id(&domain->fid);
	return ret;
}

static int
kfi_ibv_mr_reg(struct kfid *fid, const void *buf, size_t len, uint64_t access,
                uint64_t offset, uint64_t requested_key, uint64_t flags,
                struct kfid_mr **mr, void *context, uint64_t *dma_addr)
{
	struct kfi_ibv_mem_desc *md = NULL;
	int ibv_access = 0;
	int ret = 0;

	kfi_ref_id(fid);
	if (fid->fclass != KFI_CLASS_DOMAIN) {
		ret = -EINVAL;
		goto err;
	}

	md = kzalloc(sizeof(*md), GFP_KERNEL);
	if (!md) {
		ret = -ENOMEM;
		goto err;
	}
	kfi_init_id(&md->mr_fid.fid);
	md->mr_fid.fid.fclass = KFI_CLASS_MR;
	md->mr_fid.fid.context = context;
	md->mr_fid.fid.ops = &kfi_ibv_mr_fi_ops;
	md->domain = container_of(fid, struct kfi_ibv_domain, domain_fid.fid);

	ibv_access = IB_ACCESS_LOCAL_WRITE;
	if (access & KFI_REMOTE_READ) {
		ibv_access |= IB_ACCESS_REMOTE_READ;
	}
	if (access & KFI_REMOTE_WRITE) {
		ibv_access |= IB_ACCESS_REMOTE_WRITE;
	}
	if ((access & KFI_READ) || (access & KFI_WRITE)) {
		ibv_access |= IB_ACCESS_REMOTE_ATOMIC;
	}
	md->vaddr = (void*)buf;
	md->mr = ib_get_dma_mr(md->domain->pd, ibv_access);
	if (IS_ERR(md->mr)) {
		ret = PTR_ERR(md->mr);
		goto err;
	}
	md->mr_fid.mem_desc = (void *)md;
	md->mr_fid.key = md->mr->rkey;

	md->dma_addr = ib_dma_map_single(md->domain->dev->device, (void *)buf,
	                                          len, DMA_BIDIRECTIONAL);
	ret = ib_dma_mapping_error(md->domain->dev->device, md->dma_addr);
	if (ret) {
		md->dma_addr = 0;
		goto err;
	}
	md->dma_len = len;

	*mr = &md->mr_fid;
	*dma_addr = md->dma_addr;
	return ret;
err:
	if (md) {
		if (md->dma_addr) {
			ib_dma_unmap_single(md->domain->dev->device,
			                md->dma_addr, len, DMA_BIDIRECTIONAL);
			md->dma_addr = 0;
		}
		if (md->mr) {
			(void)ib_dereg_mr(md->mr);
		}
		kfree(md);
	}
	kfi_deref_id(fid);
	return ret;
}

static int
kfi_ibv_mr_close(kfid_t fid)
{
	struct kfi_ibv_mem_desc *md = NULL;
	struct kfi_ibv_domain *domain = NULL;
	int ret = 0;

	md = container_of(fid, struct kfi_ibv_mem_desc, mr_fid.fid);
	domain = md->domain;
	if (md->dma_addr) {
		ib_dma_unmap_single(md->domain->dev->device, md->dma_addr,
		                md->dma_len, DMA_BIDIRECTIONAL);
		md->dma_addr = 0;
	}
	if (md->mr) {
		ret = ib_dereg_mr(md->mr);
	}
	kfi_close_id(fid);
	kfree(md);
	kfi_deref_id(&domain->domain_fid.fid);
	return ret;
}

static int
kfi_ibv_eq_close(kfid_t fid)
{
	struct kfi_ibv_eq *eq = NULL;
	struct kfi_ibv_fabric *fab = NULL;
	struct list_head *lh = NULL, *tmp = NULL;
	struct kfi_ibv_event *event = NULL;
	int ret = 0;

	eq = container_of(fid, struct kfi_ibv_eq, eq_fid.fid);
	fab = eq->fab;
	if (eq->ep_fid) {
		if (eq->ep_fid->fclass == KFI_CLASS_PEP) {
			ret = kfi_ibv_pep_unbind(eq->ep_fid, fid);
		} else if (eq->ep_fid->fclass == KFI_CLASS_EP) {
			ret = kfi_ibv_ep_unbind(eq->ep_fid, fid, 0);
		}
	}

	mutex_lock(&eq->mut);
	if (!list_empty(&eq->event_list)) {
		list_for_each_safe(lh, tmp, &eq->event_list) {
			event = list_entry(lh, typeof(*event), list);
			list_del(&event->list);
			if (event->event.param.conn.private_data_len) {
				kfree(event->event.param.conn.private_data);
			}
			kfree(event);
		}
	}
	mutex_unlock(&eq->mut);

	kfi_close_id(fid);
	kfree(eq);
	kfi_deref_id(&fab->fabric_fid.fid);
	return 0;
}

static ssize_t
kfi_ibv_eq_read(struct kfid_eq *eq, uint32_t *event, void *buf, size_t len,
                uint64_t flags)
{
	struct kfi_ibv_eq *_eq = NULL;
	struct kfi_ibv_event *_event = NULL;
	struct kfi_eq_cm_entry *entry = NULL;
	ssize_t ret = 0;

	kfi_ref_id(&eq->fid);
	_eq = container_of(eq, struct kfi_ibv_eq, eq_fid);
	entry = (struct kfi_eq_cm_entry *) buf;

	mutex_lock(&_eq->mut);
	if (_eq->err.err) {
		ret = -EIO;
		goto exit;
	}
	if (list_empty(&_eq->event_list)) {
		ret = -EAGAIN;
		goto exit;
	}
	_event = list_first_entry(&_eq->event_list, typeof(*_event), list);
	list_del(&_event->list);

	ret = kfi_ibv_eq_cm_process_event(_eq, _event, event, entry, len);
	if (_event->event.param.conn.private_data_len) {
		kfree(_event->event.param.conn.private_data);
	}
	kfree(_event);
exit:
	mutex_unlock(&_eq->mut);
	kfi_deref_id(&eq->fid);
	return ret;
}

static ssize_t
kfi_ibv_eq_readerr(struct kfid_eq *eq, struct kfi_eq_err_entry *entry,
                uint64_t flags)
{
	struct kfi_ibv_eq *_eq = NULL;
	ssize_t ret = 0;

	kfi_ref_id(&eq->fid);
	_eq = container_of(eq, struct kfi_ibv_eq, eq_fid);

	mutex_lock(&_eq->mut);
	if (!_eq->err.err) {
		goto exit;
	}
	*entry = _eq->err;
	_eq->err.err = 0;
	_eq->err.prov_errno = 0;
	ret = sizeof(*entry);
exit:
	mutex_unlock(&_eq->mut);
	kfi_deref_id(&eq->fid);
	return ret;
}

static ssize_t
kfi_ibv_eq_sread(struct kfid_eq *eq, uint32_t *event, void *buf, size_t len,
                int timeout, uint64_t flags)
{
	struct kfi_ibv_eq *_eq = NULL;
	ssize_t ret = 0;

	kfi_ref_id(&eq->fid);
	_eq = container_of(eq, struct kfi_ibv_eq, eq_fid);

	while (1) {
		ret = kfi_ibv_eq_read(eq, event, buf, len, flags);
		if (ret && (ret != -EAGAIN)) {
			goto exit;
		}
		if (timeout > 0) {
			ret = wait_event_interruptible_timeout(_eq->poll_wait,
			                      !list_empty(&_eq->event_list),
			                      msecs_to_jiffies(timeout));
			if (ret == 0) {
				ret = -EAGAIN;
				goto exit;
			}
		} else {
			ret = wait_event_interruptible(_eq->poll_wait,
			                      !list_empty(&_eq->event_list));
		}
		if (ret < 0) {
			goto exit;
		}
	}
exit:
	kfi_deref_id(&eq->fid);
	return ret;
}

static const char *
kfi_ibv_eq_strerror(struct kfid_eq *eq, int prov_errno, const void *err_data,
                char *buf, size_t len)
{
	if (buf && len) {
		strncpy(buf, kstrerror(prov_errno), len);
	}
	return kstrerror(prov_errno);
}

static int
kfi_ibv_cq_close(kfid_t fid)
{
	struct kfi_ibv_cq *cq = NULL;
	struct kfi_ibv_domain *domain = NULL;
	int ret = 0;

	cq = container_of(fid, struct kfi_ibv_cq, cq_fid.fid);
	domain = cq->domain;

	mutex_lock(&cq->mut);
	if (cq->cq) {
		ret = ib_destroy_cq(cq->cq);
		cq->cq = NULL;
	}
	mutex_unlock(&cq->mut);

	kfi_close_id(fid);
	kfree(cq);
	kfi_deref_id(&domain->domain_fid.fid);
	return ret;
}

static ssize_t
kfi_ibv_cq_read_context(struct kfid_cq *cq, void *buf, size_t count)
{
	struct kfi_ibv_cq *_cq = NULL;
	struct kfi_cq_entry *entry = buf;
	ssize_t ret = 0, i = 0;

	kfi_ref_id(&cq->fid);
	_cq = container_of(cq, struct kfi_ibv_cq, cq_fid);

	mutex_lock(&_cq->mut);
	if (_cq->wc.status) {
		ret = -EIO;
		goto exit;
	}
	for (i = 0; i < count; i++) {
		ret = ib_poll_cq(_cq->cq, 1, &_cq->wc);
		if (ret <= 0) {
			break;
		}
		if (_cq->wc.status) {
			ret = -EIO;
			break;
		}
		entry->op_context = (void *)_cq->wc.wr_id;
		entry += 1;
	}
exit:
	mutex_unlock(&_cq->mut);
	kfi_deref_id(&cq->fid);
	return i ? i : (ret ? ret : -EAGAIN);
}

static ssize_t
kfi_ibv_cq_readerr(struct kfid_cq *cq, struct kfi_cq_err_entry *entry,
                uint64_t flags)
{
	struct kfi_ibv_cq *_cq = NULL;
	ssize_t ret = 0;

	kfi_ref_id(&cq->fid);
	_cq = container_of(cq, struct kfi_ibv_cq, cq_fid);

	mutex_lock(&_cq->mut);
	if (!_cq->wc.status) {
		ret = 0;
		goto exit;
	}
	entry->op_context = (void *)_cq->wc.wr_id;
	entry->flags = 0;
	entry->err = EIO;
	entry->prov_errno = _cq->wc.status;
	memcpy(&entry->err_data, &_cq->wc.vendor_err, sizeof(_cq->wc.vendor_err));
	_cq->wc.status = 0;
	ret = sizeof(*entry);
exit:
	mutex_unlock(&_cq->mut);
	kfi_deref_id(&cq->fid);
	return sizeof(*entry);
}

static ssize_t
kfi_ibv_cq_sread(struct kfid_cq *cq, void *buf, size_t count, const void *cond,
                int timeout)
{
	ssize_t ret = 0, cur = 0;
	ssize_t  threshold = 0;
	struct kfi_ibv_cq *_cq = NULL;

	kfi_ref_id(&cq->fid);
	_cq = container_of(cq, struct kfi_ibv_cq, cq_fid);
	if (!_cq->cq) {
		ret = -ENOSYS;
		goto exit;
	}

	threshold = (cond) ? min((size_t)cond, count) : 1;

	for (cur = 0; cur < threshold; ) {
		ret = _cq->cq_fid.ops->read(&_cq->cq_fid, buf, count - cur);
		if (ret > 0) {
			buf += ret*(_cq->entry_size);
			cur += ret;
			if (cur >= threshold) {
				break;
			}
		} else if (ret != -EAGAIN) {
			break;
		}

		_cq->new_entry = false;
		ret = ib_req_notify_cq(_cq->cq, IB_CQ_NEXT_COMP);
		if (ret) {
			LOG_ERR("Request CQ notification error: %d.", (int)ret);
			break;
		}

		/*
		 * Read again to fetch any completions that we might have missed
		 * while rearming
		 */
		ret = _cq->cq_fid.ops->read(&_cq->cq_fid, buf, count - cur);
		if (ret > 0) {
			buf += ret*(_cq->entry_size);
			cur += ret;
			if (cur >= threshold) {
				break;
			}
		} else if (ret != -EAGAIN) {
			break;
		}

		if (timeout > 0) {
			ret = wait_event_interruptible_timeout(_cq->wait,
			                      _cq->new_entry,
			                      msecs_to_jiffies(timeout));
			if (ret == 0) {
				ret = -EAGAIN;
				break;
			}
		} else {
			ret = wait_event_interruptible(_cq->wait, _cq->new_entry);
		}
		if (ret < 0) {
			break;
		}
	}
exit:
	kfi_deref_id(&cq->fid);
	return cur ? cur : ret;
}

static const char *
kfi_ibv_cq_strerror(struct kfid_cq *eq, int prov_errno, const void *err_data,
                char *buf, size_t len)
{
	if (buf && len) {
		strncpy(buf, ib_wc_status_str(prov_errno), len);
	}
	return ib_wc_status_str(prov_errno);
}

static ssize_t
kfi_ibv_cq_read_msg(struct kfid_cq *cq, void *buf, size_t count)
{
	struct kfi_ibv_cq *_cq = NULL;
	struct kfi_cq_msg_entry *entry = buf;
	ssize_t ret = 0, i = 0;

	kfi_ref_id(&cq->fid);
	_cq = container_of(cq, struct kfi_ibv_cq, cq_fid);

	mutex_lock(&_cq->mut);
	if (_cq->wc.status) {
		ret = -EIO;
		goto exit;
	}
	for (i = 0; i < count; i++) {
		ret = ib_poll_cq(_cq->cq, 1, &_cq->wc);
		if (ret <= 0) {
			break;
		}
		if (_cq->wc.status) {
			ret = -EIO;
			break;
		}
		entry->op_context = (void *)_cq->wc.wr_id;
		entry->flags = kfi_ibv_comp_flags(&_cq->wc);
		entry->len = (uint64_t) _cq->wc.byte_len;
		entry += 1;
	}
exit:
	mutex_unlock(&_cq->mut);
	kfi_deref_id(&cq->fid);
	return i ? i : (ret ? ret : -EAGAIN);
}

static ssize_t
kfi_ibv_cq_read_data(struct kfid_cq *cq, void *buf, size_t count)
{
	struct kfi_ibv_cq *_cq = NULL;
	struct kfi_cq_data_entry *entry = buf;
	ssize_t ret = 0, i = 0;

	kfi_ref_id(&cq->fid);
	_cq = container_of(cq, struct kfi_ibv_cq, cq_fid);

	mutex_lock(&_cq->mut);
	if (_cq->wc.status) {
		ret = -EIO;
		goto exit;
	}
	for (i = 0; i < count; i++) {
		ret = ib_poll_cq(_cq->cq, 1, &_cq->wc);
		if (ret <= 0) {
			break;
		}
		if (_cq->wc.status) {
			ret = -EIO;
			break;
		}
		entry->op_context = (void *)_cq->wc.wr_id;
		entry->flags = kfi_ibv_comp_flags(&_cq->wc);
		if (_cq->wc.wc_flags & IB_WC_WITH_IMM) {
			entry->data = _cq->wc.ex.imm_data;
		} else {
			entry->data = 0;
		}
		if (_cq->wc.opcode & (IB_WC_RECV | IB_WC_RECV_RDMA_WITH_IMM)) {
			entry->len = _cq->wc.byte_len;
		} else {
			entry->len = 0;
		}
		entry += 1;
	}
exit:
	mutex_unlock(&_cq->mut);
	kfi_deref_id(&cq->fid);
	return i ? i : (ret ? ret : -EAGAIN);
}

static int
kfi_ibv_pep_close(kfid_t fid)
{
	struct kfi_ibv_pep *pep = NULL;
	struct kfi_ibv_fabric *fab = NULL;
	int ret = 0;

	pep = container_of(fid, struct kfi_ibv_pep, pep_fid.fid);
	fab = pep->fab;
	if (pep->eq) {
		ret = kfi_ibv_pep_unbind(fid, &pep->eq->eq_fid.fid);
	}

	mutex_lock(&pep->mut);
	if (pep->id) {
		rdma_destroy_id(pep->id);
		pep->id = NULL;
	}
	mutex_unlock(&pep->mut);

	kfi_close_id(fid);
	kfree(pep);
	kfi_deref_id(&fab->fabric_fid.fid);
	return ret;
}

static int
kfi_ibv_pep_bind(kfid_t fid, struct kfid *bfid, uint64_t flags)
{
	struct kfi_ibv_pep *pep = NULL;
	struct kfi_ibv_eq *eq = NULL;
	int ret = 0;

	kfi_ref_id(fid);
	kfi_ref_id(bfid);
	pep = container_of(fid, struct kfi_ibv_pep, pep_fid.fid);
	eq = container_of(bfid, struct kfi_ibv_eq, eq_fid.fid);

	mutex_lock(&pep->mut);
	if (bfid->fclass != KFI_CLASS_EQ) {
		ret = -EINVAL;
		goto exit;
	}
	if (!pep->id || pep->eq || eq->ep_fid) {
		ret = -EINVAL;
		goto exit;
	}
	kfi_ref_id(fid);
	eq->ep_fid = fid;
	kfi_ref_id(bfid);
	pep->eq = eq;
exit:
	mutex_unlock(&pep->mut);
	kfi_deref_id(fid);
	kfi_deref_id(bfid);
	return ret;
}

static int
kfi_ibv_pep_getname(kfid_t fid, void *addr, size_t *addrlen)
{
	struct kfi_ibv_pep *_pep = NULL;
	struct sockaddr *sa = NULL;
	int ret = 0;

	kfi_ref_id(fid);
	_pep = container_of(fid, struct kfi_ibv_pep, pep_fid.fid);
	mutex_lock(&_pep->mut);
	sa = (struct sockaddr *)&_pep->id->route.addr.src_addr;
	ret = kfi_ibv_copy_addr(addr, addrlen, sa);
	mutex_unlock(&_pep->mut);
	kfi_deref_id(fid);
	return ret;
}

static int
kfi_ibv_pep_listen(struct kfid_pep *pep)
{
	struct kfi_ibv_pep *_pep = NULL;
	int ret = 0;

	kfi_ref_id(&pep->fid);
	_pep = container_of(pep, struct kfi_ibv_pep, pep_fid);

	mutex_lock(&_pep->mut);
	ret = rdma_listen(_pep->id, 0);
	mutex_unlock(&_pep->mut);
	kfi_deref_id(&pep->fid);
	return ret;
}

static int
kfi_ibv_pep_reject(struct kfid_pep *pep, kfid_t handle,
                const void *param, size_t paramlen)
{
	struct kfi_ibv_connreq *connreq = NULL;
	struct kfi_ibv_ep *ep = NULL;
	int ret = 0;

	kfi_ref_id(&pep->fid);
	connreq = container_of(handle, struct kfi_ibv_connreq, handle);
	ret = rdma_reject(connreq->id, param, (uint8_t) paramlen);
	/*
	 * Clean up if connection request is already associated with
	 * an endpoint.
	 */
	if (connreq->ep) {
		ep = connreq->ep;
		mutex_lock(&ep->mut);
		ep->id = NULL;
		ep->handle = NULL;
		kfi_deref_id(handle);
		connreq->ep = NULL;
		kfi_deref_id(&ep->ep_fid.fid);
		mutex_unlock(&ep->mut);
	}
	rdma_destroy_id(connreq->id);
	connreq->id = NULL;
	kfi_close_id(handle);
	kfree(connreq);
	kfi_deref_id(&pep->fid);
	return ret;
}

static int
kfi_ibv_ep_close(kfid_t fid)
{
	struct kfi_ibv_ep *ep = NULL;
	struct kfi_ibv_domain *domain = NULL;
	struct kfi_ibv_connreq *connreq = NULL;
	int ret = 0;

	ep = container_of(fid, struct kfi_ibv_ep, ep_fid.fid);
	domain = ep->domain;

	if (ep->eq) {
		ret = kfi_ibv_ep_unbind(fid, &ep->eq->eq_fid.fid, 0);
	}
	if (ep->scq) {
		ret = kfi_ibv_ep_unbind(fid, &ep->scq->cq_fid.fid, KFI_SEND);
	}
	if (ep->rcq) {
		ret = kfi_ibv_ep_unbind(fid, &ep->rcq->cq_fid.fid, KFI_RECV);
	}

	mutex_lock(&ep->mut);
	if (ep->handle) {
		connreq = container_of(ep->handle, struct kfi_ibv_connreq, handle);
		connreq->ep = NULL;
		connreq->id = NULL;
		kfi_deref_id(fid);
		ep->handle = NULL;
		kfi_deref_id(&connreq->handle);
		kfi_close_id(&connreq->handle);
		kfree(connreq);
	}
	if (ep->id) {
		rdma_destroy_id(ep->id);
		ep->id = NULL;
	}
	mutex_unlock(&ep->mut);

	kfi_close_id(fid);
	if (ep->tx_attr) {
		kfree(ep->tx_attr);
	}
	if (ep->rx_attr) {
		kfree(ep->rx_attr);
	}
	kfree(ep);
	kfi_deref_id(&domain->domain_fid.fid);
	return ret;
}

static int
kfi_ibv_ep_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags)
{
	struct kfi_ibv_ep *ep = NULL;
	struct kfi_ibv_eq *eq = NULL;
	struct kfi_ibv_cq *cq = NULL;
	int ret = 0;

	kfi_ref_id(fid);
	kfi_ref_id(bfid);
	ep = container_of(fid, struct kfi_ibv_ep, ep_fid.fid);

	mutex_lock(&ep->mut);
	switch (bfid->fclass) {
	case KFI_CLASS_CQ:
		cq = container_of(bfid, struct kfi_ibv_cq, cq_fid.fid);
		/* Must bind a CQ to either RECV or SEND completion. */
		if (!(flags & (KFI_RECV | KFI_SEND))) {
			ret = -EINVAL;
			goto exit;
		}
		if (flags & KFI_RECV) {
			if (ep->rcq) {
				ret = -EINVAL;
				goto exit;
			}
			kfi_ref_id(bfid);
			ep->rcq = cq;
		}
		if (flags & KFI_SEND) {
			if (ep->scq) {
				ret = -EINVAL;
				goto exit;
			}
			kfi_ref_id(bfid);
			ep->scq = cq;
			ep->tx_attr->op_flags |= KFI_COMPLETION;
		}
		break;
	case KFI_CLASS_EQ:
		eq = container_of(bfid, struct kfi_ibv_eq, eq_fid.fid);
		if (ep->eq || eq->ep_fid || !ep->id) {
			ret = -EINVAL;
			goto exit;
		}
		kfi_ref_id(fid);
		eq->ep_fid = fid;
		kfi_ref_id(bfid);
		ep->eq = eq;
		break;
	default:
		ret = -EINVAL;
		goto exit;
	}
exit:
	mutex_unlock(&ep->mut);
	kfi_deref_id(fid);
	kfi_deref_id(bfid);
	return 0;
}

static int
kfi_ibv_ep_control(struct kfid *fid, int command, void *arg)
{
	struct kfi_ibv_ep *ep = NULL;
	struct ib_qp_init_attr attr = {0};
	int ret = 0;

	kfi_ref_id(fid);
	if (fid->fclass != KFI_CLASS_EP) {
		ret = -EINVAL;
		goto exit_nolock;
	}
	ep = container_of(fid, struct kfi_ibv_ep, ep_fid.fid);

	mutex_lock(&ep->mut);
	switch (command) {
	case KFI_ENABLE:
		if (!ep->eq || !ep->scq || !ep->rcq || !ep->id || !ep->domain) {
			ret = -EINVAL;
			goto exit;
		}
		attr.event_handler = kfi_ibv_qp_handler;
		attr.qp_context	= (void *)ep;
		attr.send_cq = ep->scq->cq;
		attr.recv_cq = ep->rcq->cq;
		attr.cap.max_send_wr = ep->tx_attr->size;
		attr.cap.max_recv_wr = ep->rx_attr->size;
		attr.cap.max_send_sge = ep->tx_attr->iov_limit;
		attr.cap.max_recv_sge = ep->rx_attr->iov_limit;
		attr.cap.max_inline_data = ep->tx_attr->inject_size;
		attr.srq = NULL;
		attr.xrcd = NULL;
		attr.sq_sig_type = IB_SIGNAL_REQ_WR;
		attr.qp_type = IB_QPT_RC;
		ret = rdma_create_qp(ep->id, ep->domain->pd, &attr);
		break;
	default:
		ret = -ENOSYS;
		break;
	}
exit:
	mutex_unlock(&ep->mut);
exit_nolock:
	kfi_deref_id(fid);
	return ret;
}

static int
kfi_ibv_ep_getname(kfid_t fid, void *addr, size_t *addrlen)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct sockaddr *sa = NULL;
	int ret = 0;

	kfi_ref_id(fid);
	_ep = container_of(fid, struct kfi_ibv_ep, ep_fid.fid);
	mutex_lock(&_ep->mut);
	sa = (struct sockaddr *)&_ep->id->route.addr.src_addr;
	ret = kfi_ibv_copy_addr(addr, addrlen, sa);
	mutex_unlock(&_ep->mut);
	kfi_deref_id(fid);
	return ret;
}

static int
kfi_ibv_ep_getpeer(struct kfid_ep *ep, void *addr, size_t *addrlen)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct sockaddr *sa = NULL;
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	mutex_lock(&_ep->mut);
	sa = (struct sockaddr *)&_ep->id->route.addr.dst_addr;
	ret = kfi_ibv_copy_addr(addr, addrlen, sa);
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static int
kfi_ibv_ep_connect(struct kfid_ep *ep, const void *addr, const void *param,
                size_t paramlen)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct rdma_conn_param conn_param = {0};
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	if (!_ep->id->qp) {
		ret = ep->fid.ops->control(&ep->fid, KFI_ENABLE, NULL);
		if (ret) {
			goto exit_nolock;
		}
	}

	mutex_lock(&_ep->mut);
	conn_param.private_data = param;
	conn_param.private_data_len = paramlen;
	conn_param.responder_resources = def_max_resp_res;
	conn_param.initiator_depth = def_max_init_depth;
	conn_param.flow_control = 1;
	conn_param.retry_count = 15;
	conn_param.rnr_retry_count = 7;
	ret = rdma_connect(_ep->id, &conn_param);
	mutex_unlock(&_ep->mut);
exit_nolock:
	kfi_deref_id(&ep->fid);
	return ret;
}

static int
kfi_ibv_ep_accept(struct kfid_ep *ep, const void *param, size_t paramlen)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct rdma_conn_param conn_param = {0};
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	if (!_ep->id->qp) {
		ret = ep->fid.ops->control(&ep->fid, KFI_ENABLE, NULL);
		if (ret) {
			goto exit_nolock;
		}
	}

	mutex_lock(&_ep->mut);
	conn_param.private_data = param;
	conn_param.private_data_len = paramlen;
	conn_param.responder_resources = def_max_resp_res;
	conn_param.initiator_depth = def_max_init_depth;
	conn_param.flow_control = 1;
	conn_param.rnr_retry_count = 7;
	ret = rdma_accept(_ep->id, &conn_param);
	mutex_unlock(&_ep->mut);
exit_nolock:
	kfi_deref_id(&ep->fid);
	return ret;
}

static int
kfi_ibv_ep_shutdown(struct kfid_ep *ep, uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	mutex_lock(&_ep->mut);
	ret = rdma_disconnect(_ep->id);
	mutex_unlock(&_ep->mut);
	if (ret) {
		goto exit;
	}
	wait_for_completion_timeout(&_ep->conn.close_comp,
	                msecs_to_jiffies(def_cm_to_ms));
	if (_ep->conn.status != RDMA_CM_EVENT_DISCONNECTED) {
		LOG_INFO("Disconnected stats %d.", _ep->conn.status);
		ret = -EBUSY;
	}
exit:
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, void *context)
{
	struct kvec iov = {0};
	struct kfi_msg msg = {0};

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.context = context;

	return kfi_ibv_ep_recvmsg(ep, &msg, 0);
}

static ssize_t
kfi_ibv_ep_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t src_addr, void *context)
{
	struct kfi_msg msg = {0};

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.context = context;

	return kfi_ibv_ep_recvmsg(ep, &msg, 0);
}

static ssize_t
kfi_ibv_ep_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_recv_wr wr = {0}, *bad = NULL;
	struct ib_sge *sge = NULL;
	ssize_t ret = 0;
	int i = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);
	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge)*(msg->iov_count), GFP_KERNEL);
		if (!sge) {
			ret = -ENOMEM;
			goto exit;
		}
	}
	for (i = 0; i < msg->iov_count; i++) {
		ret = kfi_ibv_fill_sge(msg->msg_iov[i].iov_base,
		                      msg->msg_iov[i].iov_len, msg->desc[i],
		                      &sge[i]);
		if (ret) {
			goto exit;
		}
	}
	wr.sg_list = sge;
	wr.num_sge = msg->iov_count;
	wr.wr_id = (uintptr_t) msg->context;
	wr.next = NULL;
	ret = ib_post_recv(_ep->id->qp, &wr, &bad);
exit:
	if (sge) {
		kfree(sge);
	}
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_send(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                kfi_addr_t dest_addr, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kvec iov = {0};
	struct kfi_msg msg = {0};

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.context = context;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_sendmsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t dest_addr, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg msg = {0};

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.context = context;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_sendmsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_send_wr wr = {0}, *bad = NULL;
	struct ib_sge *sge = NULL;
	ssize_t ret = 0;
	size_t i = 0, len = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);
	wr.send_flags = 0;
	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge)*(msg->iov_count), GFP_KERNEL);
		if (!sge) {
			ret = -ENOMEM;
			goto exit;
		}
	}
	for (len = 0, i = 0; i < msg->iov_count; i++) {
		ret = kfi_ibv_fill_sge(msg->msg_iov[i].iov_base,
		                      msg->msg_iov[i].iov_len, msg->desc[i],
		                      &sge[i]);
		if (ret) {
			goto exit;
		}
		len += sge[i].length;
	}
	if (flags & KFI_INJECT && len <= _ep->tx_attr->inject_size) {
		wr.send_flags |= IB_SEND_INLINE;
	}
	wr.sg_list = sge;
	wr.num_sge = msg->iov_count;

	if (flags & (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)) {
		wr.send_flags |= IB_SEND_SIGNALED;
	}
	wr.wr_id = (uintptr_t) msg->context;
	wr.next = NULL;
	if (flags & KFI_REMOTE_CQ_DATA) {
		wr.opcode = IB_WR_SEND_WITH_IMM;
		wr.ex.imm_data = (uint32_t) msg->data;
	} else {
		wr.opcode = IB_WR_SEND;
	}

	ret = ib_post_send(_ep->id->qp, &wr, &bad);
exit:
	if (sge) {
		kfree(sge);
	}
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_senddata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                uint64_t data, kfi_addr_t dest_addr, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kvec iov = {0};
	struct kfi_msg msg = {0};

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.context = context;
	msg.data = data;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_sendmsg(ep, &msg, KFI_REMOTE_CQ_DATA | _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_rma_read(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_rma msg = {0};
	struct kvec iov = {0};
	struct kfi_rma_iov rma_iov = {0};

	msg.desc = &desc;
	msg.addr = src_addr;
	msg.context = context;
	iov.iov_base = buf;
	iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.msg_iov = &iov;
	msg.iov_count = 1;
	msg.rma_iov = &rma_iov;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_rma_readmsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_rma_readv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t src_addr, uint64_t addr, uint64_t key,
                void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_rma msg = {0};
	struct kfi_rma_iov rma_iov = {0};

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = src_addr;
	msg.context = context;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_rma_readmsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_rma_readmsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
                uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_send_wr wr = {0}, *bad = NULL;
	struct ib_sge *sge = NULL;
	size_t i = 0;
	ssize_t ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);
	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge)*msg->iov_count, GFP_KERNEL);
		if (!sge) {
			ret = -ENOMEM;
			goto exit;
		}
	}
	for (i = 0; i < msg->iov_count; i++) {
		ret = kfi_ibv_fill_sge(msg->msg_iov[i].iov_base,
		                      msg->msg_iov[i].iov_len, msg->desc[i],
		                      &sge[i]);
		if (ret) {
			goto exit;
		}
	}
	wr.sg_list = sge;
	wr.num_sge = msg->iov_count;

	wr.opcode = IB_WR_RDMA_READ;
	wr.wr_id = (uintptr_t) msg->context;
	wr.next = NULL;
	wr.wr.rdma.remote_addr = msg->rma_iov->addr;
	wr.wr.rdma.rkey = (uint32_t) msg->rma_iov->key;
	if (flags & (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)) {
		wr.send_flags |= IB_SEND_SIGNALED;
	}

	ret = ib_post_send(_ep->id->qp, &wr, &bad);
exit:
	if (sge) {
		kfree(sge);
	}
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_rma_write(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_rma msg = {0};
	struct kvec iov = {0};
	struct kfi_rma_iov rma_iov = {0};

	msg.desc = &desc;
	msg.context = context;
	iov.iov_base = (void*)buf;
	iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.msg_iov = &iov;
	msg.iov_count = 1;
	msg.rma_iov = &rma_iov;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_rma_writemsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_rma_writev(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_rma msg = {0};
	struct kfi_rma_iov rma_iov = {0};

	msg.desc = desc;
	msg.context = context;
	msg.msg_iov = iov;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.iov_count = count;
	msg.rma_iov = &rma_iov;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_rma_writemsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_rma_writemsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
                uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_send_wr wr = {0}, *bad = NULL;
	struct ib_sge *sge = NULL;
	size_t i = 0, len = 0;
	ssize_t ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);
	wr.send_flags = 0;
	if (msg->iov_count) {
		sge = kzalloc(sizeof(*sge)*msg->iov_count, GFP_KERNEL);
		if (!sge) {
			ret = -ENOMEM;
			goto exit;
		}
	}
	for (len = 0, i = 0; i < msg->iov_count; i++) {
		ret = kfi_ibv_fill_sge(msg->msg_iov[i].iov_base,
		                      msg->msg_iov[i].iov_len, msg->desc[i],
		                      &sge[i]);
		if (ret) {
			goto exit;
		}
		len += sge[i].length;
	}
	if (flags & KFI_INJECT && len <= _ep->tx_attr->inject_size) {
		wr.send_flags |= IB_SEND_INLINE;
	}
	wr.sg_list = sge;
	wr.num_sge = msg->iov_count;

	wr.wr_id = (uintptr_t)msg->context;
	wr.next = NULL;
	wr.opcode = IB_WR_RDMA_WRITE;
	if (flags & (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)) {
		wr.send_flags |= IB_SEND_SIGNALED;
	}
	if (flags & KFI_REMOTE_CQ_DATA) {
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data = (uint32_t) msg->data;
	}
	wr.wr.rdma.remote_addr = msg->rma_iov->addr;
	wr.wr.rdma.rkey = (uint32_t) msg->rma_iov->key;

	ret = ib_post_send(_ep->id->qp, &wr, &bad);
exit:
	if (sge) {
		kfree(sge);
	}
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_rma_writedata(struct kfid_ep *ep, const void *buf, size_t len,
                void *desc, uint64_t data, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_rma msg = {0};
	struct kvec iov = {0};
	struct kfi_rma_iov rma_iov = {0};

	msg.desc = &desc;
	msg.context = context;
	iov.iov_base = (void*)buf;
	iov.iov_len = len;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.msg_iov = &iov;
	msg.iov_count = 1;
	msg.rma_iov = &rma_iov;
	msg.data = data;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_rma_writemsg(ep, &msg,
	                       KFI_REMOTE_CQ_DATA | _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_atomic_write(struct kfid_ep *ep, const void *buf, size_t count,
                void *desc, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_atomic msg = {0};
	struct kfi_ioc msg_iov = {0};
	struct kfi_rma_ioc rma_iov = {0};

	if (count != 1) {
		return -E2BIG;
	}

	msg_iov.count = 1;
	msg_iov.addr = (void *)buf;
	msg.desc = &desc;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;

	rma_iov.count = 1;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;

	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_atomic_writemsg(ep, &msg, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_atomic_writev(struct kfid_ep *ep, const struct kfi_ioc *iov,
                void **desc, size_t count, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context)
{
	if (iov->count != 1) {
		return -E2BIG;
	}

	return kfi_ibv_ep_atomic_write(ep, iov->addr, count, desc[0], dest_addr,
	                        addr, key, datatype, op, context);
}

static ssize_t
kfi_ibv_ep_atomic_writemsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_send_wr wr = {0}, *bad = NULL;
	struct ib_sge sge = {0};
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);

	if (msg->iov_count != 1 || msg->rma_iov_count != 1
	    || msg->msg_iov->count != 1 || msg->rma_iov->count != 1) {
		ret = -E2BIG;
		goto exit;
	}
	if (msg->op != KFI_ATOMIC_WRITE) {
		ret = -ENOSYS;
		goto exit;
	}

	switch (msg->datatype) {
	case KFI_INT64:
	case KFI_UINT64:
#if __BITS_PER_LONG == 64
	case KFI_DOUBLE:
	case KFI_FLOAT:
#endif
		break;
	default:
		ret = -EINVAL;
		goto exit;
	}

	if (flags & KFI_REMOTE_CQ_DATA) {
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data = (uint32_t) msg->data;
	} else {
		wr.opcode = IB_WR_RDMA_WRITE;
	}
	wr.wr.rdma.remote_addr = msg->rma_iov->addr;
	wr.wr.rdma.rkey = (uint32_t)(uintptr_t)msg->rma_iov->key;

	ret = kfi_ibv_fill_sge(msg->msg_iov->addr, sizeof(uint64_t), msg->desc[0], &sge);
	if (ret) {
		goto exit;
	}
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_FENCE;
	if (flags & KFI_INJECT && sizeof(uint64_t) <= _ep->tx_attr->inject_size) {
		wr.send_flags |= IB_SEND_INLINE;
	}
	if (flags & (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)) {
		wr.send_flags |= IB_SEND_SIGNALED;
	}
	wr.wr_id = (uintptr_t)msg->context;
	wr.next = NULL;

	ret = ib_post_send(_ep->id->qp, &wr, &bad);
exit:
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_atomic_readwrite(struct kfid_ep *ep, const void *buf, size_t count,
                void *desc, void *result, void *result_desc, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
                enum kfi_op op, void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_atomic msg = {0};
	struct kfi_rma_ioc rma_iov = {0};
	struct kfi_ioc msg_iov = {0};
	struct kfi_ioc resultv = {0};

	if (count != 1)
		return -E2BIG;

	msg_iov.addr = (void *)buf;
	msg_iov.count = 1;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.count = 1;
	rma_iov.addr = addr;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;

	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	resultv.addr = result;
	resultv.count = 1;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_atomic_readwritemsg(ep, &msg, &resultv, &result_desc,
	                       1, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_atomic_readwritev(struct kfid_ep *ep, const struct kfi_ioc *iov,
                void **desc, size_t count, struct kfi_ioc *resultv,
                void **result_desc, size_t result_count, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
                enum kfi_op op, void *context)
{
	if (iov->count != 1)
		return -E2BIG;

	return kfi_ibv_ep_atomic_readwrite(ep, iov->addr, count, desc[0],
	                       resultv->addr, result_desc[0], dest_addr, addr, key, datatype, op, context);
}

static ssize_t
kfi_ibv_ep_atomic_readwritemsg(struct kfid_ep *ep,
                const struct kfi_msg_atomic *msg, struct kfi_ioc *resultv,
                void **result_desc, size_t result_count, uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_send_wr wr = {0}, *bad = NULL;
	struct ib_sge sge = {0};
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);

	if (msg->iov_count != 1 || msg->rma_iov_count != 1
	    || msg->msg_iov->count != 1 || msg->rma_iov->count != 1) {
		ret = -E2BIG;
		goto exit;
	}

	switch (msg->datatype) {
	case KFI_INT64:
	case KFI_UINT64:
#if __BITS_PER_LONG == 64
	case KFI_DOUBLE:
	case KFI_FLOAT:
#endif
		break;
	default:
		ret = -EINVAL;
		goto exit;
	}

	switch (msg->op) {
	case KFI_ATOMIC_READ:
		wr.opcode = IB_WR_RDMA_READ;
		wr.wr.rdma.remote_addr = msg->rma_iov->addr;
		wr.wr.rdma.rkey = (uint32_t)(uintptr_t)msg->rma_iov->key;
		break;
	case KFI_SUM:
		wr.opcode = IB_WR_ATOMIC_FETCH_AND_ADD;
		wr.wr.atomic.remote_addr = msg->rma_iov->addr;
		wr.wr.atomic.rkey = (uint32_t)(uintptr_t)msg->rma_iov->key;
		wr.wr.atomic.compare_add = *(uint64_t *)msg->msg_iov->addr;
		wr.wr.atomic.swap = 0;
		break;
	default:
		return -ENOSYS;
	}

	ret = kfi_ibv_fill_sge(resultv->addr, sizeof(uint64_t), result_desc[0], &sge);
	if (ret) {
		goto exit;
	}
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr_id = (uintptr_t)msg->context;
	wr.next = NULL;
	wr.send_flags = IB_SEND_FENCE;
	if (flags & KFI_INJECT && sizeof(uint64_t) <= _ep->tx_attr->inject_size) {
		wr.send_flags |= IB_SEND_INLINE;
	}
	if (flags & (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)) {
		wr.send_flags |= IB_SEND_SIGNALED;
	}
	if (flags & KFI_REMOTE_CQ_DATA) {
		wr.ex.imm_data = (uint32_t) msg->data;
	}

	ret = ib_post_send(_ep->id->qp, &wr, &bad);
exit:
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static ssize_t
kfi_ibv_ep_atomic_compwrite(struct kfid_ep *ep, const void *buf, size_t count,
                void *desc, const void *compare, void *compare_desc, void *result,
                void *result_desc, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct kfi_msg_atomic msg = {0};
	struct kfi_ioc msg_iov = {0};
	struct kfi_rma_ioc rma_iov = {0};
	struct kfi_ioc resultv = {0};
	struct kfi_ioc comparev = {0};

	if (count != 1)
		return -E2BIG;

	msg_iov.addr = (void *)buf;
	msg_iov.count = 1;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.count = 1;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;

	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	resultv.addr = result;
	resultv.count = 1;

	comparev.addr = (void*)compare;
	comparev.count = 1;

	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);
	return kfi_ibv_ep_atomic_compwritemsg(ep, &msg, &comparev, &compare_desc,
	                       1, &resultv, &result_desc, 1, _ep->tx_attr->op_flags);
}

static ssize_t
kfi_ibv_ep_atomic_compwritev(struct kfid_ep *ep, const struct kfi_ioc *iov,
                void **desc, size_t count, const struct kfi_ioc *comparev,
                void **compare_desc, size_t compare_count,
                struct kfi_ioc *resultv, void **result_desc, size_t result_count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	if (iov->count != 1) {
		return -E2BIG;
	}

	return kfi_ibv_ep_atomic_compwrite(ep, iov->addr, count, desc[0],
	                       comparev->addr, compare_desc[0], resultv->addr,
	                       result_desc[0], dest_addr, addr, key, datatype,
	                       op, context);
}

static ssize_t
kfi_ibv_ep_atomic_compwritemsg(struct kfid_ep *ep,
                const struct kfi_msg_atomic *msg, const struct kfi_ioc *comparev,
                void **compare_desc, size_t compare_count,
                struct kfi_ioc *resultv, void **result_desc, size_t result_count,
                uint64_t flags)
{
	struct kfi_ibv_ep *_ep = NULL;
	struct ib_send_wr wr = {0}, *bad = NULL;
	struct ib_sge sge = {0};
	int ret = 0;

	kfi_ref_id(&ep->fid);
	_ep = container_of(ep, struct kfi_ibv_ep, ep_fid);

	mutex_lock(&_ep->mut);

	if (msg->op != KFI_CSWAP) {
		ret = -ENOSYS;
		goto exit;
	}
	if (msg->iov_count != 1 || msg->rma_iov_count != 1
	    || msg->msg_iov->count != 1 || msg->rma_iov->count != 1) {
		ret = -E2BIG;
		goto exit;
	}

	switch(msg->datatype) {
	case KFI_INT64:
	case KFI_UINT64:
#if __BITS_PER_LONG == 64
	case KFI_DOUBLE:
	case KFI_FLOAT:
#endif
		break;
	default:
		ret = -EINVAL;
		goto exit;
	}

	wr.send_flags = IB_SEND_FENCE;
	wr.opcode = IB_WR_ATOMIC_CMP_AND_SWP;
	wr.wr_id = (uintptr_t) msg->context;
	wr.next = NULL;

	wr.wr.atomic.remote_addr = msg->rma_iov->addr;
	//wr.wr.atomic.compare_add = (uintptr_t)comparev->addr;
	wr.wr.atomic.compare_add = *(uint64_t *)comparev->addr;
	wr.wr.atomic.swap = *(uint64_t *)msg->msg_iov->addr;
	//wr.wr.atomic.swap = (uintptr_t)msg->addr;
	wr.wr.atomic.rkey = (uint32_t)(uintptr_t)msg->rma_iov->key;
	ret = kfi_ibv_fill_sge(resultv->addr, sizeof(uint64_t), result_desc[0], &sge);
	if (ret) {
		goto exit;
	}
	if (flags & KFI_INJECT && sizeof(uint64_t) <= _ep->tx_attr->inject_size) {
		wr.send_flags |= IB_SEND_INLINE;
	}
	wr.sg_list = &sge;
	wr.num_sge = 1;
	if (flags & (KFI_COMPLETION | KFI_TRANSMIT_COMPLETE)) {
		wr.send_flags |= IB_SEND_SIGNALED;
	}
	if (flags & KFI_REMOTE_CQ_DATA) {
		wr.ex.imm_data = (uint32_t) msg->data;
	}

	ret = ib_post_send(_ep->id->qp, &wr, &bad);
exit:
	mutex_unlock(&_ep->mut);
	kfi_deref_id(&ep->fid);
	return ret;
}

static int
kfi_ibv_ep_atomic_writevalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	switch (op) {
	case KFI_ATOMIC_WRITE:
		break;
	default:
		return -ENOSYS;
	}

	switch (datatype) {
	case KFI_INT64:
	case KFI_UINT64:
#if __BITS_PER_LONG == 64
	case KFI_DOUBLE:
	case KFI_FLOAT:
#endif
		break;
	default:
		return -EINVAL;
	}

	if (count)
		*count = 1;
	return 0;
}

static int
kfi_ibv_ep_atomic_readwritevalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	switch (op) {
	case KFI_ATOMIC_READ:
	case KFI_SUM:
		break;
	default:
		return -ENOSYS;
	}

	switch (datatype) {
	case KFI_INT64:
	case KFI_UINT64:
#if __BITS_PER_LONG == 64
	case KFI_DOUBLE:
	case KFI_FLOAT:
#endif
		break;
	default:
		return -EINVAL;
	}

	if (count)
		*count = 1;
	return 0;
}

static int
kfi_ibv_ep_atomic_compwritevalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	if (op != KFI_CSWAP)
		return -ENOSYS;

	switch (datatype) {
	case KFI_INT64:
	case KFI_UINT64:
#if __BITS_PER_LONG == 64
	case KFI_DOUBLE:
	case KFI_FLOAT:
#endif
		break;
	default:
		return -EINVAL;
	}

	if (count)
		*count = 1;
	return 0;
}

static int
kfi_ibv_cma_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	struct kfi_ibv_event *_event = NULL;
	struct kfi_ibv_eq *eq = NULL;
	struct kfid *fid = NULL;
	struct mutex *ep_mut = NULL;
	struct kfi_ibv_pep *pep = NULL;
	struct kfi_ibv_ep *ep = NULL;

	fid = (struct kfid*)cma_id->context;
	if (!fid) {
		return 0;
	}
	kfi_ref_id(fid);
	if (fid->fclass == KFI_CLASS_PEP) {
		pep = container_of(fid, struct kfi_ibv_pep, pep_fid.fid);
		ep_mut = &pep->mut;
		mutex_lock(ep_mut);
		eq = pep->eq;
	} else if (fid->fclass == KFI_CLASS_EP) {
		ep = container_of(fid, struct kfi_ibv_ep, ep_fid.fid);
		ep_mut = &ep->mut;
		mutex_lock(ep_mut);
		eq = ep->eq;
		switch (event->event) {
		case RDMA_CM_EVENT_ADDR_RESOLVED:
		case RDMA_CM_EVENT_ADDR_ERROR:
			complete(&ep->conn.addr_comp);
			ep->conn.status = event->event;
			goto exit;
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
		case RDMA_CM_EVENT_ROUTE_ERROR:
			complete(&ep->conn.route_comp);
			ep->conn.status = event->event;
			goto exit;
		case RDMA_CM_EVENT_DISCONNECTED:
			complete(&ep->conn.close_comp);
			ep->conn.status = event->event;
			/* Still report KFI_SHUTDOWN in the event queue */
			break;
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			/* Unblock the waiting threads */
			complete(&ep->conn.addr_comp);
			complete(&ep->conn.route_comp);
			complete(&ep->conn.close_comp);
			ep->conn.status = event->event;
			break;
		default:
			break;
		}
	} else {
		return 0;
	}

	if (!eq) {
		goto exit;
	}

	_event = kzalloc(sizeof(*_event), GFP_KERNEL);
	if (!_event) {
		goto exit;
	}
	INIT_LIST_HEAD(&_event->list);
	_event->id = cma_id;
	_event->event = *event;
	if (event->param.conn.private_data_len) {
		_event->event.param.conn.private_data =
		        kmemdup(event->param.conn.private_data,
		                        event->param.conn.private_data_len,
		                        GFP_KERNEL);
		if (!_event->event.param.conn.private_data) {
			kfree(_event);
			goto exit;
		}
	}

	mutex_lock(&eq->mut);
	list_add_tail(&_event->list, &eq->event_list);
	mutex_unlock(&eq->mut);
	wake_up_interruptible(&eq->poll_wait);
exit:
	mutex_unlock(ep_mut);
	kfi_deref_id(fid);
	return 0;
}

static void
kfi_ibv_qp_handler(struct ib_event *event, void *context)
{
	return;
}

static void
kfi_ibv_cq_comp_handler(struct ib_cq *cq, void *context)
{
	struct kfi_ibv_cq *_cq = NULL;

	_cq = (struct kfi_ibv_cq*)context;
	_cq->new_entry = true;
	wake_up_interruptible(&_cq->wait);

	return;
}

static void
kfi_ibv_cq_event_handler(struct ib_event *event, void *context)
{
	return;
}

static int
kfi_ibv_get_info_dev(struct ib_device *device, struct kfi_info **info)
{
	int ret = 0;
	struct kfi_info *fi = NULL;
	union ib_gid gid;
	size_t name_len = 0;

	fi = kfi_allocinfo();
	if (!fi) {
		ret = -ENOMEM;
		goto err;
	}

	fi->caps                = VERBS_CAPS;
	fi->mode                = VERBS_MODE;
	*(fi->tx_attr)          = verbs_tx_attr;
	*(fi->rx_attr)          = verbs_rx_attr;
	*(fi->ep_attr)          = verbs_ep_attr;
	*(fi->domain_attr)      = verbs_domain_attr;
	fi->fabric_attr->prov_version = ibv_prov.version;
	fi->fabric_attr->prov_name = kstrdup(ibv_prov.name, GFP_KERNEL);
	if (!fi->fabric_attr->prov_name) {
		ret = -ENOMEM;
		goto err;
	}
	fi->domain_attr->name = kstrdup(device->name, GFP_KERNEL);
	if (!(fi->domain_attr->name)) {
		ret = -ENOMEM;
		goto err;
	}

	ret = kfi_ibv_get_device_attrs(device, fi);
	if (ret) {
		goto err;
	}

	switch (rdma_node_get_transport(device->node_type)) {
	case RDMA_TRANSPORT_IB:
		if (ib_query_gid(device, 1, 0, &gid)) {
			ret = -EBUSY;
			goto err;
		}
		name_len = strlen(VERBS_IB_PREFIX) + INET6_ADDRSTRLEN;
		fi->fabric_attr->name = kzalloc(name_len + 1, GFP_KERNEL);
		if (!fi->fabric_attr->name) {
			ret = -ENOMEM;
			goto err;
		}
		snprintf(fi->fabric_attr->name, name_len, VERBS_IB_PREFIX "%lx",
		                (long unsigned)(gid.global.subnet_prefix));
		fi->ep_attr->protocol = KFI_PROTO_RDMA_CM_IB_RC;
		break;
	case RDMA_TRANSPORT_IWARP:
		fi->fabric_attr->name = kstrdup(VERBS_IWARP_FABRIC, GFP_KERNEL);
		if (!fi->fabric_attr->name) {
			ret = -ENOMEM;
			goto err;
		}
		fi->ep_attr->protocol = KFI_PROTO_IWARP;
		fi->tx_attr->op_flags = VERBS_TX_OP_FLAGS_IWARP;
		break;
	default:
		LOG_ERR("Unknown trasport type.");
		ret = -ENODATA;
		goto err;
	}

	*info = fi;
	return 0;
err:
	kfi_deallocinfo(fi);
	return ret;
}

static struct kfi_ibv_device *
kfi_ibv_find_dev(const char *fabric_name, const char *domain_name)
{
	struct list_head *lh = NULL;
	struct kfi_ibv_device *dev = NULL;

	list_for_each(lh, &ibv_dev_list) {
		dev = list_entry(lh, typeof(*dev), list);
		if ((!domain_name || !strcmp(dev->info->domain_attr->name, domain_name))
		   && (!fabric_name || !strcmp(dev->info->fabric_attr->name, fabric_name))) {
			return dev;
		}
	}
	return NULL;
}

static struct kfi_info *
kfi_ibv_find_info(const char *fabric_name, const char *domain_name)
{
	struct kfi_ibv_device *dev = NULL;

	dev = kfi_ibv_find_dev(fabric_name, domain_name);
	if (dev) {
		return dev->info;
	} else {
		return NULL;
	}
}

static struct kfi_info *
kfi_ibv_eq_cm_getinfo(struct kfi_ibv_event *event)
{
	struct kfi_info *info = NULL, *fi = NULL;
	struct kfi_ibv_connreq *connreq = NULL;
	struct sockaddr *addr = NULL;

	fi = kfi_ibv_find_info(NULL, event->id->device->name);
	if (!fi) {
		return NULL;
	}
	info = kfi_dupinfo(fi);
	if (!info) {
		return NULL;
	}
	kfi_ibv_update_info(NULL, info);

	addr = (struct sockaddr *)&event->id->route.addr.src_addr;
	info->src_addrlen = kfi_ibv_sockaddr_len(addr);
	info->src_addr = kmemdup(addr, info->src_addrlen, GFP_KERNEL);
	if (!info->src_addr) {
		goto err;
	}
	addr = (struct sockaddr *)&event->id->route.addr.dst_addr;
	info->dest_addrlen = kfi_ibv_sockaddr_len(addr);
	info->dest_addr = kmemdup(addr, info->dest_addrlen, GFP_KERNEL);
	if (!info->dest_addr) {
		goto err;
	}

	connreq = kzalloc(sizeof(*connreq), GFP_KERNEL);
	if (!connreq) {
		goto err;
	}
	kfi_init_id(&connreq->handle);
	connreq->id = event->id;
	connreq->handle.fclass = KFI_CLASS_CONNREQ;
	info->handle = &connreq->handle;
	return info;

err:
	if (connreq) {
		kfree(connreq);
	}
	kfi_deallocinfo(info);
	return NULL;
}

static int
kfi_ibv_get_device_attrs(struct ib_device *device, struct kfi_info *info)
{
	struct ib_device_attr device_attr = {0};
	struct ib_port_attr port_attr = {0};
	int ret = 0;

	ret = ib_query_device(device, &device_attr);
	if (ret) {
		return ret;
	}
	info->domain_attr->cq_cnt         = device_attr.max_cq;
	info->domain_attr->ep_cnt         = device_attr.max_qp;
	info->domain_attr->tx_ctx_cnt     = min(info->domain_attr->tx_ctx_cnt,
	                                        (size_t)device_attr.max_qp);
	info->domain_attr->rx_ctx_cnt     = min(info->domain_attr->rx_ctx_cnt,
	                                        (size_t)device_attr.max_qp);
	info->domain_attr->max_ep_tx_ctx  = device_attr.max_qp;
	info->domain_attr->max_ep_rx_ctx  = device_attr.max_qp;

	ret = kfi_ibv_get_qp_cap(device, &device_attr, info);
	if (ret) {
		return ret;
	}

	ret = ib_query_port(device, 1, &port_attr);
	if (ret) {
		return ret;
	}
	info->ep_attr->max_msg_size       = port_attr.max_msg_sz;
	info->ep_attr->max_order_raw_size = port_attr.max_msg_sz;
	info->ep_attr->max_order_waw_size = port_attr.max_msg_sz;

	return ret;
}

static int
kfi_ibv_get_qp_cap(struct ib_device *device, struct ib_device_attr *device_attr,
                struct kfi_info *info)
{
	struct ib_pd *pd = NULL;
	struct ib_cq *cq = NULL;
	struct ib_qp *qp = NULL;
	struct ib_qp_init_attr init_attr = {0};
	int ret = 0;

	pd = ib_alloc_pd(device);
	if (!pd) {
		ret = -EBUSY;
		goto exit;
	}
	cq = ib_create_cq(device, NULL, NULL, NULL, 1, 0);
	if (!cq) {
		ret = -EBUSY;
		goto exit_pd;
	}

	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	init_attr.cap.max_send_wr = def_tx_ctx_size;
	init_attr.cap.max_recv_wr = def_rx_ctx_size;
	init_attr.cap.max_inline_data = def_inject_size;
	init_attr.cap.max_send_sge = def_tx_iov_limit;
	init_attr.cap.max_recv_sge = def_rx_iov_limit;
	if (device_attr->max_sge < init_attr.cap.max_send_sge) {
		init_attr.cap.max_send_sge = device_attr->max_sge;
	}
	if (device_attr->max_sge < init_attr.cap.max_recv_sge) {
		init_attr.cap.max_recv_sge = device_attr->max_sge;
	}
	init_attr.qp_type = IB_QPT_RC;

	qp = ib_create_qp(pd, &init_attr);
	if (!qp) {
		ret = -EBUSY;
		goto exit_cq;
	}
	info->tx_attr->inject_size = init_attr.cap.max_inline_data;
	info->tx_attr->iov_limit   = init_attr.cap.max_send_sge;
	info->tx_attr->size        = init_attr.cap.max_send_wr;
	info->rx_attr->iov_limit   = init_attr.cap.max_recv_sge;
	info->rx_attr->size        = init_attr.cap.max_recv_wr;

	ib_destroy_qp(qp);
exit_cq:
	ib_destroy_cq(cq);
exit_pd:
	ib_dealloc_pd(pd);
exit:
	return ret;
}

static int
kfi_ibv_create_id(const struct kfi_info *hints, struct rdma_cm_id **id,
                bool passive_ep)
{
	struct rdma_cm_id *_id = NULL;
	struct kfi_ibv_pep *_pep = NULL;
	struct kfi_ibv_ep *_ep = NULL;
	int ret = 0;

	if (passive_ep) {
		_pep = container_of(id, struct kfi_ibv_pep, id);
		_id = rdma_create_id(kfi_ibv_cma_handler, &_pep->pep_fid.fid,
		                RDMA_PS_TCP, IB_QPT_RC);
	} else {
		_ep = container_of(id, struct kfi_ibv_ep, id);
		_id = rdma_create_id(kfi_ibv_cma_handler, &_ep->ep_fid.fid,
		                RDMA_PS_TCP, IB_QPT_RC);
	}
	if (IS_ERR(_id)) {
		ret = PTR_ERR(_id);
		LOG_ERR("Failed to create cm_id.");
		goto err;
	}

	if (passive_ep) {
		ret = rdma_bind_addr(_id, (struct sockaddr *)hints->src_addr);
		if (ret) {
			LOG_ERR("Failed to bind addr.");
			goto err_id;
		}
	} else {
		ret = rdma_resolve_addr(_id, (struct sockaddr *)hints->src_addr,
			(struct sockaddr *)hints->dest_addr, (int)def_cm_to_ms);
		if (ret) {
			LOG_ERR("Failed to init addr resolve.");
			goto err_id;
		}
		wait_for_completion_timeout(&_ep->conn.addr_comp,
		                msecs_to_jiffies(def_cm_to_ms));
		if (_ep->conn.status != RDMA_CM_EVENT_ADDR_RESOLVED) {
			LOG_ERR("Failed to resolve addr.");
			ret = -ENODATA;
			goto err_id;
		}
		ret = rdma_resolve_route(_id, (int)def_cm_to_ms);
		if (ret) {
			LOG_ERR("Failed to init route resolve.");
			goto err_id;
		}
		wait_for_completion_timeout(&_ep->conn.route_comp,
		                msecs_to_jiffies(def_cm_to_ms));
		if (_ep->conn.status != RDMA_CM_EVENT_ROUTE_RESOLVED) {
			LOG_ERR("Failed to resolve route.");
			ret = -ENODATA;
			goto err_id;
		}
	}
	*id = _id;
	return ret;

err_id:
	rdma_destroy_id(_id);
err:
	*id = NULL;
	return ret;
}

static int
kfi_ibv_check_hints(const struct kfi_info *hints, const struct kfi_info *info)
{
	int ret = 0;

	if (hints->caps & ~(info->caps)) {
		LOG_ERR("Invalid hints - unsupported capabilities.");
		return -ENODATA;
	}
	if ((hints->mode | info->mode) != info->mode) {
		LOG_ERR("Invalid hints - unsupported mode.");
		return -ENODATA;
	}
	if (hints->fabric_attr) {
		ret = kfi_ibv_check_fabric_attr(hints->fabric_attr, info);
		if (ret)
			return ret;
	}
	if (hints->domain_attr) {
		ret = kfi_ibv_check_domain_attr(hints->domain_attr, info);
		if (ret)
			return ret;
	}
	if (hints->ep_attr) {
		ret = kfi_ibv_check_ep_attr(hints->ep_attr, info);
		if (ret)
			return ret;
	}
	if (hints->rx_attr) {
		ret = kfi_ibv_check_rx_attr(hints->rx_attr, hints, info);
		if (ret)
			return ret;
	}
	if (hints->tx_attr) {
		ret = kfi_ibv_check_tx_attr(hints->tx_attr, hints, info);
		if (ret)
			return ret;
	}
	return 0;
}

static int
kfi_ibv_check_fabric_attr(const struct kfi_fabric_attr *attr,
                const struct kfi_info *info)
{
	if (attr->name && strcmp(attr->name, info->fabric_attr->name)) {
		LOG_ERR("Invalid hints - unknown fabric name.");
		return -ENODATA;
	}
	if (attr->prov_version > info->fabric_attr->prov_version) {
		LOG_ERR("Invalid hints - unsupported provider version.");
		return -ENODATA;
	}
	return 0;
}

static int
kfi_ibv_check_domain_attr(const struct kfi_domain_attr *attr,
                const struct kfi_info *info)
{
	if (attr->name && strcmp(attr->name, info->domain_attr->name)) {
		LOG_ERR("Invalid hints - unknown domain name.");
		return -ENODATA;
	}

	switch (attr->threading) {
	case KFI_THREAD_UNSPEC:
	case KFI_THREAD_SAFE:
	case KFI_THREAD_FID:
	case KFI_THREAD_DOMAIN:
	case KFI_THREAD_COMPLETION:
		break;
	default:
		LOG_ERR("Invalid hints - invalid threading mode.");
		return -ENODATA;
	}

	switch (attr->control_progress) {
	case KFI_PROGRESS_UNSPEC:
	case KFI_PROGRESS_AUTO:
	case KFI_PROGRESS_MANUAL:
		break;
	default:
		LOG_ERR("Invalid hints - invalid control progress mode.");
		return -ENODATA;
	}

	switch (attr->data_progress) {
	case KFI_PROGRESS_UNSPEC:
	case KFI_PROGRESS_AUTO:
	case KFI_PROGRESS_MANUAL:
		break;
	default:
		LOG_ERR("Invalid hints - invalid data progress mode.");
		return -ENODATA;
	}

	if (attr->mr_key_size > info->domain_attr->mr_key_size) {
		LOG_ERR("Invalid hints - MR key size too large.");
		return -ENODATA;
	}
	if (attr->cq_data_size > info->domain_attr->cq_data_size) {
		LOG_ERR("Invalid hints - CQ data size too large.");
		return -ENODATA;
	}
	if (attr->cq_cnt > info->domain_attr->cq_cnt) {
		LOG_ERR("Invalid hints - cq_cnt exceeds supported range.");
		return -ENODATA;
	}
	if (attr->ep_cnt > info->domain_attr->ep_cnt) {
		LOG_ERR("Invalid hints - ep_cnt exceeds supported range.");
		return -ENODATA;
	}
	if (attr->max_ep_tx_ctx > info->domain_attr->max_ep_tx_ctx) {
		LOG_ERR("Invalid hints - max_ep_tx_ctx exceeds supported range.");
		return -ENODATA;
	}
	if (attr->max_ep_rx_ctx > info->domain_attr->max_ep_rx_ctx) {
		LOG_ERR("Invalid hints - max_ep_rx_ctx exceeds supported range.");
		return -ENODATA;
	}
	return 0;
}

static int
kfi_ibv_check_ep_attr(const struct kfi_ep_attr *attr, const struct kfi_info *info)
{
	switch (attr->protocol) {
	case KFI_PROTO_UNSPEC:
	case KFI_PROTO_RDMA_CM_IB_RC:
	case KFI_PROTO_IWARP:
	case KFI_PROTO_IB_UD:
		break;
	default:
		LOG_ERR("Invalid hints - unsupported protocol.");
		return -ENODATA;
	}

	if (attr->protocol_version > 1) {
		LOG_ERR("Invalid hints - unsupported protocol version.");
		return -ENODATA;
	}
	if (attr->max_msg_size > info->ep_attr->max_msg_size) {
		LOG_ERR("Invalid hints - max message size too large.");
		return -ENODATA;
	}
	if (attr->max_order_raw_size > info->ep_attr->max_order_raw_size) {
		LOG_ERR("Invalid hints - max_order_raw_size exceeds supported range.");
		return -ENODATA;
	}
	if (attr->max_order_war_size > info->ep_attr->max_order_war_size) {
		LOG_ERR("Invalid hints - max_order_war_size exceeds supported range.");
		return -ENODATA;
	}
	if (attr->max_order_waw_size > info->ep_attr->max_order_waw_size) {
		LOG_ERR("Invalid hints - max_order_waw_size exceeds supported range.");
		return -ENODATA;
	}
	if (attr->tx_ctx_cnt > info->domain_attr->max_ep_tx_ctx) {
		LOG_ERR("Invalid hints - tx_ctx_cnt exceeds supported range.");
		return -ENODATA;
	}
	if (attr->rx_ctx_cnt > info->domain_attr->max_ep_rx_ctx) {
		LOG_ERR("Invalid hints - rx_ctx_cnt exceeds supported range.");
		return -ENODATA;
	}
	return 0;
}

static int
kfi_ibv_check_rx_attr(const struct kfi_rx_attr *attr,
                const struct kfi_info *hints, const struct kfi_info *info)
{
	uint64_t compare_mode, check_mode;

	if (attr->caps & ~(info->rx_attr->caps)) {
		LOG_ERR("Invalid hints - unsupported rx_attr->caps.");
		return -ENODATA;
	}

	compare_mode = attr->mode ? attr->mode : hints->mode;
	check_mode = (hints->caps & KFI_RMA) ?
		info->rx_attr->mode : VERBS_MODE;
	if ((compare_mode & check_mode) != check_mode) {
		LOG_ERR("Invalid hints - unsupported rx_attr->mode.");
		return -ENODATA;
	}
	if (attr->op_flags & ~(info->rx_attr->op_flags)) {
		LOG_ERR("Invalid hints - unsupported rx_attr->op_flags.");
		return -ENODATA;
	}
	if (attr->msg_order & ~(info->rx_attr->msg_order)) {
		LOG_ERR("Invalid hints - unsupported rx_attr->msg_order.");
		return -ENODATA;
	}
	if (attr->size > info->rx_attr->size) {
		LOG_ERR("Invalid hints - rx_attr->size exceeds supported range.");
		return -ENODATA;
	}
	if (attr->total_buffered_recv > info->rx_attr->total_buffered_recv) {
		LOG_ERR("Invalid hints - rx_attr->total_buffered_recv exceeds supported range.");
		return -ENODATA;
	}
	if (attr->iov_limit > info->rx_attr->iov_limit) {
		LOG_ERR("Invalid hints - rx_attr->iov_limit exceeds supported range.");
		return -ENODATA;
	}
	return 0;
}

static int
kfi_ibv_check_tx_attr(const struct kfi_tx_attr *attr,
                const struct kfi_info *hints, const struct kfi_info *info)
{
	if (attr->caps & ~(info->tx_attr->caps)) {
		LOG_ERR("Invalid hints - unsupported tx_attr->caps.");
		return -ENODATA;
	}
	if ( ((attr->mode ? attr->mode : hints->mode) & info->tx_attr->mode)
	     != info->tx_attr->mode ) {
		LOG_ERR("Invalid hints - unsupported tx_attr->mode.");
		return -ENODATA;
	}
	if (attr->op_flags & ~(info->tx_attr->op_flags)) {
		LOG_ERR("Invalid hints - unsupported tx_attr->op_flags.");
		return -ENODATA;
	}
	if (attr->msg_order & ~(info->tx_attr->msg_order)) {
		LOG_ERR("Invalid hints - unsupported tx_attr->msg_order.");
		return -ENODATA;
	}
	if (attr->size > info->tx_attr->size) {
		LOG_ERR("Invalid hints - tx_attr->size exceeds supported range.");
		return -ENODATA;
	}
	if (attr->iov_limit > info->tx_attr->iov_limit) {
		LOG_ERR("Invalid hints - tx_attr->iov_limit exceeds supported range.");
		return -ENODATA;
	}
	if (attr->rma_iov_limit > info->tx_attr->rma_iov_limit) {
		LOG_ERR("Invalid hints - tx_attr->rma_iov_limit exceeds supported range.");
		return -ENODATA;
	}
	return 0;
}

static void
kfi_ibv_update_info(const struct kfi_info *hints, struct kfi_info *info)
{
	if (hints) {
		if (hints->ep_attr) {
			if (hints->ep_attr->tx_ctx_cnt) {
				info->ep_attr->tx_ctx_cnt =
				        hints->ep_attr->tx_ctx_cnt;
			}
			if (hints->ep_attr->rx_ctx_cnt) {
				info->ep_attr->rx_ctx_cnt =
				        hints->ep_attr->rx_ctx_cnt;
			}
		}
		if (hints->tx_attr)
			info->tx_attr->op_flags = hints->tx_attr->op_flags;
		if (hints->rx_attr)
			info->rx_attr->op_flags = hints->rx_attr->op_flags;
		if (hints->src_addrlen) {
			info->src_addr =
			        kmemdup(hints->src_addr, hints->src_addrlen,
			                        GFP_KERNEL);
			info->src_addrlen = hints->src_addrlen;
		}
		if (hints->dest_addrlen) {
			info->dest_addr =
			        kmemdup(hints->dest_addr, hints->dest_addrlen,
			                        GFP_KERNEL);
			info->dest_addrlen = hints->dest_addrlen;
		}
	} else {
		info->tx_attr->op_flags = 0;
		info->rx_attr->op_flags = 0;
	}
	return;
}

static int
kfi_ibv_copy_addr(void *dst_addr, size_t *dst_addrlen, void *src_addr)
{
	size_t src_addrlen = kfi_ibv_sockaddr_len(src_addr);

	if (*dst_addrlen == 0) {
		*dst_addrlen = src_addrlen;
		return -EINVAL;
	}

	if (*dst_addrlen < src_addrlen) {
		memcpy(dst_addr, src_addr, *dst_addrlen);
	} else {
		memcpy(dst_addr, src_addr, src_addrlen);
	}
	*dst_addrlen = src_addrlen;
	return 0;
}

static int
kfi_ibv_sockaddr_len(struct sockaddr *addr)
{
	if (!addr) {
		return 0;
	}

	switch (addr->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	case AF_IB:
		return sizeof(struct sockaddr_ib);
	default:
		return 0;
	}
}

static ssize_t
kfi_ibv_eq_cm_process_event(struct kfi_ibv_eq *eq,
                struct kfi_ibv_event *cma_event, uint32_t *event,
                struct kfi_eq_cm_entry *entry, size_t len)
{
	kfid_t fid = NULL;
	size_t datalen = 0;
	struct rdma_conn_param *conn = NULL;

	fid = (struct kfid*)cma_event->id->context;
	switch (cma_event->event.event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		*event = KFI_CONNREQ;
		entry->info = kfi_ibv_eq_cm_getinfo(cma_event);
		if (!entry->info) {
			rdma_reject(cma_event->id, NULL, 0);
			rdma_destroy_id(cma_event->id);
			cma_event->id = NULL;
			return 0;
		}
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		*event = KFI_CONNECTED;
		entry->info = NULL;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		*event = KFI_SHUTDOWN;
		entry->info = NULL;
		break;
	/* We are not supposed to receive ADDR_RESOLVED or ROUTE_RESOLVED here */
	case RDMA_CM_EVENT_ADDR_RESOLVED:
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		eq->err.fid = fid;
		eq->err.err = cma_event->event.status;
		return -EIO;
	case RDMA_CM_EVENT_REJECTED:
		eq->err.fid = fid;
		eq->err.err = ECONNREFUSED;
		eq->err.prov_errno = cma_event->event.status;
		return -ECONNREFUSED;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		eq->err.fid = fid;
		eq->err.err = ENODEV;
		return -ENODEV;
	case RDMA_CM_EVENT_ADDR_CHANGE:
		eq->err.fid = fid;
		eq->err.err = EADDRNOTAVAIL;
		return -EADDRNOTAVAIL;
	default:
		return 0;
	}

	entry->fid = fid;
	conn = &cma_event->event.param.conn;
	datalen = min(len - sizeof(*entry), (size_t)conn->private_data_len);
	if (datalen) {
		memcpy(entry->data, conn->private_data, datalen);
	}
	return (sizeof(*entry) + datalen);
}

static int
kfi_ibv_pep_unbind(kfid_t fid, struct kfid *bfid)
{
	struct kfi_ibv_pep *pep = NULL;
	struct kfi_ibv_eq *eq = NULL;
	int ret = 0;

	kfi_ref_id(fid);
	kfi_ref_id(bfid);
	if (fid->fclass != KFI_CLASS_PEP || bfid->fclass != KFI_CLASS_EQ) {
		ret = -EINVAL;
		goto exit_nolock;
	}
	pep = container_of(fid, struct kfi_ibv_pep, pep_fid.fid);
	eq = container_of(bfid, struct kfi_ibv_eq, eq_fid.fid);

	mutex_lock(&pep->mut);
	if (pep->eq != eq || eq->ep_fid != fid) {
		ret = -EINVAL;
		goto exit;
	}
	pep->eq = NULL;
	eq->ep_fid = NULL;
	kfi_deref_id(fid);
	kfi_deref_id(bfid);
exit:
	mutex_unlock(&pep->mut);
exit_nolock:
	kfi_deref_id(fid);
	kfi_deref_id(bfid);
	return ret;
}

static int
kfi_ibv_ep_unbind(kfid_t fid, struct kfid *bfid, uint64_t flags)
{
	struct kfi_ibv_ep *ep = NULL;
	struct kfi_ibv_eq *eq = NULL;
	struct kfi_ibv_cq *cq = NULL;
	int ret = 0;

	if (fid->fclass != KFI_CLASS_EP
	    || (bfid->fclass != KFI_CLASS_EQ && bfid->fclass != KFI_CLASS_CQ) ) {
		return -EINVAL;
	}

	ep = container_of(fid, struct kfi_ibv_ep, ep_fid.fid);
	mutex_lock(&ep->mut);

	switch (bfid->fclass) {
	case KFI_CLASS_CQ:
		cq = container_of(bfid, struct kfi_ibv_cq, cq_fid.fid);
		if (!(flags & (KFI_RECV | KFI_SEND))) {
			ret = -EINVAL;
			goto exit;
		}
		if (flags & KFI_RECV) {
			if (ep->rcq != cq) {
				ret = -EINVAL;
				goto exit;
			}
			kfi_deref_id(bfid);
			ep->rcq = NULL;
		}
		if (flags & KFI_SEND) {
			if (ep->scq != cq) {
				ret = -EINVAL;
				goto exit;
			}
			kfi_deref_id(bfid);
			ep->scq = NULL;
		}
		break;
	case KFI_CLASS_EQ:
		eq = container_of(bfid, struct kfi_ibv_eq, eq_fid.fid);
		if (ep->eq != eq || eq->ep_fid != fid) {
			ret = -EINVAL;
			goto exit;
		}
		kfi_deref_id(fid);
		eq->ep_fid = NULL;
		kfi_deref_id(bfid);
		ep->eq = NULL;
		break;
	default:
		ret = -EINVAL;
		goto exit;
	}

exit:
	mutex_unlock(&ep->mut);
	return ret;
}

static const char *
kstrerror(int errno)
{
	static const char *const errno_str[] = {
		[EPERM]         = "Operation not permitted",
		[ENOENT]        = "No such file or directory",
		[ESRCH]         = "No such process",
		[EINTR]         = "Interrupted system call",
		[EIO]           = "I/O error",
		[ENXIO]         = "No such device or address",
		[E2BIG]         = "Argument list too long",
		[ENOEXEC]       = "Exec format error",
		[EBADF]         = "Bad file number",
		[ECHILD]        = "No child processes",
		[EAGAIN]        = "Try again",
		[ENOMEM]        = "Out of memory",
		[EACCES]        = "Permission denied",
		[EFAULT]        = "Bad address",
		[ENOTBLK]       = "Block device required",
		[EBUSY]         = "Device or resource busy",
		[EEXIST]        = "File exists",
		[EXDEV]         = "Cross-device link",
		[ENODEV]        = "No such device",
		[ENOTDIR]       = "Not a directory",
		[EISDIR]        = "Is a directory",
		[EINVAL]        = "Invalid argument",
		[ENFILE]        = "File table overflow",
		[EMFILE]        = "Too many open files",
		[ENOTTY]        = "Not a typewriter",
		[ETXTBSY]       = "Text file busy",
		[EFBIG]         = "File too large",
		[ENOSPC]        = "No space left on device",
		[ESPIPE]        = "Illegal seek",
		[EROFS]         = "Read-only file system",
		[EMLINK]        = "Too many links",
		[EPIPE]         = "Broken pipe",
		[EDOM]          = "Math argument out of domain of func",
		[ERANGE]        = "Math result not representable",
	};

	if (errno < EPERM || errno > ERANGE) {
		return "Unknown error";
	}

	return errno_str[errno];
}

static const char *
ib_wc_status_str(enum ib_wc_status status)
{
	static const char *const wc_status_str[] = {
		[IB_WC_SUCCESS]            = "success",
		[IB_WC_LOC_LEN_ERR]        = "local length error",
		[IB_WC_LOC_QP_OP_ERR]      = "local QP operation error",
		[IB_WC_LOC_EEC_OP_ERR]     = "local EE context operation error",
		[IB_WC_LOC_PROT_ERR]       = "local protection error",
		[IB_WC_WR_FLUSH_ERR]       = "Work Request Flushed Error",
		[IB_WC_MW_BIND_ERR]        = "memory management operation error",
		[IB_WC_BAD_RESP_ERR]       = "bad response error",
		[IB_WC_LOC_ACCESS_ERR]     = "local access error",
		[IB_WC_REM_INV_REQ_ERR]    = "remote invalid request error",
		[IB_WC_REM_ACCESS_ERR]     = "remote access error",
		[IB_WC_REM_OP_ERR]         = "remote operation error",
		[IB_WC_RETRY_EXC_ERR]      = "transport retry counter exceeded",
		[IB_WC_RNR_RETRY_EXC_ERR]  = "RNR retry counter exceeded",
		[IB_WC_LOC_RDD_VIOL_ERR]   = "local RDD violation error",
		[IB_WC_REM_INV_RD_REQ_ERR] = "remote invalid RD request",
		[IB_WC_REM_ABORT_ERR]      = "aborted error",
		[IB_WC_INV_EECN_ERR]       = "invalid EE context number",
		[IB_WC_INV_EEC_STATE_ERR]  = "invalid EE context state",
		[IB_WC_FATAL_ERR]          = "fatal error",
		[IB_WC_RESP_TIMEOUT_ERR]   = "response timeout error",
		[IB_WC_GENERAL_ERR]        = "general error"
	};

	if (status < IB_WC_SUCCESS || status > IB_WC_GENERAL_ERR)
		return "unknown";

	return wc_status_str[status];
}

static uint64_t
kfi_ibv_comp_flags(struct ib_wc *wc)
{
	uint64_t flags = 0;

	if (wc->wc_flags & IB_WC_WITH_IMM)
		flags |= KFI_REMOTE_CQ_DATA;

	switch (wc->opcode) {
	case IB_WC_SEND:
		flags |= KFI_SEND | KFI_MSG;
		break;
	case IB_WC_RDMA_WRITE:
		flags |= KFI_RMA | KFI_WRITE;
		break;
	case IB_WC_RDMA_READ:
		flags |= KFI_RMA | KFI_READ;
		break;
	case IB_WC_COMP_SWAP:
		flags |= KFI_ATOMIC;
		break;
	case IB_WC_FETCH_ADD:
		flags |= KFI_ATOMIC;
		break;
	case IB_WC_RECV:
		flags |= KFI_RECV | KFI_MSG;
		break;
	case IB_WC_RECV_RDMA_WITH_IMM:
		flags |= KFI_RMA | KFI_REMOTE_WRITE;
		break;
	default:
		break;
	}
	return flags;
}

static int
kfi_ibv_fill_sge(void *addr, size_t len, void *desc, struct ib_sge *sge)
{
	struct kfi_ibv_mem_desc *md = NULL;
	size_t offset = 0;

	md = (struct kfi_ibv_mem_desc*)desc;

	if (addr < md->vaddr) {
		return -EINVAL;
	}
	offset = (addr - md->vaddr);
	if (offset + len > md->dma_len) {
		return -EINVAL;
	}
	sge->addr = md->dma_addr + offset;
	sge->length = (uint32_t)len;
	sge->lkey = md->mr->lkey;
	return 0;
};

module_init(kfi_ibv_init);
module_exit(kfi_ibv_exit);
