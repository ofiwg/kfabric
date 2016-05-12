/*
 * Copyright (c) 2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2015 NetApp, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL); Version 2, available from the file
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

#ifndef _KFI_ENOSYS_H_
#define _KFI_ENOSYS_H_

#include <kfabric.h>
#include <kfi_domain.h>
#include <kfi_prov.h>


/*
static struct kfi_ops X = {
	.close = X,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open,
};
*/

static inline int
kfi_no_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags)
{
	return -ENOSYS;
};

static inline int
kfi_no_control(struct kfid *fid, int command, void *arg)
{
	return -ENOSYS;
};

static inline int
kfi_no_ops_open(struct kfid *fid, const char *name, uint64_t flags, void **ops,
                void *context)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_fabric X = {
	.domain = kfi_no_domain,
	.passive_ep = kfi_no_passive_ep,
	.eq_open = kfi_no_eq_open,
};
*/

static inline int
kfi_no_domain(struct kfid_fabric *fabric, struct kfi_domain_attr *attr,
                struct kfid_domain **dom, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_passive_ep(struct kfid_fabric *fabric, struct kfi_info *info,
                struct kfid_pep **pep, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
                struct kfid_eq **eq, void *context)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_atomic X = {
	.write = kfi_no_atomic_write,
	.writev = kfi_no_atomic_writev,
	.writemsg = kfi_no_atomic_writemsg,
	.inject = kfi_no_atomic_inject,
	.readwrite = kfi_no_atomic_readwrite,
	.readwritev = kfi_no_atomic_readwritev,
	.readwritemsg = kfi_no_atomic_readwritemsg,
	.compwrite = kfi_no_atomic_compwrite,
	.compwritev = kfi_no_atomic_compwritev,
	.compwritemsg = kfi_no_atomic_compwritemsg,
	.writevalid = kfi_no_atomic_writevalid,
	.readwritevalid = kfi_no_atomic_readwritevalid,
	.compwritevalid = kfi_no_atomic_compwritevalid,
};
*/

static inline ssize_t
kfi_no_atomic_write(struct kfid_ep *ep, const void *buf, size_t count,
                void *desc, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_writev(struct kfid_ep *ep, const struct kfi_ioc *iov, void **desc,
                size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_writemsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_inject(struct kfid_ep *ep, const void *buf, size_t count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_readwrite(struct kfid_ep *ep, const void *buf, size_t count,
                void *desc, void *result, void *result_desc, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
                enum kfi_op op, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_readwritev(struct kfid_ep *ep, const struct kfi_ioc *iov,
                void **desc, size_t count, struct kfi_ioc *resultv,
                void **result_desc, size_t result_count, kfi_addr_t dest_addr,
                uint64_t addr, uint64_t key, enum kfi_datatype datatype,
                enum kfi_op op, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_readwritemsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                struct kfi_ioc *resultv, void **result_desc, size_t result_count,
                uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_compwrite(struct kfid_ep *ep, const void *buf, size_t count,
                void *desc, const void *compare, void *compare_desc, void *result,
                void *result_desc, kfi_addr_t dest_addr, uint64_t addr,
                uint64_t key, enum kfi_datatype datatype, enum kfi_op op,
                void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_compwritev(struct kfid_ep *ep, const struct kfi_ioc *iov,
                void **desc, size_t count, const struct kfi_ioc *comparev,
                void **compare_desc, size_t compare_count,
                struct kfi_ioc *resultv, void **result_desc, size_t result_count,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                enum kfi_datatype datatype, enum kfi_op op, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_atomic_compwritemsg(struct kfid_ep *ep, const struct kfi_msg_atomic *msg,
                const struct kfi_ioc *comparev, void **compare_desc,
                size_t compare_count, struct kfi_ioc *resultv, void **result_desc,
                size_t result_count, uint64_t flags)
{
	return -ENOSYS;
};

static inline int
kfi_no_atomic_writevalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	return -ENOSYS;
};

static inline int
kfi_no_atomic_readwritevalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	return -ENOSYS;
};

static inline int
kfi_no_atomic_compwritevalid(struct kfid_ep *ep, enum kfi_datatype datatype,
                enum kfi_op op, size_t *count)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_cm X = {
	.setname = kfi_no_setname,
	.getname = kfi_no_getname,
	.getpeer = kfi_no_getpeer,
	.connect = kfi_no_connect,
	.listen = kfi_no_listen,
	.accept = kfi_no_accept,
	.reject = kfi_no_reject,
	.shutdown = kfi_no_shutdown,
};
*/

static inline int
kfi_no_setname(kfid_t fid, void *addr, size_t addrlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_getname(kfid_t fid, void *addr, size_t *addrlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_getpeer(struct kfid_ep *ep, void *addr, size_t *addrlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_connect(struct kfid_ep *ep, const void *addr, const void *param,
                size_t paramlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_listen(struct kfid_pep *pep)
{
	return -ENOSYS;
};

static inline int
kfi_no_accept(struct kfid_ep *ep, const void *param, size_t paramlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_reject(struct kfid_pep *pep, kfid_t handle, const void *param,
                size_t paramlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_shutdown(struct kfid_ep *ep, uint64_t flags)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_domain X = {
	.cq_open = kfi_no_cq_open,
	.endpoint = kfi_no_endpoint,
};
*/

static inline int
kfi_no_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
                struct kfid_cq **cq, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_endpoint(struct kfid_domain *domain, struct kfi_info *info,
                struct kfid_ep **ep, void *context)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_mr X = {
	.reg = kfi_no_mr_reg,
	.regv = kfi_no_mr_regv,
	.regattr = kfi_no_mr_regattr,
};
*/

static inline int
kfi_no_mr_reg(struct kfid *fid, const void *buf, size_t len, uint64_t access,
                uint64_t offset, uint64_t requested_key, uint64_t flags,
                struct kfid_mr **mr, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_mr_regv(struct kfid *fid, const struct kvec *iov, size_t count,
                uint64_t access, uint64_t offset, uint64_t requested_key,
                uint64_t flags, struct kfid_mr **mr, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_mr_regattr(struct kfid *fid, const struct kfi_mr_attr *attr,
                uint64_t flags, struct kfid_mr **mr)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_ep X = {
	.cancel = kfi_no_cancel,
	.getopt = kfi_no_getopt,
	.setopt = kfi_no_setopt,
	.tx_ctx = kfi_no_tx_ctx,
	.rx_ctx = kfi_no_rx_ctx,
	.rx_size_left = kfi_no_rx_size_left,
	.tx_size_left = kfi_no_tx_size_left,
};
*/

static inline ssize_t
kfi_no_cancel(kfid_t fid, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_getopt(kfid_t fid, int level, int optname, void *optval, size_t *optlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_setopt(kfid_t fid, int level, int optname, const void *optval,
                size_t optlen)
{
	return -ENOSYS;
};

static inline int
kfi_no_tx_ctx(struct kfid_ep *sep, int index, struct kfi_tx_attr *attr,
                struct kfid_ep **tx_ep, void *context)
{
	return -ENOSYS;
};

static inline int
kfi_no_rx_ctx(struct kfid_ep *sep, int index, struct kfi_rx_attr *attr,
                struct kfid_ep **rx_ep, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rx_size_left(struct kfid_ep *ep)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tx_size_left(struct kfid_ep *ep)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_msg X = {
	.recv = kfi_no_msg_recv,
	.recvv = kfi_no_msg_recvv,
	.recvmsg = kfi_no_msg_recvmsg,
	.send = kfi_no_msg_send,
	.sendv = kfi_no_msg_sendv,
	.sendmsg = kfi_no_msg_sendmsg,
	.inject = kfi_no_msg_inject,
	.senddata = kfi_no_msg_senddata,
	.injectdata = kfi_no_msg_injectdata,
};
*/

static inline ssize_t
kfi_no_msg_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t src_addr, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_send(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                kfi_addr_t dest_addr, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t dest_addr, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg, uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_inject(struct kfid_ep *ep, const void *buf, size_t len,
                kfi_addr_t dest_addr)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_senddata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                uint64_t data, kfi_addr_t dest_addr, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_msg_injectdata(struct kfid_ep *ep, const void *buf, size_t len,
                uint64_t data, kfi_addr_t dest_addr)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_eq X = {
	.read = X,
	.readerr = X,
	.write = kfi_no_eq_write,
	.sread = kfi_no_eq_sread,
	.strerror = X,
};
*/

static inline ssize_t
kfi_no_eq_write(struct kfid_eq *eq, uint32_t event, const void *buf, size_t len,
                uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_eq_sread(struct kfid_eq *eq, uint32_t *event, void *buf, size_t len,
                int timeout, uint64_t flags)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_cq X = {
	.read = X,
	.readfrom = kfi_no_cq_readfrom,
	.readerr = X,
	.sread = kfi_no_cq_sread,
	.sreadfrom = kfi_no_cq_sreadfrom,
	.signal = kfi_no_cq_signal,
	.strerror = X,
};
*/

static inline ssize_t
kfi_no_cq_readfrom(struct kfid_cq *cq, void *buf, size_t count,
                kfi_addr_t *src_addr)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_cq_sread(struct kfid_cq *cq, void *buf, size_t count, const void *cond,
                int timeout)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_cq_sreadfrom(struct kfid_cq *cq, void *buf, size_t count,
                kfi_addr_t *src_addr, const void *cond, int timeout)
{
	return -ENOSYS;
};

static inline int
kfi_no_cq_signal(struct kfid_cq *cq)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_rma X = {
	.read = kfi_no_rma_read,
	.readv = kfi_no_rma_readv,
	.readmsg = kfi_no_rma_readmsg,
	.write = kfi_no_rma_write,
	.writev = kfi_no_rma_writev,
	.writemsg = kfi_no_rma_writemsg,
	.inject = kfi_no_rma_inject,
	.writedata = kfi_no_rma_writedata,
	.injectdata = kfi_no_rma_injectdata,
};
*/

static inline ssize_t
kfi_no_rma_read(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                kfi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_readv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t src_addr, uint64_t addr, uint64_t key,
                void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_readmsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
                uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_write(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_writev(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                size_t count, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_writemsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
                uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_inject(struct kfid_ep *ep, const void *buf, size_t len,
                kfi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_writedata(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                uint64_t data, kfi_addr_t dest_addr, uint64_t addr, uint64_t key,
                void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_rma_injectdata(struct kfid_ep *ep, const void *buf, size_t len,
                uint64_t data, kfi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	return -ENOSYS;
};


/*
static struct kfi_ops_tagged X = {
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
*/

static inline ssize_t
kfi_no_tagged_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
                        kfi_addr_t src_addr, uint64_t tag, uint64_t ignore,
                        void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                        size_t count, kfi_addr_t src_addr, uint64_t tag,
                        uint64_t ignore, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_recvmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
                        uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_send(struct kfid_ep *ep, const void *buf, size_t len, void *desc,
                        kfi_addr_t dest_addr, uint64_t tag, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
                        size_t count, kfi_addr_t dest_addr, uint64_t tag,
                        void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_sendmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
                        uint64_t flags)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_inject(struct kfid_ep *ep, const void *buf, size_t len,
                        kfi_addr_t dest_addr, uint64_t tag)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_senddata(struct kfid_ep *ep, const void *buf, size_t len,
                        void *desc, uint64_t data, kfi_addr_t dest_addr,
                        uint64_t tag, void *context)
{
	return -ENOSYS;
};

static inline ssize_t
kfi_no_tagged_injectdata(struct kfid_ep *ep, const void *buf, size_t len,
                        uint64_t data, kfi_addr_t dest_addr, uint64_t tag)
{
	return -ENOSYS;
};


#endif /* _KFI_ENOSYS_H_ */
