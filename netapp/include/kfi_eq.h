/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2015 NetApp, Inc. All rights reserved.
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

#ifndef _KFI_EQ_H_
#define _KFI_EQ_H_

#include <kfabric.h>

/*
 * EQ = Event Queue
 * Report various control (not data transfer) events and operations.
 */

struct kfi_eq_attr {
	uint64_t                flags;
	int                     signaling_vector;
};

/* KFI EQ events */
enum {
	KFI_NOTIFY,
	KFI_CONNREQ,
	KFI_CONNECTED,
	KFI_SHUTDOWN,
	KFI_MR_COMPLETE,
};

/*
 * General event entry retrieved through read() / sread() on the EQ.
 */
struct kfi_eq_entry {
	kfid_t                  fid;
	void                    *context;
	uint64_t                data;
};

/*
 * Connection management specific event entry associated with connection
 * management events KFI_CONNREQ, KFI_CONNECTED, KFI_SHUTDOWN.
 * 
 * A kfi_info instance is returned with a KFI_CONNREQ event, with new connection
 * objects associated with its handle field. Additional private connection data
 * will be placed in the data field, up to space provided.
 *
 * If the connection request cannot be accpeted, user must explicitly reject the
 * info->handle in order to releases the new connection resources.
 *
 * User must also release the fabric info instance returned here by explicitly 
 * calling kfi_freeinfo(). 
 */
struct kfi_eq_cm_entry {
	kfid_t                  fid;
	struct kfi_info         *info;
	uint8_t                 data[];
};

/*
 * Retrieved through readerr() after any EQ operation failed. The err_data is
 * available until the next time the EQ is read.
 */
struct kfi_eq_err_entry {
	kfid_t                  fid;
	void                    *context;
	uint64_t                data;
	int                     err;
	int                     prov_errno;
	void                    *err_data;
	size_t                  err_data_size;
};

struct kfi_ops_eq {
	ssize_t (*read)(struct kfid_eq *eq, uint32_t *event, void *buf,
	                size_t len, uint64_t flags);
	ssize_t (*readerr)(struct kfid_eq *eq, struct kfi_eq_err_entry *buf,
	                uint64_t flags);
	ssize_t (*write)(struct kfid_eq *eq, uint32_t event, const void *buf,
	                size_t len, uint64_t flags);
	ssize_t (*sread)(struct kfid_eq *eq, uint32_t *event, void *buf,
	                size_t len, int timeout, uint64_t flags);
	const char* (*strerror)(struct kfid_eq *eq, int prov_errno,
	                const void *err_data, char *buf, size_t len);
};

struct kfid_eq {
	struct kfid             fid;
	struct kfi_ops_eq       *ops;
};


/*
 * CQ = Complete Queue
 * Report the completion of data transfer operations.
 */

enum kfi_cq_format {
	KFI_CQ_FORMAT_UNSPEC,
	KFI_CQ_FORMAT_CONTEXT,
	KFI_CQ_FORMAT_MSG,
	KFI_CQ_FORMAT_DATA,
	KFI_CQ_FORMAT_TAGGED,
};

struct kfi_cq_attr {
	size_t                  size;
	uint64_t                flags;
	enum kfi_cq_format      format;
	int                     signaling_vector;
};

/*
 * CQ entry returned from read() / sread(), for KFI_CQ_FORMAT_CONTEXT.
 */
struct kfi_cq_entry {
	void                    *op_context;
};

/*
 * CQ entry returned from read() / sread(), for KFI_CQ_FORMAT_MSG.
 */
struct kfi_cq_msg_entry {
	void                    *op_context;
	uint64_t                flags;
	size_t                  len;
};

/*
 * CQ entry returned from read() / sread(), for KFI_CQ_FORMAT_DATA.
 * The data field depends on operation and/or flags - e.g. remote EQ data.
 */
struct kfi_cq_data_entry {
	void                    *op_context;
	uint64_t                flags;
	size_t                  len;
	void                    *buf;
	uint64_t                data;
};

/*
 * CQ entry returned from read() / sread(), for KFI_CQ_FORMAT_TAGGED.
 */
struct kfi_cq_tagged_entry {
	void                    *op_context;
	uint64_t                flags;
	size_t                  len;
	void                    *buf;
	uint64_t                data;
	uint64_t                tag;
};

/*
 * Retrieved through readerr() after any CQ operation failed. The err_data is
 * available until the next time the CQ is read.
 */
struct kfi_cq_err_entry {
	void                    *op_context;
	uint64_t                flags;
	size_t                  len;
	void                    *buf;
	uint64_t                data;
	uint64_t                tag;
	size_t                  olen;
	int                     err;
	int                     prov_errno;
	void                    *err_data;
};

struct kfi_ops_cq {
	ssize_t (*read)(struct kfid_cq *cq, void *buf, size_t count);
	ssize_t (*readfrom)(struct kfid_cq *cq, void *buf, size_t count,
	                kfi_addr_t *src_addr);
	ssize_t (*readerr)(struct kfid_cq *cq, struct kfi_cq_err_entry *buf,
	                uint64_t flags);
	ssize_t (*sread)(struct kfid_cq *cq, void *buf, size_t count,
	                const void *cond, int timeout);
	ssize_t (*sreadfrom)(struct kfid_cq *cq, void *buf, size_t count,
	                kfi_addr_t *src_addr, const void *cond, int timeout);
	int (*signal)(struct kfid_cq *cq);
	const char* (*strerror)(struct kfid_cq *cq, int prov_errno,
	                const void *err_data, char *buf, size_t len);
};

struct kfid_cq {
	struct kfid             fid;
	struct kfi_ops_cq       *ops;
};

static inline int
kfi_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
                struct kfid_eq **eq, void *context)
{
	return fabric->ops->eq_open(fabric, attr, eq, context);
}

static inline ssize_t
kfi_eq_read(struct kfid_eq *eq, uint32_t *event, void *buf, size_t len,
                uint64_t flags)
{
	return eq->ops->read(eq, event, buf, len, flags);
}

static inline ssize_t
kfi_eq_readerr(struct kfid_eq *eq, struct kfi_eq_err_entry *buf, uint64_t flags)
{
	return eq->ops->readerr(eq, buf, flags);
}

static inline ssize_t
kfi_eq_write(struct kfid_eq *eq, uint32_t event, const void *buf, size_t len,
                uint64_t flags)
{
	return eq->ops->write(eq, event, buf, len, flags);
}

static inline ssize_t
kfi_eq_sread(struct kfid_eq *eq, uint32_t *event, void *buf, size_t len,
                int timeout, uint64_t flags)
{
	return eq->ops->sread(eq, event, buf, len, timeout, flags);
}

static inline const char *
kfi_eq_strerror(struct kfid_eq *eq, int prov_errno, const void *err_data,
                char *buf, size_t len)
{
	return eq->ops->strerror(eq, prov_errno, err_data, buf, len);
}

static inline ssize_t
kfi_cq_read(struct kfid_cq *cq, void *buf, size_t count)
{
	return cq->ops->read(cq, buf, count);
}

static inline ssize_t
kfi_cq_readfrom(struct kfid_cq *cq, void *buf, size_t count, kfi_addr_t *src_addr)
{
	return cq->ops->readfrom(cq, buf, count, src_addr);
}

static inline ssize_t
kfi_cq_readerr(struct kfid_cq *cq, struct kfi_cq_err_entry *buf, uint64_t flags)
{
	return cq->ops->readerr(cq, buf, flags);
}

static inline ssize_t
kfi_cq_sread(struct kfid_cq *cq, void *buf, size_t count, const void *cond,
                int timeout)
{
	return cq->ops->sread(cq, buf, count, cond, timeout);
}

static inline ssize_t
kfi_cq_sreadfrom(struct kfid_cq *cq, void *buf, size_t count,
                kfi_addr_t *src_addr, const void *cond, int timeout)
{
	return cq->ops->sreadfrom(cq, buf, count, src_addr, cond, timeout);
}

static inline int
kfi_cq_signal(struct kfid_cq *cq)
{
	return cq->ops->signal(cq);
}

static inline const char *
kfi_cq_strerror(struct kfid_cq *cq, int prov_errno, const void *err_data,
                char *buf, size_t len)
{
	return cq->ops->strerror(cq, prov_errno, err_data, buf, len);
}

#endif
