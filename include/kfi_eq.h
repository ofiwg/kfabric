/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
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
 * Wait Set
 * Allows associating multiple EQs and counters with a single wait object.
 */

/* Use kfi_control GETWAIT to get underlying wait object(s) */
enum kfi_wait_obj {
	KFI_WAIT_NONE,
	KFI_WAIT_UNSPEC,
	KFI_WAIT_SET,
	KFI_WAIT_FD,
	KFI_WAIT_MUTEX_COND,	/* pthread mutex & cond */
};

struct kfi_wait_attr {
	enum kfi_wait_obj	wait_obj;
	uint64_t		flags;
};

struct kfi_ops_wait {
	size_t	size;
	int	(*wait)(struct kfid_wait *waitset, int timeout);
};

struct kfid_wait {
	struct kfid		fid;
	struct kfi_ops_wait	*ops;
};

/*
 * Poll Set
 * Allows polling multiple event queues and counters for progress
 */

struct kfi_poll_attr {
	uint64_t		flags;
};

struct kfi_ops_poll {
	size_t	size;
	int	(*poll)(struct kfid_poll *pollset, void **context, int count);
	int	(*poll_add)(struct kfid_poll *pollset, struct kfid *event_kfid,
			uint64_t flags);
	int	(*poll_del)(struct kfid_poll *pollset, struct kfid *event_kfid,
			uint64_t flags);
};

struct kfid_poll {
	struct kfid		fid;
	struct kfi_ops_poll	*ops;
};


/*
 * EQ = Event Queue
 * Used to report various control (not data transfer) events and operations.
 */

struct kfi_eq_attr {
	size_t			size;
	uint64_t		flags;
	enum kfi_wait_obj	wait_obj;
	int			signaling_vector;
	struct kfid_wai		*wait_set;
};

/* Standard EQ events */
enum {
	KFI_NOTIFY,
	KFI_CONNREQ,
	KFI_CONNECTED,
	KFI_SHUTDOWN,
	KFI_MR_COMPLETE,
	KFI_AV_COMPLETE,
};

struct kfi_eq_entry {
	struct kfid		*fid;
	void			*context;
	uint64_t		data;
};

struct kfi_eq_err_entry {
	struct kfid		*fid;
	void			*context;
	uint64_t		data;
	int			err;
	int			prov_errno;
	/* err_data is available until the next time the CQ is read */
	void			*err_data;
};

struct kfi_eq_cm_entry {
	struct kfid		*fid;
	/* user must call kfi_freeinfo to release info */
	struct kfi_info		*info;
	/* connection data placed here, up to space provided */
	uint8_t			data[];
};

struct kfi_ops_eq {
	size_t	size;
	ssize_t	(*read)(struct kfid_eq *eq, uint32_t *event,
			void *buf, size_t len, uint64_t flags);
	ssize_t	(*readerr)(struct kfid_eq *eq, struct kfi_eq_err_entry *buf,
			uint64_t flags);
	ssize_t	(*write)(struct kfid_eq *eq, uint32_t event,
			const void *buf, size_t len, uint64_t flags);
	ssize_t	(*sread)(struct kfid_eq *eq, uint32_t *event,
			void *buf, size_t len, int timeout, uint64_t flags);
	const char * (*strerror)(struct kfid_eq *eq, int prov_errno,
			const void *err_data, char *buf, size_t len);
};

struct kfid_eq {
	struct kfid		fid;
	struct kfi_ops_eq	*ops;
};


/*
 * CQ = Complete Queue
 * Used to report the completion of data transfer operations.
 */

enum kfi_cq_format {
	KFI_CQ_FORMAT_UNSPEC,
	KFI_CQ_FORMAT_CONTEXT,
	KFI_CQ_FORMAT_MSG,
	KFI_CQ_FORMAT_DATA,
	KFI_CQ_FORMAT_TAGGED,
};

struct kfi_cq_entry {
	void			*op_context;
};

struct kfi_cq_msg_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
};

struct kfi_cq_data_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	/* data depends on operation and/or flags - e.g. remote EQ data */
	uint64_t		data;
};

struct kfi_cq_tagged_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	uint64_t		data;
	uint64_t		tag;
};

struct kfi_cq_err_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	uint64_t		data;
	uint64_t		tag;
	size_t			olen;
	int			err;
	int			prov_errno;
	/* err_data is available until the next time the CQ is read */
	void			*err_data;
};

enum kfi_cq_wait_cond {
	KFI_CQ_COND_NONE,
	KFI_CQ_COND_THRESHOLD	/* size_t threshold */
};

struct kfi_cq_attr {
	size_t			size;
	uint64_t		flags;
	enum kfi_cq_format	format;
	enum kfi_wait_obj	wait_obj;
	int			signaling_vector;
	enum kfi_cq_wait_cond	wait_cond;
	struct kfid_wait	*wait_set;
};

struct kfi_ops_cq {
	size_t	size;
	ssize_t	(*read)(struct kfid_cq *cq, void *buf, size_t count);
	ssize_t	(*readfrom)(struct kfid_cq *cq, void *buf, size_t count,
			kfi_addr_t *src_addr);
	ssize_t	(*readerr)(struct kfid_cq *cq, struct kfi_cq_err_entry *buf,
			uint64_t flags);
	ssize_t	(*write)(struct kfid_cq *cq, const void *buf, size_t len);
	ssize_t	(*writeerr)(struct kfid_cq *cq, struct kfi_cq_err_entry *buf,
			size_t len, uint64_t flags);
	ssize_t	(*sread)(struct kfid_cq *cq, void *buf, size_t count,
			const void *cond, int timeout);
	ssize_t	(*sreadfrom)(struct kfid_cq *cq, void *buf, size_t count,
			kfi_addr_t *src_addr, const void *cond, int timeout);
	int (*signal)(struct kfid_cq *cq);
	const char * (*strerror)(struct kfid_cq *cq, int prov_errno,
			const void *err_data, char *buf, size_t len);
};

struct kfid_cq {
	struct kfid		fid;
	struct kfi_ops_cq	*ops;
};


/*
 * CNTR = Counter
 * Used to report the number of completed of asynchronous operations.
 */

enum kfi_cntr_events {
	KFI_CNTR_EVENTS_COMP
};

struct kfi_cntr_attr {
	enum kfi_cntr_events	events;
	enum kfi_wait_obj	wait_obj;
	struct kfid_wait	*wait_set;
	uint64_t		flags;
};

struct kfi_ops_cntr {
	size_t	size;
	uint64_t (*read)(struct kfid_cntr *cntr);
	uint64_t (*readerr)(struct kfid_cntr *cntr);
	int	(*add)(struct kfid_cntr *cntr, uint64_t value);
	int	(*set)(struct kfid_cntr *cntr, uint64_t value);
	int	(*wait)(struct kfid_cntr *cntr, uint64_t threshold, int timeout);
};

struct kfid_cntr {
	struct kfid		fid;
	struct kfi_ops_cntr	*ops;
};


#ifndef KFABRIC_DIRECT

static inline int
kfi_wait(struct kfid_wait *waitset, int timeout)
{
	return waitset->ops->wait(waitset, timeout);
}

static inline int
kfi_poll(struct kfid_poll *pollset, void **context, int count)
{
	return pollset->ops->poll(pollset, context, count);
}

static inline int
kfi_poll_add(struct kfid_poll *pollset, struct kfid *event_kfid, uint64_t flags)
{
	return pollset->ops->poll_add(pollset, event_kfid, flags);
}

static inline int
kfi_poll_del(struct kfid_poll *pollset, struct kfid *event_kfid, uint64_t flags)
{
	return pollset->ops->poll_del(pollset, event_kfid, flags);
}

static inline int
kfi_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
	   struct kfid_eq **eq, void *context)
{
	return fabric->ops->eq_open(fabric, attr, eq, context);
}

static inline ssize_t
kfi_eq_read(struct kfid_eq *eq, uint32_t *event, void *buf,
	   size_t len, uint64_t flags)
{
	return eq->ops->read(eq, event, buf, len, flags);
}

static inline ssize_t
kfi_eq_readerr(struct kfid_eq *eq, struct kfi_eq_err_entry *buf, uint64_t flags)
{
	return eq->ops->readerr(eq, buf, flags);
}

static inline ssize_t
kfi_eq_write(struct kfid_eq *eq, uint32_t event, const void *buf,
	    size_t len, uint64_t flags)
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


static inline ssize_t kfi_cq_read(struct kfid_cq *cq, void *buf, size_t count)
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

static inline ssize_t kfi_cq_write(struct kfid_cq *cq, const void *buf,
				  size_t len)
{
	return cq->ops->write(cq, buf, len);
}

static inline ssize_t kfi_cq_writeerr(struct kfid_cq *cq,
				     struct kfi_cq_err_entry *buf, size_t len,
				     uint64_t flags)
{
	return cq->ops->writeerr(cq, buf, len, flags);
}

static inline ssize_t
kfi_cq_sread(struct kfid_cq *cq, void *buf, size_t count, const void *cond,
	    int timeout)
{
	return cq->ops->sread(cq, buf, count, cond, timeout);
}

static inline ssize_t
kfi_cq_sreadfrom(struct kfid_cq *cq, void *buf, size_t count, kfi_addr_t *src_addr,
		const void *cond, int timeout)
{
	return cq->ops->sreadfrom(cq, buf, count, src_addr, cond, timeout);
}

static inline const char *
kfi_cq_strerror(struct kfid_cq *cq, int prov_errno, const void *err_data,
	       char *buf, size_t len)
{
	return cq->ops->strerror(cq, prov_errno, err_data, buf, len);
}


static inline uint64_t kfi_cntr_read(struct kfid_cntr *cntr)
{
	return cntr->ops->read(cntr);
}

static inline uint64_t kfi_cntr_readerr(struct kfid_cntr *cntr)
{
	return cntr->ops->readerr(cntr);
}

static inline int kfi_cntr_add(struct kfid_cntr *cntr, uint64_t value)
{
	return cntr->ops->add(cntr, value);
}

static inline int kfi_cntr_set(struct kfid_cntr *cntr, uint64_t value)
{
	return cntr->ops->set(cntr, value);
}

static inline int
kfi_cntr_wait(struct kfid_cntr *cntr, uint64_t threshold, int timeout)
{
	return cntr->ops->wait(cntr, threshold, timeout);
}


#else /* KFABRIC_DIRECT */
#include <kfi_direct_eq.h>
#endif

#endif /* _KFI_EQ_H_ */
