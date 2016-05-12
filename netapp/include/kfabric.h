/*
 * Copyright (c) 2013-2015 Intel Corporation. All rights reserved.
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

#ifndef _KFABRIC_H_
#define _KFABRIC_H_

enum {
	KFI_MAJOR_VERSION = 1,
	KFI_MINOR_VERSION = 0,
};

#define KFI_VERSION(major, minor)       ((major << 16) | (minor))
#define KFI_MAJOR(version)              (version >> 16)
#define KFI_MINOR(version)              (version & 0xFFFF)
#define KFI_VERSION_GE(v1, v2)          ( (KFI_MAJOR(v1) > KFI_MAJOR(v2)) \
                                        || ( KFI_MAJOR(v1) == KFI_MAJOR(v2) \
                                           && KFI_MINOR(v1) >= KFI_MINOR(v2) ) )

/*
 * Flags
 * The 64-bit flag field is used as follows:
 * 1-grow up    common (usable with multiple operations)
 * 59-grow down operation specific (used for single call/class)
 * 60 - 63      provider specific
 */
enum {
	KFI_MSG = (1ULL << 1),
	KFI_RMA = (1ULL << 2),
	KFI_TAGGED = (1ULL << 3),
	KFI_ATOMIC = (1ULL << 4),
	KFI_ATOMICS = KFI_ATOMIC,

	KFI_READ = (1ULL << 8),
	KFI_WRITE = (1ULL << 9),
	KFI_RECV = (1ULL << 10),
	KFI_SEND = (1ULL << 11),
	KFI_TRANSMIT = KFI_SEND,
	KFI_REMOTE_READ = (1ULL << 12),
	KFI_REMOTE_WRITE = (1ULL << 13),

	KFI_MULTI_RECV = (1ULL << 16),
	KFI_REMOTE_CQ_DATA = (1ULL << 17),
	KFI_MORE = (1ULL << 18),
	KFI_PEEK = (1ULL << 19),
	KFI_TRIGGER = (1ULL << 20),
	KFI_FENCE = (1ULL << 21),

	KFI_COMPLETION = (1ULL << 24),
	KFI_EVENT = KFI_COMPLETION,
	KFI_INJECT = (1ULL << 25),
	KFI_INJECT_COMPLETE = (1ULL << 26),
	KFI_TRANSMIT_COMPLETE = (1ULL << 27),
	KFI_DELIVERY_COMPLETE = (1ULL << 28),

	/* kfi_getinfo()-specific flags/caps */
	KFI_NUMERICHOST = (1ULL << 55),
	KFI_RMA_EVENT = (1ULL << 56),
	KFI_SOURCE = (1ULL << 57),
	KFI_NAMED_RX_CTX = (1ULL << 58),
	KFI_DIRECTED_RECV = (1ULL << 59),

	/* Mode bits */
	KFI_CONTEXT = (1ULL << 59),
	KFI_MSG_PREFIX = (1ULL << 58),
	KFI_ASYNC_IOV = (1ULL << 57),
	KFI_RX_CQ_DATA = (1ULL << 56),
	KFI_LOCAL_MR = (1ULL << 55),
};

struct list_head;

/*
 * KFI object (ID) types and corresponding classes.
 */
struct kfid;
struct kfid_fabric;
struct kfid_domain;
struct kfid_mr;
struct kfid_pep;
struct kfid_ep;
struct kfid_eq;
struct kfid_cq;

typedef struct kfid *kfid_t;

/*
 * KFI attributes, as part of fabric info populated in kfi_getinfo().
 */
struct kfi_eq_attr;
struct kfi_cq_attr;
struct kfi_domain_attr;
struct kfi_tx_attr;
struct kfi_rx_attr;
struct kfi_ep_attr;
typedef uint64_t kfi_addr_t;

struct kfi_fabric_attr {
	struct kfid_fabric      *fabric;
	char                    *name;
	char                    *prov_name;
	uint32_t                prov_version;
};

/*
 * Fabric info, returned by kfi_getinfo for client use.
 */
struct kfi_info {
	struct kfi_info         *next;
	uint64_t                caps;
	uint64_t                mode;
	uint32_t                addr_format;
	size_t                  src_addrlen;
	size_t                  dest_addrlen;
	void                    *src_addr;
	void                    *dest_addr;
	struct kfi_tx_attr      *tx_attr;
	struct kfi_rx_attr      *rx_attr;
	struct kfi_ep_attr      *ep_attr;
	struct kfi_domain_attr  *domain_attr;
	struct kfi_fabric_attr  *fabric_attr;
	struct kfid             *handle;
};

/*
 * Retrieve the fabric info based on given hints. Can return a chain of multiple
 * kfi_info instances.
 */
int kfi_getinfo(uint32_t version, struct kfi_info *hints, struct kfi_info **info);

/*
 * All fabric info instances returned from kfi_getinfo() should be recycled
 * through kfi_freeinfo(). If a chain of multiple kfi_info instances are passed,
 * all instances in the chain will be freed.
 */
void kfi_freeinfo(struct kfi_info *info);

/*
 * KFI base ID, ops and classes.
 */
struct kfi_ops {
	int (*close)(struct kfid *fid);
	int (*bind)(struct kfid *fid, struct kfid *bfid, uint64_t flags);
	int (*control)(struct kfid *fid, int command, void *arg);
	int (*ops_open)(struct kfid *fid, const char *name,
	                uint64_t flags, void **ops, void *context);
};

struct kfid {
        size_t                  fclass;
        void                    *context;
        struct kfi_ops          *ops;
        struct completion       comp;
        atomic_t                ref_cnt;
};

enum {
	KFI_CLASS_UNSPEC,
	KFI_CLASS_FABRIC,
	KFI_CLASS_DOMAIN,
	KFI_CLASS_EP,
	KFI_CLASS_PEP,
	KFI_CLASS_MR,
	KFI_CLASS_EQ,
	KFI_CLASS_CQ,
	KFI_CLASS_CONNREQ,
};

/*
 * KFI fabric ID and ops.
 */
struct kfi_ops_fabric {
	int (*domain)(struct kfid_fabric *fabric, struct kfi_info *info,
	                struct kfid_domain **dom, void *context);
	int (*passive_ep)(struct kfid_fabric *fabric, struct kfi_info *info,
	                struct kfid_pep **pep, void *context);
	int (*eq_open)(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
	                struct kfid_eq **eq, void *context);
};

struct kfid_fabric {
	struct kfid             fid;
	struct kfi_ops_fabric   *ops;
};

/*
 * Create a fabric instance according to fabric attributes returned
 * from kfi_getinfo().
 */
int kfi_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
                void *context);

/*
 * Inline routines to fasciliate access to KFI base ID ops.
 */
static inline int
kfi_open_ops(struct kfid *fid, const char *name, uint64_t flags,
                void **ops, void *context)
{
	return fid->ops->ops_open(fid, name, flags, ops, context);
}

static inline int
kfi_close(struct kfid *fid)
{
	return fid->ops->close(fid);
}

/* control commands */
enum {
	KFI_ENABLE,
};

static inline int
kfi_control(struct kfid *fid, int command, void *arg)
{
	return fid->ops->control(fid, command, arg);
}

#endif /* _KFABRIC_H_ */
