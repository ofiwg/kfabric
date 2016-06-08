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

#ifndef _KFABRIC_H_
#define _KFABRIC_H_

#include <linux/types.h>
#include <linux/kernel.h>

#define KFI_DEFINE_HANDLE(name) struct name##_s { int dummy; }; \
				typedef struct name##_s *name

enum {
	KFI_MAJOR_VERSION	= 1,
	KFI_MINOR_VERSION	= 0,
	KFI_PATH_MAX		= 256,
	KFI_NAME_MAX		= 64,
	KFI_VERSION_MAX		= 64
};

#define KFI_VERSION(major, minor) ((major << 16) | (minor))
#define KFI_MAJOR(version)	(version >> 16)
#define KFI_MINOR(version)	(version & 0xFFFF)
#define KFI_VERSION_GE(v1, v2) \
	((KFI_MAJOR(v1) > KFI_MAJOR(v2)) || \
	 (KFI_MAJOR(v1) == KFI_MAJOR(v2) && KFI_MINOR(v1) == KFI_MINOR(v2)) || \
	 (KFI_MAJOR(v1) == KFI_MAJOR(v2) && KFI_MINOR(v1) > KFI_MINOR(v2)))

#ifndef UINT64_MAX
#define UINT64_MAX (~0UL)
#endif

uint32_t kfi_version(void);

struct kfid;
struct kfid_fabric;
struct kfid_domain;
struct kfid_av;
struct kfid_wait;
struct kfid_poll;
struct kfid_eq;
struct kfid_cq;
struct kfid_cntr;
struct kfid_ep;
struct kfid_pep;
struct kfid_stx;
struct kfid_mr;

/*
 * Provider specific values are indicated by setting the high-order bit.
 */
#define KFI_PROV_SPECIFIC	(1 << 31)

/* kfi_info and operation flags - pass into endpoint ops calls.
 * A user may also set these on a endpoint by using fcntl, which has the
 * affect of applying them to all applicable operations.
 */

/* FI capabilities */
#define KFI_MSG			(1ULL << 1)
#define KFI_RMA			(1ULL << 2)
#define KFI_TAGGED		(1ULL << 3)
#define KFI_ATOMIC		(1ULL << 4)
#define KFI_ATOMICS		KFI_ATOMIC
#define KFI_DYNAMIC_MR		(1ULL << 7)
#define KFI_NAMED_RX_CTX	(1ULL << 8)
#define KFI_BUFFERED_RECV	(1ULL << 9)
#define KFI_DIRECTED_RECV	(1ULL << 10)

/*
 * Flags
 * The 64-bit flag field is divided as follows:
 * bits		use
 *  0 - 10	operation specific (used for a single call)
 * 11 - 32	common (usable with multiple operations)
 * 33 - 59	reserved
 * 60 - 63	provider specific
 */

#define KFI_INJECT		(1ULL << 11)
#define KFI_MULTI_RECV		(1ULL << 12)
#define KFI_SOURCE		(1ULL << 13)
#define KFI_SYMMETRIC		(1ULL << 14)

#define KFI_READ			(1ULL << 16)
#define KFI_WRITE		(1ULL << 17)
#define KFI_RECV			(1ULL << 18)
#define KFI_SEND			(1ULL << 19)
#define KFI_TRANSMIT		KFI_SEND
#define KFI_REMOTE_READ		(1ULL << 20)
#define KFI_REMOTE_WRITE	(1ULL << 21)

#define KFI_REMOTE_CQ_DATA	(1ULL << 24)
#define KFI_EVENT		(1ULL << 25)
#define KFI_COMPLETION		KFI_EVENT
#define KFI_REMOTE_SIGNAL	(1ULL << 26)
#define KFI_REMOTE_COMPLETE	(1ULL << 27)
#define KFI_CANCEL		(1ULL << 28)
#define KFI_MORE		(1ULL << 29)
#define KFI_PEEK		(1ULL << 30)
#define KFI_TRIGGER		(1ULL << 31)
#define KFI_FENCE		(1ULL << 32)


struct kfi_ioc {
	void			*addr;
	size_t			count;
};

/*
 * Format for transport addresses: sendto, writeto, etc.
 */
enum {
	KFI_FORMAT_UNSPEC,	/* void * */
	KFI_SOCKADDR,		/* struct sockaddr */
	KFI_SOCKADDR_IN,	/* struct sockaddr_in */
	KFI_SOCKADDR_IN6,	/* struct sockaddr_in6 */
	KFI_SOCKADDR_IB,	/* struct sockaddr_ib */
	KFI_ADDR_PSMX,		/* uint64_t */
};

#define KFI_ADDR_UNSPEC		UINT64_MAX
#define KFI_ADDR_NOTAVAIL	UINT64_MAX
#define KFI_SHARED_CONTEXT	UINT64_MAX
typedef uint64_t	kfi_addr_t;
KFI_DEFINE_HANDLE(kfi_connreq_t);

enum kfi_progress {
	KFI_PROGRESS_UNSPEC,
	KFI_PROGRESS_AUTO,
	KFI_PROGRESS_MANUAL
};

enum kfi_threading {
	KFI_THREAD_UNSPEC,
	KFI_THREAD_SAFE,
	KFI_THREAD_FID,
	KFI_THREAD_DOMAIN,
	KFI_THREAD_COMPLETION,
	KFI_THREAD_ENDPOINT,
};

enum kfi_resource_mgmt {
	KFI_RM_UNSPEC,
	KFI_RM_DISABLED,
	KFI_RM_ENABLED
};

#define KFI_ORDER_NONE		0
#define KFI_ORDER_RAR		(1 << 0)
#define KFI_ORDER_RAW		(1 << 1)
#define KFI_ORDER_RAS		(1 << 2)
#define KFI_ORDER_WAR		(1 << 3)
#define KFI_ORDER_WAW		(1 << 4)
#define KFI_ORDER_WAS		(1 << 5)
#define KFI_ORDER_SAR		(1 << 6)
#define KFI_ORDER_SAW		(1 << 7)
#define KFI_ORDER_SAS		(1 << 8)
#define KFI_ORDER_RECV		(1 << 9)
#define KFI_ORDER_STRICT	0xFFFFFFFF

enum kfi_ep_type {
	KFI_EP_UNSPEC,
	KFI_EP_MSG,
	KFI_EP_DGRAM,
	KFI_EP_RDM,
	/* KFI_EP_RAW, */
	/* KFI_EP_PACKET, */
};

/* Endpoint protocol
 * If two providers support the same protocol, then they shall interoperate
 * when the protocol capabilities match.
 */
enum {
	KFI_PROTO_UNSPEC,
	KFI_PROTO_RDMA_CM_IB_RC,
	KFI_PROTO_IWARP,
	KFI_PROTO_IB_UD,
	KFI_PROTO_PSMX,
	KFI_PROTO_UDP,
	KFI_PROTO_SOCK_TCP
};

/* Mode bits */
#define KFI_CONTEXT		(1ULL << 0)
#define KFI_LOCAL_MR		(1ULL << 1)
#define KFI_PROV_MR_ATTR	(1ULL << 2)
#define KFI_MSG_PREFIX		(1ULL << 3)
#define KFI_ASYNC_IOV		(1ULL << 4)

struct kfi_tx_attr {
	uint64_t		caps;
	uint64_t		mode;
	uint64_t		op_flags;
	uint64_t		msg_order;
	uint64_t		comp_order;
	size_t			inject_size;
	size_t			size;
	size_t			iov_limit;
	size_t			rma_iov_limit;
};

struct kfi_rx_attr {
	uint64_t		caps;
	uint64_t		mode;
	uint64_t		op_flags;
	uint64_t		msg_order;
	uint64_t		comp_order;
	size_t			total_buffered_recv;
	size_t			size;
	size_t			iov_limit;
};

struct kfi_ep_attr {
	uint32_t		protocol;
	uint32_t		protocol_version;
	size_t			max_msg_size;
	size_t			inject_size;
	size_t			total_buffered_recv;
	size_t			msg_prefix_size;
	size_t			max_order_raw_size;
	size_t			max_order_war_size;
	size_t			max_order_waw_size;
	uint64_t		mem_tag_format;
	uint64_t		msg_order;
	uint64_t		comp_order;
	size_t			tx_ctx_cnt;
	size_t			rx_ctx_cnt;
};

struct kfi_domain_attr {
	struct kfid_domain	*domain;
	char			*name;
	enum kfi_threading	threading;
	enum kfi_progress	control_progress;
	enum kfi_progress	data_progress;
	enum kfi_resource_mgmt	resource_mgmt;
	size_t			mr_key_size;
	size_t			cq_data_size;
	size_t			cq_cnt;
	size_t			ep_cnt;
	size_t			tx_ctx_cnt;
	size_t			rx_ctx_cnt;
	size_t			max_ep_tx_ctx;
	size_t			max_ep_rx_ctx;
};

struct kfi_fabric_attr {
	struct kfid_fabric	*fabric;
	char			*name;
	char			*prov_name;
	uint32_t		prov_version;
};

struct kfi_info {
	struct kfi_info		*next;
	uint64_t		caps;
	uint64_t		mode;
	enum kfi_ep_type	ep_type;
	uint32_t		addr_format;
	size_t			src_addrlen;
	size_t			dest_addrlen;
	void			*src_addr;
	void			*dest_addr;
	kfi_connreq_t		connreq;
	struct kfi_tx_attr	*tx_attr;
	struct kfi_rx_attr	*rx_attr;
	struct kfi_ep_attr	*ep_attr;
	struct kfi_domain_attr	*domain_attr;
	struct kfi_fabric_attr	*fabric_attr;
};

enum {
	KFI_CLASS_UNSPEC,
	KFI_CLASS_FABRIC,
	KFI_CLASS_DOMAIN,
	KFI_CLASS_EP,
	KFI_CLASS_SEP,
	KFI_CLASS_RX_CTX,
	KFI_CLASS_SRX_CTX,
	KFI_CLASS_TX_CTX,
	KFI_CLASS_STX_CTX,
	KFI_CLASS_PEP,
	KFI_CLASS_INTERFACE,
	KFI_CLASS_AV,
	KFI_CLASS_MR,
	KFI_CLASS_EQ,
	KFI_CLASS_CQ,
	KFI_CLASS_CNTR,
	KFI_CLASS_WAIT,
	KFI_CLASS_POLL
};

struct kfi_eq_attr;
struct kfi_wait_attr;

struct kfi_ops {
	size_t	size;
	int	(*close)(struct kfid *kfid);
	int	(*bind)(struct kfid *kfid, struct kfid *bkfid, uint64_t flags);
	int	(*control)(struct kfid *kfid, int command, void *arg);
	int	(*ops_open)(struct kfid *kfid, const char *name,
			uint64_t flags, void **ops, void *context);
};

/* All fabric interface descriptors must start with this structure */
struct kfid {
	size_t			fclass;
	void			*context;
	struct kfi_ops		*ops;
};

#define KFI_NUMERICHOST		(1ULL << 1)

uint32_t kfi_version(void);
int kfi_getinfo(uint32_t version, struct kfi_info *hints,
		struct kfi_info **info);
void kfi_freeinfo(struct kfi_info *info);
struct kfi_info *kfi_dupinfo(const struct kfi_info *info);

struct kfi_ops_fabric {
	size_t	size;
	int	(*domain)(struct kfid_fabric *fabric, struct kfi_info *info,
			struct kfid_domain **dom, void *context);
	int	(*passive_ep)(struct kfid_fabric *fabric, struct kfi_info *info,
			struct kfid_pep **pep, void *context);
	int	(*eq_open)(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
			struct kfid_eq **eq, void *context);
	int	(*wait_open)(struct kfid_fabric *fabric,
			struct kfi_wait_attr *attr, struct kfid_wait **waitset);
};

struct kfid_fabric {
	struct kfid		kfid;
	struct kfi_ops_fabric	*ops;
};

int kfi_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
	       void *context);

#define KFI_CHECK_OP(ops, opstype, op) \
	((ops->size > offsetof(opstype, op)) && ops->op)

static inline int kfi_close(struct kfid *kfid)
{
	return kfid->ops->close(kfid);
}

struct kfi_alias {
	struct kfid	**kfid;
	uint64_t	flags;
};

/* control commands */
enum {
	KFI_GETFIDFLAG,		/* uint64_t flags */
	KFI_SETFIDFLAG,		/* uint64_t flags */
	KFI_GETOPSFLAG,		/* uint64_t flags */
	KFI_SETOPSFLAG,		/* uint64_t flags */

	/* Duplicate a kfid_t.  This allows for 2 kfids that refer to a single
	 * HW resource.  Each kfid may reference functions that are optimized
	 * for different use cases.
	 */
	KFI_ALIAS,		/* struct kfi_alias * */
	KFI_GETWAIT,		/* void * wait object */
	KFI_ENABLE,		/* NULL */
};

static inline int kfi_control(struct kfid *kfid, int command, void *arg)
{
	return kfid->ops->control(kfid, command, arg);
}

static inline int kfi_alias(struct kfid *kfid, struct kfid **alias_kfid,
			    uint64_t flags)
{
	struct kfi_alias alias;
	alias.kfid = alias_kfid;
	alias.flags = flags;
	return kfi_control(kfid, KFI_ALIAS, &alias);
}

static inline int
kfi_open_ops(struct kfid *kfid, const char *name, uint64_t flags,
	    void **ops, void *context)
{
	return kfid->ops->ops_open(kfid, name, flags, ops, context);
}

enum kfi_type {
	KFI_TYPE_INFO,
	KFI_TYPE_EP_TYPE,
	KFI_TYPE_CAPS,
	KFI_TYPE_OP_FLAGS,
	KFI_TYPE_ADDR_FORMAT,
	KFI_TYPE_TX_ATTR,
	KFI_TYPE_RX_ATTR,
	KFI_TYPE_EP_ATTR,
	KFI_TYPE_DOMAIN_ATTR,
	KFI_TYPE_FABRIC_ATTR,
	KFI_TYPE_THREADING,
	KFI_TYPE_PROGRESS,
	KFI_TYPE_PROTOCOL,
	KFI_TYPE_MSG_ORDER,
	KFI_TYPE_MODE,
	KFI_TYPE_AV_TYPE,
	KFI_TYPE_ATOMIC_TYPE,
	KFI_TYPE_ATOMIC_OP,
	KFI_TYPE_VERSION,
};

char *kfi_tostr(const void *data, enum kfi_type datatype);


#ifndef KFABRIC_DIRECT

struct kfi_context {
	void	*internal[4];
};

#else /* KFABRIC_DIRECT */
#include <kfi_direct.h>
#endif

#endif /* _KFABRIC_H_ */
