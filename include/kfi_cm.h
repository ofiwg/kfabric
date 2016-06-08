/*
 * Copyright (c) 2013-2016 Intel Corporation. All rights reserved.
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

#ifndef _KFI_CM_H_
#define _KFI_CM_H_

#include <kfi_endpoint.h>

struct kfi_ops_cm {
	size_t	size;
	int	(*getname)(struct kfid *kfid, void *addr, size_t *addrlen);
	int	(*getpeer)(struct kfid_ep *ep, void *addr, size_t *addrlen);
	int	(*connect)(struct kfid_ep *ep, const void *addr,
			const void *param, size_t paramlen);
	int	(*listen)(struct kfid_pep *pep);
	int	(*accept)(struct kfid_ep *ep, const void *param,
			size_t paramlen);
	int	(*reject)(struct kfid_pep *pep, kfi_connreq_t connreq,
			const void *param, size_t paramlen);
	int	(*shutdown)(struct kfid_ep *ep, uint64_t flags);
};


#ifndef KFABRIC_DIRECT

static inline int kfi_getname(struct kfid *kfid, void *addr, size_t *addrlen)
{
	struct kfid_ep *ep = container_of(kfid, struct kfid_ep, kfid);
	return ep->cm->getname(kfid, addr, addrlen);
}

static inline int kfi_getpeer(struct kfid_ep *ep, void *addr, size_t *addrlen)
{
	return ep->cm->getpeer(ep, addr, addrlen);
}

static inline int kfi_listen(struct kfid_pep *pep)
{
	return pep->cm->listen(pep);
}

static inline int
kfi_connect(struct kfid_ep *ep, const void *addr,
	   const void *param, size_t paramlen)
{
	return ep->cm->connect(ep, addr, param, paramlen);
}

static inline int
kfi_accept(struct kfid_ep *ep, const void *param, size_t paramlen)
{
	return ep->cm->accept(ep, param, paramlen);
}

static inline int
kfi_reject(struct kfid_pep *pep, kfi_connreq_t connreq,
	  const void *param, size_t paramlen)
{
	return pep->cm->reject(pep, connreq, param, paramlen);
}

static inline int kfi_shutdown(struct kfid_ep *ep, uint64_t flags)
{
	return ep->cm->shutdown(ep, flags);
}

#else /* KFABRIC_DIRECT */
#include <kfi_direct_cm.h>
#endif

#endif /* _KFI_CM_H_ */
