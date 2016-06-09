/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
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

#ifndef _KFI_PROV_H_
#define _KFI_PROV_H_

#include <linux/types.h>
#include <linux/completion.h>
#include <kfabric.h>

/*
 * This header file declares types and routines to be used by KFI
 * providers only. Not to be included by clients of the KFI framework.
 */

/*
 * The provider instance. Each provider instance is uniquely identified
 * by its name.
 */
struct kfi_provider {
	uint32_t version;
	uint32_t kfi_version;
	const char *name;
	int (*kgetinfo)(uint32_t version,
	                struct kfi_info *hints,
	                struct kfi_info **info);
	int (*kfabric)(struct kfi_fabric_attr *attr,
	                struct kfid_fabric **fabric,
	                void *context);
	void (*kfreeinfo)(struct kfi_info *info);
	void (*cleanup)(void);
	struct completion comp;
	atomic_t ref_cnt;
};

/*
 * Each provider must register at least one provider instance to KFI framework.
 * Therefore fabric services of that provider can be found 
 */
int kfi_provider_register(struct kfi_provider *provider);

/*
 * Any provider instances registered to KFI framework must be deregistered
 * before it can be freed.
 */
int kfi_provider_deregister(struct kfi_provider *provider);

/*
 * The provider instance should be referenced / dereferenced when any KFI
 * objects (IDs) are created / destroyed by that provider.
 */
static inline void
kfi_ref_provider(struct kfi_provider *provider)
{
	atomic_inc(&provider->ref_cnt);
};

static inline void
kfi_deref_provider(struct kfi_provider *provider)
{
	if (atomic_dec_and_test(&provider->ref_cnt))
		complete(&provider->comp);
};

/*
 * Helper routine to allocate a kfi_info instance.
 */
struct kfi_info *kfi_allocinfo(void);

/*
 * Helper routine to duplicate a kfi_info instance.
 */
struct kfi_info *kfi_dupinfo(const struct kfi_info *info);

/*
 * Helper routine to recycle a kfi_info instance. Instances returned to clients
 * in kfi_getinfo() should be recycled by clients through kfi_freeinfo().
 */
void kfi_deallocinfo(const struct kfi_info *info);

/*
 * Each KFI object should initialize its reference count through kfi_init_id()
 * immediately after the ID is allocated.
 */
static inline void kfi_init_id(struct kfid *fid)
{
	init_completion(&fid->comp);
	atomic_set(&fid->ref_cnt, 1);
};

/*
 * Each KFI object should be referneced / dereferenced when a provider routine
 * accesses the object, or another KFI object obatains / releases a reference
 * to that object.
 */
static inline void kfi_ref_id(struct kfid *fid)
{
	atomic_inc(&fid->ref_cnt);
};

static inline void kfi_deref_id(struct kfid *fid)
{
	if (atomic_dec_and_test(&fid->ref_cnt))
		complete(&fid->comp);
};

/*
 * Each KFI object should wait for all pending references be released through
 * kfi_close_id() before it can be destroyed.
 */
static inline void kfi_close_id(struct kfid *fid)
{
	kfi_deref_id(fid);
	wait_for_completion(&fid->comp);
};

#endif /* _KFI_PROV_H_ */
