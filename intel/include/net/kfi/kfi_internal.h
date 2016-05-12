/*
 * Copyright (c) 2015 Intel Corporation. All rights reserved.
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

#ifndef _KFI_INTERNAL_H_
#define _KFI_INTERNAL_H_

#include <linux/kernel.h>
#include <linux/byteorder/generic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/string.h>

#include <net/kfi/kfi.h>

#define DRV_NAME "kfi"
#define DRV_PFX "[" DRV_NAME "] "

extern struct list_head kfi_providers;
extern struct mutex kfi_provider_list_mutex;
extern int num_kfi_providers;

struct kfi_prov {
	struct list_head	plist;
	struct kfi_provider	*provider;
};

void fi_freeinfo_internal(struct fi_info *info);

#endif /* _KFI_INTERNAL_H_ */
