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

#ifndef _KFI_PROVIDER_H_
#define _KFI_PROVIDER_H_

#include <net/kfi/fabric.h>

#include <net/kfi/kfi.h>

struct kfi_provider {
	const char *name;
	uint32_t version;
	int	(*getinfo)(uint32_t version, struct fi_info *hints,
			struct fi_info **info);
	int	(*freeinfo)(struct fi_info *info);
	int	(*fabric)(struct fi_fabric_attr *attr,
			struct fid_fabric **fabric, void *context);
};


int kfi_register_provider(uint32_t version, struct kfi_provider *provider);
int kfi_deregister_provider(struct kfi_provider *provider);

struct fi_info *fi_allocinfo(void);
void fi_freeinfo(struct fi_info *info);

#endif /* _KFI_PROVIDER_H_ */
