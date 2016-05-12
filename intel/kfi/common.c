/*
 * Copyright (c) 2015 Intel Corp., Inc.  All rights reserved.
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

#include <net/kfi/kfi.h>

#include <net/kfi/fabric.h>
#include <net/kfi/fi_errno.h>


void fi_freeinfo_internal(struct fi_info *info)
{
	kfree(info->src_addr);
	kfree(info->dest_addr);
	kfree(info->tx_attr);
	kfree(info->rx_attr);
	kfree(info->ep_attr);
	if (info->domain_attr) {
		kfree(info->domain_attr->name);
		kfree(info->domain_attr);
	}
	if (info->fabric_attr) {
		kfree(info->fabric_attr->name);
		kfree(info->fabric_attr->prov_name);
		kfree(info->fabric_attr);
	}
	kfree(info);
}

struct fi_info *fi_allocinfo(void)
{
	struct fi_info *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return NULL;

	info->tx_attr = kzalloc(sizeof(*info->tx_attr), GFP_KERNEL);
	info->rx_attr = kzalloc(sizeof(*info->rx_attr), GFP_KERNEL);
	info->ep_attr = kzalloc(sizeof(*info->ep_attr), GFP_KERNEL);
	info->domain_attr = kzalloc(sizeof(*info->domain_attr), GFP_KERNEL);
	info->fabric_attr = kzalloc(sizeof(*info->fabric_attr), GFP_KERNEL);

	if (!info->tx_attr || !info->rx_attr || !info->ep_attr ||
	    !info->domain_attr || !info->fabric_attr) {
		fi_freeinfo_internal(info);
		info = NULL;
	}

	return info;
}
EXPORT_SYMBOL(fi_allocinfo);

