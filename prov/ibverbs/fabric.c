/*
 * Copyright (c) 2015 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/errno.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "ibvp.h"

static LIST_HEAD(device_list);
struct rw_semaphore		list_rwsem;

struct fi_ib_device {
	struct list_head	node;
	struct ib_device	*ib_dev;
};

static void add_one(struct ib_device *ib_dev);
static void remove_one(struct ib_device *ib_dev);

static struct ib_client ib_client = {
	.name   = DRV_NAME,
	.add    = add_one,
	.remove = remove_one
};

int init_driver()
{
	int ret = 0;

	return ret;
}

int cleanup_driver()
{
	ib_unregister_client(&ib_client);

	return 0;
}

#if 0

static struct fi_ib_device *create_device(struct ib_device *ib_dev)
{
	struct fi_ib_device	*device;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device) {
		print_err("kalloc failed!\n");
		return ERR_PTR(-ENOMEM);
	}

	device->ib_dev = ib_dev;

	ib_set_client_data(ib_dev, &ib_client, device);

	down_write(&list_rwsem);
	list_add_tail(&device->node, &device_list);
	up_write(&list_rwsem);

	return device;
}

static void destroy_device(struct fi_ib_device *device)
{
	down_write(&list_rwsem);
	list_del(&device->node);
	up_write(&list_rwsem);

	ib_set_client_data(device->ib_dev, &ib_client, NULL);

	kfree(device);
}

static int ignore_ib_dev(struct ib_device *ib_dev)
{
	/*
	 * Only allow PCI-based channel adapters and RNICs.
	 * PCI is required in order to read the vendor id.
	 */
	return (!ib_dev->dma_device->bus			  ||
		!ib_dev->dma_device->bus->name			  ||
		strnicmp(ib_dev->dma_device->bus->name, "pci", 3) ||
		((ib_dev->node_type != RDMA_NODE_IB_CA) &&
		 (ib_dev->node_type != RDMA_NODE_RNIC))) ? 1 : 0;
}

static void add_one(struct ib_device *ib_dev)
{
	struct fi_ib_device	*device;

	if (ignore_ib_dev(ib_dev))
		return;

	device = create_device(ib_dev);
	if (IS_ERR(device))
		return;
}

static void remove_one(struct ib_device *ib_dev)
{
	struct fi_ib_device	*device;

	device = ib_get_client_data(ib_dev, &ib_client);
	if (!device)
		return;

	destroy_device(device);
}

static struct ib_device *find_device(const char *name)
{
	struct fi_ib_device	*dev;

	down_write(&list_rwsem);

	list_for_each_entry(dev, &device_list, node)
		if (!strncmp(dev->ib_dev->name, name, IB_DEVICE_NAME_MAX))
			break;

	up_write(&list_rwsem);

	if (dev)
		return dev->ib_dev;
	else
		return NULL;
}

int fi_ib_domain_close(struct fid *fid)
{
	struct fi_ib_domain	*domain = (struct fi_ib_domain *) fid;

	print_trace("in\n");

	if (domain->pd)
		ib_dealloc_pd(domain->pd);

	kfree(domain);

	return 0;
}
#endif

static struct fi_ops fi_ib_fid_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_no_domain_close,
	.bind		= fi_no_bind,
	.control	= fi_no_control,
	.ops_open	= fi_no_ops_open,
};

static struct fi_ops_mr fi_ib_domain_mr_ops = {
	.size		= sizeof(struct fi_ops_mr),
	.reg		= fi_no_mr_reg,
	.regv		= fi_no_mr_regv,
	.regattr	= fi_no_mr_regattr,
};

static struct fi_ops_domain fi_ib_domain_ops = {
	.size		= sizeof(struct fi_ops_domain),
	.av_open	= fi_no_av_open,
	.cq_open	= fi_no_cq_open,
	.endpoint	= fi_no_ep_open,
	.cntr_open	= fi_no_cntr_open,
	.poll_open	= fi_no_poll_open,
};

#if 0

static int fi_ib_domain(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_domain **_domain, void *context)
{
	struct fi_ib_domain	*domain;
	int			ret;

	print_trace("in\n");

	if (!info || !info->domain_attr || !info->domain_attr->name) {
		print_err("no device name in domain_attr\n");
		return -FI_EINVAL;
	}

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain) {
		print_err("kalloc failed!\n");
		return -FI_ENOMEM;
	}

	domain->device = find_device(info->domain_attr->name);
	if (!domain->device) {
		ret = PTR_ERR(domain->device);
		print_err("ib_device_get_by_name returned %d\n", ret);
		domain->device = NULL;
		goto err;
	}

	domain->pd = ib_alloc_pd(domain->device);
	if (IS_ERR(domain->pd)) {
		ret = PTR_ERR(domain->pd);
		print_err("ib_alloc_pd returned %d\n", ret);
		domain->pd = NULL;
		goto err;
	}

	domain->domain_fid.fid.fclass = FI_CLASS_DOMAIN;
	domain->domain_fid.fid.context = context;
	domain->domain_fid.fid.ops = &fi_ib_fid_ops;
	domain->domain_fid.ops = &fi_ib_domain_ops;
	domain->domain_fid.mr = &fi_ib_domain_mr_ops;

	*_domain = &domain->domain_fid;

	return 0;
err:
	kfree(domain);

	return ret;
}

static int fi_ib_fabric_close(struct fid *fid)
{
	print_trace("in\n");

	kfree(fid);

	return 0;
}
#endif

static struct fi_ops fi_ib_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= fi_no_fabric_close,
	.bind		= fi_no_bind,
	.control	= fi_no_control,
	.ops_open	= fi_no_ops_open,
};

static struct fi_ops_fabric fi_ib_ops_fabric = {
	.size		= sizeof(struct fi_ops_fabric),
	.domain		= fi_ib_domain,
	.passive_ep	= fi_no_pendpoint,
	.eq_open	= fi_no_eq_open,
};

#if 0

int fi_ib_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		 void *context)
{
	struct fi_ib_fabric	*fab;

	print_trace("in\n");

	if (strcmp(attr->prov_name, IBV_PROVIDER_NAME))
		return -FI_ENODATA;

	fab = kzalloc(sizeof(*fab), GFP_KERNEL);
	if (!fab) {
		print_err("kalloc failed!\n");
		return -FI_ENOMEM;
	}

	fab->fabric_fid.fid.fclass	= FI_CLASS_FABRIC;
	fab->fabric_fid.fid.context	= context;
	fab->fabric_fid.fid.ops		= &fi_ib_fi_ops;
	fab->fabric_fid.ops		= &fi_ib_ops_fabric;

	*fabric	 = &fab->fabric_fid;

	return 0;
}
#endif
