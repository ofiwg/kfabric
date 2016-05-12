/*
 * Copyright (c) 2015 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

/*
 * KFI (Kernel Fabric Interface) InfiniBand verbs provider
 *   depends on kernel verbs modules:
 *	ib_core ib_cm ib_sa ib_mad ib_addr rdma_cm
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/uio.h>

#include <rdma/ib_verbs.h>

#include "ibvp.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("KFI InfiniBand verbs provider");
MODULE_AUTHOR("Jay Sternberg <jay.e.sternberg@intel.com>");

MODULE_PARAM(debug, debug_level, int, -1,
	     "Debug bit mask: 0-none, 1-general, 8-trace, 0x10-connect");

static int
fi_ib_getinfo(uint32_t version, struct fi_info *hints, struct fi_info **info);

static int fi_ib_freeinfo(struct fi_info *info);
static int fi_ib_create_fabric(struct fi_fabric_attr *attr,
			       struct fid_fabric **fabric, void *context);

static int initialized = 0;

static struct kfi_provider ibvp = {
	.name = IBV_PROVIDER_NAME,
	.version = FI_VERSION(1, 0),
	.getinfo = fi_ib_getinfo,
	.freeinfo = fi_ib_freeinfo,
	.fabric = fi_ib_create_fabric
};

static int init(void)
{
	int ret;

	print_trace("in\n");

	print_info("kfabric/ibv provider initializing: version %d.%d.\n",
		   FI_MAJOR(ibvp.version), FI_MINOR(ibvp.version));

	ret = kfi_register_provider(ibvp.version, &ibvp);
	if (ret) {
		print_err("register returned %d for KFI %s provider\n",
			  ret, ibvp.name);
		return ret;
	}

	// ret = init_driver();
	if (ret) {
		print_err("init_driver returned %d for KFI %s provider\n",
			  ret, ibvp.name);
		kfi_deregister_provider(&ibvp);
		return ret;
	}

	initialized++;

	print_dbg("KFI provider '%s' registered.\n", ibvp.name);

	print_info("kfabric/ibv provider loaded\n");

	return 0;
}
module_init(init);

static void cleanup(void)
{
	print_trace("in\n");

	if (initialized) {
		int ret;

		// cleanup_driver();

		ret = kfi_deregister_provider(&ibvp);
		if (ret)
			print_err("deregister returned %d KFI %s provider\n",
				  ret, ibvp.name);
		else
			print_dbg("deregistered KFI provider '%s'\n",
				  ibvp.name);
	}

	initialized = 0;
	print_info("KFI/IBV provider unloaded.\n");
}
module_exit(cleanup);

static int fi_ib_getinfo(uint32_t version, struct fi_info *hints,
			 struct fi_info **info)
{
	return -ENOSYS;
}

static int fi_ib_freeinfo(struct fi_info *info)
{
	print_trace("in\n");
	if (!info)
		return -EINVAL;

	return -ENOSYS;
#if 0
	/* prevent recursion via def of fi_freeinfo() */
	if (info->fabric_attr) {
		kfree(info->fabric_attr->name);
		kfree(info->fabric_attr->prov_name);
		kfree(info->fabric_attr);
		info->fabric_attr = NULL;
	}

	fi_freeinfo(info);

	return 0;
#endif
}

static int fi_ib_create_fabric(struct fi_fabric_attr *attr,
			       struct fid_fabric **fabric, void *context)
{
	return -ENOSYS;
}

