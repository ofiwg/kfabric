/*
 * Copyright (c) 2015 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
 *
 *	   Redistribution and use in source and binary forms, with or
 *	   without modification, are permitted provided that the following
 *	   conditions are met:
 *
 *		- Redistributions of source code must retain the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer.
 *
 *		- Redistributions in binary form must reproduce the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer in the documentation and/or other materials
 *		  provided with the distribution.
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
 * Kernel OpenFabrics Interface (kfi)
 *	Provide a fabric device agnostic interface.
 *	Fabric device providers register/unregister with kfi.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>

#include "net/kfi/kfi_internal.h"
#include "net/kfi/kfi_provider.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Kernel OpenFabrics Interface");
MODULE_AUTHOR("Stan C. Smith <stan.smith@intel.com>");

#ifdef KFI_DEBUG
MODULE_PARAM(debug, debug_level, int, 0, "Debug: 0-none, 3-medium, 7-all");
#endif

struct list_head kfi_providers;
struct mutex kfi_provider_list_mutex;
int num_kfi_providers;

static struct ctl_table_header *kfi_sysctl_reg_table;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)

static struct ctl_path kfi_sysctl_path[] = {
	{ .procname = "net", .ctl_name = CTL_NET, },
	{ .procname = "kfabric", .ctl_name = CTL_UNNUMBERED, },
	{ }
};

static struct ctl_table kfabric_sysctl_table[] = {
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname	= "num_providers",
		.data		= &num_kfi_providers,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler   = &proc_dointvec,
	},
	{ }
};
#else
static struct ctl_table kfabric_sysctl_table[] = {
	{
		.procname	= "num_providers",
		.data		= &num_kfi_providers,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{ }
};
#endif

static int kfi_init_module(void)
{
	print_info("kfabric loading\n");

	print_dbg("Initializing version %d.%d\n",
		  FI_MAJOR_VERSION, FI_MINOR_VERSION);

	INIT_LIST_HEAD(&kfi_providers);
	mutex_init(&kfi_provider_list_mutex);
	num_kfi_providers = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
	kfi_sysctl_reg_table = register_sysctl_paths(kfi_sysctl_path,
						kfabric_sysctl_table);
#else
	kfi_sysctl_reg_table = register_net_sysctl(&init_net, "net/kfabric",
						kfabric_sysctl_table);
#endif
	if (!kfi_sysctl_reg_table)
		print_err("Failed to register '/proc/sys/net/kfabric'?\n");

	print_info("kfabric loaded.\n");

	return 0;
}
module_init(kfi_init_module);

static int kfi_registered_providers(int verbose)
{
	struct list_head *pos;
	struct kfi_prov *prov;
	int i = 0;

	if (verbose)
		print_dbg("Current kfabric providers:\n");

	mutex_lock(&kfi_provider_list_mutex);
	list_for_each(pos, &kfi_providers) {
		prov = list_entry(pos, struct kfi_prov, plist);
		if (verbose)
			print_dbg("  %s\n", prov->provider->name);
		i++;
	}
	mutex_unlock(&kfi_provider_list_mutex);

	if (verbose)
		print_dbg("total(%d)\n", i);

	return i;
}

static void kfi_cleanup_module(void)
{
	print_trace("Begin\n");

	(void) kfi_registered_providers(1);

	if (kfi_sysctl_reg_table)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
		unregister_sysctl_table(kfi_sysctl_reg_table);
#else
		unregister_net_sysctl_table(kfi_sysctl_reg_table);
#endif

	print_trace("End\n");

	print_info("kfabric unloaded\n");

}
module_exit(kfi_cleanup_module);
