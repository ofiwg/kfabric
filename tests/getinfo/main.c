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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/slab.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Kernel Fabric Interface test: fi_getinfo()");
MODULE_AUTHOR("Sean Hefty<sean.hefty@intel.com>");

/*
 * Port of the fabtest/getinfo code to kfi.
 */

#define SRC_HINT 0	/* 0 sez use ib0 to get the local IF addr.
			 * 1 sez use the module load arg ibv_ipaddr (string)
			 * as the IF address.
			 */

#define PFX "[kfit-info] "
#define DRV_PFX PFX

#define SERVER_PORT 4001

#define LOCAL_IF "10.10.4.40"

static char *ibv_ipaddr = LOCAL_IF;
module_param(ibv_ipaddr, charp, 0000);
MODULE_PARM_DESC(ibv_ipaddr, " InfiniBand IF IPv4 address");

#include <net/kfi/debug.h>
#include <net/kfi/fi_endpoint.h>
#include <net/kfi/fi_errno.h>

char *fi_tostr(const void *data, enum fi_type datatype);

static struct fi_info *getinfo_ibv(char *local_ipaddr)
{
	int			rc = 0;
	struct fi_info		*providers = NULL;
	struct fi_info		hints = { 0 };
	struct fi_fabric_attr	fabric_attr = { 0 };
	struct fi_domain_attr	domain_hints = { 0 };
	struct fi_ep_attr	ep_hints = { 0 };
#if SRC_HINT
	struct sockaddr_in	local_sa = { 0 };

	print_msg("local_ipaddr %s\n", local_ipaddr);

	rc = in4_pton(local_ipaddr, strlen(local_ipaddr),
			(u8 *)&local_sa.sin_addr.s_addr, '\0', NULL);
	if (rc != 1) {
		printk(KERN_INFO PFX "Err converting local IF address '%s'?\n",
			local_ipaddr);
		return NULL;
	}
	local_sa.sin_family = AF_INET;
#endif
	fabric_attr.prov_name = "ibverbs";
#if SRC_HINT == 0
	domain_hints.name = "ib0";	/* provider will set local adrs of */
#endif

	hints.domain_attr = &domain_hints;
	hints.fabric_attr = &fabric_attr;
	hints.ep_attr	= &ep_hints;
	hints.ep_type	= FI_EP_MSG;
	hints.caps	= FI_MSG | FI_CANCEL;
	hints.addr_format = FI_SOCKADDR_IN;
#if SRC_HINT
	hints.src_addr	= &local_sa;
	hints.src_addrlen = sizeof(struct sockaddr_in);
#endif
	rc = fi_getinfo(FI_VERSION(1, 0), &hints, &providers);

	if (rc == 0 && providers)
		return providers;

	print_msg("ERR: fi_getinfo(IBV) '%s'\n", fi_strerror(-rc));

	if (providers)
		fi_freeinfo(providers);

	return NULL;
}


static void display_provider_info(char *prov_name, struct fi_info *providers)
{
	int		num_providers;
	struct fi_info	*fi;
	char		*desc;

	for (fi = providers, num_providers = 0; fi; fi = fi->next) {

		if (!fi->fabric_attr) {
			printk(KERN_INFO PFX "info->fabric_attr NULL?\n");
			continue;
		}

		if (!fi->fabric_attr->prov_name) {
			printk(KERN_INFO PFX
				"info->fabric_attr->prov_name NULL?\n");
			continue;
		}

		desc = fi_tostr((void *) fi, FI_TYPE_INFO);
		if (desc) {
			printk(KERN_INFO PFX "kfi provider '%s' %s\n",
				fi->fabric_attr->prov_name, desc);
			kfree(desc);
		} else
			printk(KERN_INFO PFX "fi tostr() returns NULL?\n");

		num_providers++;
	}
	printk(KERN_INFO PFX "total of %d %s providers\n",
		num_providers, prov_name);
}


static int cli_mod_init(void)
{
	struct fi_info *providers;

	printk(KERN_INFO "\n" PFX "****kfi fi_getinfo() test\n");

	providers = getinfo_ibv(ibv_ipaddr);
	if (providers) {
		display_provider_info("IBV", providers);
		fi_freeinfo(providers);
	}
	return 0;
}
module_init(cli_mod_init);

static void cli_cleanup(void)
{
	printk(KERN_INFO PFX "module unloaded\n");
}
module_exit(cli_cleanup);

