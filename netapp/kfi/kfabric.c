/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006-2015 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 Intel Corporation. All rights reserved.
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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_domain.h>
#include <kfi_prov.h>
#include <kfi_endpoint.h>
#include <kfi_log.h>

MODULE_AUTHOR("Frank Yang, Chen Zhao");
MODULE_DESCRIPTION("Open Fabric Interface Framework");
MODULE_LICENSE("Dual BSD/GPL");

struct kfi_prov {
	struct list_head        list;
	struct kfi_provider     *provider;
};

static LIST_HEAD(prov_list);
static DEFINE_MUTEX(prov_mutex);

/*
 * Helper routine to find the kfi_prov instance with the given provider name.
 * Provider list mutex must be held when calling kfi_get_prov().
 */
static struct kfi_prov *kfi_getprov(const char *prov_name);

/*
 * Helper routine to invoke clean up ops, if implemented, before de-listing
 * a provider.
 */
static void cleanup_provider(struct kfi_provider *provider);

static int __init
kfi_init(void)
{
	LOG_INFO("Kernel Open Fabric Interface framework loaded.");
	return 0;
}

static void __exit
kfi_exit(void)
{
	struct kfi_prov *prov = NULL;
	struct list_head *lh = NULL, *tmp = NULL;

	mutex_lock(&prov_mutex);
	list_for_each_safe(lh, tmp, &prov_list) {
		prov = list_entry(lh, typeof(*prov), list);
		list_del(&prov->list);
		kfree(prov);
		LOG_WARN("Found a stale provider instances, forced clean up.");
	}
	mutex_unlock(&prov_mutex);
	LOG_INFO("Kernel Open Fabric Interface framework unloaded.");
	return;
}

int
kfi_getinfo(uint32_t version, struct kfi_info *hints, struct kfi_info **info)
{
	struct list_head *lh = NULL;
	struct kfi_prov *prov = NULL;
	struct kfi_info *tail = NULL, *cur = NULL;
	struct kfi_provider *provider = NULL;
	struct kfi_fabric_attr *attr = NULL;
	char * hints_name = NULL;
	int ret = -ENODATA;
	*info = NULL;

	if (hints && hints->fabric_attr && hints->fabric_attr->prov_name) {
		hints_name = hints->fabric_attr->prov_name;
	}
	mutex_lock(&prov_mutex);
	list_for_each(lh, &prov_list) {
		prov = list_entry(lh, typeof(*prov), list);
		provider = prov->provider;

		if (!provider->kgetinfo) {
			continue;
		}
		if (hints_name && strcmp(provider->name, hints_name)) {
			continue;
		}

		ret = provider->kgetinfo(version, hints, &cur);
		if (ret) {
			if (ret != -ENODATA) {
				LOG_WARN("kfi_getinfo: provider %s returned %d",
				         provider->name, ret);
				kfi_deallocinfo(cur);
			}
			continue;
		}

		if (!*info) {
			*info = cur;
		} else {
			tail->next = cur;
		}
		for (tail = cur; tail; tail = tail->next) {
			attr = tail->fabric_attr;
			if (attr && !attr->prov_name) {
				attr->prov_name = kstrdup(provider->name, GFP_KERNEL);
				attr->prov_version = provider->version;
			}
		}
	}
	mutex_unlock(&prov_mutex);

	return *info ? 0 : ret;
}
EXPORT_SYMBOL(kfi_getinfo);

void
kfi_freeinfo(struct kfi_info *info)
{
	kfi_deallocinfo(info);
	return;
}
EXPORT_SYMBOL(kfi_freeinfo);

int
kfi_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
                void *context)
{
	struct kfi_prov *prov = NULL;
	int ret = 0;

	if (!attr || !attr->prov_name || !attr->name) {
		return -EINVAL;
	}

	mutex_lock(&prov_mutex);
	prov = kfi_getprov(attr->prov_name);
	if (!prov) {
		ret = -ENODEV;
		goto cleanup;
	}
	kfi_ref_provider(prov->provider);
	ret = prov->provider->kfabric(attr, fabric, context);

cleanup:
	if (prov) {
		kfi_deref_provider(prov->provider);
	}
	mutex_unlock(&prov_mutex);
	return ret;
}
EXPORT_SYMBOL(kfi_fabric);

int
kfi_provider_register(struct kfi_provider *provider)
{
	struct kfi_prov *prov = NULL;
	struct kfi_provider *ex_provider = NULL;
	int ret = 0;

	if (!provider || !provider->name) {
		return -EINVAL;
	}

	init_completion(&provider->comp);
	atomic_set(&provider->ref_cnt, 1);

	if (KFI_MAJOR(provider->kfi_version) != KFI_MAJOR_VERSION ||
	    KFI_MINOR(provider->kfi_version) > KFI_MINOR_VERSION) {
		LOG_ERR("Provider %s ignored. Provider requries KFI version %d.%d, \
		       incompatible with current KFI version %d.%d.",
		       provider->name,
		       KFI_MAJOR(provider->kfi_version),
		       KFI_MINOR(provider->kfi_version),
		       KFI_MAJOR_VERSION,
		       KFI_MINOR_VERSION);
		ret = -ENOSYS;
		goto err;
	}

	mutex_lock(&prov_mutex);
	prov = kfi_getprov(provider->name);
	if (prov) {
		ex_provider = prov->provider;
		kfi_ref_provider(ex_provider);
		if (KFI_VERSION_GE(ex_provider->version, provider->version)) {
			/*
			 * This provider is older than an already-loaded
			 * provider of the same name, then discard this one.
			 */
			LOG_WARN("A newer %s %d.%d provider is already loaded; \
				ignoring the older %d.%d version.", \
				provider->name,
				KFI_MAJOR(ex_provider->version),
				KFI_MINOR(ex_provider->version),
				KFI_MAJOR(provider->version),
				KFI_MINOR(provider->version));
			ret = -EEXIST;
			kfi_deref_provider(ex_provider);
			mutex_unlock(&prov_mutex);
			goto err;
		} else {
			/*
			 * This provider is newer than an already-loaded
			 * provider of the same name, so replace the
			 * already-loaded one.
			 */
			LOG_INFO("An older %s %d.%d provider is already loaded; \
				replacing with a newer %d.%d version.", \
				provider->name,
				KFI_MAJOR(ex_provider->version),
				KFI_MINOR(ex_provider->version),
				KFI_MAJOR(provider->version),
				KFI_MINOR(provider->version));
			kfi_ref_provider(provider);
			prov->provider = provider;
			kfi_deref_provider(ex_provider);
			mutex_unlock(&prov_mutex);
			return ret;
		}
	}

	prov = kzalloc(sizeof(*prov), GFP_KERNEL);
	if (!prov) {
		ret = -ENOMEM;
		mutex_unlock(&prov_mutex);
		goto err;
	}

	INIT_LIST_HEAD(&prov->list);
	kfi_ref_provider(provider);
	prov->provider = provider;
	list_add_tail(&prov->list, &prov_list);
	LOG_INFO("A %s %d.%d provider is successuflly loaded.", \
		provider->name,
		KFI_MAJOR(provider->version),
		KFI_MINOR(provider->version));
	mutex_unlock(&prov_mutex);
	return ret;

err:
	cleanup_provider(provider);
	kfi_deref_provider(provider);
	return ret;
}
EXPORT_SYMBOL(kfi_provider_register);

int
kfi_provider_deregister(struct kfi_provider *provider)
{
	struct list_head *lh = NULL;
	struct kfi_prov *prov = NULL;
	bool found = false;
	int ret = 0;

	if (!provider || !provider->name) {
		return -EINVAL;
	}

	mutex_lock(&prov_mutex);
	list_for_each(lh, &prov_list) {
		prov = list_entry(lh, typeof(*prov), list);
		if (prov->provider == provider) {
			found = true;
			break;
		}
	}
	if (found) {
		list_del(&prov->list);
	}
	mutex_unlock(&prov_mutex);

	if (found) {
		LOG_INFO("A %s %d.%d provider is successuflly unloaded.",
			provider->name,
			KFI_MAJOR(provider->version),
			KFI_MINOR(provider->version));
		kfi_deref_provider(provider);
		kfree(prov);
	} else {
		LOG_INFO("Unable to find the %s %d.%d provider.",
			provider->name,
			KFI_MAJOR(provider->version),
			KFI_MINOR(provider->version));
		ret = -ENODATA;
	}

	cleanup_provider(provider);
	kfi_deref_provider(provider);
	wait_for_completion(&provider->comp);
	return ret;
}
EXPORT_SYMBOL(kfi_provider_deregister);

struct kfi_info *
kfi_allocinfo(void)
{
        struct kfi_info *info = NULL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
        if (!info) {
		LOG_ERR("Failed to allocate fabric info.");
                return NULL;
	}

        info->tx_attr = kzalloc(sizeof(*info->tx_attr), GFP_KERNEL);
        info->rx_attr = kzalloc(sizeof(*info->rx_attr), GFP_KERNEL);
        info->ep_attr = kzalloc(sizeof(*info->ep_attr), GFP_KERNEL);
        info->domain_attr = kzalloc(sizeof(*info->domain_attr), GFP_KERNEL);
        info->fabric_attr = kzalloc(sizeof(*info->fabric_attr), GFP_KERNEL);
        if (!info->tx_attr|| !info->rx_attr || !info->ep_attr ||
            !info->domain_attr || !info->fabric_attr) {
		LOG_ERR("Failed to allocate fabric info attributes.");
                goto err;
	}

        return info;
err:
        kfi_deallocinfo(info);
        return NULL;
}
EXPORT_SYMBOL(kfi_allocinfo);

struct kfi_info *
kfi_dupinfo(const struct kfi_info *info)
{
	struct kfi_info *dup = NULL;

	if (!info) {
		return kfi_allocinfo();
	}

	dup = kmemdup(info, sizeof(*info), GFP_KERNEL);
	if (!dup) {
		goto err;
	}

	dup->next = NULL;
	dup->src_addr = NULL;
	dup->dest_addr = NULL;
	dup->tx_attr = NULL;
	dup->rx_attr = NULL;
	dup->ep_attr = NULL;
	dup->domain_attr = NULL;
	dup->fabric_attr = NULL;

	if (info->src_addr) {
		dup->src_addr = kmemdup(info->src_addr, dup->src_addrlen, GFP_KERNEL);
		if (!dup->src_addr) {
			goto err;
		}
	}
	if (info->dest_addr) {
		dup->dest_addr = kmemdup(info->dest_addr, dup->dest_addrlen, GFP_KERNEL);
		if (!dup->dest_addr) {
			goto err;
		}
	}
	if (info->tx_attr) {
		dup->tx_attr = kmemdup(info->tx_attr, sizeof(*info->tx_attr), GFP_KERNEL);
		if (!dup->tx_attr) {
			goto err;
		}
	}
	if (info->rx_attr) {
		dup->rx_attr = kmemdup(info->rx_attr, sizeof(*info->rx_attr), GFP_KERNEL);
		if (!dup->rx_attr) {
			goto err;
		}
	}
	if (info->ep_attr) {
		dup->ep_attr = kmemdup(info->ep_attr, sizeof(*info->ep_attr), GFP_KERNEL);
		if (!dup->ep_attr) {
			goto err;
		}
	}
	if (info->domain_attr) {
		dup->domain_attr = kmemdup(info->domain_attr,
		                           sizeof(*info->domain_attr),
		                           GFP_KERNEL);
		if (!dup->domain_attr) {
			goto err;
		}
		dup->domain_attr->name = NULL;
		if (info->domain_attr->name) {
			dup->domain_attr->name = kstrdup(info->domain_attr->name,
			                                 GFP_KERNEL);
			if (!dup->domain_attr->name) {
				goto err;
			}
		}
	}
	if (info->fabric_attr) {
		dup->fabric_attr = kmemdup(info->fabric_attr,
		                           sizeof(*info->fabric_attr),
		                           GFP_KERNEL);
		if (!dup->fabric_attr) {
			goto err;
		}
		dup->fabric_attr->name = NULL;
		dup->fabric_attr->prov_name = NULL;
		if (info->fabric_attr->name) {
			dup->fabric_attr->name = kstrdup(info->fabric_attr->name,
			                                 GFP_KERNEL);
			if (!dup->fabric_attr->name) {
				goto err;
			}
		}
		if (info->fabric_attr->prov_name) {
			dup->fabric_attr->prov_name = kstrdup(info->fabric_attr->prov_name,
			                                      GFP_KERNEL);
			if (!dup->fabric_attr->prov_name) {
				goto err;
			}
		}
	}

	return dup;

err:
	LOG_ERR("Failed to allocate duplicate fabric info.");
	kfi_deallocinfo(dup);
	return NULL;
};
EXPORT_SYMBOL(kfi_dupinfo);

void
kfi_deallocinfo(const struct kfi_info *info)
{
	struct kfi_info *next = NULL;

	for (; info; info = next) {
		next = info->next;
		if (info) {
			if (info->src_addr) {
				kfree(info->src_addr);
			}
			if (info->dest_addr) {
				kfree(info->dest_addr);
			}
			if (info->tx_attr) {
				kfree(info->tx_attr);
			}
			if (info->rx_attr) {
				kfree(info->rx_attr);
			}
			if (info->ep_attr) {
				kfree(info->ep_attr);
			}
			if (info->domain_attr) {
				if (info->domain_attr->name) {
					kfree(info->domain_attr->name);
				}
				kfree(info->domain_attr);
			}
			if (info->fabric_attr) {
				if (info->fabric_attr->name) {
					kfree(info->fabric_attr->name);
				}
				if (info->fabric_attr->prov_name) {
					kfree(info->fabric_attr->prov_name);
				}
				kfree(info->fabric_attr);
			}
			kfree(info);
		}
	}
	return;
};
EXPORT_SYMBOL(kfi_deallocinfo);

static void
cleanup_provider(struct kfi_provider *provider)
{
	if (provider && provider->cleanup) {
		provider->cleanup();
	}
}

static struct kfi_prov *
kfi_getprov(const char *prov_name)
{
	struct list_head *lh = NULL;
	struct kfi_prov *prov = NULL;

	list_for_each(lh, &prov_list) {
		prov = list_entry(lh, typeof(*prov), list);
		if (!strcmp(prov_name, prov->provider->name)) {
			break;
		}
	}
	return prov;
}

module_init(kfi_init);
module_exit(kfi_exit);
