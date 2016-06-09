/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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

#ifndef DEBUG_H
#define DEBUG_H

#ifdef CONFIG_KFI_DEBUG
extern int debug_level;
#define set_debug_level(val) (debug_level = (val))
#define update_debug_level(val) (debug_level |= (val))
#else
#define set_debug_level(val)
#define update_debug_level(val)
#endif

#ifndef MODULE_PARAM
#define MODULE_PARAM(name, var, type, value, desc)	\
	type var = value;				\
	module_param_named(name, var, type, 0644);	\
	MODULE_PARM_DESC(name, desc)
#endif

enum {
	DEBUG_NONE	= 0,
	DEBUG_LOW	= (1 << 0),
	DEBUG_MED	= (1 << 1),
	DEBUG_HIGH	= (1 << 2),
	DEBUG_TRACE	= (1 << 3),
	DEBUG_NEXT	= (1 << 4), /* extensions start here */

	DEBUG_LEVEL_LOW	= DEBUG_LOW,
	DEBUG_LEVEL_MED	= (DEBUG_LOW | DEBUG_MED),
	DEBUG_LEVEL_HI	= (DEBUG_LOW | DEBUG_MED | DEBUG_HIGH)
};

#define _PRINTK(l, f, arg...)	\
	printk(l DRV_PFX "%s(%d) " f, __func__, __LINE__, ##arg)

#ifdef CONFIG_KFI_DEBUG
#define PRINTK(dbg, l, f, arg...)				\
	do {							\
		if (dbg & debug_level)				\
			printk(l DRV_PFX "%s(%d) " f,		\
				 __func__, __LINE__, ##arg);	\
	} while (0)
#else
#define PRINTK(dbg, f, arg...) do { } while (0)
#endif

/* info does not print function or line numbers */
#define print_info(f, arg...) pr_info(f, ##arg)

/* err is not based on mask but does include function and line number */
#define print_err(f, arg...) _PRINTK(KERN_ERR, f, ##arg)
#define print_msg(f, arg...) _PRINTK(KERN_ERR, f, ##arg)

/* dprint is generic so allows for the mask to be specified */
#define dprint(mask, f, arg...) PRINTK(mask, KERN_DEBUG, f, ##arg)

/* these are very common so specific macros are defined */
#define print_dbg(f, arg...) PRINTK(DEBUG_LOW, KERN_DEBUG, f, ##arg)
#define print_trace(f, arg...) PRINTK(DEBUG_TRACE, KERN_ERR, f, ##arg)
#endif /* DEBUG_H */
