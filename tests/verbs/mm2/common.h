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

#ifndef _COMMON_H_
#define _COMMON_H_

/* hack to work around OFED 3.12-1 duplicate defs */
#define CONFIG_COMPAT_IS_KTHREAD
#include <linux/kthread.h>

#include "debug.h"

#define DRV_PFX "[" DRV_NAME "] "

#define TEST_MESSAGE "Yadda, yadda...(%03d)"

#define TEST_PORT       18500
#define TEST_ADDR       "192.168.22.11"
#define BUFFER_SIZE     128
#define PRIVATE_DATA	"my IB Private data"

#if 0
#define print_ptr(x,y)					\
	do { char str[60] = { 0 }; int l;		\
	  sprintf(str, " %s %s %d",DRV_PFX,__func__,__LINE__);	\
	  l = strlen(str);				\
	  memset(str, ' ', 59);				\
	  strncpy(str, x, strlen(x));			\
	  str[60 - l] = 0;				\
	  print_dbg("%s %p\n", str, y);			\
	} while (0)
#else
#define print_ptr(x,y) do { } while (0)
#endif

enum {
	DEBUG_CONNECT		= DEBUG_NEXT,
	DEBUG_MSG		= DEBUG_NEXT << 1,
};

int create_connection(void);
int do_test(void);
void destroy_connection(void);

#endif /* _COMMON_H_ */
