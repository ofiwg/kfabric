/*
 * Copyright (c) 2015 NetApp, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL); Version 2, available from the file
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

#ifndef _KFI_LOG_H_
#define _KFI_LOG_H_

#include <linux/printk.h>

#ifndef MODULE_NAME
#define MODULE_NAME "KFI"
#endif

#define LOG_DEBUG(fmt, ... ) printk(KERN_DEBUG "%s - %s:%d " fmt "\n", \
	MODULE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define LOG_DEFAULT(fmt, ... ) printk(KERN_DEFAULT "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_INFO(fmt, ... ) printk(KERN_INFO "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_NOTICE(fmt, ... ) printk(KERN_NOTICE "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_WARN(fmt, ... ) printk(KERN_WARNING "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_ERR(fmt, ... ) printk(KERN_ERR "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_CRIT(fmt, ... ) printk(KERN_CRIT "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_ALERT(fmt, ... ) printk(KERN_ALERT "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_EMERG(fmt, ... ) printk(KERN_EMERG "%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#endif /* _KFI_LOG_H_ */
