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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/time.h>

#define DRV_NAME "kfit_verbs_mm2_cli"

#include <common.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Kernel Fabric Interface test (verbs) client side");
MODULE_AUTHOR("Jay E. Sternberg <jay.e.sternberg@intel.com>");

MODULE_PARAM(debug, debug_level, int, -1, "Debug: 0-none, 1-some, 2-all");

static int			running;
static struct task_struct	*thread;

static int test_thread(void *arg)
{
	int			i;
#if 0
	static const struct sched_param param = { .sched_priority = 0 };

	sched_setscheduler(current, SCHED_RR, &param);
	msleep(100);
	schedule();
#endif
	print_msg("Kthread: Connecting...\n");
	i = create_connection();
	if (i) {
		print_err("ERR: connect_2_server() failed(%d)\n", i);
		thread = NULL;
		running = 0;
		return -1;
	}
	print_msg("Kthread: Connected.\n");

	do_test();

	print_msg("Kthread: Disconnecting...\n");
	destroy_connection();
	print_msg("Kthread: Test Finished.\n");

	running = 0;
	thread = NULL;

	print_msg("Kthread: Exit\n");
	return 0;
}

static int init(void)
{
	print_msg("module loading\n");

	running = 1;

	thread = kthread_run(test_thread, NULL, DRV_NAME "thread");
	if (IS_ERR(thread)) {
		print_err("kthread_create returned %ld\n", PTR_ERR(thread));
		thread = NULL;
		running = 0;
		return -1;
	}
	print_msg("module loaded.\n");

	return 0;
}
module_init(init);

static void cleanup(void)
{
	print_msg("module unloading...\n");
	if (thread) {
		kthread_stop(thread);
		while (running)
			msleep(25);
	}
	print_msg("module unloaded.\n");
}
module_exit(cleanup);
