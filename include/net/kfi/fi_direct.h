/*
 * Copyright (c) 2015 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

/* TODO: revisit these values, these are just placeholders now */


#ifndef _FI_FXR_DIRECT_H_
#define _FI_FXR_DIRECT_H_

enum fi_fxr_static_limits {
	FI_FXR_MAX_MSG_SIZE		= (1ULL<<30),
	FI_FXR_INJECT_SIZE		= (1ULL<<3),
	FI_FXR_TOTAL_BUFFERED_RECV	= (1ULL<<30),
	FI_FXR_MAX_ORDER_RAW_SIZE	= (1ULL<<13),
	FI_FXR_MAX_ORDER_WAR_SIZE	= (1ULL<<13),
	FI_FXR_MAX_ORDER_WAW_SIZE	= (1ULL<<13),
	FI_FXR_MR_KEY_SIZE		= (1ULL<<3),
	FI_FXR_CQ_DATA_SIZE		= (1ULL<<3)
};

#endif /* _FI_FXR_DIRECT_H_ */
