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

#ifndef	_SEND_H_
#define	_SEND_H_ 1

ssize_t
fi_ib_ep_recv(struct fid_ep *_ep, void *buf, size_t len, void *desc,
		  fi_addr_t src_addr, void *context);
ssize_t
fi_ib_ep_recvv(struct fid_ep *_ep, const struct iovec *iov, void **desc,
	       size_t count, fi_addr_t src_addr, void *context);
ssize_t
fi_ib_ep_send(struct fid_ep *_ep, const void *buf, size_t len,
	      void *desc, fi_addr_t dest_addr, void *context);
ssize_t
fi_ib_ep_senddata(struct fid_ep *_ep, const void *buf, size_t len, void *desc,
		  uint64_t data, fi_addr_t dest_addr, void *context);
ssize_t
fi_ib_ep_sendv(struct fid_ep *_ep, const struct iovec *iov, void **desc,
	       size_t count, fi_addr_t dest_addr, void *context);
ssize_t
fi_ib_ep_sendmsg(struct fid_ep *_ep, const struct fi_msg *msg, uint64_t flags);
ssize_t
fi_ib_ep_recvmsg(struct fid_ep *_ep, const struct fi_msg *msg, uint64_t flags);
ssize_t
fi_ib_ep_rma_write(struct fid_ep *_ep, const void *buf, size_t len,
		   void *desc, fi_addr_t dest_addr, uint64_t addr,
		   uint64_t key, void *context);
ssize_t
fi_ib_ep_rma_writev(struct fid_ep *_ep, const struct iovec *iov, void **desc,
		    size_t count, fi_addr_t dest_addr, uint64_t addr,
		    uint64_t key, void *context);
ssize_t
fi_ib_ep_rma_writemsg(struct fid_ep *_ep, const struct fi_msg_rma *msg,
		      uint64_t flags);
ssize_t
fi_ib_ep_rma_read(struct fid_ep *_ep, void *buf, size_t len, void *desc,
		  fi_addr_t src_addr, uint64_t addr, uint64_t key,
		  void *context);
ssize_t
fi_ib_ep_rma_readv(struct fid_ep *_ep, const struct iovec *iov, void **desc,
		   size_t count, fi_addr_t src_addr, uint64_t addr,
		   uint64_t key, void *context);
ssize_t
fi_ib_ep_rma_readmsg(struct fid_ep *_ep, const struct fi_msg_rma *msg,
		     uint64_t flags);
ssize_t
fi_ib_ep_rma_writedata(struct fid_ep *_ep, const void *buf, size_t len,
		       void *desc, uint64_t data, fi_addr_t dest_addr,
		       uint64_t addr, uint64_t key, void *context);
ssize_t
fi_ib_ep_atomic_write(struct fid_ep *_ep, const void *buf, size_t count,
		      void *desc, fi_addr_t dest_addr, uint64_t addr,
		      uint64_t key, enum fi_datatype datatype, enum fi_op op,
		      void *context);
ssize_t
fi_ib_ep_atomic_writev(struct fid_ep *_ep, const struct fi_ioc *iov,
		       void **desc, size_t count, fi_addr_t dest_addr,
		       uint64_t addr, uint64_t key, enum fi_datatype datatype,
		       enum fi_op op, void *context);
ssize_t
fi_ib_ep_atomic_writemsg(struct fid_ep *_ep, const struct fi_msg_atomic *msg,
			 uint64_t flags);
ssize_t
fi_ib_ep_atomic_readwrite(struct fid_ep *_ep, const void *buf, size_t count,
			  void *desc, void *result, void *result_desc,
			  fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			  enum fi_datatype datatype,
			  enum fi_op op, void *context);
ssize_t
fi_ib_ep_atomic_readwritev(struct fid_ep *_ep, const struct fi_ioc *iov,
			   void **desc, size_t count,
			   struct fi_ioc *resultv, void **result_desc,
			   size_t result_count, fi_addr_t dest_addr,
			   uint64_t addr, uint64_t key,
			   enum fi_datatype datatype,
			   enum fi_op op, void *context);
ssize_t
fi_ib_ep_atomic_readwritemsg(struct fid_ep *_ep,
			     const struct fi_msg_atomic *msg,
			     struct fi_ioc *resultv, void **result_desc,
			     size_t result_count, uint64_t flags);
ssize_t
fi_ib_ep_atomic_compwrite(struct fid_ep *_ep, const void *buf, size_t count,
			  void *desc, const void *compare,
			  void *compare_desc, void *result,
			  void *result_desc, fi_addr_t dest_addr,
			  uint64_t addr, uint64_t key,
			  enum fi_datatype datatype,
			  enum fi_op op, void *context);
ssize_t
fi_ib_ep_atomic_compwritev(struct fid_ep *_ep, const struct fi_ioc *iov,
			   void **desc, size_t count,
			   const struct fi_ioc *comparev,
			   void **compare_desc, size_t compare_count,
			   struct fi_ioc *resultv, void **result_desc,
			   size_t result_count, fi_addr_t dest_addr,
			   uint64_t addr, uint64_t key,
			   enum fi_datatype datatype,
			   enum fi_op op, void *context);
ssize_t
fi_ib_ep_atomic_compwritemsg(struct fid_ep *_ep,
			     const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev,
			     void **compare_desc, size_t compare_count,
			     struct fi_ioc *resultv,
			     void **result_desc, size_t result_count,
			     uint64_t flags);
int
fi_ib_ep_atomic_writevalid(struct fid_ep *_ep, enum fi_datatype datatype,
			   enum fi_op op, size_t *count);
int
fi_ib_ep_atomic_readwritevalid(struct fid_ep *_ep, enum fi_datatype datatype,
			       enum fi_op op, size_t *count);
int
fi_ib_ep_atomic_compwritevalid(struct fid_ep *_ep, enum fi_datatype datatype,
			       enum fi_op op, size_t *count);

#endif	/* _SEND_H_ */
