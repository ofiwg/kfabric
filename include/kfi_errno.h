/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
 * Copyright (c) 2015 Cisco Systems, Inc. All rights reserved.
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

#ifndef _KFI_ERRNO_H_
#define _KFI_ERRNO_H_

#include <linux/errno.h>

/* KFI directly mapped errno values */

#define	KFI_SUCCESS		0
#define	KFI_ENOENT		ENOENT		/* No such file or directory */
#define	KFI_EIO			EIO		/* I/O error */
#define	KFI_E2BIG		E2BIG		/* Argument list too long */
#define	KFI_EBADF		EBADF		/* Bad file number */
#define	KFI_EAGAIN		EAGAIN		/* Try again */
#define	KFI_ENOMEM		ENOMEM		/* Out of memory */
#define	KFI_EACCES		EACCES		/* Permission denied */
#define	KFI_EBUSY		EBUSY		/* Device or resource busy */
#define	KFI_ENODEV		ENODEV		/* No such device */
#define	KFI_EINVAL		EINVAL		/* Invalid argument */
#define	KFI_EMFILE		EMFILE		/* Too many open files */
#define	KFI_ENOSPC		ENOSPC		/* No space left on device */
#define	KFI_ENOSYS		ENOSYS		/* Function not implemented */
#define	KFI_ENOMSG		ENOMSG		/* No message of desired type */
#define	KFI_ENODATA		ENODATA		/* No data available */
#define	KFI_EMSGSIZE		EMSGSIZE	/* Message too long */
#define	KFI_ENOPROTOOPT		ENOPROTOOPT	/* Protocol not available */
#define	KFI_EOPNOTSUPP		EOPNOTSUPP	/* Operation not supported on
						 * transport endpoint */
#define	KFI_EADDRINUSE		EADDRINUSE	/* Address already in use */
#define	KFI_EADDRNOTAVAIL	EADDRNOTAVAIL	/* Cannot assign requested
						 * address */
#define	KFI_ENETDOWN		ENETDOWN	/* Network is down */
#define	KFI_ENETUNREACH		ENETUNREACH	/* Network is unreachable */
#define	KFI_ECONNABORTED	ECONNABORTED	/* Software caused connection
						 * abort */
#define	KFI_ECONNRESET		ECONNRESET	/* Connection reset by peer */

#define	KFI_EISCONN		EISCONN		/* Transport endpoint is
						 * already connected */
#define	KFI_ENOTCONN		ENOTCONN	/* Transport endpoint is not
						 * connected */
#define	KFI_ESHUTDOWN		ESHUTDOWN	/* Cannot send after transport
						 * endpoint shutdown */
#define	KFI_ETIMEDOUT		ETIMEDOUT	/* Connection timed out */
#define	KFI_ECONNREFUSED	ECONNREFUSED	/* Connection refused */
#define	KFI_EHOSTUNREACH	EHOSTUNREACH	/* No route to host */
#define	KFI_EALREADY		EALREADY	/* Operation already in
						 * progress */
#define	KFI_EINPROGRESS		EINPROGRESS	/* Operation now in progress */
#define	KFI_EREMOTEIO		EREMOTEIO	/* Remote I/O error */
#define	KFI_ECANCELED		ECANCELED	/* Operation Canceled */
#define	KFI_EKEYREJECTED	EKEYREJECTED	/* Key was rejected by
						 * service */

#ifdef NOT_USED

#define	KFI_EPERM		EPERM		/* Operation not permitted */
#define	KFI_ESRCH		ESRCH		/* No such process */
#define	KFI_EINTR		EINTR		/* Interrupted system call */
#define	KFI_ENXIO		ENXIO		/* No such device or address */
#define	KFI_ENOEXEC		ENOEXEC		/* Exec format error */
#define	KFI_ECHILD		ECHILD		/* No child processes */
#define	KFI_EFAULT		EFAULT		/* Bad address */
#define	KFI_ENOTBLK		ENOTBLK		/* Block device required */
#define	KFI_EEXIST		EEXIST		/* File exists */
#define	KFI_EXDEV		EXDEV		/* Cross-device link */
#define	KFI_ENOTDIR		ENOTDIR		/* Not a directory */
#define	KFI_EISDIR		EISDIR		/* Is a directory */
#define	KFI_ENFILE		ENFILE		/* File table overflow */
#define	KFI_ENOTTY		ENOTTY		/* Not a typewriter */
#define	KFI_ETXTBSY		ETXTBSY		/* Text file busy */
#define	KFI_EFBIG		EFBIG		/* File too large */
#define	KFI_ESPIPE		ESPIPE		/* Illegal seek */
#define	KFI_EROFS		EROFS		/* Read-only file system */
#define	KFI_EMLINK		EMLINK		/* Too many links */
#define	KFI_EPIPE		EPIPE		/* Broken pipe */
#define	KFI_EDOM		EDOM		/* Math argument out of domain
						 * of func */
#define	KFI_ERANGE		ERANGE		/* Math result not
						 * representable */
#define	KFI_EDEADLK		EDEADLK		/* Resource deadlock would
						 * occur */
#define	KFI_ENAMETOOLONG	ENAMETOLONG	/* File name too long */
#define	KFI_ENOLCK		ENOLCK		/* No record locks available */
#define	KFI_ENOTEMPTY		ENOTEMPTY	/* Directory not empty */
#define	KFI_ELOOP		ELOOP		/* Too many symbolic links
						 * encountered */
#define	KFI_EWOULDBLOCK		EWOULDBLOCK	/* Operation would block */
#define	KFI_EIDRM		EIDRM		/* Identifier removed */
#define	KFI_ECHRNG		ECHRNG		/* Channel number out of
						 * range */
#define	KFI_EL2NSYNC		EL2NSYCN	/* Level 2 not synchronized */
#define	KFI_EL3HLT		EL3HLT		/* Level 3 halted */
#define	KFI_EL3RST		EL3RST		/* Level 3 reset */
#define	KFI_ELNRNG		ELNRNG		/* Link number out of range */
#define	KFI_EUNATCH		EUNATCH		/* Protocol driver not
						 * attached */
#define	KFI_ENOCSI		ENOCSI		/* No CSI structure available */
#define	KFI_EL2HLT		EL2HLT		/* Level 2 halted */
#define	KFI_EBADE		EBADE		/* Invalid exchange */
#define	KFI_EBADR		EBADDR		/* Invalid request descriptor */
#define	KFI_EXFULL		EXFULL		/* Exchange full */
#define	KFI_ENOANO		ENOANO		/* No anode */
#define	KFI_EBADRQC		EBADRQC		/* Invalid request code */
#define	KFI_EBADSLT		EBADSLT		/* Invalid slot */
#define	KFI_EDEADLOCK		EDEADLOCK	/* Resource deadlock would
						 * occur */
#define	KFI_EBFONT		EBFONT		/* Bad font file format */
#define	KFI_ENOSTR		ENOSTR		/* Device not a stream */
#define	KFI_ETIME		ETIME		/* Timer expired */
#define	KFI_ENOSR		ENOSR		/* Out of streams resources */
#define	KFI_ENONET		ENONET		/* Machine is not on the
						 * network */
#define	KFI_ENOPKG		ENOPKG		/* Package not installed */
#define	KFI_EREMOTE		EREMOTE		/* Object is remote */
#define	KFI_ENOLINK		ENOLINK		/* Link has been severed */
#define	KFI_EADV		EADV		/* Advertise error */
#define	KFI_ESRMNT		ESRMNT		/* Srmount error */
#define	KFI_ECOMM		ECOMM		/* Communication error on
						 * send */
#define	KFI_EPROTO		EPROTO		/* Protocol error */
#define	KFI_EMULTIHOP		EMULTIHOP	/* Multihop attempted */
#define	KFI_EDOTDOT		EDOTDOT		/* RFS specific error */
#define	KFI_EBADMSG		EBADMSG		/* Not a data message */
#define	KFI_EOVERFLOW		EOVERFLOW	/* Value too large for defined
						 * data type */
#define	KFI_ENOTUNIQ		ENOTUNIQ	/* Name not unique on network */
#define	KFI_EBADFD		EBADFD		/* File descriptor in bad
						 * state */
#define	KFI_EREMCHG		EREMCHG		/* Remote address changed */
#define	KFI_ELIBACC		ELIBACC		/* Can not access a needed
						 * shared library */
#define	KFI_ELIBBAD		ELIBBAD		/* Accessing a corrupted
						 * shared library */
#define	KFI_ELIBSCN		ELIBSCN		/* .lib section in a.out
						 * corrupted */
#define	KFI_ELIBMAX		ELIBMAX		/* Attempting to link in too
						 * many shared libraries */
#define	KFI_ELIBEXEC		ELIBEXEC	/* Cannot exec a shared library
						 * directly */
#define	KFI_EILSEQ		EILSEQ		/* Illegal byte sequence */
#define	KFI_ERESTART		ERESTART	/* Interrupted system call
						 * should be restarted */
#define	KFI_ESTRPIPE		ESTRPIPE	/* Streams pipe error */
#define	KFI_EUSERS		EUSERS		/* Too many users */
#define	KFI_ENOTSOCK		ENOTSOCK	/* Socket operation on
						 * non-socket */
#define	KFI_EDESTADDRREQ	EDESTADDRREQ	/* Destination address
						 * required */
#define	KFI_EPROTOTYPE		EPROTOTYPE	/* Protocol wrong type for
						 * endpoint */
#define	KFI_EPROTONOSUPPORT	EPROTONOSUPPORT	/* Protocol not supported */
#define	KFI_ESOCKTNOSUPPORT	ESOCKTNOSUPPORT	/* Socket type not supported */
#define	KFI_EPFNOSUPPORT	EPFNOSUPPORT	/* Protocol family not
						 * supported */
#define	KFI_EAFNOSUPPORT	EAFNOSUPPORT	/* Address family not supported
						 * by protocol */
#define	KFI_ENETRESET		ENETRESET	/* Network dropped connection
						 * because of reset */
#define	KFI_ENOBUFS		ENOBUFS		/* No buffer space available */
#define	KFI_ETOOMANYREFS	ETOOMANYREFS	/* Too many references: cannot
						 * splice */
#define	KFI_EHOSTDOWN		EHOSTDOWN	/* Host is down */
#define	KFI_ESTALE		ESTALE		/* Stale NFS file handle */
#define	KFI_EUCLEAN		EUNCLEAN	/* Structure needs cleaning */
#define	KFI_ENOTNAM		ENOTNAM		/* Not a XENIX named type
						 * file */
#define	KFI_ENAVAIL		ENAVAIL		/* No XENIX semaphores
						 * available */
#define	KFI_EISNAM		EISNAM		/* Is a named type file */
#define	KFI_EDQUOT		EDQUOT		/* Quota exceeded */
#define	KFI_ENOMEDIUM		ENOMEDIUM	/* No medium found */
#define	KFI_EMEDIUMTYPE		EMEDIUMTYPE	/* Wrong medium type */

#define	KFI_EKEYEXPIRED		EKEYEXPIRED	/* Key has expired */
#define	KFI_EKEYREVOKED		EKEYREVOKED	/* Key has been revoked */
#define	KFI_EOWNERDEAD		EOWNERDEAD	/* Owner died */
#define	KFI_ENOTRECOVERABLE	ENOTRECOVERABLE	/* State not recoverable */

#endif	/* NOT_USED - clean */

/* KFI specific return values: >= 256 */

#define KFI_EOTHER		256		/* Unspecified error */
#define KFI_ETOOSMALL		257		/* Provided buffer is too
						 * small */
#define KFI_EOPBADSTATE		258		/* Operation not permitted in
						 * current state */
#define KFI_EAVAIL		259		/* Error available */
#define KFI_EBADFLAGS		260		/* Flags not supported */
#define KFI_ENOEQ		261		/* Missing or unavailable
						 * event queue */
#define KFI_EDOMAIN		262		/* Invalid resource domain */
#define KFI_ENOCQ		263		/* Missing or unavailable
						 * completion queue */
#define KKFI_ECRC		264		/* CRC error */
#define KKFI_ETRUNC		265		/* Truncation error */
#define KKFI_ENOKEY		266		/* Required key not available */

const char *fi_strerror(int errnum);

#endif /* _KKFI_ERRNO_H_ */
