/*
 * Copyright (c) 2015 Intel Corp., Inc.  All rights reserved.
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

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <net/kfi/fabric.h>
#include <net/kfi/fi_errno.h>
#include <net/kfi/fi_atomic.h>
#include <net/kfi/kfi_provider.h>

#include "kfi_internal.h"
#include "debug.h"


int kfi_register_provider(uint32_t version, struct kfi_provider *provider)
{
	struct kfi_prov *prov;

	if (FI_MAJOR(version) != FI_MAJOR_VERSION ||
	    FI_MINOR(version) > FI_MINOR_VERSION) {
		print_err(
			"ERR: MAJ(%d) != cmaj(%d) or MINOR(%d) != cminor(%d)\n",
			FI_MAJOR(version), FI_MAJOR_VERSION,
			FI_MINOR(version), FI_MINOR_VERSION);
		return -FI_ENOSYS;
	}

	prov = kzalloc(sizeof(struct kfi_prov), GFP_KERNEL);
	if (!prov) {
		print_err("ERR: kzalloc(%ld)?\n", sizeof(struct kfi_prov));
		return -FI_ENOMEM;
	}

	prov->provider = provider;
	mutex_lock(&kfi_provider_list_mutex);
	list_add_tail(&(prov->plist), &kfi_providers);
	num_kfi_providers++;
	mutex_unlock(&kfi_provider_list_mutex);

	return 0;
}
EXPORT_SYMBOL(kfi_register_provider);

int kfi_deregister_provider(struct kfi_provider *provider)
{
	struct kfi_prov *prov;
	struct list_head *pos, *tmp;
	int located = 1;

	mutex_lock(&kfi_provider_list_mutex);
	list_for_each_safe(pos, tmp, &kfi_providers) {
		prov = list_entry(pos, struct kfi_prov, plist);
		if (prov->provider == provider) {
			located = 0;
			print_dbg("removing provider '%s'\n", provider->name);
			list_del(pos);
			kfree(prov);
			num_kfi_providers--;
			break;
		}
	}
	mutex_unlock(&kfi_provider_list_mutex);

	return located;
}
EXPORT_SYMBOL(kfi_deregister_provider);

static struct kfi_prov *fi_getprov(const char *prov_name)
{
	struct list_head *pos;
	struct kfi_prov *prov, *result = NULL;

	mutex_lock(&kfi_provider_list_mutex);
	list_for_each(pos, &kfi_providers) {
		prov = list_entry(pos, struct kfi_prov, plist);
		if (strcmp(prov_name, prov->provider->name) == 0) {
			result = prov;
			break;
		}
	}
	mutex_unlock(&kfi_provider_list_mutex);

	return result;
}

int fi_getinfo(uint32_t version, struct fi_info *hints, struct fi_info **info)
{
	struct kfi_prov *prov;
	struct fi_info *tail, *cur;
	int ret = -ENOSYS;
	struct list_head *pos;

	*info = tail = NULL;
	mutex_lock(&kfi_provider_list_mutex);

	list_for_each(pos, &kfi_providers) {
		prov = list_entry(pos, struct kfi_prov, plist);
		if (!prov->provider->getinfo)
			continue;

		ret = prov->provider->getinfo(version, hints, &cur);
		if (ret) {
			if (ret == -FI_ENODATA)
				continue;
			break;
		}

		if (*info == NULL)
			*info = cur;
		else
			tail->next = cur;

		tail = cur;
	}
	mutex_unlock(&kfi_provider_list_mutex);

	return *info ? 0 : ret;
}
EXPORT_SYMBOL(fi_getinfo);

void fi_freeinfo(struct fi_info *info)
{
	struct kfi_prov *prov;
	struct fi_info *next;

	for (; info; info = next) {
		next = info->next;
		prov = info->fabric_attr ?
		       fi_getprov(info->fabric_attr->prov_name) : NULL;

		if (prov && prov->provider->freeinfo)
			prov->provider->freeinfo(info);
		else
			fi_freeinfo_internal(info);
	}
}
EXPORT_SYMBOL(fi_freeinfo);

int fi_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
	      void *context)
{
	struct kfi_prov *prov;

	if (!attr || !attr->prov_name || !attr->name)
		return -FI_EINVAL;

	prov = fi_getprov(attr->prov_name);
	if (!prov || !prov->provider->fabric)
		return -FI_ENODEV;

	return prov->provider->fabric(attr, fabric, context);
}
EXPORT_SYMBOL(fi_fabric);

uint32_t kfi_version(void)
{
	return FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION);
}
EXPORT_SYMBOL(kfi_version);

#if 1
/* DEBUG hack start - to be removed in the future */
struct __errno {
	char		*short_str;
	unsigned char	errno;
	char		*long_str;
};

static struct __errno errno_str[134] = {
	{"ESUCCESS",	 0,	"SUCCESS"},
	{"EPERM",	 1,	"Operation not permitted"},
	{"ENOENT",	 2,	"No such file or directory"},
	{"ESRCH",	 3,	"No such process"},
	{"EINTR",	 4,	"Interrupted system call"},
	{"EIO",		 5,	"I/O error"},
	{"ENXIO",	 6,	"No such device or address"},
	{"E2BIG",	 7,	"Argument list too long"},
	{"ENOEXEC",	 8,	"Exec format error"},
	{"EBADF",	 9,	"Bad file number"},
	{"ECHILD",	10,	"No child processes"},
	{"EAGAIN",	11,	"Try again"},
	{"ENOMEM",	12,	"Out of memory"},
	{"EACCES",	13,	"Permission denied"},
	{"EFAULT",	14,	"Bad address"},
	{"ENOTBLK",	15,	"Block device required"},
	{"EBUSY",	16,	"Device or resource busy"},
	{"EEXIST",	17,	"File exists"},
	{"EXDEV",	18,	"Cross-device link"},
	{"ENODEV",	19,	"No such device"},
	{"ENOTDIR",	20,	"Not a directory"},
	{"EISDIR",	21,	"Is a directory"},
	{"EINVAL",	22,	"Invalid argument"},
	{"ENFILE",	23,	"File table overflow"},
	{"EMFILE",	24,	"Too many open files"},
	{"ENOTTY",	25,	"Not a typewriter"},
	{"ETXTBSY",	26,	"Text file busy"},
	{"EFBIG",	27,	"File too large"},
	{"ENOSPC",	28,	"No space left on device"},
	{"ESPIPE",	29,	"Illegal seek"},
	{"EROFS",	30,	"Read-only file system"},
	{"EMLINK",	31,	"Too many links"},
	{"EPIPE",	32,	"Broken pipe"},
	{"EDOM",	33,	"Math argument out of domain of func"},
	{"ERANGE",	34,	"Math result not representable"},
	{"EDEADLK",	35,	"Resource deadlock would occur"},
	{"ENAMETOOLONG", 36,	"File name too long"},
	{"ENOLCK",	37,	"No record locks available"},
	{"ENOSYS",	38,	"Function not implemented"},
	{"ENOTEMPTY",	39,	"Directory not empty"},
	{"ELOOP",	40,	"Too many symbolic links encountered"},
	{"EWOULDBLOCK",	41,	"Operation would block"},
	{"ENOMSG",	42,	"No message of desired type"},
	{"EIDRM",	43,	"Identifier removed"},
	{"ECHRNG",	44,	"Channel number out of range"},
	{"EL2NSYNC",	45,	"Level 2 not synchronized"},
	{"EL3HLT",	46,	"Level 3 halted"},
	{"EL3RST",	47,	"Level 3 reset"},
	{"ELNRNG",	48,	"Link number out of range"},
	{"EUNATCH",	49,	"Protocol driver not attached"},
	{"ENOCSI",	50,	"No CSI structure available"},
	{"EL2HLT",	51,	"Level 2 halted"},
	{"EBADE",	52,	"Invalid exchange"},
	{"EBADR",	53,	"Invalid request descriptor"},
	{"EXFULL",	54,	"Exchange full"},
	{"ENOANO",	55,	"No anode"},
	{"EBADRQC",	56,	"Invalid request code"},
	{"EBADSLT",	57,	"Invalid slot"},
	{"EDEADLOCK",	58,	"Operation would Dead lock"},
	{"EBFONT",	59,	"Bad font file format"},
	{"ENOSTR",	60,	"Device not a stream"},
	{"ENODATA",	61,	"No data available"},
	{"ETIME",	62,	"Timer expired"},
	{"ENOSR",	63,	"Out of streams resources"},
	{"ENONET",	64,	"Machine is not on the network"},
	{"ENOPKG",	65,	"Package not installed"},
	{"EREMOTE",	66,	"Object is remote"},
	{"ENOLINK",	67,	"Link has been severed"},
	{"EADV",	68,	"Advertise error"},
	{"ESRMNT",	69,	"Srmount error"},
	{"ECOMM",	70,	"Communication error on send"},
	{"EPROTO",	71,	"Protocol error"},
	{"EMULTIHOP",	72,	"Multihop attempted"},
	{"EDOTDOT",	73,	"RFS specific error"},
	{"EBADMSG",	74,	"Not a data message"},
	{"EOVERFLOW",	75,	"Value too large for defined data type"},
	{"ENOTUNIQ",	76,	"Name not unique on network"},
	{"EBADFD",	77,	"File descriptor in bad state"},
	{"EREMCHG",	78,	"Remote address changed"},
	{"ELIBACC",	79,	"Can not access a needed shared library"},
	{"ELIBBAD",	80,	"Accessing a corrupted shared library"},
	{"ELIBSCN",	81,	".lib section in a.out corrupted"},
	{"ELIBMAX",	82, "Attempting to link in too many shared libraries"},
	{"ELIBEXEC",	83,	"Cannot exec a shared library directly"},
	{"EILSEQ",	84,	"Illegal byte sequence"},
	{"ERESTART",	85,	"Interrupted system call should be restarted"},
	{"ESTRPIPE",	86,	"Streams pipe error"},
	{"EUSERS",	87,	"Too many users"},
	{"ENOTSOCK",	88,	"Socket operation on non-socket"},
	{"EDESTADDRREQ", 89,	"Destination address required"},
	{"EMSGSIZE",	90,	"Message too long"},
	{"EPROTOTYPE",	91,	"Protocol wrong type for socket"},
	{"ENOPROTOOPT",	92,	"Protocol not available"},
	{"EPROTONOSUPPORT", 93,	"Protocol not supported"},
	{"ESOCKTNOSUPPORT", 94,	"Socket type not supported"},
	{"EOPNOTSUPP",	95, "Operation not supported on transport endpoint"},
	{"EPFNOSUPPORT", 96, "Protocol family not supported"},
	{"EAFNOSUPPORT", 97, "Address family not supported by protocol"},
	{"EADDRINUSE",	98,	"Address already in use"},
	{"EADDRNOTAVAIL", 99,	"Cannot assign requested address"},
	{"ENETDOWN",	100,	"Network is down"},
	{"ENETUNREACH",	101,	"Network is unreachable"},
	{"ENETRESET",	102,	"Network dropped connection because of reset"},
	{"ECONNABORTED", 103,	"Software caused connection abort"},
	{"ECONNRESET",	104,	"Connection reset by peer"},
	{"ENOBUFS",	105,	"No buffer space available"},
	{"EISCONN",	106,	"Transport endpoint is already connected"},
	{"ENOTCONN",	107,	"Transport endpoint is not connected"},
	{"ESHUTDOWN",	108, "Cannot send after transport endpoint shutdown"},
	{"ETOOMANYREFS", 109,	"Too many references: cannot splice"},
	{"ETIMEDOUT",	110,	"Connection timed out"},
	{"ECONNREFUSED", 111,	"Connection refused"},
	{"EHOSTDOWN",	112,	"Host is down"},
	{"EHOSTUNREACH", 113,	"No route to host"},
	{"EALREADY",	114,	"Operation already in progress"},
	{"EINPROGRESS",	115,	"Operation now in progress"},
	{"ESTALE",	116,	"Stale file handle"},
	{"EUCLEAN",	117,	"Structure needs cleaning"},
	{"ENOTNAM",	118,	"Not a XENIX named type file"},
	{"ENAVAIL",	119,	"No XENIX semaphores available"},
	{"EISNAM",	120,	"Is a named type file"},
	{"EREMOTEIO",	121,	"Remote I/O error"},
	{"EDQUOT",	122,	"Quota exceeded"},

	{"ENOMEDIUM",	123,	"No medium found"},
	{"EMEDIUMTYPE",	124,	"Wrong medium type"},
	{"ECANCELED",	125,	"Operation Canceled"},
	{"ENOKEY",	126,	"Required key not available"},
	{"EKEYEXPIRED",	127,	"Key has expired"},
	{"EKEYREVOKED",	128,	"Key has been revoked"},
	{"EKEYREJECTED", 129,	"Key was rejected by service"},

	/* for robust mutexes */
	{"EOWNERDEAD",	130,	"Owner died"},
	{"ENOTRECOVERABLE", 131, "State not recoverable"},
	{"ERFKILL",	132,	"Operation not possible due to RF-kill"},
	{"EHWPOISON",	133,	"Memory page has hardware error"}
};

static char *strerror(int err)
{
	static char buf[72];	/* short_str + long_str + slop */

	if (err <= 134)
		snprintf(buf, sizeof(buf), "%s(%d) %s",
			errno_str[err].short_str, err, errno_str[err].long_str);
	else
		snprintf(buf, sizeof(buf), "%d", err);
	return buf;
}
/* DEBUG hack end */

#else

static char *strerror(int err)
{
	static char buf[16];

	snprintf(buf, sizeof(buf), "%d", err);
	return buf;
}
#endif

#define FI_ERRNO_OFFSET	256
#define FI_ERRNO_MAX	FI_ENOCQ

static const char *const errstr[] = {
	[FI_EOTHER - FI_ERRNO_OFFSET] = "Unspecified error",
	[FI_ETOOSMALL - FI_ERRNO_OFFSET] = "Provided buffer is too small",
	[FI_EOPBADSTATE - FI_ERRNO_OFFSET] =
				"Operation not permitted in current state",
	[FI_EAVAIL - FI_ERRNO_OFFSET]  = "Error available",
	[FI_EBADFLAGS - FI_ERRNO_OFFSET] = "Flags not supported",
	[FI_ENOEQ - FI_ERRNO_OFFSET] = "Missing or unavailable event queue",
	[FI_EDOMAIN - FI_ERRNO_OFFSET] = "Invalid resource domain",
	[FI_ENOCQ - FI_ERRNO_OFFSET] =
				"Missing or unavailable completion queue",
	[FI_ECRC - FI_ERRNO_OFFSET] = "CRC error",
	[FI_ETRUNC - FI_ERRNO_OFFSET] = "Truncation error",
	[FI_ENOKEY - FI_ERRNO_OFFSET] = "Required key not available"
};

const char *fi_strerror(int errnum)
{
	if (errnum < 0)
		errnum *= -1;
	if (errnum < FI_ERRNO_OFFSET)
		return strerror(errnum);
	else if (errnum < FI_ERRNO_MAX)
		return errstr[errnum - FI_ERRNO_OFFSET];
	else
		return errstr[FI_EOTHER - FI_ERRNO_OFFSET];
}
EXPORT_SYMBOL(fi_strerror);

static const size_t __fi_datatype_size[] = {
	[FI_INT8]   = sizeof(int8_t),
	[FI_UINT8]  = sizeof(uint8_t),
	[FI_INT16]  = sizeof(int16_t),
	[FI_UINT16] = sizeof(uint16_t),
	[FI_INT32]  = sizeof(int32_t),
	[FI_UINT32] = sizeof(uint32_t),
	[FI_INT64]  = sizeof(int64_t),
	[FI_UINT64] = sizeof(uint64_t),
	[FI_FLOAT]  = sizeof(float),
	[FI_DOUBLE] = sizeof(double)
};

size_t fi_datatype_size(enum fi_datatype datatype)
{
	if (datatype >= FI_DATATYPE_LAST)
		return -1;
	return __fi_datatype_size[datatype];
}

struct fi_info *fi_dupinfo(const struct fi_info *info)
{
	struct fi_info *dup;

	dup = kzalloc(sizeof(*dup), GFP_KERNEL);
	if (dup == NULL)
		return NULL;
	*dup = *info;
	dup->src_addr = NULL;
	dup->dest_addr = NULL;
	dup->tx_attr = NULL;
	dup->rx_attr = NULL;
	dup->ep_attr = NULL;
	dup->domain_attr = NULL;
	dup->fabric_attr = NULL;
	dup->next = NULL;

	if (info->src_addr != NULL) {
		dup->src_addr = kzalloc(dup->src_addrlen, GFP_KERNEL);
		if (dup->src_addr == NULL)
			goto fail;
		memcpy(dup->src_addr, info->src_addr, info->src_addrlen);
	}
	if (info->dest_addr != NULL) {
		dup->dest_addr = kzalloc(dup->dest_addrlen, GFP_KERNEL);
		if (dup->dest_addr == NULL)
			goto fail;
		memcpy(dup->dest_addr, info->dest_addr, info->dest_addrlen);
	}
	if (info->tx_attr != NULL) {
		dup->tx_attr = kzalloc(sizeof(*dup->tx_attr), GFP_KERNEL);
		if (dup->tx_attr == NULL)
			goto fail;
		*dup->tx_attr = *info->tx_attr;
	}
	if (info->rx_attr != NULL) {
		dup->rx_attr = kzalloc(sizeof(*dup->rx_attr), GFP_KERNEL);
		if (dup->rx_attr == NULL)
			goto fail;
		*dup->rx_attr = *info->rx_attr;
	}
	if (info->ep_attr != NULL) {
		dup->ep_attr = kzalloc(sizeof(*dup->ep_attr), GFP_KERNEL);
		if (dup->ep_attr == NULL)
			goto fail;
		*dup->ep_attr = *info->ep_attr;
	}
	if (info->domain_attr) {
		dup->domain_attr =
				kzalloc(sizeof(*dup->domain_attr), GFP_KERNEL);
		if (dup->domain_attr == NULL)
			goto fail;
		*dup->domain_attr = *info->domain_attr;
		if (info->domain_attr->name != NULL) {
			dup->domain_attr->name =
						kstrdup(info->domain_attr->name, GFP_KERNEL);
			if (dup->domain_attr->name == NULL)
				goto fail;
		}
	}
	if (info->fabric_attr) {
		dup->fabric_attr =
				kzalloc(sizeof(*dup->fabric_attr), GFP_KERNEL);
		if (dup->fabric_attr == NULL)
			goto fail;
		*dup->fabric_attr = *info->fabric_attr;
		if (info->fabric_attr->name != NULL) {
			dup->fabric_attr->name =
						kstrdup(info->fabric_attr->name, GFP_KERNEL);
			if (dup->fabric_attr->name == NULL)
				goto fail;
		}
		if (info->fabric_attr->prov_name != NULL) {
			dup->fabric_attr->prov_name =
				kstrdup(info->fabric_attr->prov_name, GFP_KERNEL);
			if (dup->fabric_attr->prov_name == NULL)
				goto fail;
		}
	}
	return dup;

fail:
	fi_freeinfo(dup);
	return NULL;
}
EXPORT_SYMBOL(fi_dupinfo);
