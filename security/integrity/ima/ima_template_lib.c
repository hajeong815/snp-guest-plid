// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Politecnico di Torino, Italy
 *                    TORSEC group -- https://security.polito.it
 *
 * Author: Roberto Sassu <roberto.sassu@polito.it>
 *
 * File: ima_template_lib.c
 *      Library of supported template fields.
 */

#include "ima_template_lib.h"
#include "ima.h"
#include <linux/xattr.h>
#include <linux/evm.h>

#include<linux/module.h>
#include<linux/init.h>
#include<linux/proc_fs.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/seq_file.h>
#include<linux/slab.h>
#include <linux/namei.h>
#include <linux/kernel_read_file.h>
#include <linux/fcntl.h>
#include <linux/fs.h>

static bool ima_template_hash_algo_allowed(u8 algo)
{
	if (algo == HASH_ALGO_SHA1 || algo == HASH_ALGO_MD5)
		return true;

	return false;
}

enum data_formats {
	DATA_FMT_DIGEST = 0,
	DATA_FMT_DIGEST_WITH_ALGO,
	DATA_FMT_DIGEST_WITH_TYPE_AND_ALGO,
	DATA_FMT_STRING,
	DATA_FMT_HEX,
	DATA_FMT_UINT
};

enum digest_type { DIGEST_TYPE_IMA, DIGEST_TYPE_VERITY, DIGEST_TYPE__LAST };

#define DIGEST_TYPE_NAME_LEN_MAX 7 /* including NUL */
static const char *const digest_type_name[DIGEST_TYPE__LAST] = {
	[DIGEST_TYPE_IMA] = "ima",
	[DIGEST_TYPE_VERITY] = "verity"
};

static int ima_write_template_field_data(const void *data, const u32 datalen,
					 enum data_formats datafmt,
					 struct ima_field_data *field_data)
{
	u8 *buf, *buf_ptr;
	u32 buflen = datalen;

	if (datafmt == DATA_FMT_STRING)
		buflen = datalen + 1;

	buf = kzalloc(buflen, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, data, datalen);

	/*
	 * Replace all space characters with underscore for event names and
	 * strings. This avoid that, during the parsing of a measurements list,
	 * filenames with spaces or that end with the suffix ' (deleted)' are
	 * split into multiple template fields (the space is the delimitator
	 * character for measurements lists in ASCII format).
	 */
	if (datafmt == DATA_FMT_STRING) {
		for (buf_ptr = buf; buf_ptr - buf < datalen; buf_ptr++)
			if (*buf_ptr == ' ')
				*buf_ptr = '_';
	}

	field_data->data = buf;
	field_data->len = buflen;
	return 0;
}

static void ima_show_template_data_ascii(struct seq_file *m,
					 enum ima_show_type show,
					 enum data_formats datafmt,
					 struct ima_field_data *field_data)
{
	u8 *buf_ptr = field_data->data;
	u32 buflen = field_data->len;

	switch (datafmt) {
	case DATA_FMT_DIGEST_WITH_TYPE_AND_ALGO:
	case DATA_FMT_DIGEST_WITH_ALGO:
		buf_ptr = strrchr(field_data->data, ':');
		if (buf_ptr != field_data->data)
			seq_printf(m, "%s", field_data->data);

		/* skip ':' and '\0' */
		buf_ptr += 2;
		buflen -= buf_ptr - field_data->data;
		fallthrough;
	case DATA_FMT_DIGEST:
	case DATA_FMT_HEX:
		if (!buflen)
			break;
		ima_print_digest(m, buf_ptr, buflen);
		break;
	case DATA_FMT_STRING:
		seq_printf(m, "%s", buf_ptr);
		break;
	case DATA_FMT_UINT:
		switch (field_data->len) {
		case sizeof(u8):
			seq_printf(m, "%u", *(u8 *)buf_ptr);
			break;
		case sizeof(u16):
			if (ima_canonical_fmt)
				seq_printf(m, "%u",
					   le16_to_cpu(*(__le16 *)buf_ptr));
			else
				seq_printf(m, "%u", *(u16 *)buf_ptr);
			break;
		case sizeof(u32):
			if (ima_canonical_fmt)
				seq_printf(m, "%u",
					   le32_to_cpu(*(__le32 *)buf_ptr));
			else
				seq_printf(m, "%u", *(u32 *)buf_ptr);
			break;
		case sizeof(u64):
			if (ima_canonical_fmt)
				seq_printf(m, "%llu",
					   le64_to_cpu(*(__le64 *)buf_ptr));
			else
				seq_printf(m, "%llu", *(u64 *)buf_ptr);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

static void ima_show_template_data_binary(struct seq_file *m,
					  enum ima_show_type show,
					  enum data_formats datafmt,
					  struct ima_field_data *field_data)
{
	u32 len = (show == IMA_SHOW_BINARY_OLD_STRING_FMT) ?
			  strlen(field_data->data) :
			  field_data->len;

	if (show != IMA_SHOW_BINARY_NO_FIELD_LEN) {
		u32 field_len = !ima_canonical_fmt ?
					len :
					(__force u32)cpu_to_le32(len);

		ima_putc(m, &field_len, sizeof(field_len));
	}

	if (!len)
		return;

	ima_putc(m, field_data->data, len);
}

static void ima_show_template_field_data(struct seq_file *m,
					 enum ima_show_type show,
					 enum data_formats datafmt,
					 struct ima_field_data *field_data)
{
	switch (show) {
	case IMA_SHOW_ASCII:
		ima_show_template_data_ascii(m, show, datafmt, field_data);
		break;
	case IMA_SHOW_BINARY:
	case IMA_SHOW_BINARY_NO_FIELD_LEN:
	case IMA_SHOW_BINARY_OLD_STRING_FMT:
		ima_show_template_data_binary(m, show, datafmt, field_data);
		break;
	default:
		break;
	}
}

void ima_show_template_digest(struct seq_file *m, enum ima_show_type show,
			      struct ima_field_data *field_data)
{
	ima_show_template_field_data(m, show, DATA_FMT_DIGEST, field_data);
}

void ima_show_template_digest_ng(struct seq_file *m, enum ima_show_type show,
				 struct ima_field_data *field_data)
{
	ima_show_template_field_data(m, show, DATA_FMT_DIGEST_WITH_ALGO,
				     field_data);
}

void ima_show_template_digest_ngv2(struct seq_file *m, enum ima_show_type show,
				   struct ima_field_data *field_data)
{
	ima_show_template_field_data(
		m, show, DATA_FMT_DIGEST_WITH_TYPE_AND_ALGO, field_data);
}

void ima_show_template_string(struct seq_file *m, enum ima_show_type show,
			      struct ima_field_data *field_data)
{
	ima_show_template_field_data(m, show, DATA_FMT_STRING, field_data);
}

void ima_show_template_sig(struct seq_file *m, enum ima_show_type show,
			   struct ima_field_data *field_data)
{
	ima_show_template_field_data(m, show, DATA_FMT_HEX, field_data);
}

void ima_show_template_buf(struct seq_file *m, enum ima_show_type show,
			   struct ima_field_data *field_data)
{
	ima_show_template_field_data(m, show, DATA_FMT_HEX, field_data);
}

void ima_show_template_uint(struct seq_file *m, enum ima_show_type show,
			    struct ima_field_data *field_data)
{
	ima_show_template_field_data(m, show, DATA_FMT_UINT, field_data);
}

/**
 * ima_parse_buf() - Parses lengths and data from an input buffer
 * @bufstartp:       Buffer start address.
 * @bufendp:         Buffer end address.
 * @bufcurp:         Pointer to remaining (non-parsed) data.
 * @maxfields:       Length of fields array.
 * @fields:          Array containing lengths and pointers of parsed data.
 * @curfields:       Number of array items containing parsed data.
 * @len_mask:        Bitmap (if bit is set, data length should not be parsed).
 * @enforce_mask:    Check if curfields == maxfields and/or bufcurp == bufendp.
 * @bufname:         String identifier of the input buffer.
 *
 * Return: 0 on success, -EINVAL on error.
 */
int ima_parse_buf(void *bufstartp, void *bufendp, void **bufcurp, int maxfields,
		  struct ima_field_data *fields, int *curfields,
		  unsigned long *len_mask, int enforce_mask, char *bufname)
{
	void *bufp = bufstartp;
	int i;

	for (i = 0; i < maxfields; i++) {
		if (len_mask == NULL || !test_bit(i, len_mask)) {
			if (bufp > (bufendp - sizeof(u32)))
				break;

			if (ima_canonical_fmt)
				fields[i].len = le32_to_cpu(*(__le32 *)bufp);
			else
				fields[i].len = *(u32 *)bufp;

			bufp += sizeof(u32);
		}

		if (bufp > (bufendp - fields[i].len))
			break;

		fields[i].data = bufp;
		bufp += fields[i].len;
	}

	if ((enforce_mask & ENFORCE_FIELDS) && i != maxfields) {
		pr_err("%s: nr of fields mismatch: expected: %d, current: %d\n",
		       bufname, maxfields, i);
		return -EINVAL;
	}

	if ((enforce_mask & ENFORCE_BUFEND) && bufp != bufendp) {
		pr_err("%s: buf end mismatch: expected: %p, current: %p\n",
		       bufname, bufendp, bufp);
		return -EINVAL;
	}

	if (curfields)
		*curfields = i;

	if (bufcurp)
		*bufcurp = bufp;

	return 0;
}

static int ima_eventdigest_init_common(const u8 *digest, u32 digestsize,
				       u8 digest_type, u8 hash_algo,
				       struct ima_field_data *field_data)
{
	/*
	 * digest formats:
	 *  - DATA_FMT_DIGEST: digest
	 *  - DATA_FMT_DIGEST_WITH_ALGO: <hash algo> + ':' + '\0' + digest,
	 *  - DATA_FMT_DIGEST_WITH_TYPE_AND_ALGO:
	 *	<digest type> + ':' + <hash algo> + ':' + '\0' + digest,
	 *
	 *    where 'DATA_FMT_DIGEST' is the original digest format ('d')
	 *      with a hash size limitation of 20 bytes,
	 *    where <digest type> is either "ima" or "verity",
	 *    where <hash algo> is the hash_algo_name[] string.
	 */
	u8 buffer[DIGEST_TYPE_NAME_LEN_MAX + CRYPTO_MAX_ALG_NAME + 2 +
		  IMA_MAX_DIGEST_SIZE] = { 0 };
	enum data_formats fmt = DATA_FMT_DIGEST;
	u32 offset = 0;

	if (digest_type < DIGEST_TYPE__LAST && hash_algo < HASH_ALGO__LAST) {
		fmt = DATA_FMT_DIGEST_WITH_TYPE_AND_ALGO;
		offset += 1 + sprintf(buffer,
				      "%s:%s:", digest_type_name[digest_type],
				      hash_algo_name[hash_algo]);
	} else if (hash_algo < HASH_ALGO__LAST) {
		fmt = DATA_FMT_DIGEST_WITH_ALGO;
		offset += 1 + sprintf(buffer, "%s:", hash_algo_name[hash_algo]);
	}

	if (digest)
		memcpy(buffer + offset, digest, digestsize);
	else
		/*
		 * If digest is NULL, the event being recorded is a violation.
		 * Make room for the digest by increasing the offset by the
		 * hash algorithm digest size.
		 */
		offset += hash_digest_size[hash_algo];

	return ima_write_template_field_data(buffer, offset + digestsize, fmt,
					     field_data);
}

/*
 * This function writes the digest of an event (with size limit).
 */
int ima_eventdigest_init(struct ima_event_data *event_data,
			 struct ima_field_data *field_data)
{
	struct ima_max_digest_data hash;
	u8 *cur_digest = NULL;
	u32 cur_digestsize = 0;
	struct inode *inode;
	int result;

	memset(&hash, 0, sizeof(hash));

	if (event_data->violation) /* recording a violation. */
		goto out;

	if (ima_template_hash_algo_allowed(event_data->iint->ima_hash->algo)) {
		cur_digest = event_data->iint->ima_hash->digest;
		cur_digestsize = event_data->iint->ima_hash->length;
		goto out;
	}

	if ((const char *)event_data->filename == boot_aggregate_name) {
		if (ima_tpm_chip) {
			hash.hdr.algo = HASH_ALGO_SHA1;
			result = ima_calc_boot_aggregate(&hash.hdr);

			/* algo can change depending on available PCR banks */
			if (!result && hash.hdr.algo != HASH_ALGO_SHA1)
				result = -EINVAL;

			if (result < 0)
				memset(&hash, 0, sizeof(hash));
		}

		cur_digest = hash.hdr.digest;
		cur_digestsize = hash_digest_size[HASH_ALGO_SHA1];
		goto out;
	}

	if (!event_data->file) /* missing info to re-calculate the digest */
		return -EINVAL;

	inode = file_inode(event_data->file);
	hash.hdr.algo = ima_template_hash_algo_allowed(ima_hash_algo) ?
				ima_hash_algo :
				HASH_ALGO_SHA1;
	result = ima_calc_file_hash(event_data->file, &hash.hdr);
	if (result) {
		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode,
				    event_data->filename, "collect_data",
				    "failed", result, 0);
		return result;
	}
	cur_digest = hash.hdr.digest;
	cur_digestsize = hash.hdr.length;
out:
	return ima_eventdigest_init_common(cur_digest, cur_digestsize,
					   DIGEST_TYPE__LAST, HASH_ALGO__LAST,
					   field_data);
}

/*
 * This function writes the digest of an event (without size limit).
 */
int ima_eventdigest_ng_init(struct ima_event_data *event_data,
			    struct ima_field_data *field_data)
{
	u8 *cur_digest = NULL, hash_algo = ima_hash_algo;
	u32 cur_digestsize = 0;

	if (event_data->violation) /* recording a violation. */
		goto out;

	cur_digest = event_data->iint->ima_hash->digest;
	cur_digestsize = event_data->iint->ima_hash->length;

	hash_algo = event_data->iint->ima_hash->algo;
out:
	return ima_eventdigest_init_common(cur_digest, cur_digestsize,
					   DIGEST_TYPE__LAST, hash_algo,
					   field_data);
}

/*
 * This function writes the digest of an event (without size limit),
 * prefixed with both the digest type and hash algorithm.
 */
int ima_eventdigest_ngv2_init(struct ima_event_data *event_data,
			      struct ima_field_data *field_data)
{
	u8 *cur_digest = NULL, hash_algo = ima_hash_algo;
	u32 cur_digestsize = 0;
	u8 digest_type = DIGEST_TYPE_IMA;

	if (event_data->violation) /* recording a violation. */
		goto out;

	cur_digest = event_data->iint->ima_hash->digest;
	cur_digestsize = event_data->iint->ima_hash->length;

	hash_algo = event_data->iint->ima_hash->algo;
	if (event_data->iint->flags & IMA_VERITY_REQUIRED)
		digest_type = DIGEST_TYPE_VERITY;
out:
	return ima_eventdigest_init_common(cur_digest, cur_digestsize,
					   digest_type, hash_algo, field_data);
}

/*
 * This function writes the digest of the file which is expected to match the
 * digest contained in the file's appended signature.
 */
int ima_eventdigest_modsig_init(struct ima_event_data *event_data,
				struct ima_field_data *field_data)
{
	enum hash_algo hash_algo;
	const u8 *cur_digest;
	u32 cur_digestsize;

	if (!event_data->modsig)
		return 0;

	if (event_data->violation) {
		/* Recording a violation. */
		hash_algo = HASH_ALGO_SHA1;
		cur_digest = NULL;
		cur_digestsize = 0;
	} else {
		int rc;

		rc = ima_get_modsig_digest(event_data->modsig, &hash_algo,
					   &cur_digest, &cur_digestsize);
		if (rc)
			return rc;
		else if (hash_algo == HASH_ALGO__LAST || cur_digestsize == 0)
			/* There was some error collecting the digest. */
			return -EINVAL;
	}

	return ima_eventdigest_init_common(cur_digest, cur_digestsize,
					   DIGEST_TYPE__LAST, hash_algo,
					   field_data);
}

static int ima_eventname_init_common(struct ima_event_data *event_data,
				     struct ima_field_data *field_data,
				     bool size_limit)
{
	const char *cur_filename = NULL;
	u32 cur_filename_len = 0;

	BUG_ON(event_data->filename == NULL && event_data->file == NULL);

	if (event_data->filename) {
		cur_filename = event_data->filename;
		cur_filename_len = strlen(event_data->filename);

		if (!size_limit || cur_filename_len <= IMA_EVENT_NAME_LEN_MAX)
			goto out;
	}

	if (event_data->file) {
		cur_filename = event_data->file->f_path.dentry->d_name.name;
		cur_filename_len = strlen(cur_filename);
	} else
		/*
		 * Truncate filename if the latter is too long and
		 * the file descriptor is not available.
		 */
		cur_filename_len = IMA_EVENT_NAME_LEN_MAX;
out:
	return ima_write_template_field_data(cur_filename, cur_filename_len,
					     DATA_FMT_STRING, field_data);
}

/*
 * This function writes the name of an event (with size limit).
 */
int ima_eventname_init(struct ima_event_data *event_data,
		       struct ima_field_data *field_data)
{
	return ima_eventname_init_common(event_data, field_data, true);
}

/*
 * This function writes the name of an event (without size limit).
 */
int ima_eventname_ng_init(struct ima_event_data *event_data,
			  struct ima_field_data *field_data)
{
	return ima_eventname_init_common(event_data, field_data, false);
}

/*
 *  ima_eventsig_init - include the file signature as part of the template data
 */
int ima_eventsig_init(struct ima_event_data *event_data,
		      struct ima_field_data *field_data)
{
	struct evm_ima_xattr_data *xattr_value = event_data->xattr_value;

	if (!xattr_value || (xattr_value->type != EVM_IMA_XATTR_DIGSIG &&
			     xattr_value->type != IMA_VERITY_DIGSIG))
		return ima_eventevmsig_init(event_data, field_data);

	return ima_write_template_field_data(xattr_value, event_data->xattr_len,
					     DATA_FMT_HEX, field_data);
}

/*
 *  ima_eventbuf_init - include the buffer(kexec-cmldine) as part of the
 *  template data.
 */
int ima_eventbuf_init(struct ima_event_data *event_data,
		      struct ima_field_data *field_data)
{
	if ((!event_data->buf) || (event_data->buf_len == 0))
		return 0;

	return ima_write_template_field_data(
		event_data->buf, event_data->buf_len, DATA_FMT_HEX, field_data);
}

/*
 *  ima_eventmodsig_init - include the appended file signature as part of the
 *  template data
 */
int ima_eventmodsig_init(struct ima_event_data *event_data,
			 struct ima_field_data *field_data)
{
	const void *data;
	u32 data_len;
	int rc;

	if (!event_data->modsig)
		return 0;

	/*
	 * modsig is a runtime structure containing pointers. Get its raw data
	 * instead.
	 */
	rc = ima_get_raw_modsig(event_data->modsig, &data, &data_len);
	if (rc)
		return rc;

	return ima_write_template_field_data(data, data_len, DATA_FMT_HEX,
					     field_data);
}

/*
 *  ima_eventevmsig_init - include the EVM portable signature as part of the
 *  template data
 */
int ima_eventevmsig_init(struct ima_event_data *event_data,
			 struct ima_field_data *field_data)
{
	struct evm_ima_xattr_data *xattr_data = NULL;
	int rc = 0;

	if (!event_data->file)
		return 0;

	rc = vfs_getxattr_alloc(&nop_mnt_idmap, file_dentry(event_data->file),
				XATTR_NAME_EVM, (char **)&xattr_data, 0,
				GFP_NOFS);
	if (rc <= 0 || xattr_data->type != EVM_XATTR_PORTABLE_DIGSIG) {
		rc = 0;
		goto out;
	}

	rc = ima_write_template_field_data((char *)xattr_data, rc, DATA_FMT_HEX,
					   field_data);

out:
	kfree(xattr_data);
	return rc;
}

static int ima_eventinodedac_init_common(struct ima_event_data *event_data,
					 struct ima_field_data *field_data,
					 bool get_uid)
{
	unsigned int id;

	if (!event_data->file)
		return 0;

	if (get_uid)
		id = i_uid_read(file_inode(event_data->file));
	else
		id = i_gid_read(file_inode(event_data->file));

	if (ima_canonical_fmt) {
		if (sizeof(id) == sizeof(u16))
			id = (__force u16)cpu_to_le16(id);
		else
			id = (__force u32)cpu_to_le32(id);
	}

	return ima_write_template_field_data((void *)&id, sizeof(id),
					     DATA_FMT_UINT, field_data);
}

/*
 *  ima_eventinodeuid_init - include the inode UID as part of the template
 *  data
 */
int ima_eventinodeuid_init(struct ima_event_data *event_data,
			   struct ima_field_data *field_data)
{
	return ima_eventinodedac_init_common(event_data, field_data, true);
}

/*
 *  ima_eventinodegid_init - include the inode GID as part of the template
 *  data
 */
int ima_eventinodegid_init(struct ima_event_data *event_data,
			   struct ima_field_data *field_data)
{
	return ima_eventinodedac_init_common(event_data, field_data, false);
}

/*
 *  ima_eventinodemode_init - include the inode mode as part of the template
 *  data
 */
int ima_eventinodemode_init(struct ima_event_data *event_data,
			    struct ima_field_data *field_data)
{
	struct inode *inode;
	u16 mode;

	if (!event_data->file)
		return 0;

	inode = file_inode(event_data->file);
	mode = inode->i_mode;
	if (ima_canonical_fmt)
		mode = (__force u16)cpu_to_le16(mode);

	return ima_write_template_field_data((char *)&mode, sizeof(mode),
					     DATA_FMT_UINT, field_data);
}

static int ima_eventinodexattrs_init_common(struct ima_event_data *event_data,
					    struct ima_field_data *field_data,
					    char type)
{
	u8 *buffer = NULL;
	int rc;

	if (!event_data->file)
		return 0;

	rc = evm_read_protected_xattrs(file_dentry(event_data->file), NULL, 0,
				       type, ima_canonical_fmt);
	if (rc < 0)
		return 0;

	buffer = kmalloc(rc, GFP_KERNEL);
	if (!buffer)
		return 0;

	rc = evm_read_protected_xattrs(file_dentry(event_data->file), buffer,
				       rc, type, ima_canonical_fmt);
	if (rc < 0) {
		rc = 0;
		goto out;
	}

	rc = ima_write_template_field_data((char *)buffer, rc, DATA_FMT_HEX,
					   field_data);
out:
	kfree(buffer);
	return rc;
}

/*
 *  ima_eventinodexattrnames_init - include a list of xattr names as part of the
 *  template data
 */
int ima_eventinodexattrnames_init(struct ima_event_data *event_data,
				  struct ima_field_data *field_data)
{
	return ima_eventinodexattrs_init_common(event_data, field_data, 'n');
}

/*
 *  ima_eventinodexattrlengths_init - include a list of xattr lengths as part of
 *  the template data
 */
int ima_eventinodexattrlengths_init(struct ima_event_data *event_data,
				    struct ima_field_data *field_data)
{
	return ima_eventinodexattrs_init_common(event_data, field_data, 'l');
}

/*
 *  ima_eventinodexattrvalues_init - include a list of xattr values as part of
 *  the template data
 */
int ima_eventinodexattrvalues_init(struct ima_event_data *event_data,
				   struct ima_field_data *field_data)
{
	return ima_eventinodexattrs_init_common(event_data, field_data, 'v');
}

/*
ima_eventpid_init - include current PID and child PIDs(if exists) of event as part of the template data
*/
int ima_eventpid_init(struct ima_event_data *event_data,
		      struct ima_field_data *field_data)
{
    struct task_struct *current_task = current;
    char *ppid_list = NULL;
    u32 pid = task_tgid_vnr(current);
    int buffer_size = 128;
    int offset = 0;

    if (ima_canonical_fmt)
        pid = (__force u32)cpu_to_le32(pid);

    // Allocate initial buffer for ppid_list
    ppid_list = kmalloc(buffer_size, GFP_KERNEL);
    memset(ppid_list, 0, buffer_size);

    // Add current PID to the list
    int len = snprintf(ppid_list + offset, buffer_size - offset, "%d", pid);
    offset += len;

    // Traverse up the process tree to collect parent PIDs
    while (current_task->real_parent != current_task) {
        current_task = current_task->real_parent;
        u32 parent_pid = task_tgid_vnr(current_task);
        char temp[16]; // Temporary buffer for sprintf

        len = snprintf(temp, sizeof(temp), "->%d", parent_pid);

        // Ensure we have enough space in ppid_list
        if (offset + len >= buffer_size) {
            buffer_size *= 2;
            char *new_ppid_list = krealloc(ppid_list, buffer_size, GFP_KERNEL);
            ppid_list = new_ppid_list;
        }

        strcat(ppid_list + offset, temp);
        offset += len;
    }

    //printk(KERN_INFO "PPID list: %s\n", ppid_list);

    // Write the collected PID list to field_data
    int result = ima_write_template_field_data(ppid_list, strlen(ppid_list),
                                               DATA_FMT_STRING, field_data);

    kfree(ppid_list);
    return result;
}

static char *str = NULL;

/* returns pointer to hlist_node */
static void *ima_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_queue_entry *qe;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(qe, &ima_measurements, later) {
		if (!l--) {
			rcu_read_unlock();
			return qe;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_queue_entry *qe = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	qe = list_entry_rcu(qe->later.next, struct ima_queue_entry, later);
	rcu_read_unlock();
	(*pos)++;

	return (&qe->later == &ima_measurements) ? NULL : qe;
}

static void ima_measurements_stop(struct seq_file *m, void *v)
{
}

static int pipeline_log_show(struct seq_file *m,void *v){
	char filename[256];
	strncpy(filename, m->file->f_path.dentry->d_iname, 256);
	//printk(KERN_INFO "my_proc_show: filename=%s\n", filename);
	//filename is the name of the file in /proc/pipelines/pipeline_<pipeline_id>
	// retrieve the pipeline_id from the filename, get pipeline_id from pipeline_<pipeline_id>
	// parse string pipeline_<pipeline_id> to get pipeline_id
	char *pipeline_id = filename + strlen("pipeline_");
	//printk(KERN_INFO "my_proc_show: pipeline_id=%s\n", pipeline_id);

	// print in ascii
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/* 4th:  template specific data */
	// check if template data has pipeline_id variable in it
	// Construct the search string "plid:<pipeline_id>"
    char search_str[256];
    snprintf(search_str, sizeof(search_str), "plid:%s", pipeline_id);
	bool plid_found = false;
	for (i = 0; i < e->template_desc->num_fields; i++) {
		// Check if the template data contains the search string
		if (strstr((const char *)e->template_data[i].data, search_str) != NULL) {
			plid_found = true;
			break;
		}
	}
	if (plid_found) {
		// Print the template data
		for (i = 0; i < e->template_desc->num_fields; i++) {
				seq_puts(m, " ");
				if (e->template_data[i].len == 0)
					continue;
				e->template_desc->fields[i]->field_show(m, IMA_SHOW_ASCII,
									&e->template_data[i]);
		}
		seq_puts(m, "\n");
	}
	return 0;
}

// for pipeline tree
static char buf[4096];    
static char *limit = buf;
static void *pipeline_tree_start(struct seq_file *s, loff_t *pos)
{
    if(*pos >= limit - buf) {
        return NULL;
    }
    char *data = buf + *pos;
    *pos = limit - buf;
    return data;
}

static void *pipeline_tree_next(struct seq_file *s, void *v, loff_t *pos)
{
    (*pos)++;
    return NULL; // Only one entry, so always return NULL
}

static void pipeline_tree_stop(struct seq_file *s, void *v)
{
    // No cleanup needed in this case
}

static int pipeline_tree_show(struct seq_file *s, void *v)
{
    seq_printf(s, "%s", (char *)v);
    return 0;
}

static int pipeline_command_log_show(struct seq_file *m,void *v){
	char filename[256];
	strncpy(filename, m->file->f_path.dentry->d_iname, 256);
	//printk(KERN_INFO "my_proc_show: filename=%s\n", filename);
	//filename is the name of the file in /proc/pipelines/pipeline_<pipeline_id>_<pipeline_job_id>
	// retrieve the pipeline_id and pipeline_job_id from the filename, get pipeline_id and pipeline_job_id from pipeline_<pipeline_id>_<pipeline_job_id>
	// parse string pipeline_<pipeline_id> to get pipeline_id, and pipeline_job_id
    // Skip "pipeline_"
    char *start = filename + strlen("pipeline_");
    // Extract pipeline_id (before the second "_")
    char pipeline_id[32];  // Adjust size as needed
    char *end = strchr(start, '_');
    if (end) {
        *end = '\0';  // Temporarily terminate string
        strncpy(pipeline_id, start, sizeof(pipeline_id));
        *end = '_';   // Restore original string
    } else {
        printk(KERN_ERR "Invalid filename format: %s\n", filename);
        return 0;
    }
    // Move start to after the first "_"
    start = end + 1;
    // Extract pipeline_job_id (rest of the string)
    char pipeline_job_id[32];  // Adjust size as needed
    strncpy(pipeline_job_id, start, sizeof(pipeline_job_id));

    // Print or use pipeline_id and pipeline_job_id as needed
    printk(KERN_INFO "Pipeline ID: %s, Pipeline Job ID: %s\n", pipeline_id, pipeline_job_id);

	// print in ascii
	// only print the pid/ppid and the command
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/* 4th:  template specific data */
	// check if template data has pipeline_id and pipeline_job_id variables in it
	// Construct the search string "plid:<pipeline_id> pljid:<pipeline_job_id>"
    char search_str[256];
    snprintf(search_str, sizeof(search_str), "plid:%s pljobid:%s", pipeline_id, pipeline_job_id);
	bool plid_found = false;
	for (i = 0; i < e->template_desc->num_fields; i++) {
		// Check if the template data contains the search string
		if (strstr((const char *)e->template_data[i].data, search_str) != NULL) {
			plid_found = true;
			break;
		}
	}
	if (plid_found) {
		// Print the template data
		for (i = 0; i < e->template_desc->num_fields; i++) {
				seq_puts(m, " ");
				if (e->template_data[i].len == 0)
					continue;
				// fields[0]: ppid list
				// fields[1]: plid
				// fields[2]: pljobid
				// fields[3]: ima hash
				// fields[4]: filename
				// fields[5]: command
				// only print fildes[0] and fields[5]
				if (i == 0 || i == 5) {
					e->template_desc->fields[i]->field_show(m, IMA_SHOW_ASCII,
									&e->template_data[i]);
				}
		}
		seq_puts(m, "\n");
	}
	return 0;
}


static const struct seq_operations pipeline_log_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = pipeline_log_show
};

static const struct seq_operations pipeline_command_log_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = pipeline_command_log_show
};

static const struct seq_operations pipeline_tree_seqops = {
	.start = pipeline_tree_start,
	.next = pipeline_tree_next,
	.stop = pipeline_tree_stop,
	.show = pipeline_tree_show
};

static int pipeline_log_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &pipeline_log_seqops);
}

static int pipeline_command_log_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &pipeline_command_log_seqops);
}

static int pipeline_tree_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pipeline_tree_seqops);
}

// Function called when data is written to the file
static ssize_t my_proc_write(struct file* file, const char __user *buffer, size_t count, loff_t *f_pos) {
    if (count >= sizeof(buf)) {
        printk(KERN_INFO "my_proc_write: input too large\n");
        return -EINVAL;
    }

    if (copy_from_user(buf, buffer, count)) {
        printk(KERN_INFO "my_proc_write: copy_from_user failed\n");
        return -EFAULT;
    }

    buf[count] = '\0'; // Null-terminate the buffer
    limit = buf + count; // Update limit to indicate the new end of the buffer

    printk(KERN_INFO "my_proc_write: data=%s\n", buf);
    return count;
}

static const struct proc_ops pipeline_log_fops = {
	.proc_open = pipeline_log_open,
    .proc_release = single_release,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_write = my_proc_write
};

static const struct proc_ops pipeline_job_commands_log_fops = {
	.proc_open = pipeline_command_log_open,
    .proc_release = single_release,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_write = my_proc_write
};

static const struct proc_ops pipeline_job_tree_fops = {
	.proc_open = pipeline_tree_open,
    .proc_release = single_release,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_write = my_proc_write
};


static struct proc_dir_entry *proc_dir;
int ima_write_pipeline_log(const char *pipeline_id)
{
	// create a file in /proc/ima_pipeline_logs/ with the pipeline_id and write the event_data to the file
	// if the file already exists, append the event_data to the file
	// return 0 on success, -1 on failure
    char *log_path;
    int ret = 0;

    // Allocate memory for the log path
    log_path = kmalloc(strlen("/proc/pipelines/pipeline_") + strlen(pipeline_id) + 1, GFP_KERNEL);
    if (!log_path)
        return -ENOMEM;

    // Construct the log file path
    sprintf(log_path, "/proc/pipelines/pipeline_%s", pipeline_id);

    // Create the log directory if it doesn't exist
    if (!proc_dir) {
        proc_dir = proc_mkdir("pipelines", NULL);
        if (!proc_dir) {
            kfree(log_path);
            return -ENOMEM;
        }
    }

    // Open the log file
	// Assuming pipeline_id is a variable representing the ID of the pipeline
	char log_file_name[64];
	snprintf(log_file_name, sizeof(log_file_name), "pipeline_%s", pipeline_id);

	// Create the log file under /proc/pipelines/pipeline_<pipeline_id>, skip if already exists
	// Check if the proc entry already exists
    // Construct the full path for lookup
    char full_path[128];
	struct path path;
    snprintf(full_path, sizeof(full_path), "/proc/pipelines/%s", log_file_name);
	static struct proc_dir_entry *log_file;

    // Lookup if the proc file already exists
    if (kern_path(full_path, LOOKUP_FOLLOW, &path) == 0) {
        //printk(KERN_INFO "Proc entry %s already exists, skipping creation\n", full_path);
        path_put(&path);  // Release the path
    } else {
        log_file = proc_create(log_file_name, 0644, proc_dir, &pipeline_log_fops);
        if (!log_file) {
            printk(KERN_ERR "Failed to create /proc/pipelines/%s\n", log_file_name);
            return -ENOMEM;
        }
        printk(KERN_INFO "Proc entry /proc/pipelines/%s created successfully\n", log_file_name);
    }
	return ret;
}

int ima_write_pipeline_command_log(const char *pipeline_id, const char *pipeline_job_id)
{
	// create a file in /proc/pipelines/ with the pipeline_id_job_id and write the whole command to the file
	// if the file already exists, append the event_data to the file
	// return 0 on success, -1 on failure
    char *log_path;
    int ret = 0;

    // Allocate memory for the log path
    log_path = kmalloc(strlen("/proc/pipelines/pipeline_") + strlen(pipeline_id) + strlen("_") + strlen(pipeline_job_id) + 1, GFP_KERNEL);
    if (!log_path) {
		printk(KERN_ERR "Failed to allocate memory for log path cmd log\n");
		return -ENOMEM;
	}

    // Construct the log file path
    sprintf(log_path, "/proc/pipelines/pipeline_%s_%s", pipeline_id, pipeline_job_id);

    // Create the log directory if it doesn't exist
    if (!proc_dir) {
        proc_dir = proc_mkdir("pipelines", NULL);
        if (!proc_dir) {
			printk(KERN_ERR "Failed to create /proc/pipelines\n");
            kfree(log_path);
            return -ENOMEM;
        }
    }

    // Open the log file
	// Assuming pipeline_id is a variable representing the ID of the pipeline, and pipeline_job_id is a variable representing the ID of the job
	char log_file_name[128];
	snprintf(log_file_name, sizeof(log_file_name), "pipeline_%s_%s", pipeline_id, pipeline_job_id);

	// Create the log file under /proc/pipelines/pipeline_<pipeline_id>_<pipeline_job_id>, skip if already exists
	// Check if the proc entry already exists
    // Construct the full path for lookup
    char full_path[256];
	struct path path;
    snprintf(full_path, sizeof(full_path), "/proc/pipelines/%s", log_file_name);
	static struct proc_dir_entry *log_file;

    // Lookup if the proc file already exists
    if (kern_path(full_path, LOOKUP_FOLLOW, &path) == 0) {
        //printk(KERN_INFO "Proc entry %s already exists, skipping creation\n", full_path);
        path_put(&path);  // Release the path
    } else {
        log_file = proc_create(log_file_name, 0644, proc_dir, &pipeline_job_commands_log_fops);
        if (!log_file) {
            printk(KERN_ERR "Failed to create /proc/pipelines/%s\n", log_file_name);
            return -ENOMEM;
        }
        printk(KERN_INFO "Proc entry /proc/pipelines/%s created successfully\n", log_file_name);
    }
	return ret;
}

int ima_write_pipeline_tree(const char *pipeline_id, const char *pipeline_job_id)
{
	// create a file in /proc/pipelines/ with the pipeline_id_job_id and write the whole command to the file
	// if the file already exists, append the event_data to the file
	// return 0 on success, -1 on failure
    char *log_path;
    int ret = 0;

    // Allocate memory for the log path
    log_path = kmalloc(strlen("/proc/pipelines/pipeline_") + strlen(pipeline_id) + strlen("_") + strlen(pipeline_job_id) + 1, GFP_KERNEL);
    if (!log_path) {
		printk(KERN_ERR "Failed to allocate memory for log path cmd log\n");
		return -ENOMEM;
	}

    // Construct the log file path
    sprintf(log_path, "/proc/pipelines/pipeline_%s_%s", pipeline_id, pipeline_job_id);

    // Create the log directory if it doesn't exist
    if (!proc_dir) {
        proc_dir = proc_mkdir("pipelines", NULL);
        if (!proc_dir) {
			printk(KERN_ERR "Failed to create /proc/pipelines\n");
            kfree(log_path);
            return -ENOMEM;
        }
    }

    // Open the log file
	// Assuming pipeline_id is a variable representing the ID of the pipeline, and pipeline_job_id is a variable representing the ID of the job
	char log_file_name[64];
	snprintf(log_file_name, sizeof(log_file_name), "pipeline_%s_%s", pipeline_id, pipeline_job_id);
	printk(KERN_INFO "Creating pipeline tree file: %s\n", log_file_name);

	// Create the log file under /proc/pipelines/pipeline_<pipeline_id>_<pipeline_job_id>, skip if already exists
	// Check if the proc entry already exists
    // Construct the full path for lookup
    char full_path[128];
	struct path path;
    snprintf(full_path, sizeof(full_path), "/proc/pipelines/%s", log_file_name);
	static struct proc_dir_entry *log_file;

    // Lookup if the proc file already exists
    if (kern_path(full_path, LOOKUP_FOLLOW, &path) == 0) {
        //printk(KERN_INFO "Proc entry %s already exists, skipping creation\n", full_path);
        path_put(&path);  // Release the path
    } else {
        log_file = proc_create(log_file_name, 0644, proc_dir, &pipeline_job_tree_fops);
        if (!log_file) {
            printk(KERN_ERR "Failed to create /proc/pipelines/%s\n", log_file_name);
            return -ENOMEM;
        }
        printk(KERN_INFO "Proc entry /proc/pipelines/%s created successfully\n", log_file_name);
    }
	return ret;
}

/*
ima_pipelineid_init - include PIPELINE_ID from process as part of template data
*/

int ima_pipelineid_init(struct ima_event_data *event_data,
		       struct ima_field_data *field_data)
{
    struct task_struct *current_task = current;
    char *pipeline_id = NULL;
    int buffer_size = 128;
    char *env = NULL;
    unsigned long env_offset = 0;

    // Allocate initial buffer for pipeline_id
    pipeline_id = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_id)
        return -ENOMEM;
    memset(pipeline_id, 0, buffer_size);

    // Traverse through parent processes to find PIPELINE_ID
    while (current_task->real_parent != current_task) {
        struct mm_struct *mm = current_task->mm;
        if (mm) {
            unsigned long env_start = mm->env_start;
            unsigned long env_end = mm->env_end;

            for (env_offset = env_start; env_offset < env_end; ) {
                // Calculate the length of the current environment variable
                size_t env_len = strnlen_user((const char __user *)env_offset, env_end - env_offset);
                if (env_len == 0 || env_len > env_end - env_offset) {
                    break;
                }

                env = kmalloc(env_len, GFP_KERNEL); // Allocate buffer for the environment variable
                if (!env) {
                    kfree(pipeline_id);
                    return -ENOMEM;
                }

                // Copy the environment variable from user space
                if (copy_from_user(env, (void __user *)env_offset, env_len)) {
                    kfree(env);
                    kfree(pipeline_id);
                    return -EFAULT;
                }
				//printk(KERN_INFO "env: %s\n", env);

                // Search for the PIPELINE_ID in the environment variable
                if (strncmp(env, "CI_PIPELINE_ID=", strlen("CI_PIPELINE_ID=")) == 0) {
                    // Find the value of PIPELINE_ID
					//printk(KERN_INFO "PIPELINE_ID found\n");

					// extract the value of PIPELINE_ID from env, cut the "CI_PIPELINE_ID=" prefix
					char *pipeline_id_value = env + strlen("CI_PIPELINE_ID=");
					//printk(KERN_INFO "PIPELINE_ID value: %s\n", pipeline_id_value);
					// add plid: prefix to the pipeline_id_value
					char *plid_prefix = "plid:";
					int plid_prefix_len = strlen(plid_prefix);
					int pipeline_id_value_len = strlen(pipeline_id_value);
					int total_len = plid_prefix_len + pipeline_id_value_len;
					char *pipeline_id_value_with_prefix = kmalloc(total_len, GFP_KERNEL);
					memcpy(pipeline_id_value_with_prefix, plid_prefix, plid_prefix_len);
					memcpy(pipeline_id_value_with_prefix + plid_prefix_len, pipeline_id_value, pipeline_id_value_len);

					// extract the value of JOB_NAME from env, but the "CI_JOB_NAME=" prefix
					

					// Write the collected PIPELINE_ID to field_data
					int result = ima_write_template_field_data(pipeline_id_value_with_prefix, strlen(pipeline_id_value_with_prefix), DATA_FMT_STRING, field_data);
					ima_write_pipeline_log(pipeline_id_value);
					//ima_create_merkle_tree(pipeline_id_value);
					kfree(pipeline_id);
					kfree(env);
					return result;
                }

                // Free the allocated environment variable buffer
                kfree(env);

                // Move to the next environment variable
                env_offset += env_len; // strnlen_user includes the null-terminator
            }
        }
        current_task = current_task->real_parent;
    }

    // PIPELINE_ID not found in the environment, return NULL data
    int failed_res = ima_write_template_field_data(pipeline_id, strlen(pipeline_id), DATA_FMT_STRING, field_data);
    kfree(pipeline_id);
    return failed_res;
}

/*
ima_pipeline_jobname_init - include JOBNAME of the pipeline in template data
							if CI_JOB_NAME is found, create a pipeline log file under /proc, and a merkle tree binary file under /proc/pipelines/pipeline_<pipeline_id>_tree.bin
							name of the CI_JOB_NAME is the target build component of the pipeline job
 */
int ima_pipeline_jobname_init(struct ima_event_data *event_data,
		       struct ima_field_data *field_data)
{
    struct task_struct *current_task = current;
    char *pipeline_jobname = NULL;
    int buffer_size = 128;
    char *env = NULL;
    unsigned long env_offset = 0;

    // Allocate initial buffer for jobname
    pipeline_jobname = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_jobname)
        return -ENOMEM;
    memset(pipeline_jobname, 0, buffer_size);

    // Traverse through parent processes to find JOB_NAME
    while (current_task->real_parent != current_task) {
        struct mm_struct *mm = current_task->mm;
        if (mm) {
            unsigned long env_start = mm->env_start;
            unsigned long env_end = mm->env_end;

            for (env_offset = env_start; env_offset < env_end; ) {
                // Calculate the length of the current environment variable
                size_t env_len = strnlen_user((const char __user *)env_offset, env_end - env_offset);
                if (env_len == 0 || env_len > env_end - env_offset) {
                    break;
                }

                env = kmalloc(env_len, GFP_KERNEL); // Allocate buffer for the environment variable
                if (!env) {
                    kfree(pipeline_jobname);
                    return -ENOMEM;
                }

                // Copy the environment variable from user space
                if (copy_from_user(env, (void __user *)env_offset, env_len)) {
                    kfree(env);
                    kfree(pipeline_jobname);
                    return -EFAULT;
                }
				//printk(KERN_INFO "env: %s\n", env);

                // Search for the CI_JOB_NAME in the environment variable
                if (strncmp(env, "CI_JOB_NAME=", strlen("CI_JOB_NAME=")) == 0) {
                    // Find the value of CI_JOB_NAME
					//printk(KERN_INFO "CI_JOB_NAME found\n");

					// extract the value of CI_JOB_NAME from env, cut the "CI_JOB_NAME=" prefix
					char *pipeline_jobname_value = env + strlen("CI_JOB_NAME=");
					printk(KERN_INFO "CI_JOB_NAME value: %s\n", pipeline_jobname_value);
					// add plid: prefix to the pipeline_jobname_value
					char *jobname_prefix = "pljobname:";
					int jobname_prefix_len = strlen(jobname_prefix);
					int jobname_value_len = strlen(pipeline_jobname_value);
					int total_len = jobname_prefix_len + jobname_value_len;
					char *jobname_value_with_prefix = kmalloc(total_len, GFP_KERNEL);
					memcpy(jobname_value_with_prefix, jobname_prefix, jobname_prefix_len);
					memcpy(jobname_value_with_prefix + jobname_prefix_len, pipeline_jobname_value, jobname_value_len);
					
					// Write the collected CI_JOB_NAME to field_data
					int result = ima_write_template_field_data(jobname_value_with_prefix, strlen(jobname_value_with_prefix), DATA_FMT_STRING, field_data);
					kfree(pipeline_jobname);
					kfree(env);
					return result;
                }

                // Free the allocated environment variable buffer
                kfree(env);

                // Move to the next environment variable
                env_offset += env_len; // strnlen_user includes the null-terminator
            }
        }
        current_task = current_task->real_parent;
    }

    // pipeline_jobname not found in the environment, return NULL data
    int failed_res = ima_write_template_field_data(pipeline_jobname, strlen(pipeline_jobname), DATA_FMT_STRING, field_data);
    kfree(pipeline_jobname);
    return failed_res;
}

/*
int ima_pipeline_jobid_init - include JOBID of the pipeline in template data
 */
int ima_pipeline_jobid_init(struct ima_event_data *event_data,
		       struct ima_field_data *field_data) 
{
    struct task_struct *current_task = current;
    char *pipeline_jobid = NULL;
    int buffer_size = 128;
    char *env = NULL;
    unsigned long env_offset = 0;

    // Allocate initial buffer for pipeline_jobid
    pipeline_jobid = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_jobid)
        return -ENOMEM;
    memset(pipeline_jobid, 0, buffer_size);

    // Traverse through parent processes to find JOB_NAME
    while (current_task->real_parent != current_task) {
        struct mm_struct *mm = current_task->mm;
        if (mm) {
            unsigned long env_start = mm->env_start;
            unsigned long env_end = mm->env_end;

            for (env_offset = env_start; env_offset < env_end; ) {
                // Calculate the length of the current environment variable
                size_t env_len = strnlen_user((const char __user *)env_offset, env_end - env_offset);
                if (env_len == 0 || env_len > env_end - env_offset) {
                    break;
                }

                env = kmalloc(env_len, GFP_KERNEL); // Allocate buffer for the environment variable
                if (!env) {
                    kfree(pipeline_jobid);
                    return -ENOMEM;
                }

                // Copy the environment variable from user space
                if (copy_from_user(env, (void __user *)env_offset, env_len)) {
                    kfree(env);
                    kfree(pipeline_jobid);
                    return -EFAULT;
                }
				//printk(KERN_INFO "env: %s\n", env);

                // Search for the CI_JOB_NAME in the environment variable
                if (strncmp(env, "CI_JOB_ID=", strlen("CI_JOB_ID=")) == 0) {
                    // Find the value of CI_JOB_NAME
					//printk(KERN_INFO "CI_JOB_NAME found\n");

					// extract the value of CI_JOB_NAME from env, cut the "CI_JOB_NAME=" prefix
					char *pipeline_jobid_value = env + strlen("CI_JOB_ID=");
					//printk(KERN_INFO "CI_JOB_NAME value: %s\n", pipeline_jobid_value);
					// add plid: prefix to the pipeline_jobid_value
					char *jobid_prefix = "pljobid:";
					int jobid_prefix_len = strlen(jobid_prefix); //jobid_prefix_len
					int jobid_value_len = strlen(pipeline_jobid_value); //jobid_value_len
					int total_len = jobid_prefix_len + jobid_value_len;
					char *jobid_value_with_prefix = kmalloc(total_len, GFP_KERNEL); //jobid_value_with_prefix
					memcpy(jobid_value_with_prefix, jobid_prefix, jobid_prefix_len);
					memcpy(jobid_value_with_prefix + jobid_prefix_len, pipeline_jobid_value, jobid_value_len);
					
					// Write the collected CI_JOB_NAME to field_data
					int result = ima_write_template_field_data(jobid_value_with_prefix, strlen(jobid_value_with_prefix), DATA_FMT_STRING, field_data);
					kfree(pipeline_jobid);
					kfree(env);
					return result;
                }

                // Free the allocated environment variable buffer
                kfree(env);

                // Move to the next environment variable
                env_offset += env_len; // strnlen_user includes the null-terminator
            }
        }
        current_task = current_task->real_parent;
    }

    // pipeline_jobname not found in the environment, return NULL data
    int failed_res = ima_write_template_field_data(pipeline_jobid, strlen(pipeline_jobid), DATA_FMT_STRING, field_data);
    kfree(pipeline_jobid);
    return failed_res;
}

/*
int ima_pipeline_command_init - include the whole command with arguments of a pipeline
 */
int ima_check_pipeline_jobend(struct ima_event_data *event_data,
		       struct ima_field_data *field_data) 
{
    struct task_struct *current_task = current;
    int buffer_size = 128;
    char *pipeline_jobid = NULL;
    char *pipeline_id = NULL;
    char *env = NULL;
    unsigned long env_offset = 0;
    int is_success = 0;

    // Allocate initial buffer for pipeline_id
    pipeline_id = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_id)
        return -ENOMEM;
    memset(pipeline_id, 0, buffer_size);

    // Allocate initial buffer for pipeline_jobid
    pipeline_jobid = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_jobid) {
        kfree(pipeline_id);
        return -ENOMEM;
    }
    memset(pipeline_jobid, 0, buffer_size);

    // Allocate buffers for storing values of pipeline_id and pipeline_jobid
    char *pipeline_id_value = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_id_value) {
        kfree(pipeline_id);
        kfree(pipeline_jobid);
        return -ENOMEM;
    }
    memset(pipeline_id_value, 0, buffer_size);

    char *pipeline_jobid_value = kmalloc(buffer_size, GFP_KERNEL);
    if (!pipeline_jobid_value) {
        kfree(pipeline_id);
        kfree(pipeline_jobid);
        kfree(pipeline_id_value);
        return -ENOMEM;
    }
    memset(pipeline_jobid_value, 0, buffer_size);

    // Traverse through argv to get the whole command with arguments
	// Also traverse through env to get the PIPELINE_ID and JOB_NAME
    while (current_task->real_parent != current_task) {
        struct mm_struct *mm = current_task->mm;
        if (mm) {
            unsigned long env_start = mm->env_start;
            unsigned long env_end = mm->env_end;

            // traverse through env to get the PIPELINE_ID and JOB_NAME
            for (env_offset = env_start; env_offset < env_end; ) {
                // Calculate the length of the current environment variable
                size_t env_len = strnlen_user((const char __user *)env_offset, env_end - env_offset);	
                if (env_len == 0 || env_len > env_end - env_offset) {
                    break;
                }
                env = kmalloc(env_len, GFP_KERNEL); // Allocate buffer for the environment variable
                if (!env) {
                    kfree(pipeline_jobid);
                    kfree(pipeline_id);
                    kfree(pipeline_id_value);
                    kfree(pipeline_jobid_value);
                    return -ENOMEM;
                }
                // Copy the environment variable from user space
                if (copy_from_user(env, (void __user *)env_offset, env_len)) {
                    kfree(env);
                    kfree(pipeline_jobid);
                    kfree(pipeline_id);
                    kfree(pipeline_id_value);
                    kfree(pipeline_jobid_value);
                    return -EFAULT;
                }
                // Search for the PIPELINE_ID and JOB_NAME in the environment variable
                if (strncmp(env, "CI_PIPELINE_ID=", strlen("CI_PIPELINE_ID=")) == 0) {
                    // Find the value of PIPELINE_ID
                    strncpy(pipeline_id_value, env + strlen("CI_PIPELINE_ID="), buffer_size - 1);
                    pipeline_id_value[buffer_size - 1] = '\0'; // Ensure null-termination
                }
                if (strncmp(env, "CI_JOB_ID=", strlen("CI_JOB_ID=")) == 0) {
                    // Find the value of JOB_NAME
                    strncpy(pipeline_jobid_value, env + strlen("CI_JOB_ID="), buffer_size - 1);
                    pipeline_jobid_value[buffer_size - 1] = '\0'; // Ensure null-termination
                }
                if (strcmp(env, "CI_JOB_STATUS=success") == 0) {
                    // check if CI_JOB_STATUS is set to "success", if "failed" return NULL data
                    printk(KERN_INFO "CI_JOB_STATUS is success\n");
                    is_success = 1;
                }
                // Free the allocated environment variable buffer
                kfree(env);
                // Move to the next environment variable
                env_offset += env_len; // strnlen_user includes the null-terminator
            }
            if (pipeline_id_value[0] != '\0' && pipeline_jobid_value[0] != '\0' && is_success == 1) {
                // this means that this is the last of the pipeline job, and the job is successful
                printk(KERN_INFO "PIPELINE_ID value: %s\n", pipeline_id_value);
                printk(KERN_INFO "PIPELINE_JOB_ID value: %s\n", pipeline_jobid_value);
                ima_write_pipeline_tree(pipeline_id_value, pipeline_jobid_value);
            }
        }
        current_task = current_task->real_parent;
    }

    // Free allocated buffers
    kfree(pipeline_id);
    kfree(pipeline_jobid);
    kfree(pipeline_id_value);
    kfree(pipeline_jobid_value);

    // command not found in the argument, return NULL data
    int failed_res = ima_write_template_field_data(pipeline_jobid, strlen(pipeline_jobid), DATA_FMT_STRING, field_data);
    return failed_res;
}
