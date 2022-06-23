/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>

#ifdef CONFIG_FS_ENCRYPTION
bool btrfs_fscrypt_match_name(const struct fscrypt_name *fname,
			      struct extent_buffer *leaf,
			      unsigned long de_name, u32 de_name_len);

#else
static bool btrfs_fscrypt_match_name(const struct fscrypt_name *fname,
				     struct extent_buffer *leaf,
				     unsigned long de_name, u32 de_name_len)
{
	if (de_name_len != fname->disk_name.len)
		return false;
	return !memcmp_extent_buffer(leaf, fname->disk_name.name,
				     de_name, de_name_len);
}
#endif

extern const struct fscrypt_operations btrfs_fscrypt_ops;
#endif /* BTRFS_FSCRYPT_H */
