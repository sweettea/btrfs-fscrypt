/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fs.h>
#include <linux/fscrypt.h>

bool btrfs_fscrypt_match_name(const struct fscrypt_name *fname,
			      struct extent_buffer *leaf,
			      unsigned long de_name, u32 de_name_len);

#ifdef CONFIG_FS_ENCRYPTION
extern const struct fscrypt_operations btrfs_fscrypt_ops;
#endif

#endif /* BTRFS_FSCRYPT_H */
