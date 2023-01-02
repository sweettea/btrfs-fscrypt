/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>
#include "accessors.h"
#include "extent_io.h"

#include "fs.h"

static inline u32
btrfs_file_extent_encryption_ctxsize(const struct extent_buffer *eb,
				     struct btrfs_file_extent_item *e)
{
	if (!btrfs_file_extent_encryption(eb, e))
		return 0;

	return btrfs_get_32(eb, e, offsetof(struct btrfs_file_extent_item,
					    encryption_context));
}

static inline u8
btrfs_file_extent_ctxsize_from_item(const struct extent_buffer *leaf,
				    const struct btrfs_path *path)
{
	return (btrfs_item_size(leaf, path->slots[0]) -
		sizeof(struct btrfs_file_extent_item));
}


#ifdef CONFIG_FS_ENCRYPTION
int btrfs_fscrypt_get_disk_name(struct extent_buffer *leaf,
				struct btrfs_dir_item *di,
				struct fscrypt_str *qstr);

bool btrfs_fscrypt_match_name(struct fscrypt_name *fname,
			      struct extent_buffer *leaf,
			      unsigned long de_name, u32 de_name_len);

#else
static inline int btrfs_fscrypt_get_disk_name(struct extent_buffer *leaf,
					      struct btrfs_dir_item *di,
					      struct fscrypt_str *qstr)
{
	return 0;
}

static inline bool btrfs_fscrypt_match_name(struct fscrypt_name *fname,
					    struct extent_buffer *leaf,
					    unsigned long de_name,
					    u32 de_name_len)
{
	if (de_name_len != fname_len(fname))
		return false;
	return !memcmp_extent_buffer(leaf, fname->disk_name.name, de_name,
				     de_name_len);
}
#endif /* CONFIG_FS_ENCRYPTION */

void btrfs_fscrypt_copy_fscrypt_info(struct btrfs_inode *inode,
				     struct fscrypt_info *from,
				     struct fscrypt_info **to_ptr);

extern const struct fscrypt_operations btrfs_fscrypt_ops;

#endif /* BTRFS_FSCRYPT_H */
