/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>

#define BTRFS_ENCRYPTION_POLICY_MASK 0x03
#define BTRFS_ENCRYPTION_CTXSIZE_MASK 0xfc

struct btrfs_fscrypt_extent_context {
	u8 buffer[FSCRYPT_EXTENT_CONTEXT_MAX_SIZE];
	size_t len;
};

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

static inline void btrfs_unpack_encryption(u8 encryption,
					   u8 *policy,
					   u8 *ctxsize)
{
	if (policy)
		*policy = encryption & BTRFS_ENCRYPTION_POLICY_MASK;
	if (ctxsize)
		*ctxsize = (encryption & BTRFS_ENCRYPTION_CTXSIZE_MASK) >> 2;
}

static inline u8 btrfs_pack_encryption(u8 policy, u8 ctxsize)
{
	return policy | (ctxsize << 2);
}

extern const struct fscrypt_operations btrfs_fscrypt_ops;
#endif /* BTRFS_FSCRYPT_H */
