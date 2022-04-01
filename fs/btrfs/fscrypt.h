/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>

#define BTRFS_ENCRYPTION_POLICY_MASK 0x0f
#define BTRFS_ENCRYPTION_IVSIZE_MASK 0xf0

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
					   u8 *ivsize)
{
	if (policy)
		*policy = encryption & BTRFS_ENCRYPTION_POLICY_MASK;
	if (ivsize) {
		u8 transformed_ivsize =
			(encryption & BTRFS_ENCRYPTION_IVSIZE_MASK) >> 4;
		*ivsize = (transformed_ivsize ?
			   (1 << (transformed_ivsize - 1)) : 0);
	}
}

static inline u8 btrfs_pack_encryption(u8 policy, u8 ivsize)
{
	u8 transformed_ivsize = ivsize ? ilog2(ivsize) + 1 : 0;
	return policy | (transformed_ivsize << 4);
}

extern const struct fscrypt_operations btrfs_fscrypt_ops;
#endif /* BTRFS_FSCRYPT_H */
