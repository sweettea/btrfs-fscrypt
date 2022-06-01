/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>

#define BTRFS_ENCRYPTION_POLICY_BITS 2
#define BTRFS_ENCRYPTION_CTXSIZE_BITS 6

#define BTRFS_ENCRYPTION_POLICY_MASK ((1 << BTRFS_ENCRYPTION_POLICY_BITS) - 1)
#define BTRFS_ENCRYPTION_CTXSIZE_MASK \
	(((1 << BTRFS_ENCRYPTION_CTXSIZE_BITS) - 1) << \
		BTRFS_ENCRYPTION_POLICY_BITS)

#ifdef CONFIG_FS_ENCRYPTION
struct btrfs_fscrypt_extent_context {
	u8 buffer[FSCRYPT_EXTENT_CONTEXT_MAX_SIZE];
	u8 len;
};
#else
struct btrfs_fscrypt_extent_context {
	u8 len;
};
#endif

static inline void btrfs_unpack_encryption(u8 encryption,
					   u8 *policy,
					   u8 *ctxsize)
{
	if (policy)
		*policy = encryption & BTRFS_ENCRYPTION_POLICY_MASK;
	if (ctxsize)
		*ctxsize = ((encryption & BTRFS_ENCRYPTION_CTXSIZE_MASK) >>
			    BTRFS_ENCRYPTION_POLICY_BITS);
}

static inline u8 btrfs_pack_encryption(u8 policy, u8 ctxsize)
{
	return policy | (ctxsize << BTRFS_ENCRYPTION_POLICY_BITS);
}

extern const struct fscrypt_operations btrfs_fscrypt_ops;

#endif /* BTRFS_FSCRYPT_H */
