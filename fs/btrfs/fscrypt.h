/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>
#include "extent_io.h"

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

#ifdef CONFIG_FS_ENCRYPTION
bool btrfs_fscrypt_match_name(struct fscrypt_name *fname,
			      struct extent_buffer *leaf,
			      unsigned long de_name, u32 de_name_len);

#else
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
