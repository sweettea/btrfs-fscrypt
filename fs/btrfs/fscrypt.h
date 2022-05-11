/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/refcount.h>

bool btrfs_fscrypt_match_name(const struct fscrypt_name *fname,
			      struct extent_buffer *leaf,
			      unsigned long de_name, u32 de_name_len);

#ifdef CONFIG_FS_ENCRYPTION
extern const struct fscrypt_operations btrfs_fscrypt_ops;

#endif
struct iv {
	u8 iv[32];
	refcount_t refs;
};

static inline struct iv *alloc_iv(void)
{
	struct iv *iv = kzalloc(sizeof(struct iv), GFP_NOFS);
	if (!iv)
		return iv;
	refcount_set(&iv->refs, 1);
	return iv;
}

static inline void put_iv(struct iv *iv)
{
	if (iv && refcount_dec_and_test(&iv->refs))
		kfree(iv);
}

static inline struct iv *get_iv(struct iv *iv)
{
	if (iv)
		refcount_inc(&iv->refs);
	return iv;
}

static inline void btrfs_unpack_encryption(u8 encryption,
					   u8 *policy,
					   u8 *ivsize)
{
	if (policy)
		*policy = encryption & 0xf;
	if (ivsize) {
		u8 transformed_ivsize = (encryption & 0xf0) >> 4;
		*ivsize = (transformed_ivsize ?
			   (1 << (transformed_ivsize - 1)) : 0);
	}
}	

static inline u8 btrfs_pack_encryption(u8 policy, u8 ivsize)
{
	u8 transformed_ivsize = ivsize ? ilog2(ivsize) + 1 : 0;
	return policy | (transformed_ivsize << 4);
}	

#endif /* BTRFS_FSCRYPT_H */
