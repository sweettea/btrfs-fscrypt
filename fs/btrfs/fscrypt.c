// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Facebook
 */

#include <linux/iversion.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "fscrypt.h"
#include "transaction.h"
#include "xattr.h"

/*
 * TODO: should explicit IV policies be mandatory for Btrfs? Or at least for
 * snapshots?
 */

#define BTRFS_XATTR_NAME_ENCRYPTION_CONTEXT "c"

/* fscrypt_match_name() but for an extent_buffer. */
bool btrfs_fscrypt_match_name(const struct fscrypt_name *fname,
			      struct extent_buffer *leaf, unsigned long de_name,
			      u32 de_name_len)
{
	const struct fscrypt_nokey_name *nokey_name =
		(const void *)fname->crypto_buf.name;
	u8 digest[SHA256_DIGEST_SIZE];

	if (likely(fname->disk_name.name)) {
		if (de_name_len != fname->disk_name.len)
			return false;
		return !memcmp_extent_buffer(leaf, fname->disk_name.name,
					     de_name, de_name_len);
	}
	if (de_name_len <= sizeof(nokey_name->bytes))
		return false;
	if (memcmp_extent_buffer(leaf, nokey_name->bytes, de_name,
				 sizeof(nokey_name->bytes)))
		return false;
	extent_buffer_sha256(leaf, de_name + sizeof(nokey_name->bytes),
			     de_name_len - sizeof(nokey_name->bytes), digest);
	return !memcmp(digest, nokey_name->sha256, sizeof(digest));
}

static int btrfs_fscrypt_get_context(struct inode *inode, void *ctx, size_t len)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct inode *put_inode = NULL;
	int ret;

	if (S_ISREG(inode->i_mode) &&
	    (btrfs_root_flags(&root->root_item) & BTRFS_ROOT_SUBVOL_FSCRYPT)) {
		/*
		 * TODO: don't look up the xattr every time
		 * TODO: only do this for explicit IV policies (or make them
		 * mandatory)
		 * TODO: maybe zero out the nonce?
		 */
		inode = btrfs_iget(inode->i_sb, BTRFS_FIRST_FREE_OBJECTID,
				   root);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
		put_inode = inode;
	}
	ret = btrfs_getxattr(inode, BTRFS_XATTR_NAME_ENCRYPTION_CONTEXT, ctx,
			     len);
	iput(put_inode);
	return ret;
}

static int btrfs_fscrypt_set_context(struct inode *inode, const void *ctx,
				     size_t len, void *fs_data)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	int is_subvolume = inode->i_ino == BTRFS_FIRST_FREE_OBJECTID;
	int ret;

	/*
	 * If the whole subvolume is encrypted, we can get the policy for
	 * regular files from the root inode.
	 *
	 * TODO: only do this for explicit IV policies (or make them mandatory)
	 * TODO: for directories, only store the nonce and get the rest from the
	 * subvolume?
	 */
	if (S_ISREG(inode->i_mode) &&
	    (btrfs_root_flags(&root->root_item) & BTRFS_ROOT_SUBVOL_FSCRYPT))
		return 0;

	if (fs_data) {
		/*
		 * We are setting the context as part of an existing
		 * transaction. This happens when we are inheriting the context
		 * for a new inode.
		 */
		trans = fs_data;
	} else {
		/*
		 * 1 for the xattr item
		 * 1 for the inode item
		 * 1 for the root item if the inode is a subvolume
		 */
		trans = btrfs_start_transaction(root, 2 + is_subvolume);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}

	ret = btrfs_setxattr(trans, inode, BTRFS_XATTR_NAME_ENCRYPTION_CONTEXT,
			     ctx, len, 0);
	if (ret)
		goto out;

	BTRFS_I(inode)->flags |= BTRFS_INODE_FSCRYPT_CONTEXT;
	btrfs_sync_inode_flags_to_i_flags(inode);
	if (!fs_data) {
		inode_inc_iversion(inode);
		inode->i_ctime = current_time(inode);
		ret = btrfs_update_inode(trans, root, BTRFS_I(inode));
		if (ret)
			goto out;
		/*
		 * For new subvolumes, the root item is already initialized with
		 * the BTRFS_ROOT_SUBVOL_FSCRYPT flag.
		 */
		if (is_subvolume) {
			u64 root_flags = btrfs_root_flags(&root->root_item);

			btrfs_set_root_flags(&root->root_item,
					     root_flags |
					     BTRFS_ROOT_SUBVOL_FSCRYPT);
			ret = btrfs_update_root(trans, root->fs_info->tree_root,
						&root->root_key,
						&root->root_item);
		}
	}
out:
	if (!fs_data)
		btrfs_end_transaction(trans);
	return ret;
}

static bool btrfs_fscrypt_empty_dir(struct inode *inode)
{
	return (inode->i_size == BTRFS_EMPTY_DIR_SIZE ||
		/*
		 * TODO: I think this is going to end up being too racy, and we
		 * just want to atomically snapshot + enable encryption.
		 *
		 * TODO: we probably shouldn't allow setting an encryption
		 * policy on a non-empty subvolume if it contains any encrypted
		 * directories, but that's going to require some extra tracking.
		 * (But should we allow it if the encrypted directory uses the
		 * same policy that we're trying to set?)
		 */
		inode->i_ino == BTRFS_FIRST_FREE_OBJECTID);
}

const struct fscrypt_operations btrfs_fscrypt_ops = {
	/* TODO: FS_CFLG_OWN_PAGES? */
	.flags = FS_CFLG_ALLOW_PARTIAL,
	.key_prefix = "btrfs:",
	.get_context = btrfs_fscrypt_get_context,
	.set_context = btrfs_fscrypt_set_context,
	.empty_dir = btrfs_fscrypt_empty_dir,
};
