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
	struct btrfs_key key;
	struct btrfs_path *path;
	int ret;

	if (S_ISREG(inode->i_mode) &&
	    (btrfs_root_flags(&root->root_item) & BTRFS_ROOT_SUBVOL_FSCRYPT)) {
		/* TODO: cache the item */
		inode = btrfs_iget(inode->i_sb, BTRFS_FIRST_FREE_OBJECTID,
				   root);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
		put_inode = inode;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key = (struct btrfs_key) {
		.objectid = btrfs_ino(BTRFS_I(inode)),
		.type = BTRFS_FSCRYPT_CTXT_ITEM_KEY,
		.offset = 0,
	};

	ret = btrfs_search_slot(NULL, BTRFS_I(inode)->root, &key, path, 0, 0);
	if (!ret) {
		struct extent_buffer *leaf = path->nodes[0];
		unsigned long ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);
		/* fscrypt provides max context length, but it could be less */
		len = min_t(size_t, len, btrfs_item_size(leaf, path->slots[0]));
		read_extent_buffer(leaf, ctx, ptr, len);
	} else {
		return -EINVAL;
	}

	btrfs_free_path(path);	
	iput(put_inode);
	return len;
}

static int btrfs_fscrypt_set_context(struct inode *inode, const void *ctx,
				     size_t len, void *fs_data)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	int is_subvolume = inode->i_ino == BTRFS_FIRST_FREE_OBJECTID;
	int ret;
	struct btrfs_key key = {
		.objectid = btrfs_ino(BTRFS_I(inode)),
		.type = BTRFS_FSCRYPT_CTXT_ITEM_KEY,
		.offset = 0,
	};

	/*
	 * If the whole subvolume is encrypted, we can get the policy for
	 * regular files from the root inode.
	 *
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
		 * 1 for the inode item
		 * 1 for the root item if the inode is a subvolume
		 */
		trans = btrfs_start_transaction(root, 1 + is_subvolume);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}

	ret = btrfs_insert_item(trans, BTRFS_I(inode)->root, &key, ctx, len);
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

static void btrfs_fscrypt_get_iv(u8 *iv, int ivsize, struct inode *inode,
				 u64 lblk_num)
{
	__le64 *iv_64 = (__le64 *)iv;
	u64 offset = lblk_num << inode->i_blkbits; 
	struct extent_map *em = btrfs_get_extent(BTRFS_I(inode), NULL, 0, offset, PAGE_SIZE);
	if (em) {
		memcpy(iv, em->iv, ivsize);
		/* 
		 * Add the lblk_num to the low bits of the IV to ensure
		 * the IV changes for every page
		 */
		*iv_64 = cpu_to_le64(le64_to_cpu(*iv_64) + lblk_num);
		return;
	} 

	/*
	 * For encryption that doesn't involve extent data, we use a policy
	 * equivalent to the standard FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64.
	 */
	lblk_num |= (u64)inode->i_ino << 32;
	*iv_64 = cpu_to_le64(lblk_num);
}

const struct fscrypt_operations btrfs_fscrypt_ops = {
	/* TODO: FS_CFLG_OWN_PAGES? */
	.flags = FS_CFLG_ALLOW_PARTIAL,
	.key_prefix = "btrfs:",
	.get_context = btrfs_fscrypt_get_context,
	.set_context = btrfs_fscrypt_set_context,
	.empty_dir = btrfs_fscrypt_empty_dir,
	.get_fs_defined_iv = btrfs_fscrypt_get_iv,
};
