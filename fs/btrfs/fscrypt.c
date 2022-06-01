// SPDX-License-Identifier: GPL-2.0

#include <linux/iversion.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "disk-io.h"
#include "fscrypt.h"
#include "transaction.h"
#include "xattr.h"

static int btrfs_fscrypt_get_context(struct inode *inode, void *ctx, size_t len)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key key = {
		.objectid = btrfs_ino(BTRFS_I(inode)),
		.type = BTRFS_FSCRYPT_CTXT_ITEM_KEY,
		.offset = 0,
	};
	struct inode *put_inode = NULL;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	unsigned long ptr;
	int ret;


	if (btrfs_root_flags(&root->root_item) & BTRFS_ROOT_SUBVOL_FSCRYPT) {
		inode = btrfs_iget(inode->i_sb, BTRFS_FIRST_FREE_OBJECTID,
				   root);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
		put_inode = inode;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(NULL, BTRFS_I(inode)->root, &key, path, 0, 0);
	if (ret) {
		len = -EINVAL;
		goto out;
	}

	leaf = path->nodes[0];
	ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);
	/* fscrypt provides max context length, but it could be less */
	len = min_t(size_t, len, btrfs_item_size(leaf, path->slots[0]));
	read_extent_buffer(leaf, ctx, ptr, len);

out:
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
	struct btrfs_path *path;
	struct btrfs_key key = {
		.objectid = btrfs_ino(BTRFS_I(inode)),
		.type = BTRFS_FSCRYPT_CTXT_ITEM_KEY,
		.offset = 0,
	};

	/*
	 * If the whole subvolume is encrypted, we expect that all children
	 * have the same policy.
	 */
	if (btrfs_root_flags(&root->root_item) & BTRFS_ROOT_SUBVOL_FSCRYPT) {
		bool same_policy;
		struct inode *root_inode = NULL;

		root_inode = btrfs_iget(inode->i_sb, BTRFS_FIRST_FREE_OBJECTID,
				   root);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
		same_policy = fscrypt_have_same_policy(inode, root_inode);
		iput(root_inode);
		if (same_policy)
			return 0;
	}

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
		 * 1 for the fscrypt item
		 * 1 for the root item if the inode is a subvolume
		 */
		trans = btrfs_start_transaction(root, 2 + is_subvolume);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	ret = btrfs_search_slot(trans, BTRFS_I(inode)->root, &key, path, 0, 1);
	if (ret == 0) {
		struct extent_buffer *leaf = path->nodes[0];
		unsigned long ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);

		len = min_t(size_t, len, btrfs_item_size(leaf, path->slots[0]));
		write_extent_buffer(leaf, ctx, ptr, len);
		btrfs_mark_buffer_dirty(leaf);
		btrfs_free_path(path);
		goto out;
	} else if (ret < 0) {
		goto out;
	}
	btrfs_free_path(path);

	ret = btrfs_insert_item(trans, BTRFS_I(inode)->root, &key, (void *) ctx, len);
	if (ret)
		goto out;

	BTRFS_I(inode)->flags |= BTRFS_INODE_FSCRYPT_CONTEXT;
	btrfs_sync_inode_flags_to_i_flags(inode);
	inode_inc_iversion(inode);
	inode->i_ctime = current_time(inode);
	ret = btrfs_update_inode(trans, root, BTRFS_I(inode));
	if (ret)
		goto out_fatal;

	/*
	 * For new subvolumes, the root item is already initialized with
	 * the BTRFS_ROOT_SUBVOL_FSCRYPT flag.
	 */
	if (!fs_data && is_subvolume) {
		u64 root_flags = btrfs_root_flags(&root->root_item);

		btrfs_set_root_flags(&root->root_item,
				     root_flags |
				     BTRFS_ROOT_SUBVOL_FSCRYPT);
		ret = btrfs_update_root(trans, root->fs_info->tree_root,
					&root->root_key,
					&root->root_item);
	}
	if (!ret)
		goto out;

out_fatal:
	if (fs_data)
		return ret;

	btrfs_abort_transaction(trans, ret);

out:
	if (fs_data)
		return ret;

	btrfs_end_transaction(trans);
	return ret;
}

static bool btrfs_fscrypt_empty_dir(struct inode *inode)
{
	return inode->i_size == BTRFS_EMPTY_DIR_SIZE;
}

const struct fscrypt_operations btrfs_fscrypt_ops = {
	.key_prefix = "btrfs:",
	.get_context = btrfs_fscrypt_get_context,
	.set_context = btrfs_fscrypt_set_context,
	.empty_dir = btrfs_fscrypt_empty_dir,
};
