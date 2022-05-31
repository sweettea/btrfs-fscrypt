// SPDX-License-Identifier: GPL-2.0

#include <linux/iversion.h>
#include "ctree.h"
#include "accessors.h"
#include "btrfs_inode.h"
#include "disk-io.h"
#include "ioctl.h"
#include "fs.h"
#include "fscrypt.h"
#include "messages.h"
#include "transaction.h"
#include "xattr.h"
#include "root-tree.h"

/*
 * This function is extremely similar to fscrypt_match_name() but uses an
 * extent_buffer. Also, it edits the provided argument to populate the disk_name
 * if we successfully match and previously were using a nokey name.
 */
bool btrfs_fscrypt_match_name(struct fscrypt_name *fname,
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
	if (!memcmp(digest, nokey_name->sha256, sizeof(digest))) {
		/*
		 * For no-key names, we use this opportunity to find the disk
		 * name, so future searches don't need to deal with nokey names
		 * and we know what the encrypted size is.
		 */
		fname->disk_name.name = kmalloc(de_name_len, GFP_KERNEL | GFP_NOFS);
		if (!fname->disk_name.name)
			fname->disk_name.name = ERR_PTR(-ENOMEM);
		else
			read_extent_buffer(leaf, fname->disk_name.name,
					   de_name, de_name_len);
		fname->disk_name.len = de_name_len;
		return true;
	}
	return false;
}

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

static void btrfs_fscrypt_update_context(struct btrfs_path *path,
					 const void *ctx, size_t len)
{
	struct extent_buffer *leaf = path->nodes[0];
	unsigned long ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);

	len = min_t(size_t, len, btrfs_item_size(leaf, path->slots[0]));
	write_extent_buffer(leaf, ctx, ptr, len);
	btrfs_mark_buffer_dirty(leaf);
}

static int __btrfs_fscrypt_set_context(struct inode *inode,
				       struct btrfs_trans_handle *trans,
				       const void *ctx, size_t len)
{
	struct btrfs_path *path;
	int ret;
	struct btrfs_key key = {
		.objectid = btrfs_ino(BTRFS_I(inode)),
		.type = BTRFS_FSCRYPT_CTXT_ITEM_KEY,
		.offset = 0,
	};

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(trans, BTRFS_I(inode)->root, &key, path, 0, 1);
	if (ret == 0) {
		btrfs_fscrypt_update_context(path, ctx, len);
		btrfs_free_path(path);
		return ret;
	}

	btrfs_free_path(path);
	if (ret < 0)
		return ret;

	ret = btrfs_insert_item(trans, BTRFS_I(inode)->root, &key, (void *) ctx, len);
	if (ret)
		return ret;

	BTRFS_I(inode)->flags |= BTRFS_INODE_FSCRYPT_CONTEXT;
	btrfs_sync_inode_flags_to_i_flags(inode);
	inode_inc_iversion(inode);
	inode->i_ctime = current_time(inode);
	ret = btrfs_update_inode(trans, BTRFS_I(inode)->root, BTRFS_I(inode));
	if (!ret)
		return ret;

	btrfs_abort_transaction(trans, ret);
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
		ret = fscrypt_have_same_policy(inode, root_inode, &same_policy);
		iput(root_inode);

		if (ret)
			return ret;
		if (same_policy)
			return 0;
	}

	if (fs_data) {
		/*
		 * We are setting the context as part of an existing
		 * transaction. This happens when we are inheriting the context
		 * for a new inode.
		 */
		return __btrfs_fscrypt_set_context(inode, fs_data, ctx, len);
	}

	/*
	 * 1 for the inode item
	 * 1 for the fscrypt item
	 * 1 for the root item if the inode is a subvolume
	 */
	trans = btrfs_start_transaction(root, 2 + is_subvolume);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = __btrfs_fscrypt_set_context(inode, trans, ctx, len);

	/*
	 * For new subvolumes, the root item is already initialized with
	 * the BTRFS_ROOT_SUBVOL_FSCRYPT flag.
	 */
	if (!ret && is_subvolume) {
		u64 root_flags = btrfs_root_flags(&root->root_item);

		btrfs_set_root_flags(&root->root_item,
				     root_flags |
				     BTRFS_ROOT_SUBVOL_FSCRYPT);
		ret = btrfs_update_root(trans, root->fs_info->tree_root,
					&root->root_key,
					&root->root_item);
	}

	btrfs_end_transaction(trans);
	return ret;
}

static bool btrfs_fscrypt_empty_dir(struct inode *inode)
{
	return inode->i_size == BTRFS_EMPTY_DIR_SIZE;
}

static int btrfs_fscrypt_get_extent_context(const struct inode *inode,
					    u64 lblk_num, void *ctx,
					    size_t len,
					    size_t *extent_offset,
					    size_t *extent_length)
{
	u64 offset = lblk_num << inode->i_blkbits;
	struct extent_map *em;
	int ret;

	/* Since IO must be in progress on this extent, this must succeed */
	em = btrfs_get_extent(BTRFS_I(inode), NULL, 0, offset, PAGE_SIZE);
	if (!em)
		return -EINVAL;

	if (em->block_start == EXTENT_MAP_HOLE) {
		btrfs_info(BTRFS_I(inode)->root->fs_info,
			   "extent context requested for block %llu of inode %lu without an extent",
			   lblk_num, inode->i_ino);
		free_extent_map(em);
		return -ENOENT;
	}

	ret = ctx ? em->fscrypt_context.len : 0;

	if (ctx)
		memcpy(ctx, em->fscrypt_context.buffer,
		       em->fscrypt_context.len);

	if (extent_offset)
		*extent_offset
			 = (offset - em->start) >> inode->i_blkbits;

	if (extent_length)
		*extent_length = em->len >> inode->i_blkbits;

	free_extent_map(em);
	return ret;
}

static int btrfs_fscrypt_set_extent_context(void *extent, void *ctx,
					    size_t len)
{
	struct btrfs_fscrypt_extent_context *extent_context = extent;

	memcpy(extent_context->buffer, ctx, len);
	extent_context->len = len;
	return 0;
}

const struct fscrypt_operations btrfs_fscrypt_ops = {
	.key_prefix = "btrfs:",
	.get_context = btrfs_fscrypt_get_context,
	.set_context = btrfs_fscrypt_set_context,
	.empty_dir = btrfs_fscrypt_empty_dir,
	.get_extent_context = btrfs_fscrypt_get_extent_context,
	.set_extent_context = btrfs_fscrypt_set_extent_context,
};
