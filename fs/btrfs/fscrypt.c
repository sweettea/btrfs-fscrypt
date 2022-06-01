// SPDX-License-Identifier: GPL-2.0

#include <linux/iversion.h>
#include "ctree.h"
#include "accessors.h"
#include "btrfs_inode.h"
#include "disk-io.h"
#include "fs.h"
#include "fscrypt.h"
#include "ioctl.h"
#include "messages.h"
#include "transaction.h"
#include "xattr.h"
#include "fscrypt.h"

static int btrfs_fscrypt_get_context(struct inode *inode, void *ctx, size_t len)
{
	struct btrfs_key key = {
		.objectid = btrfs_ino(BTRFS_I(inode)),
		.type = BTRFS_FSCRYPT_CTXT_ITEM_KEY,
		.offset = 0,
	};
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	unsigned long ptr;
	int ret;


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

static int btrfs_fscrypt_set_context(struct inode *inode, const void *ctx,
				     size_t len, void *fs_data)
{
	struct btrfs_path *path;
	int ret;
	struct btrfs_trans_handle *trans = fs_data;
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
	.get_context = btrfs_fscrypt_get_context,
	.set_context = btrfs_fscrypt_set_context,
	.empty_dir = btrfs_fscrypt_empty_dir,
};
