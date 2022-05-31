// SPDX-License-Identifier: GPL-2.0

#include <linux/iversion.h>
#include "ctree.h"
#include "accessors.h"
#include "btrfs_inode.h"
#include "disk-io.h"
#include "ioctl.h"
#include "fs.h"
#include "fscrypt.h"
#include "ioctl.h"
#include "messages.h"
#include "root-tree.h"
#include "transaction.h"
#include "xattr.h"

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

	if (!trans)
		trans = btrfs_start_transaction(BTRFS_I(inode)->root, 1);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = btrfs_search_slot(trans, BTRFS_I(inode)->root, &key, path, 0, 1);
	if (ret == 0) {
		btrfs_fscrypt_update_context(path, ctx, len);
		btrfs_free_path(path);
		return ret;
	}

	btrfs_free_path(path);
	if (ret < 0) {
		btrfs_abort_transaction(trans, ret);
		return ret;
	}

	ret = btrfs_insert_item(trans, BTRFS_I(inode)->root, &key, (void *) ctx, len);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		return ret;
	}

	BTRFS_I(inode)->flags |= BTRFS_INODE_ENCRYPT;
	btrfs_sync_inode_flags_to_i_flags(inode);
	inode_inc_iversion(inode);
	inode->i_ctime = current_time(inode);
	ret = btrfs_update_inode(trans, BTRFS_I(inode)->root, BTRFS_I(inode));
	if (!ret) {
		if (!fs_data)
			btrfs_end_transaction(trans);
		return ret;
	}

	btrfs_abort_transaction(trans, ret);
	return ret;
}

static bool btrfs_fscrypt_empty_dir(struct inode *inode)
{
	return inode->i_size == BTRFS_EMPTY_DIR_SIZE;
}

const struct fscrypt_operations btrfs_fscrypt_ops = {
	.get_context = btrfs_fscrypt_get_context,
	.set_context = btrfs_fscrypt_set_context,
	.empty_dir = btrfs_fscrypt_empty_dir,
	.key_prefix = "btrfs:"
};
