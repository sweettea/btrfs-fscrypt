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

/*
 * Read inode items of the given key type and offset from the btree.
 *
 * @inode:      inode to read items of
 * @key_type:   key type to read
 * @offset:     item offset to read from
 * @dest:       Buffer to read into. This parameter has slightly tricky
 *              semantics.  If it is NULL, the function will not do any copying
 *              and will just return the size of all the items up to len bytes.
 *              If dest_page is passed, then the function will kmap_local the
 *              page and ignore dest, but it must still be non-NULL to avoid the
 *              counting-only behavior.
 * @len:        length in bytes to read
 * @dest_page:  copy into this page instead of the dest buffer
 *
 * Helper function to read items from the btree.  This returns the number of
 * bytes read or < 0 for errors.  We can return short reads if the items don't
 * exist on disk or aren't big enough to fill the desired length.  Supports
 * reading into a provided buffer (dest) or into the page cache
 *
 * Returns number of bytes read or a negative error code on failure.
 */
static int read_key_bytes(struct btrfs_inode *inode, u8 key_type, u64 offset,
			  char *dest, u64 len, struct page *dest_page)
{
	struct btrfs_path *path;
	struct btrfs_root *root = inode->root;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	u64 item_end;
	u64 copy_end;
	int copied = 0;
	u32 copy_offset;
	unsigned long copy_bytes;
	unsigned long dest_offset = 0;
	void *data;
	char *kaddr = dest;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	if (dest_page)
		path->reada = READA_FORWARD;

	key.objectid = btrfs_ino(inode);
	key.type = key_type;
	key.offset = offset;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		goto out;
	} else if (ret > 0) {
		ret = 0;
		if (path->slots[0] == 0)
			goto out;
		path->slots[0]--;
	}

	while (len > 0) {
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);

		if (key.objectid != btrfs_ino(inode) || key.type != key_type)
			break;

		item_end = btrfs_item_size(leaf, path->slots[0]) + key.offset;

		if (copied > 0) {
			/*
			 * Once we've copied something, we want all of the items
			 * to be sequential
			 */
			if (key.offset != offset)
				break;
		} else {
			/*
			 * Our initial offset might be in the middle of an
			 * item.  Make sure it all makes sense.
			 */
			if (key.offset > offset)
				break;
			if (item_end <= offset)
				break;
		}

		/* desc = NULL to just sum all the item lengths */
		if (!dest)
			copy_end = item_end;
		else
			copy_end = min(offset + len, item_end);

		/* Number of bytes in this item we want to copy */
		copy_bytes = copy_end - offset;

		/* Offset from the start of item for copying */
		copy_offset = offset - key.offset;

		if (dest) {
			if (dest_page)
				kaddr = kmap_local_page(dest_page);

			data = btrfs_item_ptr(leaf, path->slots[0], void);
			read_extent_buffer(leaf, kaddr + dest_offset,
					   (unsigned long)data + copy_offset,
					   copy_bytes);

			if (dest_page)
				kunmap_local(kaddr);
		}

		offset += copy_bytes;
		dest_offset += copy_bytes;
		len -= copy_bytes;
		copied += copy_bytes;

		path->slots[0]++;
		if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
			/*
			 * We've reached the last slot in this leaf and we need
			 * to go to the next leaf.
			 */
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				break;
			} else if (ret > 0) {
				ret = 0;
				break;
			}
		}
	}
out:
	btrfs_free_path(path);
	if (!ret)
		ret = copied;
	return ret;
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
	ret = read_key_bytes(BTRFS_I(inode), BTRFS_FSCRYPT_CTXT_ITEM_KEY, 0, ctx,
			     len, NULL);
	iput(put_inode);
	return ret;
}

/*
 * Insert and write inode items with a given key type and offset.
 *
 * @inode:     inode to insert for
 * @key_type:  key type to insert
 * @offset:    item offset to insert at
 * @src:       source data to write
 * @len:       length of source data to write
 *
 * Write len bytes from src into items of up to 2K length.
 * The inserted items will have key (ino, key_type, offset + off) where off is
 * consecutively increasing from 0 up to the last item ending at offset + len.
 *
 * Returns 0 on success and a negative error code on failure.
 */
static int write_key_bytes(struct btrfs_inode *inode, u8 key_type, u64 offset,
			   const char *src, u64 len)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_path *path;
	struct btrfs_root *root = inode->root;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	unsigned long copy_bytes;
	unsigned long src_offset = 0;
	void *data;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	while (len > 0) {
		/* 1 for the new item being inserted */
		trans = btrfs_join_transaction(root);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			break;
		}

		key.objectid = btrfs_ino(inode);
		key.type = key_type;
		key.offset = offset;

		/*
		 * Insert 2K at a time mostly to be friendly for smaller leaf
		 * size filesystems
		 */
		copy_bytes = min_t(u64, len, 2048);

		ret = btrfs_insert_empty_item(trans, root, path, &key, copy_bytes);
		if (ret) {
			btrfs_end_transaction(trans);
			break;
		}

		leaf = path->nodes[0];

		data = btrfs_item_ptr(leaf, path->slots[0], void);
		write_extent_buffer(leaf, src + src_offset,
				    (unsigned long)data, copy_bytes);
		offset += copy_bytes;
		src_offset += copy_bytes;
		len -= copy_bytes;

		btrfs_release_path(path);
		btrfs_end_transaction(trans);
	}

	btrfs_free_path(path);
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
		 * 1 for the inode item
		 * 1 for the root item if the inode is a subvolume
		 */
		trans = btrfs_start_transaction(root, 1 + is_subvolume);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}

	ret = write_key_bytes(BTRFS_I(inode), BTRFS_FSCRYPT_CTXT_ITEM_KEY,0,
			     ctx, len);
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
