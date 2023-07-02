// SPDX-License-Identifier: GPL-2.0
/*
 * Key setup facility for FS encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Originally written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar.
 * Heavily modified since then.
 */

#include <crypto/skcipher.h>
#include <linux/random.h>

#include "fscrypt_private.h"

#define MAX_MODE_KEY_HKDF_INFO_SIZE 17

/*
 * Constant defining the various policy flags which require a non-default key
 * policy.
 */
#define FSCRYPT_POLICY_FLAGS_KEY_MASK		\
	(FSCRYPT_POLICY_FLAG_DIRECT_KEY		\
	 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64	\
	 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)

struct fscrypt_mode fscrypt_modes[] = {
	[FSCRYPT_MODE_AES_256_XTS] = {
		.friendly_name = "AES-256-XTS",
		.cipher_str = "xts(aes)",
		.keysize = 64,
		.security_strength = 32,
		.ivsize = 16,
		.blk_crypto_mode = BLK_ENCRYPTION_MODE_AES_256_XTS,
	},
	[FSCRYPT_MODE_AES_256_CTS] = {
		.friendly_name = "AES-256-CTS-CBC",
		.cipher_str = "cts(cbc(aes))",
		.keysize = 32,
		.security_strength = 32,
		.ivsize = 16,
	},
	[FSCRYPT_MODE_AES_128_CBC] = {
		.friendly_name = "AES-128-CBC-ESSIV",
		.cipher_str = "essiv(cbc(aes),sha256)",
		.keysize = 16,
		.security_strength = 16,
		.ivsize = 16,
		.blk_crypto_mode = BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV,
	},
	[FSCRYPT_MODE_AES_128_CTS] = {
		.friendly_name = "AES-128-CTS-CBC",
		.cipher_str = "cts(cbc(aes))",
		.keysize = 16,
		.security_strength = 16,
		.ivsize = 16,
	},
	[FSCRYPT_MODE_SM4_XTS] = {
		.friendly_name = "SM4-XTS",
		.cipher_str = "xts(sm4)",
		.keysize = 32,
		.security_strength = 16,
		.ivsize = 16,
		.blk_crypto_mode = BLK_ENCRYPTION_MODE_SM4_XTS,
	},
	[FSCRYPT_MODE_SM4_CTS] = {
		.friendly_name = "SM4-CTS-CBC",
		.cipher_str = "cts(cbc(sm4))",
		.keysize = 16,
		.security_strength = 16,
		.ivsize = 16,
	},
	[FSCRYPT_MODE_ADIANTUM] = {
		.friendly_name = "Adiantum",
		.cipher_str = "adiantum(xchacha12,aes)",
		.keysize = 32,
		.security_strength = 32,
		.ivsize = 32,
		.blk_crypto_mode = BLK_ENCRYPTION_MODE_ADIANTUM,
	},
	[FSCRYPT_MODE_AES_256_HCTR2] = {
		.friendly_name = "AES-256-HCTR2",
		.cipher_str = "hctr2(aes)",
		.keysize = 32,
		.security_strength = 32,
		.ivsize = 32,
	},
};

static DEFINE_MUTEX(fscrypt_mode_key_setup_mutex);

static struct fscrypt_mode *
select_encryption_mode(const union fscrypt_policy *policy,
		       const struct inode *inode)
{
	BUILD_BUG_ON(ARRAY_SIZE(fscrypt_modes) != FSCRYPT_MODE_MAX + 1);

	if (S_ISREG(inode->i_mode))
		return &fscrypt_modes[fscrypt_policy_contents_mode(policy)];

	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		return &fscrypt_modes[fscrypt_policy_fnames_mode(policy)];

	WARN_ONCE(1, "fscrypt: filesystem tried to load encryption info for inode %lu, which is not encryptable (file type %d)\n",
		  inode->i_ino, (inode->i_mode & S_IFMT));
	return ERR_PTR(-EINVAL);
}

static int lock_master_key(struct fscrypt_master_key *mk)
{
	down_read(&mk->mk_sem);

	/* Has the secret been removed (via FS_IOC_REMOVE_ENCRYPTION_KEY)? */
	if (!is_master_key_secret_present(&mk->mk_secret))
		return -ENOKEY;

	return 0;
}

/* Create a symmetric cipher object for the given encryption mode */
static struct crypto_skcipher *
fscrypt_allocate_skcipher(struct fscrypt_mode *mode, const u8 *raw_key,
			  const struct inode *inode)
{
	struct crypto_skcipher *tfm;
	int err;

	tfm = crypto_alloc_skcipher(mode->cipher_str, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT) {
			fscrypt_warn(inode,
				     "Missing crypto API support for %s (API name: \"%s\")",
				     mode->friendly_name, mode->cipher_str);
			return ERR_PTR(-ENOPKG);
		}
		fscrypt_err(inode, "Error allocating '%s' transform: %ld",
			    mode->cipher_str, PTR_ERR(tfm));
		return tfm;
	}
	if (!xchg(&mode->logged_cryptoapi_impl, 1)) {
		/*
		 * fscrypt performance can vary greatly depending on which
		 * crypto algorithm implementation is used.  Help people debug
		 * performance problems by logging the ->cra_driver_name the
		 * first time a mode is used.
		 */
		pr_info("fscrypt: %s using implementation \"%s\"\n",
			mode->friendly_name, crypto_skcipher_driver_name(tfm));
	}
	if (WARN_ON_ONCE(crypto_skcipher_ivsize(tfm) != mode->ivsize)) {
		err = -EINVAL;
		goto err_free_tfm;
	}
	crypto_skcipher_set_flags(tfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
	err = crypto_skcipher_setkey(tfm, raw_key, mode->keysize);
	if (err)
		goto err_free_tfm;

	return tfm;

err_free_tfm:
	crypto_free_skcipher(tfm);
	return ERR_PTR(err);
}

/*
 * Prepare the crypto transform object or blk-crypto key in @prep_key, given the
 * raw key, encryption mode (@ci->ci_mode), flag indicating which encryption
 * implementation (fs-layer or blk-crypto) will be used (@ci->ci_inlinecrypt),
 * and IV generation method (@ci->ci_policy.flags).
 */
int fscrypt_prepare_key(struct fscrypt_prepared_key *prep_key,
			const u8 *raw_key, const struct fscrypt_info *ci)
{
	struct crypto_skcipher *tfm;

	if (fscrypt_using_inline_encryption(ci))
		return fscrypt_prepare_inline_crypt_key(prep_key, raw_key, ci);

	tfm = fscrypt_allocate_skcipher(ci->ci_mode, raw_key, ci->ci_inode);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	/*
	 * Pairs with the smp_load_acquire() in fscrypt_is_key_prepared().
	 * I.e., here we publish ->tfm with a RELEASE barrier so that
	 * concurrent tasks can ACQUIRE it.  Note that this concurrency is only
	 * possible for per-mode keys, not for per-file keys.
	 */
	smp_store_release(&prep_key->tfm, tfm);
	return 0;
}

/* Destroy a crypto transform object and/or blk-crypto key. */
void fscrypt_destroy_prepared_key(struct super_block *sb,
				  struct fscrypt_prepared_key *prep_key)
{
	crypto_free_skcipher(prep_key->tfm);
	fscrypt_destroy_inline_crypt_key(sb, prep_key);
	memzero_explicit(prep_key, sizeof(*prep_key));
}

/* Given a per-file encryption key, set up the file's crypto transform object */
int fscrypt_set_per_file_enc_key(struct fscrypt_info *ci, const u8 *raw_key)
{
	ci->ci_enc_key = kzalloc(sizeof(*ci->ci_enc_key), GFP_KERNEL);
	if (!ci->ci_enc_key)
		return -ENOMEM;

	ci->ci_enc_key->type = FSCRYPT_KEY_PER_INFO;
	return fscrypt_prepare_key(ci->ci_enc_key, raw_key, ci);
}

static struct fscrypt_prepared_key *
mk_prepared_key_for_mode_policy(struct fscrypt_master_key *mk,
				union fscrypt_policy *policy,
				struct fscrypt_mode *mode)
{
	const u8 mode_num = mode - fscrypt_modes;

	switch (policy->v2.flags & FSCRYPT_POLICY_FLAGS_KEY_MASK) {
	case FSCRYPT_POLICY_FLAG_DIRECT_KEY:
		return &mk->mk_direct_keys[mode_num];
	case FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64:
		return &mk->mk_iv_ino_lblk_64_keys[mode_num];
	case FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32:
		return &mk->mk_iv_ino_lblk_32_keys[mode_num];
	default:
		return ERR_PTR(-EINVAL);
	}
}

static size_t
fill_hkdf_info_for_mode_key(const struct fscrypt_info *ci,
			    u8 hkdf_info[MAX_MODE_KEY_HKDF_INFO_SIZE])
{
	const u8 mode_num = ci->ci_mode - fscrypt_modes;
	const struct super_block *sb = ci->ci_inode->i_sb;
	u8 hkdf_infolen = 0;

	hkdf_info[hkdf_infolen++] = mode_num;
	if (!(ci->ci_policy.v2.flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY)) {
		memcpy(&hkdf_info[hkdf_infolen], &sb->s_uuid,
				sizeof(sb->s_uuid));
		hkdf_infolen += sizeof(sb->s_uuid);
	}
	return hkdf_infolen;
}

static int setup_new_mode_prepared_key(struct fscrypt_master_key *mk,
				       struct fscrypt_prepared_key *prep_key,
				       const struct fscrypt_info *ci)
{
	const struct super_block *sb = ci->ci_sb;
	unsigned int policy_flags = fscrypt_policy_flags(&ci->ci_policy);
	struct fscrypt_mode *mode = ci->ci_mode;
	const u8 mode_num = mode - fscrypt_modes;
	u8 mode_key[FSCRYPT_MAX_KEY_SIZE];
	u8 hkdf_info[sizeof(mode_num) + sizeof(sb->s_uuid)];
	unsigned int hkdf_infolen = 0;
	u8 hkdf_context = 0;
	int err = 0;

	switch (policy_flags & FSCRYPT_POLICY_FLAGS_KEY_MASK) {
	case FSCRYPT_POLICY_FLAG_DIRECT_KEY:
		hkdf_context = HKDF_CONTEXT_DIRECT_KEY;
		break;
	case FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64:
		hkdf_context = HKDF_CONTEXT_IV_INO_LBLK_64_KEY;
		break;
	case FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32:
		hkdf_context = HKDF_CONTEXT_IV_INO_LBLK_32_KEY;
		break;
	}

	/*
	 * For DIRECT_KEY policies: instead of deriving per-file encryption
	 * keys, the per-file nonce will be included in all the IVs.  But
	 * unlike v1 policies, for v2 policies in this case we don't encrypt
	 * with the master key directly but rather derive a per-mode encryption
	 * key.  This ensures that the master key is consistently used only for
	 * HKDF, avoiding key reuse issues.
	 *
	 * For IV_INO_LBLK policies: encryption keys are derived from
	 * (master_key, mode_num, filesystem_uuid), and inode number is
	 * included in the IVs.  This format is optimized for use with inline
	 * encryption hardware compliant with the UFS standard.
	 */

	mutex_lock(&fscrypt_mode_key_setup_mutex);

	if (fscrypt_is_key_prepared(prep_key, ci))
		goto out_unlock;

	BUILD_BUG_ON(sizeof(mode_num) != 1);
	BUILD_BUG_ON(sizeof(sb->s_uuid) != 16);
	BUILD_BUG_ON(sizeof(hkdf_info) != MAX_MODE_KEY_HKDF_INFO_SIZE);
	hkdf_infolen = fill_hkdf_info_for_mode_key(ci, hkdf_info);

	err = fscrypt_hkdf_expand(&mk->mk_secret.hkdf,
				  hkdf_context, hkdf_info, hkdf_infolen,
				  mode_key, mode->keysize);
	if (err)
		return err;
	prep_key->type = FSCRYPT_KEY_MASTER_KEY;
	err = fscrypt_prepare_key(prep_key, mode_key, ci);
	memzero_explicit(mode_key, mode->keysize);

out_unlock:
	mutex_unlock(&fscrypt_mode_key_setup_mutex);
	return err;
}

static int setup_mode_prepared_key(struct fscrypt_info *ci,
				  struct fscrypt_master_key *mk)
{
	struct fscrypt_mode *mode = ci->ci_mode;
	const u8 mode_num = mode - fscrypt_modes;
	struct fscrypt_prepared_key *prep_key;
	int err;

	if (WARN_ON_ONCE(mode_num > FSCRYPT_MODE_MAX))
		return -EINVAL;

	prep_key = mk_prepared_key_for_mode_policy(mk, &ci->ci_policy, mode);
	if (IS_ERR(prep_key))
		return PTR_ERR(prep_key);

	if (fscrypt_is_key_prepared(prep_key, ci)) {
		ci->ci_enc_key = prep_key;
		return 0;
	}
	err = setup_new_mode_prepared_key(mk, prep_key, ci);
	if (err)
		return err;

	ci->ci_enc_key = prep_key;
	return 0;
}

/*
 * Derive a SipHash key from the given fscrypt master key and the given
 * application-specific information string.
 *
 * Note that the KDF produces a byte array, but the SipHash APIs expect the key
 * as a pair of 64-bit words.  Therefore, on big endian CPUs we have to do an
 * endianness swap in order to get the same results as on little endian CPUs.
 */
static int fscrypt_derive_siphash_key(const struct fscrypt_master_key *mk,
				      u8 context, const u8 *info,
				      unsigned int infolen, siphash_key_t *key)
{
	int err;

	err = fscrypt_hkdf_expand(&mk->mk_secret.hkdf, context, info, infolen,
				  (u8 *)key, sizeof(*key));
	if (err)
		return err;

	BUILD_BUG_ON(sizeof(*key) != 16);
	BUILD_BUG_ON(ARRAY_SIZE(key->key) != 2);
	le64_to_cpus(&key->key[0]);
	le64_to_cpus(&key->key[1]);
	return 0;
}

int fscrypt_derive_dirhash_key(struct fscrypt_info *ci,
			       const struct fscrypt_master_key *mk)
{
	int err;

	err = fscrypt_derive_siphash_key(mk, HKDF_CONTEXT_DIRHASH_KEY,
					 ci->ci_nonce, FSCRYPT_FILE_NONCE_SIZE,
					 &ci->ci_dirhash_key);
	if (err)
		return err;
	ci->ci_dirhash_key_initialized = true;
	return 0;
}

void fscrypt_hash_inode_number(struct fscrypt_info *ci,
			       const struct fscrypt_master_key *mk)
{
	WARN_ON_ONCE(fscrypt_get_info_ino(ci) == 0);
	WARN_ON_ONCE(!mk->mk_ino_hash_key_initialized);

	ci->ci_hashed_ino = (u32)siphash_1u64(fscrypt_get_info_ino(ci),
					      &mk->mk_ino_hash_key);
}

static int fscrypt_setup_ino_hash_key(struct fscrypt_master_key *mk)
{
	int err;

	/* pairs with smp_store_release() below */
	if (smp_load_acquire(&mk->mk_ino_hash_key_initialized))
		return 0;

	mutex_lock(&fscrypt_mode_key_setup_mutex);

	if (mk->mk_ino_hash_key_initialized)
		goto unlock;

	err = fscrypt_derive_siphash_key(mk,
					 HKDF_CONTEXT_INODE_HASH_KEY,
					 NULL, 0, &mk->mk_ino_hash_key);
	if (err)
		goto unlock;
	/* pairs with smp_load_acquire() above */
	smp_store_release(&mk->mk_ino_hash_key_initialized, true);
unlock:
	mutex_unlock(&fscrypt_mode_key_setup_mutex);

	return err;
}

static int fscrypt_setup_v2_file_key(struct fscrypt_info *ci,
				     struct fscrypt_master_key *mk)
{
	int err;

	if (ci->ci_policy.v2.flags & FSCRYPT_POLICY_FLAGS_KEY_MASK) {
		err = setup_mode_prepared_key(ci, mk);
	} else {
		u8 derived_key[FSCRYPT_MAX_KEY_SIZE];

		err = fscrypt_hkdf_expand(&mk->mk_secret.hkdf,
					  HKDF_CONTEXT_PER_FILE_ENC_KEY,
					  ci->ci_nonce, FSCRYPT_FILE_NONCE_SIZE,
					  derived_key, ci->ci_mode->keysize);
		if (err)
			return err;

		err = fscrypt_set_per_file_enc_key(ci, derived_key);
		memzero_explicit(derived_key, ci->ci_mode->keysize);
	}

	return err;
}

/*
 * Find or create the appropriate prepared key for an info.
 */
static int fscrypt_setup_file_key(struct fscrypt_info *ci,
				  struct fscrypt_master_key *mk)
{
	int err;

	if (!mk) {
		if (ci->ci_policy.version != FSCRYPT_POLICY_V1)
			return -ENOKEY;

		/*
		 * As a legacy fallback for v1 policies, search for the key in
		 * the current task's subscribed keyrings too.  Don't move this
		 * to before the search of ->s_master_keys, since users
		 * shouldn't be able to override filesystem-level keys.
		 */
		return fscrypt_setup_v1_file_key_via_subscribed_keyrings(ci);
	}

	switch (ci->ci_policy.version) {
	case FSCRYPT_POLICY_V1:
		err = fscrypt_setup_v1_file_key(ci, mk->mk_secret.raw);
		break;
	case FSCRYPT_POLICY_V2:
		err = fscrypt_setup_v2_file_key(ci, mk);
		break;
	default:
		WARN_ON_ONCE(1);
		err = -EINVAL;
		break;
	}
	return err;
}

/*
 * Check whether the size of the given master key (@mk) is appropriate for the
 * encryption settings which a particular file will use (@ci).
 *
 * If the file uses a v1 encryption policy, then the master key must be at least
 * as long as the derived key, as this is a requirement of the v1 KDF.
 *
 * Otherwise, the KDF can accept any size key, so we enforce a slightly looser
 * requirement: we require that the size of the master key be at least the
 * maximum security strength of any algorithm whose key will be derived from it
 * (but in practice we only need to consider @ci->ci_mode, since any other
 * possible subkeys such as DIRHASH and INODE_HASH will never increase the
 * required key size over @ci->ci_mode).  This allows AES-256-XTS keys to be
 * derived from a 256-bit master key, which is cryptographically sufficient,
 * rather than requiring a 512-bit master key which is unnecessarily long.  (We
 * still allow 512-bit master keys if the user chooses to use them, though.)
 */
static bool fscrypt_valid_master_key_size(const struct fscrypt_master_key *mk,
					  const struct fscrypt_info *ci)
{
	unsigned int min_keysize;

	if (ci->ci_policy.version == FSCRYPT_POLICY_V1)
		min_keysize = ci->ci_mode->keysize;
	else
		min_keysize = ci->ci_mode->security_strength;

	if (mk->mk_secret.size < min_keysize) {
		fscrypt_warn(NULL,
			     "key with %s %*phN is too short (got %u bytes, need %u+ bytes)",
			     master_key_spec_type(&mk->mk_spec),
			     master_key_spec_len(&mk->mk_spec),
			     (u8 *)&mk->mk_spec.u,
			     mk->mk_secret.size, min_keysize);
		return false;
	}
	return true;
}

/*
 * Find and lock the master key.
 *
 * If the master key is found in the filesystem-level keyring, then it is
 * returned in *mk_ret with its semaphore read-locked.  This is needed to ensure
 * that only one task links the fscrypt_info into ->mk_decrypted_inodes (as
 * multiple tasks may race to create an fscrypt_info for the same inode), and to
 * synchronize the master key being removed with a new inode starting to use it.
 */
static int find_and_lock_master_key(const struct fscrypt_info *ci,
				    struct fscrypt_master_key **mk_ret)
{
	struct super_block *sb = ci->ci_sb;
	struct fscrypt_key_specifier mk_spec;
	struct fscrypt_master_key *mk;
	int err;

	err = fscrypt_policy_to_key_spec(&ci->ci_policy, &mk_spec);
	if (err)
		return err;

	mk = fscrypt_find_master_key(sb, &mk_spec);
	if (unlikely(!mk)) {
		const union fscrypt_policy *dummy_policy =
			fscrypt_get_dummy_policy(sb);

		/*
		 * Add the test_dummy_encryption key on-demand.  In principle,
		 * it should be added at mount time.  Do it here instead so that
		 * the individual filesystems don't need to worry about adding
		 * this key at mount time and cleaning up on mount failure.
		 */
		if (dummy_policy &&
		    fscrypt_policies_equal(dummy_policy, &ci->ci_policy)) {
			err = fscrypt_add_test_dummy_key(sb, &mk_spec);
			if (err)
				return err;
			mk = fscrypt_find_master_key(sb, &mk_spec);
		}
	}

	if (unlikely(!mk)) {
		if (ci->ci_policy.version != FSCRYPT_POLICY_V1)
			return -ENOKEY;

		/*
		 * This might be the case of a v1 policy using a process
		 * subscribed keyring to get the key, so there may not be
		 * a relevant master key.
		 */

		*mk_ret = NULL;
		return 0;
	}

	err = lock_master_key(mk);
	if (err)
		goto out_release_key;

	if (!fscrypt_valid_master_key_size(mk, ci)) {
		err = -ENOKEY;
		goto out_release_key;
	}

	*mk_ret = mk;
	return 0;

out_release_key:
	up_read(&mk->mk_sem);
	fscrypt_put_master_key(mk);
	return err;
}

static void put_crypt_info(struct fscrypt_info *ci)
{
	struct fscrypt_master_key *mk;

	if (!ci)
		return;

	if (ci->ci_enc_key) {
		enum fscrypt_prepared_key_type type = ci->ci_enc_key->type;

		if (type == FSCRYPT_KEY_DIRECT_V1)
			fscrypt_put_direct_key(ci->ci_enc_key);
		if (type == FSCRYPT_KEY_PER_INFO) {
			fscrypt_destroy_prepared_key(ci->ci_sb,
						     ci->ci_enc_key);
			kfree_sensitive(ci->ci_enc_key);
		}
	}

	mk = ci->ci_master_key;
	if (mk) {
		/*
		 * Remove this inode from the list of inodes that were unlocked
		 * with the master key.  In addition, if we're removing the last
		 * inode from a master key struct that already had its secret
		 * removed, then complete the full removal of the struct.
		 */
		spin_lock(&mk->mk_decrypted_inodes_lock);
		list_del(&ci->ci_master_key_link);
		spin_unlock(&mk->mk_decrypted_inodes_lock);
		fscrypt_put_master_key_activeref(ci->ci_sb, mk);
	}
	memzero_explicit(ci, sizeof(*ci));
	kmem_cache_free(fscrypt_info_cachep, ci);
}

static int
fscrypt_setup_encryption_info(struct inode *inode,
			      const union fscrypt_policy *policy,
			      const u8 nonce[FSCRYPT_FILE_NONCE_SIZE],
			      bool need_dirhash_key,
			      struct fscrypt_info **info_ptr)
{
	struct fscrypt_info *crypt_info;
	struct fscrypt_mode *mode;
	struct fscrypt_master_key *mk = NULL;
	int res;
	bool info_for_extent = !!info_ptr;

	if (!info_ptr)
		info_ptr = &inode->i_crypt_info;

	res = fscrypt_initialize(inode->i_sb);
	if (res)
		return res;

	crypt_info = kmem_cache_zalloc(fscrypt_info_cachep, GFP_KERNEL);
	if (!crypt_info)
		return -ENOMEM;

	if (fscrypt_uses_extent_encryption(inode) && info_for_extent)
		crypt_info->ci_info_ptr = info_ptr;

	crypt_info->ci_inode = inode;

	crypt_info->ci_sb = inode->i_sb;
	crypt_info->ci_policy = *policy;
	memcpy(crypt_info->ci_nonce, nonce, FSCRYPT_FILE_NONCE_SIZE);

	mode = select_encryption_mode(&crypt_info->ci_policy, inode);
	if (IS_ERR(mode)) {
		res = PTR_ERR(mode);
		goto out;
	}
	WARN_ON_ONCE(mode->ivsize > FSCRYPT_MAX_IV_SIZE);
	crypt_info->ci_mode = mode;

	res = fscrypt_select_encryption_impl(crypt_info);
	if (res)
		goto out;
	if (info_for_extent && !fscrypt_using_inline_encryption(crypt_info)) {
		fscrypt_warn(inode,
			     "extent encryption requires inlinecrypt mount option");
		res = -EINVAL;
		goto out;
	}

	res = find_and_lock_master_key(crypt_info, &mk);
	if (res)
		goto out;

	res = fscrypt_setup_file_key(crypt_info, mk);
	if (res)
		goto out;

	/*
	 * Derive a secret dirhash key for directories that need it. It
	 * should be impossible to set flags such that a v1 policy sets
	 * need_dirhash_key, but check it anyway.
	 */
	if (need_dirhash_key) {
		if (WARN_ON_ONCE(policy->version == FSCRYPT_POLICY_V1)) {
			res = -EINVAL;
			goto out;
		}

		res = fscrypt_derive_dirhash_key(crypt_info, mk);
		if (res)
			goto out;
	}

	/*
	 * The IV_INO_LBLK_32 policy needs a hashed inode number, but new
	 * inodes may not have an inode number assigned yet.
	 */
	if (policy->version == FSCRYPT_POLICY_V2 &&
	    (policy->v2.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)) {
		res = fscrypt_setup_ino_hash_key(mk);
		if (res)
			goto out;

		if (fscrypt_get_info_ino(crypt_info))
			fscrypt_hash_inode_number(crypt_info, mk);
	}

	/*
	 * For existing inodes, multiple tasks may race to set ->i_crypt_info.
	 * So use cmpxchg_release().  This pairs with the smp_load_acquire() in
	 * fscrypt_get_info().  I.e., here we publish ->i_crypt_info with a
	 * RELEASE barrier so that other tasks can ACQUIRE it.
	 */
	if (cmpxchg_release(info_ptr, NULL, crypt_info) == NULL) {
		/*
		 * We won the race and set ->i_crypt_info to our crypt_info.
		 * Now link it into the master key's inode list.
		 */
		if (mk) {
			crypt_info->ci_master_key = mk;
			refcount_inc(&mk->mk_active_refs);
			spin_lock(&mk->mk_decrypted_inodes_lock);
			list_add(&crypt_info->ci_master_key_link,
				 &mk->mk_decrypted_inodes);
			spin_unlock(&mk->mk_decrypted_inodes_lock);
		}
		crypt_info = NULL;
	}
	res = 0;
out:
	if (mk) {
		up_read(&mk->mk_sem);
		fscrypt_put_master_key(mk);
	}
	put_crypt_info(crypt_info);
	return res;
}

/**
 * fscrypt_get_encryption_info() - set up an inode's encryption key
 * @inode: the inode to set up the key for.  Must be encrypted.
 * @allow_unsupported: if %true, treat an unsupported encryption policy (or
 *		       unrecognized encryption context) the same way as the key
 *		       being unavailable, instead of returning an error.  Use
 *		       %false unless the operation being performed is needed in
 *		       order for files (or directories) to be deleted.
 *
 * Set up inode->i_crypt_info, if it hasn't already been done.
 *
 * Note: unless ->i_crypt_info is already set, this isn't %GFP_NOFS-safe.  So
 * generally this shouldn't be called from within a filesystem transaction.
 *
 * Return: 0 if ->i_crypt_info was set or was already set, *or* if the
 *	   encryption key is unavailable.  (Use fscrypt_has_encryption_key() to
 *	   distinguish these cases.)  Also can return another -errno code.
 */
int fscrypt_get_encryption_info(struct inode *inode, bool allow_unsupported)
{
	int res;
	union fscrypt_context ctx;
	union fscrypt_policy policy;
	const u8 *nonce;

	if (fscrypt_has_encryption_key(inode))
		return 0;

	if (fscrypt_uses_extent_encryption(inode)) {
		/*
		 * Nothing will be encrypted with this info, so we can borrow
		 * the parent (dir) inode's policy and nonce.
		 */
		struct dentry *dentry = d_find_any_alias(inode);
		struct dentry *parent_dentry = dget_parent(dentry);
		struct inode *dir = parent_dentry->d_inode;
		bool found = false;

		if (dir->i_crypt_info) {
			found = true;
			policy = dir->i_crypt_info->ci_policy;
			nonce = dir->i_crypt_info->ci_nonce;
		}
		dput(parent_dentry);
		dput(dentry);
		if (!found)
			return 0;
	} else {
		res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
		if (res < 0) {
			if (res == -ERANGE && allow_unsupported)
				return 0;
			fscrypt_warn(inode, "Error %d getting encryption context", res);
			return res;
		}

		res = fscrypt_policy_from_context(&policy, &ctx, res);
		if (res) {
			if (allow_unsupported)
				return 0;
			fscrypt_warn(inode,
				     "Unrecognized or corrupt encryption context");
			return res;
		}
		nonce = fscrypt_context_nonce(&ctx);
	}

	if (!fscrypt_supported_policy(&policy, inode)) {
		if (allow_unsupported)
			return 0;
		return -EINVAL;
	}

	res = fscrypt_setup_encryption_info(inode, &policy, nonce,
					    IS_CASEFOLDED(inode) &&
					    S_ISDIR(inode->i_mode),
					    NULL);
	if (res == -ENOPKG && allow_unsupported) /* Algorithm unavailable? */
		res = 0;
	if (res == -ENOKEY)
		res = 0;
	return res;
}

/**
 * fscrypt_prepare_new_inode() - prepare to create a new inode in a directory
 * @dir: a possibly-encrypted directory
 * @inode: the new inode.  ->i_mode must be set already.
 *	   ->i_ino doesn't need to be set yet.
 * @encrypt_ret: (output) set to %true if the new inode will be encrypted
 *
 * If the directory is encrypted, set up its ->i_crypt_info in preparation for
 * encrypting the name of the new file.  Also, if the new inode will be
 * encrypted, set up its ->i_crypt_info and set *encrypt_ret=true.
 *
 * This isn't %GFP_NOFS-safe, and therefore it should be called before starting
 * any filesystem transaction to create the inode.  For this reason, ->i_ino
 * isn't required to be set yet, as the filesystem may not have set it yet.
 *
 * This doesn't persist the new inode's encryption context.  That still needs to
 * be done later by calling fscrypt_set_context().
 *
 * Return: 0 on success, -ENOKEY if the encryption key is missing, or another
 *	   -errno code
 */
int fscrypt_prepare_new_inode(struct inode *dir, struct inode *inode,
			      bool *encrypt_ret)
{
	const union fscrypt_policy *policy;
	u8 nonce_bytes[FSCRYPT_FILE_NONCE_SIZE];
	const u8 *nonce;

	policy = fscrypt_policy_to_inherit(dir);
	if (policy == NULL)
		return 0;
	if (IS_ERR(policy))
		return PTR_ERR(policy);

	if (WARN_ON_ONCE(inode->i_mode == 0))
		return -EINVAL;

	/*
	 * Only regular files, directories, and symlinks are encrypted.
	 * Special files like device nodes and named pipes aren't.
	 */
	if (!S_ISREG(inode->i_mode) &&
	    !S_ISDIR(inode->i_mode) &&
	    !S_ISLNK(inode->i_mode))
		return 0;

	*encrypt_ret = true;

	if (fscrypt_uses_extent_encryption(inode)) {
		nonce = dir->i_crypt_info->ci_nonce;
	} else {
		get_random_bytes(nonce_bytes, FSCRYPT_FILE_NONCE_SIZE);
		nonce = nonce_bytes;
	}

	return fscrypt_setup_encryption_info(inode, policy, nonce,
					     IS_CASEFOLDED(dir) &&
					     S_ISDIR(inode->i_mode),
					     NULL);
}
EXPORT_SYMBOL_GPL(fscrypt_prepare_new_inode);

/**
 * fscrypt_prepare_new_extent() - set up the fscrypt_info for a new extent
 * @inode: the inode to which the extent belongs
 * @info_ptr: a pointer to return the extent's fscrypt_info into. Should be
 *	      a pointer to a member of the extent struct, as it will be passed
 *	      back to the filesystem if key removal demands removal of the
 *	      info from the extent
 * @encrypt_ret: (output) set to %true if the new inode will be encrypted
 *
 * If the extent is part of an encrypted inode, set up its fscrypt_info in
 * preparation for encrypting data and set *encrypt_ret=true.
 *
 * This isn't %GFP_NOFS-safe, and therefore it should be called before starting
 * any filesystem transaction to create the inode.
 *
 * This doesn't persist the new inode's encryption context.  That still needs to
 * be done later by calling fscrypt_set_context().
 *
 * Return: 0 on success, -ENOKEY if the encryption key is missing, or another
 *	   -errno code
 */
int fscrypt_prepare_new_extent(struct inode *inode,
			       struct fscrypt_info **info_ptr)
{
	const union fscrypt_policy *policy;
	u8 nonce[FSCRYPT_FILE_NONCE_SIZE];

	policy = fscrypt_policy_to_inherit(inode);
	if (policy == NULL)
		return 0;
	if (IS_ERR(policy))
		return PTR_ERR(policy);

	/* Only regular files can have extents.  */
	if (WARN_ON_ONCE(!S_ISREG(inode->i_mode)))
		return -EINVAL;

	get_random_bytes(nonce, FSCRYPT_FILE_NONCE_SIZE);
	return fscrypt_setup_encryption_info(inode, policy, nonce,
					     false, info_ptr);
}
EXPORT_SYMBOL_GPL(fscrypt_prepare_new_extent);

/**
 * fscrypt_free_extent_info() - free an extent's fscrypt_info
 * @info_ptr: a pointer containing the extent's fscrypt_info pointer.
 */
void fscrypt_free_extent_info(struct fscrypt_info **info_ptr)
{
	put_crypt_info(*info_ptr);
	*info_ptr = NULL;
}
EXPORT_SYMBOL_GPL(fscrypt_free_extent_info);

/**
 * fscrypt_load_extent_info() - set up a preexisting extent's fscrypt_info
 * @inode: the inode to which the extent belongs. Must be encrypted.
 * @buf: a buffer containing the extent's stored context
 * @len: the length of the @ctx buffer
 * @info_ptr: a pointer to return the extent's fscrypt_info into. Should be
 *	      a pointer to a member of the extent struct, as it will be passed
 *	      back to the filesystem if key removal demands removal of the
 *	      info from the extent
 *
 * This is not %GFP_NOFS safe, so the caller is expected to call
 * memalloc_nofs_save/restore() if appropriate.
 *
 * Return: 0 if successful, or -errno if it fails.
 */
int fscrypt_load_extent_info(struct inode *inode, void *buf, size_t len,
			     struct fscrypt_info **info_ptr)
{
	int res;
	union fscrypt_context ctx;
	union fscrypt_policy policy;

	if (!fscrypt_has_encryption_key(inode))
		return -EINVAL;

	memcpy(&ctx, buf, len);

	res = fscrypt_policy_from_context(&policy, &ctx, len);
	if (res) {
		fscrypt_warn(inode,
			     "Unrecognized or corrupt encryption context");
		return res;
	}

	if (!fscrypt_supported_policy(&policy, inode))
		return -EINVAL;

	res = fscrypt_setup_encryption_info(inode, &policy,
					    fscrypt_context_nonce(&ctx),
					    IS_CASEFOLDED(inode) &&
					    S_ISDIR(inode->i_mode),
					    info_ptr);

	if (res == -ENOPKG) /* Algorithm unavailable? */
		res = 0;
	return res;
}
EXPORT_SYMBOL_GPL(fscrypt_load_extent_info);

/**
 * fscrypt_put_encryption_info() - free most of an inode's fscrypt data
 * @inode: an inode being evicted
 *
 * Free the inode's fscrypt_info.  Filesystems must call this when the inode is
 * being evicted.  An RCU grace period need not have elapsed yet.
 */
void fscrypt_put_encryption_info(struct inode *inode)
{
	put_crypt_info(inode->i_crypt_info);
	inode->i_crypt_info = NULL;
}
EXPORT_SYMBOL(fscrypt_put_encryption_info);

/**
 * fscrypt_free_inode() - free an inode's fscrypt data requiring RCU delay
 * @inode: an inode being freed
 *
 * Free the inode's cached decrypted symlink target, if any.  Filesystems must
 * call this after an RCU grace period, just before they free the inode.
 */
void fscrypt_free_inode(struct inode *inode)
{
	if (IS_ENCRYPTED(inode) && S_ISLNK(inode->i_mode)) {
		kfree(inode->i_link);
		inode->i_link = NULL;
	}
}
EXPORT_SYMBOL(fscrypt_free_inode);

/**
 * fscrypt_drop_inode() - check whether the inode's master key has been removed
 * @inode: an inode being considered for eviction
 *
 * Filesystems supporting fscrypt must call this from their ->drop_inode()
 * method so that encrypted inodes are evicted as soon as they're no longer in
 * use and their master key has been removed.
 *
 * Return: 1 if fscrypt wants the inode to be evicted now, otherwise 0
 */
int fscrypt_drop_inode(struct inode *inode)
{
	const struct fscrypt_info *ci = fscrypt_get_info(inode);

	/*
	 * If ci is NULL, then the inode doesn't have an encryption key set up
	 * so it's irrelevant.  If ci_master_key is NULL, then the master key
	 * was provided via the legacy mechanism of the process-subscribed
	 * keyrings, so we don't know whether it's been removed or not.
	 */
	if (!ci || !ci->ci_master_key)
		return 0;

	/*
	 * With proper, non-racy use of FS_IOC_REMOVE_ENCRYPTION_KEY, all inodes
	 * protected by the key were cleaned by sync_filesystem().  But if
	 * userspace is still using the files, inodes can be dirtied between
	 * then and now.  We mustn't lose any writes, so skip dirty inodes here.
	 */
	if (inode->i_state & I_DIRTY_ALL)
		return 0;

	/*
	 * Note: since we aren't holding the key semaphore, the result here can
	 * immediately become outdated.  But there's no correctness problem with
	 * unnecessarily evicting.  Nor is there a correctness problem with not
	 * evicting while iput() is racing with the key being removed, since
	 * then the thread removing the key will either evict the inode itself
	 * or will correctly detect that it wasn't evicted due to the race.
	 */
	return !is_master_key_secret_present(&ci->ci_master_key->mk_secret);
}
EXPORT_SYMBOL_GPL(fscrypt_drop_inode);
