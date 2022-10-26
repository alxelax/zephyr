/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/bluetooth/mesh.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_MESH_DEBUG_CRYPTO)
#define LOG_MODULE_NAME bt_mesh_mbedtls_crypto
#include "common/log.h"

#include "mesh.h"
#include "crypto.h"
#include "prov.h"

/* Mesh requires to keep in persistent memory network keys (2 keys per subnetwork),
 * application keys (2 real keys per 1 configured) and device key.
 */
#define KEY_ID_RANGE_SIZE (2 * CONFIG_BT_MESH_SUBNET_COUNT + \
		2 * CONFIG_BT_MESH_APP_KEY_COUNT + 1)

static struct {
	bool is_ready;
	psa_key_id_t priv_key_id;
	uint8_t public_key_be[PUB_KEY_SIZE + 1];
} key;

static psa_key_id_t pst_key_id[KEY_ID_RANGE_SIZE] = {PSA_KEY_ID_NULL};

int bt_mesh_crypto_init(void)
{
	if (psa_crypto_init() != PSA_SUCCESS) {
		return -EIO;
	}

	return 0;
}

int bt_mesh_encrypt(const struct bt_mesh_key *key, const uint8_t plaintext[16],
		uint8_t enc_data[16])
{
	uint32_t output_len;
	psa_status_t status;
	int err = 0;

	status = psa_cipher_encrypt(key->key, PSA_ALG_ECB_NO_PADDING,
				    plaintext, 16,
				    enc_data, 16,
				    &output_len);

	if (status != PSA_SUCCESS || output_len != 16) {
		err = -EIO;
	}

	return err;
}

int bt_mesh_ccm_encrypt(const struct bt_mesh_key *key, uint8_t nonce[13],
			const uint8_t *plaintext, size_t len, const uint8_t *aad,
			size_t aad_len, uint8_t *enc_data, size_t mic_size)
{
	uint32_t output_len;
	psa_status_t status;
	int err = 0;

	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mic_size);

	status = psa_aead_encrypt(key->key, alg,
				  nonce, 13,
				  aad, aad_len,
				  plaintext, len,
				  enc_data, len + mic_size,
				  &output_len);

	if (status != PSA_SUCCESS || output_len != len + mic_size) {
		err = -EIO;
	}

	return err;
}

int bt_mesh_ccm_decrypt(const struct bt_mesh_key *key, uint8_t nonce[13],
			const uint8_t *enc_data, size_t len, const uint8_t *aad,
			size_t aad_len, uint8_t *plaintext, size_t mic_size)
{
	uint32_t output_len;
	psa_status_t status;
	int err = 0;

	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mic_size);

	status = psa_aead_decrypt(key->key, alg,
				  nonce, 13,
				  aad, aad_len,
				  enc_data, len + mic_size,
				  plaintext, len,
				  &output_len);

	if (status != PSA_SUCCESS || output_len != len) {
		err = -EIO;
	}

	return err;
}

int bt_mesh_aes_cmac_mesh_key(const struct bt_mesh_key *key, struct bt_mesh_sg *sg,
			size_t sg_len, uint8_t mac[16])
{
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
	psa_algorithm_t alg = PSA_ALG_CMAC;
	psa_status_t status;

	status = psa_mac_sign_setup(&operation, key->key, alg);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	for (; sg_len; sg_len--, sg++) {
		status = psa_mac_update(&operation, sg->data, sg->len);
		if (status != PSA_SUCCESS) {
			return -EIO;
		}
	}

	if (PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, 128, alg) > 16) {
		return -ERANGE;
	}

	size_t mac_len;

	status = psa_mac_sign_finish(&operation, mac, 16, &mac_len);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	if (mac_len != 16) {
		return -ERANGE;
	}

	return 0;
}

int bt_mesh_aes_cmac_raw_key(const uint8_t key[16], struct bt_mesh_sg *sg,
			size_t sg_len, uint8_t mac[16])
{
	struct bt_mesh_key key_id;
	int err;

	err = bt_mesh_key_import(BT_MESH_KEY_TYPE_CMAC, key, &key_id);
	if (err) {
		return err;
	}

	err = bt_mesh_aes_cmac_mesh_key(&key_id, sg, sg_len, mac);

	psa_destroy_key(key_id.key);

	return err;
}

int bt_mesh_pub_key_gen(void)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;
	int err = 0;
	size_t key_len;

	psa_destroy_key(key.priv_key_id);
	key.is_ready = false;

	/* Crypto settings for ECDH using the SHA256 hashing algorithm,
	 * the secp256r1 curve
	 */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	/* Generate a key pair */
	status = psa_generate_key(&key_attributes, &key.priv_key_id);
	if (status != PSA_SUCCESS) {
		err = -EIO;
		goto end;
	}

	status = psa_export_public_key(key.priv_key_id, key.public_key_be,
				sizeof(key.public_key_be), &key_len);
	if (status != PSA_SUCCESS) {
		err = -EIO;
		goto end;
	}

	if (key_len != PUB_KEY_SIZE + 1) {
		err = -ERANGE;
		goto end;
	}

	key.is_ready = true;

end:
	psa_reset_key_attributes(&key_attributes);

	return err;
}

const uint8_t *bt_mesh_pub_key_get(void)
{
	return key.is_ready ? key.public_key_be + 1 : NULL;
}

BUILD_ASSERT(PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(
	PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256) == DH_KEY_SIZE,
	"Diffie-Hellman shared secret size should be the same in PSA and BLE Mesh");

BUILD_ASSERT(PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256) == PUB_KEY_SIZE + 1,
	"Exported PSA public key should be 1 byte larger than BLE Mesh public key");

int bt_mesh_dhkey_gen(const uint8_t *pub_key, const uint8_t *priv_key, uint8_t *dhkey)
{
	int err = 0;
	psa_key_id_t priv_key_id  = PSA_KEY_ID_NULL;
	uint8_t public_key_repr[PUB_KEY_SIZE + 1];
	psa_status_t status;
	size_t dh_key_len;

	if (priv_key) {
		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

		/* Import a custom private key */
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, 256);

		status = psa_import_key(&attributes, priv_key, PRIV_KEY_SIZE, &priv_key_id);
		if (status != PSA_SUCCESS) {
			err = -EIO;
			goto end;
		}

		psa_reset_key_attributes(&attributes);
	} else {
		priv_key_id = key.priv_key_id;
	}

	/* For elliptic curve key pairs for Weierstrass curve families (PSA_ECC_FAMILY_SECP_R1)
	 *  the representations of public key is:
	 *  - The byte 0x04;
	 *  - x_P as a ceiling(m/8)-byte string, big-endian;
	 *  - y_P as a ceiling(m/8)-byte string, big-endian.
	 */
	public_key_repr[0] = 0x04;
	memcpy(public_key_repr + 1, pub_key, PUB_KEY_SIZE);

	/* Calculate the secret */
	status = psa_raw_key_agreement(PSA_ALG_ECDH, priv_key_id, public_key_repr,
			PUB_KEY_SIZE + 1, dhkey, DH_KEY_SIZE, &dh_key_len);
	if (status != PSA_SUCCESS) {
		err = -EIO;
		goto end;
	}

	if (dh_key_len != DH_KEY_SIZE) {
		err = -ERANGE;
	}

end:

	if (priv_key) {
		psa_destroy_key(priv_key_id);
	}

	return err;
}

__weak psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *context,
		uint8_t *output, size_t output_size, size_t *output_length)
{
	(void)context;

	if (bt_rand(output, output_size)) {
		return PSA_ERROR_INSUFFICIENT_ENTROPY;
	}

	*output_length = output_size;

	return PSA_SUCCESS;
}

__weak psa_key_id_t bt_mesh_user_keyid_alloc(void)
{
	for (int i = 0; i < KEY_ID_RANGE_SIZE; i++) {
		if (pst_key_id[i] == PSA_KEY_ID_NULL) {
			pst_key_id[i] = PSA_KEY_ID_USER_MIN + i;
			return pst_key_id[i];
		}
	}

	return PSA_KEY_ID_NULL;
}

__weak int bt_mesh_user_keyid_free(psa_key_id_t key_id)
{
	if (IN_RANGE(key_id, PSA_KEY_ID_USER_MIN,
			PSA_KEY_ID_USER_MIN + KEY_ID_RANGE_SIZE - 1)) {
		pst_key_id[key_id - PSA_KEY_ID_USER_MIN] = PSA_KEY_ID_NULL;
		return 0;
	}

	return -EIO;
}

int bt_mesh_key_import(enum bt_mesh_key_type type, const uint8_t in[16], struct bt_mesh_key *out)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;
	int err = 0;

	switch (type) {
	case BT_MESH_KEY_TYPE_ECB:
		psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&key_attributes,
			PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(&key_attributes, PSA_ALG_ECB_NO_PADDING);
		break;
	case BT_MESH_KEY_TYPE_CCM:
		psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&key_attributes,
			PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(&key_attributes,
			PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_CCM, 4));
		break;
	case BT_MESH_KEY_TYPE_CMAC:
		psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
		psa_set_key_algorithm(&key_attributes, PSA_ALG_CMAC);
		break;
	case BT_MESH_KEY_TYPE_NET:
		if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
			psa_key_id_t key_id = bt_mesh_user_keyid_alloc();

			if (key_id == PSA_KEY_ID_NULL) {
				return -ENOMEM;
			}

			psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
			psa_set_key_id(&key_attributes, key_id);
		} else {
			psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
		}
		psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_EXPORT);
		break;
	case BT_MESH_KEY_TYPE_APP:
	case BT_MESH_KEY_TYPE_DEV:
		if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
			psa_key_id_t key_id = bt_mesh_user_keyid_alloc();

			if (key_id == PSA_KEY_ID_NULL) {
				return -ENOMEM;
			}

			psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
			psa_set_key_id(&key_attributes, key_id);
		} else {
			psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
		}
		psa_set_key_usage_flags(&key_attributes,
			PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
		psa_set_key_algorithm(&key_attributes,
			PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_CCM, 4));
		break;
	default:
		return -EIO;
	}

	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);

	status = psa_import_key(&key_attributes, in, 16, &out->key);
	err = status == PSA_SUCCESS ? 0 :
		status == PSA_ERROR_ALREADY_EXISTS ? -EALREADY : -EIO;
	psa_reset_key_attributes(&key_attributes);

	return err;
}

int bt_mesh_key_export(uint8_t out[16], const struct bt_mesh_key *in)
{
	size_t data_length;

	if (psa_export_key(in->key, out, 16, &data_length) != PSA_SUCCESS) {
		return -EIO;
	}

	if (data_length != 16) {
		return -EIO;
	}

	return 0;
}

int bt_mesh_key_destroy(struct bt_mesh_key *key)
{
	if (psa_destroy_key(key->key) != PSA_SUCCESS) {
		return -EIO;
	}

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		return bt_mesh_user_keyid_free(key->key);
	}

	return 0;
}

int bt_mesh_key_compare(const uint8_t raw_key[16], struct bt_mesh_key *key)
{
	uint8_t out[16];
	int err;

	err = bt_mesh_key_export(out, key);
	if (err) {
		return err;
	}

	return memcmp(out, raw_key, 16);
}
