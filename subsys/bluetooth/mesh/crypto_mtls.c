/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <psa/crypto.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_MESH_DEBUG_CRYPTO)
#define LOG_MODULE_NAME bt_mesh_mbedtls_crypto
#include "common/log.h"

#include "mesh.h"
#include "crypto.h"

int bt_mesh_crypto_init(void)
{
	if (psa_crypto_init() != PSA_SUCCESS) {
		return -EIO;
	}

	return 0;
}

int bt_mesh_encrypt(const uint8_t key[16], const uint8_t plaintext[16], uint8_t enc_data[16])
{
	psa_key_id_t key_id;
	uint32_t output_len;
	psa_status_t status;
	int err = 0;

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECB_NO_PADDING);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);

	status = psa_import_key(&key_attributes, key, 16, &key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING,
				    plaintext, 16,
				    enc_data, 16,
				    &output_len);

	if (status != PSA_SUCCESS || output_len != 16) {
		err = -EIO;
	}

	psa_reset_key_attributes(&key_attributes);

	status = psa_destroy_key(key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	return err;
}

int bt_mesh_ccm_encrypt(const uint8_t key[16], uint8_t nonce[13],
			const uint8_t *plaintext, size_t len, const uint8_t *aad,
			size_t aad_len, uint8_t *enc_data, size_t mic_size)
{
	psa_key_id_t key_id;
	uint32_t output_len;
	psa_status_t status;
	int err = 0;

	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mic_size);

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);

	status = psa_import_key(&key_attributes, key, 16, &key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_aead_encrypt(key_id, alg,
				  nonce, 13,
				  aad, aad_len,
				  plaintext, len,
				  enc_data, len + mic_size,
				  &output_len);

	if (status != PSA_SUCCESS || output_len != len + mic_size) {
		err = -EIO;
	}

	psa_reset_key_attributes(&key_attributes);

	status = psa_destroy_key(key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	return err;
}

int bt_mesh_ccm_decrypt(const uint8_t key[16], uint8_t nonce[13],
			const uint8_t *enc_data, size_t len, const uint8_t *aad,
			size_t aad_len, uint8_t *plaintext, size_t mic_size)
{
	psa_key_id_t key_id;
	uint32_t output_len;
	psa_status_t status;
	int err = 0;

	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, mic_size);

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);

	status = psa_import_key(&key_attributes, key, 16, &key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_aead_decrypt(key_id, alg,
				  nonce, 13,
				  aad, aad_len,
				  enc_data, len + mic_size,
				  plaintext, len,
				  &output_len);

	if (status != PSA_SUCCESS || output_len != len) {
		err = -EIO;
	}

	psa_reset_key_attributes(&key_attributes);

	status = psa_destroy_key(key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	return err;
}

int bt_mesh_aes_cmac(const uint8_t key[16], struct bt_mesh_sg *sg,
			size_t sg_len, uint8_t mac[16])
{
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
	psa_algorithm_t alg = PSA_ALG_CMAC;

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	int err = 0;

	/* Import a key */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 128);

	if (psa_import_key(&attributes, key, 16, &key_id) != PSA_SUCCESS) {
		err = -EIO;
		goto end;
	}

	psa_reset_key_attributes(&attributes);

	if (psa_mac_sign_setup(&operation, key_id, alg) != PSA_SUCCESS) {
		err = -EIO;
		goto end;
	}

	for (; sg_len; sg_len--, sg++) {
		if (psa_mac_update(&operation, sg->data, sg->len) != PSA_SUCCESS) {
			err = -EIO;
			goto end;
		}
	}

	if (PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, 128, alg) > 16) {
		err = -ERANGE;
		goto end;
	}

	size_t mac_len;

	if (psa_mac_sign_finish(&operation, mac, 16, &mac_len) != PSA_SUCCESS) {
		err = -EIO;
		goto end;
	}

	if (mac_len != 16) {
		err = -ERANGE;
	}

end:
	/* Destroy the key */
	psa_destroy_key(key_id);

	return err;
}

int bt_mesh_dhkey_gen(const uint8_t *pub_key, const uint8_t *priv_key, uint8_t *dhkey)
{
	return -ENOSYS;
}

psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *context,
		uint8_t *output, size_t output_size, size_t *output_length)
{
	(void)context;

	if (bt_rand(output, output_size)) {
		return PSA_ERROR_INSUFFICIENT_ENTROPY;
	}

	*output_length = output_size;

	return PSA_SUCCESS;
}
