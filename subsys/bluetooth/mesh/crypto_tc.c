/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/cmac_mode.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_MESH_DEBUG_CRYPTO)
#define LOG_MODULE_NAME bt_mesh_tc_crypto
#include "common/log.h"

#include "mesh.h"
#include "crypto.h"

int bt_mesh_aes_cmac(const uint8_t key[16], struct bt_mesh_sg *sg,
			size_t sg_len, uint8_t mac[16])
{
	struct tc_aes_key_sched_struct sched;
	struct tc_cmac_struct state;

	if (tc_cmac_setup(&state, key, &sched) == TC_CRYPTO_FAIL) {
		return -EIO;
	}

	for (; sg_len; sg_len--, sg++) {
		if (tc_cmac_update(&state, sg->data,
				   sg->len) == TC_CRYPTO_FAIL) {
			return -EIO;
		}
	}

	if (tc_cmac_final(mac, &state) == TC_CRYPTO_FAIL) {
		return -EIO;
	}

	return 0;
}

int bt_mesh_dhkey_gen(const uint8_t *pub_key, const uint8_t *priv_key, uint8_t *dhkey)
{
	if (uECC_valid_public_key(pub_key, &curve_secp256r1)) {
		BT_ERR("Public key is not valid");
		return -EIO;
	} else if (uECC_shared_secret(pub_key, priv_key, dhkey,
				&curve_secp256r1) != TC_CRYPTO_SUCCESS) {
		BT_ERR("DHKey generation failed");
		return -EIO;
	}

	return 0;
}

int bt_mesh_crypto_init(void)
{
	return 0;
}
