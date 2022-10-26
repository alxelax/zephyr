/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_BLUETOOTH_MESH_KEYS_H_
#define ZEPHYR_INCLUDE_BLUETOOTH_MESH_KEYS_H_

#include <stdint.h>
#if defined CONFIG_BT_MESH_USES_MBEDTLS_PSA
#include <psa/crypto.h>
#elif defined CONFIG_BT_MESH_USES_TINYCRYPT
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum bt_mesh_key_type {
	BT_MESH_KEY_TYPE_ECB,
	BT_MESH_KEY_TYPE_CCM,
	BT_MESH_KEY_TYPE_CMAC,
	BT_MESH_KEY_TYPE_NET,
	BT_MESH_KEY_TYPE_APP,
	BT_MESH_KEY_TYPE_DEV
};

#if defined CONFIG_BT_MESH_USES_MBEDTLS_PSA

struct bt_mesh_key {
	psa_key_id_t key;
};

int bt_mesh_key_import(enum bt_mesh_key_type type,
		       const uint8_t in[16],
		       struct bt_mesh_key *out);

#elif defined CONFIG_BT_MESH_USES_TINYCRYPT

struct bt_mesh_key {
	uint8_t key[16];
};

static inline int bt_mesh_key_import(enum bt_mesh_key_type type,
				     const uint8_t in[16],
				     struct bt_mesh_key *out)
{
	memcpy(out, in, 16);
	return 0;
}

#else
#error "Crypto library has not been chosen"
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_BLUETOOTH_MESH_KEYS_H_ */
