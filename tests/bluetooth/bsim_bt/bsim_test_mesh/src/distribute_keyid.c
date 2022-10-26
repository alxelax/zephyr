/*
 * Copyright (c) 2022 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/bluetooth/mesh.h>
#include "argparse.h"
#include "mesh/crypto.h"
#include "mesh/keys.h"

#define LOG_MODULE_NAME distribute_keys
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

/* Mesh requires to keep in persistent memory network keys (2 keys per subnetwork),
 * application keys (2 real keys per 1 configured) and device key.
 */
#define KEY_ID_RANGE_SIZE (2 * CONFIG_BT_MESH_SUBNET_COUNT + \
		2 * CONFIG_BT_MESH_APP_KEY_COUNT + 1)

#define DEV_ID (get_device_nbr() << 8)

static psa_key_id_t pst_key_id[KEY_ID_RANGE_SIZE] = {PSA_KEY_ID_NULL};

psa_key_id_t bt_mesh_user_keyid_alloc(void)
{
	unsigned int dev_id = DEV_ID;

	for (int i = 0; i < KEY_ID_RANGE_SIZE; i++) {
		if (pst_key_id[i] == PSA_KEY_ID_NULL) {
			pst_key_id[i] = PSA_KEY_ID_USER_MIN + i + dev_id;
			LOG_INF("key id %d is allocated", pst_key_id[i]);
			return pst_key_id[i];
		}
	}

	return PSA_KEY_ID_NULL;
}

int bt_mesh_user_keyid_free(psa_key_id_t key_id)
{
	unsigned int dev_id = DEV_ID;

	if (!IN_RANGE(key_id - dev_id, PSA_KEY_ID_USER_MIN,
			PSA_KEY_ID_USER_MIN + KEY_ID_RANGE_SIZE - 1)) {
		return -EIO;
	}

	LOG_INF("key id %d is freed", pst_key_id[key_id - PSA_KEY_ID_USER_MIN]);
	pst_key_id[key_id - PSA_KEY_ID_USER_MIN] = PSA_KEY_ID_NULL;

	return 0;
}

void stored_keys_clear(void)
{
	struct bt_mesh_key key;
	unsigned int dev_id = DEV_ID;

	for (int i = 0; i < KEY_ID_RANGE_SIZE; i++) {
		key.key = PSA_KEY_ID_USER_MIN + i + dev_id;
		bt_mesh_key_destroy(&key);
	}
}
