/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined CONFIG_BT_MESH_USES_MBEDTLS_PSA

int bt_mesh_key_export(uint8_t out[16], const struct bt_mesh_key *in);
void bt_mesh_key_assign(struct bt_mesh_key *key);
int bt_mesh_key_destroy(struct bt_mesh_key *key);
int bt_mesh_key_compare(const uint8_t raw_key[16], struct bt_mesh_key *mesh_key);

#elif defined CONFIG_BT_MESH_USES_TINYCRYPT

static inline int bt_mesh_key_export(uint8_t out[16], const struct bt_mesh_key *in)
{
	memcpy(out, in, 16);
	return 0;
}

static inline void bt_mesh_key_assign(struct bt_mesh_key *key)
{}

static inline int bt_mesh_key_destroy(struct bt_mesh_key *key)
{
	return 0;
}

static inline int bt_mesh_key_compare(const uint8_t raw_key[16], struct bt_mesh_key *mesh_key)
{
	return memcmp(mesh_key, raw_key, 16);
}

#endif
