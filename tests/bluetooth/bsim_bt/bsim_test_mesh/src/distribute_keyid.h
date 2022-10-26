/*
 * Copyright (c) 2022 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TESTS_BLUETOOTH_BSIM_BT_BSIM_TEST_MESH_SRC_DISTRIBUTE_KEYID_H_
#define TESTS_BLUETOOTH_BSIM_BT_BSIM_TEST_MESH_SRC_DISTRIBUTE_KEYID_H_

#if defined CONFIG_BT_MESH_USES_MBEDTLS_PSA
void stored_keys_clear(void);
#else
static inline void stored_keys_clear(void)
{}
#endif

#endif /* TESTS_BLUETOOTH_BSIM_BT_BSIM_TEST_MESH_SRC_DISTRIBUTE_KEYID_H_ */
