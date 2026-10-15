/*
 * Copyright The Zephyr Project Contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/bluetooth/mesh.h>
#include <zephyr/ztest.h>

#define BLOB_OP_BLOCK_STATUS BT_MESH_MODEL_OP_1(0x67)

static struct bt_mesh_blob_cli blob_cli;

static const struct bt_mesh_model blob_cli_mod = {
	.rt = &(struct bt_mesh_model_rt_ctx){ .user_data = &blob_cli },
};

static const struct bt_mesh_model_op *op_find(uint32_t opcode)
{
	for (const struct bt_mesh_model_op *op = _bt_mesh_blob_cli_op; op->func != NULL; op++) {
		if (op->opcode == opcode) {
			return op;
		}
	}

	return NULL;
}

/* A Block Status received while no transfer was ever started must be
 * ignored, and must not touch the (unset) transfer inputs.
 */
ZTEST(blob_cli, test_block_status_idle)
{
	const struct bt_mesh_model_op *op = op_find(BLOB_OP_BLOCK_STATUS);
	struct bt_mesh_msg_ctx ctx = {
		.addr = 0x0001,
	};
	/* Status SUCCESS, format "no chunks missing", block 0, chunk size 16 */
	uint8_t data[] = { 0x40, 0x00, 0x00, 0x10, 0x00 };
	struct net_buf_simple buf;

	zassert_not_null(op, "Block Status handler not found");
	zassert_is_null(blob_cli.inputs);
	zassert_equal(blob_cli.state, BT_MESH_BLOB_CLI_STATE_NONE);

	net_buf_simple_init_with_data(&buf, data, sizeof(data));

	zassert_equal(op->func(&blob_cli_mod, &ctx, &buf), -EBUSY);
}

ZTEST_SUITE(blob_cli, NULL, NULL, NULL, NULL, NULL);
