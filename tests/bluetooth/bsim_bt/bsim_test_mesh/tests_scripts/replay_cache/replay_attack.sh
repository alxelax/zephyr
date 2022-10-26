#!/usr/bin/env bash
# Copyright 2021 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname "${BASH_SOURCE[0]}")/../../_mesh_test.sh

# Note:
# Tests must be added in pairs and in sequence.
# First test: saves replay cache; second test: verifies it.

conf=prj_pst_conf
RunTest mesh_replay_attack \
	rpc_tx_immediate_replay_attack \
	rpc_rx_immediate_replay_attack

conf=prj_pst_conf
RunTest mesh_replay_attack \
	rpc_tx_power_replay_attack \
	rpc_rx_power_replay_attack
