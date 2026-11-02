#!/usr/bin/env bash
# Runs the network-management test suites (tests/network_management.rs and
# tests/conformance.rs) against a live Fabric test network.
#
# Usage:
#   FABRIC_IT_BASE=/path/to/test-network scripts/run_network_management_tests.sh
#
# FABRIC_IT_BASE must point to a fabric-samples-style test-network directory
# (containing organizations/ and configtx/) whose network is up, started with
# CAs (`network.sh up createChannel -ca`). The Fabric release binaries
# (configtxgen, configtxlator) are expected in <FABRIC_IT_BASE>/../bin unless
# CONFIGTXGEN_BIN / CONFIGTXLATOR_BIN are set explicitly.
#
# Optional overrides (defaults in parentheses):
#   FABRIC_IT_PEER      peer endpoint authority        (localhost:7051)
#   FABRIC_IT_ORDERER   orderer endpoint authority     (localhost:7050)
#   FABRIC_IT_OSNADMIN  orderer admin URL              (https://localhost:7053)
#   FABRIC_IT_OPS       orderer operations URL         (http://localhost:9443)
#   FABRIC_IT_CA        org1 Fabric CA URL             (https://localhost:7054)
#   FABRIC_IT_CHANNEL   existing channel name          (mychannel)
#
# The full-loop tests create throwaway channels named sdk-it-<epoch36> on the
# target network; they never modify existing channels.

set -euo pipefail

if [[ -z "${FABRIC_IT_BASE:-}" ]]; then
    echo "FABRIC_IT_BASE must point to the test-network directory" >&2
    exit 1
fi

# Resolve the path before changing directory: the tests read it too, and a
# relative path would point elsewhere from the crate root.
FABRIC_IT_BASE="$(cd "$FABRIC_IT_BASE" && pwd)"
export FABRIC_IT_BASE

# `cargo test --test ...` must run from the crate root, wherever this is called from.
cd "$(dirname "$0")/.."

export CONFIGTXGEN_BIN="${CONFIGTXGEN_BIN:-$FABRIC_IT_BASE/../bin/configtxgen}"
export CONFIGTXLATOR_BIN="${CONFIGTXLATOR_BIN:-$FABRIC_IT_BASE/../bin/configtxlator}"

echo "=== conformance: Rust Compute vs configtxlator compute_update ==="
cargo test --test conformance -- --ignored --nocapture

echo "=== integration: live network (cscc/qscc, orderer, osnadmin, operations, CA, full loop) ==="
cargo test --test network_management -- --ignored --test-threads=1 --nocapture
