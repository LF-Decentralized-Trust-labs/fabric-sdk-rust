# Changelog

## Unreleased

Network management: everything needed to create channels and maintain their
configuration without external tooling (`configtxgen` excepted). All additions
are additive; no existing public API changed.

- **Channel-config protos compiled**: `common/configtx`, `common/configuration`,
  `common/policies`, `msp/msp_principal`, `msp/msp_config`,
  `orderer/configuration`, `orderer/etcdraft/*`, `orderer/smartbft/configuration`,
  `peer/configuration`, `peer/query` (new modules `fabric::etcdraft` and
  `fabric::smartbft`). The map fields of `common.ConfigGroup` /
  `common.ConfigUpdate` are generated as `BTreeMap`, making config encoding
  deterministic (sorted keys).
- **`gateway::cscc::CsccClient`** (`Client::get_cscc_client()`): JoinChain,
  JoinChainBySnapshot, GetChannels, GetConfigBlock, GetChannelConfig — WASM-capable.
- **`gateway::qscc::QsccClient`** (`Client::get_qscc_client()`): GetChainInfo,
  GetBlockByNumber, GetBlockByTxID, GetTransactionByID — WASM-capable.
- **`gateway::configtx`** (pure, WASM-safe):
  - `compute_config_update` — faithful port of Fabric's
    `internal/configtxlator/update` read-set/write-set computation,
    cross-validated against the official `configtxlator` binary
    (`tests/conformance.rs`; byte-identical output in all scenarios exercised).
  - `sign_config_update`, `create_config_update_envelope`, `add_signature`,
    `encode`/`decode_config_update_envelope`, `build_config_update_transaction`
    for multi-org signature collection and CONFIG_UPDATE envelope assembly.
  - Edit helpers `set_anchor_peers`, `add_application_org`, `add_consenter`,
    `remove_consenter` (etcdraft).
- **`gateway::orderer::OrdererClient`** (native only): `broadcast`, `deliver`,
  `fetch_block` (newest/oldest/specified) with signed seek envelopes.
- **`osnadmin::OsnadminClient`** (native only): channel-participation API with
  mutual TLS — list/get/join/remove channels.
- **`operations::OperationsClient`** (native only): healthz, version,
  logspec get/put, raw metrics.
- **Fabric CA enroll/reenroll** (`FabricCAClient::enroll` / `reenroll`):
  local P-256 key + PKCS#10 CSR generation (RustCrypto `x509-cert`), basic-auth
  enroll and token-authenticated reenroll; WASM-safe. `FabricCAClientBuilder`
  no longer requires an identity (enroll is the operation that produces one);
  token-authenticated calls without an identity return
  `FabricCAError::NotConfigured` instead.
- New error types: `SystemChaincodeError`, `ConfigTxError`, `OsnadminError`,
  `OperationsError`.
- Verified end-to-end against a live Fabric 2.5 network
  (`tests/network_management.rs`): full channel-creation loop — configtxgen
  genesis block → osnadmin join → cscc JoinChain → anchor-peer config update
  computed, signed and broadcast with this SDK → new config verified on peer
  and orderer. Notably, the Gateway `Submit` RPC also accepts and commits
  CONFIG_UPDATE envelopes, so WASM clients can submit config updates through
  the gateway without a native orderer connection.

## 0.5.8

- Fixed `FabricCAClient::revoke` sending a request body the Fabric CA server rejected with
  "Either Name or Serial and AKI are required for a revoke request." The internal
  `RevokeBody` serialized fields using Rust naming (`enrollment_id`, `gen_crl`) instead of
  the JSON tags the CA's `/api/v1/revoke` endpoint expects (`id`, `gencrl`). The public
  `RevokeRequest` API is unchanged.
