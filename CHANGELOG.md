# Changelog

## Unreleased

- **`configtx::check_config_update_signatures`**: tells which mod policies
  a config update needs, whether the signatures collected so far meet them
  and which orgs still have to sign (`PolicyCheck::orgs_to_sign`) — before
  the update goes to the orderer. A port of the orderer's delta-set
  authorization, `ImplicitMeta` (`ANY`/`ALL`/`MAJORITY`) and `cauthdsl`
  n-out-of evaluation, with MSP role checks from the signers' certificates
  (NodeOUs, admin certs). It only checks who signed: signatures,
  certificate chains and expiry are not verified. Cross-checked against a
  live orderer (`signature_check_agrees_with_the_orderer`): it accepts and
  rejects the same updates.
- **`configtx::set_batch_size`, `configtx::set_batch_timeout`,
  `configtx::update_consenter_tls`**: edit helpers for the orderer batch
  settings and for rotating a consenter's TLS certificates. Like
  `add_consenter`, they take the proto types (`orderer::BatchSize`,
  `etcdraft::Consenter`). Values the orderer would refuse are rejected with
  `InvalidOrdererValue` (same checks as `GenesisBuilder`), certificates must
  be PEM.
- **`configtx::GenesisBuilder`**: builds the genesis block of an application
  channel (no system channel; join orderers through osnadmin) from
  `ApplicationOrg`s, `OrdererOrg`s, etcdraft consenters, batch size and
  timeout, capabilities and optional ACLs — `configtxgen -outputBlock`
  without the binary, WASM-safe. The config tree is byte-identical to
  `configtxgen`'s for the test-network's `ChannelUsingRaft` profile, and the
  block header and metadata follow Fabric's genesis factory
  (`tests/configtx_fixtures.rs`). Inputs the orderer would refuse (channel
  ID, batch size, durations, etcdraft ticks, consenter TLS PEMs) are
  rejected with new `ConfigTxError` variants `InvalidChannelId`,
  `MissingGenesisField` and `InvalidOrdererValue`. Consenters, anchor peers
  and the batch size are passed as their proto types
  (`etcdraft::Consenter`, `AnchorPeer`, `orderer::BatchSize`).
- **`configtx::org_policies` and `configtx::orderer_org_policies`**: the
  standard `Readers`/`Writers`/`Admins`(/`Endorsement`) signature policies of
  an application or orderer organization with NodeOUs, ready for
  `add_application_org`. Byte-identical to `configtxgen -printOrg` for the
  test-network's `Org1MSP` and `OrdererOrg` (`tests/configtx_fixtures.rs`).
- **`configtx::MspConfigBuilder`**: builds an org's FABRIC `MspConfig` from
  PEM input (root, intermediate, TLS root/intermediate certificates,
  revocation list, NodeOUs bound to a CA certificate, SHA2/SHA256 crypto
  config) without an MSP directory. NodeOU roles are the proto's
  `MspRoleType` (`Member` is rejected). Every input is parsed; a NodeOU
  certificate must be one of the MSP's root or intermediate certificates.
  Byte-identical to `configtxgen -printOrg` for the test-network orgs.
  `ConfigTxError` gains `MissingMspField`, `InvalidPem`, `InvalidNodeOuRole`
  and `NodeOuCertNotInChain` (the enum is not `#[non_exhaustive]`, so an
  exhaustive `match` on it needs the new arms).
- **`collection::role_or_policy`**: `OR('<msp>.<role>', ...)` signature
  policy over any MSP roles; `member_or_policy` now delegates to it.

- **Fixed: osnadmin channel names can no longer change the request path.**
  `OsnadminClient::get_channel` and `remove_channel` put the name into the
  URL as is, and the HTTP client resolves `..` and cuts at `?`/`#`, so
  `remove_channel("tenant-a/../victim")` removed channel `victim`. Names
  that are not valid Fabric channel IDs are now rejected with the new
  `OsnadminError::InvalidChannelName` before anything is sent (the enum is
  not `#[non_exhaustive]`, so an exhaustive `match` on it needs the new
  arm).
- **Fixed: a TLS client no longer connects in plaintext with a non-https
  scheme.** `ClientBuilder` and `OrdererClientBuilder` require a TLS CA, but
  tonic only uses TLS for `https`: `with_scheme("http")` connected without
  TLS and without an error, so proposals, transient data and results went
  unencrypted and unauthenticated. `build` now returns
  `BuilderError::InvalidParameter` for any scheme other than `https` (native
  builds; on wasm the scheme is the gRPC-web proxy's) instead of panicking
  on an unparsable one.
- **Fixed: the chaincode no longer drops transactions under load.**
  Transactions run one at a time from a queue of 100. When the peer sent
  more at once, the router could not queue them and dropped them with a log
  line; nothing answered them, so each of those clients waited for the
  peer's execute timeout (30 s by default). Anyone allowed to invoke the
  chaincode could cause it by sending many requests at once. The queue is
  now unbounded; the peer bounds how many transactions it has in flight.
- **Fixed: a peer ERROR reply no longer hangs the chaincode.** The peer
  answers a failed ledger call (a rejected rich query or bookmark, a denied
  private-data read, an invalid key) with `ERROR` instead of `RESPONSE`. The
  router only logged it, so the `Context` call waited for a reply that never
  came, and because transactions run one at a time, every later transaction
  stalled until the process was restarted. One request with a garbage
  pagination bookmark was enough. `ERROR` now reaches the waiting call, which
  fails its transaction with the peer's message.
- **Fixed: ledger calls of one transaction no longer take each other's
  replies.** Each `Context` call now sends and receives under one lock and only
  accepts a reply for its own transaction id, so concurrent calls (`join!`)
  get their own answers and a stale reply is skipped.
- **Fixed: gRPC-web calls work with tonic 0.14.6 and later.**
  `tonic-web-wasm-client` 0.8 parsed the gRPC-web trailer frame but never
  emitted it; tonic 0.14.6+ fails such a stream ("missing grpc-status
  trailer"), so every browser call failed. Bumped to 0.9.2, which emits it.
- **Fixed: a peer message over 4 MiB no longer hangs the chaincode.** The
  chaincode's stream to the peer used tonic's default 4 MiB decode limit, so a
  large answer (e.g. a `GetStateByRange` over a grown ledger) broke the stream.
  The process stayed alive and the peer timed out every following transaction
  until the chaincode was restarted by hand. The limit is lifted (the peer
  bounds what it sends), and a broken stream now ends the process so the peer
  relaunches it.
- **Fixed: a malformed chaincode invocation no longer ends the chaincode
  process.** The invocation arguments were decoded with `expect` in the loop
  that serves every transaction, outside the task that catches a contract
  function's panics, so one proposal with a non-UTF-8 argument, or with no
  arguments at all, killed the chaincode for every org on the channel. Such an
  invocation is now answered with `BadRequest` for that transaction only.

Network management: everything needed to create channels and maintain their
configuration without external tooling (`configtxgen` excepted). All additions
are additive; no existing public API changed.

- **Channel-config protos compiled**: `common/configtx`, `common/configuration`,
  `common/policies`, `msp/msp_principal`, `msp/msp_config`,
  `orderer/configuration`, `orderer/etcdraft/*`, `orderer/smartbft/configuration`,
  `peer/configuration`, `peer/query` (new modules `fabric::etcdraft` and
  `fabric::smartbft`). The map fields of `common.ConfigGroup` /
  `common.ConfigUpdate`, `common.Capabilities` and `protos.ACLs` are
  generated as `BTreeMap`, making config encoding deterministic (sorted
  keys).
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
