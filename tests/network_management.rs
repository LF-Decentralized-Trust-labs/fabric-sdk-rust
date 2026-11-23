//! Integration tests for the network-management features (cscc/qscc clients,
//! configtx helpers, orderer client, osnadmin client, operations client)
//! against a live Fabric test network.
//!
//! All tests are `#[ignore]` and gated on the `FABRIC_IT_BASE` environment
//! variable, which must point to a running test-network directory (the
//! `fabric-samples`-style layout with an `organizations/` tree). See
//! `scripts/run_network_management_tests.sh` for a ready-to-use launcher.
//!
//! Environment variables (all optional except `FABRIC_IT_BASE`):
//! - `FABRIC_IT_BASE`      — path to the test-network directory (required)
//! - `FABRIC_IT_PEER`      — peer endpoint authority (default `localhost:7051`)
//! - `FABRIC_IT_ORDERER`   — orderer endpoint authority (default `localhost:7050`)
//! - `FABRIC_IT_OSNADMIN`  — orderer admin URL (default `https://localhost:7053`)
//! - `FABRIC_IT_OPS`       — orderer operations URL (default `http://localhost:9443`)
//! - `FABRIC_IT_CHANNEL`   — existing channel name (default `mychannel`)
//! - `CONFIGTXGEN_BIN`     — path to `configtxgen` (default `<base>/../bin/configtxgen`)
//!
//! Run with:
//! ```sh
//! FABRIC_IT_BASE=/path/to/test-network cargo test --test network_management -- --ignored --test-threads=1
//! ```

#![cfg(not(feature = "client-wasm"))]

use std::path::{Path, PathBuf};

use fabric_sdk::{
    fabric::{
        common::{Block, Config, Envelope, Payload},
        protos::AnchorPeer,
    },
    gateway::{
        client::{Client, ClientBuilder},
        configtx,
        orderer::{BlockPosition, OrdererClient, OrdererClientBuilder},
    },
    identity::{Identity, IdentityBuilder},
    operations::OperationsClientBuilder,
    osnadmin::OsnadminClientBuilder,
    prelude::Message,
};

// ===== environment plumbing =====

fn base() -> PathBuf {
    PathBuf::from(
        std::env::var("FABRIC_IT_BASE")
            .expect("FABRIC_IT_BASE must point to the test-network directory"),
    )
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn channel_name() -> String {
    env_or("FABRIC_IT_CHANNEL", "mychannel")
}

/// Returns the single file inside `dir` (used for CA-issued keystores where
/// the key file name is a hash).
fn only_file(dir: &Path) -> PathBuf {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    entries
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no file in {}", dir.display()))
}

fn org1_admin_identity() -> Identity {
    let msp = base()
        .join("organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp");
    let cert = only_file(&msp.join("signcerts"));
    let key = only_file(&msp.join("keystore"));
    IdentityBuilder::from_pem(std::fs::read(&cert).unwrap())
        .unwrap()
        .with_msp("Org1MSP")
        .unwrap()
        .with_private_key(std::fs::read_to_string(&key).unwrap())
        .unwrap()
        .build()
        .unwrap()
}

fn peer_tls_ca() -> Vec<u8> {
    std::fs::read(
        base().join(
            "organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
        ),
    )
    .unwrap()
}

fn orderer_tls_ca() -> Vec<u8> {
    std::fs::read(
        base().join("organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"),
    )
    .unwrap()
}

async fn peer_client() -> Client {
    let mut client = ClientBuilder::new()
        .with_identity(org1_admin_identity())
        .unwrap()
        .with_tls(peer_tls_ca())
        .unwrap()
        .with_authority(env_or("FABRIC_IT_PEER", "localhost:7051"))
        .unwrap()
        .build()
        .unwrap();
    client.connect().await.expect("cannot connect to peer");
    client
}

async fn orderer_client() -> OrdererClient {
    let mut orderer = OrdererClientBuilder::new()
        .with_identity(org1_admin_identity())
        .unwrap()
        .with_tls(orderer_tls_ca())
        .unwrap()
        .with_authority(env_or("FABRIC_IT_ORDERER", "localhost:7050"))
        .unwrap()
        .build()
        .unwrap();
    orderer.connect().await.expect("cannot connect to orderer");
    orderer
}

fn osnadmin_client() -> fabric_sdk::osnadmin::OsnadminClient {
    let tls_dir =
        base().join("organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls");
    OsnadminClientBuilder::new()
        .with_url(env_or("FABRIC_IT_OSNADMIN", "https://localhost:7053"))
        .unwrap()
        .with_client_identity(
            std::fs::read(tls_dir.join("server.crt")).unwrap(),
            std::fs::read(tls_dir.join("server.key")).unwrap(),
        )
        .unwrap()
        .with_tls(orderer_tls_ca())
        .danger_accept_invalid_certs()
        .build()
        .unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ===== CsccClient / QsccClient =====

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn cscc_get_channels_lists_existing_channel() {
    runtime().block_on(async {
        let client = peer_client().await;
        let channels = client.get_cscc_client().get_channels().await.unwrap();
        let names: Vec<_> = channels.channels.iter().map(|c| c.channel_id.as_str()).collect();
        assert!(
            names.contains(&channel_name().as_str()),
            "expected {} in {:?}",
            channel_name(),
            names
        );
    });
}

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn cscc_get_config_block_decodes_to_config_with_orgs() {
    runtime().block_on(async {
        let client = peer_client().await;
        let block = client
            .get_cscc_client()
            .get_config_block(channel_name())
            .await
            .unwrap();

        let config = config_from_config_block(&block);
        let channel_group = config.channel_group.as_ref().unwrap();
        let application = channel_group.groups.get("Application").unwrap();
        assert!(application.groups.contains_key("Org1MSP"));
        assert!(application.groups.contains_key("Org2MSP"));
    });
}

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn cscc_get_channel_config_returns_config_tree() {
    runtime().block_on(async {
        let client = peer_client().await;
        let config = client
            .get_cscc_client()
            .get_channel_config(channel_name())
            .await
            .unwrap();
        let channel_group = config.channel_group.as_ref().unwrap();
        assert!(channel_group.groups.contains_key("Application"));
        assert!(channel_group.groups.contains_key("Orderer"));
        let application = channel_group.groups.get("Application").unwrap();
        assert!(application.groups.contains_key("Org1MSP"));
        assert!(application.groups.contains_key("Org2MSP"));
    });
}

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn qscc_chain_info_and_blocks() {
    runtime().block_on(async {
        let client = peer_client().await;
        let qscc = client.get_qscc_client();

        let info = qscc.get_chain_info(channel_name()).await.unwrap();
        assert!(info.height > 0, "expected non-zero height");

        let block = qscc
            .get_block_by_number(channel_name(), info.height - 1)
            .await
            .unwrap();
        assert_eq!(block.header.as_ref().unwrap().number, info.height - 1);
    });
}

/// Regenerates the conformance fixture `tests/resources/mychannel_config.pb`
/// from the live network. Only needed when the fixture should be refreshed.
#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE); regenerates a fixture"]
fn capture_config_fixture() {
    runtime().block_on(async {
        let client = peer_client().await;
        let config = client
            .get_cscc_client()
            .get_channel_config(channel_name())
            .await
            .unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/resources/mychannel_config.pb");
        std::fs::write(&path, config.encode_to_vec()).unwrap();
        println!("fixture written to {}", path.display());
    });
}

// ===== OrdererClient =====

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn orderer_fetches_newest_and_oldest_block() {
    runtime().block_on(async {
        let orderer = orderer_client().await;
        let newest = orderer
            .fetch_block(channel_name(), BlockPosition::Newest)
            .await
            .unwrap();
        let oldest = orderer
            .fetch_block(channel_name(), BlockPosition::Oldest)
            .await
            .unwrap();
        assert_eq!(oldest.header.as_ref().unwrap().number, 0);
        assert!(newest.header.as_ref().unwrap().number >= oldest.header.as_ref().unwrap().number);

        let specified = orderer
            .fetch_block(channel_name(), BlockPosition::Specified(0))
            .await
            .unwrap();
        assert_eq!(specified.header.as_ref().unwrap().number, 0);
    });
}

// ===== osnadmin =====

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn osnadmin_lists_channels() {
    runtime().block_on(async {
        let osnadmin = osnadmin_client();
        let channels = osnadmin.list_channels().await.unwrap();
        let names: Vec<_> = channels.channels.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&channel_name().as_str()),
            "expected {} in {:?}",
            channel_name(),
            names
        );

        let info = osnadmin.get_channel(channel_name()).await.unwrap();
        assert_eq!(info.name, channel_name());
        assert!(info.height > 0);
        assert_eq!(info.status, "active");
    });
}

// ===== operations =====

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE)"]
fn operations_healthz_version_logspec() {
    runtime().block_on(async {
        let ops = OperationsClientBuilder::new()
            .with_url(env_or("FABRIC_IT_OPS", "http://localhost:9443"))
            .unwrap()
            .build()
            .unwrap();

        let health = ops.healthz().await.unwrap();
        assert_eq!(health.status, "OK");

        let version = ops.version().await.unwrap();
        assert!(version.contains("Version"), "unexpected version body: {version}");

        let logspec = ops.get_logspec().await.unwrap();
        assert!(!logspec.spec.is_empty());

        // Round-trip the logspec to exercise PUT without changing anything.
        ops.put_logspec(logspec.spec.clone()).await.unwrap();
        assert_eq!(ops.get_logspec().await.unwrap().spec, logspec.spec);

        let metrics = ops.metrics_raw().await;
        // Metrics may be disabled; only assert transport-level success shape.
        if let Ok(m) = metrics {
            assert!(!m.is_empty());
        }
    });
}

// ===== full loop: create channel, join orderer + peer, anchor-peer update =====

fn unique_channel() -> String {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // base36 for compactness; channel names must be lowercase alphanumerics/dashes
    let mut n = epoch;
    let mut s = String::new();
    while n > 0 {
        let d = (n % 36) as u32;
        s.push(char::from_digit(d, 36).unwrap());
        n /= 36;
    }
    format!("sdk-it-{}", s.chars().rev().collect::<String>())
}

fn generate_genesis_block(channel: &str) -> Vec<u8> {
    let base = base();
    let configtxgen = std::env::var("CONFIGTXGEN_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base.join("../bin/configtxgen"));
    let out = std::env::temp_dir().join(format!("{channel}.block"));

    let output = std::process::Command::new(&configtxgen)
        .arg("-profile")
        .arg("ChannelUsingRaft")
        .arg("-outputBlock")
        .arg(&out)
        .arg("-channelID")
        .arg(channel)
        .arg("-configPath")
        .arg(base.join("configtx"))
        .output()
        .expect("failed to run configtxgen");
    assert!(
        output.status.success(),
        "configtxgen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    bytes
}

/// Extracts the `Config` from a config block (genesis or latest config block).
fn config_from_config_block(block: &Block) -> Config {
    let data = block.data.as_ref().expect("block without data");
    let envelope = Envelope::decode(data.data[0].as_slice()).expect("invalid envelope");
    let payload = Payload::decode(envelope.payload.as_slice()).expect("invalid payload");
    let config_envelope =
        fabric_sdk::fabric::common::ConfigEnvelope::decode(payload.data.as_slice())
            .expect("invalid config envelope");
    config_envelope.config.expect("config envelope without config")
}

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE); creates a throwaway channel"]
fn full_loop_create_channel_and_update_anchor_peers() {
    runtime().block_on(async {
        let channel = unique_channel();
        println!("=== full loop on channel {channel} ===");

        // 1. Genesis block via configtxgen
        let genesis = generate_genesis_block(&channel);
        println!("genesis block: {} bytes", genesis.len());

        // 2. Join the orderer via the channel-participation API
        let osnadmin = osnadmin_client();
        let info = osnadmin.join_channel(genesis.clone()).await.unwrap();
        println!("osnadmin join: name={} status={} relation={}", info.name, info.status, info.consensus_relation);
        assert_eq!(info.name, channel);

        // 3. Join peer0.org1 via cscc
        let client = peer_client().await;
        let cscc = client.get_cscc_client();
        cscc.join_chain(genesis.clone()).await.unwrap();
        println!("peer joined channel");

        // 4. The peer lists the new channel
        let channels = cscc.get_channels().await.unwrap();
        assert!(
            channels.channels.iter().any(|c| c.channel_id == channel),
            "peer does not list {channel}: {:?}",
            channels.channels
        );

        // 5. Fetch current config, set the anchor peer with the edit helper
        let original = cscc.get_channel_config(&channel).await.unwrap();
        let mut updated = original.clone();
        configtx::set_anchor_peers(
            &mut updated,
            "Org1MSP",
            vec![AnchorPeer {
                host: "peer0.org1.example.com".into(),
                port: 7051,
            }],
        )
        .unwrap();

        // 6. Compute the delta, sign it, build the CONFIG_UPDATE transaction
        let identity = org1_admin_identity();
        let update = configtx::compute_config_update(&original, &updated, &channel).unwrap();
        let mut update_envelope = configtx::create_config_update_envelope(&update);
        configtx::add_signature(&mut update_envelope, &identity);
        let tx = configtx::build_config_update_transaction(&identity, &update_envelope).unwrap();

        // 7. Broadcast to the orderer. A freshly joined raft channel needs a
        //    moment to elect its leader, so retry on "no Raft leader".
        let orderer = orderer_client().await;
        let mut response = None;
        for attempt in 0..30 {
            match orderer.broadcast(tx.clone()).await {
                Ok(r) => {
                    response = Some(r);
                    break;
                }
                Err(err) => {
                    let msg = err.to_string();
                    if msg.contains("no Raft leader") {
                        println!("attempt {attempt}: orderer not ready yet ({msg}), retrying");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    } else {
                        panic!("broadcast failed: {msg}");
                    }
                }
            }
        }
        let response = response.expect("orderer never elected a raft leader");
        println!("broadcast response: status={} info={:?}", response.status, response.info);

        // 8. Wait for the config block to land on the peer
        let qscc = client.get_qscc_client();
        let mut height = 0;
        for _ in 0..30 {
            height = qscc.get_chain_info(&channel).await.unwrap().height;
            if height >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        assert!(height >= 2, "config update block never committed (height={height})");

        // 9. Fetch the new config and assert the anchor peer is present
        let final_config = cscc.get_channel_config(&channel).await.unwrap();
        let org1 = final_config
            .channel_group
            .as_ref()
            .unwrap()
            .groups
            .get("Application")
            .unwrap()
            .groups
            .get("Org1MSP")
            .unwrap();
        let anchor_value = org1
            .values
            .get("AnchorPeers")
            .expect("AnchorPeers value missing after config update");
        let anchors =
            fabric_sdk::fabric::protos::AnchorPeers::decode(anchor_value.value.as_slice())
                .unwrap();
        assert_eq!(anchors.anchor_peers.len(), 1);
        assert_eq!(anchors.anchor_peers[0].host, "peer0.org1.example.com");
        assert_eq!(anchors.anchor_peers[0].port, 7051);

        // 10. Cross-check via the orderer: the newest block is a config block
        //     carrying the anchor peer as well.
        let newest = orderer.fetch_block(&channel, BlockPosition::Newest).await.unwrap();
        let config_from_orderer = config_from_config_block(&newest);
        assert!(
            config_from_orderer
                .channel_group
                .unwrap()
                .groups
                .get("Application")
                .unwrap()
                .groups
                .get("Org1MSP")
                .unwrap()
                .values
                .contains_key("AnchorPeers")
        );

        println!("=== full loop OK on {channel} ===");
    });
}

// ===== channel creation with the SDK's own genesis block =====

/// The org's verifying MSP, read from its `msp/` directory the way
/// configtxgen reads it (`cacerts/`, `tlscacerts/`, NodeOUs bound to the CA).
fn msp_from_dir(msp_id: &str, msp_dir: &Path) -> fabric_sdk::fabric::msp::MspConfig {
    let ca = std::fs::read(only_file(&msp_dir.join("cacerts"))).unwrap();
    let tlsca = std::fs::read(only_file(&msp_dir.join("tlscacerts"))).unwrap();
    configtx::MspConfigBuilder::new(msp_id)
        .with_root_cert(ca.clone())
        .with_tls_root_cert(tlsca)
        .with_node_ous(ca)
        .build()
        .unwrap()
}

/// The test-network's `ChannelUsingRaft` profile, built with
/// [`configtx::GenesisBuilder`] instead of configtxgen.
fn sdk_genesis_builder(channel: &str) -> configtx::GenesisBuilder {
    let orgs = base().join("organizations");
    let tls_cert = std::fs::read(
        orgs.join("ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt"),
    )
    .unwrap();
    configtx::GenesisBuilder::new(channel)
        .with_application_org(
            configtx::ApplicationOrg::new(
                "Org1MSP",
                msp_from_dir(
                    "Org1MSP",
                    &orgs.join("peerOrganizations/org1.example.com/msp"),
                ),
            )
            .with_anchor_peer("peer0.org1.example.com", 7051),
        )
        .with_application_org(configtx::ApplicationOrg::new(
            "Org2MSP",
            msp_from_dir(
                "Org2MSP",
                &orgs.join("peerOrganizations/org2.example.com/msp"),
            ),
        ))
        .with_orderer_org(
            configtx::OrdererOrg::new(
                "OrdererMSP",
                msp_from_dir(
                    "OrdererMSP",
                    &orgs.join("ordererOrganizations/example.com/msp"),
                ),
            )
            .with_name("OrdererOrg")
            .with_endpoint("orderer.example.com:7050"),
        )
        .with_consenter("orderer.example.com", 7050, tls_cert.clone(), tls_cert)
        .with_batch_size(10, 99 * 1024 * 1024, 512 * 1024)
        .with_batch_timeout("2s")
}

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE); creates a throwaway channel"]
fn create_channel_with_sdk_genesis_block() {
    runtime().block_on(async {
        let channel = unique_channel();
        println!("=== SDK genesis block on channel {channel} ===");

        let builder = sdk_genesis_builder(&channel);
        let genesis = builder.build().unwrap().encode_to_vec();
        println!("genesis block: {} bytes", genesis.len());

        // 1. The orderer accepts the block and becomes a raft consenter.
        let osnadmin = osnadmin_client();
        let info = osnadmin.join_channel(genesis.clone()).await.unwrap();
        println!(
            "osnadmin join: name={} status={} relation={}",
            info.name, info.status, info.consensus_relation
        );
        assert_eq!(info.name, channel);
        assert_eq!(info.consensus_relation, "consenter");
        let mut status = info.status;
        for _ in 0..30 {
            if status == "active" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            status = osnadmin.get_channel(&channel).await.unwrap().status;
        }
        assert_eq!(status, "active", "orderer never activated {channel}");

        // 2. The peer joins with the same block.
        let client = peer_client().await;
        let cscc = client.get_cscc_client();
        cscc.join_chain(genesis.clone()).await.unwrap();
        let channels = cscc.get_channels().await.unwrap();
        assert!(
            channels.channels.iter().any(|c| c.channel_id == channel),
            "peer does not list {channel}: {:?}",
            channels.channels
        );

        // 3. The peer's channel config is exactly the config we built.
        let config = cscc.get_channel_config(&channel).await.unwrap();
        assert_eq!(config, builder.build_config().unwrap());

        // 4. The orderer serves the same config in its genesis block. Deliver
        //    answers 503 until the new raft channel has elected a leader.
        let orderer = orderer_client().await;
        let mut oldest = None;
        for attempt in 0..30 {
            match orderer.fetch_block(&channel, BlockPosition::Oldest).await {
                Ok(block) => {
                    oldest = Some(block);
                    break;
                }
                Err(err) if err.to_string().contains("503") => {
                    println!("attempt {attempt}: orderer not ready yet ({err}), retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(err) => panic!("deliver failed: {err}"),
            }
        }
        let oldest = oldest.expect("orderer never served the genesis block");
        assert_eq!(
            config_from_config_block(&oldest),
            builder.build_config().unwrap()
        );

        println!("=== SDK genesis block OK on {channel} ===");
    });
}

// ===== signature check against the orderer's own decision =====

/// The admin of an org of the test network, e.g. `("org2.example.com",
/// "Org2MSP")` or `("example.com", "OrdererMSP")` for the orderer org.
fn admin_identity(domain: &str, msp_id: &str) -> Identity {
    let kind = if msp_id == "OrdererMSP" {
        "ordererOrganizations"
    } else {
        "peerOrganizations"
    };
    let msp = base().join(format!(
        "organizations/{kind}/{domain}/users/Admin@{domain}/msp"
    ));
    IdentityBuilder::from_pem(std::fs::read(only_file(&msp.join("signcerts"))).unwrap())
        .unwrap()
        .with_msp(msp_id)
        .unwrap()
        .with_private_key(std::fs::read_to_string(only_file(&msp.join("keystore"))).unwrap())
        .unwrap()
        .build()
        .unwrap()
}

/// Signs `update` with `signers`, checks it with
/// `check_config_update_signatures`, broadcasts it (submitted by the first
/// signer) and returns `(check satisfied, orderer accepted)`.
async fn check_and_broadcast(
    orderer: &OrdererClient,
    current: &Config,
    update: &fabric_sdk::fabric::common::ConfigUpdate,
    signers: &[&Identity],
) -> (bool, bool) {
    let mut envelope = configtx::create_config_update_envelope(update);
    for signer in signers {
        configtx::add_signature(&mut envelope, signer);
    }
    let check =
        configtx::check_config_update_signatures(current, update, &envelope.signatures).unwrap();
    println!(
        "check: satisfied={} orgs_to_sign={:?}",
        check.is_satisfied(),
        check.orgs_to_sign()
    );

    let tx = configtx::build_config_update_transaction(signers[0], &envelope).unwrap();
    for attempt in 0..30 {
        match orderer.broadcast(tx.clone()).await {
            Ok(_) => return (check.is_satisfied(), true),
            Err(err) if err.to_string().contains("no Raft leader") => {
                println!("attempt {attempt}: orderer not ready yet, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(err) => {
                println!("orderer rejected: {err}");
                return (check.is_satisfied(), false);
            }
        }
    }
    panic!("orderer never elected a raft leader");
}

/// Waits until the peer's ledger of `channel` reaches `height` blocks.
async fn wait_for_height(client: &Client, channel: &str, height: u64) {
    let qscc = client.get_qscc_client();
    for _ in 0..30 {
        if qscc.get_chain_info(channel).await.unwrap().height >= height {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("{channel} never reached height {height}");
}

#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE); creates a throwaway channel"]
fn signature_check_agrees_with_the_orderer() {
    runtime().block_on(async {
        let channel = unique_channel();
        println!("=== signature check vs orderer on channel {channel} ===");
        let genesis = sdk_genesis_builder(&channel)
            .build()
            .unwrap()
            .encode_to_vec();
        osnadmin_client()
            .join_channel(genesis.clone())
            .await
            .unwrap();
        let client = peer_client().await;
        let cscc = client.get_cscc_client();
        cscc.join_chain(genesis).await.unwrap();
        let orderer = orderer_client().await;

        let org1 = org1_admin_identity();
        let org2 = admin_identity("org2.example.com", "Org2MSP");
        let orderer_admin = admin_identity("example.com", "OrdererMSP");

        // 1. Orderer/BatchSize: mod policy /Channel/Orderer/Admins.
        let current = cscc.get_channel_config(&channel).await.unwrap();
        let mut updated = current.clone();
        configtx::set_batch_size(&mut updated, 20, 10 * 1024 * 1024, 1024 * 1024).unwrap();
        let update = configtx::compute_config_update(&current, &updated, &channel).unwrap();

        let (met, accepted) = check_and_broadcast(&orderer, &current, &update, &[&org1]).await;
        assert!(!met, "an Org1 admin must not meet /Channel/Orderer/Admins");
        assert!(!accepted, "the orderer must reject it as well");

        let (met, accepted) =
            check_and_broadcast(&orderer, &current, &update, &[&orderer_admin]).await;
        assert!(
            met && accepted,
            "orderer admin: met={met} accepted={accepted}"
        );
        wait_for_height(&client, &channel, 2).await;

        // 2. Application ACL: mod policy /Channel/Application/Admins,
        //    MAJORITY of two orgs = both.
        let current = cscc.get_channel_config(&channel).await.unwrap();
        let mut updated = current.clone();
        updated
            .channel_group
            .as_mut()
            .unwrap()
            .groups
            .get_mut("Application")
            .unwrap()
            .values
            .get_mut("Capabilities")
            .unwrap()
            .mod_policy = "Writers".into();
        let update = configtx::compute_config_update(&current, &updated, &channel).unwrap();

        let (met, accepted) = check_and_broadcast(&orderer, &current, &update, &[&org1]).await;
        assert!(!met, "one of two org admins must not meet MAJORITY Admins");
        assert!(!accepted, "the orderer must reject it as well");

        let (met, accepted) =
            check_and_broadcast(&orderer, &current, &update, &[&org1, &org2]).await;
        assert!(
            met && accepted,
            "both admins: met={met} accepted={accepted}"
        );
        wait_for_height(&client, &channel, 3).await;

        println!("=== signature check agrees with the orderer on {channel} ===");
    });
}

/// Experiment: does the Gateway `Submit` RPC accept a CONFIG_UPDATE envelope?
///
/// This is an open architecture question: if it does, WASM clients could
/// submit config updates through the gateway without a native orderer
/// connection. The test reports the outcome either way and only fails on
/// unexpected transport errors.
#[test]
#[ignore = "requires a running Fabric test network (set FABRIC_IT_BASE); creates a throwaway channel"]
fn experiment_gateway_submit_config_update() {
    runtime().block_on(async {
        let channel = format!("{}g", unique_channel());
        let genesis = generate_genesis_block(&channel);
        let osnadmin = osnadmin_client();
        osnadmin.join_channel(genesis.clone()).await.unwrap();
        let client = peer_client().await;
        let cscc = client.get_cscc_client();
        cscc.join_chain(genesis.clone()).await.unwrap();

        let original = cscc.get_channel_config(&channel).await.unwrap();
        let mut updated = original.clone();
        configtx::set_anchor_peers(
            &mut updated,
            "Org1MSP",
            vec![AnchorPeer {
                host: "peer0.org1.example.com".into(),
                port: 7051,
            }],
        )
        .unwrap();

        let identity = org1_admin_identity();
        let update = configtx::compute_config_update(&original, &updated, &channel).unwrap();
        let mut update_envelope = configtx::create_config_update_envelope(&update);
        configtx::add_signature(&mut update_envelope, &identity);
        let mut tx = configtx::build_config_update_transaction(&identity, &update_envelope).unwrap();

        // Give the fresh channel time to elect a raft leader, then submit;
        // retry transient orderer errors so a timing issue is not mistaken
        // for a gateway-level rejection.
        let mut outcome = tx.submit(&client).await.map(|_| ());
        for _ in 0..20 {
            match &outcome {
                Err(err) if err.to_string().contains("no orderers could successfully") => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    outcome = tx.submit(&client).await.map(|_| ());
                }
                _ => break,
            }
        }

        match outcome {
            Ok(_) => {
                // Did it actually commit?
                let qscc = client.get_qscc_client();
                let mut height = 0;
                for _ in 0..20 {
                    height = qscc.get_chain_info(&channel).await.unwrap().height;
                    if height >= 2 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                println!(
                    "RESULT: gateway Submit ACCEPTED the CONFIG_UPDATE envelope; final height={height} (>=2 means committed)"
                );
            }
            Err(err) => {
                println!("RESULT: gateway Submit REJECTED the CONFIG_UPDATE envelope: {err}");
            }
        }
    });
}

// ===== Fabric CA enroll / reenroll =====

/// Enrolls a freshly registered identity with the org1 CA, verifies the
/// issued certificate matches the locally generated key by signing a
/// chaincode-style message, then re-enrolls to rotate the credentials.
///
/// Requires the test network to have been started with CAs
/// (`network.sh up -ca`); set `FABRIC_IT_CA` to override the CA URL.
#[test]
#[ignore = "requires a running Fabric test network with CAs (set FABRIC_IT_BASE)"]
fn fabric_ca_enroll_and_reenroll() {
    runtime().block_on(async {
        use fabric_sdk::fabric_ca::{
            EnrollmentRequest, FabricCAClientBuilder, ReenrollmentRequest, RegisterIdentityRequest,
            RevokeRequest,
        };

        let ca_url = env_or("FABRIC_IT_CA", "https://localhost:7054");

        // Bootstrap admin of the org1 CA (test-network default).
        let bootstrap = FabricCAClientBuilder::new()
            .with_url(&ca_url)
            .unwrap()
            .danger_accept_invalid_certs()
            .build()
            .unwrap();
        let admin = bootstrap
            .enroll(EnrollmentRequest {
                enrollment_id: "admin".into(),
                secret: "adminpw".into(),
                profile: None,
                csr_hosts: vec![],
                ca_name: None,
            })
            .await
            .unwrap();
        assert!(admin.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(admin.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(admin.ca_chain_pem.contains("BEGIN CERTIFICATE"));

        // Use the enrolled admin as registrar for a brand-new identity.
        let admin_identity = IdentityBuilder::from_pem(admin.certificate_pem.as_bytes())
            .unwrap()
            .with_msp("Org1MSP")
            .unwrap()
            .with_private_key(admin.private_key_pem.clone())
            .unwrap()
            .build()
            .unwrap();
        let ca = FabricCAClientBuilder::new()
            .with_url(&ca_url)
            .unwrap()
            .with_identity(admin_identity)
            .danger_accept_invalid_certs()
            .build()
            .unwrap();

        let user = format!("sdk-it-user-{}", unique_channel());
        let secret = ca
            .register_identity(RegisterIdentityRequest {
                id: user.clone(),
                r#type: "client".into(),
                secret: None,
                max_enrollments: Some(5),
                affiliation: None,
                attrs: vec![],
            })
            .await
            .unwrap();

        // Enroll the new identity with a TLS-style SAN.
        let enrolled = ca
            .enroll(EnrollmentRequest {
                enrollment_id: user.clone(),
                secret,
                profile: None,
                csr_hosts: vec!["client.example.com".into()],
                ca_name: None,
            })
            .await
            .unwrap();
        assert!(enrolled.certificate_pem.contains("BEGIN CERTIFICATE"));

        // The issued cert + local key must form a working Fabric identity.
        let user_identity = IdentityBuilder::from_pem(enrolled.certificate_pem.as_bytes())
            .unwrap()
            .with_msp("Org1MSP")
            .unwrap()
            .with_private_key(enrolled.private_key_pem.clone())
            .unwrap()
            .build()
            .unwrap();
        let _signature = user_identity.sign_message(b"probe");

        // Re-enroll (rotate) as that user.
        let user_ca = FabricCAClientBuilder::new()
            .with_url(&ca_url)
            .unwrap()
            .with_identity(user_identity)
            .danger_accept_invalid_certs()
            .build()
            .unwrap();
        let rotated = user_ca
            .reenroll(ReenrollmentRequest {
                enrollment_id: user.clone(),
                profile: None,
                csr_hosts: vec![],
                ca_name: None,
            })
            .await
            .unwrap();
        assert!(rotated.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert_ne!(rotated.certificate_pem, enrolled.certificate_pem);
        assert_ne!(rotated.private_key_pem, enrolled.private_key_pem);

        // Cleanup: remove the throwaway identity. Fabric CA refuses removal
        // unless the server runs with cfg.identities.allowremove, which the
        // test-network's CAs do not; revoke it there instead, which every CA
        // allows and which invalidates all of its certificates.
        match ca.remove_identity(&user).await {
            Ok(_) => println!("removed {user}"),
            Err(err) if err.to_string().contains("Identity removal is disabled") => {
                ca.revoke(RevokeRequest {
                    enrollment_id: Some(user.clone()),
                    serial: None,
                    aki: None,
                    reason: None,
                    gen_crl: false,
                })
                .await
                .unwrap();
                println!("identity removal disabled on the CA; revoked {user} instead");
            }
            Err(err) => panic!("cleanup of {user} failed: {err}"),
        }
        println!("enroll + reenroll OK for {user}");
    });
}
