//! Golden tests of the `gateway::configtx` building blocks against
//! `configtxgen` output.
//!
//! Fixtures in `tests/resources/configtxgen/` (Fabric v2.5.11 binaries,
//! fabric-samples test-network crypto material):
//!
//! - `Org1MSP.json`, `OrdererOrg.json`: `configtxgen -printOrg <name>` run in
//!   `test-network/configtx`.
//! - `printOrg.pb`: both org groups wrapped into a `common.Config`
//!   (`Application/Org1MSP`, `Orderer/OrdererOrg`) and encoded with
//!   `configtxlator proto_encode --type common.Config`, so the nested MSP and
//!   policy values are binary protobuf.
//! - `*.pem`: the `cacerts/` and `tlscacerts/` files of the org MSP
//!   directories (Org1, Org2, orderer), byte for byte (configtxgen embeds
//!   the file content as is); `orderer.example.com-tls-server.crt` is the
//!   consenter TLS certificate.
//! - `mychannel_genesis.block`: `configtxgen -profile ChannelUsingRaft
//!   -outputBlock mychannel_genesis.block -channelID mychannel`.
//!
//! The comparison is structural: groups are decoded and the nested
//! `MSPConfig` / `SignaturePolicyEnvelope` bytes are compared after decoding.

#![cfg(not(feature = "client-wasm"))]

use std::path::PathBuf;

use fabric_sdk::{
    fabric::{
        common::{
            Block, ChannelHeader, Config, ConfigEnvelope, ConfigGroup, Envelope, Payload,
            SignatureHeader, SignaturePolicyEnvelope,
        },
        msp::{FabricMspConfig, MspConfig},
    },
    gateway::configtx::{self, ApplicationOrg, GenesisBuilder, MspConfigBuilder, OrdererOrg},
    prelude::Message,
};
use sha2::{Digest, Sha256};

fn resource(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/resources/configtxgen")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()))
}

/// Returns `(Application/Org1MSP, Orderer/OrdererOrg)` from the fixture.
fn fixture_orgs() -> (ConfigGroup, ConfigGroup) {
    let config = Config::decode(resource("printOrg.pb").as_slice()).unwrap();
    let mut channel = config.channel_group.unwrap();
    let org1 = channel
        .groups
        .get_mut("Application")
        .unwrap()
        .groups
        .remove("Org1MSP")
        .unwrap();
    let orderer_org = channel
        .groups
        .get_mut("Orderer")
        .unwrap()
        .groups
        .remove("OrdererOrg")
        .unwrap();
    (org1, orderer_org)
}

/// Asserts that the generated policies equal the fixture group's policies:
/// same names, versions, mod policies, types and decoded envelopes.
fn assert_policies_match(
    generated: &std::collections::BTreeMap<String, fabric_sdk::fabric::common::ConfigPolicy>,
    fixture: &ConfigGroup,
) {
    assert_eq!(
        generated.keys().collect::<Vec<_>>(),
        fixture.policies.keys().collect::<Vec<_>>()
    );
    for (name, expected) in &fixture.policies {
        let actual = &generated[name];
        assert_eq!(actual.version, expected.version, "{name}: version");
        assert_eq!(actual.mod_policy, expected.mod_policy, "{name}: mod_policy");
        let (actual, expected) = (
            actual.policy.as_ref().unwrap(),
            expected.policy.as_ref().unwrap(),
        );
        assert_eq!(actual.r#type, expected.r#type, "{name}: type");
        assert_eq!(
            SignaturePolicyEnvelope::decode(actual.value.as_slice()).unwrap(),
            SignaturePolicyEnvelope::decode(expected.value.as_slice()).unwrap(),
            "{name}: envelope"
        );
        // policydsl encodes deterministically, so the bytes match as well.
        assert_eq!(actual.value, expected.value, "{name}: bytes");
    }
}

#[test]
fn org_policies_match_configtxgen() {
    let (org1, _) = fixture_orgs();
    assert_policies_match(&configtx::org_policies("Org1MSP"), &org1);
}

#[test]
fn orderer_org_policies_match_configtxgen() {
    let (_, orderer_org) = fixture_orgs();
    assert_policies_match(&configtx::orderer_org_policies("OrdererMSP"), &orderer_org);
}

/// Decodes the org group's `MSP` value into `(MSPConfig, FabricMSPConfig)`.
fn fixture_msp(org: &ConfigGroup) -> (MspConfig, FabricMspConfig) {
    let value = &org.values["MSP"];
    assert_eq!(value.mod_policy, "Admins");
    let msp = MspConfig::decode(value.value.as_slice()).unwrap();
    let fabric = FabricMspConfig::decode(msp.config.as_slice()).unwrap();
    (msp, fabric)
}

fn assert_msp_matches(built: MspConfig, fixture: &ConfigGroup) {
    let (expected, expected_fabric) = fixture_msp(fixture);
    assert_eq!(built.r#type, expected.r#type);
    let built_fabric = FabricMspConfig::decode(built.config.as_slice()).unwrap();
    assert_eq!(built_fabric, expected_fabric);
    // Same field order and certificate bytes as Go's proto.Marshal.
    assert_eq!(built.config, expected.config);
}

#[test]
fn msp_config_matches_configtxgen_org1() {
    let (org1, _) = fixture_orgs();
    let ca = resource("ca.org1.example.com-cert.pem");
    let msp = MspConfigBuilder::new("Org1MSP")
        .with_root_cert(ca.clone())
        .with_tls_root_cert(resource("tlsca.org1.example.com-cert.pem"))
        .with_node_ous(ca)
        .build()
        .unwrap();
    assert_msp_matches(msp, &org1);
}

#[test]
fn msp_config_matches_configtxgen_orderer_org() {
    let (_, orderer_org) = fixture_orgs();
    let ca = resource("ca.example.com-cert.pem");
    let msp = MspConfigBuilder::new("OrdererMSP")
        .with_root_cert(ca.clone())
        .with_tls_root_cert(resource("tlsca.example.com-cert.pem"))
        .with_node_ous(ca)
        .build()
        .unwrap();
    assert_msp_matches(msp, &orderer_org);
}

/// MspConfigBuilder + org_policies + add_application_org compose to the
/// org group configtxgen emits.
#[test]
fn added_application_org_matches_configtxgen() {
    let (org1, _) = fixture_orgs();
    let ca = resource("ca.org1.example.com-cert.pem");
    let msp = MspConfigBuilder::new("Org1MSP")
        .with_root_cert(ca.clone())
        .with_tls_root_cert(resource("tlsca.org1.example.com-cert.pem"))
        .with_node_ous(ca)
        .build()
        .unwrap();

    let application = ConfigGroup {
        mod_policy: "Admins".into(),
        ..Default::default()
    };
    let mut channel = ConfigGroup::default();
    channel.groups.insert("Application".into(), application);
    let mut config = Config {
        sequence: 0,
        channel_group: Some(channel),
    };
    configtx::add_application_org(
        &mut config,
        "Org1MSP",
        &msp,
        configtx::org_policies("Org1MSP"),
    )
    .unwrap();

    let added = &config.channel_group.unwrap().groups["Application"].groups["Org1MSP"];
    assert_eq!(added, &org1);
}

// ===== genesis block (configtxgen -profile ChannelUsingRaft -outputBlock) =====

fn fixture_genesis_block() -> Block {
    Block::decode(resource("mychannel_genesis.block").as_slice()).unwrap()
}

/// `(payload, channel header, signature header, config envelope)` of the
/// block's only envelope.
fn genesis_parts(block: &Block) -> (Envelope, ChannelHeader, SignatureHeader, ConfigEnvelope) {
    let data = &block.data.as_ref().unwrap().data;
    assert_eq!(data.len(), 1, "genesis block holds exactly one envelope");
    let envelope = Envelope::decode(data[0].as_slice()).unwrap();
    let payload = Payload::decode(envelope.payload.as_slice()).unwrap();
    let header = payload.header.unwrap();
    (
        envelope,
        ChannelHeader::decode(header.channel_header.as_slice()).unwrap(),
        SignatureHeader::decode(header.signature_header.as_slice()).unwrap(),
        ConfigEnvelope::decode(payload.data.as_slice()).unwrap(),
    )
}

/// Asserts two config groups are equal and names the first differing path.
fn assert_groups_equal(path: &str, actual: &ConfigGroup, expected: &ConfigGroup) {
    assert_eq!(actual.version, expected.version, "{path}: version");
    assert_eq!(actual.mod_policy, expected.mod_policy, "{path}: mod_policy");
    assert_eq!(
        actual.values.keys().collect::<Vec<_>>(),
        expected.values.keys().collect::<Vec<_>>(),
        "{path}: value names"
    );
    for (name, value) in &expected.values {
        assert_eq!(&actual.values[name], value, "{path}/{name}: value");
    }
    assert_eq!(
        actual.policies.keys().collect::<Vec<_>>(),
        expected.policies.keys().collect::<Vec<_>>(),
        "{path}: policy names"
    );
    for (name, policy) in &expected.policies {
        assert_eq!(&actual.policies[name], policy, "{path}/{name}: policy");
    }
    assert_eq!(
        actual.groups.keys().collect::<Vec<_>>(),
        expected.groups.keys().collect::<Vec<_>>(),
        "{path}: group names"
    );
    for (name, group) in &expected.groups {
        assert_groups_equal(&format!("{path}/{name}"), &actual.groups[name], group);
    }
}

fn msp(msp_id: &str, ca: &str, tlsca: &str) -> MspConfig {
    MspConfigBuilder::new(msp_id)
        .with_root_cert(resource(ca))
        .with_tls_root_cert(resource(tlsca))
        .with_node_ous(resource(ca))
        .build()
        .unwrap()
}

/// The test-network's `ChannelUsingRaft` profile (`configtx/configtx.yaml`).
fn channel_using_raft() -> GenesisBuilder {
    let tls = resource("orderer.example.com-tls-server.crt");
    GenesisBuilder::new("mychannel")
        .with_application_org(ApplicationOrg::new(
            "Org1MSP",
            msp(
                "Org1MSP",
                "ca.org1.example.com-cert.pem",
                "tlsca.org1.example.com-cert.pem",
            ),
        ))
        .with_application_org(ApplicationOrg::new(
            "Org2MSP",
            msp(
                "Org2MSP",
                "ca.org2.example.com-cert.pem",
                "tlsca.org2.example.com-cert.pem",
            ),
        ))
        .with_orderer_org(
            OrdererOrg::new(
                "OrdererMSP",
                msp(
                    "OrdererMSP",
                    "ca.example.com-cert.pem",
                    "tlsca.example.com-cert.pem",
                ),
            )
            .with_name("OrdererOrg")
            .with_endpoint("orderer.example.com:7050"),
        )
        .with_consenter(fabric_sdk::fabric::etcdraft::Consenter {
            host: "orderer.example.com".into(),
            port: 7050,
            client_tls_cert: tls.clone(),
            server_tls_cert: tls,
        })
        .with_orderer_address("orderer.example.com:7050")
        .with_batch_size(fabric_sdk::fabric::orderer::BatchSize {
            max_message_count: 10,
            absolute_max_bytes: 99 * 1024 * 1024,
            preferred_max_bytes: 512 * 1024,
        })
        .with_batch_timeout("2s")
}

#[test]
fn genesis_config_matches_configtxgen() {
    let (_, _, _, expected) = genesis_parts(&fixture_genesis_block());
    let expected = expected.config.unwrap();
    let actual = channel_using_raft().build_config().unwrap();

    assert_eq!(actual.sequence, expected.sequence);
    assert_groups_equal(
        "Channel",
        actual.channel_group.as_ref().unwrap(),
        expected.channel_group.as_ref().unwrap(),
    );
    // Every value is byte-identical, so the whole tree encodes identically.
    assert_eq!(actual.encode_to_vec(), expected.encode_to_vec());
}

#[test]
fn genesis_block_matches_configtxgen_layout() {
    let expected = fixture_genesis_block();
    let actual = channel_using_raft().build().unwrap();

    // Header: number 0, no previous hash, data hash over the envelope.
    let header = actual.header.as_ref().unwrap();
    let expected_header = expected.header.as_ref().unwrap();
    assert_eq!(header.number, 0);
    assert_eq!(header.previous_hash, expected_header.previous_hash);
    let data = &actual.data.as_ref().unwrap().data;
    assert_eq!(
        header.data_hash,
        Sha256::digest(data.concat()).to_vec(),
        "data hash"
    );
    // configtxgen's own block follows the same rule.
    assert_eq!(
        expected_header.data_hash,
        Sha256::digest(expected.data.as_ref().unwrap().data.concat()).to_vec()
    );

    // Metadata slots are byte-identical.
    assert_eq!(actual.metadata, expected.metadata);

    // Envelope: unsigned, same header fields except time, nonce and tx id.
    let (envelope, channel_header, signature_header, config_envelope) = genesis_parts(&actual);
    let (expected_envelope, expected_channel_header, expected_signature_header, expected_config) =
        genesis_parts(&expected);
    assert_eq!(envelope.signature, expected_envelope.signature);
    assert_eq!(channel_header.r#type, expected_channel_header.r#type);
    assert_eq!(channel_header.version, expected_channel_header.version);
    assert_eq!(
        channel_header.channel_id,
        expected_channel_header.channel_id
    );
    assert_eq!(channel_header.epoch, expected_channel_header.epoch);
    assert_eq!(channel_header.extension, expected_channel_header.extension);
    assert_eq!(
        channel_header.tls_cert_hash,
        expected_channel_header.tls_cert_hash
    );
    assert_eq!(channel_header.timestamp.unwrap().nanos, 0);
    assert_eq!(signature_header.creator, expected_signature_header.creator);
    assert_eq!(
        signature_header.nonce.len(),
        expected_signature_header.nonce.len()
    );
    // tx id = hex(sha256(nonce || creator)), creator empty.
    assert_eq!(
        channel_header.tx_id,
        hex_sha256(&signature_header.nonce),
        "tx id"
    );
    assert_eq!(
        expected_channel_header.tx_id,
        hex_sha256(&expected_signature_header.nonce)
    );
    assert_eq!(config_envelope.last_update, expected_config.last_update);
    assert_eq!(config_envelope.config, expected_config.config);
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
