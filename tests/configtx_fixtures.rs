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
//! - `*.pem`: the `cacerts/` and `tlscacerts/` files of the two org MSP
//!   directories, byte for byte (configtxgen embeds the file content as is).
//!
//! The comparison is structural: groups are decoded and the nested
//! `MSPConfig` / `SignaturePolicyEnvelope` bytes are compared after decoding.

#![cfg(not(feature = "client-wasm"))]

use std::path::PathBuf;

use fabric_sdk::{
    fabric::{
        common::{Config, ConfigGroup, SignaturePolicyEnvelope},
        msp::{FabricMspConfig, MspConfig},
    },
    gateway::configtx::{self, MspConfigBuilder},
    prelude::Message,
};

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
