//! Conformance cross-validation of the Rust ConfigUpdate delta computation
//! ([`fabric_sdk::gateway::configtx::compute_config_update`]) against the
//! canonical Go implementation via the official `configtxlator` binary
//! (`configtxlator compute_update`).
//!
//! Tests are `#[ignore]` and gated on the `CONFIGTXLATOR_BIN` environment
//! variable. The channel config fixture `tests/resources/mychannel_config.pb`
//! was captured from a live Fabric 2.5 test network (see the
//! `capture_config_fixture` test in `network_management.rs` to refresh it).
//!
//! Run with:
//! ```sh
//! CONFIGTXLATOR_BIN=/path/to/configtxlator cargo test --test conformance -- --ignored
//! ```
//!
//! Comparison semantics: the resulting `ConfigUpdate` protos are compared
//! **structurally** (prost `PartialEq` after decoding). Byte equality is
//! additionally *reported* but not asserted: protobuf map-field encoding
//! order is not canonical — the Rust side encodes maps in sorted (BTreeMap)
//! order while Go's `proto.Marshal` makes no ordering guarantee — so two
//! semantically identical updates may serialize differently.

#![cfg(not(feature = "client-wasm"))]

use std::collections::BTreeMap;
use std::path::PathBuf;

use fabric_sdk::{
    fabric::{
        common::{Config, ConfigPolicy, ConfigUpdate, Policy},
        etcdraft,
        msp::MspConfig,
        protos::AnchorPeer,
    },
    gateway::configtx,
    prelude::Message,
};

const CHANNEL_ID: &str = "mychannel";

fn configtxlator_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("CONFIGTXLATOR_BIN")
            .expect("CONFIGTXLATOR_BIN must point to the configtxlator binary"),
    )
}

fn fixture_config() -> Config {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/resources/mychannel_config.pb");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
    Config::decode(bytes.as_slice()).expect("fixture is not a valid common.Config")
}

/// Runs `configtxlator compute_update` on the two configs and returns the
/// decoded reference ConfigUpdate.
fn reference_compute_update(original: &Config, updated: &Config) -> ConfigUpdate {
    let dir = std::env::temp_dir().join(format!(
        "fabric-sdk-conformance-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let original_path = dir.join("original.pb");
    let updated_path = dir.join("updated.pb");
    let output_path = dir.join("update.pb");
    std::fs::write(&original_path, original.encode_to_vec()).unwrap();
    std::fs::write(&updated_path, updated.encode_to_vec()).unwrap();

    let output = std::process::Command::new(configtxlator_bin())
        .arg("compute_update")
        .arg("--channel_id")
        .arg(CHANNEL_ID)
        .arg("--original")
        .arg(&original_path)
        .arg("--updated")
        .arg(&updated_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("failed to run configtxlator");
    assert!(
        output.status.success(),
        "configtxlator compute_update failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read(&output_path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    ConfigUpdate::decode(bytes.as_slice()).expect("configtxlator output is not a ConfigUpdate")
}

/// Computes the update both ways and asserts structural equality; reports
/// byte equality.
fn assert_conformance(scenario: &str, original: &Config, updated: &Config) {
    let ours = configtx::compute_config_update(original, updated, CHANNEL_ID)
        .unwrap_or_else(|e| panic!("[{scenario}] rust compute failed: {e}"));
    let reference = reference_compute_update(original, updated);

    assert_eq!(
        ours, reference,
        "[{scenario}] Rust ConfigUpdate differs structurally from configtxlator"
    );

    let byte_equal = ours.encode_to_vec() == reference.encode_to_vec();
    println!(
        "[{scenario}] structural equality: OK; byte equality: {}",
        if byte_equal { "yes" } else { "no (map-field ordering, expected)" }
    );
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_identical_configs_both_report_no_differences() {
    let config = fixture_config();

    // Rust side
    match configtx::compute_config_update(&config, &config, CHANNEL_ID) {
        Err(fabric_sdk::error::ConfigTxError::NoDifferences) => {}
        other => panic!("expected NoDifferences, got {:?}", other),
    }

    // Reference side: configtxlator must fail with the same complaint.
    let dir = std::env::temp_dir().join(format!("fabric-sdk-conf-nodiff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.pb");
    std::fs::write(&path, config.encode_to_vec()).unwrap();
    let output = std::process::Command::new(configtxlator_bin())
        .arg("compute_update")
        .arg("--channel_id")
        .arg(CHANNEL_ID)
        .arg("--original")
        .arg(&path)
        .arg("--updated")
        .arg(&path)
        .arg("--output")
        .arg(dir.join("out.pb"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no differences detected"),
        "unexpected configtxlator error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_set_anchor_peers() {
    // The fixture (captured from mychannel) already carries the default
    // anchor peers, so set a *different* peer to produce a real delta.
    let original = fixture_config();
    let mut updated = original.clone();
    configtx::set_anchor_peers(
        &mut updated,
        "Org1MSP",
        vec![AnchorPeer {
            host: "peer1.org1.example.com".into(),
            port: 8051,
        }],
    )
    .unwrap();
    assert_conformance("set_anchor_peers", &original, &updated);
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_replace_anchor_peers() {
    let mut original = fixture_config();
    configtx::set_anchor_peers(
        &mut original,
        "Org1MSP",
        vec![AnchorPeer {
            host: "old.example.com".into(),
            port: 1111,
        }],
    )
    .unwrap();
    let mut updated = original.clone();
    configtx::set_anchor_peers(
        &mut updated,
        "Org1MSP",
        vec![
            AnchorPeer {
                host: "peer0.org1.example.com".into(),
                port: 7051,
            },
            AnchorPeer {
                host: "peer1.org1.example.com".into(),
                port: 8051,
            },
        ],
    )
    .unwrap();
    assert_conformance("replace_anchor_peers", &original, &updated);
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_add_application_org() {
    let original = fixture_config();
    let mut updated = original.clone();

    let mut policies = BTreeMap::new();
    for name in ["Readers", "Writers", "Admins", "Endorsement"] {
        policies.insert(
            name.to_string(),
            ConfigPolicy {
                version: 0,
                policy: Some(Policy {
                    r#type: 1, // SIGNATURE
                    value: b"placeholder-signature-policy".to_vec(),
                }),
                mod_policy: "Admins".into(),
            },
        );
    }
    configtx::add_application_org(
        &mut updated,
        "Org3MSP",
        &MspConfig {
            r#type: 0,
            config: b"placeholder-fabric-msp-config".to_vec(),
        },
        policies,
    )
    .unwrap();
    assert_conformance("add_application_org", &original, &updated);
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_add_and_remove_consenter() {
    let original = fixture_config();

    let mut with_added = original.clone();
    configtx::add_consenter(
        &mut with_added,
        etcdraft::Consenter {
            host: "orderer2.example.com".into(),
            port: 7050,
            client_tls_cert: b"fake-cert-pem".to_vec(),
            server_tls_cert: b"fake-cert-pem".to_vec(),
        },
    )
    .unwrap();
    assert_conformance("add_consenter", &original, &with_added);

    let mut with_removed = with_added.clone();
    configtx::remove_consenter(&mut with_removed, "orderer2.example.com", 7050).unwrap();
    assert_conformance("remove_consenter", &with_added, &with_removed);
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_policy_removal_and_mod_policy_change() {
    let original = fixture_config();

    // Remove a policy from Org1MSP (membership change deep in the tree).
    let mut updated = original.clone();
    let org1 = updated
        .channel_group
        .as_mut()
        .unwrap()
        .groups
        .get_mut("Application")
        .unwrap()
        .groups
        .get_mut("Org1MSP")
        .unwrap();
    assert!(
        org1.policies.remove("Endorsement").is_some(),
        "fixture unexpectedly has no Org1MSP Endorsement policy"
    );
    assert_conformance("policy_removal", &original, &updated);

    // Change a group's mod_policy.
    let mut updated = original.clone();
    updated
        .channel_group
        .as_mut()
        .unwrap()
        .groups
        .get_mut("Application")
        .unwrap()
        .mod_policy = "Writers".into();
    assert_conformance("group_mod_policy_change", &original, &updated);
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_orderer_value_change() {
    let original = fixture_config();

    // Modify the Orderer BatchTimeout value in place.
    let mut updated = original.clone();
    let orderer = updated
        .channel_group
        .as_mut()
        .unwrap()
        .groups
        .get_mut("Orderer")
        .unwrap();
    let batch_timeout = orderer
        .values
        .get_mut("BatchTimeout")
        .expect("fixture unexpectedly has no BatchTimeout");
    batch_timeout.value = {
        // common.BatchTimeout { timeout: "5s" } — field 1, string
        let mut v = vec![0x0a, 0x02];
        v.extend_from_slice(b"5s");
        v
    };
    assert_conformance("orderer_value_change", &original, &updated);
}

#[test]
#[ignore = "requires the configtxlator binary (set CONFIGTXLATOR_BIN)"]
fn conformance_combined_multi_edit() {
    // Several edits at once: anchor peers + new org + consenter add.
    let original = fixture_config();
    let mut updated = original.clone();
    configtx::set_anchor_peers(
        &mut updated,
        "Org2MSP",
        vec![AnchorPeer {
            host: "peer0.org2.example.com".into(),
            port: 9051,
        }],
    )
    .unwrap();
    configtx::add_application_org(
        &mut updated,
        "Org4MSP",
        &MspConfig {
            r#type: 0,
            config: b"org4".to_vec(),
        },
        BTreeMap::new(),
    )
    .unwrap();
    configtx::add_consenter(
        &mut updated,
        etcdraft::Consenter {
            host: "orderer3.example.com".into(),
            port: 7050,
            client_tls_cert: b"c".to_vec(),
            server_tls_cert: b"s".to_vec(),
        },
    )
    .unwrap();
    assert_conformance("combined_multi_edit", &original, &updated);
}
