//! Tests of `configtx::check_config_update_signatures` on channel configs
//! built with `GenesisBuilder` (standard ImplicitMeta and org policies).
//!
//! Fixtures in `tests/resources/policy/` (openssl, P-256, no keys kept):
//! - `<org>-ca.pem`: the CA of `org1`..`org3` and `orderer`;
//! - `<org>-admin.pem`, `-peer.pem`, `-client.pem`, `orderer-orderer.pem`:
//!   certificates issued by that CA with the NodeOU of their role as `OU`;
//!   `org1-admin2.pem` is a second Org1 admin;
//! - `org1-rogueadmin.pem`: `OU=admin` with an Org1 subject, but issued by
//!   another CA.
//!
//! Signatures are built without keys: the check only reads who signed.

#![cfg(not(feature = "client-wasm"))]

use std::path::PathBuf;

use fabric_sdk::{
    fabric::{
        common::{
            Config, ConfigSignature, ImplicitMetaPolicy, SignatureHeader,
            implicit_meta_policy::Rule,
        },
        msp::SerializedIdentity,
        protos::AnchorPeer,
    },
    gateway::configtx::{
        self, ApplicationOrg, ConfigElementKind, GenesisBuilder, MspConfigBuilder, OrdererOrg,
        PolicyEvaluationDetail,
    },
    prelude::Message,
};

fn pem(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/resources/policy")
        .join(format!("{name}.pem"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn msp_id(org: &str) -> String {
    match org {
        "orderer" => "OrdererMSP".into(),
        _ => format!("{}MSP", org.replacen("org", "Org", 1)),
    }
}

fn msp(org: &str) -> fabric_sdk::fabric::msp::MspConfig {
    let ca = pem(&format!("{org}-ca"));
    MspConfigBuilder::new(msp_id(org))
        .with_root_cert(ca.clone())
        .with_node_ous(ca)
        .build()
        .unwrap()
}

/// A channel with the first `n` of org1..org3 and one orderer org.
fn channel(n: usize) -> Config {
    let mut builder = GenesisBuilder::new("policychannel")
        .with_orderer_org(OrdererOrg::new("OrdererMSP", msp("orderer")))
        .with_consenter(fabric_sdk::fabric::etcdraft::Consenter {
            host: "orderer.example.com".into(),
            port: 7050,
            client_tls_cert: pem("orderer-orderer"),
            server_tls_cert: pem("orderer-orderer"),
        });
    for org in ["org1", "org2", "org3"].into_iter().take(n) {
        builder = builder.with_application_org(ApplicationOrg::new(&msp_id(org), msp(org)));
    }
    builder.build_config().unwrap()
}

/// A signature by `<org>-<who>.pem` claiming `<org>`'s MSP (or `as_msp`).
fn signature_as(cert: &str, as_msp: &str) -> ConfigSignature {
    let creator = SerializedIdentity {
        mspid: as_msp.into(),
        id_bytes: pem(cert),
    };
    ConfigSignature {
        signature_header: SignatureHeader {
            creator: creator.encode_to_vec(),
            nonce: vec![7; 24],
        }
        .encode_to_vec(),
        signature: vec![],
    }
}

fn signature(cert: &str) -> ConfigSignature {
    let org = cert.split('-').next().unwrap();
    signature_as(cert, &msp_id(org))
}

/// Adds Org9MSP (reusing org3's MSP material): changes the Application
/// group, whose mod policy is `/Channel/Application/Admins` (MAJORITY).
fn add_org_update(current: &Config) -> fabric_sdk::fabric::common::ConfigUpdate {
    let mut updated = current.clone();
    configtx::add_application_org(
        &mut updated,
        "Org9MSP",
        &msp("org3"),
        configtx::org_policies("Org9MSP"),
    )
    .unwrap();
    configtx::compute_config_update(current, &updated, "policychannel").unwrap()
}

fn orgs(names: &[&str]) -> std::collections::BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn majority_with_one_two_and_three_orgs() {
    // (orgs in channel, admins signing, satisfied)
    let cases: &[(usize, &[&str], bool)] = &[
        (1, &[], false),
        (1, &["org1-admin"], true),
        (2, &["org1-admin"], false), // 2/2+1 = 2 needed
        (2, &["org1-admin", "org2-admin"], true),
        (3, &["org1-admin"], false),
        (3, &["org1-admin", "org3-admin"], true), // 3/2+1 = 2 needed
        (3, &["org1-admin", "org2-admin", "org3-admin"], true),
    ];
    for (n, signers, expected) in cases {
        let current = channel(*n);
        let update = add_org_update(&current);
        let signatures: Vec<_> = signers.iter().map(|s| signature(s)).collect();
        let check =
            configtx::check_config_update_signatures(&current, &update, &signatures).unwrap();

        // Exactly one element needs authorization: the Application group.
        assert_eq!(check.elements.len(), 1, "{n} orgs, {signers:?}");
        let element = &check.elements[0];
        assert_eq!(element.kind, ConfigElementKind::Group);
        assert_eq!(element.path, "/Channel/Application");
        assert_eq!(element.evaluation.path, "/Channel/Application/Admins");
        match &element.evaluation.detail {
            PolicyEvaluationDetail::ImplicitMeta {
                rule,
                sub_policy,
                required,
                sub_policies,
            } => {
                assert_eq!(*rule, Rule::Majority);
                assert_eq!(sub_policy, "Admins");
                assert_eq!(*required, n / 2 + 1);
                assert_eq!(sub_policies.len(), *n);
            }
            other => panic!("expected ImplicitMeta, got {other:?}"),
        }
        assert_eq!(check.is_satisfied(), *expected, "{n} orgs, {signers:?}");
    }
}

#[test]
fn orgs_to_sign_names_the_missing_admins() {
    let current = channel(3);
    let update = add_org_update(&current);
    let check =
        configtx::check_config_update_signatures(&current, &update, &[signature("org2-admin")])
            .unwrap();
    assert!(!check.is_satisfied());
    assert_eq!(check.orgs_to_sign(), orgs(&["Org1MSP", "Org3MSP"]));

    let check = configtx::check_config_update_signatures(
        &current,
        &update,
        &[signature("org2-admin"), signature("org1-admin")],
    )
    .unwrap();
    assert!(check.is_satisfied());
    assert!(check.orgs_to_sign().is_empty());
}

/// Rewrites `/Channel/Application/Admins` to `<rule> Admins`.
fn with_application_admins_rule(mut config: Config, rule: Rule) -> Config {
    let policy = config
        .channel_group
        .as_mut()
        .unwrap()
        .groups
        .get_mut("Application")
        .unwrap()
        .policies
        .get_mut("Admins")
        .unwrap()
        .policy
        .as_mut()
        .unwrap();
    policy.value = ImplicitMetaPolicy {
        sub_policy: "Admins".into(),
        rule: rule.into(),
    }
    .encode_to_vec();
    config
}

#[test]
fn all_needs_every_org() {
    let current = with_application_admins_rule(channel(3), Rule::All);
    let update = add_org_update(&current);
    let two = [signature("org1-admin"), signature("org2-admin")];
    let check = configtx::check_config_update_signatures(&current, &update, &two).unwrap();
    assert!(!check.is_satisfied());
    assert_eq!(check.orgs_to_sign(), orgs(&["Org3MSP"]));

    let three = [
        signature("org1-admin"),
        signature("org2-admin"),
        signature("org3-admin"),
    ];
    let check = configtx::check_config_update_signatures(&current, &update, &three).unwrap();
    assert!(check.is_satisfied());
}

#[test]
fn any_needs_one_org() {
    let current = with_application_admins_rule(channel(3), Rule::Any);
    let update = add_org_update(&current);
    let check =
        configtx::check_config_update_signatures(&current, &update, &[signature("org3-admin")])
            .unwrap();
    assert!(check.is_satisfied());
    let check = configtx::check_config_update_signatures(&current, &update, &[]).unwrap();
    assert!(!check.is_satisfied());
    assert_eq!(
        check.orgs_to_sign(),
        orgs(&["Org1MSP", "Org2MSP", "Org3MSP"])
    );
}

/// Sets Org1's anchor peers: changes `/Channel/Application/Org1MSP`
/// (a new value bumps the group), mod policy `OR('Org1MSP.admin')`.
fn anchor_peer_update(current: &Config) -> fabric_sdk::fabric::common::ConfigUpdate {
    let mut updated = current.clone();
    configtx::set_anchor_peers(
        &mut updated,
        "Org1MSP",
        vec![AnchorPeer {
            host: "peer0.org1.example.com".into(),
            port: 7051,
        }],
    )
    .unwrap();
    configtx::compute_config_update(current, &updated, "policychannel").unwrap()
}

#[test]
fn signer_of_the_wrong_role_does_not_count() {
    let current = channel(2);
    let update = anchor_peer_update(&current);

    for wrong in ["org1-peer", "org1-client", "org2-admin"] {
        let check =
            configtx::check_config_update_signatures(&current, &update, &[signature(wrong)])
                .unwrap();
        assert_eq!(check.elements.len(), 1);
        assert_eq!(check.elements[0].path, "/Channel/Application/Org1MSP");
        assert_eq!(
            check.elements[0].evaluation.path,
            "/Channel/Application/Org1MSP/Admins"
        );
        assert!(
            !check.is_satisfied(),
            "{wrong} must not satisfy Org1 admins"
        );
        assert_eq!(check.orgs_to_sign(), orgs(&["Org1MSP"]));
    }

    let check =
        configtx::check_config_update_signatures(&current, &update, &[signature("org1-admin")])
            .unwrap();
    assert!(check.is_satisfied());
}

#[test]
fn admin_ou_from_another_ca_does_not_count() {
    // OU=admin and claims Org1MSP, but was issued by a CA that is not the
    // one Org1's admin NodeOU is bound to.
    let current = channel(1);
    let update = anchor_peer_update(&current);
    let check = configtx::check_config_update_signatures(
        &current,
        &update,
        &[signature_as("org1-rogueadmin", "Org1MSP")],
    )
    .unwrap();
    assert!(!check.is_satisfied());
}

#[test]
fn duplicate_signer_counts_once() {
    let current = channel(3);
    let update = add_org_update(&current);

    // The same admin twice: one identity.
    let twice = [signature("org1-admin"), signature("org1-admin")];
    let check = configtx::check_config_update_signatures(&current, &update, &twice).unwrap();
    assert!(!check.is_satisfied());

    // Two different admins of the same org: still one org of three.
    let same_org = [signature("org1-admin"), signature("org1-admin2")];
    let check = configtx::check_config_update_signatures(&current, &update, &same_org).unwrap();
    assert!(!check.is_satisfied());
    assert_eq!(check.orgs_to_sign(), orgs(&["Org2MSP", "Org3MSP"]));
}

#[test]
fn signer_outside_the_channel_is_ignored() {
    // Org3 is not in a two-org channel: its admin cannot help.
    let current = channel(2);
    let update = add_org_update(&current);
    let check = configtx::check_config_update_signatures(
        &current,
        &update,
        &[signature("org1-admin"), signature("org3-admin")],
    )
    .unwrap();
    assert!(!check.is_satisfied());
    assert_eq!(check.orgs_to_sign(), orgs(&["Org2MSP"]));
}

#[test]
fn orderer_values_need_orderer_admins() {
    let current = channel(2);
    let mut updated = current.clone();
    let batch_size = fabric_sdk::fabric::orderer::BatchSize {
        max_message_count: 20,
        absolute_max_bytes: 10 * 1024 * 1024,
        preferred_max_bytes: 1024 * 1024,
    };
    configtx::set_batch_size(&mut updated, batch_size).unwrap();
    let update = configtx::compute_config_update(&current, &updated, "policychannel").unwrap();

    let app_admins = [signature("org1-admin"), signature("org2-admin")];
    let check = configtx::check_config_update_signatures(&current, &update, &app_admins).unwrap();
    assert_eq!(check.elements.len(), 1);
    assert_eq!(check.elements[0].kind, ConfigElementKind::Value);
    assert_eq!(check.elements[0].path, "/Channel/Orderer/BatchSize");
    assert_eq!(check.elements[0].evaluation.path, "/Channel/Orderer/Admins");
    assert!(!check.is_satisfied());
    assert_eq!(check.orgs_to_sign(), orgs(&["OrdererMSP"]));

    // The orderer node is not an admin; the orderer org admin is.
    let check = configtx::check_config_update_signatures(
        &current,
        &update,
        &[signature("orderer-orderer")],
    )
    .unwrap();
    assert!(!check.is_satisfied());
    let check =
        configtx::check_config_update_signatures(&current, &update, &[signature("orderer-admin")])
            .unwrap();
    assert!(check.is_satisfied());
}

#[test]
fn absolute_mod_policy_resolves_from_channel_root() {
    // OrdererAddresses has the absolute mod policy /Channel/Orderer/Admins.
    let mut current = channel(1);
    current.channel_group.as_mut().unwrap().values.insert(
        "OrdererAddresses".into(),
        fabric_sdk::fabric::common::ConfigValue {
            version: 0,
            value: fabric_sdk::fabric::common::OrdererAddresses {
                addresses: vec!["a:1".into()],
            }
            .encode_to_vec(),
            mod_policy: "/Channel/Orderer/Admins".into(),
        },
    );
    let mut updated = current.clone();
    updated
        .channel_group
        .as_mut()
        .unwrap()
        .values
        .get_mut("OrdererAddresses")
        .unwrap()
        .value = fabric_sdk::fabric::common::OrdererAddresses {
        addresses: vec!["b:2".into()],
    }
    .encode_to_vec();
    let update = configtx::compute_config_update(&current, &updated, "policychannel").unwrap();

    let check =
        configtx::check_config_update_signatures(&current, &update, &[signature("orderer-admin")])
            .unwrap();
    assert_eq!(check.elements.len(), 1);
    assert_eq!(check.elements[0].mod_policy, "/Channel/Orderer/Admins");
    assert_eq!(check.elements[0].evaluation.path, "/Channel/Orderer/Admins");
    assert!(check.is_satisfied());
}

#[test]
fn a_signer_satisfies_at_most_one_principal() {
    // Org1's Admins becomes AND('Org1MSP.admin', 'Org1MSP.admin'): two
    // distinct admins are needed, one admin cannot fill both slots.
    let mut current = channel(1);
    let admin = (
        "Org1MSP",
        fabric_sdk::fabric::common::msp_role::MspRoleType::Admin,
    );
    let mut envelope = fabric_sdk::gateway::collection::role_or_policy(&[admin, admin]);
    if let Some(fabric_sdk::fabric::common::signature_policy::Type::NOutOf(n_out_of)) =
        envelope.rule.as_mut().and_then(|r| r.r#type.as_mut())
    {
        n_out_of.n = 2;
    }
    current
        .channel_group
        .as_mut()
        .unwrap()
        .groups
        .get_mut("Application")
        .unwrap()
        .groups
        .get_mut("Org1MSP")
        .unwrap()
        .policies
        .get_mut("Admins")
        .unwrap()
        .policy
        .as_mut()
        .unwrap()
        .value = envelope.encode_to_vec();
    let update = anchor_peer_update(&current);

    let check =
        configtx::check_config_update_signatures(&current, &update, &[signature("org1-admin")])
            .unwrap();
    assert!(!check.is_satisfied());

    let check = configtx::check_config_update_signatures(
        &current,
        &update,
        &[signature("org1-admin"), signature("org1-admin2")],
    )
    .unwrap();
    assert!(check.is_satisfied());
}
