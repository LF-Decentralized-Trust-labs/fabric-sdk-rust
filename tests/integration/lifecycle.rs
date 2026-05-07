#![cfg(not(feature = "client-wasm"))]

use fabric_sdk::{
    error::LifecycleError,
    fabric::lifecycle::{
        chaincode_source, ApproveChaincodeDefinitionForMyOrgArgs, ChaincodeSource,
        CheckCommitReadinessArgs, CommitChaincodeDefinitionArgs, InstallChaincodeResult,
    },
    gateway::{client, lifecycle::LifecycleClient},
    identity,
};
use std::{env, fs};

async fn build_admin_client(
    msp_id: &str,
    cert_path_var: &str,
    key_path_var: &str,
    tls_cert_path_var: &str,
    authority: &str,
) -> client::Client {
    let key = fs::read_to_string(
        env::var(key_path_var).unwrap_or_else(|_| panic!("{key_path_var} environment variable not set")),
    )
    .unwrap_or_else(|_| panic!("Couldn't read file at {key_path_var}"));

    let identity = identity::IdentityBuilder::from_pem(
        fs::read(
            env::var(cert_path_var)
                .unwrap_or_else(|_| panic!("{cert_path_var} environment variable not set")),
        )
        .unwrap_or_else(|_| panic!("Couldn't read file at {cert_path_var}"))
        .as_slice(),
    )
    .unwrap()
    .with_msp(msp_id)
    .unwrap()
    .with_private_key(key)
    .unwrap()
    .build()
    .unwrap();

    let tls_cert = fs::read(
        env::var(tls_cert_path_var)
            .unwrap_or_else(|_| panic!("{tls_cert_path_var} environment variable not set")),
    )
    .unwrap_or_else(|_| panic!("Couldn't read file at {tls_cert_path_var}"));

    let mut client = client::ClientBuilder::new()
        .with_identity(identity)
        .unwrap()
        .with_tls(tls_cert)
        .unwrap()
        .with_scheme("https")
        .unwrap()
        .with_authority(authority)
        .unwrap()
        .build()
        .unwrap();

    client.connect().await.unwrap();
    client
}

/// Installs a chaincode package, tolerating a "already successfully installed" error.
///
/// When the same package has been installed in a previous test run the peer returns a 500
/// with the package ID embedded in the message.  This helper extracts that ID and queries
/// the peer for the full result rather than failing the test.
async fn install_or_reuse(
    lifecycle: &LifecycleClient<'_>,
    package: Vec<u8>,
) -> InstallChaincodeResult {
    match lifecycle.install_chaincode(package).await {
        Ok(result) => result,
        Err(LifecycleError::NodeError(ref msg)) if msg.contains("already successfully installed") => {
            let package_id = msg
                .split("package ID '")
                .nth(1)
                .and_then(|s| s.split('\'').next())
                .unwrap_or_else(|| panic!("Failed to parse package_id from: {msg}"))
                .to_string();
            let queried = lifecycle
                .query_installed_chaincode(&package_id)
                .await
                .unwrap_or_else(|e| panic!("Failed to query already-installed chaincode: {e:?}"));
            InstallChaincodeResult {
                package_id: queried.package_id,
                label: queried.label,
            }
        }
        Err(e) => panic!("install_chaincode failed: {e:?}"),
    }
}

pub async fn run() {
    let channel_name =
        env::var("CHANNEL_NAME").expect("CHANNEL_NAME environment variable not set");
    let chaincode_name =
        env::var("CHAINCODE_NAME").expect("CHAINCODE_NAME environment variable not set");
    let chaincode_version =
        env::var("CHAINCODE_VERSION").expect("CHAINCODE_VERSION environment variable not set");
    let msp_id_org1 = env::var("MSP_ID").expect("MSP_ID environment variable not set");
    let msp_id_org2 = env::var("MSP_ID_ORG2").expect("MSP_ID_ORG2 environment variable not set");

    let org1_client = build_admin_client(
        &msp_id_org1,
        "PEER1_ADMIN_CERT_PATH",
        "PEER1_ADMIN_KEY_PATH",
        "PEER1_TLS_CERT_PATH",
        "localhost:7051",
    )
    .await;

    let org2_client = build_admin_client(
        &msp_id_org2,
        "PEER2_ADMIN_CERT_PATH",
        "PEER2_ADMIN_KEY_PATH",
        "PEER2_TLS_CERT_PATH",
        "localhost:9051",
    )
    .await;

    let org1_lifecycle = org1_client.get_lifecycle_client();
    let org2_lifecycle = org2_client.get_lifecycle_client();

    let package = fs::read("tests/resources/basic.tar.gz")
        .expect("tests/resources/basic.tar.gz not found");

    // --- Install on Org1 ---
    let install_result = install_or_reuse(&org1_lifecycle, package.clone()).await;
    println!(
        "Org1 installed: package_id={}, label={}",
        install_result.package_id, install_result.label
    );
    assert!(!install_result.package_id.is_empty());
    assert_eq!(install_result.label, "basic");

    // --- Install on Org2 ---
    let org2_install_result = install_or_reuse(&org2_lifecycle, package).await;
    println!(
        "Org2 installed: package_id={}, label={}",
        org2_install_result.package_id, org2_install_result.label
    );
    assert_eq!(org2_install_result.package_id, install_result.package_id);

    // --- Query all installed chaincodes (Org1) ---
    let installed = org1_lifecycle.query_installed_chaincodes().await.unwrap();
    assert!(
        installed
            .installed_chaincodes
            .iter()
            .any(|cc| cc.package_id == install_result.package_id),
        "Package not found in query_installed_chaincodes result"
    );

    // --- Query a specific installed chaincode ---
    let queried = org1_lifecycle
        .query_installed_chaincode(&install_result.package_id)
        .await
        .unwrap();
    assert_eq!(queried.package_id, install_result.package_id);
    assert_eq!(queried.label, "basic");

    // --- Download the installed package ---
    let pkg_bytes = org1_lifecycle
        .get_installed_chaincode_package(&install_result.package_id)
        .await
        .unwrap();
    assert!(!pkg_bytes.is_empty(), "Downloaded package must not be empty");

    // Determine the next sequence: bump if already committed, otherwise start at 1.
    let sequence = match org1_lifecycle
        .query_chaincode_definition(&channel_name, &chaincode_name)
        .await
    {
        Ok(def) => def.sequence + 1,
        Err(_) => 1,
    };
    println!("Using sequence={sequence}");

    // --- Approve chaincode definition for Org1 ---
    org1_lifecycle
        .approve_chaincode_definition(
            &channel_name,
            ApproveChaincodeDefinitionForMyOrgArgs {
                name: chaincode_name.clone(),
                version: chaincode_version.clone(),
                sequence,
                source: Some(ChaincodeSource {
                    r#type: Some(chaincode_source::Type::LocalPackage(
                        chaincode_source::Local {
                            package_id: install_result.package_id.clone(),
                        },
                    )),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    println!("Org1 approved chaincode definition (sequence={sequence})");

    // --- Approve chaincode definition for Org2 ---
    org2_lifecycle
        .approve_chaincode_definition(
            &channel_name,
            ApproveChaincodeDefinitionForMyOrgArgs {
                name: chaincode_name.clone(),
                version: chaincode_version.clone(),
                sequence,
                source: Some(ChaincodeSource {
                    r#type: Some(chaincode_source::Type::LocalPackage(
                        chaincode_source::Local {
                            package_id: org2_install_result.package_id.clone(),
                        },
                    )),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    println!("Org2 approved chaincode definition (sequence={sequence})");

    // --- Check commit readiness ---
    let readiness = org1_lifecycle
        .check_commit_readiness(
            &channel_name,
            CheckCommitReadinessArgs {
                name: chaincode_name.clone(),
                version: chaincode_version.clone(),
                sequence,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        readiness.approvals.get(&msp_id_org1).copied().unwrap_or(false),
        "{msp_id_org1} should have approved the definition"
    );
    assert!(
        readiness.approvals.get(&msp_id_org2).copied().unwrap_or(false),
        "{msp_id_org2} should have approved the definition"
    );

    // --- Commit the chaincode definition (endorsements from both orgs required) ---
    org1_lifecycle
        .commit_chaincode_definition(
            &channel_name,
            CommitChaincodeDefinitionArgs {
                name: chaincode_name.clone(),
                version: chaincode_version.clone(),
                sequence,
                ..Default::default()
            },
            &[&org2_client],
        )
        .await
        .unwrap();
    println!("Committed chaincode definition (sequence={sequence})");

    // --- Query the committed definition ---
    let committed = org1_lifecycle
        .query_chaincode_definition(&channel_name, &chaincode_name)
        .await
        .unwrap();
    assert_eq!(committed.sequence, sequence);
    assert_eq!(committed.version, chaincode_version);
    println!(
        "Verified: {} v{} seq={}",
        chaincode_name, committed.version, committed.sequence
    );

    // --- Query this org's approved definition (namespace exists after commit) ---
    let approved = org1_lifecycle
        .query_approved_chaincode_definition(&channel_name, &chaincode_name, sequence)
        .await
        .unwrap();
    assert_eq!(approved.sequence, sequence);
    assert_eq!(approved.version, chaincode_version);

    // --- Query all committed definitions ---
    let all_committed = org1_lifecycle
        .query_chaincode_definitions(&channel_name)
        .await
        .unwrap();
    assert!(
        all_committed
            .chaincode_definitions
            .iter()
            .any(|def| def.name == chaincode_name),
        "Chaincode not found in query_chaincode_definitions result"
    );
}
