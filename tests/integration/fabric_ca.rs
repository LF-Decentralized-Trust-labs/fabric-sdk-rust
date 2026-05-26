#![cfg(not(feature = "client-wasm"))]

use fabric_sdk::{
    fabric_ca::{FabricCAClientBuilder, ModifyIdentityRequest, RegisterIdentityRequest},
    identity,
};
use std::{env, fs};

pub async fn run() {
    let url = match env::var("FABRIC_CA_URL") {
        Ok(u) => u,
        Err(_) => {
            println!("Skipping Fabric CA tests: FABRIC_CA_URL not set");
            return;
        }
    };

    let msp_id = env::var("MSP_ID").expect("MSP_ID environment variable not set");

    let cert_path = env::var("CA_ADMIN_CERT_PATH").unwrap_or_else(|_| {
        env::var("PEER1_ADMIN_CERT_PATH").expect("PEER1_ADMIN_CERT_PATH not set")
    });
    let key_path = env::var("CA_ADMIN_KEY_PATH").unwrap_or_else(|_| {
        env::var("PEER1_ADMIN_KEY_PATH").expect("PEER1_ADMIN_KEY_PATH not set")
    });

    let pkey = fs::read_to_string(&key_path)
        .unwrap_or_else(|_| panic!("Could not read key at {key_path}"));

    let identity = identity::IdentityBuilder::from_pem(
        fs::read(&cert_path)
            .unwrap_or_else(|_| panic!("Could not read cert at {cert_path}"))
            .as_slice(),
    )
    .unwrap()
    .with_msp(msp_id)
    .unwrap()
    .with_private_key(pkey)
    .unwrap()
    .build()
    .unwrap();

    let mut builder = FabricCAClientBuilder::new()
        .with_url(url)
        .unwrap()
        .with_identity(identity);

    if let Ok(tls_path) = env::var("CA_TLS_CERT_PATH") {
        let tls = fs::read(tls_path).expect("Could not read CA_TLS_CERT_PATH");
        builder = builder.with_tls(tls);
    } else {
        builder = builder.danger_accept_invalid_certs();
    }

    let ca = builder.build().unwrap();

    // get_ca_info does not require auth
    let info = ca.get_ca_info().await.unwrap();
    assert!(!info.ca_name.is_empty(), "CA name should not be empty");
    println!("CA: {} v{}", info.ca_name, info.version);

    // list all identities
    let identities = ca.list_identities().await.unwrap();
    assert!(
        !identities.is_empty(),
        "Expected at least one identity (admin)"
    );
    println!("Identities: {}", identities.len());

    // get the admin identity by id
    let admin_id = &identities[0].id;
    let admin = ca.get_identity(admin_id).await.unwrap();
    assert_eq!(&admin.id, admin_id);

    // register, modify, then remove a test identity
    let test_id = "sdk-test-user";
    // clean up any leftover from a previous interrupted run
    let _ = ca.remove_identity(test_id).await;
    let secret = ca
        .register_identity(RegisterIdentityRequest {
            id: test_id.to_string(),
            r#type: "client".to_string(),
            secret: Some("testsecret".to_string()),
            max_enrollments: Some(1),
            affiliation: None,
            attrs: vec![],
        })
        .await
        .unwrap();
    assert!(!secret.is_empty());
    println!("Registered {}: secret={}", test_id, secret);

    let modified = ca
        .modify_identity(
            test_id,
            ModifyIdentityRequest {
                r#type: None,
                secret: None,
                max_enrollments: Some(-1),
                affiliation: None,
                attrs: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(modified.max_enrollments, -1);

    ca.remove_identity(test_id).await.unwrap();
    println!("Removed {}", test_id);

    // list affiliations
    let affiliations = ca.list_affiliations().await.unwrap();
    println!("Root affiliation: {}", affiliations.name);
}
