#![cfg(not(feature = "client-wasm"))]

use fabric_sdk::{gateway::client, identity};
use std::{env, fs};

/// Evaluates a chaincode call via the Gateway Evaluate RPC and returns the
/// result as a UTF-8 string.  This is the correct path for read-only queries:
/// the Gateway Endorse RPC only populates `ChaincodeAction.response.payload`
/// for ledger-mutating transactions, so queries need to go through Evaluate.
async fn evaluate(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    function_name: &str,
    args: &[&str],
) -> String {
    let mut builder = client.get_chaincode_call_builder();
    let b = builder
        .with_channel_name(channel_name)
        .unwrap()
        .with_chaincode_id(chaincode_name)
        .unwrap()
        .with_function_name(function_name)
        .unwrap();
    if !args.is_empty() {
        b.with_function_args(args).unwrap();
    }
    let sp = b.build().unwrap();

    let ch = sp
        .get_proposal()
        .unwrap()
        .get_header()
        .unwrap()
        .get_channel_header()
        .unwrap();

    let result = client
        .evaluate(sp, ch.tx_id, ch.channel_id)
        .await
        .unwrap();
    String::from_utf8_lossy(&result).to_string()
}

/// Endorses, submits, and waits for commit.  Does not return a result; use
/// `evaluate` afterwards if you need to read back data.
async fn submit(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    function_name: &str,
    args: &[&str],
) {
    let mut builder = client.get_chaincode_call_builder();
    let b = builder
        .with_channel_name(channel_name)
        .unwrap()
        .with_chaincode_id(chaincode_name)
        .unwrap()
        .with_function_name(function_name)
        .unwrap();
    if !args.is_empty() {
        b.with_function_args(args).unwrap();
    }
    let sp = b.build().unwrap();

    let mut envelope = sp.endorse(client).await.unwrap();
    envelope.submit(client).await.unwrap();
    envelope.wait_for_commit(client).await.unwrap();
}

/// Like `submit` but silently ignores failures (used for cleanup of previous test runs).
async fn try_submit(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    function_name: &str,
    args: &[&str],
) {
    let mut builder = client.get_chaincode_call_builder();
    let b = builder
        .with_channel_name(channel_name)
        .unwrap()
        .with_chaincode_id(chaincode_name)
        .unwrap()
        .with_function_name(function_name)
        .unwrap();
    if !args.is_empty() {
        b.with_function_args(args).unwrap();
    }
    let sp = b.build().unwrap();
    if let Ok(mut envelope) = sp.endorse(client).await {
        let _ = envelope.submit(client).await;
        let _ = envelope.wait_for_commit(client).await;
    }
}

pub async fn run() {
    let chaincode_name =
        env::var("CHAINCODE_NAME").expect("CHAINCODE_NAME environment variable not set");
    let channel_name =
        env::var("CHANNEL_NAME").expect("CHANNEL_NAME environment variable not set");
    println!("Channel: {channel_name}");
    let msp_id = env::var("MSP_ID").expect("MSP_ID environment variable not set");
    println!("Msp: {msp_id}");

    let pkey = fs::read_to_string(env::var("PEER1_KEY_PATH").expect("PEER1_KEY_PATH not set"))
        .expect("No file found in PEER1_KEY_PATH");

    let identity = identity::IdentityBuilder::from_pem(
        fs::read(
            env::var("PEER1_USER1_CERT_PATH")
                .expect("PEER1_USER1_CERT_PATH environment variable not set"),
        )
        .expect("Couldn't read file")
        .as_slice(),
    )
    .unwrap()
    .with_msp(msp_id)
    .unwrap()
    .with_private_key(pkey)
    .unwrap()
    .build()
    .unwrap();

    let mut client = client::ClientBuilder::new()
        .with_identity(identity)
        .unwrap()
        .with_tls(
            fs::read(
                env::var("PEER1_TLS_CERT_PATH")
                    .expect("PEER1_TLS_CERT_PATH environment variable not set"),
            )
            .unwrap(),
        )
        .unwrap()
        .with_scheme("https")
        .unwrap()
        .with_authority("localhost:7051")
        .unwrap()
        .build()
        .unwrap();
    client.connect().await.unwrap();

    // Clean up any assets left over from a previous failed run.
    try_submit(&client, &channel_name, &chaincode_name, "delete_asset", &["Fish"]).await;

    // Empty list is to be expected on a fresh deployment.
    let asset_list = evaluate(&client, &channel_name, &chaincode_name, "get_all_assets", &[]).await;
    assert_eq!(&asset_list, "[]", "expected empty asset list on fresh ledger");

    // Insert an asset and read it back via evaluate.
    submit(
        &client,
        &channel_name,
        &chaincode_name,
        "create_asset",
        &["Fish", "Orange", "10", "Frank", "1"],
    )
    .await;

    let frank_the_fish = evaluate(&client, &channel_name, &chaincode_name, "read_asset", &["Fish"]).await;
    assert_eq!(
        &frank_the_fish,
        "{\"asset_id\":\"Fish\",\"color\":\"Orange\",\"size\":10,\"owner\":\"Frank\",\"appraised_value\":1}",
        "read_asset returned unexpected data"
    );

    // Read the asset list; it should now contain Fish.
    let asset_list = evaluate(&client, &channel_name, &chaincode_name, "get_all_assets", &[]).await;
    assert!(
        asset_list.contains("Fish"),
        "asset list should contain Fish, got: {asset_list}"
    );

    // Delete the asset so the test is repeatable.
    submit(
        &client,
        &channel_name,
        &chaincode_name,
        "delete_asset",
        &["Fish"],
    )
    .await;

    // Confirm deletion.
    let asset_list = evaluate(&client, &channel_name, &chaincode_name, "get_all_assets", &[]).await;
    assert_eq!(&asset_list, "[]", "expected empty asset list after deletion");
}
