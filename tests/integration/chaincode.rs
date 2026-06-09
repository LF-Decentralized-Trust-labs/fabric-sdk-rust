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

/// Submits a transaction carrying private data in the transient map, endorsed
/// only by the given organizations. `transient` entries are sent to the
/// endorsing peers but never written to the public ledger.
async fn submit_private(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    function_name: &str,
    args: &[&str],
    transient: &[(&str, &[u8])],
    endorsing_orgs: &[&str],
) {
    let mut builder = client.get_chaincode_call_builder();
    let b = builder
        .with_channel_name(channel_name)
        .unwrap()
        .with_chaincode_id(chaincode_name)
        .unwrap()
        .with_function_name(function_name)
        .unwrap()
        .with_endorsing_organizations(endorsing_orgs.iter().copied());
    if !args.is_empty() {
        b.with_function_args(args).unwrap();
    }
    for (key, value) in transient {
        b.with_transient(*key, value.to_vec());
    }
    let prepared = b.build_prepared().unwrap();

    let mut envelope = prepared.endorse(client).await.unwrap();
    envelope.submit(client).await.unwrap();
    envelope.wait_for_commit(client).await.unwrap();
}

/// Evaluates a read-only query against the given organizations' peers. Required
/// for private data, since only collection member organizations hold the data.
async fn evaluate_private(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    function_name: &str,
    args: &[&str],
    target_orgs: &[&str],
) -> String {
    let mut builder = client.get_chaincode_call_builder();
    let b = builder
        .with_channel_name(channel_name)
        .unwrap()
        .with_chaincode_id(chaincode_name)
        .unwrap()
        .with_function_name(function_name)
        .unwrap()
        .with_endorsing_organizations(target_orgs.iter().copied());
    if !args.is_empty() {
        b.with_function_args(args).unwrap();
    }
    let prepared = b.build_prepared().unwrap();
    let result = prepared.evaluate(client).await.unwrap();
    String::from_utf8_lossy(&result).to_string()
}

/// Exercises private data collections against the implicit org collection
/// (`_implicit_org_<MSPID>`). This requires a chaincode deployed with private
/// data functions, so it only runs when `ENABLE_PRIVATE_DATA_TESTS` is set.
///
/// The deployed chaincode is expected to expose:
///   - `CreateAssetPrivate`: reads the transient key `asset_properties`
///     (JSON `{"asset_id","color","size","owner","appraised_value"}`) and
///     writes it to the org's implicit private data collection.
///   - `ReadAssetPrivate(asset_id)`: returns the JSON value from the collection.
///   - `DeleteAssetPrivate(asset_id)`: removes it.
async fn run_private_data(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    msp_id: &str,
) {
    if env::var("ENABLE_PRIVATE_DATA_TESTS").is_err() {
        println!("Skipping private data tests (set ENABLE_PRIVATE_DATA_TESTS to enable)");
        return;
    }

    let asset = br#"{"asset_id":"FishPriv","color":"Orange","size":10,"owner":"Frank","appraised_value":1}"#;

    submit_private(
        client,
        channel_name,
        chaincode_name,
        "CreateAssetPrivate",
        &[],
        &[("asset_properties", asset)],
        &[msp_id],
    )
    .await;

    let read = evaluate_private(
        client,
        channel_name,
        chaincode_name,
        "ReadAssetPrivate",
        &["FishPriv"],
        &[msp_id],
    )
    .await;
    assert!(
        read.contains("FishPriv"),
        "private read should contain the asset, got: {read}"
    );

    submit_private(
        client,
        channel_name,
        chaincode_name,
        "DeleteAssetPrivate",
        &["FishPriv"],
        &[],
        &[msp_id],
    )
    .await;
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
    .with_msp(msp_id.clone())
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
    try_submit(&client, &channel_name, &chaincode_name, "DeleteAsset", &["Fish"]).await;

    // Empty list is to be expected on a fresh deployment.
    let asset_list = evaluate(&client, &channel_name, &chaincode_name, "GetAllAssets", &[]).await;
    assert_eq!(&asset_list, "[]", "expected empty asset list on fresh ledger");

    // Insert an asset and read it back via evaluate.
    submit(
        &client,
        &channel_name,
        &chaincode_name,
        "CreateAsset",
        &["Fish", "Orange", "10", "Frank", "1"],
    )
    .await;

    let frank_the_fish = evaluate(&client, &channel_name, &chaincode_name, "ReadAsset", &["Fish"]).await;
    assert_eq!(
        &frank_the_fish,
        "{\"asset_id\":\"Fish\",\"color\":\"Orange\",\"size\":10,\"owner\":\"Frank\",\"appraised_value\":1}",
        "read_asset returned unexpected data"
    );

    // Read the asset list; it should now contain Fish.
    let asset_list = evaluate(&client, &channel_name, &chaincode_name, "GetAllAssets", &[]).await;
    assert!(
        asset_list.contains("Fish"),
        "asset list should contain Fish, got: {asset_list}"
    );

    // Delete the asset so the test is repeatable.
    submit(
        &client,
        &channel_name,
        &chaincode_name,
        "DeleteAsset",
        &["Fish"],
    )
    .await;

    // Confirm deletion.
    let asset_list = evaluate(&client, &channel_name, &chaincode_name, "GetAllAssets", &[]).await;
    assert_eq!(&asset_list, "[]", "expected empty asset list after deletion");

    // Private data collections (skipped unless ENABLE_PRIVATE_DATA_TESTS is set).
    run_private_data(&client, &channel_name, &chaincode_name, &msp_id).await;
}
