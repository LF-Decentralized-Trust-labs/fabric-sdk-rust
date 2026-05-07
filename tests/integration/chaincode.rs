#![cfg(not(feature = "client-wasm"))]

use fabric_sdk::{gateway::client, identity};
use std::{env, fs};

pub async fn run() {
    let chaincode_name =
        env::var("CHAINCODE_NAME").expect("CHAINCODE_NAME environment variable not set");
    let channel_name =
        env::var("CHANNEL_NAME").expect("CHANNEL_NAME environment variable not set");
    println!("Channel: {channel_name}");
    let msp_id = env::var("MSP_ID").expect("MSP_ID environment variable not set");
    println!("Msp: {msp_id}");

    let pkey = fs::read_to_string(
        env::var("PEER1_KEY_PATH").expect("PEER1_KEY_PATH not set"),
    )
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

    let asset_list = {
        let mut builder = client.get_chaincode_call_builder();
        let tx = builder
            .with_channel_name(channel_name.clone())
            .unwrap()
            .with_chaincode_id(chaincode_name.clone())
            .unwrap()
            .with_function_name("get_all_assets")
            .unwrap()
            .build()
            .unwrap();
        let envelope = tx.endorse(&client).await.unwrap();
        envelope
            .get_payload()
            .unwrap()
            .get_transaction()
            .unwrap()
            .get_result_string()
            .unwrap()
    };
    // Empty list is to be expected on a fresh deployment
    assert_eq!(&asset_list, "\"[]\"");

    // Insert an asset
    let frank_the_fish = {
        let mut builder = client.get_chaincode_call_builder();
        let tx = builder
            .with_channel_name(channel_name.clone())
            .unwrap()
            .with_chaincode_id(chaincode_name.clone())
            .unwrap()
            .with_function_name("create_asset")
            .unwrap()
            .with_function_args(["Fish", "Orange", "10", "Frank", "1"])
            .unwrap()
            .build()
            .unwrap();
        let mut envelope = tx.endorse(&client).await.unwrap();
        envelope.submit(&client).await.expect("Submit error");
        envelope
            .wait_for_commit(&client)
            .await
            .expect("Error while waiting for commit");
        envelope
            .get_payload()
            .unwrap()
            .get_transaction()
            .unwrap()
            .get_result_string()
            .unwrap()
    };
    assert_eq!(
        &frank_the_fish,
        "{\"asset_id\":\"Fish\",\"color\":\"Orange\",\"size\":10,\"owner\":\"Frank\",\"appraised_value\":1}"
    );

    // Read the asset back
    let read_frank = {
        let mut builder = client.get_chaincode_call_builder();
        let tx = builder
            .with_channel_name(channel_name.clone())
            .unwrap()
            .with_chaincode_id(chaincode_name.clone())
            .unwrap()
            .with_function_name("read_asset")
            .unwrap()
            .with_function_args(["Fish"])
            .unwrap()
            .build()
            .unwrap();
        let envelope = tx.endorse(&client).await.unwrap();
        envelope
            .get_payload()
            .unwrap()
            .get_transaction()
            .unwrap()
            .get_result_string()
            .unwrap()
    };
    assert_eq!(&frank_the_fish, &read_frank);

    let asset_list = {
        let mut builder = client.get_chaincode_call_builder();
        let tx = builder
            .with_channel_name(channel_name.clone())
            .unwrap()
            .with_chaincode_id(chaincode_name.clone())
            .unwrap()
            .with_function_name("get_all_assets")
            .unwrap()
            .build()
            .unwrap();
        let envelope = tx.endorse(&client).await.unwrap();
        envelope
            .get_payload()
            .unwrap()
            .get_transaction()
            .unwrap()
            .get_result_string()
            .unwrap()
    };
    assert_eq!(
        &asset_list,
        "\"[{\\\"appraised_value\\\":1,\\\"asset_id\\\":\\\"Fish\\\",\\\"color\\\":\\\"Orange\\\",\\\"owner\\\":\\\"Frank\\\",\\\"size\\\":10}]\""
    );

    // Delete the asset so the test is repeatable
    {
        let mut builder = client.get_chaincode_call_builder();
        let tx = builder
            .with_channel_name(channel_name.clone())
            .unwrap()
            .with_chaincode_id(chaincode_name.clone())
            .unwrap()
            .with_function_name("delete_asset")
            .unwrap()
            .with_function_args(["Fish"])
            .unwrap()
            .build()
            .unwrap();
        let mut envelope = tx.endorse(&client).await.unwrap();
        envelope.submit(&client).await.unwrap();
        envelope.wait_for_commit(&client).await.unwrap();
    }

    // Confirm deletion
    let asset_list = {
        let mut builder = client.get_chaincode_call_builder();
        let tx = builder
            .with_channel_name(channel_name.clone())
            .unwrap()
            .with_chaincode_id(chaincode_name.clone())
            .unwrap()
            .with_function_name("get_all_assets")
            .unwrap()
            .build()
            .unwrap();
        let envelope = tx.endorse(&client).await.unwrap();
        envelope
            .get_payload()
            .unwrap()
            .get_transaction()
            .unwrap()
            .get_result_string()
            .unwrap()
    };
    assert_eq!(&asset_list, "\"[]\"");
}
