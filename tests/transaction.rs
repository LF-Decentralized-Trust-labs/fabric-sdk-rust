#[cfg(test)]
mod transaction_test {
    use std::{env, fs};

    use fabric_sdk::{gateway::client, identity, signer};

    #[test]
    fn test_transaction() {
        dotenv::dotenv().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let chaincode_name = env::var("CHAINCODE_NAME")
                    .expect("CHAINCODE_NAME environment variable not set");
                let contract_name = env::var("CONTRACT_NAME").unwrap_or_default();
                let _ = env::var("CHAINCODE_VERSION")
                    .expect("CHAINCODE_VERSION environment variable not set");

                let _ = env::var("CONTRACT_NAME").unwrap_or_default();
                let function_name =
                    env::var("FUNCTION_NAME").expect("FUNCTION_NAME environment variable not set");
                let channel_name =
                    env::var("CHANNEL_NAME").expect("CHANNEL_NAME environment variable not set");
                let pkey =
                    fs::read(std::env::var("PEER1_KEY_PATH").expect("PEER1_KEY_PATH not set"))
                        .expect("No file found in PEER1_KEY_PATH");

                let identity = identity::IdentityBuilder::from_pem(
                    fs::read(
                        env::var("PEER1_USER1_CERT_PATH")
                            .expect("PEER1_USER1_CERT_PATH environment variable not set"),
                    )
                    .expect("Couldn't read file")
                    .as_slice(),
                )
                .with_msp(env::var("MSP_ID").expect("MSP_ID environment variable not set"))
                .unwrap()
                .build()
                .unwrap();

                let mut client = client::ClientBuilder::new()
                    .with_identity(identity)
                    .unwrap()
                    .with_tls(
                        std::fs::read(
                            env::var("PEER1_TLS_CERT_PATH")
                                .expect("TLS_CERT_PATH environment variable not set"),
                        )
                        .unwrap(),
                    )
                    .unwrap()
                    .with_scheme("https")
                    .unwrap()
                    .with_authority("localhost:7051")
                    .unwrap()
                    .with_signer(signer::Signer::new(pkey))
                    .unwrap()
                    .build()
                    .unwrap();
                client.connect().await.unwrap();

                let mut tx_builder = client.get_transaction_builder();
                tx_builder
                    .with_channel_name(channel_name)
                    .unwrap()
                    .with_chaincode_id(chaincode_name)
                    .unwrap()
                    .with_function_name(function_name)
                    .unwrap();
                if !contract_name.is_empty() {
                    tx_builder.with_contract_id(contract_name).unwrap();
                }
                match tx_builder.build() {
                    Ok(prepared_transaction) => {
                        match client.submit_transaction(prepared_transaction).await {
                            Ok(result) => {
                                println!("{}", String::from_utf8_lossy(result.as_slice()));
                            }
                            Err(err) => {
                                println!("Failed to submit: {}", err);
                                panic!("Failed to submit: {}", err);
                            }
                        }
                    }
                    Err(err) => {
                        println!("{}", err);
                        panic!("{}", err);
                    }
                }
            })
    }
}
