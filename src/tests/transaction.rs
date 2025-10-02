#[cfg(test)]
mod transaction_test {
    use crate::protos::common::{ChannelHeader, Header, HeaderType, SignatureHeader};
    use crate::protos::gateway::gateway_client::GatewayClient;
    use crate::protos::gateway::{EndorseRequest, ProposedTransaction, SubmitRequest};
    use crate::protos::protos::*;
    use openssl::ec::EcKey;
    use openssl::hash::{Hasher, MessageDigest};
    use openssl::sha::Sha256;
    use p256::pkcs8::der::Encode;
    use prost::Message;
    use std::{env, fs, vec};
    use tonic::transport::Certificate;

    fn create_transaction_id(nonce: &[u8], creator: &[u8]) -> String {
        let salted_creator = [nonce, creator].concat();
        let hash = openssl::sha::sha256(salted_creator.as_slice());
        hex::encode(hash)
    }

    fn sign_message(message: &[u8], pem_bytes: &[u8]) -> Vec<u8> {
        let ec_key = EcKey::private_key_from_pem(pem_bytes).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finish();

        let signature = openssl::ecdsa::EcdsaSig::sign(hash.as_slice(), &ec_key).unwrap();

        //Hyperledger uses a normalized s signature. Openssl does not support it so we use ecdsa implementation from RustCrypto https://github.com/RustCrypto/signatures/tree/master/ecdsa
        // which is not verified to be secure
        let signature: ecdsa::Signature<p256::NistP256> =
            ecdsa::Signature::from_der(signature.to_der().unwrap().as_slice()).unwrap();

        let mut v = vec![];
        if let Some(signature) = signature.normalize_s() {
            signature.to_der().encode_to_vec(&mut v).unwrap();
            v
        } else {
            signature.to_der().encode_to_vec(&mut v).unwrap();
            v
        }
    }

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

                let identity = crate::identity::IdentityBuilder::from_pem(
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

                let mut client = crate::client::ClientBuilder::new()
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
                    .with_sheme("https")
                    .unwrap()
                    .with_authority("localhost:7051")
                    .unwrap()
                    .with_signer(crate::signer::Signer::new(pkey))
                    .unwrap()
                    .build()
                    .unwrap();
                client.connect().await.unwrap();

                let mut tx_builder = client
                    .get_transaction_builder()
                    .with_channel_name(channel_name)
                    .unwrap()
                    .with_chaincode_id(chaincode_name)
                    .unwrap()
                    .with_function_name(function_name)
                    .unwrap();
                if !contract_name.is_empty() {
                    tx_builder = tx_builder.with_contract_id(contract_name).unwrap();
                }
                match tx_builder.build() {
                    Ok(prepared_transaction) => match prepared_transaction.submit().await {
                        Ok(result) => {
                            println!("{}", String::from_utf8_lossy(result.as_slice()));
                        }
                        Err(err) => println!("{}", err),
                    },
                    Err(err) => println!("{}", err),
                }
            });
    }
}
