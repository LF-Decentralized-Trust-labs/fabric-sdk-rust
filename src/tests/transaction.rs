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
                let chaincode_version = env::var("CHAINCODE_VERSION")
                    .expect("CHAINCODE_VERSION environment variable not set");

                let contract_name = env::var("CONTRACT_NAME").unwrap_or_default();
                let function_name =
                    env::var("FUNCTION_NAME").expect("FUNCTION_NAME environment variable not set");
                let channel_name =
                    env::var("CHANNEL_NAME").expect("CHANNEL_NAME environment variable not set");
                let pkey = fs::read_to_string(
                    std::env::var("PEER1_KEY_PATH").expect("PEER1_KEY_PATH not set"),
                )
                .expect("No file found in PEER1_KEY_PATH");

                //let qualified_name = if contract_name.is_empty() {
                //    function_name
                //} else {
                //    format!("{}:{}", contract_name, function_name)
                //};

                let identity = {
                    //Read identity
                    let identity_pm_path = env::var("PEER1_USER1_CERT_PATH")
                        .expect("PEER1_USER1_CERT_PATH environment variable not set");

                    let public_cert = Certificate::from_pem(
                        fs::read(identity_pm_path).expect("Couldn't read file"),
                    );

                    crate::protos::msp::SerializedIdentity {
                        mspid: env::var("MSP_ID").expect("MSP_ID environment variable not set"),
                        id_bytes: public_cert.as_ref().to_vec(),
                    }
                };

                //Generate random bytes for transaction id and signature header
                let mut nonce = [0u8; crate::transaction::NONCE_LENGTH];
                openssl::rand::rand_bytes(&mut nonce).expect("Unable to generate random bytes");

                //Create transaction id
                let transaction_id =
                    create_transaction_id(&nonce, identity.encode_to_vec().as_slice());

                let signature_header = SignatureHeader {
                    creator: identity.encode_to_vec(),
                    nonce: nonce.to_vec(),
                };

                let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
                hasher.update(identity.id_bytes.as_slice()).unwrap();
                let tls_cert_hash = hasher.finish().expect("Couldn't finalize hash").to_vec();

                let chaincode_id = ChaincodeId {
                    path: String::default(),
                    name: chaincode_name.clone(),
                    version: chaincode_version,
                };

                let chaincode_header_expansion = ChaincodeHeaderExtension {
                    chaincode_id: Some(chaincode_id.clone()),
                };

                let channel_header = ChannelHeader {
                    r#type: HeaderType::EndorserTransaction.into(),
                    version: 1, //I dunno
                    timestamp: Some(std::time::SystemTime::now().into()),
                    channel_id: channel_name.clone(), // On the test network it will be myChannel
                    tx_id: transaction_id.clone(),
                    epoch: 0, // The epoch in which this header was generated, where epoch is defined based on block height
                    extension: chaincode_header_expansion.encode_to_vec(), // Extension that may be attached based on the header type
                    tls_cert_hash, // If mutual TLS is employed, this represents the hash of the client's TLS certificate
                };

                let chaincode_input = ChaincodeInput {
                    args: vec![function_name.as_bytes().to_vec()], //TODO Chaincode args
                    decorations: std::collections::HashMap::default(), //TODO Chaincode decorations
                    is_init: false,
                };

                let chaincode_spec = ChaincodeSpec {
                    r#type: chaincode_spec::Type::Java.into(),
                    chaincode_id: Some(chaincode_id.clone()),
                    input: Some(chaincode_input),
                    timeout: 10,
                };

                let chaincode_invokation_spec = ChaincodeInvocationSpec {
                    chaincode_spec: Some(chaincode_spec),
                };

                let chaincode_poposal_payload = ChaincodeProposalPayload {
                    input: chaincode_invokation_spec.encode_to_vec(),
                    transient_map: std::collections::HashMap::default(),
                };

                let header = Header {
                    channel_header: channel_header.encode_to_vec(),
                    signature_header: signature_header.encode_to_vec(),
                };

                let proposal = Proposal {
                    header: header.encode_to_vec(),
                    payload: chaincode_poposal_payload.encode_to_vec(),
                    // Optional extensions to the proposal. Its content depends on the Header's
                    // type field.  For the type CHAINCODE, it might be the bytes of a
                    // ChaincodeAction message.
                    extension: chaincode_header_expansion.encode_to_vec(),
                };

                let signature = sign_message(&proposal.encode_to_vec(), pkey.as_bytes());

                let signed_proposal = SignedProposal {
                    proposal_bytes: proposal.encode_to_vec(),
                    signature,
                };

                let proposed_transaction = ProposedTransaction {
                    transaction_id,
                    proposal: Some(signed_proposal),
                    endorsing_organizations: vec![], //Currently empty since private data is not implemented yet
                };

                let endorse_request = EndorseRequest {
                    transaction_id: proposed_transaction.transaction_id,
                    channel_id: channel_name.clone(), // On the test network it will be myChannel
                    proposed_transaction: proposed_transaction.proposal,
                    endorsing_organizations: proposed_transaction.endorsing_organizations,
                };

                let connection = crate::tests::handshake::handshake_peer1().await;
                let mut gateway_client = GatewayClient::new(connection);
                let response = gateway_client.endorse(endorse_request).await;
                match response {
                    Ok(response) => {
                        match response.into_inner().prepared_transaction {
                            Some(mut prepared_transaction) => {
                                unsafe {
                                    println!(
                                        "{}",
                                        String::from_utf8_unchecked(
                                            prepared_transaction.payload.clone()
                                        )
                                    )
                                }

                                //Generate random bytes for transaction id and signature header
                                let mut nonce = [0u8; crate::transaction::NONCE_LENGTH];
                                openssl::rand::rand_bytes(&mut nonce)
                                    .expect("Unable to generate random bytes");

                                prepared_transaction.signature = sign_message(
                                    prepared_transaction.payload.as_slice(),
                                    pkey.as_bytes(),
                                );

                                //Create transaction id
                                let transaction_id = create_transaction_id(
                                    &nonce,
                                    identity.encode_to_vec().as_slice(),
                                );
                                let submit_request = SubmitRequest {
                                    transaction_id: transaction_id.clone(),
                                    channel_id: channel_name.clone(),
                                    prepared_transaction: Some(prepared_transaction),
                                };
                                match gateway_client.submit(submit_request).await {
                                    Ok(submit_request) => {
                                        println!("{:?}", submit_request.into_inner());
                                    }
                                    Err(err) => {
                                        unsafe {
                                            println!(
                                                "Error: {}\n {}",
                                                err.message(),
                                                String::from_utf8_unchecked(err.details().to_vec())
                                            );
                                        }

                                        panic!("{}", err.message())
                                    }
                                }
                            }
                            None => {
                                println!("None");
                            }
                        }
                    }
                    Err(err) => {
                        unsafe {
                            println!(
                                "Error: {}\n {}",
                                err.message(),
                                String::from_utf8_unchecked(err.details().to_vec())
                            );
                        }

                        panic!("{}", err.message())
                    }
                }
            });
    }
}
