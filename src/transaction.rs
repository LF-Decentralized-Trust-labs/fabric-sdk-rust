use prost::Message;

use crate::{
    error::BuilderError,
    protos::{
        common::Payload,
        protos::{
            ChaincodeAction, ChaincodeActionPayload, ProposalResponsePayload
        },
    },
    signer::Signer,
};

pub(crate) const NONCE_LENGTH: usize = 24;

pub struct PreparedTransaction {
    pub(crate) identity: crate::protos::msp::SerializedIdentity,
    pub(crate) signer: Signer,
    pub(crate) channel_name: String,
    pub(crate) channel: tonic::transport::Channel,
    endorse_request: crate::protos::gateway::EndorseRequest,
}

impl PreparedTransaction {
    pub async fn submit(&self) -> Result<Vec<u8>, String> {
        let mut gateway_client =
            crate::protos::gateway::gateway_client::GatewayClient::new(self.channel.clone());
        //First transaction will be endorsed to the network
        let response = gateway_client.endorse(self.endorse_request.clone()).await;
        match response {
            Ok(response) => {
                match response.into_inner().prepared_transaction {
                    Some(mut envelope) => {
                        //TODO CHECK SIGNATURES

                        let mut result = vec![];
                        //TODO Error handling

                        if let Ok(payload) = Payload::decode(envelope.payload.as_slice())
                            && let Ok(transaction) =
                                crate::protos::protos::Transaction::decode(payload.data.as_slice())
                        {
                            for action in transaction.actions {
                                if let Ok(action) =
                                    ChaincodeActionPayload::decode(action.payload.as_slice())
                                    && let Some(action) = action.action
                                    && let Ok(payload) = ProposalResponsePayload::decode(
                                        action.proposal_response_payload.as_slice(),
                                    )
                                    && let Ok(action) =
                                        ChaincodeAction::decode(payload.extension.as_slice())
                                    && let Some(response) = action.response
                                {
                                    result = response.payload;
                                }
                            }
                        }
                        //Generate random bytes for transaction id and signature header
                        let mut nonce = [0u8; NONCE_LENGTH];
                        openssl::rand::rand_bytes(&mut nonce)
                            .expect("Unable to generate random bytes");

                        envelope.signature =
                            sign_message(envelope.payload.as_slice(), self.signer.pkey.as_slice());

                        //Create transaction id
                        let transaction_id =
                            create_transaction_id(&nonce, self.identity.encode_to_vec().as_slice());
                        let submit_request = crate::protos::gateway::SubmitRequest {
                            transaction_id: transaction_id.clone(),
                            channel_id: self.channel_name.clone(),
                            prepared_transaction: Some(envelope),
                        };
                        match gateway_client.submit(submit_request).await {
                            Ok(_) => Ok(result),
                            Err(err) => Err(err.message().to_string()),
                        }
                    }
                    None => Err("None".into()),
                }
            }
            Err(err) => Err(err.message().to_string()),
        }
    }
}

pub struct TransaktionBuilder {
    pub(crate) identity: crate::protos::msp::SerializedIdentity,
    pub(crate) channel: tonic::transport::Channel,
    pub(crate) signer: Signer,
    pub(crate) channel_name: Option<String>,
    pub(crate) chaincode_id: Option<String>,
    pub(crate) function_name: Option<String>,
    pub(crate) function_args: Vec<String>,
}

impl TransaktionBuilder {
    pub fn with_channel_name(
        mut self,
        name: impl Into<String>,
    ) -> Result<TransaktionBuilder, BuilderError> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "name cannot be empty".into(),
            ));
        }
        self.channel_name = Some(name);
        Ok(self)
    }

    pub fn with_chaincode_id(
        mut self,
        id: impl Into<String>,
    ) -> Result<TransaktionBuilder, BuilderError> {
        let id = id.into().trim().to_string();
        if id.is_empty() {
            return Err(BuilderError::InvalidParameter("id cannot be empty".into()));
        }
        self.chaincode_id = Some(id);
        Ok(self)
    }

    pub fn with_function_name(
        mut self,
        name: impl Into<String>,
    ) -> Result<TransaktionBuilder, BuilderError> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "name cannot be empty".into(),
            ));
        }
        self.function_name = Some(name);
        Ok(self)
    }

    pub fn with_function_args(
        mut self,
        args: Vec<String>,
    ) -> Result<TransaktionBuilder, BuilderError> {
        self.function_args = args;
        Ok(self)
    }

    pub fn build(self) -> Result<PreparedTransaction, BuilderError> {
        let channel_name = match self.channel_name {
            Some(channel_name) => channel_name,
            None => return Err(BuilderError::MissingParameter("channel_name".into())),
        };
        let chaincode_id = match self.chaincode_id {
            Some(chaincode_id) => chaincode_id,
            None => return Err(BuilderError::MissingParameter("chaincode_id".into())),
        };
        let function_name = match self.function_name {
            Some(function_name) => function_name,
            None => return Err(BuilderError::MissingParameter("function_name".into())),
        };
        let function_args = self.function_args;

        let identity = self.identity;

        //Create signature header
        let mut nonce = [0u8; NONCE_LENGTH];
        openssl::rand::rand_bytes(&mut nonce).expect("Unable to generate random bytes");
        let transaction_id = create_transaction_id(&nonce, identity.encode_to_vec().as_slice());

        let signature_header = crate::protos::common::SignatureHeader {
            creator: identity.encode_to_vec(),
            nonce: nonce.to_vec(),
        };

        let mut hasher =
            openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()).unwrap();
        hasher
            .update(identity.id_bytes.encode_to_vec().as_slice())
            .unwrap();
        let tls_cert_hash = hasher.finish().expect("Couldn't finalize hash").to_vec();

        let chaincode_id = crate::protos::protos::ChaincodeId {
            path: String::default(),
            name: chaincode_id.clone(),
            version: "1.0".into(),
        };

        let chaincode_header_expansion = crate::protos::protos::ChaincodeHeaderExtension {
            chaincode_id: Some(chaincode_id.clone()),
        };

        let channel_header = crate::protos::common::ChannelHeader {
            r#type: crate::protos::common::HeaderType::EndorserTransaction.into(),
            version: 1, //I dunno
            timestamp: Some(std::time::SystemTime::now().into()),
            channel_id: channel_name.clone(), // On the test network it will be myChannel
            tx_id: transaction_id.clone(),
            epoch: 0, // The epoch in which this header was generated, where epoch is defined based on block height
            extension: chaincode_header_expansion.encode_to_vec(), // Extension that may be attached based on the header type
            tls_cert_hash, // If mutual TLS is employed, this represents the hash of the client's TLS certificate
        };

        let chaincode_input = crate::protos::protos::ChaincodeInput {
            args: vec![function_name.as_bytes().to_vec()], //TODO Chaincode args
            decorations: std::collections::HashMap::default(), //TODO Chaincode decorations
            is_init: false,
        };

        let chaincode_spec = crate::protos::protos::ChaincodeSpec {
            r#type: crate::protos::protos::chaincode_spec::Type::Golang.into(),
            chaincode_id: Some(chaincode_id.clone()),
            input: Some(chaincode_input),
            timeout: 10,
        };

        let chaincode_invokation_spec = crate::protos::protos::ChaincodeInvocationSpec {
            chaincode_spec: Some(chaincode_spec),
        };

        let chaincode_poposal_payload = crate::protos::protos::ChaincodeProposalPayload {
            input: chaincode_invokation_spec.encode_to_vec(),
            transient_map: std::collections::HashMap::default(),
        };

        let header = crate::protos::common::Header {
            channel_header: channel_header.encode_to_vec(),
            signature_header: signature_header.encode_to_vec(),
        };

        let proposal = crate::protos::protos::Proposal {
            header: Message::encode_to_vec(&header),
            payload: chaincode_poposal_payload.encode_to_vec(),
            // Optional extensions to the proposal. Its content depends on the Header's
            // type field.  For the type CHAINCODE, it might be the bytes of a
            // ChaincodeAction message.
            extension: chaincode_header_expansion.encode_to_vec(),
        };

        let signature = sign_message(&proposal.encode_to_vec(), self.signer.pkey.as_slice());

        let signed_proposal = crate::protos::protos::SignedProposal {
            proposal_bytes: proposal.encode_to_vec(),
            signature,
        };

        let proposed_transaction = crate::protos::gateway::ProposedTransaction {
            transaction_id,
            proposal: Some(signed_proposal),
            endorsing_organizations: vec![], //Currently empty since private data is not implemented yet
        };

        let endorse_request = crate::protos::gateway::EndorseRequest {
            transaction_id: proposed_transaction.transaction_id,
            channel_id: channel_name.clone(), // On the test network it will be myChannel
            proposed_transaction: proposed_transaction.proposal,
            endorsing_organizations: proposed_transaction.endorsing_organizations,
        };

        Ok(PreparedTransaction {
            identity,
            channel: self.channel,
            signer: self.signer,
            channel_name,
            endorse_request,
        })
    }
}

/// Creates a unique transaction ID by concatenating a nonce with an identity and then hashing the result.
///
/// # Arguments
/// * `nonce` - A byte slice representing a random nonce.
/// * `creator` - A byte slice representing the identity of the creator in serialized format.
///
/// # Returns
/// A string representing the hashed transaction ID, encoded in hexadecimal format.
fn create_transaction_id(nonce: &[u8], creator: &[u8]) -> String {
    let salted_creator = [nonce, creator].concat();
    let hash = openssl::sha::sha256(salted_creator.as_slice());
    hex::encode(hash)
}

fn sign_message(message: &[u8], pem_bytes: &[u8]) -> Vec<u8> {
    use p256::pkcs8::der::Encode;

    let ec_key = openssl::ec::EcKey::private_key_from_pem(pem_bytes).unwrap();

    let mut hasher = openssl::sha::Sha256::new();
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
