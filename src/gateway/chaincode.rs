use prost::Message;

use crate::{
    error::BuilderError,
    fabric::{
        common::{ChannelHeader, Header, HeaderType, SignatureHeader},
        protos::{
            ChaincodeHeaderExtension, ChaincodeId, ChaincodeInput, ChaincodeInvocationSpec,
            ChaincodeProposalPayload, ChaincodeSpec, Proposal, SignedProposal,
        },
    },
    identity::Identity,
    implement::crypto::{NONCE_LENGTH, generate_nonce, generate_transaction_id},
};

pub struct ChaincodeCallBuilder {
    pub(crate) identity: Identity,
    pub(crate) channel_name: Option<String>,
    pub(crate) chaincode_id: Option<String>,
    pub(crate) contract_id: Option<String>,
    pub(crate) function_name: Option<String>,
    pub(crate) function_args: Vec<Vec<u8>>,
    pub(crate) proposal: Option<SignedProposal>,
    pub(crate) header: Option<Header>,
    pub(crate) nonce: Option<[u8; NONCE_LENGTH]>,
    pub(crate) transaction_id: Option<String>,
}
impl ChaincodeCallBuilder {
    pub fn with_channel_name(
        &mut self,
        name: impl Into<String>,
    ) -> Result<&mut Self, BuilderError> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "name cannot be empty".into(),
            ));
        }
        self.channel_name = Some(name);
        Ok(self)
    }

    pub fn with_chaincode_id(&mut self, id: impl Into<String>) -> Result<&mut Self, BuilderError> {
        let id = id.into().trim().to_string();
        if id.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "chaincode id cannot be empty".into(),
            ));
        }
        self.chaincode_id = Some(id);
        Ok(self)
    }

    pub fn with_contract_id(&mut self, id: impl Into<String>) -> Result<&mut Self, BuilderError> {
        let id = id.into().trim().to_string();
        if id.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "contract id cannot be empty".into(),
            ));
        }
        self.contract_id = Some(id);
        Ok(self)
    }

    pub fn with_function_name(
        &mut self,
        name: impl Into<String>,
    ) -> Result<&mut Self, BuilderError> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "name cannot be empty".into(),
            ));
        }
        self.function_name = Some(name);
        Ok(self)
    }

    pub fn with_function_args<T, U>(
        &mut self,
        args: T,
    ) -> Result<&mut ChaincodeCallBuilder, BuilderError>
    where
        T: IntoIterator<Item = U>,
        U: AsRef<[u8]>,
    {
        for arg in args {
            self.function_args.push(arg.as_ref().into());
        }
        Ok(self)
    }
    /// Statically sets the proposal. If the propsal is none, the builder will generate a new one every time building a transaction
    pub fn with_proposal(&mut self, signed_proposal: Option<SignedProposal>) -> &mut Self {
        self.proposal = signed_proposal;
        self
    }
    /// Statically sets the header. If the header is none, the builder will generate a new one every time building a transaction
    pub fn with_header(&mut self, signed_proposal: Option<SignedProposal>) -> &mut Self {
        self.proposal = signed_proposal;
        self
    }
    /// Statically sets the nonce. If the nonce is none, the builder will generate a new one every time building a transaction
    pub fn with_nonce(&mut self, nonce: Option<[u8; NONCE_LENGTH]>) -> &mut Self {
        self.nonce = nonce;
        self
    }
    /// Statically sets the transaction id. If the transaction id is none, the builder will generate a new one every time building a transaction
    pub fn with_transaction_id(&mut self, transaction_id: Option<String>) -> &mut Self {
        self.transaction_id = transaction_id;
        self
    }

    pub fn build(&self) -> Result<SignedProposal, BuilderError> {
        if self.chaincode_id.is_none() {
            return Err(BuilderError::MissingParameter("chaincode_id".into()));
        }
        if self.function_name.is_none() {
            return Err(BuilderError::MissingParameter("function_name".into()));
        }

        let chaincode_id = ChaincodeId {
            name: self
                .chaincode_id
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
            ..Default::default()
        };

        let chaincode_proposal_payload = generate_chaincode_definition(
            chaincode_id.clone(),
            self.contract_id.clone(),
            self.function_name
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
            self.function_args.clone(),
        );

        let chaincode_header_extension = ChaincodeHeaderExtension {
            chaincode_id: Some(chaincode_id.clone()),
        };

        self.generate_transaction(
            chaincode_header_extension.encode_to_vec(),
            chaincode_proposal_payload.encode_to_vec(),
        )
    }
    ///Generates the prepared transaction with the given extension and payload. If you want to do an basic chaincode call use `build()` instead.
    pub fn generate_transaction(
        &self,
        extension: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<SignedProposal, BuilderError> {
        let nonce = match self.nonce {
            Some(nonce) => nonce,
            None => generate_nonce(),
        };
        let transaction_id = match &self.transaction_id {
            Some(transaction_id) => transaction_id.clone(),
            None => generate_transaction_id(
                &nonce,
                self.identity
                    .get_serialized_identity()
                    .encode_to_vec()
                    .as_slice(),
            ),
        };
        let header = match &self.header {
            Some(header) => header.clone(),
            None => self.generate_header(&nonce, transaction_id.clone(), extension.clone()),
        };
        let signed_proposal = match &self.proposal {
            Some(proposal) => proposal.clone(),
            None => self.generate_proposal(&header, extension, payload),
        };
        Ok(signed_proposal)
    }
    ///Generates a message from a chaincode. This is only needed for the chaincode feature.
    /// This method neither requiers function name or function args
    /// Payload depends on the message type. For Register it is for example the ID of the chaincode
    #[cfg(feature = "chaincode")]
    pub(crate) fn generate_chaincode_message(
        &self,
        r#type: crate::fabric::protos::chaincode_message::Type,
        payload: Vec<u8>,
    ) -> Result<crate::fabric::protos::ChaincodeMessage, BuilderError> {
        if self.chaincode_id.is_none() {
            return Err(BuilderError::MissingParameter("chaincode_id".into()));
        }
        let chaincode_id = ChaincodeId {
            name: self
                .chaincode_id
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
            ..Default::default()
        };
        let extension = ChaincodeHeaderExtension {
            chaincode_id: Some(chaincode_id.clone()),
        };
        let nonce = match self.nonce {
            Some(nonce) => nonce,
            None => generate_nonce(),
        };
        let transaction_id = match &self.transaction_id {
            Some(transaction_id) => transaction_id.clone(),
            None => generate_transaction_id(
                &nonce,
                self.identity
                    .get_serialized_identity()
                    .encode_to_vec()
                    .as_slice(),
            ),
        };
        let header = match &self.header {
            Some(header) => header.clone(),
            None => self.generate_header(&nonce, transaction_id.clone(), extension.encode_to_vec()),
        };
        let signed_proposal = match &self.proposal {
            Some(proposal) => proposal.clone(),
            None => self.generate_proposal(&header, extension.encode_to_vec(), payload),
        };
        Ok(crate::fabric::protos::ChaincodeMessage {
            r#type: r#type.into(),
            timestamp: Some({
                #[cfg(feature = "client-wasm")]
                {
                    crate::fabric::google_protobuf::Timestamp {
                        seconds: web_time::SystemTime::now()
                            .duration_since(web_time::SystemTime::UNIX_EPOCH)
                            .expect("Invalid duration calc")
                            .as_secs() as i64,
                        nanos: 0,
                    }
                }
                #[cfg(not(feature = "client-wasm"))]
                {
                    std::time::SystemTime::now().into()
                }
            }),
            payload: chaincode_id.encode_to_vec(),
            txid: transaction_id,
            proposal: Some(signed_proposal),
            chaincode_event: None,
            channel_id: self.channel_name.clone().unwrap_or_default(),
        })
    }
    pub(crate) fn generate_header(
        &self,
        nonce: &[u8],
        transaction_id: String,
        extension: Vec<u8>,
    ) -> Header {
        let signature_header = SignatureHeader {
            creator: self.identity.get_serialized_identity().encode_to_vec(),
            nonce: nonce.to_vec(),
        };

        let tls_cert_hash = self.identity.generate_tls_cert_hash();

        let channel_header = ChannelHeader {
            r#type: HeaderType::EndorserTransaction.into(),
            version: 1, //I dunno
            timestamp: Some({
                #[cfg(feature = "client-wasm")]
                {
                    crate::fabric::google_protobuf::Timestamp {
                        seconds: web_time::SystemTime::now()
                            .duration_since(web_time::SystemTime::UNIX_EPOCH)
                            .expect("Invalid duration calc")
                            .as_secs() as i64,
                        nanos: 0,
                    }
                }
                #[cfg(not(feature = "client-wasm"))]
                {
                    std::time::SystemTime::now().into()
                }
            }),
            channel_id: self
                .channel_name
                .as_ref()
                .unwrap_or(&String::default())
                .clone(), // On the test network it will be myChannel
            tx_id: transaction_id.clone(),
            epoch: 0, // The epoch in which this header was generated, where epoch is defined based on block height
            extension: extension.clone(), // Extension that may be attached based on the header type
            tls_cert_hash, // If mutual TLS is employed, this represents the hash of the client's TLS certificate
        };

        Header {
            channel_header: channel_header.encode_to_vec(),
            signature_header: signature_header.encode_to_vec(),
        }
    }
    pub(crate) fn generate_proposal(
        &self,
        header: &Header,
        extension: Vec<u8>,
        payload: Vec<u8>,
    ) -> SignedProposal {
        let proposal = Proposal {
            header: Message::encode_to_vec(header),
            payload,
            // Optional extensions to the proposal. Its content depends on the Header's
            // type field.  For the type CHAINCODE, it might be the bytes of a
            // ChaincodeAction message.
            extension,
        };

        let signature = self.identity.sign_message(&proposal.encode_to_vec());

        SignedProposal {
            proposal_bytes: proposal.encode_to_vec(),
            signature,
        }
    }
}

pub(crate) fn generate_chaincode_definition(
    chaincode_id: ChaincodeId,
    contract_id: Option<String>,
    function_name: String,
    function_args: Vec<Vec<u8>>,
) -> ChaincodeProposalPayload {
    let mut args = if let Some(contract_id) = contract_id {
        vec![
            format!("{}:{}", contract_id, function_name)
                .as_bytes()
                .to_vec(),
        ]
    } else {
        vec![function_name.as_bytes().to_vec()]
    };
    for function_arg in function_args {
        args.push(function_arg);
    }
    let chaincode_input = ChaincodeInput {
        args,
        decorations: std::collections::HashMap::default(), //TODO Chaincode decorations
        is_init: false,
    };

    let chaincode_spec = ChaincodeSpec {
        r#type: crate::fabric::protos::chaincode_spec::Type::Golang.into(),
        chaincode_id: Some(chaincode_id),
        input: Some(chaincode_input),
        timeout: 10,
    };

    let chaincode_invokation_spec = ChaincodeInvocationSpec {
        chaincode_spec: Some(chaincode_spec),
    };

    ChaincodeProposalPayload {
        input: chaincode_invokation_spec.encode_to_vec(),
        transient_map: std::collections::HashMap::default(),
    }
}
