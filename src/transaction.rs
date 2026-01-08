use prost::Message;

use crate::{
    error::BuilderError,
    fabric::{
        common::{ChannelHeader, Header, HeaderType, SignatureHeader},
        gateway::EndorseRequest,
        msp::SerializedIdentity,
        protos::{
            ChaincodeHeaderExtension, ChaincodeId, ChaincodeInput, ChaincodeInvocationSpec,
            ChaincodeMessage, ChaincodeProposalPayload, ChaincodeSpec, Proposal, SignedProposal,
        },
    },
    signer::Signer,
};

pub(crate) const NONCE_LENGTH: usize = 24;

/// A prepared transaction ready to be submitted to the network.
/// This struct is being used by the `submit_transaction()` from the client struct.
pub struct PreparedTransaction {
    pub(crate) channel_name: String,
    pub(crate) endorse_request: EndorseRequest,
}

/// A builder for creating `PreparedTransaction` instances, from which you can submit the transaction.
/// `build()` only prepares the transaction. It will not send anything to the network.
///
/// # Examples
///
/// ```rust
///  let tx_builder = client
///    .get_transaction_builder()
///    .with_channel_name("mychannel")?
///    .with_chaincode_id("basic")?
///    .with_function_name("CreateAsset")?
///    .with_function_args(["assetCustom", "orange", "10", "Frank", "600"])?
///    .build();
///  match tx_builder {
///    Ok(prepared_transaction) => match prepared_transaction.submit().await {
///        Ok(result) => {
///            println!("{}", String::from_utf8_lossy(result.as_slice()));
///        }
///        Err(err) => println!("{}", err),
///    },
///    Err(err) => println!("{}", err),
///  }
/// ```
pub struct TransaktionBuilder {
    pub(crate) identity: SerializedIdentity,
    pub(crate) signer: Signer,
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

impl TransaktionBuilder {
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
    ) -> Result<&mut TransaktionBuilder, BuilderError>
    where
        T: IntoIterator<Item = U>,
        U: AsRef<[u8]>,
    {
        for arg in args {
            self.function_args.push(arg.as_ref().into());
        }
        Ok(self)
    }
    ///Statically sets the proposal. If the propsal is none, the builder will generate a new one every time building a transaction
    pub fn with_proposal(&mut self, signed_proposal: Option<SignedProposal>) -> &mut Self {
        self.proposal = signed_proposal;
        self
    }
    ///Statically sets the header. If the header is none, the builder will generate a new one every time building a transaction
    pub fn with_herader(&mut self, signed_proposal: Option<SignedProposal>) -> &mut Self {
        self.proposal = signed_proposal;
        self
    }
    ///Statically sets the nonce. If the nonce is none, the builder will generate a new one every time building a transaction
    pub fn with_nonce(&mut self, nonce: Option<[u8; NONCE_LENGTH]>) -> &mut Self {
        self.nonce = nonce;
        self
    }
    ///Statically sets the transaction id. If the transaction id is none, the builder will generate a new one every time building a transaction
    pub fn with_transaction_id(&mut self, transaction_id: Option<String>) -> &mut Self {
        self.transaction_id = transaction_id;
        self
    }

    pub fn build(&self) -> Result<PreparedTransaction, BuilderError> {
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
    ) -> Result<PreparedTransaction, BuilderError> {
        let nonce = match self.nonce {
            Some(nonce) => nonce,
            None => generate_nonce(),
        };
        let transaction_id = match &self.transaction_id {
            Some(transaction_id) => transaction_id.clone(),
            None => generate_transaction_id(&nonce, self.identity.encode_to_vec().as_slice()),
        };
        let header = match &self.header {
            Some(header) => header.clone(),
            None => self.generate_header(&nonce, transaction_id.clone(), extension.clone()),
        };
        let signed_proposal = match &self.proposal {
            Some(proposal) => proposal.clone(),
            None => self.generate_proposal(&header, extension, payload),
        };
        let endorse_request = EndorseRequest {
            transaction_id,
            channel_id: self.channel_name.clone().unwrap_or_default(),
            proposed_transaction: Some(signed_proposal),
            endorsing_organizations: vec![], //Currently empty since private data is not implemented yet
        };
        Ok(PreparedTransaction {
            channel_name: self.channel_name.clone().unwrap_or_default(),
            endorse_request,
        })
    }
    ///Generates a message from a chaincode. This is only needed for the chaincode feature.
    /// This method neither requiers function name or function args
    /// Payload depends on the message type. For Register it is for example the ID of the chaincode
    pub(crate) fn generate_chaincode_message(
        &self,
        r#type: crate::fabric::protos::chaincode_message::Type,
        payload: Vec<u8>,
    ) -> Result<ChaincodeMessage, BuilderError> {
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
            None => generate_transaction_id(&nonce, self.identity.encode_to_vec().as_slice()),
        };
        let header = match &self.header {
            Some(header) => header.clone(),
            None => self.generate_header(&nonce, transaction_id.clone(), extension.encode_to_vec()),
        };
        let signed_proposal = match &self.proposal {
            Some(proposal) => proposal.clone(),
            None => self.generate_proposal(&header, extension.encode_to_vec(), payload),
        };

        Ok(ChaincodeMessage {
            r#type: r#type.into(),
            timestamp: Some(std::time::SystemTime::now().into()),
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
            creator: self.identity.encode_to_vec(),
            nonce: nonce.to_vec(),
        };

        let tls_cert_hash = generate_sha256_hash(self.identity.id_bytes.encode_to_vec().as_slice());

        let channel_header = ChannelHeader {
            r#type: HeaderType::EndorserTransaction.into(),
            version: 1, //I dunno
            timestamp: Some(std::time::SystemTime::now().into()),
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

        let signature = self.signer.sign_message(&proposal.encode_to_vec());

        SignedProposal {
            proposal_bytes: proposal.encode_to_vec(),
            signature,
        }
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
pub(crate) fn generate_transaction_id(nonce: &[u8], creator: &[u8]) -> String {
    let salted_creator = [nonce, creator].concat();
    let hash = openssl::sha::sha256(salted_creator.as_slice());
    hex::encode(hash)
}

pub(crate) fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; NONCE_LENGTH];
    openssl::rand::rand_bytes(&mut nonce).expect("Unable to generate random bytes");
    nonce
}

pub(crate) fn generate_sha256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()).unwrap();
    hasher.update(bytes).unwrap();
    hasher.finish().expect("Couldn't finalize hash").to_vec()
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
