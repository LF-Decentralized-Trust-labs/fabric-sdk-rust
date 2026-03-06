use std::str::FromStr;

use prost::Message;

use crate::{
    error::{BuilderError, SubmitError},
    fabric::{
        common::Payload,
        discovery::{QueryResult, discovery_client::DiscoveryClient},
        gateway::{
            CommitStatusRequest, CommitStatusResponse, SignedCommitStatusRequest, SubmitRequest,
            gateway_client::GatewayClient,
        },
        protos::{ChaincodeAction, ChaincodeActionPayload, ProposalResponsePayload, Transaction},
    },
    gateway::{
        chaincode::{ChaincodeCallBuilder, PreparedChaincodeCall},
        discovery::{DiscoveryCallBuilder, PreparedDiscoveryCall},
    },
    identity::Identity,
    transaction::{generate_nonce, generate_transaction_id},
};

pub struct Client {
    identity: Identity,
    tonic_connection: TonicConnection,
}

struct TonicConnection {
    tls_config: tonic::transport::ClientTlsConfig,
    host: tonic::transport::Uri,
    channel: Option<tonic::transport::Channel>,
}

impl Client {
    pub async fn connect(&mut self) -> Result<(), tonic::transport::Error> {
        self.tonic_connection.channel = Some(
            tonic::transport::Channel::builder(self.tonic_connection.host.clone())
                .tls_config(self.tonic_connection.tls_config.clone())
                .expect("Invald TLS config")
                .connect()
                .await?,
        );
        Ok(())
    }
    /// A builder for creating `PreparedTransaction` instances, from which you can submit the transaction.
    /// build() only prepares the transaction. It will not send anything to the network.
    ///
    /// # Examples
    ///
    /// ```rust
    ///  let tx_builder = client
    ///    .get_chaincode_builder()
    ///    .with_channel_name("mychannel")?
    ///    .with_chaincode_id("basic")?
    ///    .with_function_name("CreateAsset")?
    ///    .with_function_args(["assetCustom", "orange", "10", "Frank", "600"])?
    ///    .build();
    ///  match tx_builder {
    ///    Ok(prepared_transaction) => match client.submit_chaincode_call(prepared_transaction).await {
    ///        Ok(result) => {
    ///            println!("{}", String::from_utf8_lossy(result.as_slice()));
    ///        }
    ///        Err(err) => println!("{}", err),
    ///    },
    ///    Err(err) => println!("{}", err),
    ///  }
    /// ```
    pub fn get_chaincode_call_builder(&self) -> ChaincodeCallBuilder {
        ChaincodeCallBuilder {
            identity: self.identity.clone(),
            channel_name: None,
            chaincode_id: None,
            contract_id: None,
            function_name: None,
            function_args: vec![],
            proposal: None,
            header: None,
            nonce: None,
            transaction_id: None,
        }
    }

    pub fn get_discovery_call_builder(&self) -> DiscoveryCallBuilder {
        DiscoveryCallBuilder {
            identity: self.identity.clone(),
            queries: vec![],
        }
    }

    /// Submits a prepared transaction to the network. Changed will be transmitted to the orderer and the ledger will be affected from the chaincode call.
    pub async fn submit_chaincode_call(
        &self,
        prepared_chaincode_call: PreparedChaincodeCall,
    ) -> Result<Vec<u8>, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let mut gateway_client = GatewayClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        );
        //First transaction will be endorsed to the network
        let response = gateway_client
            .endorse(prepared_chaincode_call.endorse_request)
            .await;
        match response {
            Ok(response) => {
                match response.into_inner().prepared_transaction {
                    Some(mut envelope) => {
                        //TODO CHECK SIGNATURES

                        let mut result = vec![];

                        if let Ok(payload) = Payload::decode(envelope.payload.as_slice())
                            && let Ok(transaction) = Transaction::decode(payload.data.as_slice())
                        {
                            let mut payload_found = false;
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
                                    payload_found = true;
                                }
                            }
                            if !payload_found {
                                return Err(SubmitError::NoPayload);
                            }
                        }
                        //Generate random bytes for transaction id and signature header
                        let nonce = generate_nonce();

                        envelope.signature = self.identity.sign_message(&envelope.payload);

                        //Create transaction id
                        let transaction_id = generate_transaction_id(
                            &nonce,
                            self.identity
                                .get_certificate_bytes()
                                .encode_to_vec()
                                .as_slice(),
                        );
                        let submit_request = SubmitRequest {
                            transaction_id: transaction_id.clone(),
                            channel_id: prepared_chaincode_call.channel_name.clone(),
                            prepared_transaction: Some(envelope),
                        };
                        match gateway_client.submit(submit_request).await {
                            Ok(_) => Ok(result),
                            Err(err) => Err(SubmitError::NodeError(
                                String::from_utf8_lossy(err.details()).into_owned(),
                            )),
                        }
                    }
                    None => Err(SubmitError::EmptyRespone),
                }
            }
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }

    /// Executes a chaincode call and does not send it to an orderer, therefore not affecting the ledger. This is good for read-only calls
    pub async fn peek_chaincode_call(
        &self,
        prepared_chaincode_call: PreparedChaincodeCall,
    ) -> Result<Vec<u8>, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let mut gateway_client = GatewayClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        );
        //First transaction will be endorsed to the network
        let response = gateway_client
            .endorse(prepared_chaincode_call.endorse_request)
            .await;
        match response {
            Ok(response) => {
                match response.into_inner().prepared_transaction {
                    Some(envelope) => {
                        //TODO CHECK SIGNATURES

                        if let Ok(payload) = Payload::decode(envelope.payload.as_slice())
                            && let Ok(transaction) = Transaction::decode(payload.data.as_slice())
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
                                    return Ok(response.payload);
                                }
                            }
                        }
                        Err(SubmitError::NoPayload)
                    }
                    None => Err(SubmitError::EmptyRespone),
                }
            }
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }

    /// Discovery defines a service that serves information about the fabric network like which peers, orderers, chaincodes, etc.
    pub async fn submit_discover_call(
        &self,
        prepared_discovery_call: PreparedDiscoveryCall,
    ) -> Result<Vec<QueryResult>, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let mut discovery_client = DiscoveryClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        );
        let response = discovery_client
            .discover(prepared_discovery_call.request)
            .await;
        match response {
            Ok(response) => Ok(response.into_inner().results),
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }

    /// Checks for the commit status of a given transaction
    ///
    /// This method will run until the commit will occur if it hasn’t already committed. So only run this immidentialy after [`submit()`](submit).
    pub async fn commit_status(
        &self,
        transaction_id: String,
        channel_id: String,
    ) -> Result<CommitStatusResponse, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let request = CommitStatusRequest {
            transaction_id,
            channel_id,
            identity: self.identity.get_serialized_identity().encode_to_vec(),
        };
        let mut gateway_client = GatewayClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        );
        let request = SignedCommitStatusRequest {
            request: request.encode_to_vec(),
            signature: self.identity.sign_message(&request.encode_to_vec()),
        };
        let response = gateway_client.commit_status(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }

    /// Unimplemented.
    /// The ChaincodeEvents service supplies a stream of responses, each containing all the events emitted by the requested chaincode for a specific block. The streamed responses are ordered by ascending block number. Responses are only returned for blocks that contain the requested events, while blocks not containing any of the requested events are skipped.
    pub async fn chaincode_events(&self) {
        unimplemented!()
    }
}

/// The `ClientBuilder` struct is used to configure and build a `Client` instance. It provides methods to set various parameters required for creating a client, such as identity, signer, TLS configuration, scheme, and authority.
///
/// # Examples
///
/// ```rust
///  use fabric_sdk_rust::{client::ClientBuilder, identity::IdentityBuilder, signer::Signer};
///
///  let identity = IdentityBuilder::from_pem(std::fs::read(msp_signcert_path)?.as_slice())
///    .with_msp("Org1MSP")?
///    .build()?;
///  let mut client = ClientBuilder::new()
///    .with_identity(identity)?
///    .with_tls(tlsca_bytes)?
///    .with_sheme("https")?
///    .with_authority("localhost:7051")?
///    .build()?;
///  client.connect().await?;
/// ```
#[derive(Default)]
pub struct ClientBuilder {
    identity: Option<Identity>,
    tls: Option<Vec<u8>>,
    scheme: Option<String>,
    authority: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Identity from the IdentityBuilder
    /// # Example
    /// ```rust
    ///use fabric_sdk_rust::{client::ClientBuilder, identity::IdentityBuilder, signer::Signer};
    ///
    ///let identity = IdentityBuilder::from_pem(pem_bytes)
    ///    .with_msp("Org1MSP")?
    ///    .build()?;
    ///
    ///let mut client = ClientBuilder::new()
    ///    .with_identity(identity)?;
    pub fn with_identity(mut self, identity: Identity) -> Result<ClientBuilder, BuilderError> {
        self.identity = Some(identity);
        Ok(self)
    }

    /// Chooses which scheme is being used. Default value is `https`
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Result<ClientBuilder, BuilderError> {
        let scheme = scheme.into().trim().to_string();
        if scheme.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "scheme cannot be empty".into(),
            ));
        }
        self.scheme = Some(scheme);
        Ok(self)
    }
    /// Tls for the grpc connection to the node.
    /// The needed pem from the test network can be found here: `organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem`
    pub fn with_tls(mut self, bytes: impl Into<Vec<u8>>) -> Result<ClientBuilder, BuilderError> {
        self.tls = Some(bytes.into());
        Ok(self)
    }
    /// Authority for the grpc connection to the node. Default is `localhost:7051` which corresponds to the test network
    pub fn with_authority(
        mut self,
        authority: impl Into<String>,
    ) -> Result<ClientBuilder, BuilderError> {
        let authority = authority.into().trim().to_string();
        if authority.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "authority cannot be empty".into(),
            ));
        }
        self.authority = Some(authority);
        Ok(self)
    }
    /// Collects and validates the values from the builder to build the client. Building does not start the connection to the node.
    pub fn build(self) -> Result<Client, BuilderError> {
        let identity = match self.identity {
            Some(identity) => identity,
            None => return Err(BuilderError::MissingParameter("identity".into())),
        };
        let tls = match self.tls {
            Some(tls) => tls,
            None => return Err(BuilderError::MissingParameter("tls".into())),
        };
        //TODO Allow custom tls config
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(tls.as_slice()));
        let scheme = match self.scheme {
            Some(scheme) => scheme,
            None => "https".to_string(),
        };
        let authority = match self.authority {
            Some(authority) => authority,
            None => "localhost:7051".to_string(),
        };
        let scheme =
            tonic::codegen::http::uri::Scheme::from_str(scheme.as_str()).expect("Invalid scheme");
        let uri_builder = tonic::transport::Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query("/");
        let uri = match uri_builder.build() {
            Ok(uri) => uri,
            Err(err) => return Err(BuilderError::InvalidParameter(err.to_string())),
        };
        let tonic_connection = TonicConnection {
            tls_config,
            host: uri,
            channel: None,
        };
        Ok(Client {
            identity,
            tonic_connection,
        })
    }
}
