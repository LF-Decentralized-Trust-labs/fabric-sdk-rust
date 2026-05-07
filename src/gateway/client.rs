#[allow(unused_imports)]
use crate::{
    error::{BuilderError, SubmitError},
    fabric::{
        common::Payload,
        discovery::{QueryResult, discovery_client::DiscoveryClient},
        gateway::{
            ChaincodeEventsRequest, CommitStatusRequest, CommitStatusResponse, EvaluateRequest,
            EvaluateResponse, SignedChaincodeEventsRequest, SignedCommitStatusRequest,
            SubmitRequest, gateway_client::GatewayClient,
        },
        orderer::{SeekPosition, SeekSpecified},
        protos::{
            ChaincodeAction, ChaincodeActionPayload, ProposalResponse, ProposalResponsePayload,
            SignedProposal, Transaction, endorser_client::EndorserClient,
        },
    },
    gateway::{
        chaincode::ChaincodeCallBuilder,
        discovery::{DiscoveryCallBuilder, PreparedDiscoveryCall},
        snapshot,
    },
    identity::Identity,
    implement::crypto::{generate_nonce, generate_transaction_id},
};
use prost::Message;

pub struct Client {
    pub(crate) identity: Identity,
    pub(crate) tonic_connection: TonicConnection,
}

#[cfg(feature = "client-wasm")]
pub(crate) struct TonicConnection {
    pub(crate) host: String,
    pub(crate) channel: Option<tonic_web_wasm_client::Client>,
}

#[cfg(not(feature = "client-wasm"))]
pub(crate) struct TonicConnection {
    pub(crate) tls_config: tonic::transport::ClientTlsConfig,
    pub(crate) host: tonic::transport::Uri,
    pub(crate) channel: Option<tonic::transport::Channel>,
}

impl Client {
    pub(crate) fn create_gateway(&self) -> GatewayClient<tonic::transport::Channel> {
        GatewayClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        )
    }

    #[cfg(not(feature = "client-wasm"))]
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

    #[cfg(feature = "client-wasm")]
    pub async fn connect(&mut self) {
        let client =
            tonic_web_wasm_client::Client::new(self.tonic_connection.host.clone().to_string());
        self.tonic_connection.channel = Some(client);
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
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }

    /// Checks for the commit status of a given transaction
    ///
    /// This method will run until the commit will occur if it hasn’t already committed. So only run this if you expect the transaction. To check the commit status from a self sended transaction, use [wait_for_commit](crate::implement::envelope::wait_for_commit) instead.
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
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }

    /// Evaluates a transaction (query) without updating the ledger.
    /// This method passes a proposed transaction to the gateway in order to invoke the
    /// transaction function and return the result to the client. No ledger updates are made.
    pub async fn evaluate(
        &self,
        signed_proposal: SignedProposal,
        transaction_id: String,
        channel_id: String,
    ) -> Result<Vec<u8>, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }

        let request = EvaluateRequest {
            transaction_id,
            channel_id,
            proposed_transaction: Some(signed_proposal),
            target_organizations: vec![], // Currently empty since private data is not implemented yet
        };

        let mut gateway_client = GatewayClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        );

        let response = gateway_client.evaluate(request).await;
        match response {
            Ok(response) => {
                let inner = response.into_inner();
                match inner.result {
                    Some(result) => {
                        if result.status != 200 {
                            Err(SubmitError::NodeError(result.message))
                        } else {
                            Ok(result.payload)
                        }
                    }
                    None => Err(SubmitError::NoPayload),
                }
            }
            Err(err) => Err(SubmitError::NodeError(
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }

    pub fn get_chaincode_events_request_builder(&self) -> ChaincodeEventsRequestBuilder {
        ChaincodeEventsRequestBuilder::new(self.identity.clone())
    }

    /// The ChaincodeEvents service supplies a stream of responses, each containing all the events emitted by the requested chaincode for a specific block. The streamed responses are ordered by ascending block number.
    /// Responses are only returned for blocks that contain the requested events, while blocks not containing any of the requested events are skipped.
    pub async fn chaincode_events(
        &self,
        request: SignedChaincodeEventsRequest,
    ) -> Result<tonic::Streaming<crate::fabric::gateway::ChaincodeEventsResponse>, SubmitError>
    {
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

        match gateway_client.chaincode_events(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(&err.details()).into_owned(),
            )),
        }
    }

    /// Creates a [`LifecycleClient`] for managing chaincode lifecycle operations
    /// (install, approve, commit, and query) on this peer connection.
    pub fn get_lifecycle_client(&self) -> crate::gateway::lifecycle::LifecycleClient<'_> {
        crate::gateway::lifecycle::LifecycleClient::new(self)
    }

    /// Sends a signed proposal directly to the peer's legacy `Endorser.ProcessProposal` RPC.
    ///
    /// Used for channel-less lifecycle operations (e.g. install chaincode) that cannot
    /// go through the Gateway API, which requires a valid channel ID.
    pub async fn process_proposal(
        &self,
        signed_proposal: SignedProposal,
    ) -> Result<ProposalResponse, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let mut endorser_client = EndorserClient::new(
            self.tonic_connection
                .channel
                .as_ref()
                .expect("Expected value is none.")
                .clone(),
        )
        .max_encoding_message_size(usize::MAX)
        .max_decoding_message_size(usize::MAX);
        match endorser_client.process_proposal(signed_proposal).await {
            Ok(response) => Ok(response.into_inner()),
            Err(err) => Err(SubmitError::NodeError(
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }

    /// Creates a new SnapshotClientWrapper for interacting with the Snapshot service.
    /// The channel must be connected before calling this method.
    #[cfg(not(feature = "client-wasm"))]
    pub fn create_snapshot_client(&self) -> Result<snapshot::SnapshotClientWrapper, SubmitError> {
        if self.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let channel = self
            .tonic_connection
            .channel
            .as_ref()
            .expect("Expected value is none.")
            .clone();
        Ok(snapshot::SnapshotClientWrapper::new(channel))
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
    path: Option<String>,
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

    /// Adds a url path to the request
    /// Default is `/`
    ///
    /// Paths should lead with `/`
    pub fn with_path(mut self, path: String) -> Result<ClientBuilder, BuilderError> {
        self.path = Some(path);
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
    #[cfg(not(feature = "client-wasm"))]
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

        #[cfg(not(feature = "client-wasm"))]
        let (uri, tls_config) = {
            use std::str::FromStr;

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
            let scheme = tonic::codegen::http::uri::Scheme::from_str(scheme.as_str())
                .expect("Invalid scheme");
            let uri_builder = tonic::transport::Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(self.path.unwrap_or("/".to_string()).as_str());
            match uri_builder.build() {
                Ok(uri) => (uri, tls_config),
                Err(err) => return Err(BuilderError::InvalidParameter(err.to_string())),
            }
        };
        #[cfg(feature = "client-wasm")]
        let uri = {
            let scheme = match self.scheme {
                Some(scheme) => scheme,
                None => "https".to_string(),
            };
            let authority = match self.authority {
                Some(authority) => authority,
                None => "localhost:7051".to_string(),
            };
            format!("{scheme}://{authority}{}", self.path.unwrap_or_default())
        };

        #[cfg(feature = "client-wasm")]
        let tonic_connection = TonicConnection {
            host: uri.to_string(),
            channel: None,
        };

        #[cfg(not(feature = "client-wasm"))]
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

pub struct ChaincodeEventsRequestBuilder {
    identity: Identity,
    channel_id: Option<String>,
    chaincode_id: Option<String>,
    start_block: Option<u64>,
    after_transaction_id: Option<String>,
}

impl ChaincodeEventsRequestBuilder {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            channel_id: None,
            chaincode_id: None,
            start_block: None,
            after_transaction_id: None,
        }
    }

    pub fn with_channel_id(mut self, channel_id: impl Into<String>) -> Result<Self, BuilderError> {
        self.channel_id = Some(validate_non_empty(channel_id, "channel_id")?);
        Ok(self)
    }

    pub fn with_chaincode_id(
        mut self,
        chaincode_id: impl Into<String>,
    ) -> Result<Self, BuilderError> {
        self.chaincode_id = Some(validate_non_empty(chaincode_id, "chaincode_id")?);
        Ok(self)
    }

    pub fn with_start_block(mut self, start_block: u64) -> Self {
        self.start_block = Some(start_block);
        self
    }

    pub fn with_after_transaction_id(mut self, transaction_id: impl Into<String>) -> Self {
        self.after_transaction_id = Some(transaction_id.into());
        self
    }

    pub fn build(
        self,
    ) -> Result<crate::fabric::gateway::SignedChaincodeEventsRequest, BuilderError> {
        let channel_id = self
            .channel_id
            .ok_or_else(|| BuilderError::MissingParameter("channel_id".into()))?;

        let chaincode_id = self
            .chaincode_id
            .ok_or_else(|| BuilderError::MissingParameter("chaincode_id".into()))?;

        let identity_bytes = self.identity.get_serialized_identity().encode_to_vec();

        let start_position = self.start_block.map(|block_number| SeekPosition {
            r#type: Some(crate::fabric::orderer::seek_position::Type::Specified(
                SeekSpecified {
                    number: block_number,
                },
            )),
        });

        let request = ChaincodeEventsRequest {
            channel_id,
            chaincode_id,
            identity: identity_bytes,
            start_position,
            after_transaction_id: self.after_transaction_id.unwrap_or_default(),
        };

        let request_bytes = request.encode_to_vec();
        let signature = self.identity.sign_message(&request_bytes);

        Ok(crate::fabric::gateway::SignedChaincodeEventsRequest {
            request: request_bytes,
            signature,
        })
    }
}

fn validate_non_empty(value: impl Into<String>, field: &str) -> Result<String, BuilderError> {
    let value = value.into().trim().to_string();

    if value.is_empty() {
        Err(BuilderError::InvalidParameter(format!(
            "{} cannot be empty",
            field
        )))
    } else {
        Ok(value)
    }
}
