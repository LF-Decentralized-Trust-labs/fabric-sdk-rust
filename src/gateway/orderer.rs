//! Client for the orderer's `orderer.AtomicBroadcast` service.
//!
//! Native-only (not available under the `client-wasm` feature): the orderer
//! endpoints speak plain gRPC over TLS, which browsers cannot open directly.
//!
//! [`OrdererClient::broadcast`] submits an [`Envelope`] (e.g. a signed
//! `CONFIG_UPDATE` transaction built with
//! [`configtx::build_config_update_transaction`](crate::gateway::configtx::build_config_update_transaction))
//! for ordering. [`OrdererClient::fetch_block`] retrieves a block from a
//! channel via the Deliver service.

use prost::Message;

use crate::{
    error::{BuilderError, SubmitError},
    fabric::{
        common::{
            Block, ChannelHeader, Envelope, Header, HeaderType, Payload, SignatureHeader, Status,
        },
        orderer::{
            BroadcastResponse, DeliverResponse, SeekInfo, SeekNewest, SeekOldest, SeekPosition,
            SeekSpecified, atomic_broadcast_client::AtomicBroadcastClient, deliver_response,
            seek_position,
        },
    },
    identity::Identity,
    implement::crypto::{generate_nonce, generate_transaction_id},
};

/// The block to request from the orderer's Deliver service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockPosition {
    /// The newest (highest) block currently committed on the channel.
    Newest,
    /// The oldest available block (the genesis block, unless pruned).
    Oldest,
    /// The block with the given number.
    Specified(u64),
}

impl BlockPosition {
    fn to_seek_position(self) -> SeekPosition {
        SeekPosition {
            r#type: Some(match self {
                BlockPosition::Newest => seek_position::Type::Newest(SeekNewest {}),
                BlockPosition::Oldest => seek_position::Type::Oldest(SeekOldest {}),
                BlockPosition::Specified(number) => {
                    seek_position::Type::Specified(SeekSpecified { number })
                }
            }),
        }
    }
}

/// Client for the orderer's `AtomicBroadcast` service (Broadcast + Deliver).
///
/// Build with [`OrdererClientBuilder`] and call [`connect`](Self::connect)
/// before use, analogous to [`Client`](crate::gateway::client::Client).
///
/// # Examples
///
/// ```rust
/// let mut orderer = OrdererClientBuilder::new()
///     .with_identity(identity)?
///     .with_tls(orderer_tls_ca_pem)?
///     .with_authority("localhost:7050")?
///     .build()?;
/// orderer.connect().await?;
///
/// // Fetch the latest block of a channel
/// let block = orderer.fetch_block("mychannel", BlockPosition::Newest).await?;
///
/// // Submit a signed config update transaction
/// orderer.broadcast(envelope).await?;
/// ```
pub struct OrdererClient {
    identity: Identity,
    tls_config: tonic::transport::ClientTlsConfig,
    host: tonic::transport::Uri,
    channel: Option<tonic::transport::Channel>,
}

impl OrdererClient {
    /// Opens the gRPC connection to the orderer.
    pub async fn connect(&mut self) -> Result<(), tonic::transport::Error> {
        self.channel = Some(
            tonic::transport::Channel::builder(self.host.clone())
                .tls_config(self.tls_config.clone())
                .expect("Invalid TLS config")
                .connect()
                .await?,
        );
        Ok(())
    }

    fn create_client(&self) -> Result<AtomicBroadcastClient<tonic::transport::Channel>, SubmitError> {
        match &self.channel {
            Some(channel) => Ok(AtomicBroadcastClient::new(channel.clone())
                .max_encoding_message_size(usize::MAX)
                .max_decoding_message_size(usize::MAX)),
            None => Err(SubmitError::NotConnected),
        }
    }

    /// Submits a single [`Envelope`] to the orderer for ordering and waits for
    /// its acknowledgement.
    ///
    /// Returns the [`BroadcastResponse`] on success (status `SUCCESS`);
    /// returns [`SubmitError::NodeError`] with the orderer's status and info
    /// string otherwise.
    ///
    /// Note that a successful broadcast only means the orderer accepted the
    /// envelope for ordering — it does not wait for the transaction to be
    /// committed into a block.
    pub async fn broadcast(&self, envelope: Envelope) -> Result<BroadcastResponse, SubmitError> {
        let mut client = self.create_client()?;

        let request = futures_util::stream::iter([envelope]);
        let mut response_stream = match client.broadcast(request).await {
            Ok(response) => response.into_inner(),
            Err(err) => {
                return Err(SubmitError::NodeError(
                    crate::implement::grpc_error::format_grpc_error(&err),
                ));
            }
        };

        let response = match response_stream.message().await {
            Ok(Some(response)) => response,
            Ok(None) => return Err(SubmitError::EmptyRespone),
            Err(err) => {
                return Err(SubmitError::NodeError(
                    crate::implement::grpc_error::format_grpc_error(&err),
                ));
            }
        };

        if response.status != i32::from(Status::Success) {
            return Err(SubmitError::NodeError(format!(
                "Broadcast rejected with status {}: {}",
                response.status, response.info
            )));
        }

        Ok(response)
    }

    /// Opens a Deliver stream on the orderer with the given signed seek
    /// envelope (see [`build_seek_envelope`](Self::build_seek_envelope)).
    ///
    /// Most callers want the higher-level [`fetch_block`](Self::fetch_block);
    /// this method is the escape hatch for custom seek ranges (e.g. streaming
    /// all blocks as they are committed).
    pub async fn deliver(
        &self,
        seek_envelope: Envelope,
    ) -> Result<tonic::Streaming<DeliverResponse>, SubmitError> {
        let mut client = self.create_client()?;

        let request = futures_util::stream::iter([seek_envelope]);
        match client.deliver(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(err) => Err(SubmitError::NodeError(
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }

    /// Fetches a single block from the given channel.
    ///
    /// `position` selects the block: newest, oldest, or a specific number.
    pub async fn fetch_block(
        &self,
        channel_name: impl Into<String>,
        position: BlockPosition,
    ) -> Result<Block, SubmitError> {
        let seek_envelope = self.build_seek_envelope(channel_name, position, position)?;
        let mut stream = self.deliver(seek_envelope).await?;

        let mut block = None;
        loop {
            let response = match stream.message().await {
                Ok(Some(response)) => response,
                Ok(None) => break,
                Err(err) => {
                    return Err(SubmitError::NodeError(
                        crate::implement::grpc_error::format_grpc_error(&err),
                    ));
                }
            };
            match response.r#type {
                Some(deliver_response::Type::Block(b)) => {
                    if block.is_none() {
                        block = Some(b);
                    }
                }
                Some(deliver_response::Type::Status(status)) => {
                    if status != i32::from(Status::Success) {
                        return Err(SubmitError::NodeError(format!(
                            "Deliver failed with status {}",
                            status
                        )));
                    }
                    // SUCCESS status terminates the requested block range.
                    break;
                }
                None => return Err(SubmitError::EmptyRespone),
            }
        }

        block.ok_or(SubmitError::EmptyRespone)
    }

    /// Builds and signs a `DELIVER_SEEK_INFO` envelope requesting the block
    /// range `[start, stop]` from the given channel.
    pub fn build_seek_envelope(
        &self,
        channel_name: impl Into<String>,
        start: BlockPosition,
        stop: BlockPosition,
    ) -> Result<Envelope, SubmitError> {
        let seek_info = SeekInfo {
            start: Some(start.to_seek_position()),
            stop: Some(stop.to_seek_position()),
            behavior: crate::fabric::orderer::seek_info::SeekBehavior::BlockUntilReady.into(),
            error_response: crate::fabric::orderer::seek_info::SeekErrorResponse::Strict.into(),
            content_type: crate::fabric::orderer::seek_info::SeekContentType::Block.into(),
        };

        let nonce = generate_nonce();
        let creator = self.identity.get_serialized_identity().encode_to_vec();
        let transaction_id = generate_transaction_id(&nonce, creator.as_slice());

        let channel_header = ChannelHeader {
            r#type: HeaderType::DeliverSeekInfo.into(),
            version: 0,
            timestamp: Some(std::time::SystemTime::now().into()),
            channel_id: channel_name.into(),
            tx_id: transaction_id,
            epoch: 0,
            extension: vec![],
            tls_cert_hash: vec![],
        };

        let signature_header = SignatureHeader {
            creator,
            nonce: nonce.to_vec(),
        };

        let payload = Payload {
            header: Some(Header {
                channel_header: channel_header.encode_to_vec(),
                signature_header: signature_header.encode_to_vec(),
            }),
            data: seek_info.encode_to_vec(),
        };

        let payload_bytes = payload.encode_to_vec();
        let signature = self.identity.sign_message(&payload_bytes);

        Ok(Envelope {
            payload: payload_bytes,
            signature,
        })
    }
}

/// Builder for [`OrdererClient`], mirroring
/// [`ClientBuilder`](crate::gateway::client::ClientBuilder).
#[derive(Default)]
pub struct OrdererClientBuilder {
    identity: Option<Identity>,
    tls: Option<Vec<u8>>,
    scheme: Option<String>,
    authority: Option<String>,
}

impl OrdererClientBuilder {
    pub fn new() -> OrdererClientBuilder {
        OrdererClientBuilder::default()
    }

    /// Identity used to sign broadcast/seek envelopes.
    pub fn with_identity(mut self, identity: Identity) -> Result<OrdererClientBuilder, BuilderError> {
        self.identity = Some(identity);
        Ok(self)
    }

    /// PEM bytes of the orderer's TLS CA certificate. In the test network this
    /// is `organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem`.
    pub fn with_tls(mut self, bytes: impl Into<Vec<u8>>) -> Result<OrdererClientBuilder, BuilderError> {
        self.tls = Some(bytes.into());
        Ok(self)
    }

    /// URI scheme for the gRPC connection. Default is `https`.
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Result<OrdererClientBuilder, BuilderError> {
        let scheme = scheme.into().trim().to_string();
        if scheme.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "scheme cannot be empty".into(),
            ));
        }
        self.scheme = Some(scheme);
        Ok(self)
    }

    /// Authority (host:port) of the orderer. Default is `localhost:7050`,
    /// which corresponds to the test network.
    pub fn with_authority(
        mut self,
        authority: impl Into<String>,
    ) -> Result<OrdererClientBuilder, BuilderError> {
        let authority = authority.into().trim().to_string();
        if authority.is_empty() {
            return Err(BuilderError::InvalidParameter(
                "authority cannot be empty".into(),
            ));
        }
        self.authority = Some(authority);
        Ok(self)
    }

    /// Collects and validates the builder values. Building does not open the
    /// connection; call [`OrdererClient::connect`] afterwards.
    pub fn build(self) -> Result<OrdererClient, BuilderError> {
        use std::str::FromStr;

        let identity = match self.identity {
            Some(identity) => identity,
            None => return Err(BuilderError::MissingParameter("identity".into())),
        };
        let tls = match self.tls {
            Some(tls) => tls,
            None => return Err(BuilderError::MissingParameter("tls".into())),
        };

        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(tls.as_slice()));
        let scheme = self.scheme.unwrap_or_else(|| "https".to_string());
        let authority = self.authority.unwrap_or_else(|| "localhost:7050".to_string());
        let scheme =
            tonic::codegen::http::uri::Scheme::from_str(scheme.as_str()).expect("Invalid scheme");
        let uri = tonic::transport::Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query("/")
            .build()
            .map_err(|err| BuilderError::InvalidParameter(err.to_string()))?;

        Ok(OrdererClient {
            identity,
            tls_config,
            host: uri,
            channel: None,
        })
    }
}
