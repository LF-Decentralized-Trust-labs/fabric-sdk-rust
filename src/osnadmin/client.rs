use serde::Deserialize;

use crate::error::{BuilderError, OsnadminError};

// ===== Response types =====

/// A channel entry as returned by the channel list endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelListEntry {
    /// The channel name.
    pub name: String,
    /// The relative URL of the channel's detail endpoint.
    #[serde(default)]
    pub url: String,
}

/// Response of `GET /participation/v1/channels`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelList {
    /// The system channel, if the orderer still uses one (removed in Fabric 3.x).
    #[serde(rename = "systemChannel", default)]
    pub system_channel: Option<ChannelListEntry>,
    /// All application channels this orderer participates in.
    #[serde(default)]
    pub channels: Vec<ChannelListEntry>,
}

/// Response of `GET /participation/v1/channels/{name}` and of a successful
/// join (`POST /participation/v1/channels`).
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelInfo {
    /// The channel name.
    pub name: String,
    /// The relative URL of the channel's detail endpoint.
    #[serde(default)]
    pub url: String,
    /// The orderer's relation to the channel's consensus: `"consenter"`,
    /// `"follower"`, `"config-tracker"` or `"other"`.
    #[serde(rename = "consensusRelation", default)]
    pub consensus_relation: String,
    /// The orderer's status for this channel: `"active"`, `"onboarding"`,
    /// `"inactive"` or `"failed"`.
    #[serde(default)]
    pub status: String,
    /// The orderer's current block height for the channel.
    #[serde(default)]
    pub height: u64,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

fn full_error_chain(e: &dyn std::error::Error) -> String {
    use std::fmt::Write;
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let _ = write!(msg, ": {s}");
        source = s.source();
    }
    msg
}

// ===== Builder =====

/// Builder for [`OsnadminClient`].
///
/// The channel-participation API is protected by mutual TLS: pass the admin
/// client certificate and key with [`with_client_identity`](Self::with_client_identity)
/// and the orderer's TLS CA certificate with [`with_tls`](Self::with_tls).
///
/// # Examples
///
/// ```no_run
/// use fabric_sdk::osnadmin::OsnadminClientBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client_cert = std::fs::read("admin-client.crt")?;
/// let client_key = std::fs::read("admin-client.key")?;
/// let tls_ca = std::fs::read("orderer-tls-ca.crt")?;
///
/// let osnadmin = OsnadminClientBuilder::new()
///     .with_url("https://localhost:7053")?
///     .with_client_identity(client_cert, client_key)?
///     .with_tls(tls_ca)
///     .build()?;
///
/// let channels = osnadmin.list_channels().await?;
/// # Ok(())
/// # }
/// ```
pub struct OsnadminClientBuilder {
    url: Option<String>,
    client_cert: Option<Vec<u8>>,
    client_key: Option<Vec<u8>>,
    tls: Option<Vec<u8>>,
    danger_accept_invalid_certs: bool,
}

impl Default for OsnadminClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OsnadminClientBuilder {
    pub fn new() -> Self {
        Self {
            url: None,
            client_cert: None,
            client_key: None,
            tls: None,
            danger_accept_invalid_certs: false,
        }
    }

    /// Sets the base URL of the orderer's admin endpoint, e.g.
    /// `"https://localhost:7053"`. Trailing slashes are stripped.
    pub fn with_url(mut self, url: impl Into<String>) -> Result<Self, BuilderError> {
        let url = url.into().trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(BuilderError::InvalidParameter("url cannot be empty".into()));
        }
        self.url = Some(url);
        Ok(self)
    }

    /// Sets the mutual-TLS client certificate and private key (both PEM).
    ///
    /// In the test network this is the orderer admin TLS keypair, e.g.
    /// `ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.{crt,key}`.
    pub fn with_client_identity(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Result<Self, BuilderError> {
        self.client_cert = Some(cert_pem.into());
        self.client_key = Some(key_pem.into());
        Ok(self)
    }

    /// Sets the PEM-encoded TLS CA certificate used to verify the orderer's
    /// TLS server certificate.
    pub fn with_tls(mut self, tls: impl Into<Vec<u8>>) -> Self {
        self.tls = Some(tls.into());
        self
    }

    /// Disables TLS server certificate verification entirely.
    ///
    /// **Do not use in production.** Intended for local test networks where
    /// the certificate hostname does not match the connection address.
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    pub fn build(self) -> Result<OsnadminClient, BuilderError> {
        let url = self.url.ok_or(BuilderError::MissingParameter("url".into()))?;

        let mut builder = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(self.danger_accept_invalid_certs);

        if let (Some(cert), Some(key)) = (self.client_cert, self.client_key) {
            let mut identity_pem = cert;
            identity_pem.extend_from_slice(b"\n");
            identity_pem.extend_from_slice(&key);
            let identity = reqwest::Identity::from_pem(&identity_pem)
                .map_err(|e| BuilderError::InvalidParameter(e.to_string()))?;
            builder = builder.identity(identity);
        }

        if let Some(tls) = self.tls {
            let cert = reqwest::Certificate::from_pem(&tls)
                .map_err(|e| BuilderError::InvalidParameter(e.to_string()))?;
            builder = builder.add_root_certificate(cert);
        }

        let http_client = builder
            .build()
            .map_err(|e| BuilderError::InvalidParameter(e.to_string()))?;

        Ok(OsnadminClient {
            base_url: url,
            http_client,
        })
    }
}

// ===== Client =====

/// Client for the orderer's channel-participation API
/// (the REST API behind the `osnadmin` CLI).
///
/// Lets an orderer admin list, join and remove channels without a system
/// channel. Use [`OsnadminClientBuilder`] to construct an instance.
pub struct OsnadminClient {
    base_url: String,
    http_client: reqwest::Client,
}

impl OsnadminClient {
    /// Lists all channels the orderer participates in
    /// (`GET /participation/v1/channels`).
    pub async fn list_channels(&self) -> Result<ChannelList, OsnadminError> {
        let response = self
            .http_client
            .get(format!("{}/participation/v1/channels", self.base_url))
            .send()
            .await
            .map_err(|e| OsnadminError::HttpError(full_error_chain(&e)))?;
        Self::parse_json(response).await
    }

    /// Returns detailed participation info for one channel
    /// (`GET /participation/v1/channels/{name}`).
    pub async fn get_channel(
        &self,
        channel_name: impl AsRef<str>,
    ) -> Result<ChannelInfo, OsnadminError> {
        let response = self
            .http_client
            .get(format!(
                "{}/participation/v1/channels/{}",
                self.base_url,
                channel_name.as_ref()
            ))
            .send()
            .await
            .map_err(|e| OsnadminError::HttpError(full_error_chain(&e)))?;
        Self::parse_json(response).await
    }

    /// Joins the orderer to a channel (`POST /participation/v1/channels`).
    ///
    /// `config_block` must be the marshaled bytes of the channel's config
    /// block: the genesis block when creating/joining a new channel, or the
    /// latest config block when joining as a follower.
    pub async fn join_channel(&self, config_block: Vec<u8>) -> Result<ChannelInfo, OsnadminError> {
        let part = reqwest::multipart::Part::bytes(config_block)
            .file_name("config-block.pb")
            .mime_str("application/octet-stream")
            .map_err(|e| OsnadminError::HttpError(full_error_chain(&e)))?;
        let form = reqwest::multipart::Form::new().part("config-block", part);

        let response = self
            .http_client
            .post(format!("{}/participation/v1/channels", self.base_url))
            .multipart(form)
            .send()
            .await
            .map_err(|e| OsnadminError::HttpError(full_error_chain(&e)))?;
        Self::parse_json(response).await
    }

    /// Removes the orderer from a channel
    /// (`DELETE /participation/v1/channels/{name}`).
    pub async fn remove_channel(
        &self,
        channel_name: impl AsRef<str>,
    ) -> Result<(), OsnadminError> {
        let response = self
            .http_client
            .delete(format!(
                "{}/participation/v1/channels/{}",
                self.base_url,
                channel_name.as_ref()
            ))
            .send()
            .await
            .map_err(|e| OsnadminError::HttpError(full_error_chain(&e)))?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::error_from_response(status, response).await)
        }
    }

    // ----- private helpers -----

    async fn parse_json<T: for<'de> serde::Deserialize<'de>>(
        response: reqwest::Response,
    ) -> Result<T, OsnadminError> {
        let status = response.status();
        if !status.is_success() {
            return Err(Self::error_from_response(status, response).await);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| OsnadminError::HttpError(full_error_chain(&e)))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            OsnadminError::ParseError(format!("{}: body={}", e, String::from_utf8_lossy(&bytes)))
        })
    }

    async fn error_from_response(
        status: reqwest::StatusCode,
        response: reqwest::Response,
    ) -> OsnadminError {
        let body = response.bytes().await.unwrap_or_default();
        let message = serde_json::from_slice::<ErrorResponse>(&body)
            .map(|e| e.error)
            .unwrap_or_else(|_| String::from_utf8_lossy(&body).into_owned());
        OsnadminError::ServerError {
            status: status.as_u16(),
            message,
        }
    }
}
