use serde::{Deserialize, Serialize};

use crate::error::{BuilderError, OperationsError};

// ===== Response types =====

/// Response of `GET /healthz`.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthStatus {
    /// `"OK"` when healthy; `"Service Unavailable"` otherwise.
    pub status: String,
    /// Server timestamp of the health check.
    #[serde(default)]
    pub time: String,
    /// The names of failed health checks, present when unhealthy.
    #[serde(default, rename = "failed_checks")]
    pub failed_checks: Vec<FailedCheck>,
}

/// A single failed health check inside [`HealthStatus`].
#[derive(Debug, Clone, Deserialize)]
pub struct FailedCheck {
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub reason: String,
}

/// Request/response body of the `/logspec` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSpec {
    /// The active logging specification, e.g. `"info"` or
    /// `"grpc=debug:info"`.
    pub spec: String,
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

/// Builder for [`OperationsClient`].
///
/// TLS is optional: the operations service may run plain HTTP (the test
/// network default), HTTPS, or HTTPS with mutual TLS for the sensitive
/// endpoints (`/logspec`).
///
/// # Examples
///
/// ```no_run
/// use fabric_sdk::operations::OperationsClientBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let ops = OperationsClientBuilder::new()
///     .with_url("http://localhost:9443")?
///     .build()?;
///
/// let health = ops.healthz().await?;
/// assert_eq!(health.status, "OK");
/// # Ok(())
/// # }
/// ```
pub struct OperationsClientBuilder {
    url: Option<String>,
    client_cert: Option<Vec<u8>>,
    client_key: Option<Vec<u8>>,
    tls: Option<Vec<u8>>,
    danger_accept_invalid_certs: bool,
}

impl Default for OperationsClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationsClientBuilder {
    pub fn new() -> Self {
        Self {
            url: None,
            client_cert: None,
            client_key: None,
            tls: None,
            danger_accept_invalid_certs: false,
        }
    }

    /// Sets the base URL of the operations endpoint, e.g.
    /// `"http://localhost:9443"`. Trailing slashes are stripped.
    pub fn with_url(mut self, url: impl Into<String>) -> Result<Self, BuilderError> {
        let url = url.into().trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(BuilderError::InvalidParameter("url cannot be empty".into()));
        }
        self.url = Some(url);
        Ok(self)
    }

    /// Sets an optional mutual-TLS client certificate and private key (both
    /// PEM). Required for `/logspec` when the operations service runs with
    /// `operations.tls.clientAuthRequired: true`.
    pub fn with_client_identity(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Result<Self, BuilderError> {
        self.client_cert = Some(cert_pem.into());
        self.client_key = Some(key_pem.into());
        Ok(self)
    }

    /// Sets the PEM-encoded TLS CA certificate used to verify the server's
    /// TLS certificate (for HTTPS operations endpoints).
    pub fn with_tls(mut self, tls: impl Into<Vec<u8>>) -> Self {
        self.tls = Some(tls.into());
        self
    }

    /// Disables TLS server certificate verification entirely.
    ///
    /// **Do not use in production.**
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    pub fn build(self) -> Result<OperationsClient, BuilderError> {
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

        Ok(OperationsClient {
            base_url: url,
            http_client,
        })
    }
}

// ===== Client =====

/// Client for the Fabric operations service (`/healthz`, `/version`,
/// `/logspec`, `/metrics`).
///
/// Use [`OperationsClientBuilder`] to construct an instance.
pub struct OperationsClient {
    base_url: String,
    http_client: reqwest::Client,
}

impl OperationsClient {
    /// Runs the node's health checks (`GET /healthz`).
    ///
    /// Note: an unhealthy node responds with HTTP 503 *and* a body listing
    /// the failed checks; this method returns the parsed body in both cases
    /// and only errors on transport or parse failures.
    pub async fn healthz(&self) -> Result<HealthStatus, OperationsError> {
        let response = self
            .http_client
            .get(format!("{}/healthz", self.base_url))
            .send()
            .await
            .map_err(|e| OperationsError::HttpError(full_error_chain(&e)))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|e| OperationsError::HttpError(full_error_chain(&e)))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            OperationsError::ParseError(format!(
                "{}: body={}",
                e,
                String::from_utf8_lossy(&bytes)
            ))
        })
    }

    /// Returns the node's version information (`GET /version`) as the raw
    /// JSON body, e.g. `{"CommitSHA":"...","Version":"2.5.x"}`.
    pub async fn version(&self) -> Result<String, OperationsError> {
        self.get_text("/version").await
    }

    /// Returns the active logging specification (`GET /logspec`).
    pub async fn get_logspec(&self) -> Result<LogSpec, OperationsError> {
        let body = self.get_text("/logspec").await?;
        serde_json::from_str(&body)
            .map_err(|e| OperationsError::ParseError(format!("{}: body={}", e, body)))
    }

    /// Sets the active logging specification (`PUT /logspec`), e.g. `"debug"`
    /// or `"gossip=warning:info"`.
    pub async fn put_logspec(&self, spec: impl Into<String>) -> Result<(), OperationsError> {
        let body = serde_json::to_vec(&LogSpec { spec: spec.into() })
            .map_err(|e| OperationsError::ParseError(e.to_string()))?;
        let response = self
            .http_client
            .put(format!("{}/logspec", self.base_url))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| OperationsError::HttpError(full_error_chain(&e)))?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.bytes().await.unwrap_or_default();
            Err(OperationsError::ServerError {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&body).into_owned(),
            })
        }
    }

    /// Returns the raw Prometheus metrics exposition (`GET /metrics`).
    ///
    /// Only meaningful when the node runs with the `prometheus` metrics
    /// provider.
    pub async fn metrics_raw(&self) -> Result<String, OperationsError> {
        self.get_text("/metrics").await
    }

    // ----- private helpers -----

    async fn get_text(&self, path: &str) -> Result<String, OperationsError> {
        let response = self
            .http_client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| OperationsError::HttpError(full_error_chain(&e)))?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| OperationsError::HttpError(full_error_chain(&e)))?;

        if !status.is_success() {
            return Err(OperationsError::ServerError {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }

        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}
