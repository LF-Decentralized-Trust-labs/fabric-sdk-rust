use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};

use crate::{
    error::{BuilderError, FabricCAError},
    identity::Identity,
};

// RFC 3986 path-segment reserved set: everything in CONTROLS plus characters that
// have meaning in a URL (path separators, query/fragment delimiters, sub-delims, etc.).
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ').add(b'"').add(b'<').add(b'>').add(b'`')
    .add(b'#').add(b'?').add(b'{').add(b'}')
    .add(b'/').add(b':').add(b';').add(b'=').add(b'@')
    .add(b'[').add(b']').add(b'\\').add(b'^').add(b'|')
    .add(b'%');

fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

// ===== Request types =====

/// Request body for registering a new identity with the Fabric CA.
pub struct RegisterIdentityRequest {
    pub id: String,
    pub r#type: String,
    pub secret: Option<String>,
    pub max_enrollments: Option<i32>,
    pub affiliation: Option<String>,
    pub attrs: Vec<CAAttribute>,
}

/// Request body for modifying an existing identity. Fields set to `None` are left
/// unchanged on the CA; this is a partial update, not a replace. In particular,
/// `attrs: None` leaves the identity's existing attributes untouched, while
/// `attrs: Some(vec![])` clears them.
pub struct ModifyIdentityRequest {
    pub r#type: Option<String>,
    pub secret: Option<String>,
    pub max_enrollments: Option<i32>,
    pub affiliation: Option<String>,
    pub attrs: Option<Vec<CAAttribute>>,
}

/// Request body for revoking a certificate or identity.
pub struct RevokeRequest {
    /// Enrollment ID to revoke all certificates for this identity.
    pub enrollment_id: Option<String>,
    /// Certificate serial number (used with `aki` for targeted revocation).
    pub serial: Option<String>,
    /// Authority Key Identifier (used with `serial` for targeted revocation).
    pub aki: Option<String>,
    /// Revocation reason string (e.g. `"keycompromise"`, `"affiliationchange"`).
    pub reason: Option<String>,
    /// When `true`, the response includes a freshly generated CRL.
    pub gen_crl: bool,
}

// ===== Response types =====

/// An identity registered with the Fabric CA.
#[derive(Debug, Clone, Deserialize)]
pub struct CAIdentity {
    pub id: String,
    pub r#type: String,
    pub affiliation: String,
    #[serde(default)]
    pub attrs: Vec<CAAttribute>,
    pub max_enrollments: i32,
    #[serde(default)]
    pub caname: String,
}

/// An attribute associated with a CA identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAAttribute {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub ecert: bool,
}

/// CA server information returned by [`FabricCAClient::get_ca_info`].
#[derive(Debug, Clone, Deserialize)]
pub struct CAInfo {
    #[serde(rename = "CAName")]
    pub ca_name: String,
    #[serde(rename = "CAChain")]
    pub ca_chain: String,
    #[serde(rename = "IssuerPublicKey")]
    pub issuer_public_key: String,
    #[serde(rename = "Version")]
    pub version: String,
}

/// An affiliation node in the Fabric CA affiliation hierarchy.
#[derive(Debug, Clone, Deserialize)]
pub struct Affiliation {
    pub name: String,
    #[serde(default)]
    pub affiliations: Vec<Affiliation>,
    #[serde(default)]
    pub identities: Vec<CAIdentity>,
}

// ===== Internal serde types =====

#[derive(Deserialize)]
struct FabricCAResponse {
    success: bool,
    // Fabric CA sometimes returns `"result": ""` instead of null or an object.
    #[serde(default)]
    result: serde_json::Value,
    #[serde(default)]
    errors: Vec<FabricCAErrorMsg>,
}

#[derive(Deserialize)]
struct FabricCAErrorMsg {
    message: String,
}

#[derive(Deserialize)]
struct IdentitiesResult {
    #[serde(default)]
    identities: Vec<CAIdentity>,
}

#[derive(Deserialize)]
struct RegisterResult {
    secret: String,
}

#[derive(Serialize)]
struct RegisterIdentityBody<'a> {
    id: &'a str,
    r#type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_enrollments: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affiliation: Option<&'a str>,
    attrs: &'a [CAAttribute],
}

#[derive(Serialize)]
struct ModifyIdentityBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_enrollments: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affiliation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attrs: Option<&'a [CAAttribute]>,
}

#[derive(Serialize)]
struct RevokeBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aki: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    gen_crl: bool,
}

// ===== Builder =====

/// Builder for [`FabricCAClient`].
///
/// # Examples
///
/// ```no_run
/// use fabric_sdk::fabric_ca::FabricCAClientBuilder;
/// use fabric_sdk::identity::IdentityBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cert = std::fs::read("admin-cert.pem")?;
/// let key = std::fs::read_to_string("admin-key.pem")?;
/// let tls = std::fs::read("ca-tls-cert.pem")?;
///
/// let identity = IdentityBuilder::from_pem(&cert)?
///     .with_msp("Org1MSP")?
///     .with_private_key(key)?
///     .build()?;
///
/// let ca = FabricCAClientBuilder::new()
///     .with_url("https://ca.org1.example.com:7054")?
///     .with_identity(identity)
///     .with_tls(tls)
///     .build()?;
///
/// let identities = ca.list_identities().await?;
/// for identity in &identities {
///     println!("{}: {}", identity.id, identity.r#type);
/// }
/// # Ok(())
/// # }
/// ```
pub struct FabricCAClientBuilder {
    url: Option<String>,
    identity: Option<Identity>,
    #[cfg(not(target_arch = "wasm32"))]
    tls: Option<Vec<u8>>,
    #[cfg(not(target_arch = "wasm32"))]
    danger_accept_invalid_certs: bool,
}

impl Default for FabricCAClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricCAClientBuilder {
    pub fn new() -> Self {
        Self {
            url: None,
            identity: None,
            #[cfg(not(target_arch = "wasm32"))]
            tls: None,
            #[cfg(not(target_arch = "wasm32"))]
            danger_accept_invalid_certs: false,
        }
    }

    /// Sets the base URL of the Fabric CA server, e.g. `"https://ca.org1.example.com:7054"`.
    /// Trailing slashes are stripped so paths can be appended directly.
    pub fn with_url(mut self, url: impl Into<String>) -> Result<Self, BuilderError> {
        let url = url.into().trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(BuilderError::InvalidParameter("url cannot be empty".into()));
        }
        self.url = Some(url);
        Ok(self)
    }

    /// Sets the admin identity used to authenticate requests.
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sets the PEM-encoded TLS CA certificate used to verify the server's TLS certificate.
    ///
    /// Not available in WASM builds: TLS is handled by the browser and root certificates
    /// cannot be configured per-request.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_tls(mut self, tls: impl Into<Vec<u8>>) -> Self {
        self.tls = Some(tls.into());
        self
    }

    /// Disables TLS certificate verification entirely.
    ///
    /// **Do not use in production.** This is intended for local test networks where the
    /// CA's TLS certificate hostname (e.g. `ca.org1.example.com`) does not match the
    /// connection address (e.g. `localhost`).
    ///
    /// Not available in WASM builds: TLS is handled by the browser.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    pub fn build(self) -> Result<FabricCAClient, BuilderError> {
        let url = self.url.ok_or(BuilderError::MissingParameter("url".into()))?;
        let identity = self.identity.ok_or(BuilderError::MissingParameter("identity".into()))?;

        #[cfg(target_arch = "wasm32")]
        let http_client = reqwest::Client::new();

        #[cfg(not(target_arch = "wasm32"))]
        let http_client = {
            let mut builder =
                reqwest::ClientBuilder::new().danger_accept_invalid_certs(self.danger_accept_invalid_certs);
            if let Some(tls) = self.tls {
                let cert = reqwest::Certificate::from_pem(&tls)
                    .map_err(|e| BuilderError::InvalidParameter(e.to_string()))?;
                builder = builder.add_root_certificate(cert);
            }
            builder
                .build()
                .map_err(|e| BuilderError::InvalidParameter(e.to_string()))?
        };

        Ok(FabricCAClient {
            base_url: url,
            identity,
            http_client,
        })
    }
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

// ===== Client =====

/// Client for the Hyperledger Fabric CA REST API.
///
/// The Fabric CA manages user and service identities (X.509 certificates) for an
/// organization. The authenticated identity must hold the `hf.Registrar` CA attribute
/// to perform identity management operations.
///
/// Use [`FabricCAClientBuilder`] to construct an instance.
pub struct FabricCAClient {
    base_url: String,
    identity: Identity,
    http_client: reqwest::Client,
}

impl FabricCAClient {
    /// Returns CA server information such as the CA name, certificate chain, and version.
    /// Does not require authentication.
    pub async fn get_ca_info(&self) -> Result<CAInfo, FabricCAError> {
        let path = "/api/v1/cainfo";
        let raw = self
            .http_client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| FabricCAError::HttpError(full_error_chain(&e)))?;
        let resp = self.parse_response(raw).await?;
        self.unwrap_response(resp)
    }

    /// Lists all identities registered with the CA that are visible to the caller's affiliation.
    pub async fn list_identities(&self) -> Result<Vec<CAIdentity>, FabricCAError> {
        let path = "/api/v1/identities";
        let resp = self.authenticated_get(path).await?;
        Ok(self.unwrap_response::<IdentitiesResult>(resp)?.identities)
    }

    /// Returns details for the identity with the given enrollment ID.
    pub async fn get_identity(&self, id: impl AsRef<str>) -> Result<CAIdentity, FabricCAError> {
        let path = format!("/api/v1/identities/{}", encode_segment(id.as_ref()));
        let resp = self.authenticated_get(&path).await?;
        self.unwrap_response(resp)
    }

    /// Registers a new identity and returns its enrollment secret.
    ///
    /// The caller must hold the `hf.Registrar.Roles` attribute that includes the
    /// type being registered.
    pub async fn register_identity(
        &self,
        req: RegisterIdentityRequest,
    ) -> Result<String, FabricCAError> {
        let path = "/api/v1/identities";
        let body = RegisterIdentityBody {
            id: &req.id,
            r#type: &req.r#type,
            secret: req.secret.as_deref(),
            max_enrollments: req.max_enrollments,
            affiliation: req.affiliation.as_deref(),
            attrs: &req.attrs,
        };
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| FabricCAError::ParseError(e.to_string()))?;
        let raw = self
            .authenticated_request(reqwest::Method::POST, path, &body_bytes)
            .await?;
        let parsed = self.parse_response(raw).await?;
        Ok(self.unwrap_response::<RegisterResult>(parsed)?.secret)
    }

    /// Modifies an existing identity's attributes and returns the updated identity.
    pub async fn modify_identity(
        &self,
        id: impl AsRef<str>,
        req: ModifyIdentityRequest,
    ) -> Result<CAIdentity, FabricCAError> {
        let path = format!("/api/v1/identities/{}", encode_segment(id.as_ref()));
        let body = ModifyIdentityBody {
            r#type: req.r#type.as_deref(),
            secret: req.secret.as_deref(),
            max_enrollments: req.max_enrollments,
            affiliation: req.affiliation.as_deref(),
            attrs: req.attrs.as_deref(),
        };
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| FabricCAError::ParseError(e.to_string()))?;
        let raw = self
            .authenticated_request(reqwest::Method::PUT, &path, &body_bytes)
            .await?;
        let parsed = self.parse_response(raw).await?;
        self.unwrap_response(parsed)
    }

    /// Removes an identity from the CA. All certificates issued to the identity are revoked.
    pub async fn remove_identity(&self, id: impl AsRef<str>) -> Result<(), FabricCAError> {
        let path = format!("/api/v1/identities/{}", encode_segment(id.as_ref()));
        let raw = self
            .authenticated_request(reqwest::Method::DELETE, &path, b"")
            .await?;
        let parsed = self.parse_response(raw).await?;
        self.check_response(parsed)
    }

    /// Returns the affiliation hierarchy visible to the caller as a tree rooted at the
    /// caller's affiliation level.
    pub async fn list_affiliations(&self) -> Result<Affiliation, FabricCAError> {
        let path = "/api/v1/affiliations";
        let resp = self.authenticated_get(path).await?;
        self.unwrap_response(resp)
    }

    /// Returns the affiliation subtree rooted at `name`.
    pub async fn get_affiliation(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Affiliation, FabricCAError> {
        let path = format!("/api/v1/affiliations/{}", encode_segment(name.as_ref()));
        let resp = self.authenticated_get(&path).await?;
        self.unwrap_response(resp)
    }

    /// Revokes a certificate by serial + AKI, or all certificates belonging to an identity.
    ///
    /// Set [`RevokeRequest::enrollment_id`] to revoke all certs for that identity, or
    /// set both [`RevokeRequest::serial`] and [`RevokeRequest::aki`] for a targeted revocation.
    pub async fn revoke(&self, req: RevokeRequest) -> Result<(), FabricCAError> {
        let path = "/api/v1/revoke";
        let body = RevokeBody {
            enrollment_id: req.enrollment_id.as_deref(),
            serial: req.serial.as_deref(),
            aki: req.aki.as_deref(),
            reason: req.reason.as_deref(),
            gen_crl: req.gen_crl,
        };
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| FabricCAError::ParseError(e.to_string()))?;
        let raw = self
            .authenticated_request(reqwest::Method::POST, path, &body_bytes)
            .await?;
        let parsed = self.parse_response(raw).await?;
        self.check_response(parsed)
    }

    // ----- private helpers -----

    async fn authenticated_get(&self, path: &str) -> Result<FabricCAResponse, FabricCAError> {
        let raw = self
            .authenticated_request(reqwest::Method::GET, path, b"")
            .await?;
        self.parse_response(raw).await
    }

    async fn parse_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<FabricCAResponse, FabricCAError> {
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| FabricCAError::HttpError(full_error_chain(&e)))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            FabricCAError::ParseError(format!(
                "{}: body={}",
                e,
                String::from_utf8_lossy(&bytes)
            ))
        })
    }

    async fn authenticated_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &[u8],
    ) -> Result<reqwest::Response, FabricCAError> {
        let token = self
            .identity
            .generate_fabric_ca_token(method.as_str(), path, body);
        self.http_client
            .request(method, format!("{}{}", self.base_url, path))
            .header("Authorization", token)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| FabricCAError::HttpError(full_error_chain(&e)))
    }

    fn unwrap_response<T: for<'de> Deserialize<'de>>(
        &self,
        resp: FabricCAResponse,
    ) -> Result<T, FabricCAError> {
        if resp.success {
            let is_empty = matches!(&resp.result, serde_json::Value::Null)
                || matches!(&resp.result, serde_json::Value::String(s) if s.is_empty());
            if is_empty {
                Err(FabricCAError::ParseError(
                    "CA returned success but no result".into(),
                ))
            } else {
                serde_json::from_value(resp.result)
                    .map_err(|e| FabricCAError::ParseError(e.to_string()))
            }
        } else {
            let msg = resp
                .errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join(", ");
            Err(FabricCAError::CAError(msg))
        }
    }

    fn check_response(&self, resp: FabricCAResponse) -> Result<(), FabricCAError> {
        if resp.success {
            Ok(())
        } else {
            let msg = resp
                .errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join(", ");
            Err(FabricCAError::CAError(msg))
        }
    }
}
