use ecdsa::{SigningKey, elliptic_curve::pkcs8::DecodePrivateKey, signature::Signer};
use p256::NistP256;
use prost::Message;

use crate::{
    error::BuilderError, fabric::msp::SerializedIdentity, implement::crypto::generate_sha256_hash,
};
/// A builder for creating an identity.
/// The needed pem file is usally found in the test network under `organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem`
/// # Examples
///
/// ```
/// use crate::error::BuilderError;
/// use crate::IdentityBuilder;
///
/// fn main() -> Result<(), BuilderError> {
///     let pem_bytes = include_bytes!("path_to_your_pem_file");
///     let identity = IdentityBuilder::from_pem(pem_bytes)
///         .with_msp("msp_name")?
///         .build()?;
///     Ok(())
/// }
/// ```
pub struct IdentityBuilder {
    msp: Option<String>,
    cert: Vec<u8>,
    pkey: String,
}

/// An Identiy representation which is able to sign messages
#[derive(Clone)]
pub struct Identity {
    msp: String,
    cert: Vec<u8>,
    pkey: SigningKey<NistP256>,
}

impl Identity {
    #[allow(dead_code)]
    pub(crate) fn get_certificate_bytes(&self) -> Vec<u8> {
        self.cert.clone()
    }

    pub(crate) fn generate_tls_cert_hash(&self) -> Vec<u8> {
        generate_sha256_hash(
            self.get_serialized_identity()
                .id_bytes
                .encode_to_vec()
                .as_slice(),
        )
    }

    pub(crate) fn get_serialized_identity(&self) -> SerializedIdentity {
        SerializedIdentity {
            mspid: self.msp.clone(),
            id_bytes: self.get_certificate_bytes(),
        }
    }

    /// Generates a Fabric CA authentication token for an HTTP request.
    ///
    /// The token format is `base64(cert_PEM).base64(signature)`, where the signature
    /// covers `method + "." + base64(path) + "." + base64(body) + "." + base64(cert_PEM)`.
    ///
    /// The `path` MUST be the exact path (including any percent-encoding) that will be
    /// sent on the wire; the server signs the request line as received, so a mismatch
    /// between the signed path and the transmitted path causes authentication failure.
    ///
    /// # Arguments
    /// * `method` - HTTP method in uppercase, e.g. `"GET"`, `"POST"`
    /// * `path` - URL path component, e.g. `"/api/v1/identities"`
    /// * `body` - Request body bytes (empty slice for GET/DELETE)
    #[cfg(any(feature = "client", feature = "client-wasm"))]
    pub fn generate_fabric_ca_token(&self, method: &str, path: &str, body: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        let cert_b64 = b64.encode(&self.cert);
        let msg = format!(
            "{}.{}.{}.{}",
            method,
            b64.encode(path.as_bytes()),
            b64.encode(body),
            cert_b64
        );
        let sig = self.sign_message(msg.as_bytes());
        format!("{}.{}", cert_b64, b64.encode(&sig))
    }

    /// Signs a given message using an ECDSA key derived from PEM bytes.
    /// Ring does not support private-key-only pkcs8 files, which is being used by hyperledger's test network.
    /// Hyperledger uses a normalized s signature. Openssl does not support it so we use ecdsa implementation from RustCrypto https://github.com/RustCrypto/signatures/tree/master/ecdsa which is not verified to be secure
    /// # Arguments
    /// * `message` - A byte slice representing the message to be signed.
    /// * `pem_bytes` - A byte slice representing the private key in PEM format.
    ///
    /// # Returns
    /// A vector of bytes representing the signature.
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        use p256::pkcs8::der::Encode;

        let signature: ecdsa::Signature<p256::NistP256> = self.pkey.sign(message);

        let mut v = vec![];
        signature
            .normalize_s()
            .to_der()
            .encode_to_vec(&mut v)
            .expect("Couldn't encode der to vec");
        v
    }
}

impl IdentityBuilder {
    pub fn from_pem(pem_bytes: impl AsRef<[u8]>) -> Result<Self, BuilderError> {
        Ok(IdentityBuilder {
            msp: None,
            cert: pem_bytes.as_ref().into(),
            pkey: String::default(),
        })
    }

    pub fn with_msp(mut self, msp: impl Into<String>) -> Result<Self, BuilderError> {
        let msp = msp.into().trim().to_string();
        if msp.is_empty() {
            return Err(BuilderError::InvalidParameter("msp cannot be empty".into()));
        }
        self.msp = Some(msp);
        Ok(self)
    }

    pub fn with_private_key(mut self, pkey: String) -> Result<Self, BuilderError> {
        self.pkey = pkey;
        Ok(self)
    }

    pub fn build(self) -> Result<Identity, BuilderError> {
        if self.msp.is_none() {
            return Err(BuilderError::MissingParameter("msp".into()));
        }
        if self.pkey.is_empty() {
            return Err(BuilderError::MissingParameter("pkey".into()));
        }

        let signing_key = parse_signing_key(&self.pkey)?;

        Ok(Identity {
            msp: self.msp.unwrap(),
            cert: self.cert,
            pkey: signing_key,
        })
    }
}

/// Parses a P-256 private key from a PKCS#8 (`PRIVATE KEY`, as cryptogen and
/// Fabric CA write it) or SEC1 (`EC PRIVATE KEY`, as `openssl ecparam`
/// writes it) PEM block.
fn parse_signing_key(pem: &str) -> Result<SigningKey<NistP256>, BuilderError> {
    if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }
    p256::SecretKey::from_sec1_pem(pem)
        .map(|secret| SigningKey::from(&secret))
        .map_err(|_| {
            BuilderError::InvalidParameter(
                "private key is not a P-256 key in PKCS#8 or SEC1 PEM format".into(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICPUcSpHF0fpzPkHP3WutjCvFBD6MULMphtwZ9KTgg3voAoGCCqGSM49\nAwEHoUQDQgAERXIu3cJkcC+xzqtdYjU0a8cAl1Eag9RRPSaVlTYoovuIqYXc/SsG\nFmPjuxB3RtAdpqzi4Tgkp70akiFXxGy9JQ==\n-----END EC PRIVATE KEY-----\n";
    const KEY_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgI9RxKkcXR+nM+Qc/\nda62MK8UEPoxQsymG3Bn0pOCDe+hRANCAARFci7dwmRwL7HOq11iNTRrxwCXURqD\n1FE9JpWVNiii+4iphdz9KwYWY+O7EHdG0B2mrOLhOCSnvRqSIVfEbL0l\n-----END PRIVATE KEY-----\n";

    #[test]
    fn pkcs8_and_sec1_keys_parse_to_the_same_key() {
        let pkcs8 = parse_signing_key(KEY_PKCS8).unwrap();
        let sec1 = parse_signing_key(KEY_SEC1).unwrap();
        assert_eq!(pkcs8.verifying_key(), sec1.verifying_key());
    }

    #[test]
    fn an_invalid_key_is_an_error_not_a_panic() {
        for pem in [
            "garbage",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(matches!(
                parse_signing_key(pem),
                Err(BuilderError::InvalidParameter(_))
            ));
        }
    }
}
