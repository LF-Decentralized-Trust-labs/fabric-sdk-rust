use ecdsa::{SigningKey, elliptic_curve::pkcs8::DecodePrivateKey, signature::Signer};
use p256::NistP256;
use prost::Message;

use crate::{
    error::BuilderError, fabric::msp::SerializedIdentity, transaction::generate_sha256_hash,
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

        let signing_key = ecdsa::SigningKey::from_pkcs8_pem(&self.pkey.replace("EC ", ""))
            .expect("Invalid signing key");

        Ok(Identity {
            msp: self.msp.unwrap(),
            cert: self.cert,
            pkey: signing_key,
        })
    }
}
