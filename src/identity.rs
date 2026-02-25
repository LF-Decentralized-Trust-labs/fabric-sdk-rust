use openssl::{ec::EcKey, pkey::Private};
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
    cert: tonic::transport::Certificate,
    pkey: Vec<u8>,
}

/// An Identiy representation which is able to sign messages
#[derive(Clone)]
pub struct Identity {
    msp: String,
    cert: tonic::transport::Certificate,
    pkey: EcKey<Private>,
}

impl Identity {
    pub(crate) fn get_certificate_bytes(&self) -> Vec<u8> {
        self.cert.clone().into_inner()
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
            id_bytes: self.cert.clone().into_inner(),
        }
    }

    /// Signs a given message using an ECDSA key derived from PEM bytes.
    /// Ring does not support private-key-only pkcs8 files, which is being used by hyperledger's test network. This is why openssl is being used here and in the project generally.
    /// # Arguments
    /// * `message` - A byte slice representing the message to be signed.
    /// * `pem_bytes` - A byte slice representing the private key in PEM format.
    ///
    /// # Returns
    /// A vector of bytes representing the signature.
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        use p256::pkcs8::der::Encode;

        let mut hasher = openssl::sha::Sha256::new();
        hasher.update(message);
        let hash = hasher.finish();

        let signature = openssl::ecdsa::EcdsaSig::sign(hash.as_slice(), &self.pkey).unwrap();

        //Hyperledger uses a normalized s signature. Openssl does not support it so we use ecdsa implementation from RustCrypto https://github.com/RustCrypto/signatures/tree/master/ecdsa
        // which is not verified to be secure
        let signature: ecdsa::Signature<p256::NistP256> =
            ecdsa::Signature::from_der(signature.to_der().unwrap().as_slice()).unwrap();

        let mut v = vec![];
        if let Some(signature) = signature.normalize_s() {
            signature.to_der().encode_to_vec(&mut v).unwrap();
            v
        } else {
            signature.to_der().encode_to_vec(&mut v).unwrap();
            v
        }
    }
}

impl IdentityBuilder {
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, BuilderError> {
        Ok(IdentityBuilder {
            msp: None,
            cert: tonic::transport::Certificate::from_pem(pem_bytes),
            pkey: vec![],
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

    pub fn with_private_key(mut self, pkey: Vec<u8>) -> Result<Self, BuilderError> {
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

        let pkey = openssl::ec::EcKey::private_key_from_pem(&self.pkey).unwrap();

        Ok(Identity {
            msp: self.msp.unwrap(),
            cert: self.cert,
            pkey,
        })
    }
}
