/// The signer holds the bytes of the pkcs8 key for the Ecdsa signing algorithm which is needed by the client.
/// This implementation is a place holder for future feature implementations.
/// In the test network found in `organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk`
///
/// # Example
/// ```rust
/// use fabric_sdk_rust::{client::ClientBuilder, signer::Signer};
///
/// let signer = Signer::new(std::fs::read(keystore_path)?);
/// let mut client = ClientBuilder::new().with_signer(signer)?;
/// ```
#[derive(Clone)]
pub struct Signer {
    pub pkey: Vec<u8>,
}
impl Signer {
    pub fn new(pkey: impl Into<Vec<u8>>) -> Self {
        Self { pkey: pkey.into() }
    }
}
impl Signer {
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

        let ec_key = openssl::ec::EcKey::private_key_from_pem(&self.pkey).unwrap();

        let mut hasher = openssl::sha::Sha256::new();
        hasher.update(message);
        let hash = hasher.finish();

        let signature = openssl::ecdsa::EcdsaSig::sign(hash.as_slice(), &ec_key).unwrap();

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
