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
