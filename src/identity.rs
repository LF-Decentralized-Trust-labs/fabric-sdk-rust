use crate::{error::BuilderError, fabric::msp::SerializedIdentity};
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
}

impl IdentityBuilder {
    pub fn from_pem(pem_bytes: &[u8]) -> IdentityBuilder {
        let cert = tonic::transport::Certificate::from_pem(pem_bytes);
        IdentityBuilder { msp: None, cert }
    }

    pub fn with_msp(mut self, msp: impl Into<String>) -> Result<IdentityBuilder, BuilderError> {
        let msp = msp.into().trim().to_string();
        if msp.is_empty() {
            return Err(BuilderError::InvalidParameter("msp cannot be empty".into()));
        }
        self.msp = Some(msp);
        Ok(self)
    }

    pub fn build(self) -> Result<SerializedIdentity, BuilderError> {
        if self.msp.is_none() {
            return Err(BuilderError::MissingParameter("msp".into()));
        }
        Ok(SerializedIdentity {
            mspid: self.msp.unwrap(),
            id_bytes: self.cert.clone().into_inner(),
        })
    }
}
