use crate::error::BuilderError;

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

    pub fn build(self) -> Result<crate::protos::msp::SerializedIdentity, BuilderError> {
        if self.msp.is_none() {
            return Err(BuilderError::MissingParameter("msp".into()));
        }
        Ok(crate::protos::msp::SerializedIdentity {
            mspid: self.msp.unwrap(),
            id_bytes: self.cert.clone().into_inner(),
        })
    }
}
