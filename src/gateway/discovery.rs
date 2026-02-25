use prost::Message;

use crate::{
    error::BuilderError,
    fabric::discovery::{AuthInfo, Query, Request, SignedRequest},
    identity::Identity,
};

/// A prepared discovery call is ready to be submitted to the network.
/// This struct is being used by the [`submit_discovery_call()`](submit_discovery_call) from the [`Client`](Client).
pub struct PreparedDiscoveryCall {
    pub(crate) request: SignedRequest,
}
/// Discovery defines a service that serves information about the fabric network like which peers, orderers, chaincodes, etc.
pub struct DiscoveryCallBuilder {
    pub(crate) identity: Identity,
    pub(crate) queries: Vec<Query>,
}
impl DiscoveryCallBuilder {
    pub fn add_query(&mut self, query: Query) -> Result<&mut Self, BuilderError> {
        self.queries.push(query);
        Ok(self)
    }
    /// Builds a PreparedDiscoveryCall which can be passed to [`submit_discover_call`](submit_discover_call)
    pub fn build(&self) -> Result<PreparedDiscoveryCall, BuilderError> {
        let authentication = AuthInfo {
            client_identity: self.identity.get_serialized_identity().encode_to_vec(),
            client_tls_cert_hash: self.identity.generate_tls_cert_hash(),
        };
        let request = Request {
            authentication: Some(authentication),
            queries: self.queries.clone(),
        }
        .encode_to_vec();
        let request = SignedRequest {
            signature: self.identity.sign_message(&request),
            payload: request,
        };
        Ok(PreparedDiscoveryCall { request })
    }
}
