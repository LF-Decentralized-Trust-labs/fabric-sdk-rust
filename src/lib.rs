/// Proto definitions from hyperledger fabric
///
/// See the [documentation](https://github.com/hyperledger/fabric-protos) for further details
#[allow(dead_code,clippy::doc_overindented_list_items,clippy::doc_lazy_continuation,clippy::enum_variant_names)]
#[rustfmt::skip]
pub mod fabric {
    pub mod common;
    pub mod discovery;
    pub mod gateway;
    pub mod google_protobuf;
    pub mod gossip;
    pub mod msp;
    pub mod orderer;
    pub mod protos;
    #[cfg(feature = "chaincode")]
    pub mod queryresult;
}

#[cfg(feature = "chaincode")]
pub mod chaincode;

#[cfg(any(feature = "chaincode",feature = "client"))]
pub mod error;
#[cfg(any(feature = "chaincode",feature = "client"))]
pub mod gateway;
#[cfg(any(feature = "chaincode",feature = "client"))]
pub mod identity;
#[cfg(any(feature = "chaincode",feature = "client"))]
#[allow(dead_code)]
pub(crate) mod transaction;

pub mod prelude {
    #[cfg(feature = "chaincode")]
    pub use crate::chaincode::context::Context;
    #[cfg(feature = "chaincode")]
    pub use fabric_sdk_derives as derives;
    #[cfg(feature = "chaincode")]
    pub use derives::*;
    #[cfg(any(feature = "chaincode",feature = "client"))]
    pub use tokio;

    pub use serde_json;
    pub use prost::Message;
}
