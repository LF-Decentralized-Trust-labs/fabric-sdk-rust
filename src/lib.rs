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

#[cfg(feature = "client")]
pub mod error;
#[cfg(feature = "client")]
pub mod gateway;
#[cfg(feature = "client")]
pub mod identity;
#[cfg(feature = "client")]
#[allow(dead_code)]
pub(crate) mod transaction;

pub mod prelude {
    #[cfg(all(feature = "chaincode",feature = "client"))]
    pub use crate::chaincode::context::Context;
    #[cfg(all(feature = "chaincode",feature = "client"))]
    pub use derives::*;
    #[cfg(all(feature = "chaincode",feature = "client"))]
    pub use fabric_sdk_derives as derives;
    #[cfg(all(feature = "chaincode",feature = "client"))]
    pub use tokio;

    pub use serde_json;
    pub use prost::Message;
}
