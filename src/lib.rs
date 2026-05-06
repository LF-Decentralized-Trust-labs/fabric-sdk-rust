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
    pub mod lifecycle;
    pub mod orderer;
    pub mod protos;
    #[cfg(feature = "chaincode")]
    pub mod queryresult;
}
//    #[cfg(not(feature = "client-wasm"))]

#[cfg(all(feature = "chaincode", not(feature = "client-wasm")))]
pub mod chaincode;

#[cfg(any(feature = "chaincode", feature = "client", feature = "client-wasm"))]
pub mod error;
#[cfg(any(feature = "chaincode", feature = "client", feature = "client-wasm"))]
pub mod gateway;
#[cfg(any(feature = "chaincode", feature = "client", feature = "client-wasm"))]
pub mod identity;
/// Collection of functions for the fabric common structs
#[cfg(any(feature = "chaincode", feature = "client", feature = "client-wasm"))]
#[allow(dead_code)]
pub mod implement;

pub mod prelude {
    #[cfg(all(feature = "chaincode", not(feature = "client-wasm")))]
    pub use crate::chaincode::context::Context;
    #[cfg(feature = "chaincode")]
    pub use derives::*;
    #[cfg(feature = "chaincode")]
    pub use fabric_sdk_derives as derives;
    #[cfg(any(feature = "chaincode", feature = "client"))]
    pub use tokio;

    pub use prost::Message;
    pub use serde_json;
}
