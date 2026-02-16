/// Proto definitions from hyperledger fabric
///
/// See the [documentation](https://github.com/hyperledger/fabric-protos) for further details
#[allow(dead_code,clippy::doc_overindented_list_items,clippy::doc_lazy_continuation,clippy::enum_variant_names)]
#[rustfmt::skip]
pub mod fabric {
    pub(crate) mod common;
    pub mod discovery;
    pub mod gateway;
    pub(crate) mod google_protobuf;
    pub(crate) mod gossip;
    pub(crate) mod msp;
    pub(crate) mod orderer;
    pub mod protos;
    #[cfg(feature = "chaincode")]
    pub(crate) mod queryresult;
}
#[cfg(feature = "chaincode")]
pub mod chaincode;
pub mod error;
#[cfg(feature = "client")]
pub mod gateway;
pub mod identity;
pub mod signer;
#[allow(dead_code)]
pub(crate) mod transaction;

pub mod prelude {
    #[cfg(feature = "chaincode")]
    pub use crate::chaincode::context::Context;
    #[cfg(feature = "chaincode")]
    pub use derives::*;
    #[cfg(feature = "chaincode")]
    pub use fabric_sdk_derives as derives;
    pub use serde_json;
    #[cfg(feature = "chaincode")]
    pub use tokio;
}
