/// Proto definitions from hyperledger fabric
///
/// See the [documentation](https://github.com/hyperledger/fabric-protos) for further details
#[allow(dead_code)]
pub mod fabric {
    pub(crate) mod common;
    pub mod gateway;
    pub(crate) mod msp;
    pub(crate) mod orderer;
    pub mod protos;
    #[cfg(feature = "chaincode")]
    pub(crate) mod queryresult;
    pub(crate) mod google_protobuf;
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

pub mod prelude{
    #[cfg(feature = "chaincode")]
    pub use fabric_sdk_derives as derives;
    #[cfg(feature = "chaincode")]
    pub use derives::*;
    #[cfg(feature = "chaincode")]
    pub use tokio;
    #[cfg(feature = "chaincode")]
    pub use crate::chaincode::context::Context;
    pub use serde_json;
}
