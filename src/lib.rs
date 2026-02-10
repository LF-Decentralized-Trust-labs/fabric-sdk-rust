#[allow(dead_code)]
mod fabric {
    pub mod common;
    pub mod gateway;
    pub mod msp;
    pub mod orderer;
    pub mod protos;
    #[cfg(feature = "chaincode")]
    pub mod queryresult;
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
