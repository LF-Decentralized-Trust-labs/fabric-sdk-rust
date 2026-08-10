//! Client for the orderer's channel-participation API (`osnadmin`).
//!
//! Native-only (feature `client`): the API requires mutual TLS, which
//! browsers cannot provide programmatically.

mod client;
pub use client::{
    ChannelInfo, ChannelList, ChannelListEntry, OsnadminClient, OsnadminClientBuilder,
};
