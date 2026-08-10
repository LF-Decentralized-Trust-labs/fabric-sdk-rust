use prost::Message;

use crate::{
    error::SystemChaincodeError,
    fabric::{
        common::{Block, Config},
        protos::ChannelQueryResponse,
    },
    gateway::client::Client,
};

const CSCC_CHAINCODE: &str = "cscc";

/// Client for the Configuration System Chaincode (`cscc`).
///
/// Wraps the peer connection from [`Client`] and provides ergonomic methods for
/// channel management on the connected peer: joining channels, listing joined
/// channels and fetching a channel's configuration.
///
/// All operations are sent as channel-less proposals directly to the peer's
/// `Endorser.ProcessProposal` RPC (like the chaincode install step of
/// [`LifecycleClient`](crate::gateway::lifecycle::LifecycleClient)), so they work
/// on both native and WASM builds.
///
/// # Examples
///
/// ```rust
/// let cscc = client.get_cscc_client();
///
/// // Join the peer to a channel using the channel's genesis block
/// cscc.join_chain(genesis_block_bytes).await?;
///
/// // List all channels the peer has joined
/// let channels = cscc.get_channels().await?;
/// for channel in channels.channels {
///     println!("{}", channel.channel_id);
/// }
///
/// // Fetch the current channel configuration
/// let config = cscc.get_channel_config("mychannel").await?;
/// ```
pub struct CsccClient<'a> {
    client: &'a Client,
}

impl<'a> CsccClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Joins the connected peer to a channel.
    ///
    /// `genesis_block` must be the serialized bytes of the channel's genesis
    /// block (a marshaled `common.Block`), e.g. fetched from the orderer or
    /// produced by `configtxgen`.
    pub async fn join_chain(&self, genesis_block: Vec<u8>) -> Result<(), SystemChaincodeError> {
        self.invoke_cscc("JoinChain", vec![genesis_block]).await?;
        Ok(())
    }

    /// Joins the connected peer to a channel from a snapshot.
    ///
    /// `snapshot_path` is the path of the snapshot directory *on the peer's
    /// filesystem* containing the snapshot to bootstrap from.
    pub async fn join_by_snapshot(
        &self,
        snapshot_path: impl Into<String>,
    ) -> Result<(), SystemChaincodeError> {
        self.invoke_cscc(
            "JoinChainBySnapshot",
            vec![snapshot_path.into().into_bytes()],
        )
        .await?;
        Ok(())
    }

    /// Lists all channels the connected peer has joined.
    pub async fn get_channels(&self) -> Result<ChannelQueryResponse, SystemChaincodeError> {
        let result_bytes = self.invoke_cscc("GetChannels", vec![]).await?;

        ChannelQueryResponse::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode ChannelQueryResponse"))
    }

    /// Fetches the latest configuration block of the given channel.
    ///
    /// The returned [`Block`] contains a `CONFIG` transaction with the full
    /// channel configuration; it is the block to pass to other organizations'
    /// peers when joining them to the channel is not required, or to inspect
    /// the raw configuration envelope.
    pub async fn get_config_block(
        &self,
        channel_name: impl Into<String>,
    ) -> Result<Block, SystemChaincodeError> {
        let result_bytes = self
            .invoke_cscc("GetConfigBlock", vec![channel_name.into().into_bytes()])
            .await?;

        Block::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode Block"))
    }

    /// Fetches the current configuration of the given channel as a decoded
    /// [`Config`] tree (channel group with values, policies and sub-groups).
    ///
    /// This is the input for computing configuration updates, see
    /// [`compute_config_update`](crate::gateway::configtx::compute_config_update).
    pub async fn get_channel_config(
        &self,
        channel_name: impl Into<String>,
    ) -> Result<Config, SystemChaincodeError> {
        let result_bytes = self
            .invoke_cscc("GetChannelConfig", vec![channel_name.into().into_bytes()])
            .await?;

        Config::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode Config"))
    }

    /// Builds a channel-less `cscc` proposal, sends it to the peer's
    /// `Endorser.ProcessProposal` RPC and returns the raw response payload.
    async fn invoke_cscc(
        &self,
        function_name: &str,
        args: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, SystemChaincodeError> {
        let mut builder = self.client.get_chaincode_call_builder();
        builder
            .with_chaincode_id(CSCC_CHAINCODE)
            .map_err(SystemChaincodeError::from)?;
        builder.with_system_chaincode();
        builder
            .with_function_name(function_name)
            .map_err(SystemChaincodeError::from)?;
        builder
            .with_function_args(args)
            .map_err(SystemChaincodeError::from)?;
        let signed_proposal = builder.build().map_err(SystemChaincodeError::from)?;

        let proposal_response = self
            .client
            .process_proposal(signed_proposal)
            .await
            .map_err(SystemChaincodeError::from)?;

        let response = proposal_response
            .response
            .ok_or(SystemChaincodeError::EmptyResponse)?;

        if response.status != 200 {
            return Err(SystemChaincodeError::NodeError(response.message));
        }

        Ok(response.payload)
    }
}
