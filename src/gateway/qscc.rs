use prost::Message;

use crate::{
    error::SystemChaincodeError,
    fabric::{
        common::{Block, BlockchainInfo},
        protos::ProcessedTransaction,
    },
    gateway::client::Client,
};

const QSCC_CHAINCODE: &str = "qscc";

/// Client for the Query System Chaincode (`qscc`).
///
/// Wraps the peer connection from [`Client`] and provides typed wrappers for
/// ledger queries: chain info, blocks (by number or transaction ID) and
/// processed transactions.
///
/// All operations are sent as channel-less proposals directly to the peer's
/// `Endorser.ProcessProposal` RPC (the channel is passed as a chaincode
/// argument instead), so they work on both native and WASM builds.
///
/// # Examples
///
/// ```rust
/// let qscc = client.get_qscc_client();
///
/// let info = qscc.get_chain_info("mychannel").await?;
/// println!("height: {}", info.height);
///
/// let block = qscc.get_block_by_number("mychannel", info.height - 1).await?;
/// ```
pub struct QsccClient<'a> {
    client: &'a Client,
}

impl<'a> QsccClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Returns the blockchain info of the given channel: current height and the
    /// hashes of the current and previous block.
    pub async fn get_chain_info(
        &self,
        channel_name: impl Into<String>,
    ) -> Result<BlockchainInfo, SystemChaincodeError> {
        let result_bytes = self
            .invoke_qscc("GetChainInfo", vec![channel_name.into().into_bytes()])
            .await?;

        BlockchainInfo::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode BlockchainInfo"))
    }

    /// Fetches the block with the given number from the given channel.
    pub async fn get_block_by_number(
        &self,
        channel_name: impl Into<String>,
        block_number: u64,
    ) -> Result<Block, SystemChaincodeError> {
        let result_bytes = self
            .invoke_qscc(
                "GetBlockByNumber",
                vec![
                    channel_name.into().into_bytes(),
                    block_number.to_string().into_bytes(),
                ],
            )
            .await?;

        Block::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode Block"))
    }

    /// Fetches the block containing the transaction with the given ID from the
    /// given channel.
    pub async fn get_block_by_tx_id(
        &self,
        channel_name: impl Into<String>,
        transaction_id: impl Into<String>,
    ) -> Result<Block, SystemChaincodeError> {
        let result_bytes = self
            .invoke_qscc(
                "GetBlockByTxID",
                vec![
                    channel_name.into().into_bytes(),
                    transaction_id.into().into_bytes(),
                ],
            )
            .await?;

        Block::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode Block"))
    }

    /// Fetches a committed transaction by its ID from the given channel.
    ///
    /// The returned [`ProcessedTransaction`] wraps the original transaction
    /// envelope together with its validation code.
    pub async fn get_transaction_by_id(
        &self,
        channel_name: impl Into<String>,
        transaction_id: impl Into<String>,
    ) -> Result<ProcessedTransaction, SystemChaincodeError> {
        let result_bytes = self
            .invoke_qscc(
                "GetTransactionByID",
                vec![
                    channel_name.into().into_bytes(),
                    transaction_id.into().into_bytes(),
                ],
            )
            .await?;

        ProcessedTransaction::decode(result_bytes.as_slice())
            .map_err(|_| SystemChaincodeError::DecodeError("Failed to decode ProcessedTransaction"))
    }

    /// Builds a channel-less `qscc` proposal, sends it to the peer's
    /// `Endorser.ProcessProposal` RPC and returns the raw response payload.
    async fn invoke_qscc(
        &self,
        function_name: &str,
        args: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, SystemChaincodeError> {
        let mut builder = self.client.get_chaincode_call_builder();
        builder
            .with_chaincode_id(QSCC_CHAINCODE)
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
