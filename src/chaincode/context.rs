use std::{collections::HashMap, sync::Arc};

use futures_channel::mpsc::Receiver;
use futures_util::StreamExt;
use prost::Message;
use tokio::sync::Mutex;

use crate::{
    chaincode::message::MessageBuilder,
    fabric::{
        common::{ChannelHeader, Header, SignatureHeader},
        protos::{
            ChaincodeEvent, ChaincodeMessage, ChaincodeProposalPayload, DelState, GetHistoryForKey,
            GetState, GetStateByRange, GetStateMetadata, GetStateMultiple, GetStateMultipleResult,
            Proposal, PurgePrivateState, PutState, PutStateMetadata, QueryResponse, QueryStateNext,
            SignedProposal, StateMetadata, StateMetadataResult, chaincode_message,
        },
        queryresult::Kv,
    },
};

static UNSPECIFIED_START_KEY: &str = "\u{0001}";

/// Reserved metadata key used by Fabric to store the state-based endorsement
/// policy (validation parameter) of a key.
static VALIDATION_PARAMETER: &str = "VALIDATION_PARAMETER";

#[derive(Clone)]
pub struct Context {
    pub(crate) message_builder: Arc<Mutex<MessageBuilder>>,
    pub(crate) peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
    pub(crate) message: ChaincodeMessage,
}
impl Context {
    pub(crate) fn new(
        message_builder: Arc<Mutex<MessageBuilder>>,
        message: ChaincodeMessage,
        peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
    ) -> Context {
        Context {
            message_builder,
            message,
            peer_response_queue,
        }
    }

    //Getter

    pub async fn get_state(&self, key: &str) -> Vec<u8> {
        self.get_state_inner(key, "").await
    }

    pub async fn get_state_string(&self, key: &str) -> String {
        String::from_utf8(self.get_state(key).await).expect("[Context] Invalid UTF-8 encoding")
    }

    /// Reads a value from a private data collection. Returns the value (or an
    /// empty buffer if the key does not exist or the caller is not authorized).
    pub async fn get_private_data(&self, collection: &str, key: &str) -> Vec<u8> {
        self.get_state_inner(key, collection).await
    }

    pub async fn get_private_data_string(&self, collection: &str, key: &str) -> String {
        String::from_utf8(self.get_private_data(collection, key).await)
            .expect("[Context] Invalid UTF-8 encoding")
    }

    /// Returns the hash of the value stored under `key` in `collection`.
    /// Unlike [get_private_data](Self::get_private_data), this works for peers
    /// that are not members of the collection, since only the hash (which is
    /// committed to every peer's ledger) is required.
    pub async fn get_private_data_hash(&self, collection: &str, key: &str) -> Vec<u8> {
        let payload = GetState {
            key: key.to_string(),
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(
                chaincode_message::Type::GetPrivateDataHash,
                payload,
                message_context,
            )
            .await;
        self.peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel")
            .payload
    }

    async fn get_state_inner(&self, key: &str, collection: &str) -> Vec<u8> {
        let payload = GetState {
            key: key.to_string(),
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::GetState, payload, message_context)
            .await;
        self.peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel")
            .payload
    }

    pub async fn get_state_by_range(&self, start_key: &str, end_key: &str) -> RangeResult {
        self.get_state_by_range_inner(start_key, end_key, "").await
    }

    /// Executes a range query over a private data collection.
    pub async fn get_private_data_by_range(
        &self,
        collection: &str,
        start_key: &str,
        end_key: &str,
    ) -> RangeResult {
        self.get_state_by_range_inner(start_key, end_key, collection)
            .await
    }

    async fn get_state_by_range_inner(
        &self,
        start_key: &str,
        end_key: &str,
        collection: &str,
    ) -> RangeResult {
        let start_key = if start_key.is_empty() {
            UNSPECIFIED_START_KEY
        } else {
            start_key
        };

        let payload = GetStateByRange {
            start_key: start_key.to_string(),
            end_key: end_key.to_string(),
            collection: collection.to_string(),
            metadata: vec![],
        }
        .encode_to_vec();

        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(
                chaincode_message::Type::GetStateByRange,
                payload,
                message_context,
            )
            .await;
        let response = self
            .peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
        let query_response = QueryResponse::decode(response.payload.as_slice())
            .expect("[Context] Invalid query response");
        RangeResult::new(
            self.message_builder.clone(),
            self.peer_response_queue.clone(),
            self.message.clone(),
            query_response,
        )
    }

    //Setter

    pub async fn put_state(&self, key: &str, value: Vec<u8>) {
        self.put_state_inner(key, value, "").await;
    }

    pub async fn put_state_string(&self, key: &str, value: &str) {
        self.put_state(key, value.as_bytes().to_vec()).await;
    }

    /// Writes a value into a private data collection. The value is recorded in
    /// the transaction's private write set; only its hash is committed to the
    /// public ledger.
    pub async fn put_private_data(&self, collection: &str, key: &str, value: Vec<u8>) {
        self.put_state_inner(key, value, collection).await;
    }

    pub async fn put_private_data_string(&self, collection: &str, key: &str, value: &str) {
        self.put_private_data(collection, key, value.as_bytes().to_vec())
            .await;
    }

    async fn put_state_inner(&self, key: &str, value: Vec<u8>, collection: &str) {
        let payload = PutState {
            key: key.to_string(),
            value,
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::PutState, payload, message_context)
            .await;
        self.peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
    }

    pub async fn del_state(&self, key: &str) {
        self.del_state_inner(key, "").await;
    }

    /// Deletes a key from a private data collection. History is retained; use
    /// [purge_private_data](Self::purge_private_data) to remove it entirely.
    pub async fn del_private_data(&self, collection: &str, key: &str) {
        self.del_state_inner(key, collection).await;
    }

    async fn del_state_inner(&self, key: &str, collection: &str) {
        let payload = DelState {
            key: key.to_string(),
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::DelState, payload, message_context)
            .await;
        self.peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
    }

    pub async fn get_history_for_key(&self, key: &str) -> HistoryResult {
        let payload = GetHistoryForKey {
            key: key.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::GetHistoryForKey, payload, message_context)
            .await;
        let response = self
            .peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
        let query_response = QueryResponse::decode(response.payload.as_slice())
            .expect("[Context] Invalid query response");
        HistoryResult::new(
            self.message_builder.clone(),
            self.peer_response_queue.clone(),
            self.message.clone(),
            query_response,
        )
    }

    pub async fn get_state_metadata(&self, key: &str) -> Vec<StateMetadata> {
        self.get_state_metadata_inner(key, "").await
    }

    /// Returns the metadata associated with `key` in a private data collection.
    pub async fn get_private_data_metadata(
        &self,
        collection: &str,
        key: &str,
    ) -> Vec<StateMetadata> {
        self.get_state_metadata_inner(key, collection).await
    }

    async fn get_state_metadata_inner(&self, key: &str, collection: &str) -> Vec<StateMetadata> {
        let payload = GetStateMetadata {
            key: key.to_string(),
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::GetStateMetadata, payload, message_context)
            .await;
        let response = self
            .peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
        let result = StateMetadataResult::decode(response.payload.as_slice())
            .expect("[Context] Invalid state metadata result");
        result.entries
    }

    pub async fn get_state_multiple(&self, keys: Vec<String>) -> Vec<Vec<u8>> {
        self.get_state_multiple_inner(keys, "").await
    }

    /// Reads multiple keys from a private data collection in a single call.
    pub async fn get_private_data_multiple(
        &self,
        collection: &str,
        keys: Vec<String>,
    ) -> Vec<Vec<u8>> {
        self.get_state_multiple_inner(keys, collection).await
    }

    async fn get_state_multiple_inner(&self, keys: Vec<String>, collection: &str) -> Vec<Vec<u8>> {
        let payload = GetStateMultiple {
            keys,
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::GetStateMultiple, payload, message_context)
            .await;
        let response = self
            .peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
        let result = GetStateMultipleResult::decode(response.payload.as_slice())
            .expect("[Context] Invalid get state multiple result");
        result.values
    }

    /// Purges a key from a private data collection, removing it (and its
    /// history) entirely from the peers. Unlike
    /// [del_private_data](Self::del_private_data), purged data leaves no trace.
    pub async fn purge_private_data(&self, collection: &str, key: &str) {
        let payload = PurgePrivateState {
            key: key.to_string(),
            collection: collection.to_string(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::PurgePrivateData, payload, message_context)
            .await;
        self.peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
    }

    /// Deprecated alias for [purge_private_data](Self::purge_private_data).
    /// Note the swapped argument order: this takes `(key, collection)`.
    #[deprecated(note = "use purge_private_data(collection, key) instead")]
    pub async fn purge_private_state(&self, key: &str, collection: &str) {
        self.purge_private_data(collection, key).await;
    }

    pub async fn put_state_metadata(&self, key: &str, metadata: Vec<StateMetadata>) {
        self.put_state_metadata_inner(key, metadata, "").await;
    }

    /// Sets the metadata for `key` in a private data collection.
    pub async fn put_private_data_metadata(
        &self,
        collection: &str,
        key: &str,
        metadata: Vec<StateMetadata>,
    ) {
        self.put_state_metadata_inner(key, metadata, collection)
            .await;
    }

    /// Sets the key-level (state-based) endorsement policy for `key` in a
    /// private data collection. `endorsement_policy` is the marshalled
    /// `ApplicationPolicy`/`SignaturePolicyEnvelope` bytes.
    pub async fn set_private_data_validation_parameter(
        &self,
        collection: &str,
        key: &str,
        endorsement_policy: Vec<u8>,
    ) {
        let metadata = StateMetadata {
            metakey: VALIDATION_PARAMETER.to_string(),
            value: endorsement_policy,
        };
        self.put_state_metadata_inner(key, vec![metadata], collection)
            .await;
    }

    async fn put_state_metadata_inner(
        &self,
        key: &str,
        metadata: Vec<StateMetadata>,
        collection: &str,
    ) {
        let payload = PutStateMetadata {
            key: key.to_string(),
            collection: collection.to_string(),
            metadata: metadata.into_iter().next(),
        }
        .encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(chaincode_message::Type::PutStateMetadata, payload, message_context)
            .await;
        self.peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
    }

    /// Decodes the [Proposal] carried by the chaincode message, if present.
    fn decode_proposal(&self) -> Option<Proposal> {
        self.message.proposal.as_ref().map(|proposal| {
            Proposal::decode(proposal.proposal_bytes.as_slice()).expect("Invalid proposal bytes")
        })
    }

    /// Returns the transaction timestamp in seconds.
    pub fn get_tx_timestamp(&self) -> i64 {
        let proposal = self.decode_proposal().expect("No signed proposal");
        let header = Header::decode(proposal.header.as_slice()).expect("Invalid header");
        let channel_header = ChannelHeader::decode(header.channel_header.as_slice())
            .expect("Invalid channel header");
        channel_header.timestamp.expect("No timestamp").seconds
    }

    /// Returns the channel id of the chaincode message. This value is being cloned.
    pub fn get_channel_id(&self) -> String {
        self.message.channel_id.clone()
    }

    /// Returns the transaction id of the chaincode message. This value is being cloned.
    pub fn get_tx_id(&self) -> String {
        self.message.txid.clone()
    }

    /// Returns the signed proposal of the chaincode message. This value is being cloned.
    pub fn get_signed_proposal(&self) -> SignedProposal {
        self.message
            .proposal
            .clone()
            .expect("No signed proposal found")
    }

    /// Returns the chaincode event of the chaincode message. This value is being cloned.
    pub fn get_event(&self) -> Option<ChaincodeEvent> {
        self.message.chaincode_event.clone()
    }

    /// Returns the identity of the agent (or user) submitting the transaction.
    pub fn get_creator(&self) -> Vec<u8> {
        let proposal = match self.decode_proposal() {
            Some(proposal) => proposal,
            None => return Vec::new(),
        };
        let header = Header::decode(proposal.header.as_slice()).expect("Invalid header");
        let signature_header = SignatureHeader::decode(header.signature_header.as_slice())
            .expect("Invalid signature header");
        signature_header.creator
    }

    /// Returns the transient map of the transaction.
    ///
    /// The transient map carries private data supplied by the client that is
    /// never written to the public ledger. It is the standard mechanism for
    /// passing values destined for a private data collection into the chaincode.
    pub fn get_transient_map(&self) -> HashMap<String, Vec<u8>> {
        let proposal = match self.decode_proposal() {
            Some(proposal) => proposal,
            None => return HashMap::new(),
        };
        ChaincodeProposalPayload::decode(proposal.payload.as_slice())
            .expect("Invalid chaincode proposal payload")
            .transient_map
    }

    /// Returns a single value from the transient map by key, if present.
    pub fn get_transient(&self, key: &str) -> Option<Vec<u8>> {
        self.get_transient_map().remove(key)
    }
}
pub struct RangeResult {
    message_builder: Arc<Mutex<MessageBuilder>>,
    peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
    message: ChaincodeMessage,
    query_response: QueryResponse,
    results: Vec<Vec<u8>>,
    index: usize,
}
impl RangeResult {
    pub fn new(
        message_builder: Arc<Mutex<MessageBuilder>>,
        peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
        message: ChaincodeMessage,
        query_response: QueryResponse,
    ) -> Self {
        let results = query_response
            .results
            .iter()
            .map(|f| Kv::decode(f.result_bytes.as_slice()).expect("Invalid KV"))
            .map(|f| f.value)
            .collect::<Vec<Vec<u8>>>();
        RangeResult {
            message_builder,
            peer_response_queue,
            message,
            query_response,
            results,
            index: 0,
        }
    }
}
impl Iterator for RangeResult {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.results.len() {
            //We still have some results in our buffer
            self.index += 1;
            self.results.get(self.index - 1).cloned()
        } else {
            //our buffer has been iterated through -> check if the node has more
            if self.query_response.has_more {
                //Request more from node
                let payload = QueryStateNext {
                    id: self.query_response.id.clone(),
                }
                .encode_to_vec();
                let message_context = self.message.clone();
                let message_builder = self.message_builder.clone();
                tokio::spawn(async move {
                    message_builder
                        .lock()
                        .await
                        .respond(
                            chaincode_message::Type::QueryStateNext,
                            payload,
                            message_context,
                        )
                        .await;
                });
                loop {
                    match self.peer_response_queue.blocking_lock().try_next() {
                        Ok(Some(response)) => {
                            let query_response = QueryResponse::decode(response.payload.as_slice())
                                .expect("[Context] Invalid query response");
                            self.query_response = query_response;
                            self.index = 1;
                            self.results = self
                                .query_response
                                .results
                                .iter()
                                .map(|f| Kv::decode(f.result_bytes.as_slice()).expect("Invalid KV"))
                                .map(|f| f.value)
                                .collect::<Vec<Vec<u8>>>();
                            return self.results.first().cloned();
                        }
                        Ok(None) => {
                            panic!("[Context] Query Channel is closed")
                        }
                        Err(_) => {}
                    }
                }
            } else {
                None
            }
        }
    }
}

pub struct HistoryResult {
    message_builder: Arc<Mutex<MessageBuilder>>,
    peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
    message: ChaincodeMessage,
    query_response: QueryResponse,
    results: Vec<Vec<u8>>,
    index: usize,
}

impl HistoryResult {
    pub fn new(
        message_builder: Arc<Mutex<MessageBuilder>>,
        peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
        message: ChaincodeMessage,
        query_response: QueryResponse,
    ) -> Self {
        let results = query_response
            .results
            .iter()
            .map(|f| Kv::decode(f.result_bytes.as_slice()).expect("Invalid KV"))
            .map(|f| f.value)
            .collect::<Vec<Vec<u8>>>();
        HistoryResult {
            message_builder,
            peer_response_queue,
            message,
            query_response,
            results,
            index: 0,
        }
    }
}

impl Iterator for HistoryResult {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.results.len() {
            //We still have some results in our buffer
            self.index += 1;
            self.results.get(self.index - 1).cloned()
        } else {
            //our buffer has been iterated through -> check if the node has more
            if self.query_response.has_more {
                //Request more from node
                let payload = QueryStateNext {
                    id: self.query_response.id.clone(),
                }
                .encode_to_vec();
                let message_context = self.message.clone();
                let message_builder = self.message_builder.clone();
                tokio::spawn(async move {
                    message_builder
                        .lock()
                        .await
                        .respond(
                            chaincode_message::Type::QueryStateNext,
                            payload,
                            message_context,
                        )
                        .await;
                });
                loop {
                    match self.peer_response_queue.blocking_lock().try_next() {
                        Ok(Some(response)) => {
                            let query_response = QueryResponse::decode(response.payload.as_slice())
                                .expect("[Context] Invalid query response");
                            self.query_response = query_response;
                            self.index = 1;
                            self.results = self
                                .query_response
                                .results
                                .iter()
                                .map(|f| Kv::decode(f.result_bytes.as_slice()).expect("Invalid KV"))
                                .map(|f| f.value)
                                .collect::<Vec<Vec<u8>>>();
                            return self.results.first().cloned();
                        }
                        Ok(None) => {
                            panic!("[Context] Query Channel is closed")
                        }
                        Err(_) => {}
                    }
                }
            } else {
                None
            }
        }
    }
}

