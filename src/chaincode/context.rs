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
            GetQueryResult, GetState, GetStateByRange, GetStateMetadata, GetStateMultiple,
            GetStateMultipleResult, Proposal, PurgePrivateState, PutState, PutStateMetadata,
            QueryMetadata, QueryResponse, QueryResponseMetadata, QueryStateNext, SignedProposal,
            StateMetadata, StateMetadataResult, chaincode_message,
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

    /// Executes a rich (CouchDB Mango selector) query against the public state.
    ///
    /// `query` is a state-database-specific query string. For the CouchDB state
    /// database it is a Mango selector JSON document, e.g.
    /// `{"selector":{"docType":"asset","owner":"alice"}}`. The query is only
    /// supported when the network is backed by CouchDB; it is rejected by the
    /// default LevelDB state database.
    ///
    /// Rich queries are **read-only**: the result set is not re-validated at
    /// commit time and is not guaranteed to be stable across concurrent updates.
    /// They must therefore only be used from evaluate/query transactions, never
    /// to inform a write in an update transaction (doing so risks phantom reads
    /// that the peer cannot detect, leading to non-deterministic commits).
    pub async fn get_query_result(&self, query: &str) -> RangeResult {
        self.get_query_result_inner(query, "").await
    }

    /// Executes a rich query scoped to a private data collection. See
    /// [get_query_result](Self::get_query_result) for the read-only caveat.
    pub async fn get_private_data_query_result(
        &self,
        collection: &str,
        query: &str,
    ) -> RangeResult {
        self.get_query_result_inner(query, collection).await
    }

    async fn get_query_result_inner(&self, query: &str, collection: &str) -> RangeResult {
        let payload = GetQueryResult {
            query: query.to_string(),
            collection: collection.to_string(),
            metadata: vec![],
        }
        .encode_to_vec();

        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(
                chaincode_message::Type::GetQueryResult,
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

    /// Executes a paginated rich query against the public state.
    ///
    /// `page_size` bounds the number of records returned in this page and
    /// `bookmark` resumes from a previous page (pass `""` for the first page).
    /// The returned [QueryResponseMetadata] carries the bookmark to feed into
    /// the next call as well as the number of records actually fetched.
    ///
    /// Like [get_query_result](Self::get_query_result), this is read-only and
    /// must only be used from evaluate/query transactions. Pagination is
    /// honoured by the peer for query/evaluate calls only; it is ignored inside
    /// update transactions.
    pub async fn get_query_result_with_pagination(
        &self,
        query: &str,
        page_size: i32,
        bookmark: &str,
    ) -> (RangeResult, QueryResponseMetadata) {
        let metadata = QueryMetadata {
            page_size,
            bookmark: bookmark.to_string(),
        }
        .encode_to_vec();

        let payload = GetQueryResult {
            query: query.to_string(),
            collection: String::new(),
            metadata,
        }
        .encode_to_vec();

        let message_context = self.message.clone();
        self.message_builder
            .lock()
            .await
            .respond(
                chaincode_message::Type::GetQueryResult,
                payload,
                message_context,
            )
            .await;
        self.paginated_response().await
    }

    /// Executes a paginated range query against the public state. See
    /// [get_state_by_range](Self::get_state_by_range) for the range semantics
    /// and [get_query_result_with_pagination](Self::get_query_result_with_pagination)
    /// for the bookmark/page-size semantics.
    pub async fn get_state_by_range_with_pagination(
        &self,
        start_key: &str,
        end_key: &str,
        page_size: i32,
        bookmark: &str,
    ) -> (RangeResult, QueryResponseMetadata) {
        let start_key = if start_key.is_empty() {
            UNSPECIFIED_START_KEY
        } else {
            start_key
        };
        let metadata = QueryMetadata {
            page_size,
            bookmark: bookmark.to_string(),
        }
        .encode_to_vec();

        let payload = GetStateByRange {
            start_key: start_key.to_string(),
            end_key: end_key.to_string(),
            collection: String::new(),
            metadata,
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
        self.paginated_response().await
    }

    /// Receives a [QueryResponse] from the peer and splits it into a streaming
    /// [RangeResult] and the decoded [QueryResponseMetadata] (page bookmark).
    /// Shared by the paginated query and range variants.
    async fn paginated_response(&self) -> (RangeResult, QueryResponseMetadata) {
        let response = self
            .peer_response_queue
            .lock()
            .await
            .next()
            .await
            .expect("[Context] Failed to receive response from channel");
        let query_response = QueryResponse::decode(response.payload.as_slice())
            .expect("[Context] Invalid query response");
        let response_metadata = QueryResponseMetadata::decode(query_response.metadata.as_slice())
            .expect("[Context] Invalid query response metadata");
        let range_result = RangeResult::new(
            self.message_builder.clone(),
            self.peer_response_queue.clone(),
            self.message.clone(),
            query_response,
        );
        (range_result, response_metadata)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chaincode::Metadata, fabric::protos::QueryResultBytes};
    use futures_channel::mpsc;

    /// A throw-away PKCS#8 P-256 key, only used to satisfy [MessageBuilder]
    /// construction in tests. It signs nothing meaningful here because
    /// `respond` reuses the incoming message envelope rather than minting one.
    const TEST_PKEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgX48vuTYmToNK7Vhj\n\
TUpOdvuVbiTBja4l/LU5SY5dFUqhRANCAASjBNGw6SLD+OgaUvE0HZ2K+8uK3rlT\n\
oVrYCtFE61mTSrjr8Bs3WyglOTxz3K5jlyukIsCmPqmvpAt9EwmBpCOE\n\
-----END PRIVATE KEY-----\n";

    fn test_metadata() -> Metadata {
        Metadata {
            chaincode_id: "test-cc".to_string(),
            mspid: "Org1MSP".to_string(),
            peer_address: String::new(),
            client_cert: String::new(),
            client_key: TEST_PKEY.to_string(),
            root_cert: String::new(),
        }
    }

    /// Wraps a value in the [QueryResultBytes]/[Kv] envelope the peer uses for
    /// range and rich-query results.
    fn kv_result(key: &str, value: &[u8]) -> QueryResultBytes {
        QueryResultBytes {
            result_bytes: Kv {
                namespace: "test-cc".to_string(),
                key: key.to_string(),
                value: value.to_vec(),
            }
            .encode_to_vec(),
        }
    }

    #[tokio::test]
    async fn get_query_result_forwards_selector_and_iterates_results() {
        // Channel the Context writes its outbound shim messages to.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<ChaincodeMessage>(10);
        // Channel the (mocked) peer pushes its replies onto.
        let (mut peer_tx, peer_rx) = mpsc::channel::<ChaincodeMessage>(10);

        // Mock the peer's reply: a QueryResponse with two records.
        let query_response = QueryResponse {
            results: vec![
                kv_result("asset1", b"value1"),
                kv_result("asset2", b"value2"),
            ],
            has_more: false,
            id: String::new(),
            metadata: vec![],
        };
        peer_tx
            .try_send(ChaincodeMessage {
                payload: query_response.encode_to_vec(),
                ..Default::default()
            })
            .expect("failed to queue mock peer reply");

        let message_builder = MessageBuilder::new(&test_metadata(), outbound_tx);
        let context = Context::new(
            Arc::new(Mutex::new(message_builder)),
            ChaincodeMessage::default(),
            Arc::new(Mutex::new(peer_rx)),
        );

        let selector = r#"{"selector":{"docType":"asset"}}"#;
        let range_result = context.get_query_result(selector).await;

        // The selector must be forwarded verbatim in a GET_QUERY_RESULT message.
        let sent = outbound_rx
            .try_next()
            .expect("no message was sent")
            .expect("outbound channel closed");
        assert_eq!(
            sent.r#type,
            chaincode_message::Type::GetQueryResult as i32,
            "expected a GET_QUERY_RESULT message"
        );
        let get_query_result = GetQueryResult::decode(sent.payload.as_slice())
            .expect("payload was not a GetQueryResult");
        assert_eq!(get_query_result.query, selector);
        assert!(get_query_result.collection.is_empty());

        // RangeResult must iterate the returned KV values in order.
        let values: Vec<Vec<u8>> = range_result.collect();
        assert_eq!(values, vec![b"value1".to_vec(), b"value2".to_vec()]);
    }
}

