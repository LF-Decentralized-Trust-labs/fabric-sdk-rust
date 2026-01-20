use std::sync::Arc;

use futures_channel::mpsc::Receiver;
use futures_util::StreamExt;
use prost::Message;
use tokio::sync::Mutex;

use crate::{chaincode::message::MessageBuilder, fabric::{common::{ChannelHeader, Header}, protos::{ChaincodeEvent, ChaincodeMessage, DelState, GetState, GetStateByRange, PutState, QueryResponse, SignedProposal, chaincode_message}}};

static UNSPECIFIED_START_KEY: &str = "\u{0001}";

#[derive(Clone)]
pub struct Context{
    pub(crate) message_builder: Arc<Mutex<MessageBuilder>>,
    pub(crate) peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
    pub(crate) message: ChaincodeMessage
}
impl Context{
    pub(crate) fn new(
        message_builder: Arc<Mutex<MessageBuilder>>,
        message: ChaincodeMessage,
        peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
    ) -> Context{
        Context { message_builder, message, peer_response_queue }
    }

    //Getter

    pub async fn get_state(&self, key: &str) -> Vec<u8> {
        let payload = GetState{
            key: key.to_string(),
            collection: String::new(), //TODO Implement Collection (private write set)
        }.encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder.lock().await.respond(chaincode_message::Type::GetState, payload, message_context).await;
        self.peer_response_queue.lock().await.next().await.expect("[Context] Failed to receive response from channel").payload
    }

    pub async fn get_state_string(&self, key: &str) -> String {
        String::from_utf8(self.get_state(key).await).expect("[Context] Invalid UTF-8 encoding")
    }

    pub async fn get_state_by_range(&self, start_key: &str, end_key: &str) -> Vec<Vec<u8>> {
        let start_key = if start_key.is_empty() {
            UNSPECIFIED_START_KEY
        }else{start_key};

        let payload = GetStateByRange{
            start_key: start_key.to_string(),
            end_key: end_key.to_string(),
            collection: String::new(), //TODO Implement Collection (private write set),
            metadata: vec![],
        }.encode_to_vec();

        let message_context = self.message.clone();
        self.message_builder.lock().await.respond(chaincode_message::Type::GetStateByRange, payload, message_context).await;
        let response = self.peer_response_queue.lock().await.next().await.expect("[Context] Failed to receive response from channel");
        let query_response = QueryResponse::decode(response.payload.as_slice()).expect("[Context] Invalid query response");
        query_response.results.iter().cloned().map(|f| f.result_bytes).collect::<Vec<Vec<u8>>>()
    }

    //Setter

    pub async fn put_state(&self, key: &str, value: Vec<u8>) {
        let payload = PutState{
            key: key.to_string(),
            value,
            collection: String::new(), //TODO Implement Collection (private write set)
        }.encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder.lock().await.respond(chaincode_message::Type::PutState, payload, message_context).await;
        self.peer_response_queue.lock().await.next().await.expect("[Context] Failed to receive response from channel");
    }

    pub async fn put_state_string(&self, key: &str, value: &str) {
        self.put_state(key, value.as_bytes().to_vec()).await;
    }

    pub async fn del_state(&self, key: &str) {
        let payload = DelState{
            key: key.to_string(),
            collection: String::new(), //TODO Implement Collection (private write set)
        }.encode_to_vec();
        let message_context = self.message.clone();
        self.message_builder.lock().await.respond(chaincode_message::Type::DelState, payload, message_context).await;
        self.peer_response_queue.lock().await.next().await.expect("[Context] Failed to receive response from channel");
    }

    /*
     * final Proposal proposal = Proposal.parseFrom(signedProposal.getProposalBytes());
                 final Header header = Header.parseFrom(proposal.getHeader());
                 final ChannelHeader channelHeader = ChannelHeader.parseFrom(header.getChannelHeader());
                 validateProposalType(channelHeader);
                 final SignatureHeader signatureHeader = SignatureHeader.parseFrom(header.getSignatureHeader());
                 final ChaincodeProposalPayload chaincodeProposalPayload =
                         ChaincodeProposalPayload.parseFrom(proposal.getPayload());
                 final Timestamp timestamp = channelHeader.getTimestamp();

                 this.txTimestamp = Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos());
                 this.creator = signatureHeader.getCreator();
                 this.transientMap = chaincodeProposalPayload.getTransientMapMap();
                 this.binding = computeBinding(channelHeader, signatureHeader);
     */

    /// Returns the transaction timestamp in seconds.
    pub fn get_tx_timestamp(&self) -> i64 {
        let header = Header::decode(self.message.proposal.as_ref().expect("No signed proposal").encode_to_vec().as_slice()).expect("Invalid header");
        let channel_header = ChannelHeader::decode(header.channel_header.as_slice()).expect("Invalid channel header");
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
        self.message.proposal.clone().expect("No signed proposal found")
    }

    /// Returns the chaincode event of the chaincode message. This value is being cloned.
    pub fn get_event(&self) -> Option<ChaincodeEvent>{
        self.message.chaincode_event.clone()
    }

    /// Returns the identity of the agent (or user) submitting the transaction.
    pub fn get_creator(&self) -> Vec<u8> {
        unimplemented!()
    }
}
