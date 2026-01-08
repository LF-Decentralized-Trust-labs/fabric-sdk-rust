use std::sync::Arc;

use futures_channel::mpsc::Receiver;
use futures_util::StreamExt;
use prost::Message;
use tokio::sync::Mutex;

use crate::{chaincode::message::MessageBuilder, fabric::protos::{ChaincodeMessage, DelState, GetState, GetStateByRange, PutState, QueryResponse, chaincode_message}};

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
}
