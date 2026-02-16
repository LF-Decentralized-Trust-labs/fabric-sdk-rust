use futures_channel::mpsc::Sender;

use crate::{
    chaincode::Metadata,
    fabric::protos::{ChaincodeMessage, chaincode_message},
    gateway::chaincode::ChaincodeCallBuilder,
    identity::IdentityBuilder,
};

pub struct MessageBuilder {
    tx: Sender<ChaincodeMessage>,
    chaincode_call_builder: crate::gateway::chaincode::ChaincodeCallBuilder,
}
impl MessageBuilder {
    pub fn new(metadata: &Metadata, tx: Sender<ChaincodeMessage>) -> MessageBuilder {
        let identity = IdentityBuilder::from_pem(&metadata.root_cert.clone().into_bytes())
            .expect("Invalid certificate")
            .with_msp(metadata.mspid.clone())
            .expect("Invalid msp")
            .with_private_key(metadata.client_key.as_bytes().to_vec())
            .expect("Invalid private key")
            .build()
            .expect("Could not build identity with provided data");
        MessageBuilder {
            tx,
            chaincode_call_builder: ChaincodeCallBuilder {
                identity,
                channel_name: None,
                chaincode_id: Some(metadata.chaincode_id.clone()),
                contract_id: None,
                function_name: None,
                function_args: vec![],
                proposal: None,
                header: None,
                nonce: None,
                transaction_id: None,
            },
        }
    }

    pub async fn send(&mut self, r#type: chaincode_message::Type, payload: Vec<u8>) {
        let message = self
            .chaincode_call_builder
            .generate_chaincode_message(r#type, payload)
            .expect("Failed creating message");
        self.tx.start_send(message).unwrap();
    }
    pub async fn respond(
        &mut self,
        r#type: chaincode_message::Type,
        payload: Vec<u8>,
        message: ChaincodeMessage,
    ) {
        let message = ChaincodeMessage {
            r#type: r#type.into(),
            timestamp: message.timestamp,
            payload,
            txid: message.txid,
            proposal: message.proposal,
            chaincode_event: message.chaincode_event,
            channel_id: message.channel_id,
        };
        self.tx.start_send(message).unwrap();
        self.chaincode_call_builder.with_transaction_id(None);
        self.chaincode_call_builder.with_proposal(None);
    }
}
