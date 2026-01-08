use futures_channel::mpsc::Sender;

use crate::{
    chaincode::Metadata,
    fabric::protos::{ChaincodeMessage, chaincode_message},
    signer::Signer,
    transaction::TransaktionBuilder,
};

pub struct MessageBuilder {
    tx: Sender<ChaincodeMessage>,
    transaktion_builder: crate::transaction::TransaktionBuilder,
}
impl MessageBuilder {
    pub fn new(metadata: &Metadata, tx: Sender<ChaincodeMessage>) -> MessageBuilder {
        MessageBuilder {
            tx,
            transaktion_builder: TransaktionBuilder {
                identity: crate::fabric::msp::SerializedIdentity {
                    mspid: metadata.mspid.clone(),
                    id_bytes: metadata.root_cert.clone().into_bytes(),
                },
                signer: Signer::new(metadata.client_key.as_bytes()),
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
            .transaktion_builder
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
        self.transaktion_builder.with_transaction_id(None);
        self.transaktion_builder.with_proposal(None);
    }
}
