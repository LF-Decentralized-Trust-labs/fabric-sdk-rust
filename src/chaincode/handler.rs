use std::{collections::HashMap, sync::Arc};

use crate::{
    chaincode::{
        Callable, Metadata, context::Context, message::MessageBuilder, router::Router
    },
    fabric::{
        common::Status,
        protos::{
            ChaincodeId, ChaincodeInput, ChaincodeMessage, Response, chaincode_message,
        },
    },
};
use futures_channel::mpsc::Receiver;
use futures_util::StreamExt;
use prost::Message;
use tokio::sync::Mutex;

///Handles messages incoming from the peer. Also registers itself to the peer
pub struct MessageHandler {
    ///Contract registered by this chaincode
    contracts: HashMap<String, HashMap<String, Box<dyn Callable>>>,
    ///Helper struct to generate messages to the peer
    message_builder: Arc<Mutex<MessageBuilder>>,
    chaincode_id: ChaincodeId,
    transaction_queue: Receiver<ChaincodeMessage>,
    peer_response_queue: Arc<Mutex<Receiver<ChaincodeMessage>>>,
}
impl MessageHandler {
    pub async fn new(
        metadata: &Metadata,
        chaincode_id: ChaincodeId,
        contracts: HashMap<String, HashMap<String, Box<dyn Callable>>>,
    ) -> MessageHandler {
        let (tx, rx) = futures_channel::mpsc::channel::<ChaincodeMessage>(100);

        let (transaction_queue_sender,transaction_queue_receiver) = futures_channel::mpsc::channel(100);
        let (peer_response_sender,peer_response_receiver) = futures_channel::mpsc::channel(100);

        let router = Router::new(metadata,transaction_queue_sender,peer_response_sender,rx).await;
        tokio::spawn(async move{
            eprintln!("[Router] Starting router");
            router.run().await;
            eprintln!("[Router] Router stopped");
        });

        let mut message_builder = MessageBuilder::new(metadata, tx);
        eprintln!("Current state is CREATED");
        //Register this chaincode to the peer. This needs to be the very first message
        message_builder
            .send(
                chaincode_message::Type::Register,
                metadata.chaincode_id.encode_to_vec(),
            )
            .await;
        let message_builder = Arc::new(Mutex::new(message_builder));

        MessageHandler {
            contracts,
            message_builder,
            chaincode_id,
            transaction_queue: transaction_queue_receiver,
            peer_response_queue: Arc::new(Mutex::new(peer_response_receiver)),
        }
    }

    pub async fn run(mut self) {
        while let Some(message) = self.transaction_queue.next().await {
            eprintln!("[MessageHandler] Executing transaction {}", message.txid);
            match ChaincodeInput::decode(message.payload.as_slice()) {
                Ok(input) => {
                    //structname:functionname,arg1,arg2,arg3
                    //First argument is the contract:function
                    let arg_iter = input.args.iter();
                    let arguments = arg_iter
                        .map(|f| {
                            String::from_utf8(f.clone())
                                .expect("[MessageHandler] Invalid UTF-8 encoding")
                        })
                        .collect::<Vec<String>>();
                    let contract_function = arguments
                        .first()
                        .expect("[MessageHandler] Expected first argument but found nothing")
                        .split(":")
                        .collect::<Vec<&str>>();

                    let contract_name = if contract_function.len() > 1 {
                        contract_function
                            .first()
                            .expect("[MessageHandler] Expected contract_name but found nothing")
                    } else {
                        ""
                    };
                    let function_name = contract_function
                        .last()
                        .expect("[MessageHandler] Expected function_name but found nothing");
                    let response = match self.contracts.get(contract_name) {
                        Some(contract) => match contract.get(*function_name) {
                            Some(function) => {
                                match function.call(
                                    Context::new(self.message_builder.clone(), message.clone(), self.peer_response_queue.clone()),
                                    arguments
                                        .iter()
                                        .skip(1)
                                        .cloned()
                                        .collect::<Vec<String>>(),
                                ).await {
                                    Ok(result) => match result {
                                        Ok(message) => Response {
                                            status: Status::Success.into(),
                                            message,
                                            payload: vec![],
                                        },
                                        Err(err) => Response {
                                            status: Status::InternalServerError.into(),
                                            message: format!(
                                                "An error occurred during the exection of the chaincode function: {err}"
                                            ),
                                            payload: vec![],
                                        },
                                    }
                                    Err(err) => Response {
                                        status: Status::InternalServerError.into(),
                                        message: format!(
                                            "An error occurred during the exection of the chaincode function: {err}"
                                        ),
                                        payload: vec![],
                                    }
                                }
                            }
                            None => Response {
                                status: Status::NotFound.into(),
                                message: format!(
                                    "Function {function_name} not found in contract {contract_name} from chaincode {}",
                                    self.chaincode_id.name
                                ),
                                payload: vec![],
                            },
                        },
                        None => Response {
                            status: Status::NotFound.into(),
                            message: format!(
                                "Contract {contract_name} not found in chaincode {}",
                                self.chaincode_id.name
                            ),
                            payload: vec![],
                        },
                    };

                    self.message_builder.lock().await
                        .respond(
                            chaincode_message::Type::Completed,
                            response.encode_to_vec(),
                            message,
                        )
                        .await;
                }
                Err(err) => {
                    let error_text = format!("Invalid chaincode input; {}", err);
                    eprintln!("[MessageHandler] {}", error_text);
                    self.message_builder.lock().await
                        .send(
                            chaincode_message::Type::Error,
                            error_text.encode_to_vec(),
                        )
                        .await;
                    self.message_builder.lock().await
                        .send(
                            chaincode_message::Type::Response,
                            error_text.encode_to_vec(),
                        )
                        .await;
                }
            }
        }
        eprintln!("[MessageHandler] Channel closed")
    }
}
