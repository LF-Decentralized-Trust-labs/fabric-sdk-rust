use std::{collections::HashMap, sync::Arc};

use crate::{
    chaincode::{Callable, Metadata, context::Context, message::MessageBuilder, router::Router},
    fabric::{
        common::Status,
        protos::{ChaincodeId, ChaincodeInput, ChaincodeMessage, Response, chaincode_message},
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

        let (transaction_queue_sender, transaction_queue_receiver) =
            futures_channel::mpsc::channel(100);
        let (peer_response_sender, peer_response_receiver) = futures_channel::mpsc::channel(100);

        let router =
            Router::new(metadata, transaction_queue_sender, peer_response_sender, rx).await;
        tokio::spawn(async move {
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
                    let (contract_name, function_name, arguments) =
                        match parse_invocation(&input.args) {
                            Ok(invocation) => invocation,
                            Err(reason) => {
                                // Caller input: a malformed invocation fails this
                                // one transaction, never the loop serving them all.
                                eprintln!("[MessageHandler] Invalid invocation: {reason}");
                                let response = Response {
                                    status: Status::BadRequest.into(),
                                    message: format!("Invalid chaincode invocation: {reason}"),
                                    payload: vec![],
                                };
                                self.message_builder
                                    .lock()
                                    .await
                                    .respond(
                                        chaincode_message::Type::Completed,
                                        response.encode_to_vec(),
                                        message,
                                    )
                                    .await;
                                continue;
                            }
                        };
                    let response = match self.contracts.get(&contract_name) {
                        Some(contract) => match contract.get(&function_name) {
                            Some(function) => {
                                match function
                                    .call(
                                        Context::new(
                                            self.message_builder.clone(),
                                            message.clone(),
                                            self.peer_response_queue.clone(),
                                        ),
                                        arguments,
                                    )
                                    .await
                                {
                                    Ok(result) => match result {
                                        Ok(message) => Response {
                                            status: Status::Success.into(),
                                            message: String::default(),
                                            payload: message.as_bytes().to_vec(),
                                        },
                                        Err(err) => Response {
                                            status: Status::InternalServerError.into(),
                                            message: format!(
                                                "An error occurred during the exection of the chaincode function: {err}"
                                            ),
                                            payload: vec![],
                                        },
                                    },
                                    Err(err) => Response {
                                        status: Status::InternalServerError.into(),
                                        message: format!(
                                            "An error occurred during the exection of the chaincode function: {err}"
                                        ),
                                        payload: vec![],
                                    },
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

                    self.message_builder
                        .lock()
                        .await
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
                    self.message_builder
                        .lock()
                        .await
                        .send(chaincode_message::Type::Error, error_text.encode_to_vec())
                        .await;
                    self.message_builder
                        .lock()
                        .await
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

/// Split an invocation's raw arguments into contract name, function name and
/// the function's arguments — or say why they are malformed.
///
/// The first argument names the function as `contract:function` (just
/// `function` for the default contract `""`); every argument must be UTF-8.
/// All of it is caller input, so nothing here may panic: this runs in the
/// loop that serves every transaction, outside the task that catches a
/// contract function's panics.
fn parse_invocation(args: &[Vec<u8>]) -> Result<(String, String, Vec<String>), String> {
    let mut arguments = args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            String::from_utf8(arg.clone()).map_err(|_| format!("argument {i} is not valid UTF-8"))
        })
        .collect::<Result<Vec<String>, String>>()?;
    if arguments.is_empty() {
        return Err("no function name given".to_string());
    }
    let target = arguments.remove(0);
    let parts: Vec<&str> = target.split(':').collect();
    let contract_name = if parts.len() > 1 { parts[0] } else { "" };
    let function_name = parts[parts.len() - 1];
    Ok((contract_name.to_string(), function_name.to_string(), arguments))
}

#[cfg(test)]
mod tests {
    use super::parse_invocation;

    fn args(list: &[&[u8]]) -> Vec<Vec<u8>> {
        list.iter().map(|a| a.to_vec()).collect()
    }

    #[test]
    fn a_well_formed_invocation_is_split() {
        let parsed = parse_invocation(&args(&[b"Process:invoke_step", b"p1", b"7"])).unwrap();
        assert_eq!(parsed, ("Process".into(), "invoke_step".into(), vec!["p1".into(), "7".into()]));
        // No contract part: the default contract.
        let parsed = parse_invocation(&args(&[b"whoami"])).unwrap();
        assert_eq!(parsed, (String::new(), "whoami".into(), vec![]));
    }

    #[test]
    fn a_malformed_invocation_is_an_error_not_a_panic() {
        assert!(parse_invocation(&[]).unwrap_err().contains("no function name"));
        let err = parse_invocation(&args(&[b"Process:get", &[0xff, 0xfe]])).unwrap_err();
        assert!(err.contains("argument 1"), "{err}");
        assert!(parse_invocation(&args(&[&[0xc3, 0x28]])).is_err());
    }
}
