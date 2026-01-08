use futures_channel::mpsc::{Sender,Receiver};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri};
use futures_util::StreamExt;

use crate::{chaincode::Metadata, fabric::protos::{ChaincodeMessage, chaincode_message, chaincode_support_client::{self, ChaincodeSupportClient}}};

pub struct Router{
    ///The stream for messages from the peer to the contract
    rx: Receiver<ChaincodeMessage>,
    ///The client connecting to the peer. It will hold the connection as long as this contract runs
    client: ChaincodeSupportClient<Channel>,
    transaction_queue: Sender<ChaincodeMessage>,
    peer_response_queue: Sender<ChaincodeMessage>,
}
impl Router{
    pub async fn new(
        metadata: &Metadata,
        transaction_queue: Sender<ChaincodeMessage>,
        peer_response_queue: Sender<ChaincodeMessage>,
        rx: Receiver<ChaincodeMessage>
    ) -> Self {
        let root_cert = Certificate::from_pem(metadata.root_cert.as_bytes());

        let client_identity =
            Identity::from_pem(metadata.client_cert.clone(), metadata.client_key.clone());
        let tls_config = ClientTlsConfig::new()
            .ca_certificate(root_cert.clone())
            .identity(client_identity.clone());

        let uri_builder = Uri::builder()
            .scheme("https")
            .authority(metadata.peer_address.clone())
            .path_and_query("/");
        let channel = Channel::builder(uri_builder.build().expect("Invalid uri"))
            .tls_config(tls_config.clone())
            .expect("[Router] Invald TLS config")
            .rate_limit(100, std::time::Duration::from_secs(1))
            .concurrency_limit(256)
            .connect()
            .await
            .expect("[Router] Couldn't start gRPC channel");

        let client = chaincode_support_client::ChaincodeSupportClient::new(channel.clone());

        Router { rx, client, transaction_queue, peer_response_queue }
    }
    pub async fn run(mut self){
        let mut res = self
            .client
            .register(self.rx)
            .await
            .expect("[Router] Failed to register contract")
            .into_inner();
        while let Some(result) = res.next().await {
            match result {
                Ok(message) => match chaincode_message::Type::try_from(message.r#type) {
                    Ok(chaincode_message::Type::Registered) => {
                        eprintln!("[Router] Received Registered -> Current state is ESTABLISHED");
                    }
                    Ok(chaincode_message::Type::Ready) => {
                        eprintln!("[Router] Received ready -> Current state is READY");
                        eprintln!("[Router] ready for invocations");
                    }
                    Ok(chaincode_message::Type::Error) => {
                        eprintln!(
                            "[Router] Received Error: -> {}",
                            String::from_utf8_lossy(message.payload.as_slice())
                        );
                    }
                    Ok(chaincode_message::Type::Transaction) => {
                        eprintln!("[Router] Received transaction {}", message.txid);
                        if let Err(err) = self.transaction_queue.start_send(message){
                            eprintln!("[Router] Error seinding transaction into queue: {}",err);
                        }
                    }
                    Ok(chaincode_message::Type::Response) => {
                        eprintln!("[Router] Received response for {}", message.txid);
                        if let Err(err) = self.peer_response_queue.start_send(message){
                            eprintln!("[Router] Error seinding response into queue: {}",err);
                        }
                    }
                    _ => {
                        if let Ok(message_type) = chaincode_message::Type::try_from(message.r#type)
                        {
                            let error_text = format!(
                                "Unimplemented message type: {}",
                                message_type.as_str_name()
                            );
                            eprintln!("[Router] tx {}: {}", message.txid, error_text);
                        } else {
                            let error_text = format!("Unknown message type: {}", message.r#type);
                            eprintln!("[Router] tx {}: {}", message.txid, error_text);
                        }
                    }
                },
                Err(err) => {
                    let error_text = format!("[Router] Error receiving messages stream: Status {}", err);
                    eprintln!("{}", error_text);
                }
            }
        }
    }
}
