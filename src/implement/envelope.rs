use prost::{DecodeError, Message};

use crate::{
    error::SubmitError,
    fabric::{
        common::{Envelope, Payload},
        gateway::{CommitStatusResponse, SubmitRequest},
    },
    implement::crypto::{generate_nonce, generate_transaction_id},
};

impl Envelope {
    /// Submits the envelope to the network. This will update the ledger and fill the signature of the envelope.
    pub async fn submit(
        &mut self,
        client: &crate::gateway::client::Client,
    ) -> Result<&mut Self, SubmitError> {
        if client.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        //Generate random bytes for transaction id and signature header
        let nonce = generate_nonce();

        self.signature = client.identity.sign_message(&self.payload);

        //Create transaction id
        let transaction_id = generate_transaction_id(
            &nonce,
            client
                .identity
                .get_certificate_bytes()
                .encode_to_vec()
                .as_slice(),
        );

        let submit_request = SubmitRequest {
            transaction_id: transaction_id.clone(),
            channel_id: self
                .get_payload()
                .map_err(|_| SubmitError::DecodeError("Invalid payload"))?
                .get_header()
                .expect("Expected header in payload")
                .get_channel_header()
                .map_err(|_| SubmitError::DecodeError("Invalid header"))?
                .channel_id
                .to_string(),
            prepared_transaction: Some(self.clone()),
        };

        let mut gateway_client = client.create_gateway();

        match gateway_client.submit(submit_request).await {
            Ok(_) => Ok(self),
            Err(err) => Err(SubmitError::NodeError(
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }

    /// Waits for commit and returns the commit status
    ///
    /// This method will run until the commit will occur if it hasn’t already committed. So only run this immidentialy after [`submit`](submit).
    pub async fn wait_for_commit(
        &self,
        client: &crate::gateway::client::Client,
    ) -> Result<CommitStatusResponse, SubmitError> {
        let header = self
            .get_payload()
            .map_err(|_| SubmitError::DecodeError("Invalid payload"))?
            .get_header()
            .expect("No header in payload")
            .get_channel_header()
            .map_err(|_| SubmitError::DecodeError("Invalid Channel header in payload header"))?;
        client.commit_status(header.tx_id, header.channel_id).await
    }

    /// Decodes the payload from the envelope
    pub fn get_payload(&self) -> Result<Payload, DecodeError> {
        Payload::decode(self.payload.as_slice())
    }
}
