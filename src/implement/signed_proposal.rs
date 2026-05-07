use prost::{DecodeError, Message};

use crate::{
    error::SubmitError,
    fabric::{
        gateway::EndorseRequest,
        protos::{Proposal, SignedProposal},
    },
};

impl SignedProposal {
    pub fn get_proposal(&self) -> Result<Proposal, DecodeError> {
        Proposal::decode(self.proposal_bytes.as_slice())
    }

    /// Consumes and sends the endorsement request to the peer and returns the proposed transaction. This will not update the ledger.
    pub async fn endorse(
        self,
        client: &crate::gateway::client::Client,
    ) -> Result<crate::fabric::common::Envelope, SubmitError> {
        if client.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let mut gateway_client = client.create_gateway();
        let header = self
            .get_proposal()
            .expect("Invalid proposal bytes")
            .get_header()
            .unwrap()
            .get_channel_header()
            .unwrap();

        let endorse_request = EndorseRequest {
            transaction_id: header.tx_id,
            channel_id: header.channel_id,
            proposed_transaction: Some(self),
            endorsing_organizations: vec![], //Currently empty since private data is not implemented yet
        };
        //First transaction will be endorsed to the network
        let response = gateway_client.endorse(endorse_request).await;
        match response {
            Ok(response) => match response.into_inner().prepared_transaction {
                Some(envelope) => Ok(envelope),
                None => Err(SubmitError::EmptyRespone),
            },
            Err(err) => Err(SubmitError::NodeError(
                crate::implement::grpc_error::format_grpc_error(&err),
            )),
        }
    }
}
