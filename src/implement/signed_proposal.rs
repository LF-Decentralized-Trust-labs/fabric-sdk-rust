use prost::{DecodeError, Message};

use crate::fabric::protos::{Proposal, SignedProposal};

#[cfg(any(feature = "client", feature = "client-wasm"))]
use crate::{error::SubmitError, fabric::gateway::EndorseRequest};

impl SignedProposal {
    pub fn get_proposal(&self) -> Result<Proposal, DecodeError> {
        Proposal::decode(self.proposal_bytes.as_slice())
    }
}

#[cfg(any(feature = "client", feature = "client-wasm"))]
impl SignedProposal {
    /// Consumes and sends the endorsement request to the peer and returns the proposed transaction. This will not update the ledger.
    pub async fn endorse(
        self,
        client: &crate::gateway::client::Client,
    ) -> Result<crate::fabric::common::Envelope, SubmitError> {
        self.endorse_with_organizations(client, vec![]).await
    }

    /// Like [endorse](Self::endorse) but restricts endorsement to peers of the
    /// given organizations (MSP IDs). Required for private data transactions,
    /// where only collection member organizations are able to endorse.
    pub async fn endorse_with_organizations(
        self,
        client: &crate::gateway::client::Client,
        endorsing_organizations: Vec<String>,
    ) -> Result<crate::fabric::common::Envelope, SubmitError> {
        if client.tonic_connection.channel.is_none() {
            return Err(SubmitError::NotConnected);
        }
        let mut gateway_client = client.create_gateway();
        let header = self.channel_header()?;

        let endorse_request = EndorseRequest {
            transaction_id: header.tx_id,
            channel_id: header.channel_id,
            proposed_transaction: Some(self),
            endorsing_organizations,
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

    /// The channel header of the proposal. A `SignedProposal` can be built
    /// from any bytes, so a malformed one is an error, not a panic.
    fn channel_header(&self) -> Result<crate::fabric::common::ChannelHeader, SubmitError> {
        self.get_proposal()
            .map_err(|_| SubmitError::DecodeError("Invalid proposal bytes"))?
            .get_header()
            .map_err(|_| SubmitError::DecodeError("Invalid proposal header"))?
            .get_channel_header()
            .map_err(|_| SubmitError::DecodeError("Invalid channel header in proposal header"))
    }
}

#[cfg(all(test, any(feature = "client", feature = "client-wasm")))]
mod tests {
    use super::*;
    use crate::fabric::common::{ChannelHeader, Header};

    #[test]
    fn channel_header_errors_instead_of_panicking() {
        let garbage = SignedProposal {
            proposal_bytes: vec![0xff, 0xff],
            signature: vec![],
        };
        assert!(matches!(
            garbage.channel_header(),
            Err(SubmitError::DecodeError("Invalid proposal bytes"))
        ));
        let bad_header = SignedProposal {
            proposal_bytes: Proposal {
                header: vec![0xff, 0xff],
                ..Default::default()
            }
            .encode_to_vec(),
            signature: vec![],
        };
        assert!(matches!(
            bad_header.channel_header(),
            Err(SubmitError::DecodeError("Invalid proposal header"))
        ));

        let valid = SignedProposal {
            proposal_bytes: Proposal {
                header: Header {
                    channel_header: ChannelHeader {
                        channel_id: "mychannel".into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                    signature_header: vec![],
                }
                .encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
            signature: vec![],
        };
        assert_eq!(valid.channel_header().unwrap().channel_id, "mychannel");
    }
}
