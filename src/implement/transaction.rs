use prost::Message;

use crate::fabric::protos::{
    ChaincodeAction, ChaincodeActionPayload, ProposalResponsePayload, Transaction,
};

impl Transaction {
    /// Looks for a chaincode result payload (like the return payload from the chaincode function call)
    pub fn get_result(&self) -> Option<Vec<u8>> {
        for action in &self.actions {
            if let Ok(action) = ChaincodeActionPayload::decode(action.payload.as_slice())
                && let Some(action) = action.action
                && let Ok(payload) =
                    ProposalResponsePayload::decode(action.proposal_response_payload.as_slice())
                && let Ok(action) = ChaincodeAction::decode(payload.extension.as_slice())
                && let Some(response) = action.response
            {
                return Some(response.payload);
            }
        }
        None
    }

    /// Just like [get_result](get_result) but result will be converted to an unverified string
    pub fn get_result_string(&self) -> Option<String> {
        match self.get_result() {
            Some(result) => Some(String::from_utf8_lossy(result.as_slice()).to_string()),
            None => None,
        }
    }
}
