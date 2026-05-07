use prost::{DecodeError, Message};

use crate::fabric::{
    common::{Header, Payload},
    protos::Transaction,
};

impl Payload {
    /// Decodes the payload to an transaction
    pub fn get_transaction(&self) -> Result<Transaction, DecodeError> {
        Transaction::decode(self.data.as_slice())
    }

    /// Clones the optional header
    pub fn get_header(&self) -> Option<Header> {
        self.header.clone()
    }
}
