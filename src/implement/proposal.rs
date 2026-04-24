use prost::{DecodeError, Message};

use crate::fabric::{common::Header, protos::Proposal};

impl Proposal {
    pub fn get_header(&self) -> Result<Header, DecodeError> {
        Header::decode(self.header.as_slice())
    }
}
