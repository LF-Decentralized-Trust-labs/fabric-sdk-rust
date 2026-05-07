use prost::{DecodeError, Message};

use crate::fabric::common::{ChannelHeader, Header, SignatureHeader};

impl Header {
    pub fn get_channel_header(&self) -> Result<ChannelHeader, DecodeError> {
        ChannelHeader::decode(self.channel_header.as_slice())
    }

    pub fn get_signature_header(&self) -> Result<SignatureHeader, DecodeError> {
        SignatureHeader::decode(self.signature_header.as_slice())
    }
}
