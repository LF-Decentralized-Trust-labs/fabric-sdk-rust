use crate::{
    error::SubmitError,
    fabric::{
        common::SignatureHeader,
        protos::{
            QueryPendingSnapshotsResponse, SignedSnapshotRequest, SnapshotQuery, SnapshotRequest,
        },
        protos::snapshot_client::SnapshotClient,
    },
    identity::Identity,
};
use prost::Message;

/// Builder for creating SignedSnapshotRequest for Generate and Cancel operations
pub struct SnapshotRequestBuilder {
    identity: Identity,
    channel_id: Option<String>,
    block_number: Option<u64>,
}

impl SnapshotRequestBuilder {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            channel_id: None,
            block_number: None,
        }
    }

    pub fn with_channel_id(mut self, channel_id: impl Into<String>) -> Result<Self, crate::error::BuilderError> {
        let channel_id = channel_id.into().trim().to_string();
        if channel_id.is_empty() {
            return Err(crate::error::BuilderError::InvalidParameter(
                "channel_id cannot be empty".into(),
            ));
        }
        self.channel_id = Some(channel_id);
        Ok(self)
    }

    pub fn with_block_number(mut self, block_number: u64) -> Self {
        self.block_number = Some(block_number);
        self
    }

    /// Build a SignedSnapshotRequest for Generate or Cancel operations
    pub fn build_signed_request(self) -> Result<SignedSnapshotRequest, crate::error::BuilderError> {
        let channel_id = self
            .channel_id
            .ok_or_else(|| crate::error::BuilderError::MissingParameter("channel_id".into()))?;

        let block_number = self
            .block_number
            .ok_or_else(|| crate::error::BuilderError::MissingParameter("block_number".into()))?;

        let signature_header = SignatureHeader {
            creator: self.identity.get_serialized_identity().encode_to_vec(),
            nonce: vec![], // Snapshot requests don't typically use nonces
        };

        let request = SnapshotRequest {
            signature_header: Some(signature_header),
            channel_id,
            block_number,
        };

        let request_bytes = request.encode_to_vec();
        let signature = self.identity.sign_message(&request_bytes);

        Ok(SignedSnapshotRequest {
            request: request_bytes,
            signature,
        })
    }
}

/// Builder for creating SignedSnapshotRequest for QueryPendings operation
pub struct SnapshotQueryBuilder {
    identity: Identity,
    channel_id: Option<String>,
}

impl SnapshotQueryBuilder {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            channel_id: None,
        }
    }

    pub fn with_channel_id(mut self, channel_id: impl Into<String>) -> Result<Self, crate::error::BuilderError> {
        let channel_id = channel_id.into().trim().to_string();
        if channel_id.is_empty() {
            return Err(crate::error::BuilderError::InvalidParameter(
                "channel_id cannot be empty".into(),
            ));
        }
        self.channel_id = Some(channel_id);
        Ok(self)
    }

    /// Build a SignedSnapshotRequest for QueryPendings operation
    pub fn build_signed_query(self) -> Result<SignedSnapshotRequest, crate::error::BuilderError> {
        let channel_id = self
            .channel_id
            .ok_or_else(|| crate::error::BuilderError::MissingParameter("channel_id".into()))?;

        let signature_header = SignatureHeader {
            creator: self.identity.get_serialized_identity().encode_to_vec(),
            nonce: vec![], // Snapshot queries don't typically use nonces
        };

        let query = SnapshotQuery {
            signature_header: Some(signature_header),
            channel_id,
        };

        let query_bytes = query.encode_to_vec();
        let signature = self.identity.sign_message(&query_bytes);

        Ok(SignedSnapshotRequest {
            request: query_bytes,
            signature,
        })
    }
}

/// Snapshot client wrapper for interacting with the Snapshot service
pub struct SnapshotClientWrapper {
    client: SnapshotClient<tonic::transport::Channel>,
}

impl SnapshotClientWrapper {
    pub fn new(channel: tonic::transport::Channel) -> Self {
        let client = SnapshotClient::new(channel);
        Self { client }
    }

    /// Generate a snapshot request
    pub async fn generate(
        &mut self,
        request: SignedSnapshotRequest,
    ) -> Result<(), SubmitError> {
        let response = self.client.generate(request).await;
        match response {
            Ok(_) => Ok(()),
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }

    /// Cancel a snapshot request
    pub async fn cancel(
        &mut self,
        request: SignedSnapshotRequest,
    ) -> Result<(), SubmitError> {
        let response = self.client.cancel(request).await;
        match response {
            Ok(_) => Ok(()),
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }

    /// Query pending snapshots
    pub async fn query_pendings(
        &mut self,
        request: SignedSnapshotRequest,
    ) -> Result<QueryPendingSnapshotsResponse, SubmitError> {
        let response = self.client.query_pendings(request).await;
        match response {
            Ok(response) => Ok(response.into_inner()),
            Err(err) => Err(SubmitError::NodeError(
                String::from_utf8_lossy(err.details()).into_owned(),
            )),
        }
    }
}
