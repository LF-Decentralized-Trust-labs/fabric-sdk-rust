use prost::Message;

use crate::{
    error::LifecycleError,
    fabric::{
        common::{Envelope, Payload},
        gateway::CommitStatusResponse,
        lifecycle::{
            ApproveChaincodeDefinitionForMyOrgArgs, CheckCommitReadinessArgs,
            CheckCommitReadinessResult, CommitChaincodeDefinitionArgs,
            GetInstalledChaincodePackageArgs, GetInstalledChaincodePackageResult,
            InstallChaincodeArgs, InstallChaincodeResult, QueryApprovedChaincodeDefinitionArgs,
            QueryApprovedChaincodeDefinitionResult, QueryApprovedChaincodeDefinitionsArgs,
            QueryApprovedChaincodeDefinitionsResult, QueryChaincodeDefinitionArgs,
            QueryChaincodeDefinitionResult, QueryChaincodeDefinitionsArgs,
            QueryChaincodeDefinitionsResult, QueryInstalledChaincodeArgs,
            QueryInstalledChaincodeResult, QueryInstalledChaincodesArgs,
            QueryInstalledChaincodesResult,
        },
        protos::{
            ChaincodeActionPayload, ChaincodeEndorsedAction, ProposalResponse, SignedProposal,
            Transaction, TransactionAction,
        },
    },
    gateway::client::Client,
};

const LIFECYCLE_CHAINCODE: &str = "_lifecycle";

/// Client for Hyperledger Fabric chaincode lifecycle operations.
///
/// Wraps the peer connection from [`Client`] and provides ergonomic methods
/// for each step of the v2.x chaincode lifecycle: install, approve, commit,
/// and the various query operations.
///
/// # Examples
///
/// ```rust
/// let lifecycle = client.get_lifecycle_client();
///
/// // Install a chaincode package
/// let result = lifecycle.install_chaincode(package_bytes).await?;
/// println!("Package ID: {}", result.package_id);
///
/// // Approve the chaincode definition for the current org
/// lifecycle.approve_chaincode_definition(
///     "mychannel",
///     ApproveChaincodeDefinitionForMyOrgArgs {
///         name: "basic".into(),
///         version: "1.0".into(),
///         sequence: 1,
///         source: Some(ChaincodeSource { r#type: Some(chaincode_source::Type::LocalPackage(
///             chaincode_source::Local { package_id: result.package_id },
///         ))}),
///         ..Default::default()
///     },
/// ).await?;
///
/// // Commit the chaincode definition
/// lifecycle.commit_chaincode_definition(
///     "mychannel",
///     CommitChaincodeDefinitionArgs {
///         name: "basic".into(),
///         version: "1.0".into(),
///         sequence: 1,
///         ..Default::default()
///     },
/// ).await?;
/// ```
pub struct LifecycleClient<'a> {
    client: &'a Client,
}

impl<'a> LifecycleClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Install a chaincode package on the connected peer.
    ///
    /// Returns the [`InstallChaincodeResult`] containing the `package_id` and `label`.
    /// The `package_id` is needed for the approve step.
    ///
    /// Install is not a channel operation, so this bypasses the Gateway API and calls the
    /// peer's legacy `Endorser.ProcessProposal` RPC directly.
    pub async fn install_chaincode(
        &self,
        package: Vec<u8>,
    ) -> Result<InstallChaincodeResult, LifecycleError> {
        let args = InstallChaincodeArgs {
            chaincode_install_package: package,
        };
        let signed_proposal =
            self.build_lifecycle_proposal("", "InstallChaincode", args.encode_to_vec())?;

        let proposal_response = self
            .client
            .process_proposal(signed_proposal)
            .await
            .map_err(LifecycleError::from)?;

        let response = proposal_response
            .response
            .ok_or(LifecycleError::EmptyResponse)?;

        if response.status != 200 {
            return Err(LifecycleError::NodeError(response.message));
        }

        InstallChaincodeResult::decode(response.payload.as_slice())
            .map_err(|_| LifecycleError::DecodeError("Failed to decode InstallChaincodeResult"))
    }

    /// Query all installed chaincodes on the connected peer.
    pub async fn query_installed_chaincodes(
        &self,
    ) -> Result<QueryInstalledChaincodesResult, LifecycleError> {
        let args = QueryInstalledChaincodesArgs {};
        let result_bytes = self
            .evaluate_lifecycle("", "QueryInstalledChaincodes", args.encode_to_vec())
            .await?;

        QueryInstalledChaincodesResult::decode(result_bytes.as_slice()).map_err(|_| {
            LifecycleError::DecodeError("Failed to decode QueryInstalledChaincodesResult")
        })
    }

    /// Query a specific installed chaincode by `package_id`.
    pub async fn query_installed_chaincode(
        &self,
        package_id: impl Into<String>,
    ) -> Result<QueryInstalledChaincodeResult, LifecycleError> {
        let args = QueryInstalledChaincodeArgs {
            package_id: package_id.into(),
        };
        let result_bytes = self
            .evaluate_lifecycle("", "QueryInstalledChaincode", args.encode_to_vec())
            .await?;

        QueryInstalledChaincodeResult::decode(result_bytes.as_slice()).map_err(|_| {
            LifecycleError::DecodeError("Failed to decode QueryInstalledChaincodeResult")
        })
    }

    /// Download the bytes of an installed chaincode package by `package_id`.
    pub async fn get_installed_chaincode_package(
        &self,
        package_id: impl Into<String>,
    ) -> Result<Vec<u8>, LifecycleError> {
        let args = GetInstalledChaincodePackageArgs {
            package_id: package_id.into(),
        };
        let result_bytes = self
            .evaluate_lifecycle("", "GetInstalledChaincodePackage", args.encode_to_vec())
            .await?;

        let result = GetInstalledChaincodePackageResult::decode(result_bytes.as_slice())
            .map_err(|_| {
                LifecycleError::DecodeError(
                    "Failed to decode GetInstalledChaincodePackageResult",
                )
            })?;

        Ok(result.chaincode_install_package)
    }

    /// Approve a chaincode definition for the current organization on the given channel.
    ///
    /// This endorses the approval transaction and submits it to the orderer.
    /// Waits for the transaction to be committed before returning.
    pub async fn approve_chaincode_definition(
        &self,
        channel_name: impl Into<String>,
        args: ApproveChaincodeDefinitionForMyOrgArgs,
    ) -> Result<CommitStatusResponse, LifecycleError> {
        let channel = channel_name.into();
        let signed_proposal = self.build_lifecycle_proposal(
            &channel,
            "ApproveChaincodeDefinitionForMyOrg",
            args.encode_to_vec(),
        )?;

        let mut envelope = self.endorse_lifecycle(signed_proposal).await?;
        envelope.submit(self.client).await.map_err(LifecycleError::from)?;
        envelope.wait_for_commit(self.client).await.map_err(LifecycleError::from)
    }

    /// Check whether enough organizations have approved the given chaincode definition.
    ///
    /// Returns a map of org MSP ID → `true`/`false` indicating each org's approval status.
    pub async fn check_commit_readiness(
        &self,
        channel_name: impl Into<String>,
        args: CheckCommitReadinessArgs,
    ) -> Result<CheckCommitReadinessResult, LifecycleError> {
        let channel = channel_name.into();
        let result_bytes = self
            .evaluate_lifecycle(&channel, "CheckCommitReadiness", args.encode_to_vec())
            .await?;

        CheckCommitReadinessResult::decode(result_bytes.as_slice())
            .map_err(|_| LifecycleError::DecodeError("Failed to decode CheckCommitReadinessResult"))
    }

    /// Commit the chaincode definition to the channel.
    ///
    /// This endorses the commit transaction and submits it to the orderer.
    /// Waits for the transaction to be committed before returning.
    ///
    /// `endorsing_peers` must contain a client for every additional organization whose
    /// endorsement is required by the channel's `LifecycleEndorsement` policy.  For a
    /// two-org network (MAJORITY = both), pass the Org2 admin client here.
    pub async fn commit_chaincode_definition(
        &self,
        channel_name: impl Into<String>,
        args: CommitChaincodeDefinitionArgs,
        endorsing_peers: &[&Client],
    ) -> Result<CommitStatusResponse, LifecycleError> {
        let channel = channel_name.into();
        let signed_proposal = self.build_lifecycle_proposal(
            &channel,
            "CommitChaincodeDefinition",
            args.encode_to_vec(),
        )?;

        let mut all_peers: Vec<&Client> = vec![self.client];
        all_peers.extend_from_slice(endorsing_peers);

        let responses = self.collect_endorsements(&signed_proposal, &all_peers).await?;
        let mut envelope = self.build_envelope(signed_proposal, responses)?;
        envelope.submit(self.client).await.map_err(LifecycleError::from)?;
        envelope.wait_for_commit(self.client).await.map_err(LifecycleError::from)
    }

    /// Query a committed chaincode definition by name on the given channel.
    pub async fn query_chaincode_definition(
        &self,
        channel_name: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<QueryChaincodeDefinitionResult, LifecycleError> {
        let channel = channel_name.into();
        let args = QueryChaincodeDefinitionArgs { name: name.into() };
        let result_bytes = self
            .evaluate_lifecycle(&channel, "QueryChaincodeDefinition", args.encode_to_vec())
            .await?;

        QueryChaincodeDefinitionResult::decode(result_bytes.as_slice()).map_err(|_| {
            LifecycleError::DecodeError("Failed to decode QueryChaincodeDefinitionResult")
        })
    }

    /// Query all committed chaincode definitions on the given channel.
    pub async fn query_chaincode_definitions(
        &self,
        channel_name: impl Into<String>,
    ) -> Result<QueryChaincodeDefinitionsResult, LifecycleError> {
        let channel = channel_name.into();
        let args = QueryChaincodeDefinitionsArgs {};
        let result_bytes = self
            .evaluate_lifecycle(&channel, "QueryChaincodeDefinitions", args.encode_to_vec())
            .await?;

        QueryChaincodeDefinitionsResult::decode(result_bytes.as_slice()).map_err(|_| {
            LifecycleError::DecodeError("Failed to decode QueryChaincodeDefinitionsResult")
        })
    }

    /// Query the approved chaincode definition for the current organization.
    ///
    /// Pass `sequence = -1` to query the latest approved sequence.
    pub async fn query_approved_chaincode_definition(
        &self,
        channel_name: impl Into<String>,
        name: impl Into<String>,
        sequence: i64,
    ) -> Result<QueryApprovedChaincodeDefinitionResult, LifecycleError> {
        let channel = channel_name.into();
        let args = QueryApprovedChaincodeDefinitionArgs {
            name: name.into(),
            sequence,
        };
        let result_bytes = self
            .evaluate_lifecycle(
                &channel,
                "QueryApprovedChaincodeDefinition",
                args.encode_to_vec(),
            )
            .await?;

        QueryApprovedChaincodeDefinitionResult::decode(result_bytes.as_slice()).map_err(|_| {
            LifecycleError::DecodeError(
                "Failed to decode QueryApprovedChaincodeDefinitionResult",
            )
        })
    }

    /// Query all approved chaincode definitions for the current organization on the given channel.
    pub async fn query_approved_chaincode_definitions(
        &self,
        channel_name: impl Into<String>,
    ) -> Result<QueryApprovedChaincodeDefinitionsResult, LifecycleError> {
        let channel = channel_name.into();
        let args = QueryApprovedChaincodeDefinitionsArgs {};
        let result_bytes = self
            .evaluate_lifecycle(
                &channel,
                "QueryApprovedChaincodeDefinitions",
                args.encode_to_vec(),
            )
            .await?;

        QueryApprovedChaincodeDefinitionsResult::decode(result_bytes.as_slice()).map_err(|_| {
            LifecycleError::DecodeError(
                "Failed to decode QueryApprovedChaincodeDefinitionsResult",
            )
        })
    }

    /// Endorses a `_lifecycle` proposal on the local peer and assembles the resulting `Envelope`.
    async fn endorse_lifecycle(
        &self,
        signed_proposal: SignedProposal,
    ) -> Result<Envelope, LifecycleError> {
        let responses = self.collect_endorsements(&signed_proposal, &[self.client]).await?;
        self.build_envelope(signed_proposal, responses)
    }

    /// Sends `signed_proposal` to every peer in `peers` and returns all `ProposalResponse`s.
    async fn collect_endorsements(
        &self,
        signed_proposal: &SignedProposal,
        peers: &[&Client],
    ) -> Result<Vec<ProposalResponse>, LifecycleError> {
        let mut responses = Vec::with_capacity(peers.len());
        for peer in peers {
            let response = peer
                .process_proposal(signed_proposal.clone())
                .await
                .map_err(LifecycleError::from)?;
            responses.push(response);
        }
        Ok(responses)
    }

    /// Assembles a signed `Envelope` from a proposal and the collected endorsements.
    ///
    /// `proposal_response_payload` is taken from the first response (all peers must return
    /// the same read-write set for a deterministic chaincode).  All endorsement signatures
    /// are combined into a single `ChaincodeEndorsedAction`.
    fn build_envelope(
        &self,
        signed_proposal: SignedProposal,
        responses: Vec<ProposalResponse>,
    ) -> Result<Envelope, LifecycleError> {
        if responses.is_empty() {
            return Err(LifecycleError::EmptyResponse);
        }

        for pr in &responses {
            let response = pr.response.as_ref().ok_or(LifecycleError::EmptyResponse)?;
            if response.status != 200 {
                return Err(LifecycleError::NodeError(response.message.clone()));
            }
        }

        let mut iter = responses.into_iter();
        let first = iter.next().unwrap();
        let proposal_response_payload = first.payload;
        let mut endorsements: Vec<_> = first.endorsement.into_iter().collect();
        for pr in iter {
            endorsements.extend(pr.endorsement.into_iter());
        }

        let proposal = signed_proposal
            .get_proposal()
            .map_err(|_| LifecycleError::DecodeError("Failed to decode proposal"))?;

        let header = proposal
            .get_header()
            .map_err(|_| LifecycleError::DecodeError("Failed to decode header"))?;

        let chaincode_action_payload = ChaincodeActionPayload {
            chaincode_proposal_payload: proposal.payload,
            action: Some(ChaincodeEndorsedAction {
                proposal_response_payload,
                endorsements,
            }),
        };

        let transaction = Transaction {
            actions: vec![TransactionAction {
                header: header.signature_header.clone(),
                payload: chaincode_action_payload.encode_to_vec(),
            }],
        };

        let payload = Payload {
            header: Some(header),
            data: transaction.encode_to_vec(),
        };

        let payload_bytes = payload.encode_to_vec();
        let signature = self.client.identity.sign_message(&payload_bytes);

        Ok(Envelope {
            payload: payload_bytes,
            signature,
        })
    }

    fn build_lifecycle_proposal(
        &self,
        channel_name: &str,
        function_name: &str,
        args_bytes: Vec<u8>,
    ) -> Result<SignedProposal, LifecycleError> {
        let mut builder = self.client.get_chaincode_call_builder();
        builder
            .with_chaincode_id(LIFECYCLE_CHAINCODE)
            .map_err(LifecycleError::from)?;
        if !channel_name.is_empty() {
            builder
                .with_channel_name(channel_name)
                .map_err(LifecycleError::from)?;
        }
        builder
            .with_function_name(function_name)
            .map_err(LifecycleError::from)?;
        builder
            .with_function_args([args_bytes])
            .map_err(LifecycleError::from)?;
        builder.build().map_err(LifecycleError::from)
    }

    async fn evaluate_lifecycle(
        &self,
        channel_name: &str,
        function_name: &str,
        args_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, LifecycleError> {
        let signed_proposal =
            self.build_lifecycle_proposal(channel_name, function_name, args_bytes)?;

        // Channel-less operations (e.g. QueryInstalledChaincodes) bypass the Gateway API,
        // which requires a valid channel_id. Use ProcessProposal directly instead.
        if channel_name.is_empty() {
            let proposal_response = self
                .client
                .process_proposal(signed_proposal)
                .await
                .map_err(LifecycleError::from)?;

            let response = proposal_response
                .response
                .ok_or(LifecycleError::EmptyResponse)?;

            if response.status != 200 {
                return Err(LifecycleError::NodeError(response.message));
            }

            return Ok(response.payload);
        }

        let channel_header = signed_proposal
            .get_proposal()
            .map_err(|_| LifecycleError::DecodeError("Failed to decode proposal"))?
            .get_header()
            .map_err(|_| LifecycleError::DecodeError("Failed to decode header"))?
            .get_channel_header()
            .map_err(|_| LifecycleError::DecodeError("Failed to decode channel header"))?;

        self.client
            .evaluate(signed_proposal, channel_header.tx_id, channel_header.channel_id)
            .await
            .map_err(LifecycleError::from)
    }
}
