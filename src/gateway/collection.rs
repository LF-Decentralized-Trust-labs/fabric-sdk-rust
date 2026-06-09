//! Helpers for building private data collection configurations.
//!
//! A [CollectionConfigPackage] is supplied at chaincode approve/commit time via
//! the `collections` field of `ApproveChaincodeDefinitionForMyOrgArgs` /
//! `CommitChaincodeDefinitionArgs`. Constructing the underlying
//! `SignaturePolicyEnvelope` by hand is verbose, so this module provides a small
//! builder.
//!
//! ```no_run
//! use fabric_sdk::gateway::collection::CollectionConfigBuilder;
//!
//! let collection = CollectionConfigBuilder::new("assetCollection")
//!     .with_member_orgs(["Org1MSP", "Org2MSP"])
//!     .with_required_peer_count(0)
//!     .with_maximum_peer_count(1)
//!     .with_block_to_live(1_000_000)
//!     .build();
//!
//! let package = CollectionConfigBuilder::package([collection]);
//! ```

use prost::Message;

use crate::fabric::{
    common::{
        MspPrincipal, MspRole, SignaturePolicy, SignaturePolicyEnvelope, msp_principal, msp_role,
        signature_policy,
    },
    protos::{
        ApplicationPolicy, CollectionConfig, CollectionConfigPackage, CollectionPolicyConfig,
        StaticCollectionConfig, application_policy, collection_config, collection_policy_config,
    },
};

/// Builds a single static [CollectionConfig].
///
/// The member organizations policy is generated as an `OR(...member...)` over
/// the configured MSP IDs, matching the behaviour of the standard Fabric
/// tooling. For full control, set an explicit policy with
/// [with_member_orgs_policy](Self::with_member_orgs_policy).
pub struct CollectionConfigBuilder {
    name: String,
    member_orgs: Vec<String>,
    member_orgs_policy: Option<SignaturePolicyEnvelope>,
    required_peer_count: i32,
    maximum_peer_count: i32,
    block_to_live: u64,
    member_only_read: bool,
    member_only_write: bool,
    endorsement_policy: Option<ApplicationPolicy>,
}

impl CollectionConfigBuilder {
    /// Creates a builder for a collection with the given name. Defaults:
    /// `required_peer_count = 0`, `maximum_peer_count = 1`, `block_to_live = 0`
    /// (never expires), member-only read and write enabled.
    pub fn new(name: impl Into<String>) -> Self {
        CollectionConfigBuilder {
            name: name.into(),
            member_orgs: vec![],
            member_orgs_policy: None,
            required_peer_count: 0,
            maximum_peer_count: 1,
            block_to_live: 0,
            member_only_read: true,
            member_only_write: true,
            endorsement_policy: None,
        }
    }

    /// Sets the member organizations (MSP IDs). An `OR` member policy is
    /// generated from these unless an explicit policy is supplied.
    pub fn with_member_orgs<T, U>(mut self, orgs: T) -> Self
    where
        T: IntoIterator<Item = U>,
        U: Into<String>,
    {
        self.member_orgs = orgs.into_iter().map(Into::into).collect();
        self
    }

    /// Overrides the generated member policy with an explicit one.
    pub fn with_member_orgs_policy(mut self, policy: SignaturePolicyEnvelope) -> Self {
        self.member_orgs_policy = Some(policy);
        self
    }

    /// The minimum number of peers private data is disseminated to upon
    /// endorsement. Endorsement fails if this many peers cannot be reached.
    pub fn with_required_peer_count(mut self, count: i32) -> Self {
        self.required_peer_count = count;
        self
    }

    /// The maximum number of peers private data is disseminated to upon
    /// endorsement. Must be greater than or equal to `required_peer_count`.
    pub fn with_maximum_peer_count(mut self, count: i32) -> Self {
        self.maximum_peer_count = count;
        self
    }

    /// The number of blocks after which the collection data expires and is
    /// purged. A value of `0` means the data never expires.
    pub fn with_block_to_live(mut self, blocks: u64) -> Self {
        self.block_to_live = blocks;
        self
    }

    /// Whether only collection member clients can read the private data.
    pub fn with_member_only_read(mut self, member_only: bool) -> Self {
        self.member_only_read = member_only;
        self
    }

    /// Whether only collection member clients can write the private data.
    pub fn with_member_only_write(mut self, member_only: bool) -> Self {
        self.member_only_write = member_only;
        self
    }

    /// Sets a key-level endorsement policy for the collection.
    pub fn with_endorsement_policy(mut self, policy: ApplicationPolicy) -> Self {
        self.endorsement_policy = Some(policy);
        self
    }

    /// Builds the [CollectionConfig].
    pub fn build(self) -> CollectionConfig {
        let member_policy = self
            .member_orgs_policy
            .unwrap_or_else(|| member_or_policy(&self.member_orgs));

        let static_config = StaticCollectionConfig {
            name: self.name,
            member_orgs_policy: Some(CollectionPolicyConfig {
                payload: Some(collection_policy_config::Payload::SignaturePolicy(
                    member_policy,
                )),
            }),
            required_peer_count: self.required_peer_count,
            maximum_peer_count: self.maximum_peer_count,
            block_to_live: self.block_to_live,
            member_only_read: self.member_only_read,
            member_only_write: self.member_only_write,
            endorsement_policy: self.endorsement_policy,
        };

        CollectionConfig {
            payload: Some(collection_config::Payload::StaticCollectionConfig(
                static_config,
            )),
        }
    }

    /// Wraps one or more [CollectionConfig] values into a
    /// [CollectionConfigPackage], ready to be passed to the lifecycle
    /// approve/commit calls.
    pub fn package<T>(configs: T) -> CollectionConfigPackage
    where
        T: IntoIterator<Item = CollectionConfig>,
    {
        CollectionConfigPackage {
            config: configs.into_iter().collect(),
        }
    }
}

/// Builds an `OR('<msp>.member', ...)` signature policy over the given MSP IDs.
pub fn member_or_policy<S: AsRef<str>>(msp_ids: &[S]) -> SignaturePolicyEnvelope {
    let identities: Vec<MspPrincipal> = msp_ids
        .iter()
        .map(|msp_id| MspPrincipal {
            principal_classification: msp_principal::Classification::Role.into(),
            principal: MspRole {
                msp_identifier: msp_id.as_ref().to_string(),
                role: msp_role::MspRoleType::Member.into(),
            }
            .encode_to_vec(),
        })
        .collect();

    let rules: Vec<SignaturePolicy> = (0..identities.len() as i32)
        .map(|i| SignaturePolicy {
            r#type: Some(signature_policy::Type::SignedBy(i)),
        })
        .collect();

    SignaturePolicyEnvelope {
        version: 0,
        rule: Some(SignaturePolicy {
            r#type: Some(signature_policy::Type::NOutOf(signature_policy::NOutOf {
                // OR == 1-out-of-N
                n: if rules.is_empty() { 0 } else { 1 },
                rules,
            })),
        }),
        identities,
    }
}

/// Convenience constructor for an [ApplicationPolicy] wrapping a signature
/// policy envelope, suitable for use as a collection endorsement policy.
pub fn application_signature_policy(envelope: SignaturePolicyEnvelope) -> ApplicationPolicy {
    ApplicationPolicy {
        r#type: Some(application_policy::Type::SignaturePolicy(envelope)),
    }
}
