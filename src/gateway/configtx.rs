//! Channel configuration transaction (configtx) helpers.
//!
//! This module provides everything needed to create a channel and update its
//! configuration without external tooling (`configtxgen` / `configtxlator` /
//! `peer channel update`):
//!
//! 1. [`compute_config_update`] — computes the sparse [`ConfigUpdate`]
//!    (read set / write set) between an original and an updated [`Config`].
//!    This is a faithful port of the Go implementation in
//!    `hyperledger/fabric` `internal/configtxlator/update`.
//! 2. Edit helpers ([`set_anchor_peers`], [`add_application_org`],
//!    [`add_consenter`], [`remove_consenter`]) — typed recipes that mutate a
//!    decoded [`Config`] tree so the caller does not have to hand-edit
//!    nested protobuf maps.
//! 3. Organization building blocks ([`MspConfigBuilder`], [`org_policies`],
//!    [`orderer_org_policies`]) — the `MSP` value and the standard policies
//!    of an organization, as `configtxgen` derives them from an MSP
//!    directory and `configtx.yaml`, built from PEM input.
//! 4. Channel creation ([`GenesisBuilder`], [`ApplicationOrg`],
//!    [`OrdererOrg`]) — the genesis block of a new application channel, as
//!    `configtxgen -outputBlock` builds it, for joining orderers through
//!    the channel participation API and peers through cscc.
//! 5. Signing and envelope assembly ([`sign_config_update`],
//!    [`create_config_update_envelope`], [`add_signature`],
//!    [`build_config_update_transaction`]) — produce the signed
//!    `CONFIG_UPDATE` [`Envelope`] to submit to the orderer (see
//!    [`OrdererClient`](crate::gateway::orderer::OrdererClient)).
//!
//! The whole module is pure computation plus local signing; it is fully
//! WASM-safe.
//!
//! # Multi-organization signature collection
//!
//! A config update often needs signatures from several organizations before
//! it satisfies the mod policy of the elements it touches. Admitting a new
//! organization, for example, changes the `Application` group, whose mod
//! policy is `MAJORITY Admins` of the existing orgs. The intended flow:
//!
//! ```rust
//! // Org1 adds Org3 from the PEMs Org3 handed over
//! let org3_msp = MspConfigBuilder::new("Org3MSP")
//!     .with_root_cert(org3_ca_pem.clone())
//!     .with_tls_root_cert(org3_tlsca_pem)
//!     .with_node_ous(org3_ca_pem)
//!     .build()?;
//! let mut updated = original.clone();
//! add_application_org(&mut updated, "Org3MSP", &org3_msp, org_policies("Org3MSP"))?;
//!
//! // Org1 computes the update and signs it
//! let update = compute_config_update(&original, &updated, "mychannel")?;
//! let mut envelope = create_config_update_envelope(&update);
//! add_signature(&mut envelope, &org1_identity);
//!
//! // ... pass `encode_config_update_envelope(&envelope)` out-of-band to Org2 ...
//! let mut envelope = decode_config_update_envelope(&bytes)?;
//! add_signature(&mut envelope, &org2_identity);
//!
//! // Finally wrap it into a signed transaction envelope and broadcast it
//! let tx = build_config_update_transaction(&org2_identity, &envelope)?;
//! orderer_client.broadcast(tx).await?;
//! ```

use prost::Message;

use crate::{
    error::ConfigTxError,
    fabric::{
        common::{
            Block, BlockData, BlockDataHashingStructure, BlockHeader, BlockMetadata,
            BlockMetadataIndex, ChannelHeader, Config, ConfigEnvelope, ConfigGroup, ConfigPolicy,
            ConfigSignature, ConfigUpdate, ConfigUpdateEnvelope, ConfigValue, Envelope,
            HashingAlgorithm, Header, HeaderType, ImplicitMetaPolicy, LastConfig, Metadata,
            OrdererAddresses, OrdererBlockMetadata, Payload, Policy, SignatureHeader,
            implicit_meta_policy::Rule as ImplicitMetaRule, msp_role::MspRoleType,
            policy::PolicyType,
        },
        etcdraft,
        google_protobuf::Timestamp,
        msp::{FabricCryptoConfig, FabricMspConfig, FabricNodeOUs, FabricOuIdentifier, MspConfig},
        orderer::{BatchSize, BatchTimeout, ChannelRestrictions, ConsensusType, consensus_type},
        protos::{AcLs, AnchorPeer, AnchorPeers, ApiResource},
    },
    gateway::collection::role_or_policy,
    identity::Identity,
    implement::crypto::{generate_nonce, generate_sha256_hash, generate_transaction_id},
};

use std::collections::BTreeMap;

use x509_cert::{
    Certificate,
    certificate::Rfc5280,
    crl::CertificateList,
    der::{DecodePem, Encode},
};

// =====================================================================
// ConfigUpdate delta computation
//
// Faithful port of hyperledger/fabric internal/configtxlator/update
// (update.go, Apache-2.0). Version arithmetic uses wrapping_add to match
// Go's uint64 overflow semantics.
// =====================================================================

fn compute_policies_map_update(
    original: &BTreeMap<String, ConfigPolicy>,
    updated: &BTreeMap<String, ConfigPolicy>,
) -> (
    BTreeMap<String, ConfigPolicy>,
    BTreeMap<String, ConfigPolicy>,
    BTreeMap<String, ConfigPolicy>,
    bool,
) {
    // The read set stays empty for leaf elements (matches the Go reference).
    let read_set = BTreeMap::new();
    let mut write_set = BTreeMap::new();
    // All modified config goes into the read/write sets, but in case the map
    // membership changes, we retain the config which was the same to add to
    // the read/write sets
    let mut same_set = BTreeMap::new();
    let mut updated_members = false;

    for (policy_name, original_policy) in original {
        let Some(updated_policy) = updated.get(policy_name) else {
            updated_members = true;
            continue;
        };

        if original_policy.mod_policy == updated_policy.mod_policy
            && original_policy.policy == updated_policy.policy
        {
            same_set.insert(
                policy_name.clone(),
                ConfigPolicy {
                    version: original_policy.version,
                    ..Default::default()
                },
            );
            continue;
        }

        write_set.insert(
            policy_name.clone(),
            ConfigPolicy {
                version: original_policy.version.wrapping_add(1),
                mod_policy: updated_policy.mod_policy.clone(),
                policy: updated_policy.policy.clone(),
            },
        );
    }

    for (policy_name, updated_policy) in updated {
        if original.contains_key(policy_name) {
            // If the updated policy is in the original set of policies, it was already handled
            continue;
        }
        updated_members = true;
        write_set.insert(
            policy_name.clone(),
            ConfigPolicy {
                version: 0,
                mod_policy: updated_policy.mod_policy.clone(),
                policy: updated_policy.policy.clone(),
            },
        );
    }

    (read_set, write_set, same_set, updated_members)
}

fn compute_values_map_update(
    original: &BTreeMap<String, ConfigValue>,
    updated: &BTreeMap<String, ConfigValue>,
) -> (
    BTreeMap<String, ConfigValue>,
    BTreeMap<String, ConfigValue>,
    BTreeMap<String, ConfigValue>,
    bool,
) {
    // The read set stays empty for leaf elements (matches the Go reference).
    let read_set = BTreeMap::new();
    let mut write_set = BTreeMap::new();
    let mut same_set = BTreeMap::new();
    let mut updated_members = false;

    for (value_name, original_value) in original {
        let Some(updated_value) = updated.get(value_name) else {
            updated_members = true;
            continue;
        };

        if original_value.mod_policy == updated_value.mod_policy
            && original_value.value == updated_value.value
        {
            same_set.insert(
                value_name.clone(),
                ConfigValue {
                    version: original_value.version,
                    ..Default::default()
                },
            );
            continue;
        }

        write_set.insert(
            value_name.clone(),
            ConfigValue {
                version: original_value.version.wrapping_add(1),
                mod_policy: updated_value.mod_policy.clone(),
                value: updated_value.value.clone(),
            },
        );
    }

    for (value_name, updated_value) in updated {
        if original.contains_key(value_name) {
            continue;
        }
        updated_members = true;
        write_set.insert(
            value_name.clone(),
            ConfigValue {
                version: 0,
                mod_policy: updated_value.mod_policy.clone(),
                value: updated_value.value.clone(),
            },
        );
    }

    (read_set, write_set, same_set, updated_members)
}

fn compute_groups_map_update(
    original: &BTreeMap<String, ConfigGroup>,
    updated: &BTreeMap<String, ConfigGroup>,
) -> (
    BTreeMap<String, ConfigGroup>,
    BTreeMap<String, ConfigGroup>,
    BTreeMap<String, ConfigGroup>,
    bool,
) {
    let mut read_set = BTreeMap::new();
    let mut write_set = BTreeMap::new();
    let mut same_set = BTreeMap::new();
    let mut updated_members = false;

    for (group_name, original_group) in original {
        let Some(updated_group) = updated.get(group_name) else {
            updated_members = true;
            continue;
        };

        let (group_read_set, group_write_set, group_updated) =
            compute_group_update(original_group, updated_group);
        if !group_updated {
            same_set.insert(group_name.clone(), group_read_set);
            continue;
        }

        read_set.insert(group_name.clone(), group_read_set);
        write_set.insert(group_name.clone(), group_write_set);
    }

    for (group_name, updated_group) in updated {
        if original.contains_key(group_name) {
            continue;
        }
        updated_members = true;
        let (_, group_write_set, _) = compute_group_update(&ConfigGroup::default(), updated_group);
        write_set.insert(
            group_name.clone(),
            ConfigGroup {
                version: 0,
                mod_policy: updated_group.mod_policy.clone(),
                policies: group_write_set.policies,
                values: group_write_set.values,
                groups: group_write_set.groups,
            },
        );
    }

    (read_set, write_set, same_set, updated_members)
}

fn compute_group_update(
    original: &ConfigGroup,
    updated: &ConfigGroup,
) -> (ConfigGroup, ConfigGroup, bool) {
    let (mut read_set_policies, mut write_set_policies, same_set_policies, policies_members_updated) =
        compute_policies_map_update(&original.policies, &updated.policies);
    let (mut read_set_values, mut write_set_values, same_set_values, values_members_updated) =
        compute_values_map_update(&original.values, &updated.values);
    let (mut read_set_groups, mut write_set_groups, same_set_groups, groups_members_updated) =
        compute_groups_map_update(&original.groups, &updated.groups);

    // If the updated group is 'Equal' to the original group
    // (none of the members nor the mod policy changed)
    if !(policies_members_updated
        || values_members_updated
        || groups_members_updated
        || original.mod_policy != updated.mod_policy)
    {
        // If there were no modified entries in any of the policies/values/groups maps
        if read_set_policies.is_empty()
            && write_set_policies.is_empty()
            && read_set_values.is_empty()
            && write_set_values.is_empty()
            && read_set_groups.is_empty()
            && write_set_groups.is_empty()
        {
            return (
                ConfigGroup {
                    version: original.version,
                    ..Default::default()
                },
                ConfigGroup {
                    version: original.version,
                    ..Default::default()
                },
                false,
            );
        }

        return (
            ConfigGroup {
                version: original.version,
                policies: read_set_policies,
                values: read_set_values,
                groups: read_set_groups,
                ..Default::default()
            },
            ConfigGroup {
                version: original.version,
                policies: write_set_policies,
                values: write_set_values,
                groups: write_set_groups,
                ..Default::default()
            },
            true,
        );
    }

    for (k, same_policy) in same_set_policies {
        read_set_policies.insert(k.clone(), same_policy.clone());
        write_set_policies.insert(k, same_policy);
    }

    for (k, same_value) in same_set_values {
        read_set_values.insert(k.clone(), same_value.clone());
        write_set_values.insert(k, same_value);
    }

    for (k, same_group) in same_set_groups {
        read_set_groups.insert(k.clone(), same_group.clone());
        write_set_groups.insert(k, same_group);
    }

    (
        ConfigGroup {
            version: original.version,
            policies: read_set_policies,
            values: read_set_values,
            groups: read_set_groups,
            ..Default::default()
        },
        ConfigGroup {
            version: original.version.wrapping_add(1),
            policies: write_set_policies,
            values: write_set_values,
            groups: write_set_groups,
            mod_policy: updated.mod_policy.clone(),
        },
        true,
    )
}

/// Computes the sparse [`ConfigUpdate`] between `original` and `updated`.
///
/// This is a faithful port of `Compute` from `hyperledger/fabric`
/// `internal/configtxlator/update`: unchanged groups are referenced in the
/// read set at their current version, modified elements appear in the write
/// set with their version bumped by one, and additions appear in the write
/// set at version 0. Deletions are expressed by version-bumping the parent
/// group.
///
/// `channel_id` is stamped into the resulting update (this matches the
/// behavior of `configtxlator compute_update`, which requires a channel ID).
///
/// Returns [`ConfigTxError::NoDifferences`] if the two configs are identical,
/// and [`ConfigTxError::NoChannelGroup`] if either config has no
/// `channel_group`.
///
/// The encoding of the returned update is deterministic: all config map
/// fields are `BTreeMap`s, so identical inputs always produce byte-identical
/// `ConfigUpdate` bytes.
pub fn compute_config_update(
    original: &Config,
    updated: &Config,
    channel_id: impl Into<String>,
) -> Result<ConfigUpdate, ConfigTxError> {
    let original_group = original
        .channel_group
        .as_ref()
        .ok_or(ConfigTxError::NoChannelGroup("original"))?;
    let updated_group = updated
        .channel_group
        .as_ref()
        .ok_or(ConfigTxError::NoChannelGroup("updated"))?;

    let (read_set, write_set, group_updated) = compute_group_update(original_group, updated_group);
    if !group_updated {
        return Err(ConfigTxError::NoDifferences);
    }

    Ok(ConfigUpdate {
        channel_id: channel_id.into(),
        read_set: Some(read_set),
        write_set: Some(write_set),
        isolated_data: BTreeMap::new(),
    })
}

// =====================================================================
// Typed edit helpers
//
// Further recipes (capabilities, ACLs, batch size/timeout, orderer
// addresses, channel/application policies) are intentionally not yet
// implemented — TODO: add them following the same pattern once needed.
// =====================================================================

const APPLICATION_GROUP: &str = "Application";
const ORDERER_GROUP: &str = "Orderer";
const ANCHOR_PEERS_KEY: &str = "AnchorPeers";
const MSP_KEY: &str = "MSP";
const CONSENSUS_TYPE_KEY: &str = "ConsensusType";
const ETCDRAFT_TYPE: &str = "etcdraft";
const ADMINS_POLICY: &str = "Admins";

fn channel_group_mut(config: &mut Config) -> Result<&mut ConfigGroup, ConfigTxError> {
    config
        .channel_group
        .as_mut()
        .ok_or(ConfigTxError::NoChannelGroup("target"))
}

/// Sets (or replaces) the anchor peers of an application organization.
///
/// Navigates to `channel_group.groups["Application"].groups[org_msp_id]` and
/// writes the `AnchorPeers` config value. Use [`compute_config_update`]
/// against the unmodified original to derive the update transaction.
///
/// Returns [`ConfigTxError::ElementNotFound`] if the channel has no
/// `Application` group or the organization is not part of the channel.
pub fn set_anchor_peers(
    config: &mut Config,
    org_msp_id: &str,
    anchor_peers: Vec<AnchorPeer>,
) -> Result<(), ConfigTxError> {
    let application = channel_group_mut(config)?
        .groups
        .get_mut(APPLICATION_GROUP)
        .ok_or_else(|| ConfigTxError::ElementNotFound(APPLICATION_GROUP.into()))?;

    let org = application
        .groups
        .get_mut(org_msp_id)
        .ok_or_else(|| ConfigTxError::ElementNotFound(format!("Application org {}", org_msp_id)))?;

    let value = AnchorPeers { anchor_peers }.encode_to_vec();

    match org.values.get_mut(ANCHOR_PEERS_KEY) {
        Some(existing) => {
            // Keep the existing version and mod_policy; compute_config_update
            // derives the version bump from the original config anyway.
            existing.value = value;
        }
        None => {
            org.values.insert(
                ANCHOR_PEERS_KEY.into(),
                ConfigValue {
                    version: 0,
                    value,
                    mod_policy: ADMINS_POLICY.into(),
                },
            );
        }
    }
    Ok(())
}

/// Adds a new application organization to the channel.
///
/// Inserts `channel_group.groups["Application"].groups[msp_id]` with the
/// given [`MspConfig`] (as the org's `MSP` config value) and the given
/// policies (typically `Readers`/`Writers`/`Admins`/`Endorsement`
/// signature policies referring to the org's MSP roles). Build them with
/// [`MspConfigBuilder`] and [`org_policies`].
///
/// Returns [`ConfigTxError::AlreadyExists`] if the org is already part of the
/// channel and [`ConfigTxError::ElementNotFound`] if the channel has no
/// `Application` group.
pub fn add_application_org(
    config: &mut Config,
    msp_id: &str,
    msp_config: &MspConfig,
    policies: BTreeMap<String, ConfigPolicy>,
) -> Result<(), ConfigTxError> {
    let application = channel_group_mut(config)?
        .groups
        .get_mut(APPLICATION_GROUP)
        .ok_or_else(|| ConfigTxError::ElementNotFound(APPLICATION_GROUP.into()))?;

    if application.groups.contains_key(msp_id) {
        return Err(ConfigTxError::AlreadyExists(format!(
            "Application org {}",
            msp_id
        )));
    }

    application
        .groups
        .insert(msp_id.to_string(), org_group(msp_config, policies));
    Ok(())
}

/// A config value at version 0 with mod policy `Admins`, as `configtxgen`
/// writes every value of a new group.
fn admins_value(value: Vec<u8>) -> ConfigValue {
    ConfigValue {
        version: 0,
        value,
        mod_policy: ADMINS_POLICY.into(),
    }
}

/// An organization group at version 0 with mod policy `Admins`, holding the
/// `MSP` value and the given policies (`configtxgen`'s org group layout).
fn org_group(msp_config: &MspConfig, policies: BTreeMap<String, ConfigPolicy>) -> ConfigGroup {
    ConfigGroup {
        version: 0,
        groups: BTreeMap::new(),
        values: BTreeMap::from([(
            MSP_KEY.to_string(),
            admins_value(msp_config.encode_to_vec()),
        )]),
        policies,
        mod_policy: ADMINS_POLICY.into(),
    }
}

// =====================================================================
// Organization building blocks
// =====================================================================

const READERS_POLICY: &str = "Readers";
const WRITERS_POLICY: &str = "Writers";
const ENDORSEMENT_POLICY: &str = "Endorsement";

fn signature_config_policy(principals: &[(&str, MspRoleType)]) -> ConfigPolicy {
    ConfigPolicy {
        version: 0,
        policy: Some(Policy {
            r#type: PolicyType::Signature.into(),
            value: role_or_policy(principals).encode_to_vec(),
        }),
        mod_policy: ADMINS_POLICY.into(),
    }
}

/// The standard policies of an application organization with NodeOUs
/// enabled, as Fabric's test-network `configtx.yaml` defines them:
///
/// | Policy        | Rule                                                  |
/// |---------------|-------------------------------------------------------|
/// | `Readers`     | `OR('<msp>.admin', '<msp>.peer', '<msp>.client')`     |
/// | `Writers`     | `OR('<msp>.admin', '<msp>.client')`                   |
/// | `Admins`      | `OR('<msp>.admin')`                                   |
/// | `Endorsement` | `OR('<msp>.peer')`                                    |
///
/// Each is a signature policy with mod policy `Admins` at version 0, encoded
/// exactly as `configtxgen` encodes the rule. Pass the map to
/// [`add_application_org`].
pub fn org_policies(msp_id: &str) -> BTreeMap<String, ConfigPolicy> {
    use MspRoleType::{Admin, Client, Peer};
    BTreeMap::from([
        (
            READERS_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Admin), (msp_id, Peer), (msp_id, Client)]),
        ),
        (
            WRITERS_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Admin), (msp_id, Client)]),
        ),
        (
            ADMINS_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Admin)]),
        ),
        (
            ENDORSEMENT_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Peer)]),
        ),
    ])
}

/// The standard policies of an orderer organization, as Fabric's
/// test-network `configtx.yaml` defines them:
///
/// | Policy    | Rule                   |
/// |-----------|------------------------|
/// | `Readers` | `OR('<msp>.member')`   |
/// | `Writers` | `OR('<msp>.member')`   |
/// | `Admins`  | `OR('<msp>.admin')`    |
///
/// There is no `Endorsement` policy. `Readers` and `Writers` use the
/// `member` role, not the application org's admin/peer/client roles: the
/// orderer nodes carry the `orderer` NodeOU, and the blocks they sign must
/// satisfy `/Channel/Orderer/BlockValidation` (`ANY Writers` over the
/// orderer orgs). With `OR(admin, client)` no orderer could sign a valid
/// block.
pub fn orderer_org_policies(msp_id: &str) -> BTreeMap<String, ConfigPolicy> {
    use MspRoleType::{Admin, Member};
    BTreeMap::from([
        (
            READERS_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Member)]),
        ),
        (
            WRITERS_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Member)]),
        ),
        (
            ADMINS_POLICY.to_string(),
            signature_config_policy(&[(msp_id, Admin)]),
        ),
    ])
}

/// `MSPConfig.type` of a FABRIC (X.509) MSP (`msp.FABRIC` in Fabric).
const FABRIC_MSP_TYPE: i32 = 0;

/// The roles a NodeOU identifier can stand for, in `FabricNodeOUs` field
/// order. `Member` is not one: it means any valid identity of the MSP.
const NODE_OU_ROLES: [MspRoleType; 4] = [
    MspRoleType::Client,
    MspRoleType::Peer,
    MspRoleType::Admin,
    MspRoleType::Orderer,
];

/// The OU value Fabric CA and cryptogen put into certificates of a NodeOU
/// role (`client`, `peer`, `admin`, `orderer`); `None` for `Member`.
fn default_node_ou(role: MspRoleType) -> Option<&'static str> {
    match role {
        MspRoleType::Client => Some("client"),
        MspRoleType::Peer => Some("peer"),
        MspRoleType::Admin => Some("admin"),
        MspRoleType::Orderer => Some("orderer"),
        MspRoleType::Member => None,
    }
}

/// Builds the [`MspConfig`] of a FABRIC (X.509) MSP for a channel config,
/// the value `configtxgen` derives from an org's MSP directory
/// (`msp.GetVerifyingMspConfig`).
///
/// Certificates and the revocation list are passed as PEM and stored byte
/// for byte, as `configtxgen` stores the file contents. [`build`](Self::build)
/// checks every input; it does not check validity periods or chains.
///
/// ```rust
/// let msp = MspConfigBuilder::new("Org3MSP")
///     .with_root_cert(ca_pem.clone())
///     .with_tls_root_cert(tlsca_pem)
///     .with_node_ous(ca_pem)
///     .build()?;
/// add_application_org(&mut config, "Org3MSP", &msp, org_policies("Org3MSP"))?;
/// ```
#[derive(Clone, Debug)]
pub struct MspConfigBuilder {
    msp_id: String,
    root_certs: Vec<Vec<u8>>,
    intermediate_certs: Vec<Vec<u8>>,
    tls_root_certs: Vec<Vec<u8>>,
    tls_intermediate_certs: Vec<Vec<u8>>,
    revocation_list: Vec<Vec<u8>>,
    /// `(role, OU identifier, optional certificate)` in call order; a later
    /// entry for the same role replaces an earlier one. Empty: NodeOUs off.
    node_ous: Vec<(MspRoleType, String, Option<Vec<u8>>)>,
}

impl MspConfigBuilder {
    /// Starts an MSP config for the given MSP ID.
    pub fn new(msp_id: impl Into<String>) -> Self {
        MspConfigBuilder {
            msp_id: msp_id.into(),
            root_certs: vec![],
            intermediate_certs: vec![],
            tls_root_certs: vec![],
            tls_intermediate_certs: vec![],
            revocation_list: vec![],
            node_ous: vec![],
        }
    }

    /// Adds a root CA certificate (PEM). At least one is required.
    pub fn with_root_cert(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.root_certs.push(pem.into());
        self
    }

    /// Adds an intermediate CA certificate (PEM).
    pub fn with_intermediate_cert(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.intermediate_certs.push(pem.into());
        self
    }

    /// Adds a TLS root CA certificate (PEM).
    pub fn with_tls_root_cert(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.tls_root_certs.push(pem.into());
        self
    }

    /// Adds a TLS intermediate CA certificate (PEM).
    pub fn with_tls_intermediate_cert(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.tls_intermediate_certs.push(pem.into());
        self
    }

    /// Adds a certificate revocation list (PEM, `X509 CRL`).
    pub fn with_revocation_list(mut self, crl_pem: impl Into<Vec<u8>>) -> Self {
        self.revocation_list.push(crl_pem.into());
        self
    }

    /// Enables NodeOUs with the four standard identifiers (`client`, `peer`,
    /// `admin`, `orderer`), each bound to `ca_cert_pem`. This is the
    /// `config.yaml` that cryptogen and Fabric CA deployments generate.
    ///
    /// `ca_cert_pem` must also be added as a root or intermediate
    /// certificate.
    pub fn with_node_ous(mut self, ca_cert_pem: impl Into<Vec<u8>>) -> Self {
        let cert = ca_cert_pem.into();
        for role in NODE_OU_ROLES {
            let ou = default_node_ou(role).unwrap_or_default();
            self = self.with_node_ou(role, ou, Some(cert.clone()));
        }
        self
    }

    /// Enables NodeOUs and sets the identifier of one role: certificates
    /// whose OU is `ou_identifier` are classified as `role`. With
    /// `certificate` set, only certificates issued by that root or
    /// intermediate CA are.
    ///
    /// `role` is `Client`, `Peer`, `Admin` or `Orderer`; [`build`](Self::build)
    /// rejects `Member`, which has no NodeOU.
    pub fn with_node_ou(
        mut self,
        role: MspRoleType,
        ou_identifier: impl Into<String>,
        certificate: Option<Vec<u8>>,
    ) -> Self {
        self.node_ous
            .push((role, ou_identifier.into(), certificate));
        self
    }

    /// Validates the inputs and builds the FABRIC [`MspConfig`]
    /// (`type` 0, `config` = encoded [`FabricMspConfig`]).
    ///
    /// Errors:
    /// - [`ConfigTxError::MissingMspField`] without MSP ID or root
    ///   certificate,
    /// - [`ConfigTxError::InvalidPem`] for an input that is not exactly one
    ///   PEM certificate (CRL for the revocation list),
    /// - [`ConfigTxError::InvalidNodeOuRole`] for a NodeOU set for
    ///   `MspRoleType::Member`,
    /// - [`ConfigTxError::NodeOuCertNotInChain`] for a NodeOU certificate
    ///   that is not one of the root or intermediate certificates.
    pub fn build(self) -> Result<MspConfig, ConfigTxError> {
        Ok(MspConfig {
            r#type: FABRIC_MSP_TYPE,
            config: self.build_fabric_config()?.encode_to_vec(),
        })
    }

    /// Like [`build`](Self::build), but returns the [`FabricMspConfig`]
    /// before encoding.
    pub fn build_fabric_config(self) -> Result<FabricMspConfig, ConfigTxError> {
        if self.msp_id.is_empty() {
            return Err(ConfigTxError::MissingMspField("msp id"));
        }
        if self.root_certs.is_empty() {
            return Err(ConfigTxError::MissingMspField("root certificate"));
        }

        let root_ders = certificates_der("root_certs", &self.root_certs)?;
        let intermediate_ders = certificates_der("intermediate_certs", &self.intermediate_certs)?;
        certificates_der("tls_root_certs", &self.tls_root_certs)?;
        certificates_der("tls_intermediate_certs", &self.tls_intermediate_certs)?;
        for (i, crl) in self.revocation_list.iter().enumerate() {
            CertificateList::<Rfc5280>::from_pem(crl).map_err(|e| ConfigTxError::InvalidPem {
                field: format!("revocation_list[{}]", i),
                reason: e.to_string(),
            })?;
        }

        let fabric_node_ous = if self.node_ous.is_empty() {
            None
        } else {
            let mut ou_identifiers: [Option<FabricOuIdentifier>; 4] = Default::default();
            for (role, ou, certificate) in self.node_ous {
                let Some(slot) = NODE_OU_ROLES.iter().position(|r| *r == role) else {
                    return Err(ConfigTxError::InvalidNodeOuRole(role));
                };
                let certificate = certificate.unwrap_or_default();
                if !certificate.is_empty() {
                    let field = format!("node_ous.{}", role.as_str_name().to_lowercase());
                    let der = certificate_der(field, &certificate)?;
                    if !root_ders.contains(&der) && !intermediate_ders.contains(&der) {
                        return Err(ConfigTxError::NodeOuCertNotInChain(role));
                    }
                }
                ou_identifiers[slot] = Some(FabricOuIdentifier {
                    certificate,
                    organizational_unit_identifier: ou,
                });
            }
            let [client, peer, admin, orderer] = ou_identifiers;
            Some(FabricNodeOUs {
                enable: true,
                client_ou_identifier: client,
                peer_ou_identifier: peer,
                admin_ou_identifier: admin,
                orderer_ou_identifier: orderer,
            })
        };

        Ok(FabricMspConfig {
            name: self.msp_id,
            root_certs: self.root_certs,
            intermediate_certs: self.intermediate_certs,
            admins: vec![],
            revocation_list: self.revocation_list,
            signing_identity: None,
            organizational_unit_identifiers: vec![],
            crypto_config: Some(FabricCryptoConfig {
                signature_hash_family: "SHA2".into(),
                identity_identifier_hash_function: "SHA256".into(),
            }),
            tls_root_certs: self.tls_root_certs,
            tls_intermediate_certs: self.tls_intermediate_certs,
            fabric_node_ous,
        })
    }
}

/// Parses exactly one PEM `CERTIFICATE` and returns its DER encoding.
fn certificate_der(field: String, pem: &[u8]) -> Result<Vec<u8>, ConfigTxError> {
    Certificate::from_pem(pem)
        .and_then(|cert| cert.to_der())
        .map_err(|e| ConfigTxError::InvalidPem {
            field,
            reason: e.to_string(),
        })
}

fn certificates_der(field: &str, pems: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ConfigTxError> {
    pems.iter()
        .enumerate()
        .map(|(i, pem)| certificate_der(format!("{}[{}]", field, i), pem))
        .collect()
}

fn consensus_metadata_mut(
    config: &mut Config,
) -> Result<(&mut ConfigValue, ConsensusType, etcdraft::ConfigMetadata), ConfigTxError> {
    let orderer = channel_group_mut(config)?
        .groups
        .get_mut(ORDERER_GROUP)
        .ok_or_else(|| ConfigTxError::ElementNotFound(ORDERER_GROUP.into()))?;

    let value = orderer
        .values
        .get_mut(CONSENSUS_TYPE_KEY)
        .ok_or_else(|| ConfigTxError::ElementNotFound(CONSENSUS_TYPE_KEY.into()))?;

    let consensus_type = ConsensusType::decode(value.value.as_slice())
        .map_err(|_| ConfigTxError::DecodeError("Failed to decode ConsensusType"))?;

    if consensus_type.r#type != ETCDRAFT_TYPE {
        return Err(ConfigTxError::UnsupportedConsensusType(
            consensus_type.r#type.clone(),
        ));
    }

    let metadata = etcdraft::ConfigMetadata::decode(consensus_type.metadata.as_slice())
        .map_err(|_| ConfigTxError::DecodeError("Failed to decode etcdraft ConfigMetadata"))?;

    Ok((value, consensus_type, metadata))
}

/// Adds a consenter (orderer node) to the channel's etcdraft consenter set.
///
/// Decodes the `Orderer` group's `ConsensusType` value, appends `consenter`
/// to the etcdraft `ConfigMetadata` and re-encodes it.
///
/// Returns [`ConfigTxError::UnsupportedConsensusType`] if the channel does
/// not use etcdraft and [`ConfigTxError::AlreadyExists`] if a consenter with
/// the same host and port is already present.
pub fn add_consenter(
    config: &mut Config,
    consenter: etcdraft::Consenter,
) -> Result<(), ConfigTxError> {
    let (value, mut consensus_type, mut metadata) = consensus_metadata_mut(config)?;

    if metadata
        .consenters
        .iter()
        .any(|c| c.host == consenter.host && c.port == consenter.port)
    {
        return Err(ConfigTxError::AlreadyExists(format!(
            "Consenter {}:{}",
            consenter.host, consenter.port
        )));
    }

    metadata.consenters.push(consenter);
    consensus_type.metadata = metadata.encode_to_vec();
    value.value = consensus_type.encode_to_vec();
    Ok(())
}

/// Removes the consenter with the given host and port from the channel's
/// etcdraft consenter set.
///
/// Returns [`ConfigTxError::ElementNotFound`] if no consenter with that
/// host/port exists and [`ConfigTxError::UnsupportedConsensusType`] if the
/// channel does not use etcdraft.
pub fn remove_consenter(
    config: &mut Config,
    host: &str,
    port: u32,
) -> Result<(), ConfigTxError> {
    let (value, mut consensus_type, mut metadata) = consensus_metadata_mut(config)?;

    let before = metadata.consenters.len();
    metadata
        .consenters
        .retain(|c| !(c.host == host && c.port == port));
    if metadata.consenters.len() == before {
        return Err(ConfigTxError::ElementNotFound(format!(
            "Consenter {}:{}",
            host, port
        )));
    }

    consensus_type.metadata = metadata.encode_to_vec();
    value.value = consensus_type.encode_to_vec();
    Ok(())
}

// =====================================================================
// Genesis block
//
// Port of configtxgen -outputBlock for an application channel without a
// system channel (hyperledger/fabric internal/configtxgen/encoder and
// common/genesis, release-2.5, Apache-2.0).
// =====================================================================

const HASHING_ALGORITHM_KEY: &str = "HashingAlgorithm";
const BLOCK_DATA_HASHING_STRUCTURE_KEY: &str = "BlockDataHashingStructure";
const ORDERER_ADDRESSES_KEY: &str = "OrdererAddresses";
const CAPABILITIES_KEY: &str = "Capabilities";
const ACLS_KEY: &str = "ACLs";
const BATCH_SIZE_KEY: &str = "BatchSize";
const BATCH_TIMEOUT_KEY: &str = "BatchTimeout";
const CHANNEL_RESTRICTIONS_KEY: &str = "ChannelRestrictions";
const ENDPOINTS_KEY: &str = "Endpoints";
const BLOCK_VALIDATION_POLICY: &str = "BlockValidation";
const LIFECYCLE_ENDORSEMENT_POLICY: &str = "LifecycleEndorsement";
/// Mod policy of the channel-level `OrdererAddresses` value.
const ORDERER_ADMINS_POLICY_PATH: &str = "/Channel/Orderer/Admins";
/// `configtx.MaxLength` in Fabric.
const CHANNEL_ID_MAX_LENGTH: usize = 249;
/// `msgVersion` of Fabric's `common/genesis` (the encoder uses 0, the
/// genesis factory 1).
const GENESIS_CHANNEL_HEADER_VERSION: i32 = 1;

/// An application organization of a new channel: the `Application/<name>`
/// group of the genesis block.
#[derive(Clone, Debug)]
pub struct ApplicationOrg {
    name: String,
    msp: MspConfig,
    policies: BTreeMap<String, ConfigPolicy>,
    anchor_peers: Vec<AnchorPeer>,
}

impl ApplicationOrg {
    /// An org with the given MSP and the standard [`org_policies`] for
    /// `msp_id`. The group is named after the MSP ID, as
    /// [`add_application_org`] names it.
    ///
    /// `msp_id` must be the MSP ID inside `msp`; the policies refer to it.
    pub fn new(msp_id: &str, msp: MspConfig) -> Self {
        ApplicationOrg {
            name: msp_id.to_string(),
            msp,
            policies: org_policies(msp_id),
            anchor_peers: vec![],
        }
    }

    /// Names the group differently from the MSP ID (`Name` in
    /// `configtx.yaml`).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Replaces the standard policies.
    pub fn with_policies(mut self, policies: BTreeMap<String, ConfigPolicy>) -> Self {
        self.policies = policies;
        self
    }

    /// Adds an anchor peer. Without any, the group has no `AnchorPeers`
    /// value, as with `configtxgen`.
    pub fn with_anchor_peer(mut self, host: impl Into<String>, port: i32) -> Self {
        self.anchor_peers.push(AnchorPeer {
            host: host.into(),
            port,
        });
        self
    }

    fn group(&self) -> ConfigGroup {
        let mut group = org_group(&self.msp, self.policies.clone());
        if !self.anchor_peers.is_empty() {
            group.values.insert(
                ANCHOR_PEERS_KEY.into(),
                admins_value(
                    AnchorPeers {
                        anchor_peers: self.anchor_peers.clone(),
                    }
                    .encode_to_vec(),
                ),
            );
        }
        group
    }
}

/// An orderer organization of a new channel: the `Orderer/<name>` group of
/// the genesis block.
#[derive(Clone, Debug)]
pub struct OrdererOrg {
    name: String,
    msp: MspConfig,
    policies: BTreeMap<String, ConfigPolicy>,
    endpoints: Vec<String>,
}

impl OrdererOrg {
    /// An org with the given MSP and the standard [`orderer_org_policies`]
    /// for `msp_id`, its group named after the MSP ID.
    ///
    /// `msp_id` must be the MSP ID inside `msp`; the policies refer to it.
    pub fn new(msp_id: &str, msp: MspConfig) -> Self {
        OrdererOrg {
            name: msp_id.to_string(),
            msp,
            policies: orderer_org_policies(msp_id),
            endpoints: vec![],
        }
    }

    /// Names the group differently from the MSP ID (`Name` in
    /// `configtx.yaml`, e.g. the test-network's `OrdererOrg`).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Replaces the standard policies.
    pub fn with_policies(mut self, policies: BTreeMap<String, ConfigPolicy>) -> Self {
        self.policies = policies;
        self
    }

    /// Adds an orderer endpoint (`host:port`) clients and peers deliver
    /// from (`OrdererEndpoints` in `configtx.yaml`).
    pub fn with_endpoint(mut self, address: impl Into<String>) -> Self {
        self.endpoints.push(address.into());
        self
    }

    fn group(&self) -> ConfigGroup {
        let mut group = org_group(&self.msp, self.policies.clone());
        if !self.endpoints.is_empty() {
            group.values.insert(
                ENDPOINTS_KEY.into(),
                admins_value(
                    OrdererAddresses {
                        addresses: self.endpoints.clone(),
                    }
                    .encode_to_vec(),
                ),
            );
        }
        group
    }
}

/// Builds the genesis block (block 0) of an application channel, as
/// `configtxgen -outputBlock` does for a profile without a system channel.
/// Join the orderers with it through the channel participation API
/// ([`OsnadminClient::join_channel`](crate::osnadmin::OsnadminClient)),
/// then the peers through cscc `JoinChain`.
///
/// The config tree has the standard layout `configtxgen` writes:
///
/// - `Channel`: `Readers`/`Writers` `ANY`, `Admins` `MAJORITY`;
///   `HashingAlgorithm` SHA256, `BlockDataHashingStructure`, `Capabilities`,
///   and `OrdererAddresses` only if set with
///   [`with_orderer_address`](Self::with_orderer_address).
/// - `Channel/Orderer`: `Readers`/`Writers` `ANY`, `Admins` `MAJORITY`,
///   `BlockValidation` `ANY Writers`; `ConsensusType` etcdraft, `BatchSize`,
///   `BatchTimeout`, `ChannelRestrictions`, `Capabilities`; one group per
///   orderer org.
/// - `Channel/Application`: `Readers`/`Writers` `ANY`, `Admins`,
///   `Endorsement` and `LifecycleEndorsement` `MAJORITY`; `Capabilities`,
///   `ACLs` if set; one group per application org.
///
/// Defaults are `configtxgen`'s: batch size 500 messages / 10 MiB absolute /
/// 2 MiB preferred, batch timeout `2s`, etcdraft options tick `500ms`,
/// election 10, heartbeat 1, 5 in-flight blocks, 16 MiB snapshot interval;
/// capabilities `V2_0` (channel, orderer) and `V2_5` (application).
///
/// ```rust
/// let block = GenesisBuilder::new("mychannel")
///     .with_application_org(ApplicationOrg::new("Org1MSP", org1_msp).with_anchor_peer("peer0.org1", 7051))
///     .with_orderer_org(OrdererOrg::new("OrdererMSP", orderer_msp).with_endpoint("orderer:7050"))
///     .with_consenter("orderer", 7050, tls_cert_pem.clone(), tls_cert_pem)
///     .build()?;
/// osnadmin.join_channel(block.encode_to_vec()).await?;
/// ```
#[derive(Clone, Debug)]
pub struct GenesisBuilder {
    channel_id: String,
    application_orgs: Vec<ApplicationOrg>,
    orderer_orgs: Vec<OrdererOrg>,
    consenters: Vec<etcdraft::Consenter>,
    etcdraft_options: etcdraft::Options,
    batch_size: BatchSize,
    batch_timeout: String,
    orderer_addresses: Vec<String>,
    channel_capabilities: Vec<String>,
    orderer_capabilities: Vec<String>,
    application_capabilities: Vec<String>,
    acls: BTreeMap<String, String>,
}

impl GenesisBuilder {
    /// Starts a genesis block for `channel_id` with `configtxgen`'s
    /// defaults.
    pub fn new(channel_id: impl Into<String>) -> Self {
        GenesisBuilder {
            channel_id: channel_id.into(),
            application_orgs: vec![],
            orderer_orgs: vec![],
            consenters: vec![],
            etcdraft_options: etcdraft::Options {
                tick_interval: "500ms".into(),
                election_tick: 10,
                heartbeat_tick: 1,
                max_inflight_blocks: 5,
                snapshot_interval_size: 16 * 1024 * 1024,
            },
            batch_size: BatchSize {
                max_message_count: 500,
                absolute_max_bytes: 10 * 1024 * 1024,
                preferred_max_bytes: 2 * 1024 * 1024,
            },
            batch_timeout: "2s".into(),
            orderer_addresses: vec![],
            channel_capabilities: vec!["V2_0".into()],
            orderer_capabilities: vec!["V2_0".into()],
            application_capabilities: vec!["V2_5".into()],
            acls: BTreeMap::new(),
        }
    }

    /// Adds an application organization. At least one is required.
    pub fn with_application_org(mut self, org: ApplicationOrg) -> Self {
        self.application_orgs.push(org);
        self
    }

    /// Adds an orderer organization. At least one is required.
    pub fn with_orderer_org(mut self, org: OrdererOrg) -> Self {
        self.orderer_orgs.push(org);
        self
    }

    /// Adds an etcdraft consenter. The TLS certificates are PEM, as
    /// `configtxgen` embeds the files `ClientTLSCert`/`ServerTLSCert` point
    /// to. At least one consenter is required.
    pub fn with_consenter(
        mut self,
        host: impl Into<String>,
        port: u32,
        client_tls_cert_pem: impl Into<Vec<u8>>,
        server_tls_cert_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.consenters.push(etcdraft::Consenter {
            host: host.into(),
            port,
            client_tls_cert: client_tls_cert_pem.into(),
            server_tls_cert: server_tls_cert_pem.into(),
        });
        self
    }

    /// Replaces the etcdraft options.
    pub fn with_etcdraft_options(mut self, options: etcdraft::Options) -> Self {
        self.etcdraft_options = options;
        self
    }

    /// Sets the batch size: `max_message_count` messages,
    /// `absolute_max_bytes` hard limit, `preferred_max_bytes` target.
    pub fn with_batch_size(
        mut self,
        max_message_count: u32,
        absolute_max_bytes: u32,
        preferred_max_bytes: u32,
    ) -> Self {
        self.batch_size = BatchSize {
            max_message_count,
            absolute_max_bytes,
            preferred_max_bytes,
        };
        self
    }

    /// Sets the batch timeout as a Go duration string (`"2s"`, `"500ms"`,
    /// `"1m30s"`), the format the orderer parses.
    pub fn with_batch_timeout(mut self, timeout: impl Into<String>) -> Self {
        self.batch_timeout = timeout.into();
        self
    }

    /// Adds a channel-level orderer address (`Orderer.Addresses` in
    /// `configtx.yaml`). Fabric deprecates it in favour of the per-org
    /// [`OrdererOrg::with_endpoint`]; without any, the value is omitted.
    pub fn with_orderer_address(mut self, address: impl Into<String>) -> Self {
        self.orderer_addresses.push(address.into());
        self
    }

    /// Replaces the channel capabilities (default `V2_0`). An empty list
    /// omits the value.
    pub fn with_channel_capabilities<I, S>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.channel_capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces the orderer capabilities (default `V2_0`). An empty list
    /// omits the value.
    pub fn with_orderer_capabilities<I, S>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.orderer_capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces the application capabilities (default `V2_5`). An empty list
    /// omits the value.
    pub fn with_application_capabilities<I, S>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.application_capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    /// Sets an ACL: `resource` (e.g. `"qscc/GetBlockByNumber"`) is guarded
    /// by the policy at `policy_ref` (e.g. `"/Channel/Application/Readers"`).
    /// Without any, the `ACLs` value is omitted and the peer's defaults
    /// apply.
    pub fn with_acl(mut self, resource: impl Into<String>, policy_ref: impl Into<String>) -> Self {
        self.acls.insert(resource.into(), policy_ref.into());
        self
    }

    /// Validates the inputs and builds the channel [`Config`] (sequence 0)
    /// the genesis block carries.
    ///
    /// Errors:
    /// - [`ConfigTxError::InvalidChannelId`],
    /// - [`ConfigTxError::MissingGenesisField`] without application org,
    ///   orderer org or consenter,
    /// - [`ConfigTxError::AlreadyExists`] for two orgs with the same group
    ///   name in the same section,
    /// - [`ConfigTxError::InvalidPem`] for a consenter TLS certificate that
    ///   is not a PEM certificate,
    /// - [`ConfigTxError::InvalidOrdererValue`] for settings the orderer
    ///   would refuse (zero batch sizes, preferred above absolute bytes, a
    ///   non-positive or malformed duration, election tick not above
    ///   heartbeat tick, a consenter without host or port).
    pub fn build_config(&self) -> Result<Config, ConfigTxError> {
        self.validate()?;

        let mut orderer = ConfigGroup {
            version: 0,
            groups: BTreeMap::new(),
            values: BTreeMap::new(),
            policies: BTreeMap::from([
                (
                    READERS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, READERS_POLICY),
                ),
                (
                    WRITERS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, WRITERS_POLICY),
                ),
                (
                    ADMINS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Majority, ADMINS_POLICY),
                ),
                (
                    BLOCK_VALIDATION_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, WRITERS_POLICY),
                ),
            ]),
            mod_policy: ADMINS_POLICY.into(),
        };
        orderer.values.insert(
            BATCH_SIZE_KEY.into(),
            admins_value(self.batch_size.encode_to_vec()),
        );
        orderer.values.insert(
            BATCH_TIMEOUT_KEY.into(),
            admins_value(
                BatchTimeout {
                    timeout: self.batch_timeout.clone(),
                }
                .encode_to_vec(),
            ),
        );
        orderer.values.insert(
            CHANNEL_RESTRICTIONS_KEY.into(),
            admins_value(ChannelRestrictions { max_count: 0 }.encode_to_vec()),
        );
        if !self.orderer_capabilities.is_empty() {
            orderer.values.insert(
                CAPABILITIES_KEY.into(),
                admins_value(encode_capabilities(&self.orderer_capabilities)),
            );
        }
        let metadata = etcdraft::ConfigMetadata {
            consenters: self.consenters.clone(),
            options: Some(self.etcdraft_options.clone()),
        };
        orderer.values.insert(
            CONSENSUS_TYPE_KEY.into(),
            admins_value(
                ConsensusType {
                    r#type: ETCDRAFT_TYPE.into(),
                    metadata: metadata.encode_to_vec(),
                    state: consensus_type::State::Normal.into(),
                }
                .encode_to_vec(),
            ),
        );
        for org in &self.orderer_orgs {
            orderer.groups.insert(org.name.clone(), org.group());
        }

        let mut application = ConfigGroup {
            version: 0,
            groups: BTreeMap::new(),
            values: BTreeMap::new(),
            policies: BTreeMap::from([
                (
                    READERS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, READERS_POLICY),
                ),
                (
                    WRITERS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, WRITERS_POLICY),
                ),
                (
                    ADMINS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Majority, ADMINS_POLICY),
                ),
                (
                    ENDORSEMENT_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Majority, ENDORSEMENT_POLICY),
                ),
                (
                    LIFECYCLE_ENDORSEMENT_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Majority, ENDORSEMENT_POLICY),
                ),
            ]),
            mod_policy: ADMINS_POLICY.into(),
        };
        if !self.acls.is_empty() {
            application
                .values
                .insert(ACLS_KEY.into(), admins_value(encode_acls(&self.acls)));
        }
        if !self.application_capabilities.is_empty() {
            application.values.insert(
                CAPABILITIES_KEY.into(),
                admins_value(encode_capabilities(&self.application_capabilities)),
            );
        }
        for org in &self.application_orgs {
            application.groups.insert(org.name.clone(), org.group());
        }

        let mut channel = ConfigGroup {
            version: 0,
            groups: BTreeMap::from([
                (ORDERER_GROUP.into(), orderer),
                (APPLICATION_GROUP.into(), application),
            ]),
            values: BTreeMap::new(),
            policies: BTreeMap::from([
                (
                    READERS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, READERS_POLICY),
                ),
                (
                    WRITERS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Any, WRITERS_POLICY),
                ),
                (
                    ADMINS_POLICY.into(),
                    implicit_meta_policy(ImplicitMetaRule::Majority, ADMINS_POLICY),
                ),
            ]),
            mod_policy: ADMINS_POLICY.into(),
        };
        channel.values.insert(
            HASHING_ALGORITHM_KEY.into(),
            admins_value(
                HashingAlgorithm {
                    name: "SHA256".into(),
                }
                .encode_to_vec(),
            ),
        );
        channel.values.insert(
            BLOCK_DATA_HASHING_STRUCTURE_KEY.into(),
            admins_value(BlockDataHashingStructure { width: u32::MAX }.encode_to_vec()),
        );
        if !self.orderer_addresses.is_empty() {
            channel.values.insert(
                ORDERER_ADDRESSES_KEY.into(),
                ConfigValue {
                    version: 0,
                    value: OrdererAddresses {
                        addresses: self.orderer_addresses.clone(),
                    }
                    .encode_to_vec(),
                    mod_policy: ORDERER_ADMINS_POLICY_PATH.into(),
                },
            );
        }
        if !self.channel_capabilities.is_empty() {
            channel.values.insert(
                CAPABILITIES_KEY.into(),
                admins_value(encode_capabilities(&self.channel_capabilities)),
            );
        }

        Ok(Config {
            sequence: 0,
            channel_group: Some(channel),
        })
    }

    /// Validates the inputs and builds the genesis [`Block`]: number 0, no
    /// previous hash, one unsigned `CONFIG` envelope (channel header version
    /// 1, random nonce, no creator), the data hash over it, and the
    /// metadata slots of Fabric's genesis factory (`SIGNATURES` and
    /// `LAST_CONFIG` pointing at block 0). Errors as for
    /// [`build_config`](Self::build_config).
    pub fn build(&self) -> Result<Block, ConfigTxError> {
        let config = self.build_config()?;

        let nonce = generate_nonce();
        let signature_header = SignatureHeader {
            creator: vec![],
            nonce: nonce.to_vec(),
        };
        let channel_header = ChannelHeader {
            r#type: HeaderType::Config.into(),
            version: GENESIS_CHANNEL_HEADER_VERSION,
            // Whole seconds, as Fabric's MakeChannelHeader writes them.
            timestamp: Some(Timestamp {
                nanos: 0,
                ..now_timestamp()
            }),
            channel_id: self.channel_id.clone(),
            tx_id: generate_transaction_id(&nonce, &[]),
            epoch: 0,
            extension: vec![],
            tls_cert_hash: vec![],
        };
        let payload = Payload {
            header: Some(Header {
                channel_header: channel_header.encode_to_vec(),
                signature_header: signature_header.encode_to_vec(),
            }),
            data: ConfigEnvelope {
                config: Some(config),
                last_update: None,
            }
            .encode_to_vec(),
        };
        let envelope = Envelope {
            payload: payload.encode_to_vec(),
            signature: vec![],
        };
        let data = vec![envelope.encode_to_vec()];

        let mut metadata = vec![vec![]; BlockMetadataIndex::CommitHash as usize + 1];
        metadata[BlockMetadataIndex::Signatures as usize] = Metadata {
            value: OrdererBlockMetadata {
                last_config: Some(LastConfig { index: 0 }),
                consenter_metadata: vec![],
            }
            .encode_to_vec(),
            signatures: vec![],
        }
        .encode_to_vec();
        // Fabric also writes Metadata{LastConfig{index: 0}} into the
        // deprecated LAST_CONFIG slot; every field is a proto3 default, so
        // it encodes to zero bytes and the slot stays empty.

        Ok(Block {
            header: Some(BlockHeader {
                number: 0,
                previous_hash: vec![],
                data_hash: generate_sha256_hash(&data.concat()),
            }),
            data: Some(BlockData { data }),
            metadata: Some(BlockMetadata { metadata }),
        })
    }

    fn validate(&self) -> Result<(), ConfigTxError> {
        validate_channel_id(&self.channel_id)?;
        if self.application_orgs.is_empty() {
            return Err(ConfigTxError::MissingGenesisField("application org"));
        }
        if self.orderer_orgs.is_empty() {
            return Err(ConfigTxError::MissingGenesisField("orderer org"));
        }
        if self.consenters.is_empty() {
            return Err(ConfigTxError::MissingGenesisField("consenter"));
        }
        unique_names(
            APPLICATION_GROUP,
            self.application_orgs.iter().map(|o| o.name.as_str()),
        )?;
        unique_names(
            ORDERER_GROUP,
            self.orderer_orgs.iter().map(|o| o.name.as_str()),
        )?;

        for (i, consenter) in self.consenters.iter().enumerate() {
            if consenter.host.is_empty() || consenter.port == 0 {
                return Err(ConfigTxError::InvalidOrdererValue {
                    field: "consenter",
                    reason: format!("consenter {} has no host or port", i),
                });
            }
            certificate_der(
                format!("consenters[{}].client_tls_cert", i),
                &consenter.client_tls_cert,
            )?;
            certificate_der(
                format!("consenters[{}].server_tls_cert", i),
                &consenter.server_tls_cert,
            )?;
        }

        validate_batch_size(&self.batch_size)?;
        validate_batch_timeout(&self.batch_timeout)?;

        let options = &self.etcdraft_options;
        if !go_duration_is_positive(&options.tick_interval) {
            return Err(ConfigTxError::InvalidOrdererValue {
                field: "etcdraft tick interval",
                reason: format!("'{}' is not a positive Go duration", options.tick_interval),
            });
        }
        if options.heartbeat_tick == 0 || options.election_tick <= options.heartbeat_tick {
            return Err(ConfigTxError::InvalidOrdererValue {
                field: "etcdraft ticks",
                reason: format!(
                    "election tick ({}) must be greater than heartbeat tick ({}) and heartbeat tick above 0",
                    options.election_tick, options.heartbeat_tick
                ),
            });
        }
        Ok(())
    }
}

fn validate_channel_id(channel_id: &str) -> Result<(), ConfigTxError> {
    let mut chars = channel_id.chars();
    let valid = channel_id.len() <= CHANNEL_ID_MAX_LENGTH
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if valid {
        Ok(())
    } else {
        Err(ConfigTxError::InvalidChannelId(channel_id.to_string()))
    }
}

fn unique_names<'a>(
    section: &str,
    names: impl Iterator<Item = &'a str>,
) -> Result<(), ConfigTxError> {
    let mut seen = std::collections::BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(ConfigTxError::AlreadyExists(format!(
                "{} org {}",
                section, name
            )));
        }
    }
    Ok(())
}

/// The orderer's `validateBatchSize` (common/channelconfig/orderer.go).
fn validate_batch_size(batch_size: &BatchSize) -> Result<(), ConfigTxError> {
    let reason = if batch_size.max_message_count == 0 {
        "max message count is 0".to_string()
    } else if batch_size.absolute_max_bytes == 0 {
        "absolute max bytes is 0".to_string()
    } else if batch_size.preferred_max_bytes == 0 {
        "preferred max bytes is 0".to_string()
    } else if batch_size.preferred_max_bytes > batch_size.absolute_max_bytes {
        format!(
            "preferred max bytes ({}) is greater than absolute max bytes ({})",
            batch_size.preferred_max_bytes, batch_size.absolute_max_bytes
        )
    } else {
        return Ok(());
    };
    Err(ConfigTxError::InvalidOrdererValue {
        field: "batch size",
        reason,
    })
}

/// The orderer's `validateBatchTimeout` (common/channelconfig/orderer.go).
fn validate_batch_timeout(timeout: &str) -> Result<(), ConfigTxError> {
    if go_duration_is_positive(timeout) {
        Ok(())
    } else {
        Err(ConfigTxError::InvalidOrdererValue {
            field: "batch timeout",
            reason: format!("'{}' is not a positive Go duration", timeout),
        })
    }
}

/// Whether `s` parses with Go's `time.ParseDuration` to a positive value:
/// an optional sign, then one or more `<decimal><unit>` with unit `ns`,
/// `us`/`µs`/`μs`, `ms`, `s`, `m` or `h` (`"0"` alone is zero).
fn go_duration_is_positive(s: &str) -> bool {
    let (negative, mut rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if rest.is_empty() {
        return false;
    }
    let mut total_nanos = 0f64;
    while !rest.is_empty() {
        let number_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let number = &rest[..number_len];
        if number.is_empty() || number == "." || number.matches('.').count() > 1 {
            return false;
        }
        let Ok(value) = number.parse::<f64>() else {
            return false;
        };
        rest = &rest[number_len..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let nanos_per_unit = match &rest[..unit_len] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return false,
        };
        rest = &rest[unit_len..];
        total_nanos += value * nanos_per_unit;
    }
    !negative && total_nanos >= 1.0
}

fn implicit_meta_policy(rule: ImplicitMetaRule, sub_policy: &str) -> ConfigPolicy {
    ConfigPolicy {
        version: 0,
        policy: Some(Policy {
            r#type: PolicyType::ImplicitMeta.into(),
            value: ImplicitMetaPolicy {
                sub_policy: sub_policy.into(),
                rule: rule.into(),
            }
            .encode_to_vec(),
        }),
        mod_policy: ADMINS_POLICY.into(),
    }
}

/// Encodes `Capabilities` with its map entries in sorted order. The
/// generated map is a `HashMap`, whose encoding order is random; a protobuf
/// message may be split into concatenated parts, so encoding one entry at a
/// time keeps the bytes deterministic.
///
/// Each entry is written by hand: Go's marshaller emits the empty
/// `Capability` value as an explicit empty field (`12 00`), prost omits it.
/// Both decode to the same map; writing it keeps the value byte-identical
/// to `configtxgen`'s.
fn encode_capabilities(capabilities: &[String]) -> Vec<u8> {
    use prost::encoding::{WireType, encode_key, encode_varint, encoded_len_varint};

    let sorted: std::collections::BTreeSet<&String> = capabilities.iter().collect();
    let mut buf = Vec::new();
    for name in sorted {
        // map entry: key = 1 (string), value = 2 (empty Capability message)
        let key_len = name.len();
        let entry_len = 1 + encoded_len_varint(key_len as u64) + key_len + 2;
        encode_key(1, WireType::LengthDelimited, &mut buf);
        encode_varint(entry_len as u64, &mut buf);
        encode_key(1, WireType::LengthDelimited, &mut buf);
        encode_varint(key_len as u64, &mut buf);
        buf.extend_from_slice(name.as_bytes());
        encode_key(2, WireType::LengthDelimited, &mut buf);
        encode_varint(0, &mut buf);
    }
    buf
}

/// Encodes `ACLs` with its map entries in sorted order (see
/// [`encode_capabilities`]).
fn encode_acls(acls: &BTreeMap<String, String>) -> Vec<u8> {
    acls.iter()
        .flat_map(|(resource, policy_ref)| {
            AcLs {
                acls: [(
                    resource.clone(),
                    ApiResource {
                        policy_ref: policy_ref.clone(),
                    },
                )]
                .into(),
            }
            .encode_to_vec()
        })
        .collect()
}

// =====================================================================
// ConfigUpdate signing and envelope assembly
// =====================================================================

/// Creates a [`ConfigSignature`] over the given marshaled [`ConfigUpdate`]
/// bytes.
///
/// A fresh [`SignatureHeader`] (creator = the identity's serialized MSP
/// identity, random nonce) is generated, and the signature covers
/// `signature_header_bytes || config_update_bytes`, exactly as the orderer
/// verifies it.
pub fn sign_config_update(identity: &Identity, config_update_bytes: &[u8]) -> ConfigSignature {
    let signature_header = SignatureHeader {
        creator: identity.get_serialized_identity().encode_to_vec(),
        nonce: generate_nonce().to_vec(),
    };
    let signature_header_bytes = signature_header.encode_to_vec();

    let mut message =
        Vec::with_capacity(signature_header_bytes.len() + config_update_bytes.len());
    message.extend_from_slice(&signature_header_bytes);
    message.extend_from_slice(config_update_bytes);

    ConfigSignature {
        signature: identity.sign_message(&message),
        signature_header: signature_header_bytes,
    }
}

/// Wraps a [`ConfigUpdate`] into an unsigned [`ConfigUpdateEnvelope`].
///
/// Collect signatures with [`add_signature`] afterwards.
pub fn create_config_update_envelope(config_update: &ConfigUpdate) -> ConfigUpdateEnvelope {
    ConfigUpdateEnvelope {
        config_update: config_update.encode_to_vec(),
        signatures: vec![],
    }
}

/// Appends this identity's [`ConfigSignature`] to the envelope, preserving any
/// signatures already collected from other organizations.
pub fn add_signature(envelope: &mut ConfigUpdateEnvelope, identity: &Identity) {
    let signature = sign_config_update(identity, &envelope.config_update);
    envelope.signatures.push(signature);
}

/// Serializes a [`ConfigUpdateEnvelope`] for out-of-band passing (e.g. to
/// another organization's admin for counter-signing).
pub fn encode_config_update_envelope(envelope: &ConfigUpdateEnvelope) -> Vec<u8> {
    envelope.encode_to_vec()
}

/// Deserializes a [`ConfigUpdateEnvelope`] received out-of-band.
pub fn decode_config_update_envelope(
    bytes: &[u8],
) -> Result<ConfigUpdateEnvelope, ConfigTxError> {
    ConfigUpdateEnvelope::decode(bytes)
        .map_err(|_| ConfigTxError::DecodeError("Failed to decode ConfigUpdateEnvelope"))
}

/// The current time as a protobuf timestamp (`web_time` under WASM, where
/// `std::time::SystemTime::now` panics).
fn now_timestamp() -> Timestamp {
    #[cfg(feature = "client-wasm")]
    {
        Timestamp {
            seconds: web_time::SystemTime::now()
                .duration_since(web_time::SystemTime::UNIX_EPOCH)
                .expect("Invalid duration calc")
                .as_secs() as i64,
            nanos: 0,
        }
    }
    #[cfg(not(feature = "client-wasm"))]
    {
        std::time::SystemTime::now().into()
    }
}

/// Assembles the final signed `CONFIG_UPDATE` transaction [`Envelope`] ready
/// for submission to the orderer.
///
/// The channel ID is taken from the [`ConfigUpdate`] inside the envelope. The
/// channel header uses header type `CONFIG_UPDATE` and a transaction ID
/// derived from a fresh nonce and the submitter's identity, consistent with
/// the SDK's proposal code.
pub fn build_config_update_transaction(
    identity: &Identity,
    update_envelope: &ConfigUpdateEnvelope,
) -> Result<Envelope, ConfigTxError> {
    let config_update = ConfigUpdate::decode(update_envelope.config_update.as_slice())
        .map_err(|_| ConfigTxError::DecodeError("Failed to decode ConfigUpdate"))?;
    if config_update.channel_id.is_empty() {
        return Err(ConfigTxError::ElementNotFound(
            "channel_id in ConfigUpdate".into(),
        ));
    }

    let nonce = generate_nonce();
    let creator = identity.get_serialized_identity().encode_to_vec();
    let transaction_id = generate_transaction_id(&nonce, creator.as_slice());

    let signature_header = SignatureHeader {
        creator,
        nonce: nonce.to_vec(),
    };

    let channel_header = ChannelHeader {
        r#type: HeaderType::ConfigUpdate.into(),
        version: 0,
        timestamp: Some(now_timestamp()),
        channel_id: config_update.channel_id.clone(),
        tx_id: transaction_id,
        epoch: 0,
        extension: vec![],
        // Not used for config update envelopes (no mutual-TLS binding).
        tls_cert_hash: vec![],
    };

    let payload = Payload {
        header: Some(Header {
            channel_header: channel_header.encode_to_vec(),
            signature_header: signature_header.encode_to_vec(),
        }),
        data: update_envelope.encode_to_vec(),
    };

    let payload_bytes = payload.encode_to_vec();
    let signature = identity.sign_message(&payload_bytes);

    Ok(Envelope {
        payload: payload_bytes,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric::common::Capabilities;
    use crate::identity::IdentityBuilder;
    use ecdsa::signature::Verifier;

    // Self-signed P-256 test identities, generated with openssl for these
    // tests only. PUB*_SEC1 is the uncompressed public key point extracted
    // from the corresponding certificate.
    const TEST_KEY_1: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkGIL2EmB5UG58e6m
VQ2Nnh8+3pce12DNtl7vdTgbNPahRANCAARkkRuoTjWvefAXi7VjpPZm/8/qho9H
mXaF7nf0SQs1dnKvYsi+FMusBuX8R05cD0/Oewq8rmzCzDx1WvCFnmh4
-----END PRIVATE KEY-----
";
    const TEST_CERT_1: &str = "-----BEGIN CERTIFICATE-----
MIIBqjCCAU+gAwIBAgIUHFEaKg/B8/K9HROJzqLOe4mpBogwCgYIKoZIzj0EAwIw
KjEWMBQGA1UEAwwNdGVzdC1zaWduZXItMTEQMA4GA1UECgwHT3JnMU1TUDAeFw0y
NjA4MDYxNzQ3MDZaFw00NjA4MDExNzQ3MDZaMCoxFjAUBgNVBAMMDXRlc3Qtc2ln
bmVyLTExEDAOBgNVBAoMB09yZzFNU1AwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARkkRuoTjWvefAXi7VjpPZm/8/qho9HmXaF7nf0SQs1dnKvYsi+FMusBuX8R05c
D0/Oewq8rmzCzDx1WvCFnmh4o1MwUTAdBgNVHQ4EFgQUpY4xjEUN/bqJgnUR32ia
zlSeTGQwHwYDVR0jBBgwFoAUpY4xjEUN/bqJgnUR32iazlSeTGQwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAwMJOXR1Ekl5dfHGVJ2SsoZeHC1zU
lPYMTD/oaOvGbDYCIQDSg9VLiwxIt699g6IObw3pOZYjfpikD2PpPTpouie4Sw==
-----END CERTIFICATE-----
";
    const PUB1_SEC1: &str = "0464911ba84e35af79f0178bb563a4f666ffcfea868f47997685ee77f4490b357672af62c8be14cbac06e5fc474e5c0f4fce7b0abcae6cc2cc3c755af0859e6878";

    const TEST_KEY_2: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQvpY/jNBuzqVzCEQ
QJqnGiGqXqREII6A6rjvMYbIYpWhRANCAARHUF1BT0w89bG+GKCVwWlRBGMK6rRr
P/SbF6y/unU+v52X1pvGFgB3R4PvHP8mUEIqOtwklSnpQMuAy0AkX+uQ
-----END PRIVATE KEY-----
";
    const TEST_CERT_2: &str = "-----BEGIN CERTIFICATE-----
MIIBqTCCAU+gAwIBAgIUWqDNTQhr9LRLIXxCc/w/8JqvIf0wCgYIKoZIzj0EAwIw
KjEWMBQGA1UEAwwNdGVzdC1zaWduZXItMjEQMA4GA1UECgwHT3JnMk1TUDAeFw0y
NjA4MDYxNzQ3MDZaFw00NjA4MDExNzQ3MDZaMCoxFjAUBgNVBAMMDXRlc3Qtc2ln
bmVyLTIxEDAOBgNVBAoMB09yZzJNU1AwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARHUF1BT0w89bG+GKCVwWlRBGMK6rRrP/SbF6y/unU+v52X1pvGFgB3R4PvHP8m
UEIqOtwklSnpQMuAy0AkX+uQo1MwUTAdBgNVHQ4EFgQUC4316gxLaEBCzuCv/RWn
4ME+D38wHwYDVR0jBBgwFoAUC4316gxLaEBCzuCv/RWn4ME+D38wDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiB9F+bNbxzviGs2yu8QPEuEDKK8Tryu
4yvn0r72rFpKnwIhAP9qau4XPqz9mB6OYf9++BVW3wR7FuenpeqbktbPLAvA
-----END CERTIFICATE-----
";
    const PUB2_SEC1: &str = "0447505d414f4c3cf5b1be18a095c1695104630aeab46b3ff49b17acbfba753ebf9d97d69bc61600774783ef1cff2650422a3adc249529e940cb80cb40245feb90";

    fn identity1() -> Identity {
        IdentityBuilder::from_pem(TEST_CERT_1.as_bytes())
            .unwrap()
            .with_msp("Org1MSP")
            .unwrap()
            .with_private_key(TEST_KEY_1.to_string())
            .unwrap()
            .build()
            .unwrap()
    }

    fn identity2() -> Identity {
        IdentityBuilder::from_pem(TEST_CERT_2.as_bytes())
            .unwrap()
            .with_msp("Org2MSP")
            .unwrap()
            .with_private_key(TEST_KEY_2.to_string())
            .unwrap()
            .build()
            .unwrap()
    }

    /// Verifies a DER ECDSA-SHA256 signature against a SEC1 public key point
    /// (as extracted from the signer's certificate).
    fn verify_signature(pubkey_sec1_hex: &str, message: &[u8], signature_der: &[u8]) -> bool {
        let point = hex::decode(pubkey_sec1_hex).unwrap();
        let verifying_key =
            ecdsa::VerifyingKey::<p256::NistP256>::from_sec1_bytes(&point).unwrap();
        let Ok(signature) = ecdsa::Signature::<p256::NistP256>::from_der(signature_der) else {
            return false;
        };
        verifying_key.verify(message, &signature).is_ok()
    }

    // ----- config tree construction helpers -----

    fn value(version: u64, bytes: &[u8], mod_policy: &str) -> ConfigValue {
        ConfigValue {
            version,
            value: bytes.to_vec(),
            mod_policy: mod_policy.into(),
        }
    }

    fn policy(version: u64, rule: &[u8], mod_policy: &str) -> ConfigPolicy {
        ConfigPolicy {
            version,
            policy: Some(crate::fabric::common::Policy {
                r#type: 3, // ImplicitMeta
                value: rule.to_vec(),
            }),
            mod_policy: mod_policy.into(),
        }
    }

    fn group(version: u64, mod_policy: &str) -> ConfigGroup {
        ConfigGroup {
            version,
            mod_policy: mod_policy.into(),
            ..Default::default()
        }
    }

    fn config(channel_group: ConfigGroup) -> Config {
        Config {
            sequence: 0,
            channel_group: Some(channel_group),
        }
    }

    /// A read/write set reference to an unchanged group: only the version.
    fn version_ref(version: u64) -> ConfigGroup {
        ConfigGroup {
            version,
            ..Default::default()
        }
    }

    // =========================================================
    // compute_config_update — Tier 1
    // =========================================================

    #[test]
    fn identical_configs_yield_no_differences() {
        let mut g = group(3, "Admins");
        g.values.insert("A".into(), value(1, b"x", "Admins"));
        let original = config(g.clone());
        let updated = config(g);

        match compute_config_update(&original, &updated, "chan") {
            Err(ConfigTxError::NoDifferences) => {}
            other => panic!("expected NoDifferences, got {:?}", other),
        }
    }

    #[test]
    fn empty_identical_configs_yield_no_differences() {
        let original = config(ConfigGroup::default());
        let updated = config(ConfigGroup::default());
        match compute_config_update(&original, &updated, "chan") {
            Err(ConfigTxError::NoDifferences) => {}
            other => panic!("expected NoDifferences, got {:?}", other),
        }
    }

    #[test]
    fn missing_channel_group_is_rejected() {
        let no_group = Config {
            sequence: 0,
            channel_group: None,
        };
        let ok = config(ConfigGroup::default());

        match compute_config_update(&no_group, &ok, "chan") {
            Err(ConfigTxError::NoChannelGroup("original")) => {}
            other => panic!("expected NoChannelGroup(original), got {:?}", other),
        }
        match compute_config_update(&ok, &no_group, "chan") {
            Err(ConfigTxError::NoChannelGroup("updated")) => {}
            other => panic!("expected NoChannelGroup(updated), got {:?}", other),
        }
    }

    #[test]
    fn value_change_bumps_value_version_only() {
        let mut g = group(0, "Admins");
        g.values.insert("A".into(), value(1, b"x", "Admins"));
        g.values.insert("B".into(), value(2, b"y", "Admins"));
        let original = config(g.clone());

        let mut g2 = g.clone();
        g2.values.get_mut("A").unwrap().value = b"x2".to_vec();
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        assert_eq!(update.channel_id, "chan");

        // Read set: bare group reference, no members (leaf read sets are empty).
        assert_eq!(update.read_set.unwrap(), version_ref(0));

        // Write set: group at same version, only the changed value, version-bumped.
        let mut expected_write = version_ref(0);
        expected_write
            .values
            .insert("A".into(), value(2, b"x2", "Admins"));
        assert_eq!(update.write_set.unwrap(), expected_write);
    }

    #[test]
    fn mod_policy_change_counts_as_value_change() {
        let mut g = group(0, "Admins");
        g.values.insert("A".into(), value(5, b"x", "Admins"));
        let original = config(g.clone());

        let mut g2 = g.clone();
        g2.values.get_mut("A").unwrap().mod_policy = "Writers".into();
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let mut expected_write = version_ref(0);
        expected_write
            .values
            .insert("A".into(), value(6, b"x", "Writers"));
        assert_eq!(update.write_set.unwrap(), expected_write);
    }

    #[test]
    fn nested_value_change_at_depth_three() {
        // channel -> Application(v1) -> Org1MSP(v2) -> AnchorPeers value
        let mut org = group(2, "Admins");
        org.values.insert("AnchorPeers".into(), value(0, b"ap", "Admins"));
        let mut app = group(1, "Admins");
        app.groups.insert("Org1MSP".into(), org);
        let mut channel = group(0, "Admins");
        channel.groups.insert("Application".into(), app);
        let original = config(channel.clone());

        let mut channel2 = channel.clone();
        channel2
            .groups
            .get_mut("Application")
            .unwrap()
            .groups
            .get_mut("Org1MSP")
            .unwrap()
            .values
            .get_mut("AnchorPeers")
            .unwrap()
            .value = b"ap2".to_vec();
        let updated = config(channel2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();

        // Read set: the whole path referenced at current versions, no values.
        let mut expected_read = version_ref(0);
        let mut read_app = version_ref(1);
        read_app.groups.insert("Org1MSP".into(), version_ref(2));
        expected_read.groups.insert("Application".into(), read_app);
        assert_eq!(update.read_set.unwrap(), expected_read);

        // Write set: same path, unchanged group versions, bumped value.
        let mut expected_write = version_ref(0);
        let mut write_app = version_ref(1);
        let mut write_org = version_ref(2);
        write_org
            .values
            .insert("AnchorPeers".into(), value(1, b"ap2", "Admins"));
        write_app.groups.insert("Org1MSP".into(), write_org);
        expected_write.groups.insert("Application".into(), write_app);
        assert_eq!(update.write_set.unwrap(), expected_write);
    }

    #[test]
    fn group_addition_bumps_parent_and_merges_unchanged_members() {
        // Application(v4) holds Org1MSP(v7, unchanged); Org2MSP is added.
        let mut org1 = group(7, "Admins");
        org1.values.insert("MSP".into(), value(3, b"msp1", "Admins"));
        let mut app = group(4, "Admins");
        app.groups.insert("Org1MSP".into(), org1);
        let mut channel = group(0, "Admins");
        channel.groups.insert("Application".into(), app);
        let original = config(channel.clone());

        let mut org2 = group(9, "Admins"); // version in `updated` is ignored for additions
        org2.values.insert("MSP".into(), value(3, b"msp2", "Admins"));
        org2.policies
            .insert("Admins".into(), policy(2, b"rule", "Admins"));
        let mut channel2 = channel.clone();
        channel2
            .groups
            .get_mut("Application")
            .unwrap()
            .groups
            .insert("Org2MSP".into(), org2);
        let updated = config(channel2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();

        // Read set: Application at v4 with the unchanged Org1MSP referenced at v7.
        let mut expected_read = version_ref(0);
        let mut read_app = version_ref(4);
        read_app.groups.insert("Org1MSP".into(), version_ref(7));
        expected_read.groups.insert("Application".into(), read_app);
        assert_eq!(update.read_set.unwrap(), expected_read);

        // Write set: Application bumped to v5 (membership change), mod_policy
        // restated; Org1MSP referenced at v7; Org2MSP added at v0 with all
        // members at v0.
        let mut expected_write = version_ref(0);
        let mut write_app = ConfigGroup {
            version: 5,
            mod_policy: "Admins".into(),
            ..Default::default()
        };
        write_app.groups.insert("Org1MSP".into(), version_ref(7));
        let mut new_org = ConfigGroup {
            version: 0,
            mod_policy: "Admins".into(),
            ..Default::default()
        };
        new_org.values.insert("MSP".into(), value(0, b"msp2", "Admins"));
        new_org
            .policies
            .insert("Admins".into(), policy(0, b"rule", "Admins"));
        write_app.groups.insert("Org2MSP".into(), new_org);
        expected_write.groups.insert("Application".into(), write_app);
        assert_eq!(update.write_set.unwrap(), expected_write);
    }

    #[test]
    fn policy_change_bumps_policy_version() {
        let mut g = group(0, "Admins");
        g.policies.insert("Admins".into(), policy(1, b"old", "Admins"));
        let original = config(g.clone());

        let mut g2 = g.clone();
        g2.policies.get_mut("Admins").unwrap().policy =
            Some(crate::fabric::common::Policy {
                r#type: 3,
                value: b"new".to_vec(),
            });
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let mut expected_write = version_ref(0);
        expected_write
            .policies
            .insert("Admins".into(), policy(2, b"new", "Admins"));
        assert_eq!(update.write_set.unwrap(), expected_write);
        assert_eq!(update.read_set.unwrap(), version_ref(0));
    }

    #[test]
    fn policy_addition_bumps_group_and_merges_same_members() {
        let mut g = group(2, "Admins");
        g.policies.insert("Admins".into(), policy(1, b"a", "Admins"));
        g.values.insert("V".into(), value(4, b"v", "Admins"));
        let original = config(g.clone());

        let mut g2 = g.clone();
        g2.policies.insert("Readers".into(), policy(0, b"r", "Admins"));
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();

        // Membership changed: group bumped, unchanged members merged into both
        // sets as bare version references.
        let mut expected_read = version_ref(2);
        expected_read.policies.insert(
            "Admins".into(),
            ConfigPolicy {
                version: 1,
                ..Default::default()
            },
        );
        expected_read.values.insert(
            "V".into(),
            ConfigValue {
                version: 4,
                ..Default::default()
            },
        );
        assert_eq!(update.read_set.unwrap(), expected_read);

        let mut expected_write = ConfigGroup {
            version: 3,
            mod_policy: "Admins".into(),
            ..Default::default()
        };
        expected_write.policies.insert(
            "Admins".into(),
            ConfigPolicy {
                version: 1,
                ..Default::default()
            },
        );
        expected_write
            .policies
            .insert("Readers".into(), policy(0, b"r", "Admins"));
        expected_write.values.insert(
            "V".into(),
            ConfigValue {
                version: 4,
                ..Default::default()
            },
        );
        assert_eq!(update.write_set.unwrap(), expected_write);
    }

    #[test]
    fn policy_removal_bumps_group() {
        let mut g = group(0, "Admins");
        g.policies.insert("Admins".into(), policy(1, b"a", "Admins"));
        g.policies.insert("Readers".into(), policy(0, b"r", "Admins"));
        let original = config(g.clone());

        let mut g2 = g.clone();
        g2.policies.remove("Readers");
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();

        let mut expected_read = version_ref(0);
        expected_read.policies.insert(
            "Admins".into(),
            ConfigPolicy {
                version: 1,
                ..Default::default()
            },
        );
        assert_eq!(update.read_set.unwrap(), expected_read);

        // Removed policy is simply absent; group version bumped.
        let mut expected_write = ConfigGroup {
            version: 1,
            mod_policy: "Admins".into(),
            ..Default::default()
        };
        expected_write.policies.insert(
            "Admins".into(),
            ConfigPolicy {
                version: 1,
                ..Default::default()
            },
        );
        assert_eq!(update.write_set.unwrap(), expected_write);
    }

    #[test]
    fn group_mod_policy_change_bumps_group() {
        let g = group(6, "Admins");
        let original = config(g.clone());
        let mut g2 = g.clone();
        g2.mod_policy = "Writers".into();
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        assert_eq!(update.read_set.unwrap(), version_ref(6));
        assert_eq!(
            update.write_set.unwrap(),
            ConfigGroup {
                version: 7,
                mod_policy: "Writers".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn version_overflow_wraps_like_go_uint64() {
        let mut g = group(0, "Admins");
        g.values.insert("A".into(), value(u64::MAX, b"x", "Admins"));
        let original = config(g.clone());

        let mut g2 = g.clone();
        g2.values.get_mut("A").unwrap().value = b"y".to_vec();
        let updated = config(g2);

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let write_set = update.write_set.unwrap();
        // Go: originalValue.Version + 1 wraps around to 0 for uint64.
        assert_eq!(write_set.values.get("A").unwrap().version, 0);
    }

    #[test]
    fn compute_is_deterministic() {
        let mut org = group(2, "Admins");
        org.values.insert("MSP".into(), value(0, b"m", "Admins"));
        org.values.insert("AnchorPeers".into(), value(0, b"ap", "Admins"));
        org.policies.insert("Admins".into(), policy(0, b"a", "Admins"));
        org.policies.insert("Readers".into(), policy(0, b"r", "Admins"));
        let mut app = group(1, "Admins");
        app.groups.insert("Org1MSP".into(), org.clone());
        app.groups.insert("Org2MSP".into(), org);
        let mut channel = group(0, "Admins");
        channel.groups.insert("Application".into(), app);
        let original = config(channel.clone());

        let mut channel2 = channel.clone();
        let app2 = channel2.groups.get_mut("Application").unwrap();
        app2.groups
            .get_mut("Org1MSP")
            .unwrap()
            .values
            .get_mut("AnchorPeers")
            .unwrap()
            .value = b"ap2".to_vec();
        app2.groups.remove("Org2MSP");
        let updated = config(channel2);

        let first = compute_config_update(&original, &updated, "chan").unwrap();
        let second = compute_config_update(&original, &updated, "chan").unwrap();
        assert_eq!(first, second);
        // Byte-identical too: all config maps are BTreeMaps.
        assert_eq!(first.encode_to_vec(), second.encode_to_vec());
    }

    // =========================================================
    // Edit helpers feeding compute — Tier 1
    // =========================================================

    /// A minimal but realistic channel config: Application with Org1MSP,
    /// Orderer with an etcdraft ConsensusType.
    fn realistic_config() -> Config {
        let mut org1 = group(0, "Admins");
        org1.values.insert("MSP".into(), value(0, b"org1msp", "Admins"));
        let mut app = group(0, "Admins");
        app.groups.insert("Org1MSP".into(), org1);

        let metadata = etcdraft::ConfigMetadata {
            consenters: vec![etcdraft::Consenter {
                host: "orderer.example.com".into(),
                port: 7050,
                client_tls_cert: b"cert".to_vec(),
                server_tls_cert: b"cert".to_vec(),
            }],
            options: None,
        };
        let consensus = ConsensusType {
            r#type: "etcdraft".into(),
            metadata: metadata.encode_to_vec(),
            state: 0,
        };
        let mut orderer = group(0, "Admins");
        orderer
            .values
            .insert("ConsensusType".into(), value(0, &consensus.encode_to_vec(), "Admins"));

        let mut channel = group(0, "Admins");
        channel.groups.insert("Application".into(), app);
        channel.groups.insert("Orderer".into(), orderer);
        config(channel)
    }

    #[test]
    fn set_anchor_peers_add_produces_minimal_write_set() {
        let original = realistic_config();
        let mut updated = original.clone();
        set_anchor_peers(
            &mut updated,
            "Org1MSP",
            vec![AnchorPeer {
                host: "peer0.org1.example.com".into(),
                port: 7051,
            }],
        )
        .unwrap();

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let write_set = update.write_set.unwrap();

        // Only the Application/Org1MSP path may appear in the write set.
        assert_eq!(write_set.groups.len(), 1);
        let app = write_set.groups.get("Application").unwrap();
        assert_eq!(app.version, 0);
        let org = app.groups.get("Org1MSP").unwrap();
        // AnchorPeers is a new value => org group membership changed => bump.
        assert_eq!(org.version, 1);
        let anchor_value = org.values.get("AnchorPeers").unwrap();
        assert_eq!(anchor_value.version, 0);
        let anchors = AnchorPeers::decode(anchor_value.value.as_slice()).unwrap();
        assert_eq!(anchors.anchor_peers.len(), 1);
        assert_eq!(anchors.anchor_peers[0].host, "peer0.org1.example.com");
        assert_eq!(anchors.anchor_peers[0].port, 7051);
        // The unchanged MSP value is merged as a bare version reference.
        assert_eq!(org.values.get("MSP").unwrap().version, 0);
        assert!(org.values.get("MSP").unwrap().value.is_empty());
    }

    #[test]
    fn set_anchor_peers_replace_bumps_value_only() {
        let mut original = realistic_config();
        set_anchor_peers(
            &mut original,
            "Org1MSP",
            vec![AnchorPeer {
                host: "old.example.com".into(),
                port: 1,
            }],
        )
        .unwrap();

        let mut updated = original.clone();
        set_anchor_peers(
            &mut updated,
            "Org1MSP",
            vec![AnchorPeer {
                host: "new.example.com".into(),
                port: 2,
            }],
        )
        .unwrap();

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let write_set = update.write_set.unwrap();
        let org = write_set
            .groups
            .get("Application")
            .unwrap()
            .groups
            .get("Org1MSP")
            .unwrap();
        // No membership change: group version unchanged, value bumped.
        assert_eq!(org.version, 0);
        assert_eq!(org.values.len(), 1);
        assert_eq!(org.values.get("AnchorPeers").unwrap().version, 1);
    }

    #[test]
    fn set_anchor_peers_unknown_org_fails() {
        let mut config = realistic_config();
        match set_anchor_peers(&mut config, "NopeMSP", vec![]) {
            Err(ConfigTxError::ElementNotFound(name)) => {
                assert!(name.contains("NopeMSP"))
            }
            other => panic!("expected ElementNotFound, got {:?}", other),
        }
    }

    #[test]
    fn add_application_org_produces_expected_write_set() {
        let original = realistic_config();
        let mut updated = original.clone();

        let mut policies = BTreeMap::new();
        policies.insert("Admins".to_string(), policy(0, b"rule", "Admins"));
        add_application_org(
            &mut updated,
            "Org3MSP",
            &MspConfig {
                r#type: 0,
                config: b"org3msp".to_vec(),
            },
            policies,
        )
        .unwrap();

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let write_set = update.write_set.unwrap();
        let app = write_set.groups.get("Application").unwrap();
        // Membership of Application changed => bump + mod_policy restated.
        assert_eq!(app.version, 1);
        assert_eq!(app.mod_policy, "Admins");
        // Unchanged Org1MSP merged as a bare version reference.
        assert_eq!(app.groups.get("Org1MSP").unwrap(), &version_ref(0));

        let org3 = app.groups.get("Org3MSP").unwrap();
        assert_eq!(org3.version, 0);
        assert_eq!(org3.mod_policy, "Admins");
        assert_eq!(org3.values.get("MSP").unwrap().version, 0);
        let msp = MspConfig::decode(org3.values.get("MSP").unwrap().value.as_slice()).unwrap();
        assert_eq!(msp.config, b"org3msp");
        assert_eq!(org3.policies.get("Admins").unwrap().version, 0);
    }

    #[test]
    fn add_application_org_twice_fails() {
        let mut config = realistic_config();
        match add_application_org(
            &mut config,
            "Org1MSP",
            &MspConfig::default(),
            BTreeMap::new(),
        ) {
            Err(ConfigTxError::AlreadyExists(name)) => assert!(name.contains("Org1MSP")),
            other => panic!("expected AlreadyExists, got {:?}", other),
        }
    }

    #[test]
    fn add_consenter_changes_only_consensus_type_value() {
        let original = realistic_config();
        let mut updated = original.clone();
        add_consenter(
            &mut updated,
            etcdraft::Consenter {
                host: "orderer2.example.com".into(),
                port: 7050,
                client_tls_cert: b"cert2".to_vec(),
                server_tls_cert: b"cert2".to_vec(),
            },
        )
        .unwrap();

        let update = compute_config_update(&original, &updated, "chan").unwrap();
        let write_set = update.write_set.unwrap();
        assert_eq!(write_set.groups.len(), 1);
        let orderer = write_set.groups.get("Orderer").unwrap();
        let consensus_value = orderer.values.get("ConsensusType").unwrap();
        assert_eq!(consensus_value.version, 1);

        let consensus = ConsensusType::decode(consensus_value.value.as_slice()).unwrap();
        assert_eq!(consensus.r#type, "etcdraft");
        let metadata = etcdraft::ConfigMetadata::decode(consensus.metadata.as_slice()).unwrap();
        assert_eq!(metadata.consenters.len(), 2);
        assert_eq!(metadata.consenters[1].host, "orderer2.example.com");
    }

    #[test]
    fn add_duplicate_consenter_fails() {
        let mut config = realistic_config();
        match add_consenter(
            &mut config,
            etcdraft::Consenter {
                host: "orderer.example.com".into(),
                port: 7050,
                ..Default::default()
            },
        ) {
            Err(ConfigTxError::AlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {:?}", other),
        }
    }

    #[test]
    fn remove_consenter_roundtrip() {
        let mut config = realistic_config();
        add_consenter(
            &mut config,
            etcdraft::Consenter {
                host: "orderer2.example.com".into(),
                port: 7050,
                ..Default::default()
            },
        )
        .unwrap();
        remove_consenter(&mut config, "orderer.example.com", 7050).unwrap();

        let orderer = config
            .channel_group
            .as_ref()
            .unwrap()
            .groups
            .get("Orderer")
            .unwrap();
        let consensus = ConsensusType::decode(
            orderer.values.get("ConsensusType").unwrap().value.as_slice(),
        )
        .unwrap();
        let metadata = etcdraft::ConfigMetadata::decode(consensus.metadata.as_slice()).unwrap();
        assert_eq!(metadata.consenters.len(), 1);
        assert_eq!(metadata.consenters[0].host, "orderer2.example.com");

        match remove_consenter(&mut config, "gone.example.com", 1234) {
            Err(ConfigTxError::ElementNotFound(_)) => {}
            other => panic!("expected ElementNotFound, got {:?}", other),
        }
    }

    #[test]
    fn non_etcdraft_consensus_is_rejected() {
        let mut config = realistic_config();
        {
            let orderer = config
                .channel_group
                .as_mut()
                .unwrap()
                .groups
                .get_mut("Orderer")
                .unwrap();
            let consensus = ConsensusType {
                r#type: "BFT".into(),
                metadata: vec![],
                state: 0,
            };
            orderer.values.get_mut("ConsensusType").unwrap().value =
                consensus.encode_to_vec();
        }
        match add_consenter(&mut config, etcdraft::Consenter::default()) {
            Err(ConfigTxError::UnsupportedConsensusType(t)) => assert_eq!(t, "BFT"),
            other => panic!("expected UnsupportedConsensusType, got {:?}", other),
        }
    }

    // =========================================================
    // MspConfigBuilder
    // =========================================================

    // Empty CRL issued by a throwaway P-256 CA (openssl ca -gencrl).
    const TEST_CRL: &str = "-----BEGIN X509 CRL-----
MIGtMFUCAQEwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLY3JsLXRlc3QtY2EXDTI2
MTEyMzA4NTEyMVoXDTQ2MTExODA4NTEyMVqgDjAMMAoGA1UdFAQDAgEBMAoGCCqG
SM49BAMCA0gAMEUCIQCDEFQFBjGdr+Cdc6byGb6pOEJ4CRRusjWshfpv+dUZhQIg
JN5N0qJEtUIB1daOzzQEwQ0cJ4c+DaXwdBiU15hTDzE=
-----END X509 CRL-----
";

    #[test]
    fn msp_builder_sets_all_fields() {
        let fabric = MspConfigBuilder::new("Org1MSP")
            .with_root_cert(TEST_CERT_1)
            .with_intermediate_cert(TEST_CERT_2)
            .with_tls_root_cert(TEST_CERT_2)
            .with_tls_intermediate_cert(TEST_CERT_1)
            .with_revocation_list(TEST_CRL)
            .with_node_ou(MspRoleType::Peer, "peer", Some(TEST_CERT_2.into()))
            .with_node_ou(MspRoleType::Client, "app", None)
            .build_fabric_config()
            .unwrap();

        assert_eq!(fabric.name, "Org1MSP");
        assert_eq!(fabric.root_certs, vec![TEST_CERT_1.as_bytes().to_vec()]);
        assert_eq!(
            fabric.intermediate_certs,
            vec![TEST_CERT_2.as_bytes().to_vec()]
        );
        assert_eq!(fabric.tls_root_certs, vec![TEST_CERT_2.as_bytes().to_vec()]);
        assert_eq!(
            fabric.tls_intermediate_certs,
            vec![TEST_CERT_1.as_bytes().to_vec()]
        );
        assert_eq!(fabric.revocation_list, vec![TEST_CRL.as_bytes().to_vec()]);
        assert!(fabric.admins.is_empty());
        assert!(fabric.signing_identity.is_none());
        let crypto = fabric.crypto_config.unwrap();
        assert_eq!(crypto.signature_hash_family, "SHA2");
        assert_eq!(crypto.identity_identifier_hash_function, "SHA256");

        let node_ous = fabric.fabric_node_ous.unwrap();
        assert!(node_ous.enable);
        // The peer OU is bound to the intermediate CA.
        let peer = node_ous.peer_ou_identifier.unwrap();
        assert_eq!(peer.organizational_unit_identifier, "peer");
        assert_eq!(peer.certificate, TEST_CERT_2.as_bytes());
        let client = node_ous.client_ou_identifier.unwrap();
        assert_eq!(client.organizational_unit_identifier, "app");
        assert!(client.certificate.is_empty());
        // Roles that were not set stay unset, as with a partial config.yaml.
        assert!(node_ous.admin_ou_identifier.is_none());
        assert!(node_ous.orderer_ou_identifier.is_none());
    }

    #[test]
    fn msp_builder_without_node_ous_leaves_them_unset() {
        let msp = MspConfigBuilder::new("Org1MSP")
            .with_root_cert(TEST_CERT_1)
            .build()
            .unwrap();
        assert_eq!(msp.r#type, 0);
        let fabric = FabricMspConfig::decode(msp.config.as_slice()).unwrap();
        assert!(fabric.fabric_node_ous.is_none());
    }

    #[test]
    fn msp_builder_requires_id_and_root_cert() {
        match MspConfigBuilder::new("")
            .with_root_cert(TEST_CERT_1)
            .build()
        {
            Err(ConfigTxError::MissingMspField("msp id")) => {}
            other => panic!("expected MissingMspField(msp id), got {:?}", other),
        }
        match MspConfigBuilder::new("Org1MSP").build() {
            Err(ConfigTxError::MissingMspField("root certificate")) => {}
            other => panic!(
                "expected MissingMspField(root certificate), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn msp_builder_names_the_invalid_pem_input() {
        let cases: [(MspConfigBuilder, &str); 4] = [
            (
                MspConfigBuilder::new("Org1MSP")
                    .with_root_cert(TEST_CERT_1)
                    .with_root_cert("not a pem"),
                "root_certs[1]",
            ),
            (
                // A private key is PEM, but not a certificate.
                MspConfigBuilder::new("Org1MSP")
                    .with_root_cert(TEST_CERT_1)
                    .with_tls_root_cert(TEST_KEY_1),
                "tls_root_certs[0]",
            ),
            (
                // A certificate is not a CRL.
                MspConfigBuilder::new("Org1MSP")
                    .with_root_cert(TEST_CERT_1)
                    .with_revocation_list(TEST_CERT_1),
                "revocation_list[0]",
            ),
            (
                MspConfigBuilder::new("Org1MSP")
                    .with_root_cert(TEST_CERT_1)
                    .with_node_ou(MspRoleType::Admin, "admin", Some(b"garbage".to_vec())),
                "node_ous.admin",
            ),
        ];
        for (builder, expected_field) in cases {
            match builder.build() {
                Err(ConfigTxError::InvalidPem { field, .. }) => assert_eq!(field, expected_field),
                other => panic!("expected InvalidPem({expected_field}), got {:?}", other),
            }
        }
    }

    #[test]
    fn msp_builder_rejects_member_node_ou() {
        match MspConfigBuilder::new("Org1MSP")
            .with_root_cert(TEST_CERT_1)
            .with_node_ou(MspRoleType::Member, "member", None)
            .build()
        {
            Err(ConfigTxError::InvalidNodeOuRole(MspRoleType::Member)) => {}
            other => panic!("expected InvalidNodeOuRole(Member), got {:?}", other),
        }
    }

    #[test]
    fn msp_builder_later_node_ou_replaces_earlier() {
        let node_ous = MspConfigBuilder::new("Org1MSP")
            .with_root_cert(TEST_CERT_1)
            .with_node_ous(TEST_CERT_1)
            .with_node_ou(MspRoleType::Client, "app", None)
            .build_fabric_config()
            .unwrap()
            .fabric_node_ous
            .unwrap();
        let client = node_ous.client_ou_identifier.unwrap();
        assert_eq!(client.organizational_unit_identifier, "app");
        assert!(client.certificate.is_empty());
        assert_eq!(
            node_ous
                .peer_ou_identifier
                .unwrap()
                .organizational_unit_identifier,
            "peer"
        );
    }

    #[test]
    fn msp_builder_rejects_node_ou_cert_outside_the_chain() {
        // TEST_CERT_2 is a valid certificate, but not a CA of this MSP.
        match MspConfigBuilder::new("Org1MSP")
            .with_root_cert(TEST_CERT_1)
            .with_tls_root_cert(TEST_CERT_2)
            .with_node_ous(TEST_CERT_2)
            .build()
        {
            Err(ConfigTxError::NodeOuCertNotInChain(_)) => {}
            other => panic!("expected NodeOuCertNotInChain, got {:?}", other),
        }
    }

    // =========================================================
    // GenesisBuilder
    // =========================================================

    fn test_msp(msp_id: &str) -> MspConfig {
        MspConfigBuilder::new(msp_id)
            .with_root_cert(TEST_CERT_1)
            .build()
            .unwrap()
    }

    fn minimal_genesis() -> GenesisBuilder {
        GenesisBuilder::new("testchannel")
            .with_application_org(ApplicationOrg::new("Org1MSP", test_msp("Org1MSP")))
            .with_orderer_org(OrdererOrg::new("OrdererMSP", test_msp("OrdererMSP")))
            .with_consenter("orderer.example.com", 7050, TEST_CERT_1, TEST_CERT_1)
    }

    fn channel_group(builder: &GenesisBuilder) -> ConfigGroup {
        builder.build_config().unwrap().channel_group.unwrap()
    }

    fn expect_orderer_value_error(builder: GenesisBuilder, expected_field: &str) {
        match builder.build() {
            Err(ConfigTxError::InvalidOrdererValue { field, .. }) => {
                assert_eq!(field, expected_field)
            }
            other => panic!(
                "expected InvalidOrdererValue({expected_field}), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn genesis_defaults_are_configtxgens() {
        let channel = channel_group(&minimal_genesis());
        let orderer = &channel.groups["Orderer"];
        let batch_size = BatchSize::decode(orderer.values["BatchSize"].value.as_slice()).unwrap();
        assert_eq!(
            (
                batch_size.max_message_count,
                batch_size.absolute_max_bytes,
                batch_size.preferred_max_bytes
            ),
            (500, 10 * 1024 * 1024, 2 * 1024 * 1024)
        );
        let timeout =
            BatchTimeout::decode(orderer.values["BatchTimeout"].value.as_slice()).unwrap();
        assert_eq!(timeout.timeout, "2s");
        let consensus =
            ConsensusType::decode(orderer.values["ConsensusType"].value.as_slice()).unwrap();
        let metadata = etcdraft::ConfigMetadata::decode(consensus.metadata.as_slice()).unwrap();
        let options = metadata.options.unwrap();
        assert_eq!(options.tick_interval, "500ms");
        assert_eq!((options.election_tick, options.heartbeat_tick), (10, 1));
        assert_eq!(options.max_inflight_blocks, 5);
        assert_eq!(options.snapshot_interval_size, 16 * 1024 * 1024);

        // Optional values are omitted unless set.
        assert!(!channel.values.contains_key("OrdererAddresses"));
        assert!(!channel.groups["Application"].values.contains_key("ACLs"));
        assert!(
            !channel.groups["Application"].groups["Org1MSP"]
                .values
                .contains_key("AnchorPeers")
        );
        assert!(
            !orderer.groups["OrdererMSP"]
                .values
                .contains_key("Endpoints")
        );
    }

    #[test]
    fn genesis_capabilities_are_sorted_and_decodable() {
        let builder = minimal_genesis()
            .with_channel_capabilities(["V2_0", "V1_4_3"])
            .with_orderer_capabilities(Vec::<String>::new());
        let channel = channel_group(&builder);
        let value = &channel.values["Capabilities"].value;
        let decoded = Capabilities::decode(value.as_slice()).unwrap();
        let mut names: Vec<_> = decoded.capabilities.keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["V1_4_3", "V2_0"]);
        // Sorted entries: V1_4_3 first, whatever the input order.
        assert_eq!(&value[4..10], b"V1_4_3");
        // An empty list omits the value.
        assert!(
            !channel.groups["Orderer"]
                .values
                .contains_key("Capabilities")
        );
    }

    #[test]
    fn genesis_acls_anchor_peers_and_addresses() {
        let builder = GenesisBuilder::new("testchannel")
            .with_application_org(
                ApplicationOrg::new("Org1MSP", test_msp("Org1MSP"))
                    .with_anchor_peer("peer0.org1.example.com", 7051),
            )
            .with_orderer_org(
                OrdererOrg::new("OrdererMSP", test_msp("OrdererMSP"))
                    .with_endpoint("orderer.example.com:7050"),
            )
            .with_consenter("orderer.example.com", 7050, TEST_CERT_1, TEST_CERT_1)
            .with_orderer_address("orderer.example.com:7050")
            .with_acl("qscc/GetChainInfo", "/Channel/Application/Readers")
            .with_acl("cscc/GetConfigBlock", "/Channel/Application/Readers");
        let channel = channel_group(&builder);

        let acls = AcLs::decode(
            channel.groups["Application"].values["ACLs"]
                .value
                .as_slice(),
        )
        .unwrap();
        assert_eq!(acls.acls.len(), 2);
        assert_eq!(
            acls.acls["qscc/GetChainInfo"].policy_ref,
            "/Channel/Application/Readers"
        );

        let anchors = AnchorPeers::decode(
            channel.groups["Application"].groups["Org1MSP"].values["AnchorPeers"]
                .value
                .as_slice(),
        )
        .unwrap();
        assert_eq!(anchors.anchor_peers[0].port, 7051);

        let addresses = &channel.values["OrdererAddresses"];
        assert_eq!(addresses.mod_policy, "/Channel/Orderer/Admins");
        let endpoints = OrdererAddresses::decode(
            channel.groups["Orderer"].groups["OrdererMSP"].values["Endpoints"]
                .value
                .as_slice(),
        )
        .unwrap();
        assert_eq!(endpoints.addresses, ["orderer.example.com:7050"]);
    }

    #[test]
    fn genesis_block_is_well_formed() {
        let block = minimal_genesis().build().unwrap();
        let header = block.header.unwrap();
        assert_eq!(header.number, 0);
        assert!(header.previous_hash.is_empty());
        let data = block.data.unwrap().data;
        assert_eq!(header.data_hash, generate_sha256_hash(&data.concat()));
        assert_eq!(block.metadata.unwrap().metadata.len(), 5);

        let envelope = Envelope::decode(data[0].as_slice()).unwrap();
        assert!(envelope.signature.is_empty());
        let payload = Payload::decode(envelope.payload.as_slice()).unwrap();
        let channel_header =
            ChannelHeader::decode(payload.header.unwrap().channel_header.as_slice()).unwrap();
        assert_eq!(channel_header.r#type, i32::from(HeaderType::Config));
        assert_eq!(channel_header.channel_id, "testchannel");
        let config = ConfigEnvelope::decode(payload.data.as_slice())
            .unwrap()
            .config
            .unwrap();
        assert_eq!(config, minimal_genesis().build_config().unwrap());
    }

    #[test]
    fn genesis_rejects_bad_channel_ids() {
        for id in ["", "MyChannel", "1channel", "my_channel", &"a".repeat(250)] {
            match minimal_genesis_with_id(id).build() {
                Err(ConfigTxError::InvalidChannelId(got)) => assert_eq!(got, id),
                other => panic!("expected InvalidChannelId({id}), got {:?}", other),
            }
        }
        for id in ["a", "my-channel.2", &"a".repeat(249)] {
            minimal_genesis_with_id(id).build().unwrap();
        }
    }

    fn minimal_genesis_with_id(id: &str) -> GenesisBuilder {
        GenesisBuilder {
            channel_id: id.to_string(),
            ..minimal_genesis()
        }
    }

    #[test]
    fn genesis_requires_orgs_and_consenter() {
        let cases = [
            (
                GenesisBuilder::new("c")
                    .with_orderer_org(OrdererOrg::new("O", test_msp("O")))
                    .with_consenter("o", 1, TEST_CERT_1, TEST_CERT_1),
                "application org",
            ),
            (
                GenesisBuilder::new("c")
                    .with_application_org(ApplicationOrg::new("A", test_msp("A")))
                    .with_consenter("o", 1, TEST_CERT_1, TEST_CERT_1),
                "orderer org",
            ),
            (
                GenesisBuilder::new("c")
                    .with_application_org(ApplicationOrg::new("A", test_msp("A")))
                    .with_orderer_org(OrdererOrg::new("O", test_msp("O"))),
                "consenter",
            ),
        ];
        for (builder, expected) in cases {
            match builder.build() {
                Err(ConfigTxError::MissingGenesisField(field)) => assert_eq!(field, expected),
                other => panic!("expected MissingGenesisField({expected}), got {:?}", other),
            }
        }
    }

    #[test]
    fn genesis_rejects_duplicate_org_names() {
        let builder = minimal_genesis().with_application_org(
            ApplicationOrg::new("Org2MSP", test_msp("Org2MSP")).with_name("Org1MSP"),
        );
        match builder.build() {
            Err(ConfigTxError::AlreadyExists(name)) => assert!(name.contains("Org1MSP")),
            other => panic!("expected AlreadyExists, got {:?}", other),
        }
    }

    #[test]
    fn genesis_rejects_invalid_orderer_values() {
        expect_orderer_value_error(minimal_genesis().with_batch_size(0, 10, 10), "batch size");
        expect_orderer_value_error(minimal_genesis().with_batch_size(10, 10, 11), "batch size");
        expect_orderer_value_error(minimal_genesis().with_batch_timeout("2"), "batch timeout");
        expect_orderer_value_error(minimal_genesis().with_batch_timeout("-1s"), "batch timeout");
        expect_orderer_value_error(minimal_genesis().with_batch_timeout("0s"), "batch timeout");
        expect_orderer_value_error(
            minimal_genesis().with_etcdraft_options(etcdraft::Options {
                tick_interval: "500ms".into(),
                election_tick: 1,
                heartbeat_tick: 1,
                max_inflight_blocks: 5,
                snapshot_interval_size: 1,
            }),
            "etcdraft ticks",
        );
        expect_orderer_value_error(
            minimal_genesis().with_etcdraft_options(etcdraft::Options {
                tick_interval: "half a second".into(),
                election_tick: 10,
                heartbeat_tick: 1,
                max_inflight_blocks: 5,
                snapshot_interval_size: 1,
            }),
            "etcdraft tick interval",
        );
        expect_orderer_value_error(
            minimal_genesis().with_consenter("", 7050, TEST_CERT_1, TEST_CERT_1),
            "consenter",
        );
        match minimal_genesis()
            .with_consenter("o2", 7050, TEST_CERT_1, "not a pem")
            .build()
        {
            Err(ConfigTxError::InvalidPem { field, .. }) => {
                assert_eq!(field, "consenters[1].server_tls_cert")
            }
            other => panic!("expected InvalidPem, got {:?}", other),
        }
    }

    #[test]
    fn go_duration_parsing_follows_time_parse_duration() {
        for ok in [
            "2s", "500ms", "1m30s", "1.5h", "+3us", "3µs", "3μs", "100ns", ".5s",
        ] {
            assert!(go_duration_is_positive(ok), "{ok}");
        }
        for bad in [
            "", "0", "0s", "2", "s", "-1s", "1x", "1..5s", "1.s5", "0.1ns",
        ] {
            assert!(!go_duration_is_positive(bad), "{bad}");
        }
    }

    // =========================================================
    // Signing and envelope assembly — Tier 1
    // =========================================================

    #[test]
    fn config_signature_verifies_against_cert_public_key() {
        let identity = identity1();
        let update_bytes = b"some marshaled config update".to_vec();
        let signature = sign_config_update(&identity, &update_bytes);

        // The signature header carries the serialized identity as creator.
        let header =
            SignatureHeader::decode(signature.signature_header.as_slice()).unwrap();
        assert_eq!(
            header.creator,
            identity.get_serialized_identity().encode_to_vec()
        );
        assert_eq!(header.nonce.len(), 24);

        // Signature covers signature_header_bytes || config_update_bytes.
        let mut message = signature.signature_header.clone();
        message.extend_from_slice(&update_bytes);
        assert!(verify_signature(PUB1_SEC1, &message, &signature.signature));
    }

    #[test]
    fn tampered_config_update_fails_verification() {
        let identity = identity1();
        let update_bytes = b"authentic bytes".to_vec();
        let signature = sign_config_update(&identity, &update_bytes);

        let mut tampered = signature.signature_header.clone();
        tampered.extend_from_slice(b"tampered bytes!");
        assert!(!verify_signature(PUB1_SEC1, &tampered, &signature.signature));
    }

    #[test]
    fn multi_signature_accumulation_preserves_prior_signatures() {
        let update = ConfigUpdate {
            channel_id: "testchan".into(),
            read_set: Some(version_ref(0)),
            write_set: Some(version_ref(1)),
            isolated_data: BTreeMap::new(),
        };
        let mut envelope = create_config_update_envelope(&update);
        assert!(envelope.signatures.is_empty());

        add_signature(&mut envelope, &identity1());
        let first = envelope.signatures[0].clone();
        add_signature(&mut envelope, &identity2());

        assert_eq!(envelope.signatures.len(), 2);
        assert_eq!(envelope.signatures[0], first, "first signature was altered");

        // Both signatures verify against their own signer's public key.
        for (sig, pubkey) in envelope.signatures.iter().zip([PUB1_SEC1, PUB2_SEC1]) {
            let mut message = sig.signature_header.clone();
            message.extend_from_slice(&envelope.config_update);
            assert!(verify_signature(pubkey, &message, &sig.signature));
        }
    }

    #[test]
    fn config_update_envelope_roundtrips() {
        let update = ConfigUpdate {
            channel_id: "testchan".into(),
            read_set: Some(version_ref(3)),
            write_set: Some(version_ref(4)),
            isolated_data: BTreeMap::new(),
        };
        let mut envelope = create_config_update_envelope(&update);
        add_signature(&mut envelope, &identity1());

        let bytes = encode_config_update_envelope(&envelope);
        let decoded = decode_config_update_envelope(&bytes).unwrap();
        assert_eq!(decoded, envelope);

        assert!(decode_config_update_envelope(b"\xff\xff\xff garbage").is_err());
    }

    #[test]
    fn config_update_transaction_is_well_formed_and_signed() {
        let identity = identity1();
        let update = ConfigUpdate {
            channel_id: "testchan".into(),
            read_set: Some(version_ref(0)),
            write_set: Some(version_ref(1)),
            isolated_data: BTreeMap::new(),
        };
        let mut update_envelope = create_config_update_envelope(&update);
        add_signature(&mut update_envelope, &identity);

        let envelope = build_config_update_transaction(&identity, &update_envelope).unwrap();

        // Envelope signature covers the payload and verifies against the cert key.
        assert!(verify_signature(PUB1_SEC1, &envelope.payload, &envelope.signature));

        let payload = Payload::decode(envelope.payload.as_slice()).unwrap();
        let header = payload.header.unwrap();
        let channel_header =
            ChannelHeader::decode(header.channel_header.as_slice()).unwrap();
        assert_eq!(
            channel_header.r#type,
            i32::from(HeaderType::ConfigUpdate)
        );
        assert_eq!(channel_header.channel_id, "testchan");
        assert_eq!(channel_header.tx_id.len(), 64); // hex sha256
        let signature_header =
            SignatureHeader::decode(header.signature_header.as_slice()).unwrap();
        assert_eq!(
            signature_header.creator,
            identity.get_serialized_identity().encode_to_vec()
        );

        // Payload data carries the ConfigUpdateEnvelope unchanged.
        let inner = ConfigUpdateEnvelope::decode(payload.data.as_slice()).unwrap();
        assert_eq!(inner, update_envelope);
    }

    #[test]
    fn config_update_transaction_requires_channel_id() {
        let update = ConfigUpdate::default();
        let update_envelope = create_config_update_envelope(&update);
        match build_config_update_transaction(&identity1(), &update_envelope) {
            Err(ConfigTxError::ElementNotFound(what)) => {
                assert!(what.contains("channel_id"))
            }
            other => panic!("expected ElementNotFound(channel_id), got {:?}", other),
        }
    }
}
