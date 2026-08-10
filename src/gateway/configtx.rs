//! Channel configuration transaction (configtx) helpers.
//!
//! This module provides everything needed to update a channel's configuration
//! without external tooling (`configtxlator` / `peer channel update`):
//!
//! 1. [`compute_config_update`] — computes the sparse [`ConfigUpdate`]
//!    (read set / write set) between an original and an updated [`Config`].
//!    This is a faithful port of the Go implementation in
//!    `hyperledger/fabric` `internal/configtxlator/update`.
//! 2. Edit helpers ([`set_anchor_peers`], [`add_application_org`],
//!    [`add_consenter`], [`remove_consenter`]) — typed recipes that mutate a
//!    decoded [`Config`] tree so the caller does not have to hand-edit
//!    nested protobuf maps.
//! 3. Signing and envelope assembly ([`sign_config_update`],
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
//! it satisfies the mod policy of the elements it touches. The intended flow:
//!
//! ```rust
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
            ChannelHeader, Config, ConfigGroup, ConfigPolicy, ConfigSignature, ConfigUpdate,
            ConfigUpdateEnvelope, ConfigValue, Envelope, Header, HeaderType, Payload,
            SignatureHeader,
        },
        etcdraft,
        msp::MspConfig,
        orderer::ConsensusType,
        protos::{AnchorPeer, AnchorPeers},
    },
    identity::Identity,
    implement::crypto::{generate_nonce, generate_transaction_id},
};

use std::collections::BTreeMap;

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
/// signature policies referring to the org's MSP roles).
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

    let mut values = BTreeMap::new();
    values.insert(
        MSP_KEY.to_string(),
        ConfigValue {
            version: 0,
            value: msp_config.encode_to_vec(),
            mod_policy: ADMINS_POLICY.into(),
        },
    );

    application.groups.insert(
        msp_id.to_string(),
        ConfigGroup {
            version: 0,
            groups: BTreeMap::new(),
            values,
            policies,
            mod_policy: ADMINS_POLICY.into(),
        },
    );
    Ok(())
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
        timestamp: Some({
            #[cfg(feature = "client-wasm")]
            {
                crate::fabric::google_protobuf::Timestamp {
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
        }),
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
