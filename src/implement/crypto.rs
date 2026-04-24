use std::io::Write;

use prost::Message;
use sha2::Digest;

use crate::fabric::protos::{
    ChaincodeId, ChaincodeInput, ChaincodeInvocationSpec, ChaincodeProposalPayload, ChaincodeSpec,
};

pub(crate) const NONCE_LENGTH: usize = 24;

/// Creates a unique transaction ID by concatenating a nonce with an identity and then hashing the result.
///
/// # Arguments
/// * `nonce` - A byte slice representing a random nonce.
/// * `creator` - A byte slice representing the identity of the creator in serialized format.
///
/// # Returns
/// A string representing the hashed transaction ID, encoded in hexadecimal format.
pub(crate) fn generate_transaction_id(nonce: &[u8], creator: &[u8]) -> String {
    let salted_creator = [nonce, creator].concat();
    hex::encode(generate_sha256_hash(salted_creator.as_slice()))
}

pub(crate) fn generate_nonce() -> [u8; NONCE_LENGTH] {
    ecdsa::elliptic_curve::Generate::generate()
}

pub(crate) fn generate_sha256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::default();
    hasher.write_all(bytes).unwrap();
    hasher.finalize().to_vec()
}

pub(crate) fn generate_chaincode_definition(
    chaincode_id: ChaincodeId,
    contract_id: Option<String>,
    function_name: String,
    function_args: Vec<Vec<u8>>,
) -> ChaincodeProposalPayload {
    let mut args = if let Some(contract_id) = contract_id {
        vec![
            format!("{}:{}", contract_id, function_name)
                .as_bytes()
                .to_vec(),
        ]
    } else {
        vec![function_name.as_bytes().to_vec()]
    };
    for function_arg in function_args {
        args.push(function_arg);
    }
    let chaincode_input = ChaincodeInput {
        args,
        decorations: std::collections::HashMap::default(), //TODO Chaincode decorations
        is_init: false,
    };

    let chaincode_spec = ChaincodeSpec {
        r#type: crate::fabric::protos::chaincode_spec::Type::Golang.into(),
        chaincode_id: Some(chaincode_id),
        input: Some(chaincode_input),
        timeout: 10,
    };

    let chaincode_invokation_spec = ChaincodeInvocationSpec {
        chaincode_spec: Some(chaincode_spec),
    };

    ChaincodeProposalPayload {
        input: chaincode_invokation_spec.encode_to_vec(),
        transient_map: std::collections::HashMap::default(),
    }
}
