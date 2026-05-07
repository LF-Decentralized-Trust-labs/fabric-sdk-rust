use prost::Message;

use crate::fabric::gateway::ErrorDetail;

/// Manually-defined mirror of `google.rpc.Status` for decoding the `grpc-status-details-bin`
/// trailer without pulling in the full googleapis dependency.
#[derive(prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<RpcAny>,
}

/// Manually-defined mirror of `google.protobuf.Any`.
#[derive(prost::Message)]
struct RpcAny {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

/// Converts a tonic `Status` into a human-readable error string.
///
/// Fabric's gateway embeds per-endorser [`ErrorDetail`] messages inside the
/// `grpc-status-details-bin` trailer as a `google.rpc.Status` proto.  This
/// function decodes those details and appends them to the top-level status
/// message so callers see the actual chaincode / peer error rather than the
/// generic "see attached details" placeholder.
pub(crate) fn format_grpc_error(status: &tonic::Status) -> String {
    let details_bytes = status.details();

    if details_bytes.is_empty() {
        return status.message().to_owned();
    }

    let rpc_status = match RpcStatus::decode(details_bytes) {
        Ok(s) => s,
        Err(_) => return status.message().to_owned(),
    };

    let error_details: Vec<String> = rpc_status
        .details
        .iter()
        .filter(|any| any.type_url.ends_with("gateway.ErrorDetail"))
        .filter_map(|any| ErrorDetail::decode(any.value.as_slice()).ok())
        .map(|d| format!("[{}@{}] {}", d.msp_id, d.address, d.message))
        .collect();

    if error_details.is_empty() {
        rpc_status.message
    } else {
        format!("{}; {}", rpc_status.message, error_details.join("; "))
    }
}
