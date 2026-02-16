fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(true)
        .message_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .enum_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .out_dir("src/fabric")
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "crate::fabric::google_protobuf")
        .compile_protos(
            &[
                "fabric-protos/gateway/gateway.proto",
                "fabric-protos/common/common.proto",
                "fabric-protos/peer/chaincode.proto",
                "fabric-protos/peer/chaincode_shim.proto",
                "fabric-protos/msp/identities.proto",
                "fabric-protos/ledger/queryresult/kv_query_result.proto",
                "fabric-protos/discovery/protocol.proto",
                "fabric-protos/gossip/message.proto", // Needed for protocol.proto
            ],
            &["fabric-protos"],
        )?;
    Ok(())
}
