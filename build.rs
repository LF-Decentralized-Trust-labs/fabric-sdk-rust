fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(true)
        .out_dir("src/fabric")
        .compile_protos(
            &[
                "fabric-protos/gateway/gateway.proto",
                "fabric-protos/common/common.proto",
                "fabric-protos/peer/chaincode.proto",
                "fabric-protos/peer/chaincode_shim.proto",
                "fabric-protos/msp/identities.proto",
            ],
            &["fabric-protos"],
        )?;
    Ok(())
}
