# Fabric SDK Rust
The Fabric SDK for Rust allows to interact with a Hyperledger Fabric blockchain network. It is currently early stage and not functional.
It is aiming to be compatible with Fabric v2.4 or newer.

# Using the crate

Keep in mind, that this is still under heavy development and cannot seen as "safe"!

The crate can be used via local link:
```toml
fabric-sdk-rust = {git="https://github.com/LF-Decentralized-Trust-labs/fabric-sdk-rust"}
```
Here is an simple code example how to use the library:
```rust
use std::error::Error;

use fabric_sdk_rust::{client::ClientBuilder, identity::IdentityBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let identity = IdentityBuilder::from_pem(std::fs::read_to_string(
        "/home/user/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
    )?.as_bytes())
        .with_msp("Org1MSP")?
        .build()?;

    let mut client = ClientBuilder::new()
        .with_identity(identity)?
        .with_tls(std::fs::read("/home/user/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem")?)?
        .with_signer(fabric_sdk_rust::signer::Signer{
            pkey: std::fs::read(
                "/home/user/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk")?
        })?
        .build()?;
    client.connect().await?;

    let tx_builder = client
        .get_transaction_builder()
        .with_channel_name("mychannel")?
        .with_chaincode_id("basic")?
        .with_function_name("CreateAsset")?
        .with_function_args(["assetCustom","orange","10","Frank","600"])?
        .build();
    match tx_builder {
        Ok(prepared_transaction) => match prepared_transaction.submit().await {
                Ok(result) => {
                    println!("{}", String::from_utf8_lossy(result.as_slice()));
                }
                Err(err) => println!("{}", err),
            },
        Err(err) => println!("{}", err),
    }

    let tx_builder = client
        .get_transaction_builder()
        .with_channel_name("mychannel")?
        .with_chaincode_id("basic")?
        .with_function_name("ReadAsset")?
        .with_function_args(["assetCustom"])?
        .build();
    match tx_builder {
        Ok(prepared_transaction) => match prepared_transaction.submit().await {
                Ok(result) => {
                    println!("{}", String::from_utf8_lossy(result.as_slice()));
                }
                Err(err) => println!("{}", err),
            },
        Err(err) => println!("{}", err),
    }
    Ok(())
}
```

To run this example you need to have a test network running with fabric samples and the basic assets chaincode deployed.

Executing the example twice will result the first one sending an error, that the asset already exists, demonstrating the behavior of an error.


# Developing locally

The tests written in this project are based on the basic chaincode written in the [docs](https://ethan-li-fabric.readthedocs.io/en/latest/test_network.html).
A test network with the basic asset chaincode deployed is recommended to test functionallity via tests. A test project using the library locally on your machine is also possible.

The tests are using the env variables defined in .env.

Clone the project
```bash
git clone https://github.com/LF-Decentralized-Trust-labs/fabric-sdk-rust && cd fabric-sdk-rust
```

Copy the env_default to .env and edit it according to your needings (if needed)
```bash
cp env_default .env
```
This project uses the fabric-protos git as submodule for the protobuf files. To initialize the submodule, run:

```bash
git submodule update --init --recursive
```

And now you are ready to go!

If you have set up the fabric test network with the basic asset chaincode, the tests should succeed:

```bash
cargo test
```

# TODO's

- Add protos language binding for Rust in [fabric-protos](https://github.com/hyperledger/fabric-protos)
