# Using the client

The crate can be used via crates.io:
```toml
fabric-sdk = "0.5.0"
```

Here is an simple code example how to use the library:

```rust
use std::error::Error;

use fabric_sdk::{client::ClientBuilder, identity::IdentityBuilder, signer::Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let pem_bytes = include_bytes!("/home/user/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem");
    let tlsca_bytes = include_bytes!("/home/user/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem");
    let msp_key_bytes = include_bytes!("/home/user/fabric/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk");

    let identity = IdentityBuilder::from_pem(pem_bytes)
        .with_msp("Org1MSP")?
        .with_private_key(msp_key_bytes)?
        .build()?;

    let mut client = ClientBuilder::new()
        .with_identity(identity)?
        .with_tls(tlsca_bytes)?
        .with_scheme("https")?
        .with_authority("localhost:7051")?
        .build()?;
    client.connect().await?;

    let mut tx_builder = client
        .get_transaction_builder()
        .with_channel_name("mychannel")?
        .with_chaincode_id("basic")?
        .with_function_name("CreateAsset")?
        .with_function_args(["assetCustom", "orange", "10", "Frank", "600"])?;
    match tx_builder.build() {
        Ok(prepared_transaction) -> prepared_transaction.endorse(&client).await {
            Ok(envelope) -> {
                // To have persistent changes, the envelope has to be submitted
                envelope.submit(&client).await.expect("Submit error");
                // To be certain, that the envelope has been submitted and therefore the changes be written into the ledger, we wait for the commit.
                envelope.wait_for_commit(&client).await.expect("Error while waiting for commit");
                let function_call_result = envelope.get_payload().unwrap().get_transaction().unwrap().get_result_string().unwrap()
                println!("{function_call_result}"));
            }
            Err(err) -> println!("{}", err),
        },
        Err(err) -> println!("{}", err),
    }
    Ok(())
}
```

To run this example you need to have a test network running with fabric samples and the basic assets chaincode deployed.

Executing the example twice will result the first one sending an error, that the asset already exists, demonstrating the behavior of an error.

# Private data collections

To submit private data, pass the sensitive values through the transient map with `with_transient` (they are sent to the endorsing peers but never written to the public ledger) and restrict endorsement to the collection's member organizations with `with_endorsing_organizations`. Use `build_prepared()` instead of `build()` so the target organizations survive to the endorse/evaluate call.

```rust
let mut builder = client.get_chaincode_call_builder();
let prepared = builder
    .with_channel_name("mychannel")?
    .with_chaincode_id("basic")?
    .with_function_name("CreateAssetPrivate")?
    .with_endorsing_organizations(["Org1MSP"])
    .with_transient(
        "asset_properties",
        br#"{"asset_id":"asset1","color":"blue","size":5,"owner":"Alice","appraised_value":300}"#.to_vec(),
    )
    .build_prepared()?;

let mut envelope = prepared.endorse(&client).await?;
envelope.submit(&client).await?;
envelope.wait_for_commit(&client).await?;
```

For read-only private queries use `evaluate`, which targets the configured organizations' peers (only collection members hold the data):

```rust
let prepared = client
    .get_chaincode_call_builder()
    .with_channel_name("mychannel")?
    .with_chaincode_id("basic")?
    .with_function_name("ReadAssetPrivate")?
    .with_function_args(["asset1"])?
    .with_endorsing_organizations(["Org1MSP"])
    .build_prepared()?;

let result = prepared.evaluate(&client).await?;
```

## Defining collections

Collection definitions (member organizations, endorsement policy, `blockToLive`, etc.) are supplied at chaincode approve/commit time. Build a `CollectionConfigPackage` with `gateway::collection::CollectionConfigBuilder` and pass it in the `collections` field of the approve/commit args:

```rust
use fabric_sdk::gateway::collection::CollectionConfigBuilder;

let collection = CollectionConfigBuilder::new("assetCollection")
    .with_member_orgs(["Org1MSP", "Org2MSP"])
    .with_required_peer_count(0)
    .with_maximum_peer_count(1)
    .with_block_to_live(1_000_000)
    .build();

let collections = Some(CollectionConfigBuilder::package([collection]));
```

For per-organization storage you can skip collection definitions entirely and use the implicit collection `_implicit_org_<MSPID>`.

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
