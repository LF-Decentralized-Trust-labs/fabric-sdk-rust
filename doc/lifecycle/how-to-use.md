# Lifecycle Client

The `LifecycleClient` provides ergonomic methods for managing the Hyperledger Fabric v2.x chaincode lifecycle from Rust.
It wraps a connected [`Client`](../client/how-to-use.md) and covers every step: package installation, org approval, commit readiness checks, and the various query operations.

1. [Prerequisites](#prerequisites)
2. [Obtaining a LifecycleClient](#obtaining-a-lifecycleclient)
3. [Full lifecycle walkthrough](#full-lifecycle-walkthrough)
   - [1. Install a chaincode package](#1-install-a-chaincode-package)
   - [2. Query installed chaincodes](#2-query-installed-chaincodes)
   - [3. Approve the chaincode definition](#3-approve-the-chaincode-definition)
   - [4. Check commit readiness](#4-check-commit-readiness)
   - [5. Commit the chaincode definition](#5-commit-the-chaincode-definition)
4. [Query operations](#query-operations)
   - [Query a committed definition](#query-a-committed-definition)
   - [Query all committed definitions](#query-all-committed-definitions)
   - [Query your org's approved definition](#query-your-orgs-approved-definition)
   - [Query all your org's approved definitions](#query-all-your-orgs-approved-definitions)
   - [Download an installed package](#download-an-installed-package)
5. [Error handling](#error-handling)

---

## Prerequisites

Add the crate to your `Cargo.toml`:

```toml
fabric-sdk = "0.5.0"
```

A running Fabric network with at least one peer that your client can reach is required.
See the [client docs](../client/how-to-use.md) for how to build and connect a `Client`.

---

## Obtaining a LifecycleClient

`LifecycleClient` borrows an already-connected `Client` and is obtained through `Client::get_lifecycle_client`:

```rust
use fabric_sdk::{client::ClientBuilder, identity::IdentityBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem_bytes    = include_bytes!("path/to/signcerts/User1@org1.example.com-cert.pem");
    let tlsca_bytes  = include_bytes!("path/to/tlsca/tlsca.org1.example.com-cert.pem");
    let key_bytes    = include_bytes!("path/to/keystore/priv_sk");

    let identity = IdentityBuilder::from_pem(pem_bytes)
        .with_msp("Org1MSP")?
        .with_private_key(key_bytes)?
        .build()?;

    let mut client = ClientBuilder::new()
        .with_identity(identity)?
        .with_tls(tlsca_bytes)?
        .with_scheme("https")?
        .with_authority("localhost:7051")?
        .build()?;
    client.connect().await?;

    // Borrow the client to get a lifecycle handle
    let lifecycle = client.get_lifecycle_client();

    Ok(())
}
```

---

## Full lifecycle walkthrough

### 1. Install a chaincode package

Read a `.tar.gz` chaincode package from disk and install it on the connected peer.
The returned `InstallChaincodeResult` contains the `package_id` you need for the approval step.

```rust
use fabric_sdk::error::LifecycleError;

let package_bytes = std::fs::read("basic.tar.gz")?;

let install_result = lifecycle.install_chaincode(package_bytes).await?;
println!("Installed: package_id={}, label={}", install_result.package_id, install_result.label);
```

### 2. Query installed chaincodes

Verify the package was installed and retrieve its `package_id` if you lost track of it:

```rust
let installed = lifecycle.query_installed_chaincodes().await?;

for cc in &installed.installed_chaincodes {
    println!("  {} ({})", cc.label, cc.package_id);
}

// Or look up one package by id:
let details = lifecycle.query_installed_chaincode(&install_result.package_id).await?;
println!("Label: {}", details.label);
```

### 3. Approve the chaincode definition

Each organization must approve the chaincode definition before it can be committed.
This sends an endorsement transaction to the peer and waits for the block to be committed.

```rust
use fabric_sdk::fabric::lifecycle::{
    ApproveChaincodeDefinitionForMyOrgArgs, ChaincodeSource, chaincode_source,
};

lifecycle.approve_chaincode_definition(
    "mychannel",
    ApproveChaincodeDefinitionForMyOrgArgs {
        name: "basic".into(),
        version: "1.0".into(),
        sequence: 1,
        // Point to the locally installed package
        source: Some(ChaincodeSource {
            r#type: Some(chaincode_source::Type::LocalPackage(
                chaincode_source::Local {
                    package_id: install_result.package_id.clone(),
                },
            )),
        }),
        ..Default::default()
    },
).await?;

println!("Approved for Org1MSP");
```

### 4. Check commit readiness

Before committing, verify that enough organizations have approved.
The result maps each org's MSP ID to a boolean indicating its approval status.

```rust
use fabric_sdk::fabric::lifecycle::CheckCommitReadinessArgs;

let readiness = lifecycle.check_commit_readiness(
    "mychannel",
    CheckCommitReadinessArgs {
        name: "basic".into(),
        version: "1.0".into(),
        sequence: 1,
        ..Default::default()
    },
).await?;

for (org, approved) in &readiness.approvals {
    println!("  {org}: {}", if *approved { "approved" } else { "not approved" });
}
```

### 5. Commit the chaincode definition

Once sufficient organizations have approved, commit the definition to the channel.
Like approval, this waits for the block to be committed before returning.

```rust
use fabric_sdk::fabric::lifecycle::CommitChaincodeDefinitionArgs;

lifecycle.commit_chaincode_definition(
    "mychannel",
    CommitChaincodeDefinitionArgs {
        name: "basic".into(),
        version: "1.0".into(),
        sequence: 1,
        ..Default::default()
    },
).await?;

println!("Chaincode committed to mychannel");
```

---

## Query operations

### Query a committed definition

```rust
let def = lifecycle.query_chaincode_definition("mychannel", "basic").await?;
println!("basic v{} seq={}", def.version, def.sequence);

// Approval map: org MSP ID -> approved
for (org, approved) in &def.approvals {
    println!("  {org}: {approved}");
}
```

### Query all committed definitions

```rust
let result = lifecycle.query_chaincode_definitions("mychannel").await?;

for def in &result.chaincode_definitions {
    println!("{} v{} (seq {})", def.name, def.version, def.sequence);
}
```

### Query your org's approved definition

Pass `-1` as `sequence` to retrieve the latest approved sequence for your org.

```rust
// Query the latest approved sequence
let approved = lifecycle
    .query_approved_chaincode_definition("mychannel", "basic", -1)
    .await?;

println!("Approved seq={}, version={}", approved.sequence, approved.version);
```

### Query all your org's approved definitions

```rust
let all_approved = lifecycle
    .query_approved_chaincode_definitions("mychannel")
    .await?;

for def in &all_approved.approved_chaincode_definitions {
    println!("{} v{} (seq {})", def.name, def.version, def.sequence);
}
```

### Download an installed package

Retrieve the raw package bytes of a previously installed chaincode:

```rust
let package_bytes = lifecycle
    .get_installed_chaincode_package(&install_result.package_id)
    .await?;

std::fs::write("recovered.tar.gz", &package_bytes)?;
println!("Downloaded {} bytes", package_bytes.len());
```

---

## Error handling

All methods return `Result<_, LifecycleError>`. The variants are:

| Variant | Meaning |
|---|---|
| `NotConnected` | The client was not connected before calling a lifecycle method |
| `NodeError(String)` | The peer returned a gRPC error |
| `DecodeError(&str)` | The response payload could not be decoded as a protobuf message |
| `EmptyResponse` | The peer returned a successful response but the result payload was empty |
| `BuilderError(BuilderError)` | A proposal could not be built (e.g. missing channel or function name) |
| `SubmitError(SubmitError)` | The transaction could not be submitted to the orderer |

```rust
use fabric_sdk::error::LifecycleError;

match lifecycle.install_chaincode(package_bytes).await {
    Ok(result) => println!("Installed: {}", result.package_id),
    Err(LifecycleError::NotConnected) => eprintln!("Call client.connect() first"),
    Err(LifecycleError::NodeError(msg)) => eprintln!("Peer error: {msg}"),
    Err(e) => eprintln!("Lifecycle error: {e}"),
}
```
