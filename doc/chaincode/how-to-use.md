# Chaincode

1. [Limitations](<#Limitations>)
2. [Using-the-chaincode-library](<#Using the chaincode library>)
    - [Importing the crate](<#Importing the crate>)
    - [Configure project](<#Configure project>)
    - [Defining functions](<#Defining functions>)
    - [Registering functions](<#Registering functions>)
3. [Configure Fabric](<#Configure Fabric>)
    - [Install and Deploy the chaincode](<#Install and Deploy the chaincode>)

## Limitations

Since rust is not yet officially supported by fabric, the current implementation has some limitations.
Despite of not being fully developed yet, the resulting binary can only be compiled and deployed for one architecture. Since binaries for different architectures result in a different hash, building for a network which hosts different architectures, will result in not having a consesnus. For this there is a [current issue](https://github.com/hyperledger/fabric/issues/3649#issuecomment-3585562780) on GitHub to resolve this problem.

## Using the chaincode library

A simple asset transfer example can be found in the [fabric-samples fork](https://github.com/arne-fuchs/fabric-samples/tree/main/asset-transfer-basic/chaincode-rust) where the rust support is beind demonstrated

### Importing the crate

The crate can be used via direct github link:
```toml
fabric-sdk = {git="https://github.com/LF-Decentralized-Trust-labs/fabric-sdk-rust"}
```

### Configure project

Rust is not (yet) officialy supported by fabric so there are some preparations we have to make.

Under the `[package]` part, we need to define the name to `chaincode`. This can be changed in the builder later on to accept another name, but the provided example expects this name.

```toml
[package]
name = "chaincode"
```
Since we may not have the required libraries to execute our chaincode we need to tell cargo to statically link the libraries we are using.
Some crates do not like this and will not compile. Most of them do have a feature though, supporting this. Defining this is optional since it can also be done via cargo arguments.

If you want to configure it for your project create a `.cargo/config.toml` in your project root and put this into it:

```toml
[build]
rustflags = ["-C", "target-feature=+crt-static"]
target = "x86_64-unknown-linux-gnu"
```

Since we run on a different name, we have to tell cargo where the main.rs is, so we define in our `cargo.toml` a bin:

```toml
[[bin]]
name = "chaincode"
path = "src/main.rs"
```

### Importing the crate

A simple `use fabric_sdk::prelude::*;` should include all imports you need to use this library;

### Defining functions

Functions, which should be callable from outside the chaincode, needs to have the `#[transaction]
` macro. This macro enforces the arguments and the return type of the function to implement `Serialize` and `Deserialize` from the `serde_json` crate.

`Result` types are not (yet) supported.

```rust
use fabric_sdk::prelude::*;

#[transaction]
pub async fn read_asset(ctx: Context, asset_id: String) -> Asset {
    serde_json::from_str(ctx.get_state_string(asset_id.as_str()).await.as_str())
        .expect("Invalid or no asset")
}
```

The Context struct provides functions like `put_state` to interact with the ledger.
Only a small, basic set of methods is currently implemented.

### Registering functions

Functions defined with the `#[fabric_sdk::transaction]` macro needs to be registered via the register function to be accessable from the outside.

The functions takes a `&str` to define the name of the contract in the chaincode and the list of chaincode functions defined in the `functions![]` macro.
`""` is corresponding to the default contract.

```rust
use fabric_sdk::prelude::*;

fn main() {
    fabric_sdk::chaincode::initialize()
        .register(
            "basic",
            functions![
                asset::create_asset,
                asset::asset_exists,
                asset::read_asset,
                asset::update_asset,
                asset::delete_asset,
                asset::transfer_asset,
                asset::get_all_assets
            ],
        )
        .launch();
}
```

`register` consumes itself so it is possible to daisy chain register calls to register several contracts in a chaincode.

```rust
fabric_sdk::chaincode::initialize()
    .register(
        "", // default contract
        functions![
        ..
        ],
    )
    .register(
        "basic",
        functions![
        ..
        ],
    )
    .launch();
```

### Compile and Package

Before packaging the chaincode we need to define a `metadata.json` which contains all the information for fabric to execute the chaincode.

```json
{
    "type": "binary",
    "label": "basic"
}
```
- `type` defines in which format the chaincode is being provided, in our case a binary. For example for java chaincodes it would be java.
- `label` here we define the name of our chaincode. In the provided asset transfer example it is basic.

To compile the chaincode and package it for fabric, we need to execute following commands, which can be put into a little script:

```bash
#!/bin/bash
RUSTFLAGS="-C target-feature=+crt-static" cargo build --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/debug/chaincode chaincode
tar -cvzf code.tar.gz chaincode
tar -cvzf basic.tar.gz code.tar.gz metadata.json
rm chaincode code.tar.gz
```

## Configure Fabric

Since rust is not officially supported we need a custom builder, which is able to execute binaries.
In this repo you can find the builder in the root of the project.

Copy this folder somewhere to you fabric instance.

In the `core.yaml` file go to the `chaincode` -> `externalBuilders` section and add the builder as followed:

```yaml
externalBuilders:
    - name: cargo
      path: /opt/hyperledger/builder
```

Here the builder is called `cargo` but you can use whatever name you like.

If you use the docker setup you need to add the builder to the volumes of the fabric container:

```yaml
volumes:
    - /path/to/builder:/opt/hyperledger/builder
```

### Install and Deploy the chaincode

From now on it follows the [official documentation](https://hyperledger-fabric.readthedocs.io/en/release-2.5/deploy_chaincode.html).
