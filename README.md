# Fabric SDK Rust
The Fabric SDK for Rust allows to interact with a Hyperledger Fabric blockchain network. It is currently early stage and not functional.
It is aiming to be compatible with Fabric v2.4 or newer.

# Prepare

The tests written in this project are based on the basic chaincode written in the [docs](https://ethan-li-fabric.readthedocs.io/en/latest/test_network.html)

This can be changed via env variables

Clone the project
```bash
git clone https://github.com/LF-Decentralized-Trust-labs/fabric-sdk-rust && cd fabric-sdk-rus
```

Copy the env_default to .env
```bash
cp env_default .env
```
This project uses the fabric-protos git as submodule for the protobuf files. To initialize the submodule, run:

```bash
git submodule update --init --recursive
```

And now you are ready to go!

# Using the crate

The crate can be used via local link:
```toml
fabric-sdk-rust = {path="../fabric-sdk-rust"}
```

Keep in mind, that this is still under heavy development and cannot seen as "safe"!

# TODO's

- Add protos language binding for Rust in [fabric-protos](https://github.com/hyperledger/fabric-protos)
