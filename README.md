# Fabric SDK Rust
The Fabric SDK for Rust allows to interact with a Hyperledger Fabric blockchain network. It is currently early stage and not functional.
It is aiming to be compatible with Fabric v2.4 or newer.

# Build

This project uses the fabric-protos git as submodule for the protobuf files. To initialize the submodule, run:

```bash
git submodule update --init --recursive
```

# TODO's

- Add protos language binding for Rust in [fabric-protos](https://github.com/hyperledger/fabric-protos)