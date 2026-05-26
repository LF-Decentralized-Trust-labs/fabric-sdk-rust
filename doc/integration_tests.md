# Running the integration tests

The integration tests under `tests/integration/` drive a real Hyperledger Fabric
network. They are **not** run by `cargo test` against mocks — they require a live
test network and the relevant TLS/identity material on disk.

The suite has three parts, run in order from a single `#[test]` entry point
(`tests/integration/main.rs`):

1. **`lifecycle`** — installs, approves, and commits a chaincode definition on
   Org1 and Org2 (requires both peers and the orderer).
2. **`chaincode`** — invokes and queries the committed chaincode through the
   gateway.
3. **`fabric_ca`** — exercises the Fabric CA REST API (get info, list/get/
   register/modify/remove identities, list affiliations). **Skipped** at runtime
   if `FABRIC_CA_URL` is not set.

## Prerequisites

- Rust toolchain (stable).
- Docker + Docker Compose.
- A clone of [`hyperledger/fabric-samples`](https://github.com/hyperledger/fabric-samples).

The tests are exercised against `fabric-samples/test-network`. The SDK targets
Fabric v2.5.x; the Fabric CA test was validated against Fabric CA v1.5.13.

## Starting the test network

The test network **must** be started with the `-ca` flag if you want the
`fabric_ca` tests to pass:

```sh
cd fabric-samples/test-network
./network.sh up createChannel -ca -c mychannel
```

Why `-ca` matters:

- Without it the network uses `cryptogen` for all crypto material. No Fabric CA
  container runs, so the `fabric_ca` test cannot connect.
- With `-ca`, `network.sh` starts `ca_org1` / `ca_org2` / `ca_orderer`, enrolls
  the CA bootstrap admin (`admin:adminpw`) — that's the identity that holds
  `hf.Registrar.Roles=*` and can list/register/modify identities through the CA
  REST API. The peer org admin (`org1admin`) is registered without registrar
  attributes and would be rejected with `'org1admin' is not a registrar`.

The two modes also produce different on-disk **filenames**, which the env file
has to match (see below).

### One additional CA config tweak

The `fabric_ca` test calls `remove_identity` and (potentially) affiliation
deletion. By default Fabric CA rejects these with `Identity removal is disabled`.
To enable them, add this block near the top of the CA's
`fabric-ca-server-config.yaml` (before the `registry:` section) and restart the
CA container:

```yaml
cfg:
  identities:
    allowremove: true
  affiliations:
    allowremove: true
```

The relevant config lives at
`organizations/fabric-ca/org1/fabric-ca-server-config.yaml` in the test-network
working directory.

## Environment configuration

Tests load environment variables via `dotenv` from a `.env` file at the
repository root. Copy `env_default` to `.env` and edit the paths to match
your local checkout of `fabric-samples`.

### Required for `lifecycle` and `chaincode`

| Variable | Purpose |
|---|---|
| `ORDERER_TLS_CERT_PATH` | Orderer TLS CA certificate (PEM). |
| `PEER1_TLS_CERT_PATH` | Org1 peer TLS CA certificate. |
| `PEER1_ADMIN_CERT_PATH` | Org1 admin enrollment certificate. |
| `PEER1_ADMIN_KEY_PATH` | Org1 admin private key. |
| `PEER2_TLS_CERT_PATH` | Org2 peer TLS CA certificate. |
| `PEER2_ADMIN_CERT_PATH` | Org2 admin enrollment certificate. |
| `PEER2_ADMIN_KEY_PATH` | Org2 admin private key. |
| `MSP_ID` | Org1 MSP ID, typically `Org1MSP`. |
| `MSP_ID_ORG2` | Org2 MSP ID, typically `Org2MSP`. |
| `CHANNEL_NAME` | Channel to deploy into, typically `mychannel`. |
| `CHAINCODE_NAME` | Chaincode name, typically `basic`. |
| `CHAINCODE_VERSION` | Chaincode version, typically `1.0`. |

### Optional, for `fabric_ca`

| Variable | Purpose |
|---|---|
| `FABRIC_CA_URL` | Base URL of the CA (e.g. `https://localhost:7054`). **If unset, the `fabric_ca` test is skipped.** |
| `CA_ADMIN_CERT_PATH` | CA bootstrap admin's enrolled cert. Falls back to `PEER1_ADMIN_CERT_PATH` if unset, but that identity is usually not a registrar. |
| `CA_ADMIN_KEY_PATH` | Private key matching `CA_ADMIN_CERT_PATH`. Falls back to `PEER1_ADMIN_KEY_PATH`. |
| `CA_TLS_CERT_PATH` | CA's TLS CA certificate. If unset, the client falls back to `danger_accept_invalid_certs` — fine for a local test net, never in production. |

### Filename differences: cryptogen vs. `-ca` mode

`network.sh` produces materially different paths depending on how you start it.
If you switch modes you have to update `.env` accordingly.

| | `cryptogen` (default) | `-ca` mode |
|---|---|---|
| Admin signcert | `signcerts/Admin@org1.example.com-cert.pem` | `signcerts/cert.pem` |
| Private key | `keystore/priv_sk` | `keystore/<sha256-hash>_sk` |

The hash-prefixed `_sk` filename changes every time `network.sh down && up`
regenerates crypto. Update `.env` after each network restart, or use a
glob/script to resolve it.

### CA bootstrap admin location (`-ca` mode)

When `network.sh up -ca` enrolls the CA bootstrap admin (`admin:adminpw`), it
writes the resulting MSP one level above the peer org admin:

```
organizations/peerOrganizations/org1.example.com/msp/signcerts/cert.pem
organizations/peerOrganizations/org1.example.com/msp/keystore/<hash>_sk
```

That's the cert/key pair to point `CA_ADMIN_CERT_PATH` and `CA_ADMIN_KEY_PATH`
at. The `users/Admin@org1.example.com/...` material below it is the peer org
admin (`org1admin`), which lacks registrar privileges.

## Running

From the repository root:

```sh
cargo test --test integration test_integration -- --nocapture
```

`--nocapture` is useful because the tests print package IDs, sequence numbers,
and CA info as they go.

To run only the non-CA portion, leave `FABRIC_CA_URL` unset in `.env`. The
`fabric_ca::run()` step will print `Skipping Fabric CA tests: FABRIC_CA_URL not
set` and return.

## Re-running and cleanup

The tests are written to be **idempotent** so you can re-run them against the
same network without tearing it down:

- `lifecycle` bumps the chaincode definition sequence each run, and tolerates
  "package already installed" errors from the peer.
- `fabric_ca` deletes any leftover `sdk-test-user` from a prior failed run
  before registering it again.

If you tear the network down (`./network.sh down`), all CA state is wiped — the
SQLite DB is inside the container and not persisted. You will also need to
re-apply the `cfg.identities.allowremove` tweak on the new CA config (or bake
it into the source `fabric-ca-server-config.yaml` under
`organizations/fabric-ca/org1/`).

## Troubleshooting

- **`Couldn't read file at PEER1_ADMIN_KEY_PATH`** — `.env` paths are stale.
  After every `network.sh up` the `_sk` filename changes; re-resolve it.
- **`CAError("Authentication failure")`** — the CA can't verify the token. Most
  often this means the LDAP backend is enabled but empty; make sure you're
  pointing at a CA started by `network.sh -ca` (SQLite backend), not a separate
  LDAP-backed CA.
- **`'org1admin' is not a registrar`** — `CA_ADMIN_*` is falling back to the
  peer org admin. Point it at the CA bootstrap admin's MSP (see above).
- **`Identity removal is disabled`** — the CA config tweak above hasn't been
  applied, or the CA container wasn't restarted after editing its config.
- **`CAError("Identity 'sdk-test-user' is already registered")`** — left over
  from an aborted run on a CA that doesn't allow removal. Either enable
  `allowremove` and re-run, or bounce the CA so its SQLite DB is recreated.
