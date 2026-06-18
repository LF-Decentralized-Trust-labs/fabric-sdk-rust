# Status of implementation

In this document you'll find a list of methods available on fabric. A full list can be found [here](https://hyperledger.github.io/fabric-protos/protos.html).

Most of the respond or request structs are available through the proto files of fabric. For this crate we need to implement every request and respond handling and therefore you'll find every request in this list.

This list ist sorted by relevance. Gateway and Chaincode gives basic functionallity of processing chaincode calls.

If you find yourself missing a method or for any features please open an issue.

## Legend

| Symbol     | Description   |
| - | - |
| ✅ | Done |
| ❌ | Missing |
| 🏻 | Partially |
| 🖉 | In Progress/Planned |

## [Gateway](https://hyperledger.github.io/fabric-protos/protos.html#gateway-Gateway)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Endorse | ✅ | 🏻 | 🏻 |
| Submit | ✅ | 🏻 | 🏻 |
| CommitStatus | ✅ | ❌ | 🏻 |
| Evaluate | ✅ | ❌ | 🏻 |
| ChaincodeEvents | ✅ | ❌ | 🖉 |

## [Chaincode](https://hyperledger.github.io/fabric-protos/protos.html#protos-Chaincode)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Connect | ✅ | 🏻 | ❌ |

### Chaincode Stream Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| DelState | ✅ | 🏻 | 🏻 |
| GetHistoryForKey | ✅ | ❌ | 🏻 |
| GetQueryResult | ✅ | ✅ | ✅ |
| GetQueryResult (paginated) | ✅ | ❌ | ✅ |
| GetState | ✅  | 🏻 | 🏻 |
| GetStateByRange | ✅ | 🏻 | 🏻 |
| GetStateByRange (paginated) | ✅ | ❌ | 🏻 |
| GetStateMetadata | ✅ | ❌ | 🏻 |
| GetStateMultiple | ✅ | ❌ | 🏻 |
| GetPrivateDataHash | ✅ | ❌ | 🏻 |
| PurgePrivateData | ✅ | ❌ | 🏻 |
| PutState | ✅  | 🏻 | 🏻 |
| PutStateMetadata | ✅ | ❌ | 🏻 |

### Private Data Collections

Private data is supported on both the client and chaincode sides. The client supplies private values via the transient map (`with_transient`) and steers endorsement to collection member organizations (`with_endorsing_organizations` + `build_prepared`). The chaincode reads/writes collections via the `*_private_data` methods on `Context`. Collection definitions are supplied at approve/commit time via `gateway::collection::CollectionConfigBuilder`.

| Feature     | Implemented      | Tests | Documentation |
| - | - | - | - |
| Transient map (client) | ✅ | 🖉 | 🏻 |
| Endorsing/target organizations | ✅ | 🖉 | 🏻 |
| Get/Put/Del private data (chaincode) | ✅ | 🖉 | 🏻 |
| GetPrivateDataHash (chaincode) | ✅ | ❌ | 🏻 |
| Private data rich query (chaincode) | ✅ | ❌ | 🏻 |
| Purge private data (chaincode) | ✅ | ❌ | 🏻 |
| Private data metadata / validation parameter | ✅ | ❌ | 🏻 |
| Collection config (lifecycle) | ✅ | ❌ | 🏻 |

## [ChaincodeSupport](https://hyperledger.github.io/fabric-protos/protos.html#protos-ChaincodeSupport)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Connect | ✅ | ❌ | 🏻 |


## [Snapshot](https://hyperledger.github.io/fabric-protos/protos.html#protos-Snapshot)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Generate | ✅ | ❌ | 🏻 |
| Cancel | ✅ | ❌ | 🏻 |
| QueryPendings | ✅ | ❌ | 🏻 |

### Snapshot Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| SignedSnapshotRequest | ✅ | ❌ | 🏻 |
| SnapshotRequest | ✅ | ❌ | 🏻 |

## [Gossip](https://hyperledger.github.io/fabric-protos/protos.html#gossip-Gossip)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| GossipStream | ❌ | ❌ | ❌ |
| Ping | ❌ | ❌ | ❌ |

### Gossip Stream Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Data | ❌ | ❌ | ❌ |
| Membership | ❌ | ❌ | ❌ |
| RemotePvtData | ❌ | ❌ | ❌ |
| RemoteState | ❌ | ❌ | ❌ |

## [Discovery](https://hyperledger.github.io/fabric-protos/protos.html#discovery-Discovery)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Discover | ❌ | ❌ | ❌ |

## [AtomicBroadcast](https://hyperledger.github.io/fabric-protos/protos.html#orderer-AtomicBroadcast)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Broadcast | ❌ | ❌ | ❌ |
| Deliver | ❌ | ❌ | ❌ |

### AtomicBroadcast Stream Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| SeekInfo | ❌ | ❌ | ❌ |
| SeekNewest | ❌ | ❌ | ❌ |
| SeekNextCommit | ❌ | ❌ | ❌ |
| SeekOldest | ❌ | ❌ | ❌ |
| SeekPosition | ❌ | ❌ | ❌ |
| SeekSpecified | ❌ | ❌ | ❌ |

## [Cluster](https://hyperledger.github.io/fabric-protos/protos.html#orderer-Cluster)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Step | ❌ | ❌ | ❌ |

### Cluster Stream Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Consensus | ❌ | ❌ | ❌ |
| Step | ❌ | ❌ | ❌ |
| Submit | ❌ | ❌ | ❌ |
| ClusterNodeServiceStep | ❌ | ❌ | ❌ |
| NodeAuth | ❌ | ❌ | ❌ |
| NodeConsensus | ❌ | ❌ | ❌ |
| NodeTransactionOrder | ❌ | ❌ | ❌ |

## [ClusterNodeService](https://hyperledger.github.io/fabric-protos/protos.html#orderer-ClusterNodeService)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Step | ❌ | ❌ | ❌ |

### ClusterNodeService Stream Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| ClusterNodeServiceStep | ❌ | ❌ | ❌ |
| NodeAuth | ❌ | ❌ | ❌ |
| NodeConsensus | ❌ | ❌ | ❌ |
| NodeTransactionOrder | ❌ | ❌ | ❌ |

## [Deliver](https://hyperledger.github.io/fabric-protos/protos.html#protos-Deliver)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Deliver | ❌ | ❌ | ❌ |
| DeliverFiltered | ❌ | ❌ | ❌ |
| DeliverWithPrivateData | ❌ | ❌ | ❌ |

## [Endorser](https://hyperledger.github.io/fabric-protos/protos.html#protos-Endorser)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| ProcessProposal | ❌ | ❌ | ❌ |

## [Fabric CA](https://hyperledger-fabric-ca.readthedocs.io/en/latest/)

The Fabric CA is a separate service from the peer gateway and exposes a REST API (not gRPC).
It manages user and service identities (X.509 certificates) for each organization.

| Method           | Implemented | Integration Tests | Documentation |
| - | - | - | - |
| GetCAInfo        | ✅ | ✅ | ✅ |
| ListIdentities   | ✅ | ✅ | ✅ |
| GetIdentity      | ✅ | ✅ | ✅ |
| RegisterIdentity | ✅ | ✅ | ✅ |
| ModifyIdentity   | ✅ | ✅ | ✅ |
| RemoveIdentity   | ✅ | ✅ | ✅ |
| ListAffiliations | ✅ | ✅ | ✅ |
| GetAffiliation   | ✅ | ✅ | ✅ |
| Revoke           | ✅ | ✅ | ✅ |
| Enroll           | ❌ | ❌ | ❌ |
| Reenroll         | ❌ | ❌ | ❌ |

Required environment variables for Fabric CA integration tests:
- `FABRIC_CA_URL` — base URL of the CA server, e.g. `https://localhost:7054` (tests are skipped if not set)
- `PEER1_ADMIN_CERT_PATH` — reused from lifecycle tests (admin enrollment certificate)
- `PEER1_ADMIN_KEY_PATH` — reused from lifecycle tests (admin private key)
- `PEER1_TLS_CERT_PATH` — reused from gateway/lifecycle tests (shared TLS root CA certificate)
