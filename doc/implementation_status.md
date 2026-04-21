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
| Evaluate | ❌ | ❌ | ❌ |
| ChaincodeEvents | ✅ | ❌ | 🖉 |

## [Chaincode](https://hyperledger.github.io/fabric-protos/protos.html#protos-Chaincode)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Connect | ✅ | 🏻 | ❌ |

### Chaincode Stream Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| DelState | ✅ | ❌ | 🏻 |
| GetHistoryForKey | ❌ | ❌ | ❌ |
| GetState | ✅  | ❌ | 🏻 |
| GetStateByRange | ✅ | ❌ | 🏻 |
| GetStateMetadata | ❌ | ❌ | ❌ |
| GetStateMultiple | ❌ | ❌ | ❌ |
| PurgePrivateState | ❌ | ❌ | ❌ |
| PutState | ✅  | ❌ | 🏻 |
| PutStateMetadata | ❌ | ❌ | ❌ |

## [ChaincodeSupport](https://hyperledger.github.io/fabric-protos/protos.html#protos-ChaincodeSupport)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Connect | ✅ | ❌ | 🏻 |


## [Snapshot](https://hyperledger.github.io/fabric-protos/protos.html#protos-Snapshot)

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| Generate | ❌ | ❌ | ❌ |
| Cancel | ❌ | ❌ | ❌ |
| QueryPendings | ❌ | ❌ | ❌ |

### Snapshot Methods

| Method     | Implemented      | Unit Tests | Documentation |
| - | - | - | - |
| SignedSnapshotRequest | ❌ | ❌ | ❌ |
| SnapshotRequest | ❌ | ❌ | ❌ |

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
