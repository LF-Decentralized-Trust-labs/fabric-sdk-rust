# Changelog

## 0.5.8

- Fixed `FabricCAClient::revoke` sending a request body the Fabric CA server rejected with
  "Either Name or Serial and AKI are required for a revoke request." The internal
  `RevokeBody` serialized fields using Rust naming (`enrollment_id`, `gen_crl`) instead of
  the JSON tags the CA's `/api/v1/revoke` endpoint expects (`id`, `gencrl`). The public
  `RevokeRequest` API is unchanged.
