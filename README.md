manta crypto
------

The underlying cryptography that manta ecosystem relies on.
It comes with the following traits:

- `checksum`: definitions for message digest.
- `commitment`: definitions for commitment schemes.
- `constant`: contains constants and pre-computed values.
- `ecies`: manta's own implementation of `ECIES` algorithm.
- `merkle_tree`: definitions for merkle tree.
- `param`: which is a wrapper that exposes necessary Arkwork's structs, with proper configuration for Manta system.
- `serdes`: manta's own serialization and deserialization interfaces.
- `zkp`: manta's own zero-knowledge proof interfaces.