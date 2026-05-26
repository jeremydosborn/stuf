# stuf-tuf no-heap verifier backend

This directory contains only TUF-specific no-heap verification logic.

Generic JSON/JCS scanning and canonicalization live in `stuf-encoding::no_heap`.

This backend is enabled with the `no-heap` feature and is mutually exclusive
with the existing `alloc` verifier backend. The public entry point is still
`TrustAnchor`, re-exported from `stuf-tuf` under the selected feature.

The no-heap backend verifies the current STUF top-level TUF profile:

- trusted root;
- timestamp;
- snapshot;
- targets;
- target length/hash.

Delegations and root rotation remain separate future work.
