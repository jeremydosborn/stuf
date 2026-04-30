# stuf

Supply chain security for Rust. Runs anywhere from bare-metal to cloud and beyond.

## Architecture

```
stuf-core         # trust kernel: Verified<T>, Verifier<T>, no_std
stuf-encoding     # canonical serialization and decoding traits
stuf-env          # platform bindings: crypto, transport, storage, clock
stuf-protocols    # TUF to start
stuf-examples     # toaster demo (ARM Cortex-M3), publisher
```

## How it works

The app picks a protocol and a platform. Feature flags control what
compiles. The compiler assembles only the components you need.

stuf-core defines the trust type (Verified<T>) and verification trait.
Every protocol implements the same trait and mints the same type.
The minting ceremony is consistent across all protocols.

stuf-encoding owns canonical serialization and decoding. stuf-tuf
implements RFC 8785 (JCS) for canonicalization and JSON decoding behind
feature flags, with OLPC stubbed for legacy interop.

stuf-env provides pluggable platform bindings via feature flags. Swap
crypto, transport, and storage per target without changing protocol logic.

## Embedded

no_std + alloc. No OS assumptions. Currently requires a small heap.
A no-heap path is planned.

## Status

Early. Core complete. TUF v0.5 implemented. Integration and spec
alignment in progress.

## License

Apache 2.0