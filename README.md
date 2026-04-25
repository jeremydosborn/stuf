# stuf

A protocol-agnostic supply chain security framework for Rust, designed to run anywhere.

## Overview

stuf provides a minimal trust kernel as the foundation for all protocols.
Developers declare a target environment and receive a correct, minimal binary.
Targets range from bare-metal microcontrollers to cloud services.
The compiler assembles only required components.

## Architecture

```
stuf-core        # no_std trust kernel: Unverified<T> → Verified<T>, zero dependencies
stuf-encoding    # deterministic signing inputs: canonical JSON, PAE, etc.
stuf-env         # pluggable runtime: crypto, transport, storage, clock
stuf-protocols   # TUF, Uptane, in-toto, sigstore, notation
stuf-examples    # embedded, RTOS, cloud examples
```

## Embedded Profile

stuf is currently designed as `no_std + alloc`: it avoids the Rust standard library and operating-system runtime assumptions, while using a small heap for practical matters.

This makes stuf suitable for embedded targets with an allocator today, while leaving a path to a future strict no-alloc profile using borrowed data structures, fixed-capacity buffers, streaming verification, and heapless protocol implementations.

## Encoding

stuf-encoding defines traits for canonical serialization and decoding.
Protocol crates implement these traits with their chosen format.

stuf-tuf currently implements RFC 8785 (JSON Canonicalization Scheme) for
signature verification, with an OLPC canonical JSON stub for legacy TUF
interop. Implementations live in `stuf-protocols/tuf/src/encoding/` behind
compile-time feature flags (`canonical-jcs` is the default).

The JCS canonicalizer uses `serde_json::Value` for tree walking, which
increased heap usage from 8KB to 16KB on the toaster demo. Optimizing this
with a streaming canonicalizer is planned for a future change.

A strict no-heap encoding path is also planned.

## Design Principles

* Zero dependencies and no environment assumptions in the core
* Protocols treated as first-class, each with distinct trust models
* Compiler-enforced trust boundaries preventing unverified data from reaching verified contexts

## Status

Early stage. Core trust kernel complete. TUF protocol v.02 implemented; integration and spec alignment in progress.

## License

Apache 2.0
