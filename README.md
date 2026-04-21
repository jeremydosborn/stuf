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
stuf-env         # crypto, transport, storage, clock, encoding
stuf-protocols   # TUF, Uptane, in-toto, sigstore, notation
stuf-examples    # embedded, RTOS, cloud examples
```

## Design Principles

* Zero dependencies and no environment assumptions in the core
* Protocols treated as first-class, each with distinct trust models
* Compiler-enforced trust boundaries preventing unverified data from reaching verified contexts

## Status

Early stage. Core trust kernel complete. TUF protocol implemented; integration and spec alignment in progress.

## License

Apache 2.0
