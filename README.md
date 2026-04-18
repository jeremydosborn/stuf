# stuf
A protocol-agnostic supply chain security framework for Rust, designed to run anywhere.

## What stuf does
stuf provides a single, minimal trust kernel that every protocol builds on.
Declare your target environment and get a correct, minimal binary — from 
bare metal microcontrollers to cloud services. The compiler assembles 
exactly what you need. Nothing else is included.

## Architecture

```
stuf-core        # no_std trust kernel — Unverified<T> → Verified<T>, zero dependencies
stuf-env         # crypto, transport, storage, clock, encoding, etc.
stuf-protocols   # TUF, Uptane, in-toto, sigstore, notation
stuf-examples    # embedded, RTOS, and cloud demos
old/             # reference fork of AWS tough (frozen)
```

## Design Principles

- Core has zero dependencies and zero environment assumptions
- Protocols are first class — TUF, in-toto, and sigstore have different trust shapes and stuf respects that
- The compiler enforces trust boundaries — unverified payloads cannot reach code that requires verified ones

## Status

Early stage. Core trust kernel complete. Protocol implementations in progress.

## Roadmap
- TUF client — in progress
- TUF publisher — planned
- Uptane — planned
- in-toto — planned
- sigstore — planned
- notation — planned

## License

Apache 2.0 / MIT