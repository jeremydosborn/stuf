# stuf

A protocol-agnostic supply chain security framework for Rust, designed to run anywhere.

## What stuf does

stuf provides a single, minimal trust kernel that every protocol builds on.

## Architecture

```
stuf-core        # no_std trust kernel — runs anywhere
stuf-env         # platform bindings — FreeRTOS, std, bare metal, etc.
stuf-protocols   # TUF, Uptane, in-toto, sigstore
stuf-examples    # embedded and cloud demos
old/             # reference fork of Amazon's tough (frozen)
```

## Design Principles

- Core has zero dependencies and zero environment assumptions
- Protocols are first class — TUF, in-toto, and sigstore have different trust shapes and stuf respects that
- The compiler enforces trust boundaries — unverified payloads cannot reach code that requires verified ones

## Status

Early stage. Core trust kernel complete. Protocol implementations in progress.

## License

Apache 2.0 / MIT