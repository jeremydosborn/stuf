# stuf-encoding no-heap backend

This directory contains protocol-neutral no-heap JSON/JCS primitives.

It deliberately does **not** know about TUF. It provides:

- borrowed JSON scanning over `&[u8]`;
- object field lookup by borrowed key;
- fixed-array object/array iteration;
- canonical JSON emission to caller-owned buffers;
- canonical JSON emission to caller-provided hash sinks.

TUF-specific metadata interpretation lives in `stuf-protocols/tuf/src/verify/no_heap`.
