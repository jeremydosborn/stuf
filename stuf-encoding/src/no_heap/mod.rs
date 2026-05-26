//! No-heap JSON/JCS primitives.
//!
//! These helpers are deliberately protocol-neutral. They parse borrowed JSON
//! byte slices, expose value spans, and canonicalize JSON into caller-owned
//! buffers without `alloc`, `serde_json`, `Vec`, `String`, or maps.

pub mod json;
pub mod jcs;

pub use json::{as_bool, as_str, as_u64, array_items, field, find_object_field, item_at, object_entries, JsonError, ObjectEntry, Value};
pub use jcs::{canonicalize_json_to_buf, canonicalize_json_to_hasher, Emit, HashWriter};
