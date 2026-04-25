//! RFC 8785 — JSON Canonicalization Scheme (JCS).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde_json::Value;
use stuf_encoding::{Canonicalize, EncodeError};

#[derive(Debug, Clone, Copy)]
pub struct Jcs;

impl Canonicalize for Jcs {
    fn canonicalize<T>(&self, value: &T) -> Result<Vec<u8>, EncodeError>
    where
        T: serde::Serialize,
    {
        let json_value = serde_json::to_value(value).map_err(|_| EncodeError::Canonicalize)?;
        let mut buf = Vec::new();
        write_canonical(&json_value, &mut buf)?;
        Ok(buf)
    }
}

fn write_canonical(value: &Value, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(true) => buf.extend_from_slice(b"true"),
        Value::Bool(false) => buf.extend_from_slice(b"false"),
        Value::Number(n) => {
            let s = n.to_string();
            buf.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => write_canonical_string(s, buf),
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(item, buf)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| cmp_utf16(a, b));
            buf.push(b'{');
            for (i, (key, val)) in entries.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical_string(key, buf);
                buf.push(b':');
                write_canonical(val, buf)?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

fn write_canonical_string(s: &str, buf: &mut Vec<u8>) {
    buf.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\u{0008}' => buf.extend_from_slice(b"\\b"),
            '\u{0009}' => buf.extend_from_slice(b"\\t"),
            '\u{000A}' => buf.extend_from_slice(b"\\n"),
            '\u{000C}' => buf.extend_from_slice(b"\\f"),
            '\u{000D}' => buf.extend_from_slice(b"\\r"),
            c if c < '\u{0020}' => {
                buf.extend_from_slice(b"\\u");
                buf.extend_from_slice(alloc::format!("{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut utf8_buf = [0u8; 4];
                buf.extend_from_slice(c.encode_utf8(&mut utf8_buf).as_bytes());
            }
        }
    }
    buf.push(b'"');
}

fn cmp_utf16(a: &str, b: &str) -> core::cmp::Ordering {
    let a_units = a.encode_utf16();
    let b_units = b.encode_utf16();
    for (au, bu) in a_units.zip(b_units) {
        match au.cmp(&bu) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    a.encode_utf16().count().cmp(&b.encode_utf16().count())
}
