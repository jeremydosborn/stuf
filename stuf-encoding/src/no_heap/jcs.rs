//! No-heap JSON canonicalizer.
//!
//! Writes canonical JSON to caller-owned sinks. The implementation sorts object
//! keys without allocation by indexing borrowed key/value spans into fixed arrays.

use super::json::{self, JsonError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    Json(JsonError),
    BufferTooSmall,
    TooManyObjectFields,
}

impl From<JsonError> for EmitError {
    fn from(e: JsonError) -> Self {
        EmitError::Json(e)
    }
}

pub trait Emit {
    fn emit(&mut self, bytes: &[u8]) -> core::result::Result<(), EmitError>;
    fn emit_byte(&mut self, b: u8) -> core::result::Result<(), EmitError> {
        self.emit(&[b])
    }
}

pub struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }
    pub fn finish(self) -> &'a [u8] {
        &self.buf[..self.len]
    }
}

impl Emit for SliceWriter<'_> {
    fn emit(&mut self, bytes: &[u8]) -> core::result::Result<(), EmitError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(EmitError::BufferTooSmall)?;
        if end > self.buf.len() {
            return Err(EmitError::BufferTooSmall);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

pub trait HashSink {
    fn update(&mut self, bytes: &[u8]);
}

pub struct HashWriter<'a, H: HashSink> {
    hasher: &'a mut H,
}
impl<'a, H: HashSink> HashWriter<'a, H> {
    pub fn new(hasher: &'a mut H) -> Self {
        Self { hasher }
    }
}
impl<H: HashSink> Emit for HashWriter<'_, H> {
    fn emit(&mut self, bytes: &[u8]) -> core::result::Result<(), EmitError> {
        self.hasher.update(bytes);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Entry<'a> {
    key: &'a [u8],
    value: &'a [u8],
}

pub fn canonicalize_json_to_buf<'a>(
    json_bytes: &[u8],
    out: &'a mut [u8],
) -> core::result::Result<&'a [u8], EmitError> {
    let mut writer = SliceWriter::new(out);
    canonicalize_to(json_bytes, &mut writer)?;
    Ok(writer.finish())
}

pub fn canonicalize_json_to_hasher<H: HashSink>(
    json_bytes: &[u8],
    hasher: &mut H,
) -> core::result::Result<(), EmitError> {
    let mut writer = HashWriter::new(hasher);
    canonicalize_to(json_bytes, &mut writer)
}

pub fn canonicalize_to<W: Emit>(
    json_bytes: &[u8],
    out: &mut W,
) -> core::result::Result<(), EmitError> {
    let v = json::parse_value(json_bytes)?;
    write_value(v.bytes, out)
}

fn write_value<W: Emit>(bytes: &[u8], out: &mut W) -> core::result::Result<(), EmitError> {
    let i = json::skip_ws(bytes, 0);
    match bytes
        .get(i)
        .copied()
        .ok_or(EmitError::Json(JsonError::Invalid))?
    {
        b'{' => write_object(bytes, out),
        b'[' => write_array(bytes, out),
        b'"' => write_string(bytes, out),
        b't' => out.emit(b"true"),
        b'f' => out.emit(b"false"),
        b'n' => out.emit(b"null"),
        b'-' | b'0'..=b'9' => write_number(bytes, out),
        _ => Err(EmitError::Json(JsonError::Invalid)),
    }
}

fn write_array<W: Emit>(bytes: &[u8], out: &mut W) -> core::result::Result<(), EmitError> {
    let mut items = [&[][..]; 16];
    let len = json::array_items(bytes, &mut items)?;
    out.emit_byte(b'[')?;
    for i in 0..len {
        if i > 0 {
            out.emit_byte(b',')?;
        }
        write_value(items[i], out)?;
    }
    out.emit_byte(b']')
}

fn write_object<W: Emit>(bytes: &[u8], out: &mut W) -> core::result::Result<(), EmitError> {
    let mut entries = [Entry {
        key: &[],
        value: &[],
    }; 16];
    let mut len = 0usize;
    let mut i = json::skip_ws(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return Err(EmitError::Json(JsonError::WrongType));
    }
    i += 1;
    i = json::skip_ws(bytes, i);
    if bytes.get(i) != Some(&b'}') {
        loop {
            if len >= entries.len() {
                return Err(EmitError::TooManyObjectFields);
            }
            let (ks, ke) = json::string_span(bytes, i)?;
            i = json::skip_ws(bytes, ke);
            if bytes.get(i) != Some(&b':') {
                return Err(EmitError::Json(JsonError::Invalid));
            }
            i += 1;
            let (vs, ve) = json::value_span(bytes, i)?;
            entries[len] = Entry {
                key: &bytes[ks..ke],
                value: &bytes[vs..ve],
            };
            len += 1;
            i = json::skip_ws(bytes, ve);
            match bytes.get(i) {
                Some(b',') => {
                    i += 1;
                    i = json::skip_ws(bytes, i);
                }
                Some(b'}') => break,
                _ => return Err(EmitError::Json(JsonError::Invalid)),
            }
        }
    }
    // insertion sort by raw key bytes. For ASCII TUF keys this matches JCS order.
    for i in 1..len {
        let mut j = i;
        while j > 0 && key_less(entries[j].key, entries[j - 1].key) {
            entries.swap(j, j - 1);
            j -= 1;
        }
    }
    out.emit_byte(b'{')?;
    for i in 0..len {
        if i > 0 {
            out.emit_byte(b',')?;
        }
        write_string(entries[i].key, out)?;
        out.emit_byte(b':')?;
        write_value(entries[i].value, out)?;
    }
    out.emit_byte(b'}')
}

fn key_less(a: &[u8], b: &[u8]) -> bool {
    // Strip quotes; project metadata keys are ASCII. This keeps the generic
    // encoder no-heap and deterministic while avoiding decoded-key allocation.
    let aa = if a.len() >= 2 { &a[1..a.len() - 1] } else { a };
    let bb = if b.len() >= 2 { &b[1..b.len() - 1] } else { b };
    aa < bb
}

fn write_string<W: Emit>(bytes: &[u8], out: &mut W) -> core::result::Result<(), EmitError> {
    let i = json::skip_ws(bytes, 0);
    let (s, e) = json::string_span(bytes, i)?;
    out.emit(&bytes[s..e])
}

fn write_number<W: Emit>(bytes: &[u8], out: &mut W) -> core::result::Result<(), EmitError> {
    let i = json::skip_ws(bytes, 0);
    let (s, e) = json::value_span(bytes, i)?;
    out.emit(&bytes[s..e])
}
