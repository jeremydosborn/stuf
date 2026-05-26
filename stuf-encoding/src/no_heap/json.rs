//! Borrowed no-heap JSON scanner.
//!
//! This is intentionally small: it accepts ordinary JSON and returns borrowed
//! spans. It does not allocate and it does not deserialize to owned structs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    Invalid,
    NotFound,
    WrongType,
    TooManyItems,
    NestingTooDeep,
}

pub type Result<T> = core::result::Result<T, JsonError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value<'a> {
    pub bytes: &'a [u8],
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t')
}

pub fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && is_ws(bytes[i]) {
        i += 1;
    }
    i
}

pub fn value_span(bytes: &[u8], i: usize) -> Result<(usize, usize)> {
    value_span_inner(bytes, skip_ws(bytes, i), 0)
}

fn value_span_inner(bytes: &[u8], i: usize, depth: usize) -> Result<(usize, usize)> {
    if depth > 64 {
        return Err(JsonError::NestingTooDeep);
    }
    if i >= bytes.len() {
        return Err(JsonError::Invalid);
    }
    match bytes[i] {
        b'{' => object_span(bytes, i, depth + 1),
        b'[' => array_span(bytes, i, depth + 1),
        b'"' => string_span(bytes, i),
        b't' if bytes.get(i..i + 4) == Some(b"true") => Ok((i, i + 4)),
        b'f' if bytes.get(i..i + 5) == Some(b"false") => Ok((i, i + 5)),
        b'n' if bytes.get(i..i + 4) == Some(b"null") => Ok((i, i + 4)),
        b'-' | b'0'..=b'9' => number_span(bytes, i),
        _ => Err(JsonError::Invalid),
    }
}

pub fn string_span(bytes: &[u8], i: usize) -> Result<(usize, usize)> {
    if bytes.get(i) != Some(&b'"') {
        return Err(JsonError::WrongType);
    }
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'"' => return Ok((i, j + 1)),
            b'\\' => {
                j += 1;
                if j >= bytes.len() {
                    return Err(JsonError::Invalid);
                }
                match bytes[j] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => j += 1,
                    b'u' => {
                        if j + 4 >= bytes.len() {
                            return Err(JsonError::Invalid);
                        }
                        for k in j + 1..=j + 4 {
                            if !bytes[k].is_ascii_hexdigit() {
                                return Err(JsonError::Invalid);
                            }
                        }
                        j += 5;
                    }
                    _ => return Err(JsonError::Invalid),
                }
            }
            b if b < 0x20 => return Err(JsonError::Invalid),
            _ => j += 1,
        }
    }
    Err(JsonError::Invalid)
}

fn number_span(bytes: &[u8], mut i: usize) -> Result<(usize, usize)> {
    let start = i;
    if bytes.get(i) == Some(&b'-') {
        i += 1;
    }
    if i >= bytes.len() {
        return Err(JsonError::Invalid);
    }
    match bytes[i] {
        b'0' => i += 1,
        b'1'..=b'9' => {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        _ => return Err(JsonError::Invalid),
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        if i >= bytes.len() || !bytes[i].is_ascii_digit() {
            return Err(JsonError::Invalid);
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < bytes.len() && matches!(bytes[i], b'e' | b'E') {
        i += 1;
        if i < bytes.len() && matches!(bytes[i], b'+' | b'-') {
            i += 1;
        }
        if i >= bytes.len() || !bytes[i].is_ascii_digit() {
            return Err(JsonError::Invalid);
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    Ok((start, i))
}

fn object_span(bytes: &[u8], mut i: usize, depth: usize) -> Result<(usize, usize)> {
    let start = i;
    i += 1;
    i = skip_ws(bytes, i);
    if bytes.get(i) == Some(&b'}') {
        return Ok((start, i + 1));
    }
    loop {
        let (_, ke) = string_span(bytes, i)?;
        i = skip_ws(bytes, ke);
        if bytes.get(i) != Some(&b':') {
            return Err(JsonError::Invalid);
        }
        i += 1;
        let (_, ve) = value_span_inner(bytes, i, depth + 1)?;
        i = skip_ws(bytes, ve);
        match bytes.get(i) {
            Some(b',') => {
                i += 1;
                i = skip_ws(bytes, i);
            }
            Some(b'}') => return Ok((start, i + 1)),
            _ => return Err(JsonError::Invalid),
        }
    }
}

fn array_span(bytes: &[u8], mut i: usize, depth: usize) -> Result<(usize, usize)> {
    let start = i;
    i += 1;
    i = skip_ws(bytes, i);
    if bytes.get(i) == Some(&b']') {
        return Ok((start, i + 1));
    }
    loop {
        let (_, ve) = value_span_inner(bytes, i, depth + 1)?;
        i = skip_ws(bytes, ve);
        match bytes.get(i) {
            Some(b',') => {
                i += 1;
                i = skip_ws(bytes, i);
            }
            Some(b']') => return Ok((start, i + 1)),
            _ => return Err(JsonError::Invalid),
        }
    }
}

pub fn parse_value(bytes: &[u8]) -> Result<Value<'_>> {
    let (s, e) = value_span(bytes, 0)?;
    if skip_ws(bytes, e) != bytes.len() {
        return Err(JsonError::Invalid);
    }
    Ok(Value {
        bytes: &bytes[s..e],
    })
}

fn key_eq(raw_key: &[u8], wanted: &[u8]) -> bool {
    // Fast path for ASCII keys emitted by serde_json/TUF examples.
    raw_key == wanted
}

pub fn find_object_field<'a>(object: &'a [u8], name: &str) -> Result<Value<'a>> {
    let mut i = skip_ws(object, 0);
    if object.get(i) != Some(&b'{') {
        return Err(JsonError::WrongType);
    }
    i += 1;
    i = skip_ws(object, i);
    if object.get(i) == Some(&b'}') {
        return Err(JsonError::NotFound);
    }
    loop {
        let (ks, ke) = string_span(object, i)?;
        let raw_key = &object[ks + 1..ke - 1];
        i = skip_ws(object, ke);
        if object.get(i) != Some(&b':') {
            return Err(JsonError::Invalid);
        }
        i += 1;
        let (vs, ve) = value_span(object, i)?;
        if key_eq(raw_key, name.as_bytes()) {
            return Ok(Value {
                bytes: &object[vs..ve],
            });
        }
        i = skip_ws(object, ve);
        match object.get(i) {
            Some(b',') => {
                i += 1;
                i = skip_ws(object, i);
            }
            Some(b'}') => return Err(JsonError::NotFound),
            _ => return Err(JsonError::Invalid),
        }
    }
}

pub fn field<'a>(object: &'a [u8], name: &str) -> Result<&'a [u8]> {
    Ok(find_object_field(object, name)?.bytes)
}

pub fn as_str(bytes: &[u8]) -> Result<&str> {
    let i = skip_ws(bytes, 0);
    let (s, e) = string_span(bytes, i)?;
    if skip_ws(bytes, e) != bytes.len() {
        return Err(JsonError::Invalid);
    }
    // This intentionally supports the common no-escape metadata strings used in
    // STUF/TUF demo metadata. Escaped strings are still valid JSON, but callers
    // that need decoded strings should compare/copy via parser-specific helpers.
    let inner = &bytes[s + 1..e - 1];
    if inner.contains(&b'\\') {
        return Err(JsonError::WrongType);
    }
    core::str::from_utf8(inner).map_err(|_| JsonError::Invalid)
}

pub fn as_u64(bytes: &[u8]) -> Result<u64> {
    let i = skip_ws(bytes, 0);
    let (s, e) = number_span(bytes, i)?;
    if skip_ws(bytes, e) != bytes.len() {
        return Err(JsonError::Invalid);
    }
    let s = core::str::from_utf8(&bytes[s..e]).map_err(|_| JsonError::Invalid)?;
    let mut out = 0u64;
    for b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return Err(JsonError::WrongType);
        }
        out = out.checked_mul(10).ok_or(JsonError::Invalid)?;
        out = out
            .checked_add((b - b'0') as u64)
            .ok_or(JsonError::Invalid)?;
    }
    Ok(out)
}

pub fn as_bool(bytes: &[u8]) -> Result<bool> {
    match bytes {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(JsonError::WrongType),
    }
}

pub fn array_items<'a, const N: usize>(array: &'a [u8], out: &mut [&'a [u8]; N]) -> Result<usize> {
    let mut i = skip_ws(array, 0);
    if array.get(i) != Some(&b'[') {
        return Err(JsonError::WrongType);
    }
    i += 1;
    i = skip_ws(array, i);
    if array.get(i) == Some(&b']') {
        return Ok(0);
    }
    let mut len = 0;
    loop {
        if len >= N {
            return Err(JsonError::TooManyItems);
        }
        let (s, e) = value_span(array, i)?;
        out[len] = &array[s..e];
        len += 1;
        i = skip_ws(array, e);
        match array.get(i) {
            Some(b',') => {
                i += 1;
                i = skip_ws(array, i);
            }
            Some(b']') => return Ok(len),
            _ => return Err(JsonError::Invalid),
        }
    }
}

pub fn item_at<'a>(array: &'a [u8], index: usize) -> Result<&'a [u8]> {
    let mut tmp = [&[][..]; 16];
    let n = array_items(array, &mut tmp)?;
    if index >= n {
        return Err(JsonError::NotFound);
    }
    Ok(tmp[index])
}

#[derive(Clone, Copy, Debug)]
pub struct ObjectEntry<'a> {
    pub key: &'a str,
    pub raw_key: &'a [u8],
    pub value: &'a [u8],
}

pub fn object_entries<'a, const N: usize>(
    object: &'a [u8],
    out: &mut [ObjectEntry<'a>; N],
) -> Result<usize> {
    let mut i = skip_ws(object, 0);
    if object.get(i) != Some(&b'{') {
        return Err(JsonError::WrongType);
    }
    i += 1;
    i = skip_ws(object, i);
    if object.get(i) == Some(&b'}') {
        return Ok(0);
    }
    let mut len = 0usize;
    loop {
        if len >= N {
            return Err(JsonError::TooManyItems);
        }
        let (ks, ke) = string_span(object, i)?;
        let raw_key = &object[ks + 1..ke - 1];
        if raw_key.contains(&b'\\') {
            return Err(JsonError::WrongType);
        }
        let key = core::str::from_utf8(raw_key).map_err(|_| JsonError::Invalid)?;
        i = skip_ws(object, ke);
        if object.get(i) != Some(&b':') {
            return Err(JsonError::Invalid);
        }
        i += 1;
        let (vs, ve) = value_span(object, i)?;
        out[len] = ObjectEntry {
            key,
            raw_key,
            value: &object[vs..ve],
        };
        len += 1;
        i = skip_ws(object, ve);
        match object.get(i) {
            Some(b',') => {
                i += 1;
                i = skip_ws(object, i);
            }
            Some(b'}') => return Ok(len),
            _ => return Err(JsonError::Invalid),
        }
    }
}
