//! Canonical JSON and base64 for checkpoint manifests.
//!
//! The encoding matches kilnd's canonical JSON contract: no whitespace, object
//! keys sorted by their bytes, integers only, strings with the short escapes
//! (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`), printable ASCII as itself and
//! every other character as lowercase `\uXXXX` UTF-16 units. kiln has no JSON
//! dependency, so this is a small bounded encoder and a strict parser. The
//! parser accepts exactly the canonical form: [`parse`] re-encodes what it read
//! and refuses any input whose bytes differ, so one value has one encoding.
//!
//! Base64 is RFC 4648 section 4 (standard alphabet, `=` padding), and decoding
//! is likewise canonical.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};

/// Deepest nesting the parser accepts. Manifests use four levels.
pub const MAX_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Every integer the format uses fits in i128 (u64 and i64 both do).
    Int(i128),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj<const N: usize>(fields: [(&str, Json); N]) -> Self {
        Json::Obj(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }
    pub fn str(s: impl Into<String>) -> Self { Json::Str(s.into()) }
    pub fn int(n: impl Into<i128>) -> Self { Json::Int(n.into()) }
    pub fn b64(bytes: &[u8]) -> Self { Json::Str(base64(bytes)) }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Json::Null => out.extend_from_slice(b"null"),
            Json::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Json::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Json::Str(s) => string(out, s),
            Json::Arr(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 { out.push(b','); }
                    item.encode_into(out);
                }
                out.push(b']');
            }
            Json::Obj(items) => {
                // BTreeMap<String> iterates in byte order of the keys.
                out.push(b'{');
                for (i, (key, value)) in items.iter().enumerate() {
                    if i != 0 { out.push(b','); }
                    string(out, key);
                    out.push(b':');
                    value.encode_into(out);
                }
                out.push(b'}');
            }
        }
    }
}

fn string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            ' '..='~' => out.push(c as u8),
            _ => for unit in c.encode_utf16(&mut [0; 2]) {
                out.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
            },
        }
    }
    out.push(b'"');
}

/// Parses one canonical JSON document. Anything that does not re-encode to the
/// same bytes (whitespace, unsorted or duplicate keys, floats, exponents,
/// leading zeros, `-0`, non-canonical escapes, trailing data) is refused.
pub fn parse(bytes: &[u8]) -> Result<Json> {
    let mut p = Parser { bytes, at: 0 };
    let value = p.value(0)?;
    ensure!(p.at == bytes.len(), "trailing data after JSON value");
    ensure!(value.encode() == bytes, "JSON is not in canonical form");
    Ok(value)
}

struct Parser<'a> { bytes: &'a [u8], at: usize }

impl Parser<'_> {
    fn peek(&self) -> Option<u8> { self.bytes.get(self.at).copied() }

    fn expect(&mut self, b: u8) -> Result<()> {
        ensure!(self.peek() == Some(b), "malformed JSON at byte {}", self.at);
        self.at += 1;
        Ok(())
    }

    fn literal(&mut self, word: &[u8]) -> Result<()> {
        ensure!(self.bytes[self.at..].starts_with(word), "malformed JSON literal at byte {}", self.at);
        self.at += word.len();
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        ensure!(depth <= MAX_DEPTH, "JSON nested deeper than {MAX_DEPTH}");
        match self.peek() {
            Some(b'n') => { self.literal(b"null")?; Ok(Json::Null) }
            Some(b't') => { self.literal(b"true")?; Ok(Json::Bool(true)) }
            Some(b'f') => { self.literal(b"false")?; Ok(Json::Bool(false)) }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                if self.peek() == Some(b']') { self.at += 1; return Ok(Json::Arr(items)); }
                loop {
                    items.push(self.value(depth + 1)?);
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => { self.at += 1; return Ok(Json::Arr(items)); }
                        _ => bail!("malformed JSON array at byte {}", self.at),
                    }
                }
            }
            Some(b'{') => {
                self.at += 1;
                let mut items = BTreeMap::new();
                if self.peek() == Some(b'}') { self.at += 1; return Ok(Json::Obj(items)); }
                loop {
                    let key = self.string()?;
                    self.expect(b':')?;
                    let value = self.value(depth + 1)?;
                    ensure!(items.insert(key, value).is_none(), "duplicate JSON key");
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => { self.at += 1; return Ok(Json::Obj(items)); }
                        _ => bail!("malformed JSON object at byte {}", self.at),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.at;
                if self.peek() == Some(b'-') { self.at += 1; }
                let digits = self.at;
                while self.peek().is_some_and(|b| b.is_ascii_digit()) { self.at += 1; }
                ensure!(self.at > digits && self.at - digits <= 39, "malformed JSON number at byte {start}");
                ensure!(!matches!(self.peek(), Some(b'.' | b'e' | b'E')), "JSON numbers must be integers");
                let text = std::str::from_utf8(&self.bytes[start..self.at])?;
                Ok(Json::Int(text.parse().map_err(|_| anyhow::anyhow!("JSON integer out of range"))?))
            }
            _ => bail!("malformed JSON value at byte {}", self.at),
        }
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(b) = self.peek() else { bail!("unterminated JSON string") };
            self.at += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(e) = self.peek() else { bail!("unterminated JSON escape") };
                    self.at += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let c = if (0xd800..0xdc00).contains(&first) {
                                self.literal(b"\\u")?;
                                let second = self.hex4()?;
                                ensure!((0xdc00..0xe000).contains(&second), "unpaired JSON surrogate");
                                char::from_u32(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00))
                            } else { char::from_u32(first) };
                            out.push(c.ok_or_else(|| anyhow::anyhow!("invalid JSON escape"))?);
                        }
                        _ => bail!("invalid JSON escape"),
                    }
                }
                // Raw bytes: printable ASCII only (anything else is escaped
                // in the canonical form).
                b' '..=b'~' => out.push(b as char),
                _ => bail!("unescaped control or non-ASCII byte in JSON string"),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self.bytes.get(self.at..self.at + 4).ok_or_else(|| anyhow::anyhow!("truncated JSON escape"))?;
        ensure!(digits.iter().all(|d| d.is_ascii_digit() || (b'a'..=b'f').contains(d)), "invalid JSON escape");
        self.at += 4;
        Ok(u32::from_str_radix(std::str::from_utf8(digits)?, 16)?)
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

/// Strict decoding: the standard alphabet with padding, length a multiple of
/// four, and canonical (unused low bits zero), so a value has one encoding.
pub fn unbase64(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    ensure!(bytes.len().is_multiple_of(4), "base64 length is not a multiple of four");
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, quad) in bytes.chunks(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let pad = quad.iter().rev().take_while(|b| **b == b'=').count();
        ensure!(pad <= 2 && (pad == 0 || last), "misplaced base64 padding");
        let mut n = 0u32;
        for (i, b) in quad[..4 - pad].iter().enumerate() {
            let v = ALPHABET.iter().position(|a| a == b).ok_or_else(|| anyhow::anyhow!("invalid base64 byte"))?;
            n |= (v as u32) << (18 - 6 * i);
        }
        let keep = 3 - pad;
        for i in 0..keep { out.push((n >> (16 - 8 * i)) as u8); }
    }
    ensure!(base64(&out) == text, "non-canonical base64");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_matches_the_contract() {
        let v = Json::obj([("b", Json::int(-1)), ("a", Json::Arr(vec![Json::Null, Json::Bool(true),
            Json::str("q\"\\\u{8}\u{c}\n\r\t\u{1}é😀~")])), ("", Json::obj([]))]);
        assert_eq!(String::from_utf8(v.encode()).unwrap(),
            r#"{"":{},"a":[null,true,"q\"\\\b\f\n\r\t\u0001\u00e9\ud83d\ude00~"],"b":-1}"#);
        assert_eq!(parse(&v.encode()).unwrap(), v);
        assert_eq!(Json::int(u64::MAX).encode(), b"18446744073709551615");
    }

    #[test]
    fn parser_accepts_only_canonical_bytes() {
        for bad in [&b"{ }"[..], b"{\"b\":1,\"a\":2}", b"{\"a\":1,\"a\":1}", b"1.0", b"1e3", b"01", b"-0",
            b"\"\\u00E9\"", b"\"\\/\"", b"\"\xc3\xa9\"", b"[1,]", b"[1] ", b"\"a", b"tru", b"\"\\ud83d\"",
            b"\"\\u0041\"", b"", b"[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]"] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert_eq!(parse(b"[0,-5,\"\\u001f\"]").unwrap(),
            Json::Arr(vec![Json::int(0), Json::int(-5), Json::str("\u{1f}")]));
    }

    #[test]
    fn base64_is_rfc4648_and_strict() {
        for (raw, text) in [(&b""[..], ""), (b"f", "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v"), (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="), (b"foobar", "Zm9vYmFy"), (b"\xff\xfe\x00", "//4A")] {
            assert_eq!(base64(raw), text);
            assert_eq!(unbase64(text).unwrap(), raw);
        }
        for bad in ["Zg", "Zg=", "Zh==", "Z===", "Zg==Zg==", "Zm9v\n", "Zm-v", "Zm_v", "===="] {
            assert!(unbase64(bad).is_err(), "{bad}");
        }
    }
}
