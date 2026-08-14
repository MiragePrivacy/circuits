//! RLP encoding and a minimal decoder, native.
//!
//! This is the reference the circuit's `rlp::cursor` decoder is checked
//! against. Keeping it in Rust next to the circuit rather than in a separate
//! script means the fixture generator and the gadget cannot drift apart.

/// An RLP item: either a byte string or a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Str(Vec<u8>),
    List(Vec<Item>),
}

impl Item {
    pub fn str(b: impl Into<Vec<u8>>) -> Self {
        Item::Str(b.into())
    }

    pub fn empty() -> Self {
        Item::Str(Vec::new())
    }

    /// A canonical RLP integer: minimal big-endian, empty for zero.
    pub fn int(v: u64) -> Self {
        if v == 0 {
            return Item::empty();
        }
        let be = v.to_be_bytes();
        let first = be.iter().position(|&x| x != 0).unwrap();
        Item::Str(be[first..].to_vec())
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Item::Str(b) => {
                if b.len() == 1 && b[0] < 0x80 {
                    return b.clone();
                }
                let mut out = prefix(b.len(), 0x80);
                out.extend_from_slice(b);
                out
            }
            Item::List(items) => {
                let body: Vec<u8> = items.iter().flat_map(|i| i.encode()).collect();
                let mut out = prefix(body.len(), 0xc0);
                out.extend_from_slice(&body);
                out
            }
        }
    }
}

fn prefix(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        return vec![offset + len as u8];
    }
    let be = len.to_be_bytes();
    let first = be.iter().position(|&x| x != 0).unwrap();
    let lb = &be[first..];
    let mut out = vec![offset + 55 + lb.len() as u8];
    out.extend_from_slice(lb);
    out
}

/// Decodes one item, returning it and the remaining bytes.
///
/// Deliberately permissive about canonical form: its job is to walk trie nodes
/// the chain produced, not to validate them. The circuit's decoder is the one
/// that must reject non-canonical encodings.
pub fn decode(b: &[u8]) -> Result<(Item, &[u8]), String> {
    let p = *b.first().ok_or("empty input")?;

    if p < 0x80 {
        return Ok((Item::Str(vec![p]), &b[1..]));
    }
    if p < 0xb8 {
        let n = (p - 0x80) as usize;
        need(b, 1 + n)?;
        return Ok((Item::Str(b[1..1 + n].to_vec()), &b[1 + n..]));
    }
    if p < 0xc0 {
        let ln = (p - 0xb7) as usize;
        need(b, 1 + ln)?;
        let n = be_usize(&b[1..1 + ln]);
        need(b, 1 + ln + n)?;
        return Ok((Item::Str(b[1 + ln..1 + ln + n].to_vec()), &b[1 + ln + n..]));
    }

    let (mut body, rest) = if p < 0xf8 {
        let n = (p - 0xc0) as usize;
        need(b, 1 + n)?;
        (&b[1..1 + n], &b[1 + n..])
    } else {
        let ln = (p - 0xf7) as usize;
        need(b, 1 + ln)?;
        let n = be_usize(&b[1..1 + ln]);
        need(b, 1 + ln + n)?;
        (&b[1 + ln..1 + ln + n], &b[1 + ln + n..])
    };

    let mut items = Vec::new();
    while !body.is_empty() {
        let (item, next) = decode(body)?;
        items.push(item);
        body = next;
    }
    Ok((Item::List(items), rest))
}

/// Decodes exactly one item, rejecting trailing bytes.
pub fn decode_all(b: &[u8]) -> Result<Item, String> {
    let (item, rest) = decode(b)?;
    if !rest.is_empty() {
        return Err(format!("{} trailing bytes", rest.len()));
    }
    Ok(item)
}

fn need(b: &[u8], n: usize) -> Result<(), String> {
    if b.len() < n {
        return Err(format!("truncated: need {n}, have {}", b.len()));
    }
    Ok(())
}

fn be_usize(b: &[u8]) -> usize {
    b.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_canonical_forms() {
        assert_eq!(Item::str(vec![0x7f]).encode(), vec![0x7f], "bare byte");
        assert_eq!(Item::empty().encode(), vec![0x80], "empty string");
        assert_eq!(Item::str(vec![0xaa; 5]).encode()[0], 0x85, "short string");
        assert_eq!(Item::str(vec![0xbb; 100]).encode()[0], 0xb8, "long string");
        assert_eq!(Item::List(vec![]).encode(), vec![0xc0], "empty list");
    }

    #[test]
    fn integers_are_canonical() {
        assert_eq!(Item::int(0).encode(), vec![0x80], "zero is empty");
        assert_eq!(Item::int(1).encode(), vec![0x01], "one is bare");
        assert_eq!(Item::int(255).encode(), vec![0x81, 0xff]);
        assert_eq!(Item::int(256).encode(), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn round_trips() {
        let cases = vec![
            Item::str(vec![0x7f]),
            Item::empty(),
            Item::str(vec![0xaa; 5]),
            Item::str(vec![0xbb; 300]),
            Item::List(vec![Item::int(1), Item::str(vec![0x52, 0x08])]),
            Item::List(vec![Item::List(vec![Item::empty()]), Item::int(21_000_000)]),
        ];
        for c in cases {
            let enc = c.encode();
            assert_eq!(decode_all(&enc).unwrap(), c, "round trip {c:?}");
        }
    }

    #[test]
    fn a_256_byte_bloom_uses_two_length_bytes() {
        // The header and receipt both carry one, so getting this wrong shifts
        // every following field.
        let enc = Item::str(vec![0u8; 256]).encode();
        assert_eq!(&enc[..3], &[0xb9, 0x01, 0x00]);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut enc = Item::int(1).encode();
        enc.push(0xff);
        assert!(decode_all(&enc).is_err());
    }
}
