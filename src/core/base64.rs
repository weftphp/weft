//! Standard base64 (RFC 4648 §4): `A–Z a–z 0–9 + /` alphabet with `=` padding.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';
const INVALID: u8 = 0xff;

/// Maps an input byte to its 6-bit value, or [`INVALID`].
const DECODE: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Length of the encoding of `len` bytes.
pub const fn encoded_len(len: usize) -> usize {
    len.div_ceil(3) * 4
}

/// Encodes `input` with padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(encoded_len(input.len()));
    for group in input.chunks(3) {
        let n = u32::from(group[0]) << 16
            | u32::from(*group.get(1).unwrap_or(&0)) << 8
            | u32::from(*group.get(2).unwrap_or(&0));
        for i in 0..4 {
            // A group of k bytes yields k + 1 significant characters.
            if i <= group.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize]);
            } else {
                out.push(PAD);
            }
        }
    }
    // Only ASCII from `ALPHABET` and `PAD` was pushed.
    out.into_iter().map(char::from).collect()
}

/// Decodes padded base64. Returns `None` unless the input length is a multiple of four,
/// every character is in the alphabet, and `=` appears only as one or two trailing pads.
pub fn decode(input: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let input = input.as_ref();
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let groups = input.len() / 4;
    for (index, group) in input.as_chunks::<4>().0.iter().enumerate() {
        let pads = group.iter().rev().take_while(|&&c| c == PAD).count();
        if pads > 2 || (pads > 0 && index + 1 != groups) {
            return None;
        }
        let mut n = 0u32;
        for &c in &group[..4 - pads] {
            let value = DECODE[c as usize];
            if value == INVALID {
                return None;
            }
            n = n << 6 | u32::from(value);
        }
        n <<= 6 * pads as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pads]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors, plus high bytes.
    const VECTORS: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
        (b"\xff\xfe\xfd", "//79"),
    ];

    #[test]
    fn rfc_vectors_roundtrip() {
        for (plain, encoded) in VECTORS {
            assert_eq!(encode(plain), *encoded);
            assert_eq!(decode(encoded).as_deref(), Some(*plain));
        }
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(decode("Zm9vYg"), None, "missing padding");
        assert_eq!(decode("Zm9v!A=="), None, "bad character");
        assert_eq!(decode("Zg==Zm9v"), None, "padding in the middle");
        assert_eq!(decode("Z==="), None, "too much padding");
    }
}
