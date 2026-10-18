//! SHA-1 (FIPS 180-4).
//!
//! SHA-1 is broken for collision resistance; weft uses it only where a protocol mandates it,
//! such as the WebSocket opening handshake (RFC 6455).

/// Digest length in bytes.
pub const DIGEST_LEN: usize = 20;

const BLOCK_LEN: usize = 64;

/// Incremental SHA-1 hasher.
#[derive(Debug, Clone)]
pub struct Sha1 {
    state: [u32; 5],
    block: [u8; BLOCK_LEN],
    filled: usize,
    /// Total message length in bytes.
    length: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1 {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            block: [0; BLOCK_LEN],
            filled: 0,
            length: 0,
        }
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (BLOCK_LEN - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < BLOCK_LEN {
                return;
            }
            let block = self.block;
            self.compress(&block);
            self.filled = 0;
        }
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            self.compress(block);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    pub fn finish(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.length.wrapping_mul(8);
        // Padding: a single 1 bit, zeros, then the 64-bit length, ending on a block boundary.
        let mut tail = [0u8; 2 * BLOCK_LEN];
        tail[0] = 0x80;
        let pad = if self.filled < BLOCK_LEN - 8 {
            BLOCK_LEN - self.filled
        } else {
            2 * BLOCK_LEN - self.filled
        };
        tail[pad - 8..pad].copy_from_slice(&bits.to_be_bytes());
        let length = self.length;
        self.update(&tail[..pad]);
        self.length = length;

        let mut out = [0u8; DIGEST_LEN];
        for (chunk, word) in out.chunks_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5A82_7999),
                1 => (b ^ c ^ d, 0x6ED9_EBA1),
                2 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// SHA-1 of `data` in one call.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // FIPS 180 example messages.
    #[test]
    fn standard_vectors() {
        assert_eq!(
            hex(&digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn million_a_in_odd_pieces() {
        let mut hasher = Sha1::new();
        let piece = [b'a'; 997];
        let mut left = 1_000_000;
        while left > 0 {
            let n = left.min(piece.len());
            hasher.update(&piece[..n]);
            left -= n;
        }
        assert_eq!(
            hex(&hasher.finish()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }
}
