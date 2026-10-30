//! Poly1305 arithmetic and the RFC 8439 AEAD message layout.
//!
//! Limbs overlap at 26-bit boundaries. Loading disjoint 32-bit words and
//! masking them would discard authenticated bits of both the key and message.

const MASK: u64 = (1 << 26) - 1;

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from(u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte word"),
    ))
}

struct Poly1305 {
    r: [u64; 5],
    h: [u64; 5],
    pad: [u64; 4],
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            r: [
                word(key, 0) & 0x3ff_ffff,
                (word(key, 3) >> 2) & 0x3ff_ff03,
                (word(key, 6) >> 4) & 0x3ff_c0ff,
                (word(key, 9) >> 6) & 0x3f0_3fff,
                (word(key, 12) >> 8) & 0x00f_ffff,
            ],
            h: [0; 5],
            pad: [word(key, 16), word(key, 20), word(key, 24), word(key, 28)],
        }
    }

    fn block(&mut self, bytes: &[u8; 16], high_bit: u64) {
        let [r0, r1, r2, r3, r4] = self.r;
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        h0 += word(bytes, 0) & MASK;
        h1 += (word(bytes, 3) >> 2) & MASK;
        h2 += (word(bytes, 6) >> 4) & MASK;
        h3 += (word(bytes, 9) >> 6) & MASK;
        h4 += (word(bytes, 12) >> 8) | high_bit;

        let d0 = h0 * r0 + h1 * (5 * r4) + h2 * (5 * r3) + h3 * (5 * r2) + h4 * (5 * r1);
        let d1 = h0 * r1 + h1 * r0 + h2 * (5 * r4) + h3 * (5 * r3) + h4 * (5 * r2);
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r4) + h4 * (5 * r3);
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r4);
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        h0 = d0 & MASK;
        let d1 = d1 + (d0 >> 26);
        h1 = d1 & MASK;
        let d2 = d2 + (d1 >> 26);
        h2 = d2 & MASK;
        let d3 = d3 + (d2 >> 26);
        h3 = d3 & MASK;
        let d4 = d4 + (d3 >> 26);
        h4 = d4 & MASK;
        h0 += (d4 >> 26) * 5;
        h1 += h0 >> 26;
        h0 &= MASK;
        self.h = [h0, h1, h2, h3, h4];
    }

    // AEAD pads each segment to a whole block with zero bytes. Its Poly1305
    // high bit is at bit 128, including a partially filled final segment.
    fn padded_segment(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            self.block(chunk.try_into().expect("complete block"), 1 << 24);
        }
        let tail = chunks.remainder();
        if !tail.is_empty() {
            let mut block = [0u8; 16];
            block[..tail.len()].copy_from_slice(tail);
            self.block(&block, 1 << 24);
        }
    }

    fn finish(mut self) -> [u8; 16] {
        for i in 1..4 {
            self.h[i + 1] += self.h[i] >> 26;
            self.h[i] &= MASK;
        }
        self.h[0] += (self.h[4] >> 26) * 5;
        self.h[4] &= MASK;
        self.h[1] += self.h[0] >> 26;
        self.h[0] &= MASK;

        // Select h - (2^130 - 5) exactly when h >= that modulus, without
        // branching on secret state. Underflow leaves bit 63 set in g[4].
        let mut g = [0u64; 5];
        let mut carry = 5;
        for (i, limb) in g.iter_mut().enumerate().take(4) {
            let value = self.h[i] + carry;
            *limb = value & MASK;
            carry = value >> 26;
        }
        g[4] = (self.h[4] + carry).wrapping_sub(1 << 26);
        let select_g = (g[4] >> 63).wrapping_sub(1);
        for (h, reduced) in self.h.iter_mut().zip(g) {
            *h = (*h & !select_g) | (reduced & select_g);
        }

        let [h0, h1, h2, h3, h4] = self.h;
        let words = [
            h0 | (h1 << 26),
            (h1 >> 6) | (h2 << 20),
            (h2 >> 12) | (h3 << 14),
            (h3 >> 18) | (h4 << 8),
        ];
        let mut tag = [0u8; 16];
        carry = 0;
        for (i, value) in words.into_iter().enumerate() {
            let sum = (value & 0xffff_ffff) + self.pad[i] + carry;
            tag[i * 4..i * 4 + 4].copy_from_slice(&(sum as u32).to_le_bytes());
            carry = sum >> 32;
        }
        tag
    }
}

pub(crate) fn authenticate_aead(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut state = Poly1305::new(key);
    state.padded_segment(aad);
    state.padded_segment(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    state.block(&lengths, 1 << 24);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_poly1305_vector() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let mut state = Poly1305::new(&key);
        for chunk in b"Cryptographic Forum Research Group".chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let high_bit = if chunk.len() == 16 {
                1 << 24
            } else {
                block[chunk.len()] = 1;
                0
            };
            state.block(&block, high_bit);
        }
        assert_eq!(
            crate::hex_lower(&state.finish()),
            "a8061dc1305136c6c22b8baf0c0127a9"
        );
    }
}
