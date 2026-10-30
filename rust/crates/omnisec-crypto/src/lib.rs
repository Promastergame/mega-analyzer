//! Zero-dependency crypto primitives (replaces `sha2`, `md-5`, `chacha20poly1305`).
//!
//! - [`sha256`] / [`Sha256`] (FIPS 180-4).
//! - [`md5`] / [`Md5`] (RFC 1321).
//! - [`chacha20poly1305::{seal, open}`] (RFC 8439).
//! - [`rand`] tiny PRNG (replaces `rand` crate for non-security uses).
//! - [`b64_encode`] / [`b64_decode`], [`hex_lower`] / [`hex_decode`].
//! - [`ed25519`] / [`sha512`] (RFC 8032 / FIPS 180-4) — see `ed25519.rs`.

pub mod ed25519;
mod poly1305;
mod random;
pub use random::{entropy_seed, fill_os_random};

/// SHA-256 of bytes (FIPS 180-4).
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize()
}

/// Incremental SHA-256 (API shaped like the `sha2` crate).
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// New hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.total_len += bytes.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(bytes.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&bytes[..take]);
            self.buf_len += take;
            bytes = &bytes[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            Self::compress(&mut self.state, &block);
            bytes = &bytes[64..];
        }
        if !bytes.is_empty() {
            self.buf[..bytes.len()].copy_from_slice(bytes);
            self.buf_len = bytes.len();
        }
    }

    /// Finalize and return digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        // Zero-pad until exactly 56 bytes are buffered (room for the 8-byte
        // length). `update` compresses automatically at 64 and resets the
        // buffer, so this terminates even across a block boundary.
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 32];
        for (i, s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }

    /// One-shot digest (sha2-shaped).
    #[must_use]
    pub fn digest(bytes: &[u8]) -> [u8; 32] {
        sha256(bytes)
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(hh);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Digest trait shim so `use sha2::Digest` call-sites migrate easily.
pub trait Digest {
    /// Feed bytes.
    fn update(&mut self, bytes: &[u8]);
    /// Finish.
    fn finalize(self) -> [u8; 32];
}

/// MD5 of bytes (RFC 1321).
#[must_use]
pub fn md5(bytes: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(bytes);
    h.finalize()
}

/// Incremental MD5 (API shaped like the `md-5` crate).
#[derive(Debug, Clone)]
pub struct Md5 {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Md5 {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const T: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    /// New hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buf: [0; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.total_len += bytes.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(bytes.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&bytes[..take]);
            self.buf_len += take;
            bytes = &bytes[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            Self::compress(&mut self.state, &block);
            bytes = &bytes[64..];
        }
        if !bytes.is_empty() {
            self.buf[..bytes.len()].copy_from_slice(bytes);
            self.buf_len = bytes.len();
        }
    }

    /// Finalize.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            if self.buf_len > 56 {
                while self.buf_len != 64 {
                    self.update(&[0]);
                }
                break;
            }
            self.update(&[0]);
        }
        self.update(&bit_len.to_le_bytes());
        let mut out = [0u8; 16];
        for (i, s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
        }
        out
    }

    /// One-shot digest (md-5-shaped).
    #[must_use]
    pub fn digest(bytes: &[u8]) -> [u8; 16] {
        md5(bytes)
    }

    fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(Self::T[i])
                    .wrapping_add(m[g])
                    .rotate_left(Self::S[i]),
            );
            a = tmp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

/// ChaCha20-Poly1305 AEAD (RFC 8439).
pub mod chacha20poly1305 {
    /// 32-byte key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Key(pub [u8; 32]);
    /// 12-byte nonce.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Nonce(pub [u8; 12]);

    impl Key {
        /// Build from slice.
        pub fn from_slice(b: &[u8]) -> Result<Self, &'static str> {
            if b.len() != 32 {
                return Err("bad key length");
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(b);
            Ok(Self(k))
        }
    }
    impl Nonce {
        /// Build from slice.
        pub fn from_slice(b: &[u8]) -> Result<Self, &'static str> {
            if b.len() != 12 {
                return Err("bad nonce length");
            }
            let mut n = [0u8; 12];
            n.copy_from_slice(b);
            Ok(Self(n))
        }
    }

    fn quarter(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
        *a = a.wrapping_add(*b);
        *d ^= *a;
        *d = d.rotate_left(16);
        *c = c.wrapping_add(*d);
        *b ^= *c;
        *b = b.rotate_left(12);
        *a = a.wrapping_add(*b);
        *d ^= *a;
        *d = d.rotate_left(8);
        *c = c.wrapping_add(*d);
        *b ^= *c;
        *b = b.rotate_left(7);
    }

    fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
        let mut s = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, key[0], key[1], key[2], key[3], key[4],
            key[5], key[6], key[7], counter, nonce[0], nonce[1], nonce[2],
        ];
        let orig = s;
        for _ in 0..10 {
            for &(a, b, c, d) in &[
                (0usize, 4usize, 8usize, 12usize),
                (1, 5, 9, 13),
                (2, 6, 10, 14),
                (3, 7, 11, 15),
                (0, 5, 10, 15),
                (1, 6, 11, 12),
                (2, 7, 8, 13),
                (3, 4, 9, 14),
            ] {
                let (mut va, mut vb, mut vc, mut vd) = (s[a], s[b], s[c], s[d]);
                quarter(&mut va, &mut vb, &mut vc, &mut vd);
                s[a] = va;
                s[b] = vb;
                s[c] = vc;
                s[d] = vd;
            }
        }
        for i in 0..16 {
            s[i] = s[i].wrapping_add(orig[i]);
        }
        s
    }

    fn key_words(key: &Key) -> [u32; 8] {
        let mut w = [0u32; 8];
        for (i, chunk) in key.0.chunks_exact(4).enumerate() {
            w[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        w
    }

    fn nonce_words(nonce: &Nonce) -> [u32; 3] {
        [
            u32::from_le_bytes([nonce.0[0], nonce.0[1], nonce.0[2], nonce.0[3]]),
            u32::from_le_bytes([nonce.0[4], nonce.0[5], nonce.0[6], nonce.0[7]]),
            u32::from_le_bytes([nonce.0[8], nonce.0[9], nonce.0[10], nonce.0[11]]),
        ]
    }

    fn chacha_xor(key: &Key, nonce: &Nonce, counter: u32, data: &[u8]) -> Vec<u8> {
        let kw = key_words(key);
        let nw = nonce_words(nonce);
        let mut out = Vec::with_capacity(data.len());
        let mut ctr = counter;
        for chunk in data.chunks(64) {
            let ks = block(&kw, ctr, &nw);
            let mut ks_bytes = [0u8; 64];
            for (i, w) in ks.iter().enumerate() {
                ks_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            for (i, b) in chunk.iter().enumerate() {
                out.push(b ^ ks_bytes[i]);
            }
            ctr = ctr.wrapping_add(1);
        }
        out
    }

    fn poly1305_mac(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        crate::poly1305::authenticate_aead(otk, aad, ct)
    }

    /// AEAD seal: returns ciphertext ++ 16-byte tag.
    #[must_use]
    pub fn seal(key: &Key, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let kw = key_words(key);
        let nw = nonce_words(nonce);
        let ks0 = block(&kw, 0, &nw);
        let mut otk = [0u8; 32];
        for (i, w) in ks0.iter().take(8).enumerate() {
            otk[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let mut otk32 = [0u8; 32];
        otk32.copy_from_slice(&otk[..32]);
        let ct = chacha_xor(key, nonce, 1, plaintext);
        let tag = poly1305_mac(&otk32, aad, &ct);
        let mut out = ct;
        out.extend_from_slice(&tag);
        out
    }

    /// AEAD open: verifies tag (constant-time) and returns plaintext.
    #[must_use]
    pub fn open(key: &Key, nonce: &Nonce, aad: &[u8], ct_and_tag: &[u8]) -> Option<Vec<u8>> {
        if ct_and_tag.len() < 16 {
            return None;
        }
        let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
        let kw = key_words(key);
        let nw = nonce_words(nonce);
        let ks0 = block(&kw, 0, &nw);
        let mut otk32 = [0u8; 32];
        for (i, w) in ks0.iter().take(8).enumerate() {
            otk32[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let expect = poly1305_mac(&otk32, aad, ct);
        let mut diff = 0u8;
        for (a, b) in expect.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return None;
        }
        Some(chacha_xor(key, nonce, 1, ct))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rfc8439_aead_vector() {
            let key = Key([
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
                0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                0x9c, 0x9d, 0x9e, 0x9f,
            ]);
            let nonce = Nonce([
                0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            ]);
            let aad = [
                0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
            ];
            let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            let ct = seal(&key, &nonce, &aad, pt);
            assert_eq!(
                crate::hex_lower(&ct),
                concat!(
                    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63",
                    "dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692",
                    "ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4",
                    "def08e4b7a9de576d26586cec64b6116",
                    "1ae10b594f09e26a7e902ecbd0600691",
                )
            );
            let back = open(&key, &nonce, &aad, &ct).unwrap();
            assert_eq!(back, pt);
            let mut bad = ct.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(open(&key, &nonce, &aad, &bad).is_none());
        }

        #[test]
        fn authenticates_every_aad_bit_and_segment_length() {
            let key = Key([42; 32]);
            for length in [0, 1, 15, 16, 17, 31, 32, 33] {
                let nonce = Nonce([length as u8; 12]);
                let aad = vec![0x5a; length];
                let plaintext = vec![0xa5; length];
                let ciphertext = seal(&key, &nonce, &aad, &plaintext);
                assert_eq!(open(&key, &nonce, &aad, &ciphertext), Some(plaintext));
                for byte in 0..aad.len() {
                    for bit in 0..8 {
                        let mut changed = aad.clone();
                        changed[byte] ^= 1 << bit;
                        assert!(open(&key, &nonce, &changed, &ciphertext).is_none());
                    }
                }
                let mut extended = aad;
                extended.push(0);
                assert!(open(&key, &nonce, &extended, &ciphertext).is_none());
                for truncated in 0..ciphertext.len() {
                    assert!(open(&key, &nonce, &extended[..length], &ciphertext[..truncated]).is_none());
                }
            }
        }
    }
}

/// Tiny deterministic PRNG (xorshift64*; replaces `rand` for non-security uses
/// such as shuffling test fixtures). It must never seed keys, nonces, or any
/// other cryptographic material: use [`fill_os_random`][crate::fill_os_random]
/// for that. There is deliberately no time-based seeding constructor.
pub mod rand {
    /// Deterministic PRNG.
    #[derive(Debug, Clone)]
    pub struct Rng(u64);

    impl Rng {
        /// Seed explicitly.
        #[must_use]
        pub const fn new(seed: u64) -> Self {
            Self(if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            })
        }

        /// Next u64.
        pub fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        /// Next u32.
        pub fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }

        /// Next usize below `n`.
        pub fn gen_below(&mut self, n: usize) -> usize {
            assert!(n > 0);
            (self.next_u64() % (n as u64)) as usize
        }

        /// Fill bytes.
        pub fn fill_bytes(&mut self, out: &mut [u8]) {
            for chunk in out.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
    }
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 encode.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_TABLE[((n >> 18) & 63) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Lowercase hex.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Hex of SHA-256.
#[must_use]
pub fn hex_sha256(bytes: &[u8]) -> String {
    hex_lower(&sha256(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex_lower(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_lower(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn streaming_sha256_matches_one_shot_across_block_boundaries() {
        // Lengths around the 56/64-byte padding and block boundaries exercise
        // every `finalize` path (including the one that previously hung).
        for len in [0usize, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 121, 200] {
            let input = vec![b'a'; len];
            let mut h = Sha256::new();
            h.update(&input);
            assert_eq!(
                h.finalize(),
                sha256(&input),
                "streaming mismatch at len {len}"
            );
        }
    }

    #[test]
    fn md5_vectors() {
        assert_eq!(hex_lower(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex_lower(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex_lower(&md5(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn sha256_incremental_matches() {
        let mut h = Sha256::new();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(hex_lower(&h.finalize()), hex_lower(&sha256(b"abc")));
    }
}
