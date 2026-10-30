//! Pure-Rust SHA-512 (FIPS 180-4) and Ed25519 (RFC 8032) — replaces the
//! `ring`/`rcgen` signing stack for the MITM root-CA generator.
//!
//! Implemented from the specifications alone; validated against the RFC 8032
//! test vectors and FIPS 180-4 SHA-512 digests in the tests below.

/// Pure-Rust SHA-512.
pub mod sha512 {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    /// Streaming SHA-512 hasher.
    #[derive(Debug, Clone)]
    pub struct Sha512 {
        state: [u64; 8],
        buf: [u8; 128],
        buf_len: usize,
        total_len: u128,
    }

    impl Default for Sha512 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Sha512 {
        /// New hasher.
        #[must_use]
        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667f3bcc908,
                    0xbb67ae8584caa73b,
                    0x3c6ef372fe94f82b,
                    0xa54ff53a5f1d36f1,
                    0x510e527fade682d1,
                    0x9b05688c2b3e6c1f,
                    0x1f83d9abfb41bd6b,
                    0x5be0cd19137e2179,
                ],
                buf: [0; 128],
                buf_len: 0,
                total_len: 0,
            }
        }

        /// Feed bytes.
        pub fn update(&mut self, mut bytes: &[u8]) {
            self.total_len += bytes.len() as u128;
            if self.buf_len > 0 {
                let take = (128 - self.buf_len).min(bytes.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&bytes[..take]);
                self.buf_len += take;
                bytes = &bytes[take..];
                if self.buf_len == 128 {
                    let block = self.buf;
                    Self::compress(&mut self.state, &block);
                    self.buf_len = 0;
                }
            }
            while bytes.len() >= 128 {
                let mut block = [0u8; 128];
                block.copy_from_slice(&bytes[..128]);
                Self::compress(&mut self.state, &block);
                bytes = &bytes[128..];
            }
            if !bytes.is_empty() {
                self.buf[..bytes.len()].copy_from_slice(bytes);
                self.buf_len = bytes.len();
            }
        }

        /// Finalize and return the 64-byte digest.
        #[must_use]
        pub fn finalize(mut self) -> [u8; 64] {
            let bit_len = self.total_len.wrapping_mul(8);
            self.update(&[0x80]);
            // Zero-pad until exactly 112 bytes are buffered (room for the
            // 16-byte length). `update` compresses automatically at 128.
            while self.buf_len != 112 {
                self.update(&[0]);
            }
            self.update(&bit_len.to_be_bytes());
            debug_assert_eq!(self.buf_len, 0);
            let mut out = [0u8; 64];
            for (i, s) in self.state.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&s.to_be_bytes());
            }
            out
        }

        fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
            let mut w = [0u64; 80];
            for i in 0..16 {
                w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ (!e & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                h = g;
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
            state[7] = state[7].wrapping_add(h);
        }
    }

    /// One-shot SHA-512.
    #[must_use]
    pub fn sha512(bytes: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(bytes);
        h.finalize()
    }
}

/// Pure-Rust Ed25519 signatures (RFC 8032).
///
/// Field arithmetic mod p = 2^255-19 uses 5×51-bit limbs; points use extended
/// twisted-Edwards coordinates with the complete (unified) addition formulas
/// for a = -1, so the same `add` routine handles doubling as well.
pub mod ed25519 {
    use super::sha512::sha512;

    const M51: u64 = (1 << 51) - 1;

    /// Field element mod p = 2^255-19, 5×51-bit limbs.
    #[derive(Clone, Copy, Debug)]
    struct Fe([u64; 5]);

    const P_LIMBS: Fe = Fe([
        0x7FFFFFFFFFFED,
        0x7FFFFFFFFFFFF,
        0x7FFFFFFFFFFFF,
        0x7FFFFFFFFFFFF,
        0x7FFFFFFFFFFFF,
    ]);

    fn fe_zero() -> Fe {
        Fe([0; 5])
    }
    fn fe_one() -> Fe {
        Fe([1, 0, 0, 0, 0])
    }
    fn fe_from_u64(v: u64) -> Fe {
        Fe([v & M51, v >> 51, 0, 0, 0])
    }

    /// Propagate carries and fold the top limb back with 2^255 ≡ 19.
    fn fe_carry(mut v: [u64; 5]) -> Fe {
        for _ in 0..2 {
            let carry = v[4] >> 51;
            v[4] &= M51;
            v[0] += 19 * carry;
            for i in 0..4 {
                v[i + 1] += v[i] >> 51;
                v[i] &= M51;
            }
        }
        Fe(v)
    }

    fn fe_add(a: &Fe, b: &Fe) -> Fe {
        let mut v = [0u64; 5];
        for i in 0..5 {
            v[i] = a.0[i] + b.0[i];
        }
        fe_carry(v)
    }

    fn fe_sub(a: &Fe, b: &Fe) -> Fe {
        let mut v = [0u64; 5];
        for i in 0..5 {
            // Add 2p first so every limb stays non-negative.
            v[i] = a.0[i] + 2 * P_LIMBS.0[i] - b.0[i];
        }
        fe_carry(v)
    }

    fn fe_mul(a: &Fe, b: &Fe) -> Fe {
        let mut t = [0u128; 9];
        for i in 0..5 {
            for j in 0..5 {
                t[i + j] += (a.0[i] as u128) * (b.0[j] as u128);
            }
        }
        // Normalize to base 2^51 (11 words: operands can reach ~2^257, so the
        // product can reach ~2^514).
        let mut w = [0u128; 11];
        let mut carry: u128 = 0;
        for k in 0..11 {
            carry += if k < 9 { t[k] } else { 0 };
            w[k] = carry & (M51 as u128);
            carry >>= 51;
        }
        // 2^255 ≡ 19: word k+5 folds into word k with factor 19, and the
        // overflow word 10 (= 2^510 ≡ 19² = 361) folds into word 0.
        let mut v = [0u64; 5];
        for k in 0..5 {
            v[k] = (w[k] + 19 * w[k + 5]) as u64;
        }
        v[0] += (361 * w[10]) as u64;
        fe_carry(v)
    }

    fn fe_sq(a: &Fe) -> Fe {
        fe_mul(a, a)
    }

    fn fe_invert(a: &Fe) -> Fe {
        // a^(p-2); p-2 = 2^255-21 → LE bytes [0xEB, 0xFF × 30, 0x7F].
        let mut e = [0xFFu8; 32];
        e[0] = 0xFF - 20;
        e[31] = 0x7F;
        fe_pow(a, &e)
    }

    fn fe_pow(x: &Fe, exp: &[u8]) -> Fe {
        let mut result = fe_one();
        for byte in exp.iter().rev() {
            for bit in (0..8).rev() {
                result = fe_sq(&result);
                if (byte >> bit) & 1 == 1 {
                    result = fe_mul(&result, x);
                }
            }
        }
        result
    }

    fn fe_is_zero(a: &Fe) -> bool {
        // Representatives are not unique (limbs may hold multiples of p),
        // so zero-ness is checked on the canonical byte encoding.
        fe_to_bytes_le(a) == [0u8; 32]
    }

    fn fe_eq(a: &Fe, b: &Fe) -> bool {
        fe_to_bytes_le(a) == fe_to_bytes_le(b)
    }

    fn fe_from_bytes_le(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            load(0) & M51,
            (load(6) >> 3) & M51,
            (load(12) >> 6) & M51,
            (load(19) >> 1) & M51,
            (load(24) >> 12) & M51,
        ])
    }

    fn fe_to_bytes_le(a: &Fe) -> [u8; 32] {
        let mut v = fe_carry(a.0).0;
        // Conditionally subtract p up to 4 times (value < 4p after carry).
        for _ in 0..4 {
            let mut diff = [0u64; 5];
            let mut borrow = 0u64;
            for i in 0..5 {
                let (d0, b0) = v[i].overflowing_sub(P_LIMBS.0[i]);
                let (d1, b1) = d0.overflowing_sub(borrow);
                diff[i] = d1;
                borrow = u64::from(b0 || b1);
            }
            if borrow == 0 {
                v = diff;
            } else {
                break;
            }
        }
        // Chain-normalize limbs below 2^51 (value < p ⇒ no fold needed);
        // the byte packing below assumes this invariant.
        for i in 0..4 {
            v[i + 1] += v[i] >> 51;
            v[i] &= M51;
        }
        let mut out = [0u8; 32];
        let l0 = v[0] | (v[1] << 51);
        let l1 = (v[1] >> 13) | (v[2] << 38);
        let l2 = (v[2] >> 26) | (v[3] << 25);
        let l3 = (v[3] >> 39) | (v[4] << 12);
        out[0..8].copy_from_slice(&l0.to_le_bytes());
        out[8..16].copy_from_slice(&l1.to_le_bytes());
        out[16..24].copy_from_slice(&l2.to_le_bytes());
        out[24..32].copy_from_slice(&l3.to_le_bytes());
        out
    }

    /// Group constants, computed once at runtime (no hand-typed limbs).
    struct Consts {
        /// d = -121665/121666.
        d: Fe,
        /// 2*d (the factor in the unified addition formulas).
        d2: Fe,
        /// sqrt(-1) = 2^((p-1)/4).
        sqrt_m1: Fe,
        /// The Ed25519 base point.
        base: Ge,
    }

    fn consts() -> &'static Consts {
        use std::sync::OnceLock;
        static C: OnceLock<Consts> = OnceLock::new();
        C.get_or_init(|| {
            let d = fe_sub(
                &fe_zero(),
                &fe_mul(&fe_from_u64(121_665), &fe_invert(&fe_from_u64(121_666))),
            );
            let d2 = fe_add(&d, &d);
            // sqrt(-1) = 2^((p-1)/4); (p-1)/4 = 2^253-5 → LE bytes
            // [0xFB, 0xFF × 30, 0x1F].
            let mut e = [0xFFu8; 32];
            e[0] = 0xFF - 4;
            e[31] = 0x1F;
            let sqrt_m1 = fe_pow(&fe_from_u64(2), &e);
            // Base point: y = 4/5, x even. Built with the locally computed
            // constants (must not re-enter `consts()` → OnceLock re-entry).
            let y = fe_mul(&fe_from_u64(4), &fe_invert(&fe_from_u64(5)));
            let mut y_bytes = fe_to_bytes_le(&y);
            y_bytes[31] &= 0x7F; // sign bit 0 → even x
            let core = Core { d, d2, sqrt_m1 };
            let x = recover_x(
                &core,
                &fe_sub(&fe_sq(&y), &fe_one()),
                &fe_add(&fe_mul(&core.d, &fe_sq(&y)), &fe_one()),
                0,
            )
            .expect("base point decompresses");
            let base = Ge {
                x,
                y,
                z: fe_one(),
                t: fe_mul(&x, &y),
            };
            Consts {
                d,
                d2,
                sqrt_m1,
                base,
            }
        })
    }

    /// The curve constants needed for decompression, passable without
    /// re-entering the `OnceLock` (used while building `base` itself).
    struct Core {
        d: Fe,
        d2: Fe,
        sqrt_m1: Fe,
    }

    /// Extended twisted-Edwards point (X:Y:Z:T), a = -1.
    #[derive(Clone, Copy, Debug)]
    struct Ge {
        x: Fe,
        y: Fe,
        z: Fe,
        t: Fe,
    }

    impl Ge {
        fn identity() -> Ge {
            Ge {
                x: fe_zero(),
                y: fe_one(),
                z: fe_one(),
                t: fe_zero(),
            }
        }

        /// Complete unified addition (valid for doubling as well).
        fn add(&self, other: &Ge) -> Ge {
            let d2 = &consts().d2;
            let a = fe_mul(&fe_sub(&self.y, &self.x), &fe_sub(&other.y, &other.x));
            let b = fe_mul(&fe_add(&self.y, &self.x), &fe_add(&other.y, &other.x));
            let c = fe_mul(&self.t, &fe_mul(&other.t, d2));
            let dd = fe_mul(&self.z, &fe_mul(&other.z, &fe_from_u64(2)));
            let e = fe_sub(&b, &a);
            let f = fe_sub(&dd, &c);
            let g = fe_add(&dd, &c);
            let h = fe_add(&b, &a);
            Ge {
                x: fe_mul(&e, &f),
                y: fe_mul(&g, &h),
                z: fe_mul(&f, &g),
                t: fe_mul(&e, &h),
            }
        }

        /// Compress to 32 bytes (little-endian y with the sign of x on top).
        fn compress(&self) -> [u8; 32] {
            let zinv = fe_invert(&self.z);
            let x = fe_mul(&self.x, &zinv);
            let y = fe_mul(&self.y, &zinv);
            let mut out = fe_to_bytes_le(&y);
            let x_bytes = fe_to_bytes_le(&x);
            out[31] |= (x_bytes[0] & 1) << 7;
            out
        }

        /// Recover a point from its compressed encoding.
        fn decompress(data: &[u8; 32]) -> Option<Ge> {
            let c = consts();
            let core = Core {
                d: c.d,
                d2: c.d2,
                sqrt_m1: c.sqrt_m1,
            };
            Self::decompress_with(&core, data)
        }

        fn decompress_with(core: &Core, data: &[u8; 32]) -> Option<Ge> {
            let sign = data[31] >> 7;
            let mut y_bytes = *data;
            y_bytes[31] &= 0x7F;
            let y = fe_from_bytes_le(&y_bytes);
            // x^2 = u/v with u = y^2-1, v = d*y^2+1 (RFC 8032 §5.1.3).
            let y2 = fe_sq(&y);
            let u = fe_sub(&y2, &fe_one());
            let v = fe_add(&fe_mul(&core.d, &y2), &fe_one());
            let x = recover_x(core, &u, &v, sign)?;
            Some(Ge {
                x,
                y,
                z: fe_one(),
                t: fe_mul(&x, &y),
            })
        }
    }

    /// Recover x from (u, v) for the y-coordinate (RFC 8032 §5.1.3).
    fn recover_x(core: &Core, u: &Fe, v: &Fe, sign: u8) -> Option<Fe> {
        let v3 = fe_mul(&fe_sq(v), v);
        let v7 = fe_mul(&fe_sq(&v3), v);
        // (p-5)/8 = 2^252-3 → LE bytes [0xFD, 0xFF × 30, 0x0F].
        let mut e = [0xFFu8; 32];
        e[0] = 0xFF - 2;
        e[31] = 0x0F;
        let mut x = fe_mul(u, &fe_mul(&v3, &fe_pow(&fe_mul(u, &v7), &e)));
        // Check v·x² == u; if it equals -u, multiply by sqrt(-1).
        let vx2 = fe_mul(v, &fe_sq(&x));
        if fe_eq(&vx2, u) {
            // ok
        } else if fe_eq(&vx2, &fe_sub(&fe_zero(), u)) {
            x = fe_mul(&x, &core.sqrt_m1);
        } else {
            return None;
        }
        let x_bytes = fe_to_bytes_le(&x);
        if fe_is_zero(&x) && sign != 0 {
            return None;
        }
        if (x_bytes[0] & 1) != (sign & 1) {
            x = fe_sub(&fe_zero(), &x);
        }
        Some(x)
    }

    fn ge_mult(scalar_le: &[u8; 32], p: Option<&Ge>) -> Ge {
        let mut acc = Ge::identity();
        for i in (0..256).rev() {
            acc = acc.add(&acc);
            let bit = (scalar_le[i / 8] >> (i % 8)) & 1;
            if bit == 1 {
                let addp = match p {
                    Some(q) => *q,
                    None => consts().base,
                };
                acc = acc.add(&addp);
            }
        }
        acc
    }

    /// Scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493.
    mod sc {
        /// L in four little-endian u64 limbs.
        const L: [u64; 4] = [
            0x5812631A5CF5D3ED,
            0x14DEF9DEA2F79CD6,
            0x0000000000000000,
            0x1000000000000000,
        ];

        fn geq(a: &[u64; 4], b: &[u64; 4]) -> bool {
            for i in (0..4).rev() {
                if a[i] != b[i] {
                    return a[i] > b[i];
                }
            }
            true
        }

        fn sub(a: &mut [u64; 4], b: &[u64; 4]) {
            let mut borrow = 0u64;
            for i in 0..4 {
                let (d0, b0) = a[i].overflowing_sub(b[i]);
                let (d1, b1) = d0.overflowing_sub(borrow);
                a[i] = d1;
                borrow = u64::from(b0 || b1);
            }
        }

        /// Reduce a little-endian integer (up to 64 bytes) modulo L via
        /// shift-subtract long division. 512 iterations of 256-bit ops —
        /// slow by crypto standards, trivially auditable by humans.
        #[must_use]
        pub fn reduce_le(bytes: &[u8]) -> [u8; 32] {
            let mut r = [0u64; 4];
            for i in (0..bytes.len() * 8).rev() {
                // r = r*2 + bit
                let mut carry = 0u64;
                for limb in r.iter_mut() {
                    let nc = *limb >> 63;
                    *limb = (*limb << 1) | carry;
                    carry = nc;
                }
                if (bytes[i / 8] >> (i % 8)) & 1 == 1 {
                    r[0] |= 1;
                }
                if geq(&r, &L) {
                    sub(&mut r, &L);
                }
            }
            let mut out = [0u8; 32];
            for (i, limb) in r.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
            }
            out
        }

        /// (a * b) mod L.
        #[must_use]
        pub fn mul_mod(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            let mut wide = [0u64; 8];
            for i in 0..4 {
                let av = u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
                let mut carry: u128 = 0;
                for j in 0..4 {
                    let bv = u64::from_le_bytes(b[j * 8..j * 8 + 8].try_into().unwrap());
                    let t = (av as u128) * (bv as u128) + wide[i + j] as u128 + carry;
                    wide[i + j] = t as u64;
                    carry = t >> 64;
                }
                wide[i + 4] = carry as u64;
            }
            let mut prod = [0u8; 64];
            for (i, w) in wide.iter().enumerate() {
                prod[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
            }
            reduce_le(&prod)
        }

        /// (a + b) mod L.
        #[must_use]
        pub fn add_mod(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            let mut r = [0u64; 4];
            let mut carry = 0u64;
            for i in 0..4 {
                let av = u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
                let bv = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
                let t = av as u128 + bv as u128 + carry as u128;
                r[i] = t as u64;
                carry = (t >> 64) as u64;
            }
            if geq(&r, &L) {
                sub(&mut r, &L);
            }
            let mut out = [0u8; 32];
            for (i, limb) in r.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
            }
            out
        }

        /// `true` if a (32-byte LE) < L.
        #[must_use]
        pub fn lt_l(a: &[u8; 32]) -> bool {
            let mut v = [0u64; 4];
            for i in 0..4 {
                v[i] = u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
            }
            !geq(&v, &L)
        }
    }

    /// Ed25519 keypair: 32-byte seed and the matching 32-byte public key.
    #[derive(Clone, Debug)]
    pub struct KeyPair {
        /// Secret seed.
        pub seed: [u8; 32],
        /// Encoded public key.
        pub public: [u8; 32],
    }

    impl KeyPair {
        /// Derive the keypair from a seed.
        #[must_use]
        pub fn from_seed(seed: [u8; 32]) -> Self {
            let public = mult_base_clamped(&seed);
            Self { seed, public }
        }
    }

    fn clamp_scalar(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let h = sha512(seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        (a, prefix)
    }

    fn mult_base_clamped(seed: &[u8; 32]) -> [u8; 32] {
        let (a, _) = clamp_scalar(seed);
        ge_mult(&a, None).compress()
    }

    /// Sign `message` with the keypair derived from `seed`.
    #[must_use]
    pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let (a, prefix) = clamp_scalar(seed);
        let public = ge_mult(&a, None).compress();

        let mut r_in = Vec::with_capacity(32 + message.len());
        r_in.extend_from_slice(&prefix);
        r_in.extend_from_slice(message);
        let r = sc::reduce_le(&sha512(&r_in));

        let r_enc = ge_mult(&r, None).compress();

        let mut k_in = Vec::with_capacity(64 + message.len());
        k_in.extend_from_slice(&r_enc);
        k_in.extend_from_slice(&public);
        k_in.extend_from_slice(message);
        let k = sc::reduce_le(&sha512(&k_in));

        let a_mod = sc::reduce_le(&a);
        let s = sc::add_mod(&r, &sc::mul_mod(&k, &a_mod));

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        sig[32..].copy_from_slice(&s);
        sig
    }

    /// Verify `signature` over `message` for `public`.
    #[must_use]
    pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature[32..]);
        if !sc::lt_l(&s_bytes) {
            return false;
        }
        let a_point = match Ge::decompress(public) {
            Some(p) => p,
            None => return false,
        };
        let r_point = match Ge::decompress(&r_bytes) {
            Some(p) => p,
            None => return false,
        };

        let mut k_in = Vec::with_capacity(64 + message.len());
        k_in.extend_from_slice(&r_bytes);
        k_in.extend_from_slice(public);
        k_in.extend_from_slice(message);
        let k = sc::reduce_le(&sha512(&k_in));

        // [s]B == R + [k]A
        let lhs = ge_mult(&s_bytes, None);
        let ka = ge_mult(&k, Some(&a_point));
        let rhs = r_point.add(&ka);
        lhs.compress() == rhs.compress()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        #[test]
        fn rfc8032_test_vectors() {
            // (seed, public, message, signature)
            let cases: &[(&str, &str, &str, &str)] = &[
                (
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                    "",
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                ),
                (
                    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                    "72",
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                ),
                (
                    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                    "af82",
                    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                ),
            ];
            for (i, (seed, pk, msg, sig)) in cases.iter().enumerate() {
                let seed_bytes: [u8; 32] = unhex(seed).try_into().unwrap();
                let kp = KeyPair::from_seed(seed_bytes);
                assert_eq!(hex(&kp.public), *pk, "public key in case {i}");

                let sig_out = sign(&seed_bytes, &unhex(msg));
                assert_eq!(hex(&sig_out), *sig, "signature in case {i}");

                let sig_arr: [u8; 64] = unhex(sig).try_into().unwrap();
                let pk_arr: [u8; 32] = unhex(pk).try_into().unwrap();
                assert!(verify(&pk_arr, &unhex(msg), &sig_arr), "verify case {i}");
            }
        }

        #[test]
        fn tampered_message_fails_verification() {
            let seed = [7u8; 32];
            let kp = KeyPair::from_seed(seed);
            let sig = sign(&seed, b"hello");
            assert!(verify(&kp.public, b"hello", &sig));
            assert!(!verify(&kp.public, b"hellp", &sig));
            let mut bad = sig;
            bad[10] ^= 1;
            assert!(!verify(&kp.public, b"hello", &bad));
        }
    }
}

// Re-exports so callers can write `ed25519::KeyPair` directly.
pub use ed25519::{KeyPair, sign, verify};
