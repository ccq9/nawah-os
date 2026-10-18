//! nawah-crypto — SHA-256 (FIPS 180-4 §6.2), HMAC-SHA-256 (RFC 2104) and PBKDF2-HMAC-SHA-256
//! (RFC 8018 §5.2) for the user side (WP-25, ADR-0016 §5). `#![no_std]`, no allocation, no
//! dependencies; constant-time comparison for tags. Known-answer tests from FIPS 180-4
//! (NIST examples), RFC 4231 §4 and RFC 7914 §11 run on the host (`cargo test`) and in the
//! guest (`self_test`).

#![cfg_attr(not(test), no_std)]

/// SHA-256 digest length in bytes.
pub const DIGEST_LEN: usize = 32;
/// SHA-256 block length in bytes.
pub const BLOCK_LEN: usize = 64;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Incremental SHA-256.
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    block: [u8; BLOCK_LEN],
    block_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Sha256 {
            h: H0,
            block: [0; BLOCK_LEN],
            block_len: 0,
            total_len: 0,
        }
    }

    /// One-shot digest.
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut s = Self::new();
        s.update(data);
        s.finish()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.block_len > 0 {
            let take = (BLOCK_LEN - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == BLOCK_LEN {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }
        while data.len() >= BLOCK_LEN {
            let (block, rest) = data.split_at(BLOCK_LEN);
            let mut b = [0u8; BLOCK_LEN];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Padding (FIPS 180-4 §5.1.1): 0x80, zeros to 56 mod 64, the bit length big-endian.
    pub fn finish(mut self) -> [u8; DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);
        let mut pad = [0u8; BLOCK_LEN * 2];
        pad[0] = 0x80;
        let pad_len = if self.block_len < 56 {
            56 - self.block_len
        } else {
            120 - self.block_len
        };
        pad[pad_len..pad_len + 8].copy_from_slice(&bit_len.to_be_bytes());
        self.update(&pad[..pad_len + 8]);
        debug_assert_eq!(self.block_len, 0);
        let mut out = [0u8; DIGEST_LEN];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// The compression function (FIPS 180-4 §6.2.2) on one 512-bit block.
    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for t in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = big_s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (hi, v) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *hi = hi.wrapping_add(v);
        }
    }
}

/// HMAC-SHA-256 (RFC 2104): a key longer than a block is hashed first.
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            k[..DIGEST_LEN].copy_from_slice(&Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        HmacSha256 { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> [u8; DIGEST_LEN] {
        let ih = self.inner.finish();
        let mut outer = self.outer;
        outer.update(&ih);
        outer.finish()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut m = Self::new(key);
        m.update(data);
        m.finish()
    }
}

/// PBKDF2-HMAC-SHA-256 (RFC 8018 §5.2) into `out` (any length; blocks T_1..T_l).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let base = HmacSha256::new(password);
    let iterations = iterations.max(1);
    for (block_index, chunk) in out.chunks_mut(DIGEST_LEN).enumerate() {
        let i = (block_index as u32).wrapping_add(1);
        let mut mac = base.clone();
        mac.update(salt);
        mac.update(&i.to_be_bytes());
        let mut u = mac.finish();
        let mut t = u;
        for _ in 1..iterations {
            let mut m = base.clone();
            m.update(&u);
            u = m.finish();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= ui;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// Constant-time equality of two tags (the comparison does not stop at the first difference).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Known-answer vectors (FIPS 180-4 examples, RFC 4231 §4, RFC 7914 §11); `self_test` returns
/// a bit per failed vector (0 = all pass) so the guest can report them without a test harness.
pub mod kat {
    use super::*;

    fn hex(s: &str, out: &mut [u8]) -> usize {
        let b = s.as_bytes();
        let n = b.len() / 2;
        for i in 0..n {
            let v = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => 0,
            };
            out[i] = (v(b[2 * i]) << 4) | v(b[2 * i + 1]);
        }
        n
    }

    /// FIPS 180-4 / NIST SHA-256 examples: "abc" and the 56-byte two-block message.
    pub const SHA_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    pub const SHA_TWO_BLOCK: &str =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    /// SHA-256 of the empty message (FIPS 180-4 padding of a zero-length input).
    pub const SHA_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// RFC 4231 §4 test cases 1, 2, 6 and 7 (keys of 20 bytes, "Jefe", and 131 bytes).
    pub const HMAC_TC1: &str = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    pub const HMAC_TC2: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    pub const HMAC_TC6: &str = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
    pub const HMAC_TC7: &str = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

    /// RFC 7914 §11: PBKDF2-HMAC-SHA-256 ("passwd", "salt", 1, 64) and ("Password", "NaCl",
    /// 80000, 64).
    pub const PBKDF2_V1: &str = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
    pub const PBKDF2_V2: &str = "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d";

    fn check(actual: &[u8], expected_hex: &str) -> bool {
        let mut exp = [0u8; 64];
        let n = hex(expected_hex, &mut exp);
        n == actual.len() && ct_eq(actual, &exp[..n])
    }

    /// Runs the SHA-256 and HMAC vectors and the first PBKDF2 vector (the 80000-iteration one
    /// is `pbkdf2_long`, kept apart because it takes a while in the guest). Bit i set = vector
    /// i failed: 0 abc, 1 two-block, 2 empty, 3 incremental split, 4 HMAC TC1, 5 TC2, 6 TC6,
    /// 7 TC7, 8 PBKDF2 V1.
    pub fn self_test() -> u32 {
        let mut fails = 0u32;
        let two_block = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        if !check(&Sha256::digest(b"abc"), SHA_ABC) {
            fails |= 1;
        }
        if !check(&Sha256::digest(two_block), SHA_TWO_BLOCK) {
            fails |= 2;
        }
        if !check(&Sha256::digest(b""), SHA_EMPTY) {
            fails |= 4;
        }
        let mut s = Sha256::new();
        s.update(&two_block[..30]);
        s.update(&two_block[30..]);
        if !check(&s.finish(), SHA_TWO_BLOCK) {
            fails |= 8;
        }
        if !check(&HmacSha256::mac(&[0x0b; 20], b"Hi There"), HMAC_TC1) {
            fails |= 16;
        }
        if !check(
            &HmacSha256::mac(b"Jefe", b"what do ya want for nothing?"),
            HMAC_TC2,
        ) {
            fails |= 32;
        }
        let long_key = [0xaa; 131];
        if !check(
            &HmacSha256::mac(
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
            ),
            HMAC_TC6,
        ) {
            fails |= 64;
        }
        if !check(
            &HmacSha256::mac(
                &long_key,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            ),
            HMAC_TC7,
        ) {
            fails |= 128;
        }
        let mut dk = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk);
        if !check(&dk, PBKDF2_V1) {
            fails |= 256;
        }
        fails
    }

    /// RFC 7914 §11 second vector: 80000 iterations.
    pub fn pbkdf2_long() -> bool {
        let mut dk = [0u8; 64];
        pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000, &mut dk);
        check(&dk, PBKDF2_V2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(kat::self_test(), 0);
    }

    #[test]
    fn pbkdf2_80000_iterations() {
        assert!(kat::pbkdf2_long());
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        for split in [0usize, 1, 55, 56, 63, 64, 65, 500, 999, 1000] {
            let mut s = Sha256::new();
            s.update(&data[..split]);
            s.update(&data[split..]);
            assert_eq!(s.finish(), Sha256::digest(&data), "split {split}");
        }
    }

    #[test]
    fn ct_eq_lengths() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
