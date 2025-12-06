#![doc = r#"
# Gamera Engine (no_std, deterministic)

**Gamera** is a *non-cryptographic* obfuscator. It applies a reversible XOR
transform keyed by a 64-bit seed. No timing/CPU noise is used (determinism is
required so decrypt can invert encrypt exactly).

Implements the [`Encryptor`](crate::Encryptor) trait.
"#]

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};

use crate::{Encryptor, SecretStr};

/// Non-cryptographic obfuscator (reversible XOR).
pub struct Gamera;

impl Gamera {
    /// Derive a per-index mask from the 64-bit seed and the byte index.
    /// Deterministic and cheap; XOR is its own inverse.
    #[inline(always)]
    fn mask_at(seed: u64, i: usize) -> u8 {
        let sb = seed.to_le_bytes();
        let base = sb[i & 7].rotate_left(((i as u32) % 7) + 1);
        let idx  = (i as u8).wrapping_mul(0x0B);
        // small extra mixing from other seed bytes; still deterministic
        let kmix = sb[0] ^ sb[3] ^ sb[5] ^ sb[7] ^ 0xA7;
        base ^ idx ^ kmix.rotate_left((i % 5) as u32) ^ 0x3C
    }

    /// Reversible transform; same function used for encrypt and decrypt.
    #[inline(always)]
    fn transform(input: &[u8], seed: u64) -> Vec<u8> {
        let mut out = vec![0u8; input.len()];
        for (i, (&b, o)) in input.iter().zip(out.iter_mut()).enumerate() {
            *o = b ^ Self::mask_at(seed, i);
        }
        out
    }

    /// Placeholder fragments/tag to satisfy `Encryptor`.
    #[inline(always)]
    fn dummy_fragments() -> ([[u8; 8]; 4], [[u8; 8]; 4]) { ([[0u8; 8]; 4], [[0u8; 8]; 4]) }
    #[inline(always)]
    fn dummy_tag() -> [u8; 32] { [0u8; 32] }
}

impl Encryptor for Gamera {
    #[inline(always)]
    fn encrypt(
        plain: &[u8],
        seed: u64,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let ct = Self::transform(plain, seed);
        let (frag, mask) = Self::dummy_fragments();
        (ct, Self::dummy_tag(), frag, mask)
    }

    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        _tag: &[u8],
        _frag: [[u8; 8]; 4],
        _mask: [[u8; 8]; 4],
        seed: u64,
    ) -> SecretStr {
        let pt = Self::transform(ct, seed);
        SecretStr(String::from_utf8(pt).expect("Gamera: invalid UTF-8"))
    }
}