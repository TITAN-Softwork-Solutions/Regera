#![doc = r#"
# Stream Mask Engine (lightweight)

Pipeline:
- 256-bit random build-time key
- Per-string subkey = BLAKE3(build_key || seed_u64_le)
- ChaCha20 keystream XOR over plaintext/ciphertext
- No MAC, no fragmentation, no masking, no integrity checks
- Zeroize key material after decrypt
"#]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use blake3::Hasher as B3Hasher;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20 as StreamX;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{Encryptor, SecretStr};

pub struct StreamMask;

impl StreamMask {
    #[inline(always)]
    fn derive_subkey(build_key: &[u8; 32], seed: u64) -> [u8; 32] {
        let mut h = B3Hasher::new();
        h.update(build_key);
        h.update(&seed.to_le_bytes());
        *h.finalize().as_bytes()
    }

    #[inline(always)]
    fn nonce_from_seed(seed: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&seed.to_le_bytes());
        nonce
    }

    #[inline(always)]
    fn apply_keystream(buf: &mut [u8], subkey: &[u8; 32], seed: u64) {
        let nonce = Self::nonce_from_seed(seed);
        StreamX::new(&(*subkey).into(), &nonce.into()).apply_keystream(buf);
    }
}

impl Encryptor for StreamMask {
    #[inline(always)]
    fn encrypt(plain: &[u8], seed: u64) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        // Build-time random 256-bit key (proc-macro path calls this at compile time).
        let mut build_key = [0u8; 32];
        OsRng.fill_bytes(&mut build_key);

        let mut subkey = Self::derive_subkey(&build_key, seed);
        let mut ct = plain.to_vec();
        Self::apply_keystream(&mut ct, &subkey, seed);

        // Return build key in the tag field (StreamMask has no MAC).
        let tag = build_key;

        subkey.zeroize();

        (ct, tag, [[0u8; 8]; 4], [[0u8; 8]; 4])
    }

    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        tag: &[u8],
        _frag: [[u8; 8]; 4],
        _mask: [[u8; 8]; 4],
        seed: u64,
    ) -> SecretStr {
        if tag.len() != 32 {
            #[cfg(debug_assertions)]
            panic!("VALV/STREAMMASK: invalid key material");
            #[cfg(not(debug_assertions))]
            crate::abort_or_panic("VALV/STREAMMASK: invalid key material")
        }

        let mut build_key = [0u8; 32];
        build_key.copy_from_slice(tag);

        let mut subkey = Self::derive_subkey(&build_key, seed);
        let mut pt = ct.to_vec();
        Self::apply_keystream(&mut pt, &subkey, seed);

        // Explicit key hygiene requested for StreamMask.
        subkey.zeroize();
        build_key.zeroize();

        SecretStr(String::from_utf8(pt).expect("StreamMask: invalid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::StreamMask;
    use crate::Encryptor;

    #[test]
    fn roundtrip_recovers_plaintext() {
        let plain = b"streammask-roundtrip";
        let seed = 0x1234_5678_90AB_CDEFu64;

        let (ct, tag, frag, mask) = StreamMask::encrypt(plain, seed);
        let pt = StreamMask::decrypt(&ct, &tag, frag, mask, seed);

        assert_eq!(pt.as_bytes(), plain);
    }

    #[test]
    fn output_shape_matches_contract() {
        let plain = b"shape-check";
        let seed = 0xCAFEBABE_DEADC0DEu64;

        let (ct, tag, frag, mask) = StreamMask::encrypt(plain, seed);

        assert_eq!(ct.len(), plain.len());
        assert_eq!(tag.len(), 32);
        assert_eq!(frag, [[0u8; 8]; 4]);
        assert_eq!(mask, [[0u8; 8]; 4]);
    }

    #[test]
    fn encrypt_is_randomized_per_call() {
        let plain = b"same-input";
        let seed = 7u64;

        let (ct1, tag1, _, _) = StreamMask::encrypt(plain, seed);
        let (ct2, tag2, _, _) = StreamMask::encrypt(plain, seed);

        assert_ne!(tag1, tag2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    #[should_panic(expected = "VALV/STREAMMASK: invalid key material")]
    fn decrypt_panics_on_invalid_tag_length() {
        let ct = [0u8; 4];
        let bad_tag = [0u8; 31];
        let _ = StreamMask::decrypt(&ct, &bad_tag, [[0u8; 8]; 4], [[0u8; 8]; 4], 1);
    }
}
