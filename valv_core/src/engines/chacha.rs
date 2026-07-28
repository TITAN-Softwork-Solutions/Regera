#![doc = r#"
# ChaCha Engine (hardened)

**ChaCha** is a hybrid symmetric encryption engine tailored to **stealth string
encryption** scenarios.

Hardenings vs. initial design:
- Key separation (ENC/MAC) via BLAKE3 domain separation
- Deterministic nonce derived from `enc_key || seed` (u64), not raw key bytes
- MAC computed over the **raw stream ciphertext** (pre-obfuscation)
- Obfuscation keyed by `enc_key` as well as seed
- Constant-time MAC verification
- Wider `seed: u64`
- Zeroization completeness and release-abort on auth failure
"#]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use blake3::{hash as bl3_hash, Hasher as B3Hasher};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20 as StreamX;

use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{Encryptor, SecretStr};

/// ChaCha provides stealth-grade string encryption for short-lived sensitive data.
pub struct ChaCha;

/// Internal masked key container used to store XOR-fragmented key material
/// alongside per-fragment 8-byte masks.
#[repr(C)]
struct MaskedKey {
    /// 4x8 bytes of XOR-masked key fragments
    frag: [[u8; 8]; 4],
    /// 4x8 byte masks used to recover original key
    mask: [[u8; 8]; 4],
}

#[inline(always)]
fn split_keys(master: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Domain-separated BLAKE3-derived subkeys
    let enc = blake3::keyed_hash(master, b"VALV/CHACHA/ENC");
    let mac = blake3::keyed_hash(master, b"VALV/CHACHA/MAC");
    (*enc.as_bytes(), *mac.as_bytes())
}

impl ChaCha {
    /// Derives a 256-bit key from a 64-byte spell using BLAKE3.
    #[inline(always)]
    fn derive_key(spell: &[u8]) -> [u8; 32] {
        *bl3_hash(spell).as_bytes()
    }

    /// Deterministic 96-bit nonce from (enc_key || seed)
    #[inline(always)]
    fn make_nonce(seed: u64, enc_key: &[u8; 32]) -> [u8; 12] {
        let mut inbuf = [0u8; 32 + 8];
        inbuf[..32].copy_from_slice(enc_key);
        inbuf[32..].copy_from_slice(&seed.to_le_bytes());
        let digest = bl3_hash(&inbuf);
        let mut n = [0u8; 12];
        n.copy_from_slice(&digest.as_bytes()[..12]);
        n
    }

    /// Keyed post-encryption mutation to disrupt pattern matching on raw stream output.
    #[inline(always)]
    fn post_mutate(buf: &mut [u8], seed: u64, enc_key: &[u8; 32]) {
        let kmix = enc_key[0] ^ enc_key[13] ^ enc_key[31];
        let seed8 = seed.to_le_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            let r =
                seed8[i & 7].rotate_left(((i as u32) % 7) + 1) ^ kmix.rotate_left((i % 5) as u32);
            *b ^= r ^ 0x9B;
        }
    }

    /// Reverses `post_mutate`.
    #[inline(always)]
    fn post_unmutate(buf: &mut [u8], seed: u64, enc_key: &[u8; 32]) {
        // XOR is involutive; same as mutate.
        Self::post_mutate(buf, seed, enc_key);
    }

    /// Splits a 256-bit key into four 64-bit fragments, each masked with random 8-byte junk.
    #[inline(always)]
    fn mask_key(key: &[u8; 32]) -> MaskedKey {
        let mut frag = [[0u8; 8]; 4];
        let mut mask = [[0u8; 8]; 4];
        for i in 0..4 {
            OsRng.fill_bytes(&mut mask[i]);
            for j in 0..8 {
                frag[i][j] = key[i * 8 + j] ^ mask[i][j];
            }
        }
        MaskedKey { frag, mask }
    }

    /// Computes a keyed BLAKE3 MAC tag over the ciphertext (pre-mutation).
    #[inline(always)]
    fn compute_mac(ct_stream: &[u8], mac_key: &[u8; 32]) -> [u8; 32] {
        let mut h = B3Hasher::new_keyed(mac_key);
        h.update(ct_stream);
        *h.finalize().as_bytes()
    }

    #[cold]
    #[inline(never)]
    fn die() -> ! {
        #[cfg(debug_assertions)]
        panic!("VALV/CHACHA: verification failed");
        #[cfg(not(debug_assertions))]
        crate::abort_or_panic("VALV/CHACHA: verification failed")
    }
}

impl Encryptor for ChaCha {
    /// Encrypts plaintext using:
    /// 1. BLAKE3 key derivation from a random `spell`
    /// 2. Key splitting (ENC/MAC) with domain separation
    /// 3. Deterministic nonce from (enc_key || seed)
    /// 4. ChaCha20 stream encryption
    /// 5. MAC over raw stream ciphertext
    /// 6. Keyed XOR mutation of ciphertext
    /// 7. Key fragmentation + masking
    #[inline(always)]
    fn encrypt(plain: &[u8], seed: u64) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);

        let mut master = Self::derive_key(&spell);
        let (mut enc_key, mut mac_key) = split_keys(&master);

        let mut ct = plain.to_vec();
        let mut nonce = Self::make_nonce(seed, &enc_key);
        StreamX::new(&enc_key.into(), &nonce.into()).apply_keystream(&mut ct);

        let tag = Self::compute_mac(&ct, &mac_key);
        // Obfuscate after MAC:
        Self::post_mutate(&mut ct, seed, &enc_key);

        let MaskedKey { frag, mask } = Self::mask_key(&master);

        // Hygiene
        enc_key.zeroize();
        mac_key.zeroize();
        master.zeroize();
        spell.zeroize();
        nonce.zeroize();

        (ct, tag, frag, mask)
    }

    /// Decrypts the ciphertext using reconstructed key and nonce.
    ///
    /// # Panics/Aborts
    /// - Aborts in release if MAC verification fails
    /// - Panics in debug if verification fails or UTF-8 invalid
    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        tag: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u64,
    ) -> SecretStr {
        let mut master = [0u8; 32];
        for i in 0..4 {
            for j in 0..8 {
                master[i * 8 + j] = frag[i][j] ^ mask[i][j];
            }
        }

        if tag.len() != 32 {
            Self::die();
        }

        let (mut enc_key, mut mac_key) = split_keys(&master);

        // Undo obfuscation
        let mut data = ct.to_vec();
        Self::post_unmutate(&mut data, seed, &enc_key);

        // Verify MAC (constant time) over stream ciphertext
        let mut expected = Self::compute_mac(&data, &mac_key);
        let ok = expected.ct_eq(tag.try_into().unwrap()).unwrap_u8() == 1;
        expected.zeroize();

        if !ok {
            enc_key.zeroize();
            mac_key.zeroize();
            master.zeroize();
            Self::die();
        }

        // Stream decrypt
        let mut nonce = Self::make_nonce(seed, &enc_key);
        StreamX::new(&enc_key.into(), &nonce.into()).apply_keystream(&mut data);

        // Hygiene
        enc_key.zeroize();
        mac_key.zeroize();
        master.zeroize();
        nonce.zeroize();

        // Move `data` into String; wiped on SecretStr::drop
        let s = String::from_utf8(data).expect("ChaCha: invalid UTF-8");
        SecretStr(s)
    }
}
