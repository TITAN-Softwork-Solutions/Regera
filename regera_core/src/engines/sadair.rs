#![doc = r#"
# Sadair Engine (AES-256-GCM, hardened, no_std)

- Ephemeral per-call master key (random spell → BLAKE3)
- Key split: ENC (32B) + MAC (32B via BLAKE3 domain separation)
- Deterministic 96-bit nonce: BLAKE3(enc_key || seed_u64)[..12]
- MAC (BLAKE3 keyed) over **raw GCM output** (ct||tag) before obfuscation
- Post-encryption XOR obfuscation keyed by seed + enc_key (undone before verify/decrypt)
- Constant-time MAC verify; complete zeroization
"#]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use blake3::{hash as bl3_hash, Hasher as B3Hasher};
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{Encryptor, SecretStr};

pub struct Sadair;

/// Fragment/mask a 32B master into 4×8B rows.
#[inline(always)]
fn mask_key(master: &[u8; 32]) -> ([[u8; 8]; 4], [[u8; 8]; 4]) {
    let mut frag = [[0u8; 8]; 4];
    let mut mask = [[0u8; 8]; 4];
    for i in 0..4 {
        OsRng.fill_bytes(&mut mask[i]);
        for j in 0..8 {
            frag[i][j] = master[i * 8 + j] ^ mask[i][j];
        }
    }
    (frag, mask)
}

#[inline(always)]
fn unmask_key(frag: [[u8; 8]; 4], mask: [[u8; 8]; 4]) -> [u8; 32] {
    let mut master = [0u8; 32];
    for i in 0..4 {
        for j in 0..8 {
            master[i * 8 + j] = frag[i][j] ^ mask[i][j];
        }
    }
    master
}

/// Random 64B → master (32B) via BLAKE3.
#[inline(always)]
fn derive_master(spell: &[u8; 64]) -> [u8; 32] {
    *bl3_hash(spell).as_bytes()
}

/// Domain-separate keys.
#[inline(always)]
fn split_keys(master: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // ENC key = BLAKE3 keyed(master, "REGERA/SADAIR/ENC")
    let enc = blake3::keyed_hash(master, b"REGERA/SADAIR/ENC");
    let mac = blake3::keyed_hash(master, b"REGERA/SADAIR/MAC");
    (*enc.as_bytes(), *mac.as_bytes())
}

/// Nonce = BLAKE3(enc_key || seed)[..12].
#[inline(always)]
fn make_nonce(seed: u64, enc_key: &[u8; 32]) -> [u8; 12] {
    let mut inp = [0u8; 32 + 8];
    inp[..32].copy_from_slice(enc_key);
    inp[32..].copy_from_slice(&seed.to_le_bytes());
    let h = bl3_hash(&inp);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h.as_bytes()[..12]);
    n
}

/// Keyed MAC over raw GCM output (ciphertext||tag).
#[inline(always)]
fn compute_mac(stream: &[u8], mac_key: &[u8; 32]) -> [u8; 32] {
    let mut h = B3Hasher::new_keyed(mac_key);
    h.update(stream);
    *h.finalize().as_bytes()
}

/// Post-encryption obfuscation; XOR is involutive.
#[inline(always)]
fn post_mutate(buf: &mut [u8], seed: u64, enc_key: &[u8; 32]) {
    let kmix = enc_key[0] ^ enc_key[11] ^ enc_key[31];
    let s = seed.to_le_bytes();
    for (i, b) in buf.iter_mut().enumerate() {
        let r = s[i & 7].rotate_left(((i as u32) % 7) + 1)
            ^ kmix.rotate_left((i % 5) as u32)
            ^ 0xB3;
        *b ^= r;
    }
}
#[inline(always)]
fn post_unmutate(buf: &mut [u8], seed: u64, enc_key: &[u8; 32]) {
    post_mutate(buf, seed, enc_key);
}

#[cold]
#[inline(never)]
fn die() -> ! {
    #[cfg(debug_assertions)]
    panic!("REGERA/SADAIR: verification failed");
    #[cfg(not(debug_assertions))]
    unsafe { core::intrinsics::abort() }
}

impl Encryptor for Sadair {
    #[inline(always)]
    fn encrypt(
        plain: &[u8],
        seed: u64,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        // Random spell → master → keys
        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);
        let mut master = derive_master(&spell);
        let (mut enc_key, mut mac_key) = split_keys(&master);

        // AES-256-GCM with deterministic nonce
        let cipher = Aes256Gcm::new_from_slice(&enc_key).expect("sadair: bad key");
        let mut nonce = make_nonce(seed, &enc_key);
        let mut ct_stream = cipher
            .encrypt(Nonce::from_slice(&nonce), plain)
            .expect("sadair: encryption failed");
        // Note: `ct_stream` is ciphertext||tag(16)

        // MAC over raw GCM output
        let mut tag32 = compute_mac(&ct_stream, &mac_key);

        // Obfuscate after MAC
        post_mutate(&mut ct_stream, seed, &enc_key);

        // Fragment + mask master
        let (frag, mask) = mask_key(&master);

        // Hygiene
        enc_key.zeroize();
        mac_key.zeroize();
        master.zeroize();
        spell.zeroize();
        nonce.zeroize();

        (ct_stream, tag32, frag, mask)
    }

    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        tag: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u64,
    ) -> SecretStr {
        if tag.len() != 32 {
            die();
        }

        // Rebuild master → keys
        let mut master = unmask_key(frag, mask);
        let (mut enc_key, mut mac_key) = split_keys(&master);

        // Undo obfuscation
        let mut data = ct.to_vec();
        post_unmutate(&mut data, seed, &enc_key);

        // Verify MAC (constant time) over stream (ciphertext||tag16)
        let mut expected = compute_mac(&data, &mac_key);
        let ok = expected.ct_eq(tag.try_into().unwrap()).unwrap_u8() == 1;
        expected.zeroize();

        if !ok {
            enc_key.zeroize();
            mac_key.zeroize();
            master.zeroize();
            die();
        }

        // AES-GCM decrypt with deterministic nonce
        let mut nonce = make_nonce(seed, &enc_key);
        let plain = Aes256Gcm::new_from_slice(&enc_key)
            .expect("sadair: bad key")
            .decrypt(Nonce::from_slice(&nonce), data.as_slice())
            .expect("sadair: decryption failed");

        // Hygiene
        enc_key.zeroize();
        mac_key.zeroize();
        master.zeroize();
        nonce.zeroize();

        // Move into zeroizing wrapper
        SecretStr(String::from_utf8(plain).expect("sadair: invalid UTF-8"))
    }
}