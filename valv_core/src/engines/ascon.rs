#![doc = r#"
# Ascon Engine (hardened, no_std)

**Ascon** is a stealth-biased engine using KMAC256 -> master key, ASCON-AEAD128
for encryption, and a keyed XOR obfuscation layer. Hardenings:

- `no_std` (uses `alloc`)
- KMAC256 -> 32-byte `master`; split into `enc_key` (16B) + `mac_key` (32B via BLAKE3 DS)
- Deterministic 128-bit nonce = BLAKE3(enc_key || seed_u64)[..16]
- MAC computed over **raw AEAD ciphertext** (pre-obfuscation)
- Constant-time MAC verification (`subtle`)
- Wider `seed: u64`
- Key fragmentation + masking (32B master -> 4x8 frag/mask)
- Zeroization of all secret material; release abort on verify failure
"#]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use ascon_aead::aead::{Aead, KeyInit, Payload};
use ascon_aead::{AsconAead128, AsconAead128Key, AsconAead128Nonce};
use blake3::{hash as bl3_hash, Hasher as B3Hasher};
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroize;

use crate::{Encryptor, SecretStr};

pub struct Ascon;

/// Internal masked key container (32-byte master fragmented + masked)
#[repr(C)]
struct MaskedKey {
    frag: [[u8; 8]; 4],
    mask: [[u8; 8]; 4],
}

#[inline(always)]
fn mask_key(master: &[u8; 32]) -> MaskedKey {
    let mut frag = [[0u8; 8]; 4];
    let mut mask = [[0u8; 8]; 4];
    for i in 0..4 {
        OsRng.fill_bytes(&mut mask[i]);
        for j in 0..8 {
            frag[i][j] = master[i * 8 + j] ^ mask[i][j];
        }
    }
    MaskedKey { frag, mask }
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

#[inline(always)]
fn derive_master_kmac256(spell: &[u8], seed: u64) -> [u8; 32] {
    // KMAC256(key=domain, custom=seed_le) over random 64-byte spell
    let domain = b"VALV/ASCON/KDF/v1";
    let custom = seed.to_le_bytes();
    let mut kmac = Kmac::v256(domain, &custom);
    kmac.update(spell);
    let mut out = [0u8; 32];
    kmac.finalize(&mut out);
    out
}

#[inline(always)]
fn split_keys(master: &[u8; 32]) -> ([u8; 16], [u8; 32]) {
    // ENC key: first 16 bytes
    let mut enc = [0u8; 16];
    enc.copy_from_slice(&master[..16]);

    // MAC key: domain-separated BLAKE3 keyed by master
    let mac = blake3::keyed_hash(master, b"VALV/ASCON/MAC");
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(mac.as_bytes());
    (enc, mac_key)
}

#[inline(always)]
fn make_nonce(seed: u64, enc_key: &[u8; 16]) -> [u8; 16] {
    let mut inbuf = [0u8; 16 + 8];
    inbuf[..16].copy_from_slice(enc_key);
    inbuf[16..].copy_from_slice(&seed.to_le_bytes());
    let h = bl3_hash(&inbuf);
    let mut n = [0u8; 16];
    n.copy_from_slice(&h.as_bytes()[..16]);
    n
}

#[inline(always)]
fn compute_mac(ct_stream: &[u8], mac_key: &[u8; 32]) -> [u8; 32] {
    let mut h = B3Hasher::new_keyed(mac_key);
    h.update(ct_stream);
    *h.finalize().as_bytes()
}

#[inline(always)]
fn post_mutate(data: &mut [u8], seed: u64, enc_key: &[u8; 16]) {
    let kmix = enc_key[0] ^ enc_key[7] ^ enc_key[15];
    let s = seed.to_le_bytes();
    for (i, b) in data.iter_mut().enumerate() {
        let r = s[i & 7].rotate_left(((i as u32) % 7) + 1) ^ kmix.rotate_left((i % 5) as u32);
        *b ^= r ^ 0xE5;
    }
}

// Undo is same as apply (XOR is involutive)
#[inline(always)]
fn post_unmutate(data: &mut [u8], seed: u64, enc_key: &[u8; 16]) {
    post_mutate(data, seed, enc_key);
}

#[cold]
#[inline(never)]
fn die() -> ! {
    #[cfg(debug_assertions)]
    panic!("VALV/ASCON: verification failed");
    #[cfg(not(debug_assertions))]
    crate::abort_or_panic("VALV/ASCON: verification failed")
}

impl Encryptor for Ascon {
    #[inline(always)]
    fn encrypt(plain: &[u8], seed: u64) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        // Random spell -> master
        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);
        let mut master = derive_master_kmac256(&spell, seed);
        let (mut enc_key, mut mac_key) = split_keys(&master);

        // AEAD encrypt (raw stream ct includes ASCON tag at end)
        let cipher = AsconAead128::new(AsconAead128Key::from_slice(&enc_key));
        let mut nonce = make_nonce(seed, &enc_key);
        let mut ct_stream = cipher
            .encrypt(
                AsconAead128Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &[],
                },
            )
            .expect("ascon: encryption failed");

        // MAC over pre-obfuscated ciphertext
        let tag = compute_mac(&ct_stream, &mac_key);

        // Obfuscate after MAC
        post_mutate(&mut ct_stream, seed, &enc_key);

        // Fragment + mask the 32-byte master
        let MaskedKey { frag, mask } = mask_key(&master);

        // Hygiene
        enc_key.zeroize();
        mac_key.zeroize();
        master.zeroize();
        spell.zeroize();
        nonce.zeroize();

        (ct_stream, tag, frag, mask)
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

        // Rebuild master, derive keys
        let mut master = unmask_key(frag, mask);
        let (mut enc_key, mut mac_key) = split_keys(&master);

        // Undo obfuscation
        let mut data = ct.to_vec();
        post_unmutate(&mut data, seed, &enc_key);

        // Verify MAC (constant time) over stream ciphertext
        let mut expected = compute_mac(&data, &mac_key);
        let ok = expected.ct_eq(tag.try_into().unwrap()).unwrap_u8() == 1;
        expected.zeroize();

        if !ok {
            enc_key.zeroize();
            mac_key.zeroize();
            master.zeroize();
            die();
        }

        // AEAD decrypt
        let mut nonce = make_nonce(seed, &enc_key);
        let plain = AsconAead128::new(AsconAead128Key::from_slice(&enc_key))
            .decrypt(
                AsconAead128Nonce::from_slice(&nonce),
                Payload {
                    msg: &data,
                    aad: &[],
                },
            )
            .expect("ascon: decryption failed");

        // Hygiene
        enc_key.zeroize();
        mac_key.zeroize();
        master.zeroize();
        nonce.zeroize();

        // Move into zeroizing SecretStr
        let s = String::from_utf8(plain).expect("ascon: invalid UTF-8");
        SecretStr(s)
    }
}
