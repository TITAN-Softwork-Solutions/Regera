use valv_core::engines::chacha::ChaCha;
use valv_core::Encryptor;

#[test]
fn chacha_roundtrip() {
    let plain = b"chacha-roundtrip";
    let seed = 0xA11C_E55Eu64;

    let (ct, tag, frag, mask) = ChaCha::encrypt(plain, seed);
    let out = ChaCha::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn chacha_changes_per_call() {
    let plain = b"chacha-randomized";
    let seed = 7u64;

    let (ct1, tag1, frag1, mask1) = ChaCha::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = ChaCha::encrypt(plain, seed);

    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);
    assert_ne!(frag1, frag2);
    assert_ne!(mask1, mask2);
}

#[test]
#[should_panic(expected = "VALV/CHACHA: verification failed")]
fn chacha_panics_on_tampered_tag() {
    let plain = b"chacha-auth";
    let seed = 42u64;

    let (ct, mut tag, frag, mask) = ChaCha::encrypt(plain, seed);
    tag[0] ^= 0x01;

    let _ = ChaCha::decrypt(&ct, &tag, frag, mask, seed);
}
