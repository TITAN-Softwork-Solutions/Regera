use valv_core::engines::aesgcm::AesGcm;
use valv_core::Encryptor;

#[test]
fn aesgcm_roundtrip() {
    let plain = b"aesgcm-roundtrip";
    let seed = 0x5ADA_1A2u64;

    let (ct, tag, frag, mask) = AesGcm::encrypt(plain, seed);
    let out = AesGcm::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn aesgcm_changes_per_call() {
    let plain = b"aesgcm-randomized";
    let seed = 1337u64;

    let (ct1, tag1, frag1, mask1) = AesGcm::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = AesGcm::encrypt(plain, seed);

    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);
    assert_ne!(frag1, frag2);
    assert_ne!(mask1, mask2);
}

#[test]
#[should_panic(expected = "VALV/AESGCM: verification failed")]
fn aesgcm_panics_on_tampered_tag() {
    let plain = b"aesgcm-auth";
    let seed = 777u64;

    let (ct, mut tag, frag, mask) = AesGcm::encrypt(plain, seed);
    tag[0] ^= 0x01;

    let _ = AesGcm::decrypt(&ct, &tag, frag, mask, seed);
}
