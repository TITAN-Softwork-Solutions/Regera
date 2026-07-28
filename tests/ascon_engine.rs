use valv_core::engines::ascon::Ascon;
use valv_core::Encryptor;

#[test]
fn ascon_roundtrip() {
    let plain = b"ascon-roundtrip";
    let seed = 0xAB50_1A7u64;

    let (ct, tag, frag, mask) = Ascon::encrypt(plain, seed);
    let out = Ascon::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn ascon_changes_per_call() {
    let plain = b"ascon-randomized";
    let seed = 99u64;

    let (ct1, tag1, frag1, mask1) = Ascon::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = Ascon::encrypt(plain, seed);

    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);
    assert_ne!(frag1, frag2);
    assert_ne!(mask1, mask2);
}

#[test]
#[should_panic(expected = "VALV/ASCON: verification failed")]
fn ascon_panics_on_tampered_tag() {
    let plain = b"ascon-auth";
    let seed = 123u64;

    let (ct, mut tag, frag, mask) = Ascon::encrypt(plain, seed);
    tag[0] ^= 0x01;

    let _ = Ascon::decrypt(&ct, &tag, frag, mask, seed);
}
