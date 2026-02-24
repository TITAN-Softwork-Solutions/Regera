use regera_core::engines::absolut::Absolut;
use regera_core::Encryptor;

#[test]
fn absolut_roundtrip() {
    let plain = b"absolut-roundtrip";
    let seed = 0xAB50_1A7u64;

    let (ct, tag, frag, mask) = Absolut::encrypt(plain, seed);
    let out = Absolut::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn absolut_changes_per_call() {
    let plain = b"absolut-randomized";
    let seed = 99u64;

    let (ct1, tag1, frag1, mask1) = Absolut::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = Absolut::encrypt(plain, seed);

    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);
    assert_ne!(frag1, frag2);
    assert_ne!(mask1, mask2);
}

#[test]
#[should_panic(expected = "REGERA/ABSOLUT: verification failed")]
fn absolut_panics_on_tampered_tag() {
    let plain = b"absolut-auth";
    let seed = 123u64;

    let (ct, mut tag, frag, mask) = Absolut::encrypt(plain, seed);
    tag[0] ^= 0x01;

    let _ = Absolut::decrypt(&ct, &tag, frag, mask, seed);
}
