use regera_core::engines::sadair::Sadair;
use regera_core::Encryptor;

#[test]
fn sadair_roundtrip() {
    let plain = b"sadair-roundtrip";
    let seed = 0x5ADA_1A2u64;

    let (ct, tag, frag, mask) = Sadair::encrypt(plain, seed);
    let out = Sadair::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn sadair_changes_per_call() {
    let plain = b"sadair-randomized";
    let seed = 1337u64;

    let (ct1, tag1, frag1, mask1) = Sadair::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = Sadair::encrypt(plain, seed);

    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);
    assert_ne!(frag1, frag2);
    assert_ne!(mask1, mask2);
}

#[test]
#[should_panic(expected = "REGERA/SADAIR: verification failed")]
fn sadair_panics_on_tampered_tag() {
    let plain = b"sadair-auth";
    let seed = 777u64;

    let (ct, mut tag, frag, mask) = Sadair::encrypt(plain, seed);
    tag[0] ^= 0x01;

    let _ = Sadair::decrypt(&ct, &tag, frag, mask, seed);
}
