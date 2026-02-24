use regera_core::engines::jesko::Jesko;
use regera_core::Encryptor;

#[test]
fn jesko_roundtrip() {
    let plain = b"jesko-roundtrip";
    let seed = 0xA11C_E55Eu64;

    let (ct, tag, frag, mask) = Jesko::encrypt(plain, seed);
    let out = Jesko::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn jesko_changes_per_call() {
    let plain = b"jesko-randomized";
    let seed = 7u64;

    let (ct1, tag1, frag1, mask1) = Jesko::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = Jesko::encrypt(plain, seed);

    assert_ne!(ct1, ct2);
    assert_ne!(tag1, tag2);
    assert_ne!(frag1, frag2);
    assert_ne!(mask1, mask2);
}

#[test]
#[should_panic(expected = "REGERA/JESKO: verification failed")]
fn jesko_panics_on_tampered_tag() {
    let plain = b"jesko-auth";
    let seed = 42u64;

    let (ct, mut tag, frag, mask) = Jesko::encrypt(plain, seed);
    tag[0] ^= 0x01;

    let _ = Jesko::decrypt(&ct, &tag, frag, mask, seed);
}
