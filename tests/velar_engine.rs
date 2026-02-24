use regera_core::engines::velar::Velar;
use regera_core::Encryptor;

#[test]
fn velar_roundtrip() {
    let plain = b"root-test-roundtrip";
    let seed = 0xDEAD_BEEF_F00D_CAFEu64;

    let (ct, tag, frag, mask) = Velar::encrypt(plain, seed);
    let out = Velar::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn velar_changes_per_call() {
    let plain = b"root-test-randomized";
    let seed = 99u64;

    let (ct1, tag1, _, _) = Velar::encrypt(plain, seed);
    let (ct2, tag2, _, _) = Velar::encrypt(plain, seed);

    assert_ne!(tag1, tag2);
    assert_ne!(ct1, ct2);
}
