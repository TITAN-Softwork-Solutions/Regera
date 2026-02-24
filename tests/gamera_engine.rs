use regera_core::engines::gamera::Gamera;
use regera_core::Encryptor;

#[test]
fn gamera_roundtrip() {
    let plain = b"gamera-roundtrip";
    let seed = 0x6A6A_6A6Au64;

    let (ct, tag, frag, mask) = Gamera::encrypt(plain, seed);
    let out = Gamera::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn gamera_is_deterministic_for_same_input_and_seed() {
    let plain = b"gamera-deterministic";
    let seed = 123u64;

    let (ct1, tag1, frag1, mask1) = Gamera::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = Gamera::encrypt(plain, seed);

    assert_eq!(ct1, ct2);
    assert_eq!(tag1, tag2);
    assert_eq!(frag1, frag2);
    assert_eq!(mask1, mask2);
}

#[test]
fn gamera_output_shape_matches_contract() {
    let plain = b"shape-check";
    let seed = 11u64;

    let (ct, tag, frag, mask) = Gamera::encrypt(plain, seed);

    assert_eq!(ct.len(), plain.len());
    assert_eq!(tag, [0u8; 32]);
    assert_eq!(frag, [[0u8; 8]; 4]);
    assert_eq!(mask, [[0u8; 8]; 4]);
}
