use valv_core::engines::xormask::XorMask;
use valv_core::Encryptor;

#[test]
fn xormask_roundtrip() {
    let plain = b"xormask-roundtrip";
    let seed = 0x6A6A_6A6Au64;

    let (ct, tag, frag, mask) = XorMask::encrypt(plain, seed);
    let out = XorMask::decrypt(&ct, &tag, frag, mask, seed);

    assert_eq!(out.as_bytes(), plain);
}

#[test]
fn xormask_is_deterministic_for_same_input_and_seed() {
    let plain = b"xormask-deterministic";
    let seed = 123u64;

    let (ct1, tag1, frag1, mask1) = XorMask::encrypt(plain, seed);
    let (ct2, tag2, frag2, mask2) = XorMask::encrypt(plain, seed);

    assert_eq!(ct1, ct2);
    assert_eq!(tag1, tag2);
    assert_eq!(frag1, frag2);
    assert_eq!(mask1, mask2);
}

#[test]
fn xormask_output_shape_matches_contract() {
    let plain = b"shape-check";
    let seed = 11u64;

    let (ct, tag, frag, mask) = XorMask::encrypt(plain, seed);

    assert_eq!(ct.len(), plain.len());
    assert_eq!(tag, [0u8; 32]);
    assert_eq!(frag, [[0u8; 8]; 4]);
    assert_eq!(mask, [[0u8; 8]; 4]);
}
