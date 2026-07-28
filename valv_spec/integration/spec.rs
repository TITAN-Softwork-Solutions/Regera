use valv::{
    SecretText, aesgcm, aesgcmex, ascon, asconex, chacha, chachaex, streammask, streammaskex,
    xormask, xormaskex,
};

fn reveal(secret: &SecretText) -> String {
    secret.with_str(|s| s.to_owned())
}

fn reveal_all<const N: usize>(secrets: [SecretText; N]) -> Vec<String> {
    secrets.iter().map(reveal).collect()
}

#[test]
fn macro_coverage_single_variants_roundtrip() {
    assert_eq!(reveal(&chacha!("chacha-single")), "chacha-single");
    assert_eq!(reveal(&ascon!("ascon-single")), "ascon-single");
    assert_eq!(reveal(&aesgcm!("aesgcm-single")), "aesgcm-single");
    assert_eq!(reveal(&xormask!("xormask-single")), "xormask-single");
    assert_eq!(
        reveal(&streammask!("streammask-single")),
        "streammask-single"
    );
}

#[test]
fn macro_coverage_multi_variants_roundtrip() {
    assert_eq!(
        reveal_all(chachaex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(asconex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(aesgcmex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(xormaskex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(streammaskex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
}

#[test]
fn macro_coverage_multi_variants_support_empty_input_list() {
    let chacha_empty: [SecretText; 0] = chachaex!();
    let ascon_empty: [SecretText; 0] = asconex!();
    let aesgcm_empty: [SecretText; 0] = aesgcmex!();
    let xormask_empty: [SecretText; 0] = xormaskex!();
    let streammask_empty: [SecretText; 0] = streammaskex!();

    assert!(chacha_empty.is_empty());
    assert!(ascon_empty.is_empty());
    assert!(aesgcm_empty.is_empty());
    assert!(xormask_empty.is_empty());
    assert!(streammask_empty.is_empty());
}

#[test]
fn macro_coverage_handles_empty_and_ascii_payloads() {
    assert_eq!(reveal(&chacha!("")), "");
    assert_eq!(reveal(&ascon!("")), "");
    assert_eq!(reveal(&aesgcm!("")), "");
    assert_eq!(reveal(&xormask!("")), "");
    assert_eq!(reveal(&streammask!("")), "");

    assert_eq!(
        reveal_all(chachaex!("", "VALV", "ascii-123_!")),
        vec!["", "VALV", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(asconex!("", "VALV", "ascii-123_!")),
        vec!["", "VALV", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(aesgcmex!("", "VALV", "ascii-123_!")),
        vec!["", "VALV", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(xormaskex!("", "VALV", "ascii-123_!")),
        vec!["", "VALV", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(streammaskex!("", "VALV", "ascii-123_!")),
        vec!["", "VALV", "ascii-123_!"]
    );
}
