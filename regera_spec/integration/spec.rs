use regera::{
    absolut, absolutex, gamera, gameraex, jesko, jeskoex, sadair, sadairex, velar, velarex,
    SecretText,
};

fn reveal(secret: &SecretText) -> String {
    secret.with_str(|s| s.to_owned())
}

fn reveal_all<const N: usize>(secrets: [SecretText; N]) -> Vec<String> {
    secrets.iter().map(reveal).collect()
}

#[test]
fn macro_coverage_single_variants_roundtrip() {
    assert_eq!(reveal(&jesko!("jesko-single")), "jesko-single");
    assert_eq!(reveal(&absolut!("absolut-single")), "absolut-single");
    assert_eq!(reveal(&sadair!("sadair-single")), "sadair-single");
    assert_eq!(reveal(&gamera!("gamera-single")), "gamera-single");
    assert_eq!(reveal(&velar!("velar-single")), "velar-single");
}

#[test]
fn macro_coverage_multi_variants_roundtrip() {
    assert_eq!(
        reveal_all(jeskoex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(absolutex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(sadairex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(gameraex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(
        reveal_all(velarex!("alpha", "beta", "gamma")),
        vec!["alpha", "beta", "gamma"]
    );
}

#[test]
fn macro_coverage_multi_variants_support_empty_input_list() {
    let jesko_empty: [SecretText; 0] = jeskoex!();
    let absolut_empty: [SecretText; 0] = absolutex!();
    let sadair_empty: [SecretText; 0] = sadairex!();
    let gamera_empty: [SecretText; 0] = gameraex!();
    let velar_empty: [SecretText; 0] = velarex!();

    assert!(jesko_empty.is_empty());
    assert!(absolut_empty.is_empty());
    assert!(sadair_empty.is_empty());
    assert!(gamera_empty.is_empty());
    assert!(velar_empty.is_empty());
}

#[test]
fn macro_coverage_handles_empty_and_unicode_payloads() {
    assert_eq!(reveal(&jesko!("")), "");
    assert_eq!(reveal(&absolut!("")), "");
    assert_eq!(reveal(&sadair!("")), "");
    assert_eq!(reveal(&gamera!("")), "");
    assert_eq!(reveal(&velar!("")), "");

    assert_eq!(
        reveal_all(jeskoex!("", "REGERA", "ascii-123_!")),
        vec!["", "REGERA", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(absolutex!("", "REGERA", "ascii-123_!")),
        vec!["", "REGERA", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(sadairex!("", "REGERA", "ascii-123_!")),
        vec!["", "REGERA", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(gameraex!("", "REGERA", "ascii-123_!")),
        vec!["", "REGERA", "ascii-123_!"]
    );
    assert_eq!(
        reveal_all(velarex!("", "REGERA", "ascii-123_!")),
        vec!["", "REGERA", "ascii-123_!"]
    );
}
