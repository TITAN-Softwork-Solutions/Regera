#[cfg(target_os = "linux")]
#[test]
fn runtime_bound_macro_requires_external_material() {
    use std::{
        env, fs,
        path::PathBuf,
        process::{self, Command, Stdio},
    };

    const PEPPER: &str = "valv-runtime-bound-test-pepper-32-bytes-minimum";
    const PLAINTEXT: &str = "VALV_RUNTIME_BOUND_TOKEN: external-material-required";

    let expected_digest = PLAINTEXT
        .as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |accumulator, byte| {
            (accumulator ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });

    let project_dir = env::temp_dir().join(format!("valv-runtime-bound-test-{}", process::id()));
    let source_dir = project_dir.join("src");
    fs::create_dir_all(&source_dir).expect("failed to create test consumer");

    let valv_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = format!(
        "[package]\nname = \"valv-runtime-bound-consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nvalv = {{ path = {:?}, default-features = false, features = [\"std\", \"runtime_bound\", \"timing_guard\"] }}\n",
        valv_path
    );
    fs::write(project_dir.join("Cargo.toml"), manifest).expect("failed to write test manifest");

    let source = format!(
        "use valv::bound;\n\nfn main() {{\n    let secret = bound!({PLAINTEXT:?});\n    let key = std::env::var(\"VALV_RUNTIME_PEPPER\").unwrap();\n    let digest = secret.with_bytes(key.as_bytes(), |bytes| bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |acc, byte| (acc ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3))).unwrap();\n    assert_eq!(digest, {expected_digest});\n}}\n"
    );
    fs::write(source_dir.join("main.rs"), source).expect("failed to write test source");

    let build = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--release"])
        .current_dir(&project_dir)
        .env("VALV_BUILD_PEPPER", PEPPER)
        .status()
        .expect("failed to build runtime-bound consumer");
    assert!(build.success(), "runtime-bound consumer build failed");

    let binary = project_dir.join("target/release/valv-runtime-bound-consumer");
    let output = Command::new("strings")
        .arg("-a")
        .arg(&binary)
        .output()
        .expect("failed to inspect runtime-bound consumer");
    assert!(output.status.success(), "strings failed");

    let strings = String::from_utf8_lossy(&output.stdout);
    assert!(!strings.contains(PEPPER), "build pepper leaked into binary");
    assert!(
        !strings.contains(PLAINTEXT),
        "runtime-bound plaintext leaked into binary"
    );

    let correct_key = Command::new(&binary)
        .env("VALV_RUNTIME_PEPPER", PEPPER)
        .status()
        .expect("failed to run runtime-bound consumer");
    assert!(correct_key.success(), "matching runtime key was rejected");

    let wrong_key = Command::new(&binary)
        .env(
            "VALV_RUNTIME_PEPPER",
            "wrong-runtime-bound-test-pepper-32-bytes-minimum",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run runtime-bound consumer with wrong key");
    assert!(!wrong_key.success(), "wrong runtime key was accepted");

    fs::remove_dir_all(project_dir).expect("failed to remove runtime-bound test project");
}
