#[cfg(target_os = "linux")]
#[test]
fn stripped_release_probe_excludes_protected_literal() {
    use std::{
        env, fs,
        path::PathBuf,
        process::{self, Command},
    };

    let target_dir = env::temp_dir().join(format!("valv-stripped-probe-test-{}", process::id()));
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

    let build = Command::new(env!("CARGO"))
        .args([
            "build",
            "--quiet",
            "--release",
            "--example",
            "security_probe",
            "--manifest-path",
        ])
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("failed to run cargo for stripped probe");
    assert!(build.success(), "release probe build failed");

    let binary = target_dir.join("release/examples/security_probe");
    let stripped = target_dir.join("release/examples/security_probe.stripped");
    fs::copy(&binary, &stripped).expect("failed to copy release probe");

    let strip = Command::new("strip")
        .arg("--strip-all")
        .arg(&stripped)
        .status()
        .expect("failed to run strip");
    assert!(strip.success(), "strip failed");

    let output = Command::new("strings")
        .arg("-a")
        .arg(&stripped)
        .output()
        .expect("failed to run strings");
    assert!(output.status.success(), "strings failed");

    let strings = String::from_utf8_lossy(&output.stdout);
    assert!(!strings.contains("VALV_AUDIT_TOKEN"));
    assert!(!strings.contains("offline-recovery-check"));

    fs::remove_dir_all(target_dir).expect("failed to remove probe target directory");
}
