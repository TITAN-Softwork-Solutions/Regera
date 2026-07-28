# Publishing to crates.io

Valv is split into three crates:

1. `valv_core` - runtime types and engines
2. `valv_macros` - proc macros
3. `valv` - user-facing facade crate

Publish them in that order because `valv_macros` depends on `valv_core`, and `valv` depends on both.

## Preflight

Run the checks that do not require published internal dependencies:

```bash
cargo fmt --all --check
cargo test --workspace --all-features
cargo package -p valv_core --allow-dirty
```

For a clean release, remove `--allow-dirty` and run the commands from a committed tree.

Cargo will not package or dry-run `valv_macros` until `valv_core` exists in the crates.io index at the matching version. It will not package or dry-run `valv` until both `valv_core` and `valv_macros` exist in the index. This is normal for a first publish of a split crate family.

## Publish

Publish and verify in dependency order:

```bash
cargo publish -p valv_core
# Wait for crates.io indexing, then:
cargo publish -p valv_macros --dry-run
cargo publish -p valv_macros
# Wait for crates.io indexing, then:
cargo publish -p valv --dry-run
cargo publish -p valv
```

If crates.io indexing has not caught up between steps, wait briefly and retry the next command.

## Metadata Checklist

- Each crate has a version, description, repository, license, keywords, categories, and `rust-version`.
- Path dependencies also include matching `version` fields, so Cargo can package and publish them.
- The root package uses SPDX license `AGPL-3.0-only` and does not also set `license-file`.
- docs.rs builds all features through `[package.metadata.docs.rs] all-features = true`.

## Versioning

Keep all three crates on the same version unless there is a specific reason to decouple them. Update the path dependency versions in `Cargo.toml` and `valv_macros/Cargo.toml` whenever publishing a new version.
