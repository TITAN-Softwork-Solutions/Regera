# Regera

Compile-time string encryption for Rust with explicit engine feature flags.

Regera encrypts string literals at build time and emits runtime decrypt shims. Single-value macros return a zeroizing `SecretStr`.

![Diagram](./regera_spec/diagram/REGERA_TH_BLACK.png)

## Engines

- `jesko`: ChaCha20 + BLAKE3 MAC + obfuscation
- `absolut`: ASCON128 + KMAC256 + obfuscation
- `sadair`: AES-256-GCM + BLAKE3 MAC + obfuscation
- `gamera`: deterministic XOR obfuscator (non-crypto)
- `velar`: lightweight BLAKE3-derived key + ChaCha20 keystream XOR (no MAC/integrity)

## Feature selection

Enable only the engines you need so unused crypto crates are not linked.

```toml
[dependencies]
regera = { version = "0.1.0", default-features = false, features = ["std", "velar"] }
# example multi-engine:
# regera = { version = "0.1.0", default-features = false, features = ["std", "jesko", "velar"] }
```

## Quick start

```rust
use regera::velar;

fn main() {
    let secret = velar!("MySecretData");
    secret.with_str(|s| println!("{}", s));
}
```

Multi-string macros are available per engine (`jeskoex!`, `absolutex!`, `sadairex!`, `gameraex!`, `velarex!`).

## Crates

- `regera`: umbrella crate (re-exports macros + core types)
- `regera_core`: runtime engines and core types
- `regera_macros`: proc-macros that encrypt at compile time

## Testing

```bash
cargo test --workspace
```

## License

AGPL-3.0. See `LICENSE`.
