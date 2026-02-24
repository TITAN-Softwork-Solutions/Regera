<h1 align="center">Regera</h1>
<p align="center"><b>Compile-Time String Encryption for Rust</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Category-Proc%20Macros-8A2BE2?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-AGPL--3.0-red?style=for-the-badge" />
  <a href="https://titansoftwork.com">
    <img src="https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=for-the-badge" />
  </a>
</p>

<p align="center">
Turns string literals into encrypted blobs at compile time and injects minimal decrypt shims at runtime.
</p>

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
