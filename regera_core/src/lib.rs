// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025
//
// REGERA Core Library
//
// This crate provides the core traits, types, and engine wiring for REGERA — a
// compile-time macro encryption/obfuscation framework for Rust. Engines live
// under `crate::engines` and implement the `Encryptor` trait.
//
// Notes:
// - `no_std` friendly (uses `alloc`).
// - Engines should minimize secret lifetimes and zeroize sensitive material.

#![feature(core_intrinsics)]

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt, ops::Deref};
use zeroize::Zeroize;

/// Short license string for embedding/banners.
pub const LICENSE: &str = "AGPL-3.0 © 2025 TITAN Softwork Solutions | REGERA";

/// All concrete engines live here (jesko, absolut, sadair, gamera, …).
pub mod engines;

use engines::{absolut, gamera, jesko, sadair};

/// Engine selector used by macros and call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegeraEngine {
    /// Jesko — ChaCha20 + keyed BLAKE3 (hardened variant)
    Jesko,
    /// Absolut — ASCON-128 AEAD + KMAC/BLAKE3 DS
    Absolut,
    /// Sadair — AES-256-GCM + BLAKE3 DS
    Sadair,
    /// Gamera — fast non-crypto obfuscator
    Gamera,
}

impl RegeraEngine {
    #[inline]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "jesko" => Some(Self::Jesko),
            "absolut" => Some(Self::Absolut),
            "sadair" => Some(Self::Sadair),
            "gamera" => Some(Self::Gamera),
            _ => None,
        }
    }
}

/// A zeroizing string wrapper. Contents are wiped on drop.
///
/// Use this as the return type of `Encryptor::decrypt` to avoid leaving
/// plaintexts resident in heap memory longer than necessary.
pub struct SecretStr(String);

impl SecretStr {
    /// Consume and return the inner `String` (no additional copy).
    /// Note: this transfers ownership; zeroization will *not* occur on drop
    /// of the wrapper (the caller now owns the `String`).
    #[inline(always)]
    pub fn into_inner(mut self) -> String {
        let s = core::mem::take(&mut self.0);
        core::mem::forget(self);
        s
    }
}

impl Drop for SecretStr {
    #[inline(always)]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for SecretStr {
    type Target = str;
    #[inline(always)]
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretStr {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<SecretStr> for String {
    #[inline(always)]
    fn from(mut s: SecretStr) -> Self {
        let inner = core::mem::take(&mut s.0);
        core::mem::forget(s);
        inner
    }
}

impl AsRef<str> for SecretStr {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// REGERA engine interface implemented by each backend in `engines::*`.
///
/// Conventions:
/// - `seed` is a 64-bit value used for deterministic nonce/adversarial mixing.
/// - `encrypt` returns `(ciphertext, tag32, key_frag, key_mask)` where:
///   - `tag32` may be an authentication tag or a structured placeholder
///     (engine-dependent). In hardened engines it is a real MAC (32 bytes).
///   - `key_frag` and `key_mask` are 4×8-byte rows used to reconstruct the
///     per-call master key at runtime (XOR of corresponding rows).
pub trait Encryptor {
    fn encrypt(
        plain: &[u8],
        seed: u64,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]);

    /// Decrypt using the returned pieces from `encrypt` and the same `seed`.
    /// Implementations should verify integrity (if provided) and zeroize
    /// intermediate material before returning.
    fn decrypt(
        ct: &[u8],
        tag32: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u64,
    ) -> SecretStr;
}

/// Dispatch encryption to a specific engine.
///
/// This is primarily used by the proc-macro crate at compile time.
#[inline(always)]
pub fn pulse(
    engine: RegeraEngine,
    plain: &[u8],
    seed: u64,
) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
    match engine {
        RegeraEngine::Jesko => jesko::Jesko::encrypt(plain, seed),
        RegeraEngine::Absolut => absolut::Absolut::encrypt(plain, seed),
        RegeraEngine::Sadair => sadair::Sadair::encrypt(plain, seed),
        RegeraEngine::Gamera => gamera::Gamera::encrypt(plain, seed),
    }
}