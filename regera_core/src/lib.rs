// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025

#![feature(core_intrinsics)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

/// Short license string for embedding/banners.
pub const LICENSE: &str = "AGPL-3.0 © 2025 TITAN Softwork Solutions | REGERA";

/// All concrete engines live here (jesko, absolut, sadair, gamera, velar).
pub mod engines;

/// Engine selector used by macros and call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegeraEngine {
    #[cfg(feature = "jesko")]
    Jesko,
    #[cfg(feature = "absolut")]
    Absolut,
    #[cfg(feature = "sadair")]
    Sadair,
    #[cfg(feature = "gamera")]
    Gamera,
    #[cfg(feature = "velar")]
    Velar,
}

impl RegeraEngine {
    #[inline]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            #[cfg(feature = "jesko")]
            "jesko" => Some(Self::Jesko),
            #[cfg(feature = "absolut")]
            "absolut" => Some(Self::Absolut),
            #[cfg(feature = "sadair")]
            "sadair" => Some(Self::Sadair),
            #[cfg(feature = "gamera")]
            "gamera" => Some(Self::Gamera),
            #[cfg(feature = "velar")]
            "velar" => Some(Self::Velar),
            _ => None,
        }
    }
}

/// A zeroizing string wrapper. Contents are wiped on drop.
///
/// Deliberately does NOT implement Display / Deref / AsRef / From<SecretStr> for String.
/// That entire set is basically a “leak me into logs and conversions” kit.
pub struct SecretStr(pub(crate) String);

impl SecretStr {
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Explicit exposure hook (keeps lifetime tiny at call sites).
    #[inline(always)]
    pub fn expose_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(self.as_str())
    }

    /// Explicit byte exposure hook.
    #[inline(always)]
    pub fn expose_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.as_bytes())
    }

    /// If you absolutely must take ownership, gate it behind a feature so it’s never accidental.
    #[cfg(feature = "leaky_reveal")]
    #[inline(always)]
    pub fn into_string(mut self) -> String {
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

/// Debug is redacted so `{:?}` can’t oops secrets into logs.
impl fmt::Debug for SecretStr {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStr")
            .field("len", &self.0.len())
            .field("redacted", &true)
            .finish()
    }
}

/// REGERA engine interface implemented by each backend in `engines::*`.
pub trait Encryptor {
    fn encrypt(
        plain: &[u8],
        seed: u64,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]);

    fn decrypt(
        ct: &[u8],
        tag32: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u64,
    ) -> SecretStr;
}

/// Encrypted handle that only materializes plaintext inside a closure,
/// then drops (and zeroizes) immediately.
#[derive(Clone, Copy)]
pub struct SecretText {
    ct: &'static [u8],
    tag: &'static [u8; 32],
    frag: [[u8; 8]; 4],
    mask: [[u8; 8]; 4],
    seed: u64,
    decrypt_fn: fn(&[u8], &[u8], [[u8; 8]; 4], [[u8; 8]; 4], u64) -> SecretStr,
}

impl SecretText {
    #[inline(always)]
    pub const fn new(
        ct: &'static [u8],
        tag: &'static [u8; 32],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u64,
        decrypt_fn: fn(&[u8], &[u8], [[u8; 8]; 4], [[u8; 8]; 4], u64) -> SecretStr,
    ) -> Self {
        Self { ct, tag, frag, mask, seed, decrypt_fn }
    }

    /// Decrypt -> use -> drop (zeroize) in one tight scope.
    #[inline(always)]
    pub fn with_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        let s = (self.decrypt_fn)(self.ct, &self.tag[..], self.frag, self.mask, self.seed);
        let out = f(s.as_str());
        out
        // s drops here -> zeroize
    }

    /// Same idea, but bytes (avoids formatters and UTF widening paths).
    #[inline(always)]
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        let s = (self.decrypt_fn)(self.ct, &self.tag[..], self.frag, self.mask, self.seed);
        let out = f(s.as_bytes());
        out
    }

    /// Redacted debug hint.
    #[inline(always)]
    pub fn ct_len(&self) -> usize {
        self.ct.len()
    }
}

impl fmt::Debug for SecretText {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretText")
            .field("ct_len", &self.ct.len())
            .field("redacted", &true)
            .finish()
    }
}

/// Dispatch encryption to a specific engine.
/// Primarily used by the proc-macro crate at compile time.
#[inline(always)]
pub fn pulse(
    engine: RegeraEngine,
    plain: &[u8],
    seed: u64,
) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
    match engine {
        #[cfg(feature = "jesko")]
        RegeraEngine::Jesko => engines::jesko::Jesko::encrypt(plain, seed),
        #[cfg(feature = "absolut")]
        RegeraEngine::Absolut => engines::absolut::Absolut::encrypt(plain, seed),
        #[cfg(feature = "sadair")]
        RegeraEngine::Sadair => engines::sadair::Sadair::encrypt(plain, seed),
        #[cfg(feature = "gamera")]
        RegeraEngine::Gamera => engines::gamera::Gamera::encrypt(plain, seed),
        #[cfg(feature = "velar")]
        RegeraEngine::Velar => engines::velar::Velar::encrypt(plain, seed),
    }
}
