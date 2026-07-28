// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025

//! Runtime support for Valv encrypted string literals.
//!
//! This crate contains the [`SecretText`] handle, the zeroizing [`SecretStr`]
//! plaintext wrapper, and the feature-gated engine implementations used by the
//! proc-macro crate. Most users should depend on the top-level `valv` crate
//! instead of importing this crate directly.
//!
//! # Threat model
//!
//! Valv removes plaintext string literals from the compiled image and keeps
//! decrypted text scoped to short closures. It does **not** make embedded
//! secrets unrecoverable from a binary: the ciphertext and runtime decryption
//! material must both be present so the program can decrypt without external
//! input. Treat Valv as obfuscation and memory-hygiene tooling, not as a
//! substitute for a runtime secret manager, license server, TPM, HSM, or OS
//! credential store.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

/// Maximum uninterrupted wall-clock gap accepted by the optional timing guard.
///
/// The guard checks decryption and plaintext exposure separately. It is a
/// heuristic against long debugger pauses, not a debugger-proof boundary.
#[cfg(feature = "timing_guard")]
pub const TIMING_GUARD_MAX_GAP: std::time::Duration = std::time::Duration::from_millis(250);

#[cfg(feature = "timing_guard")]
#[inline(always)]
fn timing_guard_exceeded(started: std::time::Instant) -> bool {
    timing_guard_elapsed_exceeded(started.elapsed())
}

#[cfg(feature = "timing_guard")]
#[inline(always)]
fn timing_guard_elapsed_exceeded(elapsed: std::time::Duration) -> bool {
    elapsed > TIMING_GUARD_MAX_GAP
}

#[cfg(feature = "timing_guard")]
#[cold]
#[inline(never)]
fn timing_guard_terminate() -> ! {
    std::process::exit(70)
}

#[allow(dead_code)]
#[cold]
#[inline(never)]
pub(crate) fn abort_or_panic(message: &'static str) -> ! {
    #[cfg(feature = "std")]
    {
        let _ = message;
        std::process::abort();
    }

    #[cfg(not(feature = "std"))]
    panic!("{}", message)
}

/// Short license string for embedding/banners.
pub const LICENSE: &str = "AGPL-3.0 (C) 2025 TITAN Softwork Solutions | VALV";

/// All concrete engines live here (chacha, ascon, aesgcm, xormask, streammask).
pub mod engines;

#[cfg(feature = "runtime_bound")]
mod runtime_bound;
#[cfg(feature = "runtime_bound")]
pub use runtime_bound::{
    runtime_bound_encrypt, RuntimeBoundError, RuntimeBoundText, MIN_RUNTIME_KEY_MATERIAL_LEN,
};

/// Engine selector used by macros and call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValvEngine {
    #[cfg(feature = "chacha")]
    ChaCha,
    #[cfg(feature = "ascon")]
    Ascon,
    #[cfg(feature = "aesgcm")]
    AesGcm,
    #[cfg(feature = "xormask")]
    XorMask,
    #[cfg(feature = "streammask")]
    StreamMask,
}

impl ValvEngine {
    #[inline]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            #[cfg(feature = "chacha")]
            "chacha" => Some(Self::ChaCha),
            #[cfg(feature = "ascon")]
            "ascon" => Some(Self::Ascon),
            #[cfg(feature = "aesgcm")]
            "aesgcm" => Some(Self::AesGcm),
            #[cfg(feature = "xormask")]
            "xormask" => Some(Self::XorMask),
            #[cfg(feature = "streammask")]
            "streammask" => Some(Self::StreamMask),
            _ => None,
        }
    }
}

/// A zeroizing string wrapper. Contents are wiped on drop.
///
/// Deliberately does NOT implement Display / Deref / AsRef / `From<SecretStr>` for `String`.
/// That entire set is basically a "leak me into logs and conversions" kit.
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

    /// If you absolutely must take ownership, gate it behind a feature so it's never accidental.
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

/// Debug is redacted so `{:?}` can't oops secrets into logs.
impl fmt::Debug for SecretStr {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStr")
            .field("len", &self.0.len())
            .field("redacted", &true)
            .finish()
    }
}

/// VALV engine interface implemented by each backend in `engines::*`.
pub trait Encryptor {
    fn encrypt(plain: &[u8], seed: u64) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]);

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
        Self {
            ct,
            tag,
            frag,
            mask,
            seed,
            decrypt_fn,
        }
    }

    /// Decrypt -> use -> drop (zeroize) in one tight scope.
    #[inline(always)]
    pub fn with_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        #[cfg(feature = "timing_guard")]
        let decrypt_started = std::time::Instant::now();

        let s = (self.decrypt_fn)(self.ct, &self.tag[..], self.frag, self.mask, self.seed);

        #[cfg(feature = "timing_guard")]
        if timing_guard_exceeded(decrypt_started) {
            drop(s);
            timing_guard_terminate();
        }

        #[cfg(feature = "timing_guard")]
        let exposure_started = std::time::Instant::now();

        let out = f(s.as_str());

        #[cfg(feature = "timing_guard")]
        {
            let timing_violation = timing_guard_exceeded(exposure_started);
            drop(s);
            if timing_violation {
                drop(out);
                timing_guard_terminate();
            }
            return out;
        }

        #[cfg(not(feature = "timing_guard"))]
        {
            out
            // s drops here -> zeroize
        }
    }

    /// Same idea, but bytes (avoids formatters and UTF widening paths).
    #[inline(always)]
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        #[cfg(feature = "timing_guard")]
        let decrypt_started = std::time::Instant::now();

        let s = (self.decrypt_fn)(self.ct, &self.tag[..], self.frag, self.mask, self.seed);

        #[cfg(feature = "timing_guard")]
        if timing_guard_exceeded(decrypt_started) {
            drop(s);
            timing_guard_terminate();
        }

        #[cfg(feature = "timing_guard")]
        let exposure_started = std::time::Instant::now();

        let out = f(s.as_bytes());

        #[cfg(feature = "timing_guard")]
        {
            let timing_violation = timing_guard_exceeded(exposure_started);
            drop(s);
            if timing_violation {
                drop(out);
                timing_guard_terminate();
            }
            return out;
        }

        #[cfg(not(feature = "timing_guard"))]
        {
            out
        }
    }

    /// Redacted debug hint.
    #[inline(always)]
    pub fn ct_len(&self) -> usize {
        self.ct.len()
    }
}

#[cfg(all(test, feature = "timing_guard"))]
mod timing_guard_tests {
    use super::{timing_guard_elapsed_exceeded, TIMING_GUARD_MAX_GAP};
    use std::time::Duration;

    #[test]
    fn timing_guard_accepts_the_threshold() {
        assert!(!timing_guard_elapsed_exceeded(TIMING_GUARD_MAX_GAP));
    }

    #[test]
    fn timing_guard_rejects_a_gap_above_the_threshold() {
        assert!(timing_guard_elapsed_exceeded(
            TIMING_GUARD_MAX_GAP + Duration::from_millis(1)
        ));
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
    engine: ValvEngine,
    _plain: &[u8],
    _seed: u64,
) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
    match engine {
        #[cfg(feature = "chacha")]
        ValvEngine::ChaCha => engines::chacha::ChaCha::encrypt(_plain, _seed),
        #[cfg(feature = "ascon")]
        ValvEngine::Ascon => engines::ascon::Ascon::encrypt(_plain, _seed),
        #[cfg(feature = "aesgcm")]
        ValvEngine::AesGcm => engines::aesgcm::AesGcm::encrypt(_plain, _seed),
        #[cfg(feature = "xormask")]
        ValvEngine::XorMask => engines::xormask::XorMask::encrypt(_plain, _seed),
        #[cfg(feature = "streammask")]
        ValvEngine::StreamMask => engines::streammask::StreamMask::encrypt(_plain, _seed),
    }
}
