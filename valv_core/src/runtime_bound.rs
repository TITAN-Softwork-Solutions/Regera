extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{fmt, str};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroize;

use crate::SecretStr;

const KDF_CONTEXT: &str = "com.titansoftwork.valv.runtime-bound.v1";
const AAD: &[u8] = b"VALV/RUNTIME-BOUND/v1";

/// Minimum accepted external key-material length for runtime-bound secrets.
pub const MIN_RUNTIME_KEY_MATERIAL_LEN: usize = 32;

/// Failure returned by runtime-bound encryption or decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBoundError {
    KeyMaterialTooShort,
    AuthenticationFailed,
    InvalidUtf8,
}

impl fmt::Display for RuntimeBoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::KeyMaterialTooShort => "runtime key material must contain at least 32 bytes",
            Self::AuthenticationFailed => "runtime-bound authentication failed",
            Self::InvalidUtf8 => "runtime-bound plaintext is not valid UTF-8",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RuntimeBoundError {}

fn derive_key(key_material: &[u8], nonce: &[u8; 12]) -> Result<[u8; 32], RuntimeBoundError> {
    if key_material.len() < MIN_RUNTIME_KEY_MATERIAL_LEN {
        return Err(RuntimeBoundError::KeyMaterialTooShort);
    }

    let mut hasher = blake3::Hasher::new_derive_key(KDF_CONTEXT);
    hasher.update(&(key_material.len() as u64).to_le_bytes());
    hasher.update(key_material);
    hasher.update(nonce);
    Ok(*hasher.finalize().as_bytes())
}

/// Encrypts a literal for the proc-macro crate without embedding key material.
#[doc(hidden)]
pub fn runtime_bound_encrypt(
    plaintext: &[u8],
    key_material: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, RuntimeBoundError> {
    let mut key = derive_key(key_material, nonce)?;
    let result = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| RuntimeBoundError::AuthenticationFailed)?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| RuntimeBoundError::AuthenticationFailed);
    key.zeroize();
    result
}

/// Ciphertext that requires external key material each time it is decrypted.
#[derive(Clone, Copy)]
pub struct RuntimeBoundText {
    ciphertext: &'static [u8],
    nonce: &'static [u8; 12],
}

impl RuntimeBoundText {
    #[doc(hidden)]
    pub const fn new(ciphertext: &'static [u8], nonce: &'static [u8; 12]) -> Self {
        Self { ciphertext, nonce }
    }

    fn decrypt(&self, key_material: &[u8]) -> Result<SecretStr, RuntimeBoundError> {
        let mut key = derive_key(key_material, self.nonce)?;
        let decrypted = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| RuntimeBoundError::AuthenticationFailed)?
            .decrypt(
                Nonce::from_slice(self.nonce),
                Payload {
                    msg: self.ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| RuntimeBoundError::AuthenticationFailed);
        key.zeroize();

        let mut plaintext = decrypted?;
        if str::from_utf8(&plaintext).is_err() {
            plaintext.zeroize();
            return Err(RuntimeBoundError::InvalidUtf8);
        }

        // UTF-8 validity was checked immediately above.
        Ok(SecretStr(unsafe { String::from_utf8_unchecked(plaintext) }))
    }

    /// Decrypts with external material and exposes UTF-8 only inside the closure.
    pub fn with_str<R>(
        &self,
        key_material: &[u8],
        callback: impl FnOnce(&str) -> R,
    ) -> Result<R, RuntimeBoundError> {
        #[cfg(feature = "timing_guard")]
        let decrypt_started = std::time::Instant::now();

        let plaintext = self.decrypt(key_material)?;

        #[cfg(feature = "timing_guard")]
        if super::timing_guard_exceeded(decrypt_started) {
            drop(plaintext);
            super::timing_guard_terminate();
        }

        #[cfg(feature = "timing_guard")]
        let exposure_started = std::time::Instant::now();

        let output = callback(plaintext.as_str());

        #[cfg(feature = "timing_guard")]
        {
            let timing_violation = super::timing_guard_exceeded(exposure_started);
            drop(plaintext);
            if timing_violation {
                drop(output);
                super::timing_guard_terminate();
            }
            return Ok(output);
        }

        #[cfg(not(feature = "timing_guard"))]
        Ok(output)
    }

    /// Decrypts with external material and exposes bytes only inside the closure.
    pub fn with_bytes<R>(
        &self,
        key_material: &[u8],
        callback: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, RuntimeBoundError> {
        #[cfg(feature = "timing_guard")]
        let decrypt_started = std::time::Instant::now();

        let plaintext = self.decrypt(key_material)?;

        #[cfg(feature = "timing_guard")]
        if super::timing_guard_exceeded(decrypt_started) {
            drop(plaintext);
            super::timing_guard_terminate();
        }

        #[cfg(feature = "timing_guard")]
        let exposure_started = std::time::Instant::now();

        let output = callback(plaintext.as_bytes());

        #[cfg(feature = "timing_guard")]
        {
            let timing_violation = super::timing_guard_exceeded(exposure_started);
            drop(plaintext);
            if timing_violation {
                drop(output);
                super::timing_guard_terminate();
            }
            return Ok(output);
        }

        #[cfg(not(feature = "timing_guard"))]
        Ok(output)
    }

    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

impl fmt::Debug for RuntimeBoundText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeBoundText")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("redacted", &true)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{runtime_bound_encrypt, RuntimeBoundError, RuntimeBoundText};

    const KEY: &[u8] = b"correct-runtime-key-material-32-bytes-minimum";
    const WRONG_KEY: &[u8] = b"incorrect-runtime-key-material-32-bytes-min";
    const NONCE: &[u8; 12] = b"test-nonce12";

    fn fixture() -> RuntimeBoundText {
        let ciphertext = runtime_bound_encrypt(b"runtime-bound-secret", KEY, NONCE).unwrap();
        RuntimeBoundText::new(Box::leak(ciphertext.into_boxed_slice()), NONCE)
    }

    #[test]
    fn decrypts_with_matching_external_material() {
        let value = fixture()
            .with_str(KEY, |plaintext| plaintext.to_owned())
            .unwrap();
        assert_eq!(value, "runtime-bound-secret");
    }

    #[test]
    fn rejects_wrong_external_material() {
        assert_eq!(
            fixture().with_bytes(WRONG_KEY, |_| ()),
            Err(RuntimeBoundError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_short_external_material() {
        assert_eq!(
            fixture().with_bytes(b"too-short", |_| ()),
            Err(RuntimeBoundError::KeyMaterialTooShort)
        );
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let ciphertext = runtime_bound_encrypt(b"runtime-bound-secret", KEY, NONCE).unwrap();
        assert!(!ciphertext
            .windows(b"runtime-bound-secret".len())
            .any(|window| window == b"runtime-bound-secret"));
    }
}
